// Copyright (c) 2025 The Proof of Capacity Consortium
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <pocx/consensus/batch_validation.h>
#include <pocx/consensus/proof.h>
#include <pocx/algorithms/quality.h>
#include <pocx/algorithms/plot_generation.h>
#include <pocx/algorithms/encoding.h>
#include <pocx/crypto/shabal256.h>
#include <pocx/crypto/shabal256_avx2.h>
#include <pocx/crypto/shabal256_sse2.h>
#include <pocx/crypto/shabal256_lite.h>

#include <cstring>
#include <cstdlib>
#include <vector>
#include <algorithm>
#include <limits>
#include <thread>
#include <atomic>
#include <mutex>
#include <functional>
#include <set>

namespace pocx {
namespace consensus {

using namespace pocx::algorithms;

// Thread pool configuration
// AVX2 processes 8 work units at a time, so ensure each thread has at least 8
// (Future: SSE2/AVX1 would use 4)
static constexpr size_t MIN_WORK_PER_THREAD = 8;
static std::atomic<size_t> g_last_thread_count{0};  // Last used thread count for diagnostics

// Work unit representing a single nonce generation task
struct NonceWorkUnit {
    size_t block_index;           // Which block this belongs to
    const uint8_t* account_id;    // 20 bytes
    const uint8_t* seed;          // 32 bytes
    uint64_t base_nonce;          // The actual nonce to generate
    uint64_t scoop;               // Which scoop to extract
    bool mirror;                  // Use mirror scoop position
    uint8_t scoop_data[SCOOP_SIZE]; // Output: 64 bytes scoop data
};

// Per-block accumulator for XORing scoops
struct BlockAccumulator {
    uint8_t xor_result[SCOOP_SIZE];  // Accumulated XOR of all scoops
    std::atomic<size_t> nonces_received{0};  // Count of nonces processed (atomic for thread safety)
    size_t nonces_expected{0};           // Total nonces needed
    const BlockValidationInput* input{nullptr};
    uint64_t claimed_quality{0};         // Claimed quality for early surrender check
    std::mutex xor_mutex;             // Protects xor_result during parallel accumulation

    BlockAccumulator() {
        std::memset(xor_result, 0, SCOOP_SIZE);
    }
};

// Early surrender abort latch - shared across threads. Raised when any block's
// quality mismatches; the verdict itself lives on that block's ValidationResult.
struct EarlySurrenderState {
    std::atomic<bool> triggered{false};
};

// Forward declarations
static int pocx_validate_blocks_scalar(
    const BlockValidationInput* inputs,
    size_t count,
    ValidationResult* results
);

#ifdef ENABLE_AVX2
static int pocx_validate_blocks_avx2_impl(
    const BlockValidationInput* inputs,
    size_t count,
    ValidationResult* results
);
#endif

#ifdef ENABLE_SSE2
static int pocx_validate_blocks_sse2_impl(
    const BlockValidationInput* inputs,
    size_t count,
    ValidationResult* results
);
#endif

// Forward declaration removed - function defined before use

// Generate a single nonce and extract scoop (scalar helper)
static int generate_nonce_scoop(
    const uint8_t* account_id,
    const uint8_t* seed,
    uint64_t nonce,
    uint64_t scoop,
    uint8_t scoop_data[SCOOP_SIZE]
) {
    auto nonce_buffer = static_cast<uint8_t*>(std::malloc(NONCE_SIZE));
    if (!nonce_buffer) {
        return -1;
    }

    if (GenerateNonces(nonce_buffer, NONCE_SIZE, 0, account_id, seed, nonce, 1) != 0) {
        std::free(nonce_buffer);
        return -2;
    }

    // Extract scoop data
    const size_t scoop_start = static_cast<size_t>(scoop) * SCOOP_SIZE;
    std::memcpy(scoop_data, nonce_buffer + scoop_start, SCOOP_SIZE);

    std::free(nonce_buffer);
    return 0;
}

// Check if a block just completed and validate its quality (early surrender check)
// Returns true if block completed and quality MATCHES (or was skipped), false if mismatch
static bool check_block_completion(
    size_t block_index,
    std::vector<BlockAccumulator>& accumulators,
    ValidationResult* results,
    EarlySurrenderState& surrender_state
) {
    BlockAccumulator& acc = accumulators[block_index];

    // Check if this block just completed
    size_t received = acc.nonces_received.load(std::memory_order_acquire);
    if (received != acc.nonces_expected) {
        return true;  // Not complete yet, continue processing
    }

    // Block is complete - calculate quality
    uint64_t quality = crypto::Shabal256Lite(acc.xor_result, acc.input->generation_sig);

    // Store result
    ValidationResult& result = results[block_index];
    result.quality = quality;
    result.is_valid = true;
    result.error_code = VALIDATION_SUCCESS;

    if (acc.input->base_target > 0) {
        result.deadline = quality / acc.input->base_target;
    } else {
        result.deadline = std::numeric_limits<uint64_t>::max();
    }

    // Early surrender check: verify calculated quality matches claimed quality
    if (quality != acc.claimed_quality) {
        // Quality mismatch - record the verdict on this block's own result, then
        // raise the shared abort latch so other threads stop processing.
        result.is_valid = false;
        result.error_code = VALIDATION_ERROR_QUALITY_MISMATCH;
        surrender_state.triggered.store(true, std::memory_order_release);
        return false;
    }

    return true;
}

// Process a single work unit (scalar)
// Returns true to continue, false if early surrender triggered
static bool process_single_work_unit(
    NonceWorkUnit& wu,
    std::vector<BlockAccumulator>& accumulators,
    ValidationResult* results,
    EarlySurrenderState& surrender_state
) {
    // Check early surrender before doing work
    if (surrender_state.triggered.load(std::memory_order_acquire)) {
        return false;
    }

    if (generate_nonce_scoop(wu.account_id, wu.seed, wu.base_nonce, wu.scoop, wu.scoop_data) != 0) {
        results[wu.block_index].is_valid = false;
        results[wu.block_index].error_code = VALIDATION_ERROR_QUALITY_CALCULATION;
        return true;  // Error but not surrender
    }

    BlockAccumulator& acc = accumulators[wu.block_index];
    {
        std::lock_guard<std::mutex> lock(acc.xor_mutex);
        for (size_t k = 0; k < SCOOP_SIZE; k++) {
            acc.xor_result[k] ^= wu.scoop_data[k];
        }
    }
    acc.nonces_received.fetch_add(1, std::memory_order_release);

    // Check if this block just completed
    return check_block_completion(wu.block_index, accumulators, results, surrender_state);
}

#ifdef ENABLE_AVX2
// Process 8 work units in parallel using AVX2
// Returns true to continue, false if early surrender triggered
static bool process_8_work_units_avx2(
    std::vector<NonceWorkUnit>& work_units,
    std::vector<BlockAccumulator>& accumulators,
    ValidationResult* results,
    size_t batch_start,
    EarlySurrenderState& surrender_state
) {
    // Check early surrender before doing work
    if (surrender_state.triggered.load(std::memory_order_acquire)) {
        return false;
    }

    // Allocate 8 nonce buffers
    uint8_t* nonce_buffers[8];
    for (int i = 0; i < 8; i++) {
        nonce_buffers[i] = static_cast<uint8_t*>(std::malloc(NONCE_SIZE));
        if (!nonce_buffers[i]) {
            // Cleanup and fall back to scalar
            for (int j = 0; j < i; j++) {
                std::free(nonce_buffers[j]);
            }
            for (int j = 0; j < 8; j++) {
                if (!process_single_work_unit(work_units[batch_start + j], accumulators, results, surrender_state)) {
                    return false;
                }
            }
            return true;
        }
    }

    // Prepare inputs for AVX2 nonce generation
    const uint8_t* account_ids[8];
    const uint8_t* seeds[8];
    uint64_t nonces_arr[8];

    for (int i = 0; i < 8; i++) {
        NonceWorkUnit& wu = work_units[batch_start + i];
        account_ids[i] = wu.account_id;
        seeds[i] = wu.seed;
        nonces_arr[i] = wu.base_nonce;
    }

    // Generate 8 nonces in parallel
    int ret = GenerateNonces8_avx2(nonce_buffers, account_ids, seeds, nonces_arr);

    if (ret != 0) {
        // Fall back to scalar on error
        for (int i = 0; i < 8; i++) {
            std::free(nonce_buffers[i]);
        }
        for (int i = 0; i < 8; i++) {
            if (!process_single_work_unit(work_units[batch_start + i], accumulators, results, surrender_state)) {
                return false;
            }
        }
        return true;
    }

    // Extract scoops and accumulate
    // Track which blocks we updated so we can check completion
    std::set<size_t> updated_blocks;

    for (int i = 0; i < 8; i++) {
        NonceWorkUnit& wu = work_units[batch_start + i];
        const size_t scoop_start = static_cast<size_t>(wu.scoop) * SCOOP_SIZE;
        std::memcpy(wu.scoop_data, nonce_buffers[i] + scoop_start, SCOOP_SIZE);

        BlockAccumulator& acc = accumulators[wu.block_index];
        {
            std::lock_guard<std::mutex> lock(acc.xor_mutex);
            for (size_t k = 0; k < SCOOP_SIZE; k++) {
                acc.xor_result[k] ^= wu.scoop_data[k];
            }
        }
        acc.nonces_received.fetch_add(1, std::memory_order_release);
        updated_blocks.insert(wu.block_index);

        std::free(nonce_buffers[i]);
    }

    // Check completion for all blocks we updated
    for (size_t block_idx : updated_blocks) {
        if (!check_block_completion(block_idx, accumulators, results, surrender_state)) {
            return false;
        }
    }

    return true;
}
#endif

#ifdef ENABLE_SSE2
// Process 4 work units in parallel using SSE2
// Returns true to continue, false if early surrender triggered
static bool process_4_work_units_sse2(
    std::vector<NonceWorkUnit>& work_units,
    std::vector<BlockAccumulator>& accumulators,
    ValidationResult* results,
    size_t batch_start,
    EarlySurrenderState& surrender_state
) {
    // Check early surrender before doing work
    if (surrender_state.triggered.load(std::memory_order_acquire)) {
        return false;
    }

    // Allocate 4 nonce buffers
    uint8_t* nonce_buffers[4];
    for (int i = 0; i < 4; i++) {
        nonce_buffers[i] = static_cast<uint8_t*>(std::malloc(NONCE_SIZE));
        if (!nonce_buffers[i]) {
            // Cleanup and fall back to scalar
            for (int j = 0; j < i; j++) {
                std::free(nonce_buffers[j]);
            }
            for (int j = 0; j < 4; j++) {
                if (!process_single_work_unit(work_units[batch_start + j], accumulators, results, surrender_state)) {
                    return false;
                }
            }
            return true;
        }
    }

    // Prepare inputs for SSE2 nonce generation
    const uint8_t* account_ids[4];
    const uint8_t* seeds[4];
    uint64_t nonces_arr[4];

    for (int i = 0; i < 4; i++) {
        NonceWorkUnit& wu = work_units[batch_start + i];
        account_ids[i] = wu.account_id;
        seeds[i] = wu.seed;
        nonces_arr[i] = wu.base_nonce;
    }

    // Generate 4 nonces in parallel
    int ret = GenerateNonces4_sse2(nonce_buffers, account_ids, seeds, nonces_arr);

    if (ret != 0) {
        // Fall back to scalar on error
        for (int i = 0; i < 4; i++) {
            std::free(nonce_buffers[i]);
        }
        for (int i = 0; i < 4; i++) {
            if (!process_single_work_unit(work_units[batch_start + i], accumulators, results, surrender_state)) {
                return false;
            }
        }
        return true;
    }

    // Extract scoops and accumulate
    // Track which blocks we updated so we can check completion
    std::set<size_t> updated_blocks;

    for (int i = 0; i < 4; i++) {
        NonceWorkUnit& wu = work_units[batch_start + i];
        const size_t scoop_start = static_cast<size_t>(wu.scoop) * SCOOP_SIZE;
        std::memcpy(wu.scoop_data, nonce_buffers[i] + scoop_start, SCOOP_SIZE);

        BlockAccumulator& acc = accumulators[wu.block_index];
        {
            std::lock_guard<std::mutex> lock(acc.xor_mutex);
            for (size_t k = 0; k < SCOOP_SIZE; k++) {
                acc.xor_result[k] ^= wu.scoop_data[k];
            }
        }
        acc.nonces_received.fetch_add(1, std::memory_order_release);
        updated_blocks.insert(wu.block_index);

        std::free(nonce_buffers[i]);
    }

    // Check completion for all blocks we updated
    for (size_t block_idx : updated_blocks) {
        if (!check_block_completion(block_idx, accumulators, results, surrender_state)) {
            return false;
        }
    }

    return true;
}
#endif

// Thread worker function: processes a range of work units
static void process_work_range(
    std::vector<NonceWorkUnit>& work_units,
    std::vector<BlockAccumulator>& accumulators,
    ValidationResult* results,
    size_t start_idx,
    size_t end_idx,
    [[maybe_unused]] bool use_avx2,
    EarlySurrenderState& surrender_state
) {
    size_t i = start_idx;

#ifdef ENABLE_AVX2
    // Process in batches of 8 using AVX2 when available
    if (use_avx2 && crypto::HaveAVX2()) {
        while (i + 8 <= end_idx) {
            if (!process_8_work_units_avx2(work_units, accumulators, results, i, surrender_state)) {
                return;  // Early surrender triggered
            }
            i += 8;
        }
    }
#endif

    // Process remaining work units with scalar
    while (i < end_idx) {
        if (!process_single_work_unit(work_units[i], accumulators, results, surrender_state)) {
            return;  // Early surrender triggered
        }
        i++;
    }
}

// Scalar implementation - validates blocks with optional multi-threading
static int pocx_validate_blocks_scalar(
    const BlockValidationInput* inputs,
    size_t count,
    ValidationResult* results
) {
    // Step 1: Calculate total work units and expand
    size_t total_work = 0;
    std::vector<size_t> block_work_counts(count);
    std::vector<int> block_scoops(count);

    for (size_t i = 0; i < count; i++) {
        block_scoops[i] = CalculateScoop(inputs[i].height, inputs[i].generation_sig);
        block_work_counts[i] = static_cast<size_t>(1) << inputs[i].compression;
        total_work += block_work_counts[i];
    }

    // Step 2: Create work units
    std::vector<NonceWorkUnit> work_units(total_work);
    size_t work_idx = 0;

    for (size_t i = 0; i < count; i++) {
        const BlockValidationInput& input = inputs[i];
        const uint64_t num_base_nonces = block_work_counts[i];
        const int scoop = block_scoops[i];

        const uint64_t warp = input.nonce / NUM_SCOOPS;
        const uint64_t nonce_in_warp = input.nonce % NUM_SCOOPS;

        for (uint64_t j = 0; j < num_base_nonces; j++) {
            NonceWorkUnit& wu = work_units[work_idx++];
            wu.block_index = i;
            wu.account_id = input.account_id;
            wu.seed = input.seed;

            uint64_t scoop_x, nonce_in_warp_x;
            if ((j % 2) == 0) {
                scoop_x = scoop;
                nonce_in_warp_x = nonce_in_warp;
            } else {
                scoop_x = nonce_in_warp;
                nonce_in_warp_x = scoop;
            }

            const uint64_t warp_x = num_base_nonces * warp + j;
            wu.base_nonce = warp_x * NUM_SCOOPS + nonce_in_warp_x;
            wu.scoop = scoop_x;
            wu.mirror = (j % 2) != 0;
            std::memset(wu.scoop_data, 0, SCOOP_SIZE);
        }
    }

    // Step 3: Initialize accumulators and early surrender state
    std::vector<BlockAccumulator> accumulators(count);
    for (size_t i = 0; i < count; i++) {
        accumulators[i].nonces_expected = block_work_counts[i];
        accumulators[i].input = &inputs[i];
        accumulators[i].claimed_quality = inputs[i].claimed_quality;
    }

    EarlySurrenderState surrender_state;

    // Step 4: Process work units in parallel (scalar - no AVX2 nonce generation)
    // Reserve 1 thread for system responsiveness (networking, RPC, etc.)
    const size_t hw_threads = std::thread::hardware_concurrency();
    const size_t max_threads = (hw_threads > 1) ? hw_threads - 1 : 1;
    const size_t num_threads = std::min(max_threads, (total_work + MIN_WORK_PER_THREAD - 1) / MIN_WORK_PER_THREAD);

    // Record thread count for diagnostics
    g_last_thread_count.store(num_threads, std::memory_order_relaxed);

    constexpr bool use_avx2_scalar = false;  // Scalar implementation doesn't use AVX2 nonce gen

    if (num_threads <= 1 || total_work < MIN_WORK_PER_THREAD * 2) {
        // Single-threaded: process all work units sequentially
        g_last_thread_count.store(1, std::memory_order_relaxed);
        process_work_range(work_units, accumulators, results, 0, total_work, use_avx2_scalar, surrender_state);
    } else {
        // Multi-threaded: split work across threads
        std::vector<std::thread> threads;
        threads.reserve(num_threads);

        const size_t work_per_thread = total_work / num_threads;
        size_t remaining = total_work % num_threads;

        size_t start_idx = 0;
        for (size_t t = 0; t < num_threads; t++) {
            size_t chunk_size = work_per_thread + (t < remaining ? 1 : 0);
            size_t end_idx = start_idx + chunk_size;

            threads.emplace_back(process_work_range,
                std::ref(work_units),
                std::ref(accumulators),
                results,
                start_idx,
                end_idx,
                use_avx2_scalar,
                std::ref(surrender_state));

            start_idx = end_idx;
        }

        // Wait for all threads to complete
        for (auto& thread : threads) {
            thread.join();
        }
    }

    // Step 5: Check for early surrender. The failing block(s) already carry
    // is_valid=false from check_block_completion; -2 lets the caller skip the scan.
    if (surrender_state.triggered.load(std::memory_order_acquire)) {
        return -2;  // Early surrender error code
    }

    // Step 6: Finalize - verify all blocks completed (results already set by check_block_completion)
    for (size_t i = 0; i < count; i++) {
        ValidationResult& result = results[i];
        BlockAccumulator& acc = accumulators[i];

        // Skip if already processed by check_block_completion
        if (result.is_valid && result.error_code == VALIDATION_SUCCESS) {
            continue;
        }

        // Check for incomplete processing
        if (acc.nonces_received.load(std::memory_order_relaxed) != acc.nonces_expected) {
            result.is_valid = false;
            result.error_code = VALIDATION_ERROR_QUALITY_CALCULATION;
            result.quality = 0;
            result.deadline = std::numeric_limits<uint64_t>::max();
        }
    }

    return 0;
}

#ifdef ENABLE_AVX2

// AVX2 implementation - processes work units in batches of 8
static int pocx_validate_blocks_avx2_impl(
    const BlockValidationInput* inputs,
    size_t count,
    ValidationResult* results
) {
    // Step 1: Calculate total work units and expand
    size_t total_work = 0;
    std::vector<size_t> block_work_counts(count);
    std::vector<int> block_scoops(count);

    for (size_t i = 0; i < count; i++) {
        block_scoops[i] = CalculateScoop(inputs[i].height, inputs[i].generation_sig);
        block_work_counts[i] = static_cast<size_t>(1) << inputs[i].compression;
        total_work += block_work_counts[i];
    }

    // Step 2: Create work units
    std::vector<NonceWorkUnit> work_units(total_work);
    size_t work_idx = 0;

    for (size_t i = 0; i < count; i++) {
        const BlockValidationInput& input = inputs[i];
        const uint64_t num_base_nonces = block_work_counts[i];
        const int scoop = block_scoops[i];

        const uint64_t warp = input.nonce / NUM_SCOOPS;
        const uint64_t nonce_in_warp = input.nonce % NUM_SCOOPS;

        for (uint64_t j = 0; j < num_base_nonces; j++) {
            NonceWorkUnit& wu = work_units[work_idx++];
            wu.block_index = i;
            wu.account_id = input.account_id;
            wu.seed = input.seed;

            uint64_t scoop_x, nonce_in_warp_x;
            if ((j % 2) == 0) {
                scoop_x = scoop;
                nonce_in_warp_x = nonce_in_warp;
            } else {
                scoop_x = nonce_in_warp;
                nonce_in_warp_x = scoop;
            }

            const uint64_t warp_x = num_base_nonces * warp + j;
            wu.base_nonce = warp_x * NUM_SCOOPS + nonce_in_warp_x;
            wu.scoop = scoop_x;
            wu.mirror = (j % 2) != 0;
            std::memset(wu.scoop_data, 0, SCOOP_SIZE);
        }
    }

    // Step 3: Initialize accumulators and early surrender state
    std::vector<BlockAccumulator> accumulators(count);
    for (size_t i = 0; i < count; i++) {
        accumulators[i].nonces_expected = block_work_counts[i];
        accumulators[i].input = &inputs[i];
        accumulators[i].claimed_quality = inputs[i].claimed_quality;
    }

    EarlySurrenderState surrender_state;

    // Step 4: Process work units in parallel with AVX2 nonce generation
    // Determine number of threads based on work and available hardware
    // Reserve 1 thread for system responsiveness (networking, RPC, etc.)
    const size_t hw_threads = std::thread::hardware_concurrency();
    const size_t max_threads = (hw_threads > 1) ? hw_threads - 1 : 1;
    const size_t num_threads = std::min(max_threads, (total_work + MIN_WORK_PER_THREAD - 1) / MIN_WORK_PER_THREAD);

    // Record thread count for diagnostics
    g_last_thread_count.store(num_threads, std::memory_order_relaxed);

    constexpr bool use_avx2_impl = true;  // AVX2 implementation uses AVX2 nonce generation

    if (num_threads <= 1 || total_work < MIN_WORK_PER_THREAD * 2) {
        // Single-threaded: process all work units sequentially
        g_last_thread_count.store(1, std::memory_order_relaxed);
        process_work_range(work_units, accumulators, results, 0, total_work, use_avx2_impl, surrender_state);
    } else {
        // Multi-threaded: split work across threads
        std::vector<std::thread> threads;
        threads.reserve(num_threads);

        const size_t work_per_thread = total_work / num_threads;
        size_t remaining = total_work % num_threads;

        size_t start_idx = 0;
        for (size_t t = 0; t < num_threads; t++) {
            size_t chunk_size = work_per_thread + (t < remaining ? 1 : 0);
            size_t end_idx = start_idx + chunk_size;

            threads.emplace_back(process_work_range,
                std::ref(work_units),
                std::ref(accumulators),
                results,
                start_idx,
                end_idx,
                use_avx2_impl,
                std::ref(surrender_state));

            start_idx = end_idx;
        }

        // Wait for all threads to complete
        for (auto& thread : threads) {
            thread.join();
        }
    }

    // Step 5: Check for early surrender. The failing block(s) already carry
    // is_valid=false from check_block_completion; -2 lets the caller skip the scan.
    if (surrender_state.triggered.load(std::memory_order_acquire)) {
        return -2;  // Early surrender error code
    }

    // Step 6: Finalize - verify all blocks completed (results already set by check_block_completion)
    for (size_t i = 0; i < count; i++) {
        ValidationResult& result = results[i];
        BlockAccumulator& acc = accumulators[i];

        // Skip if already processed by check_block_completion
        if (result.is_valid && result.error_code == VALIDATION_SUCCESS) {
            continue;
        }

        // Check for incomplete processing
        if (acc.nonces_received.load(std::memory_order_relaxed) != acc.nonces_expected) {
            result.is_valid = false;
            result.error_code = VALIDATION_ERROR_QUALITY_CALCULATION;
            result.quality = 0;
            result.deadline = std::numeric_limits<uint64_t>::max();
        }
    }

    return 0;
}

#endif // ENABLE_AVX2

#ifdef ENABLE_SSE2

// SSE2 thread worker function: processes a range of work units with 4-way SIMD
static void process_work_range_sse2(
    std::vector<NonceWorkUnit>& work_units,
    std::vector<BlockAccumulator>& accumulators,
    ValidationResult* results,
    size_t start_idx,
    size_t end_idx,
    EarlySurrenderState& surrender_state
) {
    size_t i = start_idx;

    // Process in batches of 4 using SSE2
    while (i + 4 <= end_idx) {
        if (!process_4_work_units_sse2(work_units, accumulators, results, i, surrender_state)) {
            return;  // Early surrender triggered
        }
        i += 4;
    }

    // Process remaining work units with scalar
    while (i < end_idx) {
        if (!process_single_work_unit(work_units[i], accumulators, results, surrender_state)) {
            return;  // Early surrender triggered
        }
        i++;
    }
}

// SSE2 implementation - processes work units in batches of 4
static int pocx_validate_blocks_sse2_impl(
    const BlockValidationInput* inputs,
    size_t count,
    ValidationResult* results
) {
    // Step 1: Calculate total work units and expand
    size_t total_work = 0;
    std::vector<size_t> block_work_counts(count);
    std::vector<int> block_scoops(count);

    for (size_t i = 0; i < count; i++) {
        block_scoops[i] = CalculateScoop(inputs[i].height, inputs[i].generation_sig);
        block_work_counts[i] = static_cast<size_t>(1) << inputs[i].compression;
        total_work += block_work_counts[i];
    }

    // Step 2: Create work units
    std::vector<NonceWorkUnit> work_units(total_work);
    size_t work_idx = 0;

    for (size_t i = 0; i < count; i++) {
        const BlockValidationInput& input = inputs[i];
        const uint64_t num_base_nonces = block_work_counts[i];
        const int scoop = block_scoops[i];

        const uint64_t warp = input.nonce / NUM_SCOOPS;
        const uint64_t nonce_in_warp = input.nonce % NUM_SCOOPS;

        for (uint64_t j = 0; j < num_base_nonces; j++) {
            NonceWorkUnit& wu = work_units[work_idx++];
            wu.block_index = i;
            wu.account_id = input.account_id;
            wu.seed = input.seed;

            uint64_t scoop_x, nonce_in_warp_x;
            if ((j % 2) == 0) {
                scoop_x = scoop;
                nonce_in_warp_x = nonce_in_warp;
            } else {
                scoop_x = nonce_in_warp;
                nonce_in_warp_x = scoop;
            }

            const uint64_t warp_x = num_base_nonces * warp + j;
            wu.base_nonce = warp_x * NUM_SCOOPS + nonce_in_warp_x;
            wu.scoop = scoop_x;
            wu.mirror = (j % 2) != 0;
            std::memset(wu.scoop_data, 0, SCOOP_SIZE);
        }
    }

    // Step 3: Initialize accumulators and early surrender state
    std::vector<BlockAccumulator> accumulators(count);
    for (size_t i = 0; i < count; i++) {
        accumulators[i].nonces_expected = block_work_counts[i];
        accumulators[i].input = &inputs[i];
        accumulators[i].claimed_quality = inputs[i].claimed_quality;
    }

    EarlySurrenderState surrender_state;

    // Step 4: Process work units in parallel with SSE2 nonce generation
    // SSE2 processes 4 work units at a time
    static constexpr size_t MIN_WORK_PER_THREAD_SSE2 = 4;

    // Reserve 1 thread for system responsiveness
    const size_t hw_threads = std::thread::hardware_concurrency();
    const size_t max_threads = (hw_threads > 1) ? hw_threads - 1 : 1;
    const size_t num_threads = std::min(max_threads, (total_work + MIN_WORK_PER_THREAD_SSE2 - 1) / MIN_WORK_PER_THREAD_SSE2);

    // Record thread count for diagnostics
    g_last_thread_count.store(num_threads, std::memory_order_relaxed);

    if (num_threads <= 1 || total_work < MIN_WORK_PER_THREAD_SSE2 * 2) {
        // Single-threaded: process all work units sequentially
        g_last_thread_count.store(1, std::memory_order_relaxed);
        process_work_range_sse2(work_units, accumulators, results, 0, total_work, surrender_state);
    } else {
        // Multi-threaded: split work across threads
        std::vector<std::thread> threads;
        threads.reserve(num_threads);

        const size_t work_per_thread = total_work / num_threads;
        size_t remaining = total_work % num_threads;

        size_t start_idx = 0;
        for (size_t t = 0; t < num_threads; t++) {
            size_t chunk_size = work_per_thread + (t < remaining ? 1 : 0);
            size_t end_idx = start_idx + chunk_size;

            threads.emplace_back(process_work_range_sse2,
                std::ref(work_units),
                std::ref(accumulators),
                results,
                start_idx,
                end_idx,
                std::ref(surrender_state));

            start_idx = end_idx;
        }

        // Wait for all threads to complete
        for (auto& thread : threads) {
            thread.join();
        }
    }

    // Step 5: Check for early surrender. The failing block(s) already carry
    // is_valid=false from check_block_completion; -2 lets the caller skip the scan.
    if (surrender_state.triggered.load(std::memory_order_acquire)) {
        return -2;  // Early surrender error code
    }

    // Step 6: Finalize - verify all blocks completed (results already set by check_block_completion)
    for (size_t i = 0; i < count; i++) {
        ValidationResult& result = results[i];
        BlockAccumulator& acc = accumulators[i];

        // Skip if already processed by check_block_completion
        if (result.is_valid && result.error_code == VALIDATION_SUCCESS) {
            continue;
        }

        // Check for incomplete processing
        if (acc.nonces_received.load(std::memory_order_relaxed) != acc.nonces_expected) {
            result.is_valid = false;
            result.error_code = VALIDATION_ERROR_QUALITY_CALCULATION;
            result.quality = 0;
            result.deadline = std::numeric_limits<uint64_t>::max();
        }
    }

    return 0;
}

#endif // ENABLE_SSE2

int pocx_validate_blocks(
    const BlockValidationInput* inputs,
    size_t count,
    ValidationResult* results
) {
    if (!inputs || !results || count == 0) {
        return -1;
    }

    // Defensive bound: each block expands to `1 << compression` work units, so
    // reject out-of-range compression and refuse a size_t-overflowing total
    // before any shift or allocation below.
    size_t guarded_total_work = 0;
    for (size_t i = 0; i < count; i++) {
        const uint32_t compression = inputs[i].compression;
        if (compression < POCX_MIN_COMPRESSION || compression > POCX_MAX_COMPRESSION) {
            results[i].is_valid = false;
            results[i].error_code = VALIDATION_ERROR_COMPRESSION_OUT_OF_RANGE;
            return VALIDATION_ERROR_COMPRESSION_OUT_OF_RANGE;
        }
        const size_t work = static_cast<size_t>(1) << compression; // <= 1<<7 == 128
        if (guarded_total_work > std::numeric_limits<size_t>::max() - work) {
            return VALIDATION_ERROR_INVALID_INPUT;
        }
        guarded_total_work += work;
    }

#ifdef ENABLE_AVX2
    if (crypto::HaveAVX2()) {
        return pocx_validate_blocks_avx2_impl(inputs, count, results);
    }
#endif

#ifdef ENABLE_SSE2
    if (crypto::HaveSSE2()) {
        return pocx_validate_blocks_sse2_impl(inputs, count, results);
    }
#endif

    return pocx_validate_blocks_scalar(inputs, count, results);
}

const char* pocx_batch_implementation_name() {
#ifdef ENABLE_AVX2
    if (crypto::HaveAVX2()) {
        return "avx2";
    }
#endif
#ifdef ENABLE_SSE2
    if (crypto::HaveSSE2()) {
        return "sse2";
    }
#endif
    return "scalar";
}

size_t pocx_batch_thread_count() {
    return g_last_thread_count.load(std::memory_order_relaxed);
}

} // namespace consensus
} // namespace pocx
