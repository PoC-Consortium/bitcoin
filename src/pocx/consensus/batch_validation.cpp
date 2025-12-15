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
    size_t nonces_expected;           // Total nonces needed
    const BlockValidationInput* input;
    std::mutex xor_mutex;             // Protects xor_result during parallel accumulation

    BlockAccumulator() : nonces_expected(0), input(nullptr) {
        std::memset(xor_result, 0, SCOOP_SIZE);
    }
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

// Process a single work unit (scalar)
static void process_single_work_unit(
    NonceWorkUnit& wu,
    std::vector<BlockAccumulator>& accumulators,
    ValidationResult* results
) {
    if (generate_nonce_scoop(wu.account_id, wu.seed, wu.base_nonce, wu.scoop, wu.scoop_data) != 0) {
        results[wu.block_index].is_valid = false;
        results[wu.block_index].error_code = VALIDATION_ERROR_QUALITY_CALCULATION;
        return;
    }

    BlockAccumulator& acc = accumulators[wu.block_index];
    {
        std::lock_guard<std::mutex> lock(acc.xor_mutex);
        for (size_t k = 0; k < SCOOP_SIZE; k++) {
            acc.xor_result[k] ^= wu.scoop_data[k];
        }
    }
    acc.nonces_received.fetch_add(1, std::memory_order_relaxed);
}

#ifdef ENABLE_AVX2
// Process 8 work units in parallel using AVX2
static void process_8_work_units_avx2(
    std::vector<NonceWorkUnit>& work_units,
    std::vector<BlockAccumulator>& accumulators,
    ValidationResult* results,
    size_t batch_start
) {
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
                process_single_work_unit(work_units[batch_start + j], accumulators, results);
            }
            return;
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
            process_single_work_unit(work_units[batch_start + i], accumulators, results);
        }
        return;
    }

    // Extract scoops and accumulate
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
        acc.nonces_received.fetch_add(1, std::memory_order_relaxed);

        std::free(nonce_buffers[i]);
    }
}
#endif

// Thread worker function: processes a range of work units
static void process_work_range(
    std::vector<NonceWorkUnit>& work_units,
    std::vector<BlockAccumulator>& accumulators,
    ValidationResult* results,
    size_t start_idx,
    size_t end_idx,
    [[maybe_unused]] bool use_avx2
) {
    size_t i = start_idx;

#ifdef ENABLE_AVX2
    // Process in batches of 8 using AVX2 when available
    if (use_avx2 && crypto::HaveAVX2()) {
        while (i + 8 <= end_idx) {
            process_8_work_units_avx2(work_units, accumulators, results, i);
            i += 8;
        }
    }
#endif

    // Process remaining work units with scalar
    while (i < end_idx) {
        process_single_work_unit(work_units[i], accumulators, results);
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

    // Step 3: Initialize accumulators
    std::vector<BlockAccumulator> accumulators(count);
    for (size_t i = 0; i < count; i++) {
        accumulators[i].nonces_expected = block_work_counts[i];
        accumulators[i].input = &inputs[i];
    }

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
        process_work_range(work_units, accumulators, results, 0, total_work, use_avx2_scalar);
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
                use_avx2_scalar);

            start_idx = end_idx;
        }

        // Wait for all threads to complete
        for (auto& thread : threads) {
            thread.join();
        }
    }

    // Step 5: Finalize - calculate quality for each block
    for (size_t i = 0; i < count; i++) {
        ValidationResult& result = results[i];
        BlockAccumulator& acc = accumulators[i];

        // Initialize result
        result.is_valid = false;
        result.error_code = -1;
        result.quality = 0;
        result.deadline = std::numeric_limits<uint64_t>::max();

        if (acc.nonces_received.load(std::memory_order_relaxed) != acc.nonces_expected) {
            result.error_code = VALIDATION_ERROR_QUALITY_CALCULATION;
            continue;
        }

        // Calculate quality using Shabal256Lite
        uint64_t quality = crypto::Shabal256Lite(acc.xor_result, acc.input->generation_sig);

        // Calculate deadline
        uint64_t deadline;
        if (acc.input->base_target > 0) {
            deadline = quality / acc.input->base_target;
        } else {
            deadline = std::numeric_limits<uint64_t>::max();
        }

        result.is_valid = true;
        result.error_code = VALIDATION_SUCCESS;
        result.quality = quality;
        result.deadline = deadline;
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

    // Step 3: Initialize accumulators
    std::vector<BlockAccumulator> accumulators(count);
    for (size_t i = 0; i < count; i++) {
        accumulators[i].nonces_expected = block_work_counts[i];
        accumulators[i].input = &inputs[i];
    }

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
        process_work_range(work_units, accumulators, results, 0, total_work, use_avx2_impl);
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
                use_avx2_impl);

            start_idx = end_idx;
        }

        // Wait for all threads to complete
        for (auto& thread : threads) {
            thread.join();
        }
    }

    // Step 5: Finalize - calculate quality for each block
    for (size_t i = 0; i < count; i++) {
        ValidationResult& result = results[i];
        BlockAccumulator& acc = accumulators[i];

        // Initialize result
        result.is_valid = false;
        result.error_code = -1;
        result.quality = 0;
        result.deadline = std::numeric_limits<uint64_t>::max();

        if (acc.nonces_received.load(std::memory_order_relaxed) != acc.nonces_expected) {
            result.error_code = VALIDATION_ERROR_QUALITY_CALCULATION;
            continue;
        }

        // Calculate quality using Shabal256Lite (scalar, runs once per block)
        uint64_t quality = crypto::Shabal256Lite(acc.xor_result, acc.input->generation_sig);

        // Calculate deadline
        uint64_t deadline;
        if (acc.input->base_target > 0) {
            deadline = quality / acc.input->base_target;
        } else {
            deadline = std::numeric_limits<uint64_t>::max();
        }

        result.is_valid = true;
        result.error_code = VALIDATION_SUCCESS;
        result.quality = quality;
        result.deadline = deadline;
    }

    return 0;
}

#endif // ENABLE_AVX2

int pocx_validate_blocks(
    const BlockValidationInput* inputs,
    size_t count,
    ValidationResult* results
) {
    if (!inputs || !results || count == 0) {
        return -1;
    }

#ifdef ENABLE_AVX2
    if (crypto::HaveAVX2() && count >= 2) {
        return pocx_validate_blocks_avx2_impl(inputs, count, results);
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
    return "scalar";
}

size_t pocx_batch_thread_count() {
    return g_last_thread_count.load(std::memory_order_relaxed);
}

} // namespace consensus
} // namespace pocx
