// Copyright (c) 2025 The Proof of Capacity Consortium
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_POCX_CONSENSUS_BATCH_VALIDATION_H
#define BITCOIN_POCX_CONSENSUS_BATCH_VALIDATION_H

#include <pocx/consensus/proof.h>
#include <cstdint>
#include <cstddef>

namespace pocx {
namespace consensus {

// Defensive allocation ceiling for the batch validator (expands each block to
// `1 << compression` work units). Not authoritative; the height-dependent rule
// is GetPoCXCompressionBounds(), whose max is 7. Raise in lockstep if that grows.
static constexpr uint32_t POCX_MIN_COMPRESSION = 1;
static constexpr uint32_t POCX_MAX_COMPRESSION = 7;

/**
 * Input for batch block validation.
 * Contains all data needed to validate a single block's PoC proof.
 */
struct BlockValidationInput {
    const uint8_t* generation_sig;  // 32 bytes - generation signature
    uint64_t base_target;           // Current base target
    const uint8_t* account_id;      // 20 bytes - plotter account ID
    uint64_t height;                // Block height
    uint64_t nonce;                 // Submitted nonce
    const uint8_t* seed;            // 32 bytes - plot seed
    uint32_t compression;           // Compression level (1-6)
    uint64_t claimed_quality;       // Claimed quality for early surrender check
};

/**
 * Validate multiple blocks in batch.
 *
 * Automatically selects the best implementation:
 * - AVX2: If available and count >= 2, uses 8-way parallel Shabal256
 * - Scalar: Falls back to sequential validation
 *
 * @param inputs    Array of block validation inputs
 * @param count     Number of blocks to validate (1-8 recommended for AVX2 efficiency)
 * @param results   Array of validation results (must be pre-allocated)
 * @return 0 on success, negative on error
 */
int pocx_validate_blocks(
    const BlockValidationInput* inputs,
    size_t count,
    ValidationResult* results
);

/**
 * Get the name of the implementation being used.
 * @return "avx2" or "scalar"
 */
const char* pocx_batch_implementation_name();

/**
 * Get number of threads used for batch validation.
 * Returns 0 if not yet determined (call after pocx_validate_blocks).
 */
size_t pocx_batch_thread_count();

} // namespace consensus
} // namespace pocx

#endif // BITCOIN_POCX_CONSENSUS_BATCH_VALIDATION_H
