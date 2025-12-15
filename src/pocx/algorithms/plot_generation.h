// Copyright (c) 2025 The Proof of Capacity Consortium
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_POCX_ALGORITHMS_PLOT_GENERATION_H
#define BITCOIN_POCX_ALGORITHMS_PLOT_GENERATION_H

#include <cstdint>
#include <cstddef>

namespace pocx {
namespace algorithms {

static const size_t MESSAGE_SIZE = 16;
static const size_t HASH_SIZE = 32;
static const size_t HASH_CAP = 4096;
static const size_t NUM_SCOOPS = 4096;
static const size_t SCOOP_SIZE = 64;
static const size_t NONCE_SIZE = NUM_SCOOPS * SCOOP_SIZE;

/** Generate nonces for plot file creation */
int GenerateNonces(
    uint8_t* cache,
    size_t cache_size,
    size_t cache_offset,
    const uint8_t address_payload[20],
    const uint8_t seed[32],
    uint64_t start_nonce,
    uint64_t num_nonces
);

#ifdef ENABLE_AVX2
/**
 * Generate 8 nonces in parallel using AVX2.
 *
 * This function generates 8 independent nonces simultaneously using SIMD.
 * Each nonce can have a different account_id, seed, and nonce value.
 *
 * @param buffers       Array of 8 output buffers (each NONCE_SIZE bytes)
 * @param account_ids   Array of 8 account ID pointers (each 20 bytes)
 * @param seeds         Array of 8 seed pointers (each 32 bytes)
 * @param nonces        Array of 8 nonce values
 * @return 0 on success, negative on error
 */
int GenerateNonces8_avx2(
    uint8_t* buffers[8],
    const uint8_t* account_ids[8],
    const uint8_t* seeds[8],
    const uint64_t nonces[8]
);
#endif

} // namespace algorithms
} // namespace pocx

#endif // BITCOIN_POCX_ALGORITHMS_PLOT_GENERATION_H
