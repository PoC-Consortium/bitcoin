// Copyright (c) 2025 The Proof of Capacity Consortium
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_POCX_CRYPTO_SHABAL256_SSE2_H
#define BITCOIN_POCX_CRYPTO_SHABAL256_SSE2_H

#include <cstdint>
#include <cstddef>

namespace pocx {
namespace crypto {

/**
 * Check if SSE2 is available at runtime.
 * Caches result after first call.
 * Note: SSE2 is guaranteed on x86-64, but we check anyway for completeness.
 */
bool HaveSSE2();

#ifdef ENABLE_SSE2

/**
 * Process 4 independent Shabal256 computations in parallel using SSE2.
 *
 * Each of the 4 lanes operates on completely independent data.
 * This is NOT for consecutive nonces - it's for 4 unrelated hash operations.
 *
 * @param data      Array of 4 data pointers (each pointing to len bytes, NULL to skip lane)
 * @param len       Length of data in bytes (must be multiple of 64, same for all lanes)
 * @param pre_term  Array of 4 pre-termination block pointers (16 uint32_t each, can be NULL)
 * @param term      Array of 4 termination block pointers (16 uint32_t each, required)
 * @param output    Array of 4 output buffer pointers (32 bytes each)
 */
void Shabal256_sse2(
    const uint8_t* data[4],
    size_t len,
    const uint32_t* pre_term[4],
    const uint32_t* term[4],
    uint8_t* output[4]
);

#endif // ENABLE_SSE2

} // namespace crypto
} // namespace pocx

#endif // BITCOIN_POCX_CRYPTO_SHABAL256_SSE2_H
