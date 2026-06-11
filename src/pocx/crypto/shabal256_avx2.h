// Copyright (c) 2025 The Proof of Capacity Consortium
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_POCX_CRYPTO_SHABAL256_AVX2_H
#define BITCOIN_POCX_CRYPTO_SHABAL256_AVX2_H

#include <cstdint>
#include <cstddef>

namespace pocx {
namespace crypto {

/**
 * Check if AVX2 is available at runtime.
 * Caches result after first call.
 */
bool HaveAVX2();

#ifdef ENABLE_AVX2

/**
 * Process 8 independent Shabal256 computations in parallel using AVX2.
 *
 * Each of the 8 lanes operates on completely independent data.
 * This is NOT for consecutive nonces - it's for 8 unrelated hash operations.
 *
 * @param data      Array of 8 data pointers (each pointing to len bytes, NULL to skip lane)
 * @param len       Length of data in bytes (must be multiple of 64, same for all lanes)
 * @param pre_term  Array of 8 pre-termination block pointers (16 uint32_t each, can be NULL)
 * @param term      Array of 8 termination block pointers (16 uint32_t each, required)
 * @param output    Array of 8 output buffer pointers (32 bytes each)
 */
void Shabal256_avx2(
    const uint8_t* data[8],
    size_t len,
    const uint32_t* pre_term[8],
    const uint32_t* term[8],
    uint8_t* output[8]
);

#endif // ENABLE_AVX2

} // namespace crypto
} // namespace pocx

#endif // BITCOIN_POCX_CRYPTO_SHABAL256_AVX2_H
