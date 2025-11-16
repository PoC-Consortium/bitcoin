// Copyright (c) 2025 The Proof of Capacity Consortium
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_POCX_CRYPTO_SHABAL256_H
#define BITCOIN_POCX_CRYPTO_SHABAL256_H

#include <cstdint>
#include <cstddef>

namespace pocx {
namespace crypto {

extern const uint32_t A_INIT[12];
extern const uint32_t B_INIT[16];
extern const uint32_t C_INIT[16];

// Shabal256 hash function for PoC cryptocurrencies
void Shabal256(const uint8_t* data, size_t len, const uint32_t* pre_term, const uint32_t* term, uint8_t* output);


} // namespace crypto
} // namespace pocx

#endif // BITCOIN_POCX_CRYPTO_SHABAL256_H