// Copyright (c) 2025 The Proof of Capacity Consortium
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_POCX_CRYPTO_SHABAL256_LITE_H
#define BITCOIN_POCX_CRYPTO_SHABAL256_LITE_H

#include <cstdint>
#include <cstddef>

namespace pocx {
namespace crypto {

// Weakened Shabal256 for PoC quality calculation
uint64_t Shabal256Lite(const uint8_t* data, const uint8_t* gensig);

} // namespace crypto
} // namespace pocx

#endif // BITCOIN_POCX_CRYPTO_SHABAL256_LITE_H