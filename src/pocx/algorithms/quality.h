// Copyright (c) 2025 The Proof of Capacity Consortium
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_POCX_ALGORITHMS_QUALITY_H
#define BITCOIN_POCX_ALGORITHMS_QUALITY_H

#include <cstdint>
#include <cstddef>

namespace pocx {
namespace algorithms {

/** Calculate scoop number for a given height and generation signature */
int CalculateScoop(uint64_t height, const uint8_t generation_sig[32]);

/** Calculate quality for a specific compression level */
int CalculateQuality(
    const uint8_t address_payload[20],
    const uint8_t seed[32],
    uint64_t nonce,
    uint32_t compression,
    uint64_t height,
    const uint8_t generation_sig[32],
    uint64_t* quality
);

} // namespace algorithms
} // namespace pocx

#endif // BITCOIN_POCX_ALGORITHMS_QUALITY_H
