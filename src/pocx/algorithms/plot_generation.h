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

} // namespace algorithms
} // namespace pocx

#endif // BITCOIN_POCX_ALGORITHMS_PLOT_GENERATION_H
