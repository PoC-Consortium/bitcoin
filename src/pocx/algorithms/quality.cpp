// Copyright (c) 2025 The Proof of Capacity Consortium
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <pocx/algorithms/quality.h>
#include <pocx/algorithms/plot_generation.h>
#include <pocx/algorithms/encoding.h>
#include <pocx/crypto/shabal256.h>
#include <pocx/crypto/shabal256_lite.h>

#include <cstring>
#include <cstdlib>
#include <algorithm>
#include <limits>

namespace pocx {
namespace algorithms {

// Forward declaration for internal use
static int generate_scoop(
    const uint8_t address_payload[20],
    const uint8_t seed[32],
    uint64_t scoop,
    uint64_t nonce,
    uint32_t compression,
    uint8_t result[SCOOP_SIZE]
);

int CalculateScoop(uint64_t block_height, const uint8_t generation_signature[32]) {
    if (!generation_signature) {
        return 0;
    }

    uint8_t data[64] = {0};

    std::memcpy(data, generation_signature, 32);

    for (int i = 7; i >= 0; i--) {
        data[32 + (7 - i)] = static_cast<uint8_t>((block_height >> (i * 8)) & 0xFF);
    }

    data[40] = 0x80;

    uint32_t data_u32[MESSAGE_SIZE] = {0};
    BytesToU32LE(data, 64, data_u32);

    uint8_t hash[HASH_SIZE];
    crypto::Shabal256(nullptr, 0, nullptr, data_u32, hash);

    return (static_cast<uint64_t>(hash[30] & 0x0F) << 8) | static_cast<uint64_t>(hash[31]);
}

int CalculateQuality(
    const uint8_t address_payload[20],
    const uint8_t seed[32],
    uint64_t nonce,
    uint32_t compression,
    uint64_t height,
    const uint8_t generation_sig[32],
    uint64_t* quality
) {
    if (!address_payload || !seed || !generation_sig || !quality) {
        return -1;
    }

    const int scoop = CalculateScoop(height, generation_sig);

    uint8_t scoop_data[SCOOP_SIZE];
    if (generate_scoop(address_payload, seed, scoop, nonce, compression, scoop_data) != 0) {
        return -3;
    }

    *quality = crypto::Shabal256Lite(scoop_data, generation_sig);

    return 0;
}

// Internal helper: Generate scoop data for a specific compression level
static int generate_scoop(
    const uint8_t address_payload[20],
    const uint8_t seed[32],
    uint64_t scoop,
    uint64_t nonce,
    uint32_t compression,
    uint8_t result[SCOOP_SIZE]
) {
    if (!address_payload || !seed || !result || scoop >= NUM_SCOOPS) {
        return -1;
    }

    const uint64_t warp = nonce / NUM_SCOOPS;
    const uint64_t nonce_in_warp = nonce % NUM_SCOOPS;
    const uint64_t num_uncompressed_nonces = static_cast<uint64_t>(1) << compression;

    std::memset(result, 0, SCOOP_SIZE);

    auto nonce_buffer = static_cast<uint8_t*>(std::malloc(NONCE_SIZE));
    if (!nonce_buffer) {
        return -2;
    }

    for (uint64_t i = 0; i < num_uncompressed_nonces; i++) {
        uint64_t scoop_x, nonce_in_warp_x;
        if ((i % 2) == 0) {
            scoop_x = scoop;
            nonce_in_warp_x = nonce_in_warp;
        } else {
            scoop_x = nonce_in_warp;
            nonce_in_warp_x = scoop;
        }

        const uint64_t warp_x = num_uncompressed_nonces * warp + i;
        const uint64_t nonce_x = warp_x * NUM_SCOOPS + nonce_in_warp_x;

        // Generate single nonce using plot generation
        if (GenerateNonces(nonce_buffer, NONCE_SIZE, 0, address_payload, seed, nonce_x, 1) != 0) {
            std::free(nonce_buffer);
            return -3;
        }

        const size_t scoop_start = static_cast<size_t>(scoop_x) * SCOOP_SIZE;
        for (size_t j = 0; j < SCOOP_SIZE; j++) {
            result[j] ^= nonce_buffer[scoop_start + j];
        }
    }

    std::free(nonce_buffer);
    return 0;
}

} // namespace algorithms
} // namespace pocx
