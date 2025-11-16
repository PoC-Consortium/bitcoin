// Copyright (c) 2025 The Proof of Capacity Consortium
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <pocx/algorithms/plot_generation.h>
#include <pocx/algorithms/encoding.h>
#include <pocx/crypto/shabal256.h>

#include <cstring>
#include <cstdlib>

namespace pocx {
namespace algorithms {

static int unpack_shuffle_scatter(
    const uint8_t* source,
    size_t source_size,
    uint8_t* target,
    size_t target_size,
    size_t target_offset,
    size_t vector_size
) {
    if (!source || !target || vector_size == 0) {
        return -1;
    }

    const size_t target_nonce_count = target_size / NONCE_SIZE;

    if (target_offset >= target_nonce_count) {
        return -1;
    }

    for (size_t i = 0; i < (NUM_SCOOPS * 2); i++) {
        for (size_t j = 0; j < 32; j += 4) {
            for (size_t k = 0; k < vector_size; k++) {
                const size_t data_offset =
                    ((i & 1) * (4095 - (i >> 1)) + ((i + 1) & 1) * (i >> 1))
                    * SCOOP_SIZE
                    * target_nonce_count
                    + (k + target_offset) * SCOOP_SIZE
                    + (i & 1) * 32
                    + j;

                const size_t buffer_offset = (i * 32 + j) * vector_size + k * 4;

                std::memcpy(target + data_offset, source + buffer_offset, 4);
            }
        }
    }

    return 0;
}

int GenerateNonces(
    uint8_t* cache,
    size_t cache_size,
    size_t cache_offset,
    const uint8_t address_payload[20],
    const uint8_t seed[32],
    uint64_t start_nonce,
    uint64_t num_nonces
) {
    if (!cache || !address_payload || !seed) {
        return -1;
    }

    const size_t required_size = (cache_offset + num_nonces) * NONCE_SIZE;
    if (cache_size < required_size) {
        return -2;
    }

    uint32_t payload_bytes[5] = {0};
    BytesToU32LE(address_payload, 20, payload_bytes);

    uint32_t seed_u32[8] = {0};
    BytesToU32LE(seed, 32, seed_u32);

    auto buffer = static_cast<uint8_t*>(std::malloc(NONCE_SIZE));
    auto final_buffer = static_cast<uint8_t*>(std::malloc(HASH_SIZE));

    if (!buffer || !final_buffer) {
        std::free(buffer);
        std::free(final_buffer);
        return -3;
    }

    uint32_t t1[MESSAGE_SIZE] = {0};
    uint32_t t2[MESSAGE_SIZE] = {0};
    uint32_t pt2[MESSAGE_SIZE] = {0};
    uint32_t t3[MESSAGE_SIZE] = {0};
    uint8_t hash[HASH_SIZE];

    std::memcpy(t1, seed_u32, 8 * sizeof(uint32_t));
    std::memcpy(t1 + 8, payload_bytes, 5 * sizeof(uint32_t));
    t1[15] = 0x80;

    std::memcpy(t2, payload_bytes, 5 * sizeof(uint32_t));
    t2[7] = 0x80;

    std::memcpy(pt2 + 8, seed_u32, 8 * sizeof(uint32_t));

    t3[0] = 0x80;

    for (uint64_t n = 0; n < num_nonces; n++) {
        uint32_t nonce[2];
        U64ToU32BE(start_nonce + n, nonce);


        t1[13] = nonce[1]; t1[14] = nonce[0];
        t2[5] = nonce[1];  t2[6] = nonce[0];

        crypto::Shabal256(nullptr, 0, nullptr, t1, hash);

        std::memcpy(buffer + NONCE_SIZE - HASH_SIZE, hash, HASH_SIZE);

        const uint32_t* hash_u32 = reinterpret_cast<const uint32_t*>(hash);
        std::memcpy(pt2, hash_u32, 8 * sizeof(uint32_t));



        for (int i = NONCE_SIZE - HASH_SIZE; i >= static_cast<int>(NONCE_SIZE - HASH_CAP + HASH_SIZE); i -= HASH_SIZE) {
            size_t data_start = static_cast<size_t>(i);
            size_t data_len = NONCE_SIZE - data_start;

            if (i % 64 == 0) {
                crypto::Shabal256(buffer + data_start, data_len, nullptr, t1, hash);
            } else {
                crypto::Shabal256(buffer + data_start, data_len, pt2, t2, hash);
            }
            std::memcpy(buffer + i - HASH_SIZE, hash, HASH_SIZE);
        }

        for (int i = NONCE_SIZE - HASH_CAP; i >= static_cast<int>(HASH_SIZE); i -= HASH_SIZE) {
            size_t data_start = static_cast<size_t>(i);
            crypto::Shabal256(buffer + data_start, HASH_CAP, nullptr, t3, hash);
            std::memcpy(buffer + i - HASH_SIZE, hash, HASH_SIZE);
        }

        crypto::Shabal256(buffer, NONCE_SIZE, nullptr, t1, final_buffer);


        for (size_t i = 0; i < NONCE_SIZE; i++) {
            buffer[i] ^= final_buffer[i % HASH_SIZE];
        }

        if (unpack_shuffle_scatter(buffer, NONCE_SIZE,
                                  cache,
                                  cache_size,
                                  cache_offset + n, 1) != 0) {
            std::free(buffer);
            std::free(final_buffer);
            return -4;
        }
    }

    std::free(buffer);
    std::free(final_buffer);
    return 0;
}

} // namespace algorithms
} // namespace pocx
