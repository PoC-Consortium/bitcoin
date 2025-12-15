// Copyright (c) 2025 The Proof of Capacity Consortium
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <pocx/algorithms/plot_generation.h>
#include <pocx/algorithms/encoding.h>
#include <pocx/crypto/shabal256.h>
#ifdef ENABLE_AVX2
#include <pocx/crypto/shabal256_avx2.h>
#endif
#ifdef ENABLE_SSE2
#include <pocx/crypto/shabal256_sse2.h>
#endif

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

#ifdef ENABLE_AVX2

int GenerateNonces8_avx2(
    uint8_t* buffers[8],
    const uint8_t* account_ids[8],
    const uint8_t* seeds[8],
    const uint64_t nonces[8]
) {
    // Validate inputs
    for (int lane = 0; lane < 8; lane++) {
        if (!buffers[lane] || !account_ids[lane] || !seeds[lane]) {
            return -1;
        }
    }

    // Prepare per-lane data
    uint32_t payload_bytes[8][5];
    uint32_t seed_u32[8][8];
    uint32_t nonce_u32[8][2];

    for (int lane = 0; lane < 8; lane++) {
        BytesToU32LE(account_ids[lane], 20, payload_bytes[lane]);
        BytesToU32LE(seeds[lane], 32, seed_u32[lane]);
        U64ToU32BE(nonces[lane], nonce_u32[lane]);
    }

    // Prepare termination blocks for each lane
    uint32_t t1[8][MESSAGE_SIZE];
    uint32_t t2[8][MESSAGE_SIZE];
    uint32_t pt2[8][MESSAGE_SIZE];
    uint32_t t3[8][MESSAGE_SIZE];

    for (int lane = 0; lane < 8; lane++) {
        std::memset(t1[lane], 0, sizeof(t1[lane]));
        std::memset(t2[lane], 0, sizeof(t2[lane]));
        std::memset(pt2[lane], 0, sizeof(pt2[lane]));
        std::memset(t3[lane], 0, sizeof(t3[lane]));

        std::memcpy(t1[lane], seed_u32[lane], 8 * sizeof(uint32_t));
        std::memcpy(t1[lane] + 8, payload_bytes[lane], 5 * sizeof(uint32_t));
        t1[lane][13] = nonce_u32[lane][1];
        t1[lane][14] = nonce_u32[lane][0];
        t1[lane][15] = 0x80;

        std::memcpy(t2[lane], payload_bytes[lane], 5 * sizeof(uint32_t));
        t2[lane][5] = nonce_u32[lane][1];
        t2[lane][6] = nonce_u32[lane][0];
        t2[lane][7] = 0x80;

        std::memcpy(pt2[lane] + 8, seed_u32[lane], 8 * sizeof(uint32_t));

        t3[lane][0] = 0x80;
    }

    // Allocate buffers for 8-way parallel processing
    uint8_t hash[8][HASH_SIZE];
    uint8_t final_hash[8][HASH_SIZE];

    // Set up pointer arrays for AVX2 calls
    const uint8_t* data_ptrs[8];
    const uint32_t* pre_term_ptrs[8];
    const uint32_t* term_ptrs[8];
    uint8_t* output_ptrs[8];

    // First hash: no data, just t1 termination
    for (int lane = 0; lane < 8; lane++) {
        data_ptrs[lane] = nullptr;
        pre_term_ptrs[lane] = nullptr;
        term_ptrs[lane] = t1[lane];
        output_ptrs[lane] = hash[lane];
    }
    crypto::Shabal256_avx2(data_ptrs, 0, pre_term_ptrs, term_ptrs, output_ptrs);

    // Store first hash and prepare pt2 for each lane
    for (int lane = 0; lane < 8; lane++) {
        std::memcpy(buffers[lane] + NONCE_SIZE - HASH_SIZE, hash[lane], HASH_SIZE);
        const uint32_t* hash_u32 = reinterpret_cast<const uint32_t*>(hash[lane]);
        std::memcpy(pt2[lane], hash_u32, 8 * sizeof(uint32_t));
    }

    // Main loop: generate hashes from NONCE_SIZE-HASH_SIZE down to NONCE_SIZE-HASH_CAP+HASH_SIZE
    for (int i = NONCE_SIZE - HASH_SIZE; i >= static_cast<int>(NONCE_SIZE - HASH_CAP + HASH_SIZE); i -= HASH_SIZE) {
        size_t data_start = static_cast<size_t>(i);
        size_t data_len = NONCE_SIZE - data_start;

        if (i % 64 == 0) {
            // Use t1 termination, no pre-term
            for (int lane = 0; lane < 8; lane++) {
                data_ptrs[lane] = buffers[lane] + data_start;
                pre_term_ptrs[lane] = nullptr;
                term_ptrs[lane] = t1[lane];
                output_ptrs[lane] = hash[lane];
            }
        } else {
            // Use t2 termination with pt2 pre-term
            for (int lane = 0; lane < 8; lane++) {
                data_ptrs[lane] = buffers[lane] + data_start;
                pre_term_ptrs[lane] = pt2[lane];
                term_ptrs[lane] = t2[lane];
                output_ptrs[lane] = hash[lane];
            }
        }

        crypto::Shabal256_avx2(data_ptrs, data_len, pre_term_ptrs, term_ptrs, output_ptrs);

        for (int lane = 0; lane < 8; lane++) {
            std::memcpy(buffers[lane] + i - HASH_SIZE, hash[lane], HASH_SIZE);
        }
    }

    // Second loop: from NONCE_SIZE-HASH_CAP down to HASH_SIZE
    for (int i = NONCE_SIZE - HASH_CAP; i >= static_cast<int>(HASH_SIZE); i -= HASH_SIZE) {
        size_t data_start = static_cast<size_t>(i);

        for (int lane = 0; lane < 8; lane++) {
            data_ptrs[lane] = buffers[lane] + data_start;
            pre_term_ptrs[lane] = nullptr;
            term_ptrs[lane] = t3[lane];
            output_ptrs[lane] = hash[lane];
        }

        crypto::Shabal256_avx2(data_ptrs, HASH_CAP, pre_term_ptrs, term_ptrs, output_ptrs);

        for (int lane = 0; lane < 8; lane++) {
            std::memcpy(buffers[lane] + i - HASH_SIZE, hash[lane], HASH_SIZE);
        }
    }

    // Final hash: hash entire nonce buffer
    for (int lane = 0; lane < 8; lane++) {
        data_ptrs[lane] = buffers[lane];
        pre_term_ptrs[lane] = nullptr;
        term_ptrs[lane] = t1[lane];
        output_ptrs[lane] = final_hash[lane];
    }
    crypto::Shabal256_avx2(data_ptrs, NONCE_SIZE, pre_term_ptrs, term_ptrs, output_ptrs);

    // XOR final hash across entire buffer
    for (int lane = 0; lane < 8; lane++) {
        for (size_t i = 0; i < NONCE_SIZE; i++) {
            buffers[lane][i] ^= final_hash[lane][i % HASH_SIZE];
        }
    }

    // Shuffle each nonce to match plot file layout (same as GenerateNonces)
    // This rearranges scoops so that scoop N is at offset N * SCOOP_SIZE
    auto temp_buffer = static_cast<uint8_t*>(std::malloc(NONCE_SIZE));
    if (!temp_buffer) {
        return -2;
    }

    for (int lane = 0; lane < 8; lane++) {
        // Copy raw nonce to temp
        std::memcpy(temp_buffer, buffers[lane], NONCE_SIZE);

        // Apply shuffle: scatter from temp to buffer
        // For single nonce: target_nonce_count=1, target_offset=0, vector_size=1
        if (unpack_shuffle_scatter(temp_buffer, NONCE_SIZE,
                                   buffers[lane], NONCE_SIZE,
                                   0, 1) != 0) {
            std::free(temp_buffer);
            return -3;
        }
    }

    std::free(temp_buffer);
    return 0;
}

#endif // ENABLE_AVX2

#ifdef ENABLE_SSE2

int GenerateNonces4_sse2(
    uint8_t* buffers[4],
    const uint8_t* account_ids[4],
    const uint8_t* seeds[4],
    const uint64_t nonces[4]
) {
    // Validate inputs
    for (int lane = 0; lane < 4; lane++) {
        if (!buffers[lane] || !account_ids[lane] || !seeds[lane]) {
            return -1;
        }
    }

    // Prepare per-lane data
    uint32_t payload_bytes[4][5];
    uint32_t seed_u32[4][8];
    uint32_t nonce_u32[4][2];

    for (int lane = 0; lane < 4; lane++) {
        BytesToU32LE(account_ids[lane], 20, payload_bytes[lane]);
        BytesToU32LE(seeds[lane], 32, seed_u32[lane]);
        U64ToU32BE(nonces[lane], nonce_u32[lane]);
    }

    // Prepare termination blocks for each lane
    uint32_t t1[4][MESSAGE_SIZE];
    uint32_t t2[4][MESSAGE_SIZE];
    uint32_t pt2[4][MESSAGE_SIZE];
    uint32_t t3[4][MESSAGE_SIZE];

    for (int lane = 0; lane < 4; lane++) {
        std::memset(t1[lane], 0, sizeof(t1[lane]));
        std::memset(t2[lane], 0, sizeof(t2[lane]));
        std::memset(pt2[lane], 0, sizeof(pt2[lane]));
        std::memset(t3[lane], 0, sizeof(t3[lane]));

        std::memcpy(t1[lane], seed_u32[lane], 8 * sizeof(uint32_t));
        std::memcpy(t1[lane] + 8, payload_bytes[lane], 5 * sizeof(uint32_t));
        t1[lane][13] = nonce_u32[lane][1];
        t1[lane][14] = nonce_u32[lane][0];
        t1[lane][15] = 0x80;

        std::memcpy(t2[lane], payload_bytes[lane], 5 * sizeof(uint32_t));
        t2[lane][5] = nonce_u32[lane][1];
        t2[lane][6] = nonce_u32[lane][0];
        t2[lane][7] = 0x80;

        std::memcpy(pt2[lane] + 8, seed_u32[lane], 8 * sizeof(uint32_t));

        t3[lane][0] = 0x80;
    }

    // Allocate buffers for 4-way parallel processing
    uint8_t hash[4][HASH_SIZE];
    uint8_t final_hash[4][HASH_SIZE];

    // Set up pointer arrays for SSE2 calls
    const uint8_t* data_ptrs[4];
    const uint32_t* pre_term_ptrs[4];
    const uint32_t* term_ptrs[4];
    uint8_t* output_ptrs[4];

    // First hash: no data, just t1 termination
    for (int lane = 0; lane < 4; lane++) {
        data_ptrs[lane] = nullptr;
        pre_term_ptrs[lane] = nullptr;
        term_ptrs[lane] = t1[lane];
        output_ptrs[lane] = hash[lane];
    }
    crypto::Shabal256_sse2(data_ptrs, 0, pre_term_ptrs, term_ptrs, output_ptrs);

    // Store first hash and prepare pt2 for each lane
    for (int lane = 0; lane < 4; lane++) {
        std::memcpy(buffers[lane] + NONCE_SIZE - HASH_SIZE, hash[lane], HASH_SIZE);
        const uint32_t* hash_u32 = reinterpret_cast<const uint32_t*>(hash[lane]);
        std::memcpy(pt2[lane], hash_u32, 8 * sizeof(uint32_t));
    }

    // Main loop: generate hashes from NONCE_SIZE-HASH_SIZE down to NONCE_SIZE-HASH_CAP+HASH_SIZE
    for (int i = NONCE_SIZE - HASH_SIZE; i >= static_cast<int>(NONCE_SIZE - HASH_CAP + HASH_SIZE); i -= HASH_SIZE) {
        size_t data_start = static_cast<size_t>(i);
        size_t data_len = NONCE_SIZE - data_start;

        if (i % 64 == 0) {
            // Use t1 termination, no pre-term
            for (int lane = 0; lane < 4; lane++) {
                data_ptrs[lane] = buffers[lane] + data_start;
                pre_term_ptrs[lane] = nullptr;
                term_ptrs[lane] = t1[lane];
                output_ptrs[lane] = hash[lane];
            }
        } else {
            // Use t2 termination with pt2 pre-term
            for (int lane = 0; lane < 4; lane++) {
                data_ptrs[lane] = buffers[lane] + data_start;
                pre_term_ptrs[lane] = pt2[lane];
                term_ptrs[lane] = t2[lane];
                output_ptrs[lane] = hash[lane];
            }
        }

        crypto::Shabal256_sse2(data_ptrs, data_len, pre_term_ptrs, term_ptrs, output_ptrs);

        for (int lane = 0; lane < 4; lane++) {
            std::memcpy(buffers[lane] + i - HASH_SIZE, hash[lane], HASH_SIZE);
        }
    }

    // Second loop: from NONCE_SIZE-HASH_CAP down to HASH_SIZE
    for (int i = NONCE_SIZE - HASH_CAP; i >= static_cast<int>(HASH_SIZE); i -= HASH_SIZE) {
        size_t data_start = static_cast<size_t>(i);

        for (int lane = 0; lane < 4; lane++) {
            data_ptrs[lane] = buffers[lane] + data_start;
            pre_term_ptrs[lane] = nullptr;
            term_ptrs[lane] = t3[lane];
            output_ptrs[lane] = hash[lane];
        }

        crypto::Shabal256_sse2(data_ptrs, HASH_CAP, pre_term_ptrs, term_ptrs, output_ptrs);

        for (int lane = 0; lane < 4; lane++) {
            std::memcpy(buffers[lane] + i - HASH_SIZE, hash[lane], HASH_SIZE);
        }
    }

    // Final hash: hash entire nonce buffer
    for (int lane = 0; lane < 4; lane++) {
        data_ptrs[lane] = buffers[lane];
        pre_term_ptrs[lane] = nullptr;
        term_ptrs[lane] = t1[lane];
        output_ptrs[lane] = final_hash[lane];
    }
    crypto::Shabal256_sse2(data_ptrs, NONCE_SIZE, pre_term_ptrs, term_ptrs, output_ptrs);

    // XOR final hash across entire buffer
    for (int lane = 0; lane < 4; lane++) {
        for (size_t i = 0; i < NONCE_SIZE; i++) {
            buffers[lane][i] ^= final_hash[lane][i % HASH_SIZE];
        }
    }

    // Shuffle each nonce to match plot file layout (same as GenerateNonces)
    // This rearranges scoops so that scoop N is at offset N * SCOOP_SIZE
    auto temp_buffer = static_cast<uint8_t*>(std::malloc(NONCE_SIZE));
    if (!temp_buffer) {
        return -2;
    }

    for (int lane = 0; lane < 4; lane++) {
        // Copy raw nonce to temp
        std::memcpy(temp_buffer, buffers[lane], NONCE_SIZE);

        // Apply shuffle: scatter from temp to buffer
        // For single nonce: target_nonce_count=1, target_offset=0, vector_size=1
        if (unpack_shuffle_scatter(temp_buffer, NONCE_SIZE,
                                   buffers[lane], NONCE_SIZE,
                                   0, 1) != 0) {
            std::free(temp_buffer);
            return -3;
        }
    }

    std::free(temp_buffer);
    return 0;
}

#endif // ENABLE_SSE2

} // namespace algorithms
} // namespace pocx
