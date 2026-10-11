// Copyright (c) 2025 The Proof of Capacity Consortium
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <pocx/algorithms/quality.h>
#include <pocx/algorithms/plot_generation.h>
#include <pocx/algorithms/encoding.h>
#include <pocx/crypto/shabal256.h>
#include <pocx/crypto/shabal256_lite.h>

#include <array>
#include <mutex>
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

static int CalculateQualityUncached(
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

// Cache only successfully computed qualities, keyed by every calculation input.
// Proof signatures, claimed qualities and deadlines still require their normal checks.
// Keep memory bounded and perform expensive nonce generation outside the mutex.
namespace {
struct QualityInput {
    uint64_t height;
    uint64_t nonce;
    uint32_t compression;
    std::array<uint8_t, 20> account;
    std::array<uint8_t, 32> seed;
    std::array<uint8_t, 32> generation_signature;
    bool operator==(const QualityInput&) const = default;
};
class QualityCache {
    struct Entry {
        QualityInput input{};
        uint64_t quality{0};
        bool valid{false};
    };
    std::array<Entry, 512> entries{};
    size_t next{0};
    std::mutex mutex;
public:
    bool Find(const QualityInput& input, uint64_t& quality)
    {
        std::lock_guard guard(mutex);
        for (size_t i = 0; i < entries.size(); ++i) {
            const auto& entry = entries[(next + entries.size() - 1 - i) % entries.size()];
            if (entry.valid && entry.input == input) {
                quality = entry.quality;
                return true;
            }
        }
        return false;
    }
    void Store(const QualityInput& input, uint64_t quality)
    {
        std::lock_guard guard(mutex);
        entries[next] = {input, quality, true};
        next = (next + 1) % entries.size();
    }
};
} // namespace

int CalculateQuality(
    const uint8_t address_payload[20], const uint8_t seed[32], uint64_t nonce,
    uint32_t compression, uint64_t height, const uint8_t generation_sig[32], uint64_t* quality)
{
    if (!address_payload || !seed || !generation_sig || !quality) return -1;
    QualityInput input{height, nonce, compression, {}, {}, {}};
    std::memcpy(input.account.data(), address_payload, input.account.size());
    std::memcpy(input.seed.data(), seed, input.seed.size());
    std::memcpy(input.generation_signature.data(), generation_sig, input.generation_signature.size());
    static QualityCache cache;
    if (cache.Find(input, *quality)) return 0;
    const int result = CalculateQualityUncached(address_payload, seed, nonce, compression, height, generation_sig, quality);
    if (result == 0) cache.Store(input, *quality);
    return result;
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
