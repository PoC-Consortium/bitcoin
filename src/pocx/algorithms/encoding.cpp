// Copyright (c) 2025 The Proof of Capacity Consortium
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <pocx/algorithms/encoding.h>

#include <cstring>
#include <cstdlib>
#include <optional>
#include <array>

namespace pocx {
namespace algorithms {

int DecodeGenerationSignature(const char* hex_string, uint8_t generation_signature[32]) {
    if (!hex_string || !generation_signature) {
        return -1;
    }

    size_t hex_len = std::strlen(hex_string);
    if (hex_len != 64) {
        return -1;
    }

    for (size_t i = 0; i < 32; i++) {
        char hex_byte[3] = {hex_string[i * 2], hex_string[i * 2 + 1], '\0'};
        char* endptr;
        unsigned long val = std::strtoul(hex_byte, &endptr, 16);

        if (*endptr != '\0' || val > 255) {
            return -2;
        }

        generation_signature[i] = static_cast<uint8_t>(val);
    }

    return 0;
}

void BytesToU32LE(const uint8_t* bytes, size_t byte_count, uint32_t* output) {
    for (size_t i = 0; i < byte_count / 4; i++) {
        output[i] = static_cast<uint32_t>(bytes[i * 4]) |
                   (static_cast<uint32_t>(bytes[i * 4 + 1]) << 8) |
                   (static_cast<uint32_t>(bytes[i * 4 + 2]) << 16) |
                   (static_cast<uint32_t>(bytes[i * 4 + 3]) << 24);
    }
}

void U64ToU32BE(uint64_t value, uint32_t output[2]) {
    // Convert to big-endian, then split into two uint32_t
    uint64_t be_value = ((value & 0xFF00000000000000ULL) >> 56) |
                        ((value & 0x00FF000000000000ULL) >> 40) |
                        ((value & 0x0000FF0000000000ULL) >> 24) |
                        ((value & 0x000000FF00000000ULL) >> 8) |
                        ((value & 0x00000000FF000000ULL) << 8) |
                        ((value & 0x0000000000FF0000ULL) << 24) |
                        ((value & 0x000000000000FF00ULL) << 40) |
                        ((value & 0x00000000000000FFULL) << 56);

    output[0] = static_cast<uint32_t>((be_value >> 32) & 0xFFFFFFFFULL);
    output[1] = static_cast<uint32_t>(be_value & 0xFFFFFFFFULL);
}

std::optional<std::array<uint8_t, 20>> ParseAccountID(const char* hex_string) {
    if (!hex_string) {
        return std::nullopt;
    }

    size_t hex_len = std::strlen(hex_string);
    if (hex_len != 40) {
        return std::nullopt;
    }

    std::array<uint8_t, 20> result;
    for (size_t i = 0; i < 20; i++) {
        char hex_byte[3] = {hex_string[i * 2], hex_string[i * 2 + 1], '\0'};
        char* endptr;
        unsigned long val = std::strtoul(hex_byte, &endptr, 16);

        if (*endptr != '\0' || val > 255) {
            return std::nullopt;
        }

        result[i] = static_cast<uint8_t>(val);
    }

    return result;
}

} // namespace algorithms
} // namespace pocx
