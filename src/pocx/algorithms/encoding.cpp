// Copyright (c) 2025 The Proof of Capacity Consortium
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <pocx/algorithms/encoding.h>

#include <cstring>
#include <optional>
#include <array>
#include <span>
#include <string_view>

namespace pocx {
namespace algorithms {

namespace {
// Local fixed-length hex decoder (consensus lib cannot depend on util/strencodings).
bool DecodeFixedHex(std::string_view hex, std::span<uint8_t> out)
{
    if (hex.size() != out.size() * 2) return false;
    auto nibble = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    };
    for (size_t i = 0; i < out.size(); ++i) {
        int hi = nibble(hex[i * 2]);
        int lo = nibble(hex[i * 2 + 1]);
        if (hi < 0 || lo < 0) return false;
        out[i] = static_cast<uint8_t>((hi << 4) | lo);
    }
    return true;
}
} // namespace

int DecodeGenerationSignature(const char* hex_string, uint8_t generation_signature[32]) {
    if (!hex_string || !generation_signature) {
        return -1;
    }

    if (std::strlen(hex_string) != 64) {
        return -1;
    }

    if (!DecodeFixedHex(std::string_view(hex_string, 64),
                        std::span<uint8_t>(generation_signature, 32))) {
        return -2;
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
    if (!hex_string || std::strlen(hex_string) != 40) {
        return std::nullopt;
    }

    std::array<uint8_t, 20> result;
    if (!DecodeFixedHex(std::string_view(hex_string, 40), result)) {
        return std::nullopt;
    }
    return result;
}

} // namespace algorithms
} // namespace pocx
