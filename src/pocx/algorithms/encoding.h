// Copyright (c) 2025 The Proof of Capacity Consortium
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_POCX_ALGORITHMS_ENCODING_H
#define BITCOIN_POCX_ALGORITHMS_ENCODING_H

#include <array>
#include <cstdint>
#include <cstddef>
#include <optional>

namespace pocx {
namespace algorithms {

/** Decode generation signature from hex string */
int DecodeGenerationSignature(const char* hex_string, uint8_t output[32]);

/** Convert byte array to uint32 array in little-endian format */
void BytesToU32LE(const uint8_t* bytes, size_t byte_count, uint32_t* output);

/** Convert uint64 to two uint32 in big-endian format */
void U64ToU32BE(uint64_t value, uint32_t output[2]);

/** Parse account ID from hex string to 20-byte array */
std::optional<std::array<uint8_t, 20>> ParseAccountID(const char* hex_string);

} // namespace algorithms
} // namespace pocx

#endif // BITCOIN_POCX_ALGORITHMS_ENCODING_H
