// Copyright (c) 2025 The Proof of Capacity Consortium
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <pocx/consensus/proof.h>
#include <pocx/algorithms/quality.h>
#include <pocx/algorithms/encoding.h>

#include <cstring>
#include <limits>

namespace pocx {
namespace consensus {

/**
 * Native C++ implementation of PoCX block validation
 */
bool pocx_validate_block(
    const char* generation_signature_hex,
    uint64_t base_target,
    const uint8_t account_payload[20],
    uint64_t block_height,
    uint64_t nonce,
    const uint8_t seed[32],
    uint32_t compression,
    ValidationResult* result
) {

    // Validate input pointers
    if (!generation_signature_hex || !account_payload || !seed || !result) {
        return false;
    }

    // Initialize result with error state
    result->is_valid = false;
    result->error_code = -1;
    result->quality = 0;
    result->deadline = std::numeric_limits<uint64_t>::max();

    // Parse and decode generation signature from hex string
    uint8_t generation_signature[32];
    int decode_result = pocx::algorithms::DecodeGenerationSignature(generation_signature_hex, generation_signature);
    if (decode_result != 0) {
        // Generation signature decode failed
        if (decode_result == -1) {
            result->error_code = VALIDATION_ERROR_GENERATION_SIGNATURE_PARSE; // -100
        } else {
            result->error_code = VALIDATION_ERROR_GENERATION_SIGNATURE_DECODE; // -101
        }
        return false;
    }

    // Copy account payload (20 bytes) for safety
    uint8_t address_payload_copy[20];
    std::memcpy(address_payload_copy, account_payload, 20);

    // Copy seed (32 bytes) for safety
    uint8_t seed_copy[32];
    std::memcpy(seed_copy, seed, 32);

    // PoCX Validation: Calculate quality at specific compression level
    uint64_t quality;
    int quality_result = pocx::algorithms::CalculateQuality(
        address_payload_copy,
        seed_copy,
        nonce,
        compression,
        block_height,
        generation_signature,
        &quality
    );

    if (quality_result != 0) {
        // Quality calculation failed
        result->error_code = VALIDATION_ERROR_QUALITY_CALCULATION; // -106
        return false;
    }

    // PoCX Validation Step 3: Calculate deadline
    uint64_t deadline;
    if (base_target > 0) {
        deadline = quality / base_target;
    } else {
        deadline = std::numeric_limits<uint64_t>::max();
    }

    // Populate successful result
    result->is_valid = true;
    result->error_code = VALIDATION_SUCCESS; // 0
    result->quality = quality;
    result->deadline = deadline;

    return true;
}

// NOTE: GetEffectiveSigner and GetPlotForgingState have been moved to
// pocx/validation/assignments.cpp for better separation of stateless/stateful validation

} // namespace consensus
} // namespace pocx