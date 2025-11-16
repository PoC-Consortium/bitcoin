// Copyright (c) 2025 The Proof of Capacity Consortium
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_POCX_CONSENSUS_VALIDATION_H
#define BITCOIN_POCX_CONSENSUS_VALIDATION_H

#include <array>
#include <cstdint>
#include <limits>

// Include Bitcoin Core headers for complete type definitions
class CTransaction;
class TxValidationState;
class CCoinsViewCache;
class CTxMemPool;
enum class ForgingState : uint8_t; // Forward declaration from coins.h
namespace Consensus { struct Params; }

namespace pocx {
namespace consensus {

/** Validation result structure for native C++ validation */
struct ValidationResult {
    bool is_valid;
    int32_t error_code;
    uint64_t quality;
    uint64_t deadline;

    ValidationResult() : is_valid(false), error_code(-1), quality(0), deadline(std::numeric_limits<uint64_t>::max()) {}
};

/** Error codes for validation operations */
enum ValidationError {
    VALIDATION_SUCCESS = 0,
    VALIDATION_ERROR_NULL_POINTER = -1,
    VALIDATION_ERROR_INVALID_INPUT = -2,
    VALIDATION_ERROR_GENERATION_SIGNATURE_PARSE = -100,
    VALIDATION_ERROR_GENERATION_SIGNATURE_DECODE = -101,
    VALIDATION_ERROR_QUALITY_CALCULATION = -106
};

/** Native C++ implementation of PoCX block validation */
bool pocx_validate_block(
    const char* generation_signature_hex,
    uint64_t base_target,
    const uint8_t account_payload[20],
    uint64_t block_height,
    uint64_t nonce,
    const uint8_t seed[32],
    uint32_t compression,
    ValidationResult* result
);

// NOTE: GetEffectiveSigner and GetPlotForgingState have been moved to
// pocx/assignments/assignment_state.h for better separation of stateless/stateful validation

} // namespace consensus
} // namespace pocx

#endif // BITCOIN_POCX_CONSENSUS_VALIDATION_H