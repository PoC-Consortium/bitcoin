// Copyright (c) 2025 The Proof of Capacity Consortium
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_POCX_ASSIGNMENTS_OPCODES_H
#define BITCOIN_POCX_ASSIGNMENTS_OPCODES_H

#include <script/script.h>
#include <primitives/transaction.h>
#include <array>
#include <cstdint>

class CCoinsViewCache;

namespace pocx {
namespace assignments {

/** PoCX Assignment/Revocation OP_RETURN-only system */

// Assignment marker (4 bytes: "POCX" = Proof of Capacity neXt)
extern const std::vector<unsigned char> ASSIGNMENT_MARKER;

// Revocation marker (4 bytes: "XCOP" = eXit Capacity OPeration)
extern const std::vector<unsigned char> REVOCATION_MARKER;

/** Create OP_RETURN script for assignment */
CScript CreateAssignmentOpReturn(
    const std::array<uint8_t, 20>& plotAddress,
    const std::array<uint8_t, 20>& forgeAddress);

/** Create OP_RETURN script for revocation */
CScript CreateRevocationOpReturn(
    const std::array<uint8_t, 20>& plotAddress);

/** Check if output is an assignment OP_RETURN */
bool IsAssignmentOpReturn(const CTxOut& output);

/** Check if output is a revocation OP_RETURN */
bool IsRevocationOpReturn(const CTxOut& output);

/** Parse assignment OP_RETURN */
std::optional<std::pair<std::array<uint8_t, 20>, std::array<uint8_t, 20>>>
    ParseAssignmentOpReturn(const CTxOut& output);

/** Parse revocation OP_RETURN */
std::optional<std::array<uint8_t, 20>>
    ParseRevocationOpReturn(const CTxOut& output);

/** Verify transaction is signed by plot owner */
bool VerifyPlotOwnership(
    const CTransaction& tx,
    const std::array<uint8_t, 20>& plotAddress,
    const CCoinsViewCache& view);

} // namespace assignments
} // namespace pocx

#endif // BITCOIN_POCX_ASSIGNMENTS_OPCODES_H

