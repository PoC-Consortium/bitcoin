// Copyright (c) 2025 The Proof of Capacity Consortium
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <pocx/assignments/opcodes.h>

#include <coins.h>
#include <addresstype.h>

#include <algorithm>

namespace pocx {
namespace assignments {

// Assignment marker (4 bytes: "POCX" = Proof of Capacity neXt)
const std::vector<unsigned char> ASSIGNMENT_MARKER = {0x50, 0x4F, 0x43, 0x58};

// Revocation marker (4 bytes: "XCOP" = eXit Capacity OPeration)
const std::vector<unsigned char> REVOCATION_MARKER = {0x58, 0x43, 0x4F, 0x50};

// ============================================================================
// OP_RETURN Creation Functions
// ============================================================================

CScript CreateAssignmentOpReturn(
    const std::array<uint8_t, 20>& plotAddress,
    const std::array<uint8_t, 20>& forgeAddress)
{
    CScript script;

    // Build OP_RETURN script
    // Format: OP_RETURN <0x2c> <POCX> <plot_addr_20> <forge_addr_20>
    script << OP_RETURN;

    // Build data payload: marker + plot address + forge address
    std::vector<unsigned char> data;
    data.reserve(44);  // 4 + 20 + 20

    // Add POCX marker
    data.insert(data.end(), ASSIGNMENT_MARKER.begin(), ASSIGNMENT_MARKER.end());

    // Add plot address
    data.insert(data.end(), plotAddress.begin(), plotAddress.end());

    // Add forge address
    data.insert(data.end(), forgeAddress.begin(), forgeAddress.end());

    // Push as single data element
    script << data;

    return script;
}

CScript CreateRevocationOpReturn(
    const std::array<uint8_t, 20>& plotAddress)
{
    CScript script;

    // Build OP_RETURN script
    // Format: OP_RETURN <0x18> <XCOP> <plot_addr_20>
    script << OP_RETURN;

    // Build data payload: marker + plot address
    std::vector<unsigned char> data;
    data.reserve(24);  // 4 + 20

    // Add XCOP marker
    data.insert(data.end(), REVOCATION_MARKER.begin(), REVOCATION_MARKER.end());

    // Add plot address
    data.insert(data.end(), plotAddress.begin(), plotAddress.end());

    // Push as single data element
    script << data;

    return script;
}

// ============================================================================
// OP_RETURN Detection Functions
// ============================================================================

bool IsAssignmentOpReturn(const CTxOut& output)
{
    const CScript& script = output.scriptPubKey;

    // Must be OP_RETURN script
    if (script.empty() || script[0] != OP_RETURN) {
        return false;
    }

    // Parse script to extract data
    CScript::const_iterator pc = script.begin() + 1;  // Skip OP_RETURN
    std::vector<unsigned char> data;
    opcodetype opcode;

    // Get data push
    if (!script.GetOp(pc, opcode, data)) {
        return false;
    }

    // Check data size: 4 (marker) + 20 (plot) + 20 (forge) = 44 bytes
    if (data.size() != 44) {
        return false;
    }

    // Check POCX marker
    if (!std::equal(ASSIGNMENT_MARKER.begin(), ASSIGNMENT_MARKER.end(), data.begin())) {
        return false;
    }

    // Should be at end of script (no more ops)
    if (pc != script.end()) {
        return false;
    }

    return true;
}

bool IsRevocationOpReturn(const CTxOut& output)
{
    const CScript& script = output.scriptPubKey;

    // Must be OP_RETURN script
    if (script.empty() || script[0] != OP_RETURN) {
        return false;
    }

    // Parse script to extract data
    CScript::const_iterator pc = script.begin() + 1;  // Skip OP_RETURN
    std::vector<unsigned char> data;
    opcodetype opcode;

    // Get data push
    if (!script.GetOp(pc, opcode, data)) {
        return false;
    }

    // Check data size: 4 (marker) + 20 (plot) = 24 bytes
    if (data.size() != 24) {
        return false;
    }

    // Check XCOP marker
    if (!std::equal(REVOCATION_MARKER.begin(), REVOCATION_MARKER.end(), data.begin())) {
        return false;
    }

    // Should be at end of script (no more ops)
    if (pc != script.end()) {
        return false;
    }

    return true;
}

// ============================================================================
// OP_RETURN Parsing Functions
// ============================================================================

std::optional<std::pair<std::array<uint8_t, 20>, std::array<uint8_t, 20>>>
    ParseAssignmentOpReturn(const CTxOut& output)
{
    if (!IsAssignmentOpReturn(output)) {
        return std::nullopt;
    }

    const CScript& script = output.scriptPubKey;
    CScript::const_iterator pc = script.begin() + 1;  // Skip OP_RETURN
    std::vector<unsigned char> data;
    opcodetype opcode;

    // Get data push (already validated by IsAssignmentOpReturn)
    if (!script.GetOp(pc, opcode, data)) {
        return std::nullopt;
    }

    // Extract plot address (bytes 4-23)
    std::array<uint8_t, 20> plotAddress;
    std::copy(data.begin() + 4, data.begin() + 24, plotAddress.begin());

    // Extract forge address (bytes 24-43)
    std::array<uint8_t, 20> forgeAddress;
    std::copy(data.begin() + 24, data.begin() + 44, forgeAddress.begin());

    return std::make_pair(plotAddress, forgeAddress);
}

std::optional<std::array<uint8_t, 20>>
    ParseRevocationOpReturn(const CTxOut& output)
{
    if (!IsRevocationOpReturn(output)) {
        return std::nullopt;
    }

    const CScript& script = output.scriptPubKey;
    CScript::const_iterator pc = script.begin() + 1;  // Skip OP_RETURN
    std::vector<unsigned char> data;
    opcodetype opcode;

    // Get data push (already validated by IsRevocationOpReturn)
    if (!script.GetOp(pc, opcode, data)) {
        return std::nullopt;
    }

    // Extract plot address (bytes 4-23)
    std::array<uint8_t, 20> plotAddress;
    std::copy(data.begin() + 4, data.begin() + 24, plotAddress.begin());

    return plotAddress;
}

// ============================================================================
// Ownership Verification
// ============================================================================

bool VerifyPlotOwnership(
    const CTransaction& tx,
    const std::array<uint8_t, 20>& plotAddress,
    const CCoinsViewCache& view)
{
    // Check that at least one input is signed by plot owner
    // Bitcoin Core's script validation already verified signatures are valid
    // We just need to check if any input is from the plot address

    for (const auto& input : tx.vin) {
        // Get the coin being spent
        auto coin = view.GetCoin(input.prevout);
        if (!coin.has_value()) {
            continue;  // Shouldn't happen (inputs already validated)
        }

        // Extract destination from scriptPubKey
        CTxDestination dest;
        if (!ExtractDestination(coin->out.scriptPubKey, dest)) {
            continue;  // Not a standard output type
        }

        // Check if this is a P2WPKH to plot address
        if (auto* witness_addr = std::get_if<WitnessV0KeyHash>(&dest)) {
            // Extract 20-byte hash from witness address
            std::array<uint8_t, 20> input_addr;
            std::copy(witness_addr->begin(), witness_addr->end(), input_addr.begin());

            if (input_addr == plotAddress) {
                // Found input controlled by plot owner
                // Signature was already validated by Bitcoin Core
                return true;
            }
        }
    }

    // No input from plot address found
    return false;
}

} // namespace assignments
} // namespace pocx

