// Copyright (c) 2025 The Proof of Capacity Consortium
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <pocx/assignments/assignment_state.h>

#include <coins.h>
#include <logging.h>
#include <util/strencodings.h>

namespace pocx {
namespace assignments {

std::array<uint8_t, 20> GetEffectiveSigner(
    const std::array<uint8_t, 20>& plotAddress,
    int nHeight,
    const CCoinsViewCache& view
) {
    LogDebug(BCLog::POCX, "GetEffectiveSigner called for plot %s at height %d\n",
             HexStr(plotAddress).c_str(), nHeight);

    // Get current assignment for this plot address (OP_RETURN-only architecture)
    auto assignment = view.GetForgingAssignment(plotAddress, nHeight);

    if (assignment.has_value() && assignment->IsActiveAtHeight(nHeight)) {
        LogDebug(BCLog::POCX, "Found active assignment - returning forging address %s\n",
                 HexStr(assignment->forgingAddress).c_str());
        // Plot is assigned to another address
        return assignment->forgingAddress;
    } else {
        LogDebug(BCLog::POCX, "No active assignment - returning plot address itself: %s\n",
                 HexStr(plotAddress).c_str());
    }

    // No active assignment - the plot owner signs
    return plotAddress;
}

ForgingState GetAssignmentState(
    const std::array<uint8_t, 20>& plotAddress,
    int height,
    const CCoinsViewCache& view
) {
    auto assignment = view.GetForgingAssignment(plotAddress, height);
    if (!assignment.has_value()) {
        return ForgingState::UNASSIGNED;
    }
    return assignment->GetStateAtHeight(height);
}

} // namespace assignments
} // namespace pocx
