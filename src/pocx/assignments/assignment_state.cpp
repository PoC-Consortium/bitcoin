// Copyright (c) 2025 The Proof of Capacity Consortium
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <pocx/assignments/assignment_state.h>

namespace pocx {
namespace assignments {

std::array<uint8_t, 20> GetEffectiveSigner(
    const std::array<uint8_t, 20>& plotAddress,
    int nHeight,
    const std::optional<ForgingAssignment>& assignment
) {
    if (assignment.has_value() && assignment->IsActiveAtHeight(nHeight)) {
        return assignment->forgingAddress;
    }

    return plotAddress;
}

ForgingState GetAssignmentState(
    int height,
    const std::optional<ForgingAssignment>& assignment
) {
    if (!assignment.has_value()) {
        return ForgingState::UNASSIGNED;
    }
    return assignment->GetStateAtHeight(height);
}

} // namespace assignments
} // namespace pocx
