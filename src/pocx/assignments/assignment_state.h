// Copyright (c) 2025 The Proof of Capacity Consortium
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_POCX_ASSIGNMENTS_ASSIGNMENT_STATE_H
#define BITCOIN_POCX_ASSIGNMENTS_ASSIGNMENT_STATE_H

#include <coins.h>

#include <array>
#include <cstdint>
#include <optional>

namespace pocx {
namespace assignments {

/** Get the effective signer for a plot at a given height. Pure: callers resolve
 *  the assignment in effect via CCoinsViewCache::GetForgingAssignment and pass
 *  it in, keeping the consensus library free of coins-view state access. */
std::array<uint8_t, 20> GetEffectiveSigner(
    const std::array<uint8_t, 20>& plotAddress,
    int nHeight,
    const std::optional<ForgingAssignment>& assignment
);

/** Get the forging state for a plot at a specific height. Pure: assignment is
 *  resolved by the caller (see GetEffectiveSigner). */
ForgingState GetAssignmentState(
    int height,
    const std::optional<ForgingAssignment>& assignment
);

} // namespace assignments
} // namespace pocx

#endif // BITCOIN_POCX_ASSIGNMENTS_ASSIGNMENT_STATE_H
