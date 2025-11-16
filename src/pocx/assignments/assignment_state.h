// Copyright (c) 2025 The Proof of Capacity Consortium
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_POCX_ASSIGNMENTS_ASSIGNMENT_STATE_H
#define BITCOIN_POCX_ASSIGNMENTS_ASSIGNMENT_STATE_H

#include <array>
#include <cstdint>

class CCoinsViewCache;
enum class ForgingState : uint8_t;

namespace pocx {
namespace assignments {

/** Get the effective signer for a plot at a given height (considers forging assignments) */
std::array<uint8_t, 20> GetEffectiveSigner(
    const std::array<uint8_t, 20>& plotAddress,
    int nHeight,
    const CCoinsViewCache& view
);

/** Get the forging state for a plot address at a specific height */
ForgingState GetAssignmentState(
    const std::array<uint8_t, 20>& plotAddress,
    int height,
    const CCoinsViewCache& view
);

} // namespace assignments
} // namespace pocx

#endif // BITCOIN_POCX_ASSIGNMENTS_ASSIGNMENT_STATE_H
