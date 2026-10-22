// Copyright (c) 2025 The Proof of Capacity Consortium
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <pocx/mining/submission.h>

namespace pocx {
namespace mining {

bool SubmissionValidator::ValidateContext(
    const NonceSubmission& submission,
    const uint256& current_block_hash
) {
    // Block hash uniquely identifies the chain tip — single comparison
    // replaces the old height + generation_signature double-check and
    // also catches same-height reorgs.
    return submission.block_hash == current_block_hash;
}

bool SubmissionValidator::IsBetterThanCurrent(
    uint64_t new_quality,
    std::optional<uint64_t> current_best_quality
) {
    // If no current best, new submission is automatically better
    if (!current_best_quality.has_value()) {
        return true;
    }

    // Lower quality is better in PoC
    return new_quality < current_best_quality.value();
}

} // namespace mining
} // namespace pocx
