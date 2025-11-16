// Copyright (c) 2025 The Proof of Capacity Consortium
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <pocx/mining/submission.h>

namespace pocx {
namespace mining {

bool SubmissionValidator::ValidateContext(
    const NonceSubmission& submission,
    int current_height,
    const uint256& current_gen_sig
) {
    // Check if submission is stale (height mismatch)
    if (submission.expected_height != current_height) {
        return false;
    }

    // Check if generation signature matches (context validation)
    if (submission.generation_signature != current_gen_sig) {
        return false;
    }

    return true;
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
