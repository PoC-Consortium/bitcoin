// Copyright (c) 2025 The Proof of Capacity Consortium
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_POCX_MINING_SUBMISSION_H
#define BITCOIN_POCX_MINING_SUBMISSION_H

#include <uint256.h>

#include <chrono>
#include <optional>
#include <string>

namespace pocx {
namespace mining {

/** Nonce submission for queue processing */
struct NonceSubmission {
    std::string account_id;
    std::string seed;
    uint64_t nonce;
    uint64_t quality;
    uint32_t compression;
    int expected_height;
    uint256 generation_signature;
    std::chrono::steady_clock::time_point submit_time;

    NonceSubmission() = default;
    NonceSubmission(const std::string& acc_id, const std::string& s, uint64_t n,
                   uint64_t q, uint32_t c, int h, const uint256& gs)
        : account_id(acc_id), seed(s), nonce(n), quality(q), compression(c),
          expected_height(h), generation_signature(gs),
          submit_time(std::chrono::steady_clock::now()) {}
};

/** Submission validation helpers */
class SubmissionValidator {
public:
    /** Validate submission matches current chain context */
    static bool ValidateContext(
        const NonceSubmission& submission,
        int current_height,
        const uint256& current_gen_sig
    );

    /** Check if submission is better than current best (lower quality wins) */
    static bool IsBetterThanCurrent(
        uint64_t new_quality,
        std::optional<uint64_t> current_best_quality
    );
};

} // namespace mining
} // namespace pocx

#endif // BITCOIN_POCX_MINING_SUBMISSION_H
