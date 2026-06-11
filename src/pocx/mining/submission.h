// Copyright (c) 2025 The Proof of Capacity Consortium
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_POCX_MINING_SUBMISSION_H
#define BITCOIN_POCX_MINING_SUBMISSION_H

#include <primitives/transaction.h>
#include <uint256.h>

#include <chrono>
#include <optional>
#include <string>
#include <vector>

namespace pocx {
namespace mining {

/** Nonce submission for queue processing */
struct NonceSubmission {
    std::string account_id;
    std::string seed;
    uint64_t nonce;
    uint64_t quality;
    uint32_t compression;
    uint256 block_hash;             // Tip block hash (sole staleness indicator)
    std::chrono::steady_clock::time_point submit_time;

    // Optional pool payout split (Q1). Empty => single-output coinbase to the
    // effective signer (legacy). When set, the node builds the coinbase from
    // these outputs and routes any remainder (incl. fees) to the effective signer.
    std::vector<CTxOut> coinbase_outputs;

    NonceSubmission() = default;
    NonceSubmission(const std::string& acc_id, const std::string& s, uint64_t n,
                   uint64_t q, uint32_t c, const uint256& bh)
        : account_id(acc_id), seed(s), nonce(n), quality(q), compression(c),
          block_hash(bh), submit_time(std::chrono::steady_clock::now()) {}
};

/** Submission validation helpers */
class SubmissionValidator {
public:
    /** Validate submission matches current chain context (block_hash is the sole staleness indicator) */
    static bool ValidateContext(
        const NonceSubmission& submission,
        const uint256& current_block_hash
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
