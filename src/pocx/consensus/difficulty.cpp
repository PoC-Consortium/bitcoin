// Copyright (c) 2025 The Proof of Capacity Consortium
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <pocx/consensus/difficulty.h>
#include <pocx/consensus/params.h>
#include <chain.h>
#include <hash.h>
#include <span.h>
#include <sync.h>
#include <node/chainstate.h>
#include <stdexcept>

namespace pocx {
namespace consensus {


uint64_t GetNextBaseTarget(const CBlockIndex* pindexLast, const Consensus::Params& params) {
    assert(pindexLast != nullptr);

    // Calculate genesis base target (used for block 1 and as cap for adjustments)
    const uint64_t genesis_base_target = pocx::consensus::CalculateGenesisBaseTarget(params.nPowTargetSpacing, params.fPoCXLowCapacityCalibration);

    // If genesis block (height 0), return unchanged genesis base target for block 1
    if (pindexLast->nHeight == 0) {
        return genesis_base_target;
    }

    // From block 2 onwards, use rolling window adjustment

    // Get previous base target
    uint64_t prev_base_target = pindexLast->nBaseTarget;

    // Use GetAncestor for O(1) lookup like Bitcoin
    const int lookback = std::min(params.nPoCXRollingWindowSize, pindexLast->nHeight);
    const CBlockIndex* pindexFirst = pindexLast->GetAncestor(pindexLast->nHeight - lookback + 1);
    assert(pindexFirst);

    // Calculate actual timespan for the window
    int64_t actual_timespan = pindexLast->GetBlockTime() - pindexFirst->GetBlockTime();
    int64_t target_timespan = static_cast<int64_t>(lookback) * params.nPowTargetSpacing;

    // Apply time variance limits (factor 2)
    int64_t min_timespan = target_timespan / 2;
    if (min_timespan == 0) {
        min_timespan = 1; // Prevent division by zero for very short target spacing
    }
    if (actual_timespan < min_timespan) {
        actual_timespan = min_timespan;
    }
    if (actual_timespan > target_timespan * 2) {
        actual_timespan = target_timespan * 2;
    }

    // Calculate average base target over the window
    uint64_t total_base_target = 0;
    const CBlockIndex* walker = pindexLast;
    for (int i = 0; i < lookback && walker; i++) {
        total_base_target += walker->nBaseTarget;
        walker = walker->pprev;
    }
    uint64_t avg_base_target = total_base_target / lookback;

    // Calculate base target adjustment using average
    uint64_t new_base_target = avg_base_target * actual_timespan / target_timespan;

    // Apply adjustment caps (20% up/down as requested)
    uint64_t max_increase = prev_base_target + (prev_base_target / 5); // +20%
    uint64_t max_decrease = prev_base_target - (prev_base_target / 5); // -20%

    if (new_base_target > max_increase) {
        new_base_target = max_increase;
    }
    if (new_base_target < max_decrease) {
        new_base_target = max_decrease;
    }

    // Cap base target at genesis base target (never easier than genesis)
    if (new_base_target > genesis_base_target) {
        new_base_target = genesis_base_target;
    }

    // Ensure base target doesn't go to zero
    if (new_base_target == 0) {
        new_base_target = 1;
    }

    return new_base_target;
}


uint256 GetNextGenerationSignature(const CBlockIndex* pindexLast) {
    assert(pindexLast != nullptr);

    // Standard PoC generation signature calculation:
    // next_gen_sig = hash(current_block_gen_sig + current_block_account_id)

    HashWriter hasher{};

    // Add current block's generation signature
    hasher << pindexLast->generationSignature;

    // Add current block's account ID
    hasher << std::span<const uint8_t>(pindexLast->pocxProof.account_id);

    uint256 next_gen_sig = hasher.GetHash();

    return next_gen_sig;
}

NewBlockContext GetNewBlockContext(const ChainstateManager& chainman) {
    LOCK(cs_main);
    const CBlockIndex* tip = chainman.ActiveTip();
    if (!tip) {
        throw std::runtime_error("Block chain tip is empty");
    }

    return NewBlockContext{
        .height = tip->nHeight + 1,
        .generation_signature = GetNextGenerationSignature(tip),
        .base_target = GetNextBaseTarget(tip, chainman.GetParams().GetConsensus()),
        .block_hash = tip->GetBlockHash()
    };
}

} // namespace consensus
} // namespace pocx

