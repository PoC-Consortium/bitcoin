// Copyright (c) 2025 The Proof of Capacity Consortium
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_POCX_CONSENSUS_DIFFICULTY_H
#define BITCOIN_POCX_CONSENSUS_DIFFICULTY_H

#include <primitives/block.h>
#include <uint256.h>
#include <consensus/params.h>
#include <array>
#include <cstdint>

class CBlockIndex;
class CScript;

namespace pocx {
namespace consensus {


/** Get next base target (difficulty adjustment) */
uint64_t GetNextBaseTarget(const CBlockIndex* pindexLast, const Consensus::Params& params);

/** Whether a base target step between consecutive blocks is within the per-block
 *  ±20% envelope GetNextBaseTarget enforces. Used as the headers-sync analog of
 *  PermittedDifficultyTransition to bound claimed per-header work. */
bool PermittedBaseTargetTransition(uint64_t prev_base_target, uint64_t new_base_target);

/** Get next generation signature (deterministic, transaction-independent) */
uint256 GetNextGenerationSignature(const CBlockIndex* pindexLast);
uint256 GetNextGenerationSignature(const uint256& prev_generation_signature, const std::array<uint8_t, 20>& prev_account_id);

/** Whether a header's generation signature is the one derived from its predecessor. */
bool PermittedGenerationSignatureTransition(const uint256& prev_generation_signature,
                                            const std::array<uint8_t, 20>& prev_account_id,
                                            const uint256& generation_signature);

/** Whether a header's time does not go backwards and its claimed deadline fits the
 *  elapsed time since the predecessor. base_target must be > 0. */
bool PermittedTimingTransition(uint32_t prev_time, uint32_t time, uint64_t quality,
                               uint64_t base_target, int64_t target_spacing);


} // namespace consensus
} // namespace pocx

#endif // BITCOIN_POCX_CONSENSUS_DIFFICULTY_H

