// Copyright (c) 2025 The Proof of Capacity Consortium
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_POCX_CONSENSUS_DIFFICULTY_H
#define BITCOIN_POCX_CONSENSUS_DIFFICULTY_H

#include <primitives/block.h>
#include <uint256.h>
#include <consensus/params.h>
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


} // namespace consensus
} // namespace pocx

#endif // BITCOIN_POCX_CONSENSUS_DIFFICULTY_H

