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
class ChainstateManager;

namespace pocx {
namespace consensus {


/** Get next base target (difficulty adjustment) */
uint64_t GetNextBaseTarget(const CBlockIndex* pindexLast, const Consensus::Params& params);

/** Get next generation signature (deterministic, transaction-independent) */
uint256 GetNextGenerationSignature(const CBlockIndex* pindexLast);

/** Context data for new block mining/validation */
struct NewBlockContext {
    int height;
    uint256 generation_signature;
    uint64_t base_target;
    uint256 block_hash;
};

/** Get context for new block mining/validation */
NewBlockContext GetNewBlockContext(const ChainstateManager& chainman);


} // namespace consensus
} // namespace pocx

#endif // BITCOIN_POCX_CONSENSUS_DIFFICULTY_H

