// Copyright (c) 2025 The Proof of Capacity Consortium
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_POCX_MINING_BLOCK_CONTEXT_H
#define BITCOIN_POCX_MINING_BLOCK_CONTEXT_H

#include <uint256.h>
#include <cstdint>

class ChainstateManager;

namespace pocx {
namespace mining {

/** Context data for new block mining/validation */
struct NewBlockContext {
    int height;
    uint256 generation_signature;
    uint64_t base_target;
    uint256 block_hash;
};

/** Get context for new block mining/validation */
NewBlockContext GetNewBlockContext(const ChainstateManager& chainman);

} // namespace mining
} // namespace pocx

#endif // BITCOIN_POCX_MINING_BLOCK_CONTEXT_H
