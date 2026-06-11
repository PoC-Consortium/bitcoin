// Copyright (c) 2025 The Proof of Capacity Consortium
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <pocx/mining/block_context.h>
#include <pocx/consensus/difficulty.h>
#include <node/chainstate.h>
#include <sync.h>

#include <stdexcept>

namespace pocx {
namespace mining {

NewBlockContext GetNewBlockContext(const ChainstateManager& chainman) {
    LOCK(cs_main);
    const CBlockIndex* tip = chainman.ActiveTip();
    if (!tip) {
        throw std::runtime_error("Block chain tip is empty");
    }

    return NewBlockContext{
        .height = tip->nHeight + 1,
        .generation_signature = pocx::consensus::GetNextGenerationSignature(tip),
        .base_target = tip->nNextBaseTarget,
        .block_hash = tip->GetBlockHash()
    };
}

} // namespace mining
} // namespace pocx
