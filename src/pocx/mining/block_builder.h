// Copyright (c) 2025 The Proof of Capacity Consortium
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_POCX_MINING_BLOCK_BUILDER_H
#define BITCOIN_POCX_MINING_BLOCK_BUILDER_H

#include <primitives/block.h>
#include <interfaces/mining.h>

#include <memory>
#include <string>
#include <vector>

namespace node {
struct NodeContext;
}

namespace pocx {
namespace mining {

/** PoCX Block Builder - creates templates and fills proof fields (no signing/submission) */
class PoCXBlockBuilder {
private:
    interfaces::Mining* m_mining;

    /** Create coinbase output script for effective signer */
    CScript CreateCoinbaseScript(const std::string& effective_signer_account);

    /** Create block template using Bitcoin Core */
    std::unique_ptr<interfaces::BlockTemplate> CreateTemplate(
        const CScript& coinbase_script
    );

    /** Replace the template coinbase's payout output with a pool payout split.
     *  Keeps the template's other coinbase outputs (e.g. the witness commitment),
     *  routes any remainder (template payout value - sum of outputs, which includes
     *  fees) to the effective signer, and rejects if the outputs exceed the
     *  available coinbase value. Returns false (and leaves the block unchanged)
     *  on error. */
    bool ApplyCoinbaseOutputs(
        CBlock& block,
        const std::vector<CTxOut>& coinbase_outputs,
        const std::string& effective_signer_account
    );

    /** Fill in PoCX proof fields and recalculate merkle root */
    void FillPoCXProof(
        CBlock& block,
        const std::string& account_id,
        const std::string& seed,
        uint64_t nonce,
        uint64_t quality,
        uint32_t compression
    );

public:
    explicit PoCXBlockBuilder(interfaces::Mining& mining);

    /** Build complete PoCX block (unsigned, ready for signing) */
    std::unique_ptr<CBlock> BuildBlock(
        const std::string& account_id,
        const std::string& seed,
        uint64_t nonce,
        uint64_t quality,
        uint32_t compression,
        node::NodeContext* context,
        const std::vector<CTxOut>& coinbase_outputs = {}
    );
};

} // namespace mining
} // namespace pocx

#endif // BITCOIN_POCX_MINING_BLOCK_BUILDER_H
