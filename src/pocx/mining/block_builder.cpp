// Copyright (c) 2025 The Proof of Capacity Consortium
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <pocx/mining/block_builder.h>
#include <pocx/assignments/assignment_state.h>
#include <pocx/algorithms/encoding.h>

#include <addresstype.h>
#include <consensus/merkle.h>
#include <key_io.h>
#include <logging.h>
#include <node/context.h>
#include <node/chainstate.h>
#include <script/script.h>
#include <sync.h>
#include <util/strencodings.h>

namespace pocx {
namespace mining {

PoCXBlockBuilder::PoCXBlockBuilder(interfaces::Mining& mining)
    : m_mining(&mining) {
}

CScript PoCXBlockBuilder::CreateCoinbaseScript(const std::string& effective_signer_account) {
    std::vector<uint8_t> effective_signer_bytes = ParseHex(effective_signer_account);
    uint160 hash160(effective_signer_bytes);
    return GetScriptForDestination(WitnessV0KeyHash(hash160));
}

std::unique_ptr<interfaces::BlockTemplate> PoCXBlockBuilder::CreateTemplate(
    const CScript& coinbase_script
) {
    ::node::BlockCreateOptions options;
    options.coinbase_output_script = coinbase_script;
    options.use_mempool = true;

    return m_mining->createNewBlock(options);
}

void PoCXBlockBuilder::FillPoCXProof(
    CBlock& block,
    const std::string& account_id,
    const std::string& seed,
    uint64_t nonce,
    uint64_t quality,
    uint32_t compression
) {
    // Parse and fill account ID
    std::vector<uint8_t> account_bytes = ParseHex(account_id);
    std::copy(account_bytes.begin(), account_bytes.end(), block.pocxProof.account_id.begin());

    // Parse and fill seed
    std::vector<uint8_t> seed_bytes = ParseHex(seed);
    std::copy(seed_bytes.begin(), seed_bytes.end(), block.pocxProof.seed.begin());

    // Fill nonce, quality, compression
    block.pocxProof.nonce = nonce;
    block.pocxProof.quality = quality;
    block.pocxProof.compression = compression;

    // Recalculate merkle root (required after modifying block)
    block.hashMerkleRoot = BlockMerkleRoot(block);
}

std::unique_ptr<CBlock> PoCXBlockBuilder::BuildBlock(
    const std::string& account_id,
    const std::string& seed,
    uint64_t nonce,
    uint64_t quality,
    uint32_t compression,
    node::NodeContext* context
) {
    LogPrintf("PoCX: [BlockBuilder] Building block for account %s (quality=%llu, compression=%u)\n",
             account_id.c_str(), quality, compression);

    // Parse account ID
    auto plot_id = pocx::algorithms::ParseAccountID(account_id.c_str());
    if (!plot_id) {
        LogPrintf("PoCX: [BlockBuilder] Invalid account ID format\n");
        return nullptr;
    }

    // Determine effective signer for coinbase (considering assignments)
    std::string effective_signer_account = account_id;

    if (context && context->chainman) {
        LOCK(cs_main);
        int current_height = context->chainman->ActiveChainstate().m_chain.Height() + 1;
        const CCoinsViewCache& view = context->chainman->ActiveChainstate().CoinsTip();

        // Get effective signer considering assignments
        std::array<uint8_t, 20> signer = pocx::assignments::GetEffectiveSigner(*plot_id, current_height, view);
        effective_signer_account = HexStr(signer);

        LogPrintf("PoCX: [BlockBuilder] Plot: %s, Effective signer: %s at height %d\n",
                  account_id.c_str(),
                  effective_signer_account.c_str(),
                  current_height);
    }

    // Create coinbase script
    CScript coinbase_script = CreateCoinbaseScript(effective_signer_account);

    // Create block template
    std::unique_ptr<interfaces::BlockTemplate> pblocktemplate = CreateTemplate(coinbase_script);

    if (!pblocktemplate) {
        LogPrintf("PoCX: [BlockBuilder] Failed to create block template\n");
        return nullptr;
    }

    // Get block from template
    auto block = std::make_unique<CBlock>(pblocktemplate->getBlock());

    // Fill PoCX proof fields with validated quality and compression
    FillPoCXProof(*block, account_id, seed, nonce, quality, compression);

    LogPrintf("PoCX: [BlockBuilder] Block built successfully (unsigned)\n");

    return block;
}

} // namespace mining
} // namespace pocx
