// Copyright (c) 2019-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <test/util/mining.h>

#include <chainparams.h>
#include <consensus/merkle.h>
#include <consensus/validation.h>
#include <key_io.h>
#include <node/context.h>
#include <pow.h>
#include <primitives/transaction.h>
#include <test/util/script.h>
#include <util/check.h>
#include <validation.h>
#include <validationinterface.h>
#include <versionbits.h>

#ifdef ENABLE_POCX
#include <hash.h>
#include <pocx/consensus/params.h>
#include <pocx/regtest/forging.h>
#include <util/time.h>
#endif

#include <algorithm>
#include <memory>

using node::BlockAssembler;
using node::NodeContext;

COutPoint generatetoaddress(const NodeContext& node, const std::string& address)
{
    const auto dest = DecodeDestination(address);
    assert(IsValidDestination(dest));
    BlockAssembler::Options assembler_options;
    assembler_options.coinbase_output_script = GetScriptForDestination(dest);

    return MineBlock(node, assembler_options);
}

std::vector<std::shared_ptr<CBlock>> CreateBlockChain(size_t total_height, const CChainParams& params)
{
    std::vector<std::shared_ptr<CBlock>> ret{total_height};
    auto time{params.GenesisBlock().nTime};
#ifdef ENABLE_POCX
    // ForgeRegtestBlock's mocktime-aware branch needs a non-zero mocktime to
    // roll forward across the loop; anchor it at genesis time before we start.
    SetMockTime(std::chrono::seconds{params.GenesisBlock().nTime});
    const uint64_t genesis_base_target = pocx::consensus::CalculateGenesisBaseTarget(
        params.GetConsensus().nPowTargetSpacing,
        params.GetConsensus().fPoCXLowCapacityCalibration);
#endif
    // NOTE: here `height` does not correspond to the block height but the block height - 1.
    for (size_t height{0}; height < total_height; ++height) {
        CBlock& block{*(ret.at(height) = std::make_shared<CBlock>())};

        CMutableTransaction coinbase_tx;
        coinbase_tx.nLockTime = static_cast<uint32_t>(height);
        coinbase_tx.vin.resize(1);
        coinbase_tx.vin[0].prevout.SetNull();
        coinbase_tx.vin[0].nSequence = CTxIn::MAX_SEQUENCE_NONFINAL; // Make sure timelock is enforced.
        coinbase_tx.vout.resize(1);
        coinbase_tx.vout[0].scriptPubKey = P2WSH_OP_TRUE;
        coinbase_tx.vout[0].nValue = GetBlockSubsidy(height + 1, params.GetConsensus());
        coinbase_tx.vin[0].scriptSig = CScript() << (height + 1) << OP_0;
        block.vtx = {MakeTransactionRef(std::move(coinbase_tx))};

        block.nVersion = VERSIONBITS_LAST_OLD_BLOCK_VERSION;
        const CBlock& prev_block = (height >= 1 ? *ret.at(height - 1) : params.GenesisBlock());
        block.hashPrevBlock = prev_block.GetHash();
        block.hashMerkleRoot = BlockMerkleRoot(block);
        block.nTime = ++time;
#ifdef ENABLE_POCX
        // Populate the header fields BlockAssembler would normally fill in,
        // then route through the same hot-path forger as GenerateBlock.
        block.nHeight = static_cast<int>(height + 1);
        block.nBaseTarget = genesis_base_target;
        HashWriter gensig_hasher{};
        gensig_hasher << prev_block.generationSignature;
        gensig_hasher << std::span<const uint8_t>(prev_block.pocxProof.account_id);
        block.generationSignature = gensig_hasher.GetHash();

        std::string err;
        if (!pocx::regtest::ForgeRegtestBlock(block, params.GetConsensus(), prev_block.nTime, err)) {
            assert(false && "CreateBlockChain: ForgeRegtestBlock failed");
        }
        time = block.nTime; // keep `time` in sync with the forger's nTime
#else
        block.nBits = params.GenesisBlock().nBits;
        block.nNonce = 0;

        while (!CheckProofOfWork(block.GetHash(), block.nBits, params.GetConsensus())) {
            ++block.nNonce;
            assert(block.nNonce);
        }
#endif
    }
    return ret;
}

COutPoint MineBlock(const NodeContext& node, const node::BlockAssembler::Options& assembler_options)
{
#ifdef ENABLE_POCX
    // ForgeRegtestBlock requires mocktime on a mockable chain. Bench callers
    // may not set it, so enable it here if not already active.
    if (GetMockTime().count() == 0) SetMockTime(GetTime());
#endif
    auto block = PrepareBlock(node, assembler_options);
    auto valid = MineBlock(node, block);
    assert(!valid.IsNull());
    return valid;
}

struct BlockValidationStateCatcher : public CValidationInterface {
    const uint256 m_hash;
    std::optional<BlockValidationState> m_state;

    BlockValidationStateCatcher(const uint256& hash)
        : m_hash{hash},
          m_state{} {}

protected:
    void BlockChecked(const std::shared_ptr<const CBlock>& block, const BlockValidationState& state) override
    {
        if (block->GetHash() != m_hash) return;
        m_state = state;
    }
};

COutPoint MineBlock(const NodeContext& node, std::shared_ptr<CBlock>& block)
{
#ifndef ENABLE_POCX
    while (!CheckProofOfWork(block->GetHash(), block->nBits, Params().GetConsensus())) {
        ++block->nNonce;
        assert(block->nNonce);
    }
#else
    {
        auto& chainman = *Assert(node.chainman);
        int64_t prev_time{0};
        {
            LOCK(::cs_main);
            const CBlockIndex* pindexPrev = chainman.m_blockman.LookupBlockIndex(block->hashPrevBlock);
            assert(pindexPrev);
            prev_time = pindexPrev->GetBlockTime();
        }
        std::string err;
        if (!pocx::regtest::ForgeRegtestBlock(*block, chainman.GetConsensus(), prev_time, err)) {
            assert(false && "MineBlock: ForgeRegtestBlock failed");
        }
    }
#endif

    return ProcessBlock(node, block);
}

COutPoint ProcessBlock(const NodeContext& node, const std::shared_ptr<CBlock>& block)
{
    auto& chainman{*Assert(node.chainman)};
    const auto old_height = WITH_LOCK(chainman.GetMutex(), return chainman.ActiveHeight());
    bool new_block;
    BlockValidationStateCatcher bvsc{block->GetHash()};
    node.validation_signals->RegisterValidationInterface(&bvsc);
    const bool processed{chainman.ProcessNewBlock(block, true, true, &new_block)};
    const bool duplicate{!new_block && processed};
    assert(!duplicate);
    node.validation_signals->UnregisterValidationInterface(&bvsc);
    node.validation_signals->SyncWithValidationInterfaceQueue();
    const bool was_valid{bvsc.m_state && bvsc.m_state->IsValid()};
    assert(old_height + was_valid == WITH_LOCK(chainman.GetMutex(), return chainman.ActiveHeight()));

    if (was_valid) return {block->vtx[0]->GetHash(), 0};
    return {};
}

std::shared_ptr<CBlock> PrepareBlock(const NodeContext& node,
                                     const BlockAssembler::Options& assembler_options)
{
    auto block = std::make_shared<CBlock>(
        BlockAssembler{Assert(node.chainman)->ActiveChainstate(), Assert(node.mempool.get()), assembler_options}
            .CreateNewBlock()
            ->block);

    LOCK(cs_main);
    block->nTime = Assert(node.chainman)->ActiveChain().Tip()->GetMedianTimePast() + 1;
    block->hashMerkleRoot = BlockMerkleRoot(*block);

    return block;
}
std::shared_ptr<CBlock> PrepareBlock(const NodeContext& node, const CScript& coinbase_scriptPubKey)
{
    BlockAssembler::Options assembler_options;
    assembler_options.coinbase_output_script = coinbase_scriptPubKey;
    ApplyArgsManOptions(*node.args, assembler_options);
    return PrepareBlock(node, assembler_options);
}
