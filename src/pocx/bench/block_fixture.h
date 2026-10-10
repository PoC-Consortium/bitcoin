// Copyright (c) 2026 The Bitcoin PoCX developers
// Distributed under the MIT software license; see COPYING.
#ifndef BITCOIN_POCX_BENCH_BLOCK_FIXTURE_H
#define BITCOIN_POCX_BENCH_BLOCK_FIXTURE_H

#include <bench/data/block413567.raw.h>
#include <consensus/merkle.h>
#include <consensus/consensus.h>
#include <consensus/validation.h>
#include <pocx/test/util/bitcoin_block_fixture.h>
#include <pocx/test/util/forging.h>
#include <test/util/setup_common.h>
#include <validation.h>

#include <cassert>

namespace pocx::bench {

// Benchmark native serialization and validation with a signed regtest header
// and the original near-limit historical transaction workload.
// CheckBlock is context-free: these historical spends are not submitted to the
// regtest chain, whose UTXO set naturally differs from Bitcoin mainnet's.
inline CBlock MakeHistoricalTransactionBlock(const TestingSetup& setup)
{
    DataStream original{benchmark::data::block413567};
    CBlock block;
    ReadBitcoinBlockFixture(original, block);
    assert(original.empty());
    const auto original_merkle = block.hashMerkleRoot;
    assert(BlockMerkleRoot(block) == original_merkle);
    assert(block.vtx.size() == 1557);
    // Bitcoin's fixture is 999887 bytes. The native header adds 206 bytes,
    // exceeding the unchanged block-weight limit. Remove only the final
    // 520-byte transaction; all other 1556 transaction encodings are retained.
    // ForgeTestBlock recomputes the merkle root and signs the resulting body.
    assert(GetBlockWeight(block) > MAX_BLOCK_WEIGHT);
    assert(GetSerializeSize(TX_WITH_WITNESS(*block.vtx.back())) == 520);
    block.vtx.pop_back();
    assert(GetBlockWeight(block) <= MAX_BLOCK_WEIGHT);
    const auto native_merkle = BlockMerkleRoot(block);
    auto& chainman = *setup.m_node.chainman;
    {
        LOCK(cs_main);
        ForgeTestBlock(block, *chainman.ActiveChain().Tip(), chainman.GetConsensus());
    }
    assert(block.hashMerkleRoot == native_merkle);
    BlockValidationState state;
    assert(CheckBlock(block, state, chainman.GetConsensus()));

    // Ensure the fixture really exercises native header validation. A changed
    // signature must fail even though the historical transaction body is valid.
    CBlockHeader bad_header{block};
    bad_header.nTime ^= 1;
    BlockValidationState bad_state;
    assert(!CheckBlockHeader(bad_header, bad_state, chainman.GetConsensus()));
    assert(bad_state.GetRejectReason() == "bad-pocx-sig");
    return block;
}
} // namespace pocx::bench
#endif // BITCOIN_POCX_BENCH_BLOCK_FIXTURE_H
