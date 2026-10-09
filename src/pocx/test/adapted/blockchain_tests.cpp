// Copyright (c) 2017-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <chain.h>
#include <node/blockstorage.h>
#include <rpc/blockchain.h>
#include <sync.h>
#include <test/util/setup_common.h>
#include <util/string.h>

#include <boost/test/unit_test.hpp>

#include <cstdlib>

// PoCX difficulty is the 1-TiB reference base target divided by the header's
// base target. Independently fixed reference: floor(2^42 / 120) = 36650387592.
// Keep all five original difficulty ranges with PoCX fields instead of nBits.
static void TestDifficulty(uint64_t base_target, double expected)
{
    CBlockIndex block_index;
    block_index.nHeight = 46367;
    block_index.nTime = 1269211443;
    block_index.nBaseTarget = base_target;
    BOOST_CHECK_CLOSE_FRACTION(GetDifficulty(block_index), expected, 1e-12);
}

BOOST_FIXTURE_TEST_SUITE(blockchain_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(get_difficulty_for_very_low_target)
{
    TestDifficulty(36650387592000000ULL, 0.000001);
}
BOOST_AUTO_TEST_CASE(get_difficulty_for_low_target)
{
    TestDifficulty(2401919801229312ULL, 1.0 / 65536);
}
BOOST_AUTO_TEST_CASE(get_difficulty_for_mid_target)
{
    TestDifficulty(9382499223552ULL, 1.0 / 256);
}
BOOST_AUTO_TEST_CASE(get_difficulty_for_high_target)
{
    TestDifficulty(18325193796ULL, 2.0);
}
BOOST_AUTO_TEST_CASE(get_difficulty_for_very_high_target)
{
    TestDifficulty(1, 36650387592.0);
}
BOOST_AUTO_TEST_CASE(get_difficulty_invalid_and_reference_target)
{
    CBlockIndex block_index;
    block_index.nBaseTarget = 0;
    BOOST_CHECK_EQUAL(GetDifficulty(block_index), 0.0);
    TestDifficulty(36650387592ULL, 1.0);
    TestDifficulty(UINT64_MAX, 36650387592.0 / 18446744073709551615.0);
}

//! Prune chain from height down to genesis block and check that
//! GetPruneHeight returns the correct value
static void CheckGetPruneHeight(const node::BlockManager& blockman, const CChain& chain, int height) EXCLUSIVE_LOCKS_REQUIRED(::cs_main)
{
    AssertLockHeld(::cs_main);

    // Emulate pruning all blocks from `height` down to the genesis block
    // by unsetting the `BLOCK_HAVE_DATA` flag from `nStatus`
    for (CBlockIndex* it{chain[height]}; it != nullptr && it->nHeight > 0; it = it->pprev) {
        it->nStatus &= ~BLOCK_HAVE_DATA;
    }

    const auto prune_height{GetPruneHeight(blockman, chain)};
    BOOST_REQUIRE(prune_height.has_value());
    BOOST_CHECK_EQUAL(*prune_height, height);
}

BOOST_FIXTURE_TEST_CASE(get_prune_height, TestChain100Setup)
{
    LOCK(::cs_main);
    const auto& chain = m_node.chainman->ActiveChain();
    const auto& blockman = m_node.chainman->m_blockman;

    // Fresh chain of 100 blocks without any pruned blocks, so std::nullopt should be returned
    BOOST_CHECK(!GetPruneHeight(blockman, chain).has_value());

    // Start pruning
    CheckGetPruneHeight(blockman, chain, 1);
    CheckGetPruneHeight(blockman, chain, 99);
    CheckGetPruneHeight(blockman, chain, 100);
}

BOOST_AUTO_TEST_CASE(num_chain_tx_max)
{
    CBlockIndex block_index{};
    block_index.m_chain_tx_count = std::numeric_limits<uint64_t>::max();
    BOOST_CHECK_EQUAL(block_index.m_chain_tx_count, std::numeric_limits<uint64_t>::max());
}

BOOST_FIXTURE_TEST_CASE(invalidate_block, TestChain100Setup)
{
    const CChain& active{*WITH_LOCK(Assert(m_node.chainman)->GetMutex(), return &Assert(m_node.chainman)->ActiveChain())};

    // Check BlockStatus when doing InvalidateBlock()
    BlockValidationState state;
    auto* orig_tip = active.Tip();
    int height_to_invalidate = orig_tip->nHeight - 10;
    auto* tip_to_invalidate = active[height_to_invalidate];
    m_node.chainman->ActiveChainstate().InvalidateBlock(state, tip_to_invalidate);

    // tip_to_invalidate just got invalidated, so it's BLOCK_FAILED_VALID
    WITH_LOCK(::cs_main, assert(tip_to_invalidate->nStatus & BLOCK_FAILED_VALID));

    // check all ancestors of the invalidated block are validated up to BLOCK_VALID_TRANSACTIONS and are not invalid
    auto pindex = tip_to_invalidate->pprev;
    while (pindex) {
        WITH_LOCK(::cs_main, assert(pindex->IsValid(BLOCK_VALID_TRANSACTIONS)));
        WITH_LOCK(::cs_main, assert((pindex->nStatus & BLOCK_FAILED_VALID) == 0));
        pindex = pindex->pprev;
    }

    // check all descendants of the invalidated block are BLOCK_FAILED_VALID
    pindex = orig_tip;
    while (pindex && pindex != tip_to_invalidate) {
        WITH_LOCK(::cs_main, assert(pindex->nStatus & BLOCK_FAILED_VALID));
        pindex = pindex->pprev;
    }
}

BOOST_AUTO_TEST_SUITE_END()
