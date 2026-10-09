// Copyright (c) 2015-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

// Applicable cases from src/test/pow_tests.cpp. The nine Bitcoin PoW/retarget
// cases and Bitcoin-Testnet4-specific case are explicitly accounted for in
// test/pocx/unit-parity.json, rather than silently disabled here.
#include <chain.h>
#include <chainparams.h>
#include <consensus/amount.h>
#include <test/util/common.h>
#include <test/util/random.h>
#include <test/util/setup_common.h>
#include <util/chaintype.h>

#include <boost/test/unit_test.hpp>

#include <limits>

BOOST_FIXTURE_TEST_SUITE(pow_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(GetBlockProofEquivalentTime_test)
{
    const auto chainParams = CreateChainParams(*m_node.args, ChainType::MAIN);
    std::vector<CBlockIndex> blocks(10000);
    // Distinct required/next targets exercise the native actual-work branch.
    constexpr uint64_t BASE_TARGET{1ULL << 18};
    constexpr uint64_t NEXT_TARGET{1ULL << 20};
    const arith_uint256 expected_work{1ULL << 44}; // 2^64 / 2^20
    for (int i = 0; i < 10000; i++) {
        blocks[i].pprev = i ? &blocks[i - 1] : nullptr;
        blocks[i].nHeight = i;
        blocks[i].nTime = 1269211443 + i * chainParams->GetConsensus().nPowTargetSpacing;
        blocks[i].nBaseTarget = BASE_TARGET;
        blocks[i].nNextBaseTarget = NEXT_TARGET;
        BOOST_CHECK(GetBlockProof(blocks[i]) == expected_work);
        blocks[i].nChainWork = i ? blocks[i - 1].nChainWork + GetBlockProof(blocks[i - 1]) : arith_uint256(0);
    }

    // Preserve the original 10,000-block fixture and 1,000 randomized triples.
    for (int j = 0; j < 1000; j++) {
        CBlockIndex *p1 = &blocks[m_rng.randrange(10000)];
        CBlockIndex *p2 = &blocks[m_rng.randrange(10000)];
        CBlockIndex *p3 = &blocks[m_rng.randrange(10000)];
        int64_t tdiff = GetBlockProofEquivalentTime(*p1, *p2, *p3, chainParams->GetConsensus());
        BOOST_CHECK_EQUAL(tdiff, p1->GetBlockTime() - p2->GetBlockTime());
    }

    BOOST_CHECK_EQUAL(GetBlockProofEquivalentTime(blocks.back(), blocks.front(), blocks[5000], chainParams->GetConsensus()), 9999 * 120);
    BOOST_CHECK_EQUAL(GetBlockProofEquivalentTime(blocks.front(), blocks.back(), blocks[5000], chainParams->GetConsensus()), -9999 * 120);
    BOOST_CHECK_EQUAL(GetBlockProofEquivalentTime(blocks[123], blocks[123], blocks[5000], chainParams->GetConsensus()), 0);
}

static void sanity_check_chainparams(const ArgsManager& args, ChainType type, const uint256& genesis_hash, uint64_t expected_target)
{
    const auto chainParams = CreateChainParams(args, type);
    const auto& consensus = chainParams->GetConsensus();
    const auto& genesis = chainParams->GenesisBlock();
    // Retain stored-vs-computed genesis and timing consistency assertions.
    BOOST_CHECK_EQUAL(consensus.hashGenesisBlock, genesis.GetHash());
    BOOST_CHECK_EQUAL(consensus.hashGenesisBlock, genesis_hash);
    BOOST_CHECK_EQUAL(consensus.nPowTargetSpacing, 120);
    BOOST_CHECK_EQUAL(consensus.nPowTargetTimespan % consensus.nPowTargetSpacing, 0);

    // A native target is an unsigned uint64, replacing signed compact nBits.
    // Pin independently calculated 2^42/120 (ordinary) or 2^58/120 (regtest).
    BOOST_REQUIRE(genesis.nBaseTarget > 0);
    BOOST_CHECK_EQUAL(genesis.nBaseTarget, expected_target);
    BOOST_CHECK_EQUAL(genesis.nHeight, 0);
    BOOST_CHECK(genesis.hashPrevBlock.IsNull());
    BOOST_REQUIRE_EQUAL(genesis.vtx.size(), 1U);
    BOOST_CHECK_EQUAL(genesis.vtx[0]->GetValueOut(), 10 * COIN);

    // Native retarget intermediates must fit uint64 at the 2x timespan cap.
    // This replaces the original powLimit/uint256 multiplication bound.
    BOOST_CHECK_EQUAL(consensus.nPoCXRollingWindowSize, 24);
    BOOST_CHECK_LE(genesis.nBaseTarget, std::numeric_limits<uint64_t>::max() / (2 * 24 * 120));
}

BOOST_AUTO_TEST_CASE(ChainParams_MAIN_sanity)
{
    sanity_check_chainparams(*m_node.args, ChainType::MAIN,
        uint256{"6ab422073e327d42a0e5dfaaa26564324ddb225e53c64da89283cd4e3dfb7ac6"}, 36650387592ULL);
}

BOOST_AUTO_TEST_CASE(ChainParams_REGTEST_sanity)
{
    sanity_check_chainparams(*m_node.args, ChainType::REGTEST,
        uint256{"2a98a52253aeff06093948b00568d380b7634621bc606403127973c9acbbfde0"}, 2401919801264264ULL);
}

BOOST_AUTO_TEST_CASE(ChainParams_TESTNET_sanity)
{
    sanity_check_chainparams(*m_node.args, ChainType::TESTNET,
        uint256{"181c51a172fe20c203e463f6f203b7d9be388fa0f1282e507192f94d24a57e81"}, 36650387592ULL);
}

BOOST_AUTO_TEST_CASE(ChainParams_SIGNET_sanity)
{
    sanity_check_chainparams(*m_node.args, ChainType::SIGNET,
        uint256{"879af7781ec732bef50d912796cc7f0bd44232d4e0d17a4271b96a557f2c7359"}, 36650387592ULL);
}

BOOST_AUTO_TEST_CASE(pocx_testnet4_alias)
{
    const auto alias = CreateChainParams(*m_node.args, ChainType::TESTNET4);
    const auto native = CreateChainParams(*m_node.args, ChainType::TESTNET);
    BOOST_CHECK(alias->GetChainType() == ChainType::TESTNET);
    BOOST_CHECK_EQUAL(alias->GenesisBlock().GetHash(), native->GenesisBlock().GetHash());
    BOOST_CHECK(alias->MessageStart() == native->MessageStart());
}

BOOST_AUTO_TEST_SUITE_END()
