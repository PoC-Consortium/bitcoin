// Copyright (c) 2026 The Bitcoin PoCX developers
// Distributed under the MIT software license; see COPYING.

#include <arith_uint256.h>
#include <chain.h>
#include <chainparams.h>
#include <coins.h>
#include <consensus/validation.h>
#include <headerssync.h>
#include <key.h>
#include <pocx/algorithms/time_bending.h>
#include <pocx/consensus/difficulty.h>
#include <pocx/consensus/params.h>
#include <pocx/consensus/signature.h>
#include <pocx/mining/key_signing.h>
#include <test/util/setup_common.h>
#include <uint256.h>
#include <util/time.h>
#include <validation.h>

#include <boost/test/unit_test.hpp>

#include <array>
#include <cstdint>
#include <limits>
#include <optional>
#include <utility>

namespace {
using namespace pocx::consensus;

// Algorithm fixtures deliberately isolate retarget arithmetic from proof validity.
// Zero quality makes both deadline terms zero, so the expected adjustment follows
// directly from elapsed time, the weighted target and the documented 20% clamp.
struct TestChain : std::array<CBlockIndex, 31> {
    TestChain(uint64_t target, uint32_t spacing)
    {
        for (size_t i = 0; i < size(); ++i) {
            auto& index = (*this)[i];
            index.nHeight = i;
            index.nTime = 1000 + i * spacing;
            index.nBaseTarget = target;
            if (i > 0) {
                index.pprev = &(*this)[i - 1];
                index.BuildSkip();
            }
        }
    }
};

std::array<uint8_t, 32> Key(unsigned char value)
{
    std::array<uint8_t, 32> key{};
    key.back() = value;
    return key;
}

CBlock SignedBlock(unsigned char signer = 1)
{
    CBlock block;
    block.nVersion = 4;
    block.nHeight = 1;
    block.nTime = 1000;
    block.nBaseTarget = 1000;
    BOOST_REQUIRE(pocx::mining::SignPoCXBlockWithKey(block, Key(signer)));
    block.pocxProof.account_id = ExtractAccountIDFromPubKey(CPubKey(block.vchPubKey));
    BOOST_REQUIRE(pocx::mining::SignPoCXBlockWithKey(block, Key(signer)));
    return block;
}
} // namespace

BOOST_FIXTURE_TEST_SUITE(pocx_consensus_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(base_target_envelope_boundaries)
{
    for (uint64_t previous : {1ULL, 4ULL, 5ULL, 7ULL, 1000ULL, 36650387592ULL, 2401919801264264ULL}) {
        const uint64_t lower = previous - previous / 5;
        const uint64_t upper = previous + previous / 5;
        BOOST_CHECK(PermittedBaseTargetTransition(previous, lower));
        BOOST_CHECK(PermittedBaseTargetTransition(previous, upper));
        BOOST_CHECK(!PermittedBaseTargetTransition(previous, lower - 1));
        BOOST_CHECK(!PermittedBaseTargetTransition(previous, upper + 1));
    }
}

BOOST_AUTO_TEST_CASE(base_target_retarget_vectors)
{
    auto params = Params().GetConsensus();
    params.nPowTargetSpacing = 120;
    params.nPoCXRollingWindowSize = 24;
    params.fPoCXLowCapacityCalibration = false;
    for (const auto& [spacing, expected] : std::array<std::pair<uint32_t, uint64_t>, 3>{{{60, 800}, {120, 1000}, {240, 1200}}}) {
        auto chain = TestChain(1000, spacing);

        for (int height : {1, 2, 23, 24, 30}) {
            BOOST_CHECK_EQUAL(GetNextBaseTarget(&chain[height], params), expected);
        }
        // History older than the rolling window must not influence the result.
        chain[5].nTime = 0;
        chain[5].nBaseTarget = 9999;
        BOOST_CHECK_EQUAL(GetNextBaseTarget(&chain[30], params), expected);
    }
    auto weighted = TestChain(1000, 120);

    weighted[1].nBaseTarget = 600;
    weighted[2].nBaseTarget = 900;
    weighted[3].nBaseTarget = 1200;
    BOOST_CHECK_EQUAL(GetNextBaseTarget(&weighted[3], params), 975U);

    // quality/base_target=120 has an independently calculated bended deadline
    // of 134 seconds (Gamma(4/3) fixed-point constant 3927365422841 / 2^42).
    auto hybrid = TestChain(1000, 134);

    hybrid[1].pocxProof.quality = 120000;
    BOOST_CHECK_EQUAL(GetNextBaseTarget(&hybrid[1], params), 1000U);
    hybrid[1].nTime = hybrid[0].nTime + 120;
    BOOST_CHECK_EQUAL(GetNextBaseTarget(&hybrid[1], params), 883U);

    auto floor = TestChain(1, 60);

    BOOST_CHECK_EQUAL(GetNextBaseTarget(&floor[1], params), 1U);
    for (const bool low_capacity : {false, true}) {
        params.fPoCXLowCapacityCalibration = low_capacity;
        const uint64_t genesis_target = CalculateGenesisBaseTarget(120, low_capacity);
        auto capped = TestChain(genesis_target, 240);

        BOOST_CHECK_EQUAL(GetNextBaseTarget(&capped[0], params), genesis_target);
        BOOST_CHECK_EQUAL(GetNextBaseTarget(&capped[1], params), genesis_target);
    }
}

BOOST_AUTO_TEST_CASE(timing_deadline_boundaries)
{
    BOOST_CHECK_EQUAL(pocx::algorithms::CalculateTimeBendedDeadline(120000, 1000, 120), 134U);
    BOOST_CHECK(!PermittedTimingTransition(1000, 1133, 120000, 1000, 120));
    BOOST_CHECK(PermittedTimingTransition(1000, 1134, 120000, 1000, 120));
    BOOST_CHECK(PermittedTimingTransition(1000, 1135, 120000, 1000, 120));
    BOOST_CHECK(PermittedTimingTransition(1000, 1000, 0, 1000, 120));
    BOOST_CHECK(!PermittedTimingTransition(1000, 999, 0, 1000, 120));
    const auto end = std::numeric_limits<uint32_t>::max();
    BOOST_CHECK(PermittedTimingTransition(end - 134, end, 120000, 1000, 120));
    BOOST_CHECK(!PermittedTimingTransition(end - 133, end, 120000, 1000, 120));
    BOOST_CHECK(!PermittedTimingTransition(end, 0, 0, 1000, 120));
}

BOOST_AUTO_TEST_CASE(generation_signature_vectors)
{
    // sha256d(bytes(range(32)) + bytes(range(32,52))), displayed as uint256.
    constexpr uint256 previous{"1f1e1d1c1b1a191817161514131211100f0e0d0c0b0a09080706050403020100"};
    std::array<uint8_t, 20> account{};
    for (size_t i = 0; i < account.size(); ++i) account[i] = 32 + i;
    constexpr uint256 expected{"45e83653985c23ff5083e8843abe595ab2b485d45262b3af8963cce2532178f6"};
    BOOST_CHECK(GetNextGenerationSignature(previous, account) == expected);
    BOOST_CHECK(PermittedGenerationSignatureTransition(previous, account, expected));
    BOOST_CHECK(!PermittedGenerationSignatureTransition(previous, account, uint256::ZERO));
    auto other = account;
    other[19] ^= 1;
    BOOST_CHECK(!PermittedGenerationSignatureTransition(previous, other, expected));
    BOOST_CHECK(!PermittedGenerationSignatureTransition(uint256::ONE, account, expected));
    CBlockIndex parent;
    parent.generationSignature = previous;
    parent.pocxProof.account_id = account;
    BOOST_CHECK(GetNextGenerationSignature(&parent) == expected);
}

BOOST_AUTO_TEST_CASE(compact_signature_mutations)
{
    const auto block = SignedBlock();
    BOOST_REQUIRE(VerifyPoCXBlockCompactSignature(block));
    BOOST_REQUIRE(VerifyPoCXBlockCompactSignature(block, std::nullopt, 1));
    auto changed = block;
    ++changed.nTime;
    BOOST_CHECK(!VerifyPoCXBlockCompactSignature(changed));
    changed = block;
    changed.vchPubKey.fill(0);
    BOOST_CHECK(!VerifyPoCXBlockCompactSignature(changed));
    changed = block;
    changed.vchSignature.fill(0);
    BOOST_CHECK(!VerifyPoCXBlockCompactSignature(changed));
    changed = block;
    changed.vchSignature[0] ^= 1; // Wrong recovery id must recover a different key.
    BOOST_CHECK(!VerifyPoCXBlockCompactSignature(changed));
    changed = block;
    changed.vchSignature = SignedBlock(2).vchSignature;
    BOOST_CHECK(!VerifyPoCXBlockCompactSignature(changed));
    changed = block;
    changed.pocxProof.account_id[0] ^= 1;
    BOOST_REQUIRE(pocx::mining::SignPoCXBlockWithKey(changed, Key(1)));
    BOOST_REQUIRE(VerifyPoCXBlockCompactSignature(changed));
    BOOST_CHECK(!VerifyPoCXBlockCompactSignature(changed, std::nullopt, 1));
}

BOOST_AUTO_TEST_CASE(compact_signature_assignment_boundaries)
{
    const auto owner = SignedBlock(1);
    auto delegate = owner;
    BOOST_REQUIRE(pocx::mining::SignPoCXBlockWithKey(delegate, Key(2)));
    const auto delegate_id = ExtractAccountIDFromPubKey(CPubKey(delegate.vchPubKey));
    ForgingAssignment assignment{owner.pocxProof.account_id, delegate_id, uint256::ONE, 6, 10};
    assignment.revoked = true;
    assignment.revocation_height = 12;
    assignment.revocation_effective_height = 20;
    for (int height : {9, 10, 12, 19, 20}) {
        const bool delegated = height >= 10 && height < 20;
        BOOST_CHECK_EQUAL(VerifyPoCXBlockCompactSignature(owner, assignment, height), !delegated);
        BOOST_CHECK_EQUAL(VerifyPoCXBlockCompactSignature(delegate, assignment, height), delegated);
    }
}

BOOST_AUTO_TEST_CASE(mainnet_headers_sync_configuration)
{
    const auto params = CChainParams::Main();
    const auto& limits = params->HeadersSync();
    BOOST_REQUIRE_GT(limits.commitment_period, 0U);
    BOOST_REQUIRE_GT(limits.redownload_buffer_size, limits.commitment_period);
    // A new chain has no authenticated accumulated-work checkpoint yet. Do not
    // substitute Bitcoin's unrelated work threshold or invent a PoCX checkpoint.
    BOOST_CHECK(params->GetConsensus().nMinimumChainWork.IsNull());
    CBlockIndex genesis{params->GenesisBlock()};
    const auto hash = params->GenesisBlock().GetHash();
    genesis.phashBlock = &hash;
    HeadersSyncState state{0, params->GetConsensus(), limits, genesis, arith_uint256{1}};
    BOOST_CHECK(state.GetState() == HeadersSyncState::State::PRESYNC);
}

BOOST_FIXTURE_TEST_CASE(header_batch_transition_rejections, TestingSetup)
{
    // Mainnet enables the real-proof batch path. Reject these cheap structural
    // violations before nonce regeneration, not via regtest's synthetic shortcut.
    BOOST_REQUIRE(!m_node.chainman->GetConsensus().fPoCXAllowSyntheticRegtestProof);
    const auto& genesis = Params().GenesisBlock();
    const CBlockIndex* anchor = WITH_LOCK(cs_main, return m_node.chainman->ActiveChain().Tip());
    std::array<CBlockHeader, 2> headers;
    CBlockHeader previous{genesis};
    for (size_t i = 0; i < headers.size(); ++i) {
        auto& header = headers[i];
        header.nVersion = 4;
        header.nHeight = i + 1;
        header.hashPrevBlock = previous.GetHash();
        header.nBaseTarget = anchor->nNextBaseTarget;
        header.generationSignature = GetNextGenerationSignature(previous.generationSignature, previous.pocxProof.account_id);
        header.nTime = previous.nTime + 1000;
        header.pocxProof.compression = 1;
        previous = header;
    }
    SetMockTime(std::chrono::seconds{headers.back().nTime});
    for (size_t position = 0; position < headers.size(); ++position) {
        for (int mutation = 0; mutation < 5; ++mutation) {
            auto invalid = headers;
            auto& header = invalid[position];
            std::string expected{"bad-header-transition"};
            switch (mutation) {
            case 0: ++header.nHeight; break;
            case 1: header.nBaseTarget = 0; break;
            case 2: header.nBaseTarget *= 2; break;
            case 3: header.generationSignature = uint256::ONE; expected = "bad-gensig"; break;
            case 4:
                header.nTime = (position ? invalid[0].nTime : genesis.nTime) - 1;
                expected = "bad-pocx-timing";
                break;
            }
            BlockValidationState state;
            BOOST_CHECK(!m_node.chainman->ProcessNewBlockHeaders(invalid, true, state));
            BOOST_CHECK_EQUAL(state.GetRejectReason(), expected);
        }
    }
    // Structurally valid controls reach actual proof validation instead. These
    // deliberately lack real proofs; accepted proofs have independent vectors.
    BlockValidationState state;
    BOOST_CHECK(!m_node.chainman->ProcessNewBlockHeaders(headers, true, state));
    BOOST_CHECK_EQUAL(state.GetRejectReason(), "bad-pocx-quality-mismatch");
}

BOOST_AUTO_TEST_SUITE_END()
