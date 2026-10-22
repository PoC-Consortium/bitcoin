// Copyright (c) 2022-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <chain.h>
#include <chainparams.h>
#include <consensus/params.h>
#include <headerssync.h>
#include <net_processing.h>
#include <pocx/consensus/difficulty.h>
#include <test/util/common.h>
#include <test/util/setup_common.h>
#include <validation.h>

#include <cstddef>
#include <vector>

#include <boost/test/unit_test.hpp>

using State = HeadersSyncState::State;

// Standard set of checks common to all scenarios. Macro keeps failure lines at the call-site.
#define CHECK_RESULT(result_expression, hss, exp_state, exp_success, exp_request_more,                   \
                     exp_headers_size, exp_pow_validated_prev, exp_locator_hash)                         \
    do {                                                                                                 \
        const auto result{result_expression};                                                            \
        BOOST_REQUIRE_EQUAL(hss.GetState(), exp_state);                                                  \
        BOOST_CHECK_EQUAL(result.success, exp_success);                                                  \
        BOOST_CHECK_EQUAL(result.request_more, exp_request_more);                                        \
        BOOST_CHECK_EQUAL(result.pow_validated_headers.size(), exp_headers_size);                        \
        const std::optional<uint256> pow_validated_prev_opt{exp_pow_validated_prev};                     \
        if (pow_validated_prev_opt) {                                                                    \
            BOOST_CHECK_EQUAL(result.pow_validated_headers.at(0).hashPrevBlock, pow_validated_prev_opt); \
        } else {                                                                                         \
            BOOST_CHECK_EQUAL(exp_headers_size, 0);                                                      \
        }                                                                                                \
        const std::optional<uint256> locator_hash_opt{exp_locator_hash};                                 \
        if (locator_hash_opt) {                                                                          \
            BOOST_CHECK_EQUAL(hss.NextHeadersRequestLocator().vHave.at(0), locator_hash_opt);            \
        } else {                                                                                         \
            BOOST_CHECK_EQUAL(exp_state, State::FINAL);                                                  \
        }                                                                                                \
    } while (false)

constexpr size_t TARGET_BLOCKS{15'000};

// Subtract MAX_HEADERS_RESULTS (2000 headers/message) + an arbitrary smaller
// value (123) so our redownload buffer is well below the number of blocks
// required to reach the CHAIN_WORK threshold, to behave similarly to mainnet.
constexpr size_t REDOWNLOAD_BUFFER_SIZE{TARGET_BLOCKS - (MAX_HEADERS_RESULTS + 123)};
constexpr size_t COMMITMENT_PERIOD{600}; // Somewhat close to mainnet.

struct HeadersGeneratorSetup : public RegTestingSetup {
    const CBlock& genesis{Params().GenesisBlock()};
    CBlockIndex& chain_start{WITH_LOCK(::cs_main, return *Assert(m_node.chainman->m_blockman.LookupBlockIndex(genesis.GetHash())))};

    // HeadersSyncState checks claimed work and transitions. Proof/signature
    // validation belongs to the caller; these are deliberately header-only fixtures.
    const std::vector<CBlockHeader>& FirstChain()
    {
        static const auto headers{GenerateHeaders(TARGET_BLOCKS - 1, uint256::ZERO)};
        return headers;
    }
    const std::vector<CBlockHeader>& SecondChain()
    {
        static const auto headers{GenerateHeaders(TARGET_BLOCKS - 2, uint256::ONE)};
        return headers;
    }

    HeadersSyncState CreateState()
    {
        // PoCX claimed work is floor(2^64 / base_target), not two per header.
        // Include the genesis work exactly once; the shorter chain stays one
        // header below the threshold, as in the upstream regression.
        const auto work_per_header = (arith_uint256{1} << 64) / arith_uint256{chain_start.nNextBaseTarget};
        const auto required_work = chain_start.nChainWork + work_per_header * (TARGET_BLOCKS - 1);
        return {/*id=*/0,
                Params().GetConsensus(),
                HeadersSyncParams{
                    .commitment_period = COMMITMENT_PERIOD,
                    .redownload_buffer_size = REDOWNLOAD_BUFFER_SIZE,
                },
                chain_start,
                /*minimum_required_work=*/required_work};
    }

private:
    std::vector<CBlockHeader> GenerateHeaders(size_t count, const uint256& merkle_root)
    {
        std::vector<CBlockHeader> headers(count);
        CBlockHeader prev{genesis};
        int height{0};
        for (auto& next : headers) {
            next.nVersion = genesis.nVersion;
            next.hashPrevBlock = prev.GetHash();
            next.hashMerkleRoot = merkle_root;
            next.nTime = prev.nTime + 1;
            next.nHeight = ++height;
            next.nBaseTarget = chain_start.nNextBaseTarget;
            next.generationSignature = pocx::consensus::GetNextGenerationSignature(prev.generationSignature, prev.pocxProof.account_id);
            next.pocxProof.quality = 0; // Claimed zero deadline fits a one-second interval.
            prev = next;
        }
        return headers;
    }
};

// In this test, we construct two sets of headers from genesis, one with
// sufficient proof of work and one without.
// 1. We deliver the first set of headers and verify that the headers sync state
//    updates to the REDOWNLOAD phase successfully.
//    Then we deliver the second set of headers and verify that they fail
//    processing (presumably due to commitments not matching).
// 2. Verify that repeating with the first set of headers in both phases is
//    successful.
// 3. Repeat the second set of headers in both phases to demonstrate behavior
//    when the chain a peer provides has too little work.
BOOST_FIXTURE_TEST_SUITE(headers_sync_chainwork_tests, HeadersGeneratorSetup)

// Invalid PoCX transitions must fail in both sync phases, before any header
// is released for permanent storage. Valid controls are covered by happy_path.
BOOST_AUTO_TEST_CASE(pocx_invalid_transitions)
{
    for (const bool redownload : {false, true}) {
        for (int mutation = 0; mutation < 4; ++mutation) {
            auto hss = CreateState();
            if (redownload) {
                const auto presync = hss.ProcessNextHeaders(FirstChain(), true);
                BOOST_REQUIRE(presync.success);
                BOOST_REQUIRE_EQUAL(hss.GetState(), State::REDOWNLOAD);
            }
            auto header = FirstChain().front();
            switch (mutation) {
            case 0: header.nBaseTarget = 0; break;
            case 1: ++header.nBaseTarget; break; // first header must match exactly
            case 2: header.generationSignature = uint256::ONE; break;
            case 3: header.nTime = genesis.nTime - 1; break;
            }
            CHECK_RESULT(hss.ProcessNextHeaders(std::span{&header, 1}, true),
                hss, State::FINAL, false, false, 0, std::nullopt, std::nullopt);
        }
    }
}

BOOST_AUTO_TEST_CASE(sneaky_redownload)
{
    const auto& first_chain{FirstChain()};
    const auto& second_chain{SecondChain()};

    // Feed the first chain to HeadersSyncState, by delivering 1 header
    // initially and then the rest.
    HeadersSyncState hss{CreateState()};

    // Just feed one header and check state.
    // Pretend the message is still "full", so we don't abort.
    CHECK_RESULT(hss.ProcessNextHeaders({{first_chain.front()}}, /*full_headers_message=*/true),
        hss, /*exp_state=*/State::PRESYNC,
        /*exp_success=*/true, /*exp_request_more=*/true,
        /*exp_headers_size=*/0, /*exp_pow_validated_prev=*/std::nullopt,
        /*exp_locator_hash=*/first_chain.front().GetHash());

    // This chain should look valid, and we should have met the proof-of-work
    // requirement during PRESYNC and transitioned to REDOWNLOAD.
    CHECK_RESULT(hss.ProcessNextHeaders(std::span{first_chain}.subspan(1), true),
        hss, /*exp_state=*/State::REDOWNLOAD,
        /*exp_success=*/true, /*exp_request_more=*/true,
        /*exp_headers_size=*/0, /*exp_pow_validated_prev=*/std::nullopt,
        /*exp_locator_hash=*/genesis.GetHash());

    // Below is the number of commitment bits that must randomly match between
    // the two chains for this test to spuriously fail. 1 / 2^25 =
    // 1 in 33'554'432 (somewhat less due to HeadersSyncState::m_commit_offset).
    static_assert(TARGET_BLOCKS / COMMITMENT_PERIOD == 25);

    // Try to sneakily feed back the second chain during REDOWNLOAD.
    CHECK_RESULT(hss.ProcessNextHeaders(second_chain, true),
        hss, /*exp_state=*/State::FINAL,
        /*exp_success=*/false, // Foiled! We detected mismatching headers.
        /*exp_request_more=*/false,
        /*exp_headers_size=*/0, /*exp_pow_validated_prev=*/std::nullopt,
        /*exp_locator_hash=*/std::nullopt);
}

BOOST_AUTO_TEST_CASE(happy_path)
{
    const auto& first_chain{FirstChain()};

    // Headers message that moves us to the next state doesn't need to be full.
    for (const bool full_headers_message : {false, true}) {
        // This time we feed the first chain twice.
        HeadersSyncState hss{CreateState()};

        // Sufficient work transitions us from PRESYNC to REDOWNLOAD:
        const auto genesis_hash{genesis.GetHash()};
        CHECK_RESULT(hss.ProcessNextHeaders(first_chain, full_headers_message),
            hss, /*exp_state=*/State::REDOWNLOAD,
            /*exp_success=*/true, /*exp_request_more=*/true,
            /*exp_headers_size=*/0, /*exp_pow_validated_prev=*/std::nullopt,
            /*exp_locator_hash=*/genesis_hash);

        // Process only so that the internal threshold isn't exceeded, meaning
        // validated headers shouldn't be returned yet:
        CHECK_RESULT(hss.ProcessNextHeaders({first_chain.begin(), REDOWNLOAD_BUFFER_SIZE}, true),
            hss, /*exp_state=*/State::REDOWNLOAD,
            /*exp_success=*/true, /*exp_request_more=*/true,
            /*exp_headers_size=*/0, /*exp_pow_validated_prev=*/std::nullopt,
            /*exp_locator_hash=*/first_chain[REDOWNLOAD_BUFFER_SIZE - 1].GetHash());

        // We start receiving headers for permanent storage before completing:
        CHECK_RESULT(hss.ProcessNextHeaders({{first_chain[REDOWNLOAD_BUFFER_SIZE]}}, true),
            hss, /*exp_state=*/State::REDOWNLOAD,
            /*exp_success=*/true, /*exp_request_more=*/true,
            /*exp_headers_size=*/1, /*exp_pow_validated_prev=*/genesis_hash,
            /*exp_locator_hash=*/first_chain[REDOWNLOAD_BUFFER_SIZE].GetHash());

        // Feed in remaining headers, meeting the work threshold again and
        // completing the REDOWNLOAD phase:
        CHECK_RESULT(hss.ProcessNextHeaders({first_chain.begin() + REDOWNLOAD_BUFFER_SIZE + 1, first_chain.end()}, full_headers_message),
            hss, /*exp_state=*/State::FINAL,
            /*exp_success=*/true, /*exp_request_more=*/false,
            // All headers except the one already returned above:
            /*exp_headers_size=*/first_chain.size() - 1, /*exp_pow_validated_prev=*/first_chain.front().GetHash(),
            /*exp_locator_hash=*/std::nullopt);
    }
}

BOOST_AUTO_TEST_CASE(too_little_work)
{
    const auto& second_chain{SecondChain()};

    // Verify that just trying to process the second chain would not succeed
    // (too little work).
    HeadersSyncState hss{CreateState()};
    BOOST_REQUIRE_EQUAL(hss.GetState(), State::PRESYNC);

    // Pretend just the first message is "full", so we don't abort.
    CHECK_RESULT(hss.ProcessNextHeaders({{second_chain.front()}}, true),
        hss, /*exp_state=*/State::PRESYNC,
        /*exp_success=*/true, /*exp_request_more=*/true,
        /*exp_headers_size=*/0, /*exp_pow_validated_prev=*/std::nullopt,
        /*exp_locator_hash=*/second_chain.front().GetHash());

    // Tell the sync logic that the headers message was not full, implying no
    // more headers can be requested. For a low-work-chain, this should cause
    // the sync to end with no headers for acceptance.
    CHECK_RESULT(hss.ProcessNextHeaders(std::span{second_chain}.subspan(1), false),
        hss, /*exp_state=*/State::FINAL,
        // Nevertheless, no validation errors should have been detected with the
        // chain:
        /*exp_success=*/true,
        /*exp_request_more=*/false,
        /*exp_headers_size=*/0, /*exp_pow_validated_prev=*/std::nullopt,
        /*exp_locator_hash=*/std::nullopt);
}

BOOST_AUTO_TEST_SUITE_END()
