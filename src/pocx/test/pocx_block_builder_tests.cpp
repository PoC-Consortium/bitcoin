// Copyright (c) 2026 The Bitcoin PoCX developers
// Distributed under the MIT software license; see COPYING.
#include <pocx/mining/block_builder.h>
#include <consensus/amount.h>
#include <consensus/merkle.h>
#include <node/types.h>
#include <test/util/setup_common.h>
#include <boost/test/unit_test.hpp>

namespace {
// Supply a deterministic template at the public Mining boundary. Exercise the
// production builder without exposing its private helpers or altering consensus.
class FixedTemplate final : public interfaces::BlockTemplate {
public:
    CBlock block;
    explicit FixedTemplate(CBlock value) : block{std::move(value)} {}
    CBlockHeader getBlockHeader() override { return block; }
    CBlock getBlock() override { return block; }
    std::vector<CAmount> getTxFees() override { return {}; }
    std::vector<int64_t> getTxSigops() override { return {}; }
    node::CoinbaseTx getCoinbaseTx() override { throw std::logic_error("unused"); }
    std::vector<uint256> getCoinbaseMerklePath() override { throw std::logic_error("unused"); }
    bool submitSolution(uint32_t, uint32_t, uint32_t, CTransactionRef) override { throw std::logic_error("unused"); }
    std::unique_ptr<interfaces::BlockTemplate> waitNext(node::BlockWaitOptions) override { throw std::logic_error("unused"); }
    void interruptWait() override { throw std::logic_error("unused"); }
};
class FixedMining final : public interfaces::Mining {
public:
    CBlock block;
    CScript requested_script;
    bool unavailable{false};
    bool isTestChain() override { return true; }
    bool isInitialBlockDownload() override { return false; }
    std::optional<interfaces::BlockRef> getTip() override { throw std::logic_error("unused"); }
    std::optional<interfaces::BlockRef> waitTipChanged(uint256, MillisecondsDouble) override { throw std::logic_error("unused"); }
    std::unique_ptr<interfaces::BlockTemplate> createNewBlock(const node::BlockCreateOptions& options, bool) override {
        requested_script = options.coinbase_output_script;
        BOOST_CHECK(options.use_mempool);
        if (unavailable) return nullptr;
        return std::make_unique<FixedTemplate>(block);
    }
    void interrupt() override { throw std::logic_error("unused"); }
    bool checkBlock(const CBlock&, const node::BlockCheckOptions&, std::string&, std::string&) override { throw std::logic_error("unused"); }
};
}

BOOST_FIXTURE_TEST_SUITE(pocx_block_builder_tests, BasicTestingSetup)
BOOST_AUTO_TEST_CASE(payout_budget_fees_and_merkle)
{
    FixedMining mining;
    // Explicit 10-coin subsidy plus 12345 sat fees, witness commitment and a
    // second transaction so merkle recomputation cannot just return coinbase txid.
    constexpr CAmount fees{12345};
    constexpr CAmount budget{10 * COIN + fees};
    const CScript signer = CScript() << OP_0 << std::vector<unsigned char>(20, 0x11);
    const CScript recipient = CScript() << OP_0 << std::vector<unsigned char>(20, 0x22);
    const CScript commitment = CScript() << OP_RETURN << std::vector<unsigned char>(36, 0x33);
    CMutableTransaction cb;
    cb.vin.resize(1);
    cb.vin[0].prevout.SetNull();
    cb.vin[0].scriptWitness.stack = {std::vector<unsigned char>(32, 0)};
    cb.vout = {CTxOut{budget, signer}, CTxOut{0, commitment}};
    CMutableTransaction tx;
    tx.vout = {CTxOut{1, recipient}};
    mining.block.vtx = {MakeTransactionRef(cb), MakeTransactionRef(tx)};
    mining.block.hashMerkleRoot = BlockMerkleRoot(mining.block);
    const auto original_root = mining.block.hashMerkleRoot;
    pocx::mining::PoCXBlockBuilder builder{mining};
    auto build = [&](const std::vector<CTxOut>& outputs) {
        return builder.BuildBlock(std::string(40, '1'), std::string(64, '0'), 7, 9, 1, nullptr, outputs);
    };
    auto legacy = build({});
    BOOST_REQUIRE(legacy);
    BOOST_CHECK(legacy->vtx[0]->vout == cb.vout);
    BOOST_CHECK(mining.requested_script == signer);
    for (const CAmount allocation : {CAmount{0}, CAmount{COIN}, CAmount{10 * COIN}, budget}) {
        auto block = build({CTxOut{allocation, recipient}});
        BOOST_REQUIRE(block);
        const auto& outputs = block->vtx[0]->vout;
        BOOST_REQUIRE_EQUAL(outputs.size(), allocation < budget ? 3 : 2);
        BOOST_CHECK(outputs.front() == CTxOut(allocation, recipient));
        BOOST_CHECK(outputs.back() == cb.vout.back());
        if (allocation < budget) BOOST_CHECK(outputs[1] == CTxOut(budget - allocation, signer));
        BOOST_CHECK(block->vtx[0]->vin[0].scriptWitness.stack == cb.vin[0].scriptWitness.stack);
        BOOST_CHECK(block->vtx[1] == mining.block.vtx[1]);
        BOOST_CHECK(block->hashMerkleRoot == BlockMerkleRoot(*block));
        BOOST_CHECK(block->hashMerkleRoot != original_root);
        BOOST_CHECK_EQUAL(block->pocxProof.nonce, 7U);
        BOOST_CHECK_EQUAL(block->pocxProof.quality, 9U);
    }
    auto split = build({CTxOut{COIN, recipient}, CTxOut{2 * COIN, recipient}});
    BOOST_REQUIRE(split);
    BOOST_REQUIRE_EQUAL(split->vtx[0]->vout.size(), 4U);
    BOOST_CHECK_EQUAL(split->vtx[0]->vout[2].nValue, 7 * COIN + fees);
    BOOST_CHECK(!build({CTxOut{budget + 1, recipient}}));
    BOOST_CHECK(!build({CTxOut{budget, recipient}, CTxOut{1, recipient}}));
    BOOST_CHECK(mining.block.vtx[0]->vout == cb.vout);
    BOOST_CHECK(mining.block.hashMerkleRoot == original_root);
    mining.unavailable = true;
    BOOST_CHECK(!build({}));
    mining.unavailable = false;
    mining.block.vtx.clear();
    BOOST_CHECK(!build({CTxOut{1, recipient}}));
    cb.vout.clear();
    mining.block.vtx = {MakeTransactionRef(cb)};
    BOOST_CHECK(!build({CTxOut{1, recipient}}));
    cb.vin[0].prevout.n = 0;
    mining.block.vtx = {MakeTransactionRef(cb)};
    BOOST_CHECK(!build({CTxOut{1, recipient}}));
}
BOOST_AUTO_TEST_SUITE_END()
