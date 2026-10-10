// Copyright (c) 2011-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <bench/bench.h>
#include <consensus/consensus.h>
#include <node/miner.h>
#include <primitives/transaction.h>
#include <random.h>
#include <script/script.h>
#include <sync.h>
#include <test/util/mining.h>
#include <test/util/script.h>
#include <test/util/setup_common.h>
#include <validation.h>
#include <util/time.h>

#include <array>
#include <cassert>
#include <cstddef>
#include <memory>
#include <vector>
#include <deque>
#include <stdexcept>
#include <txmempool.h>

using node::BlockAssembler;

static void AssembleBlock(benchmark::Bench& bench)
{
    const auto test_setup = MakeNoLogFileContext<const TestingSetup>();
    // Native regtest forging advances this clock through actual deadlines.
    SetMockTime(test_setup->m_node.chainman->GetParams().GenesisBlock().nTime);

    CScriptWitness witness;
    witness.stack.push_back(WITNESS_STACK_ELEM_OP_TRUE);
    BlockAssembler::Options options;
    options.coinbase_output_script = P2WSH_OP_TRUE;
    options.include_dummy_extranonce = true;

    // Collect some loose transactions that spend the coinbases of our mined blocks
    constexpr size_t NUM_BLOCKS{200};
    std::array<CTransactionRef, NUM_BLOCKS - COINBASE_MATURITY + 1> txs;
    for (size_t b{0}; b < NUM_BLOCKS; ++b) {
        CMutableTransaction tx;
        tx.vin.emplace_back(MineBlock(test_setup->m_node, options));
        tx.vin.back().scriptWitness = witness;
        tx.vout.emplace_back(1337, P2WSH_OP_TRUE);
        if (NUM_BLOCKS - b >= COINBASE_MATURITY)
            txs.at(b) = MakeTransactionRef(tx);
    }
    {
        LOCK(::cs_main);

        for (const auto& txr : txs) {
            const MempoolAcceptResult res = test_setup->m_node.chainman->ProcessTransaction(txr);
            assert(res.m_result_type == MempoolAcceptResult::ResultType::VALID);
        }
    }

    bench.run([&] {
        PrepareBlock(test_setup->m_node, options);
    });
}
// Preserve the original deterministic transaction graph despite the native
// 10-coin subsidy. Calculate fixture values in Bitcoin-equivalent units and
// convert outputs/actual fees to native satoshis. Rounding each intermediate
// value before deciding which outputs to reuse changes the RNG consumption
// and can strand every remaining output in a policy-saturated cluster.
static std::vector<CTransactionRef> PopulateBenchmarkMempool(TestChain100Setup& setup, FastRandomContext& det_rand, size_t num_transactions, bool submit)
{
    auto& m_node = setup.m_node;
    auto& m_coinbase_txns = setup.m_coinbase_txns;
    constexpr CAmount SUBSIDY_SCALE{5};
    assert(GetBlockSubsidy(1, m_node.chainman->GetConsensus()) == 10 * COIN);
    const size_t requested = num_transactions;
    size_t attempts{0};
    std::vector<CTransactionRef> mempool_transactions;
    std::deque<std::pair<COutPoint, CAmount>> unspent_prevouts, undo_info;
    std::transform(m_coinbase_txns.begin(), m_coinbase_txns.end(), std::back_inserter(unspent_prevouts),
        [](const auto& tx){ return std::make_pair(COutPoint(tx->GetHash(), 0), tx->vout[0].nValue * SUBSIDY_SCALE); });
    while (num_transactions > 0 && !unspent_prevouts.empty()) {
        // Fail explicitly if a future policy change prevents constructing the
        // full workload; a short/empty mempool must never count as success.
        if (++attempts > 1'000'000) {
            throw std::runtime_error("Cannot construct complete native benchmark mempool");
        }
        // The number of inputs and outputs are randomly chosen, between 1-5
        // and 1-25 respectively.
        CMutableTransaction mtx = CMutableTransaction();
        const size_t num_inputs = det_rand.randrange(5) + 1;
        CAmount total_in{0};
        CAmount native_total_in{0};
        for (size_t n{0}; n < num_inputs; ++n) {
            if (unspent_prevouts.empty()) break;
            const auto& [prevout, amount] = unspent_prevouts.front();
            undo_info.emplace_back(prevout, amount);
            mtx.vin.emplace_back(prevout, CScript());
            total_in += amount;
            native_total_in += amount / SUBSIDY_SCALE;
            unspent_prevouts.pop_front();
        }
        const size_t num_outputs = det_rand.randrange(25) + 1;
        // Retain original arithmetic in normalized fixture units, converting
        // to native satoshis only when writing actual transaction outputs.
        const CAmount fee = 100 * det_rand.randrange(30);
        const CAmount amount_per_output = (total_in - fee) / num_outputs;
        for (size_t n{0}; n < num_outputs; ++n) {
            CScript spk = CScript() << CScriptNum(num_transactions + n);
            mtx.vout.emplace_back(amount_per_output / SUBSIDY_SCALE, spk);
        }
        CTransactionRef ptx = MakeTransactionRef(mtx);
        bool success{true};
        if (submit) {
            LOCK2(cs_main, m_node.mempool->cs);
            LockPoints lp;
            auto changeset = m_node.mempool->GetChangeSet();
            changeset->StageAddition(ptx, /*fee=*/(native_total_in - num_outputs * (amount_per_output / SUBSIDY_SCALE)),
                    /*time=*/0, /*entry_height=*/1, /*entry_sequence=*/0,
                    /*spends_coinbase=*/false, /*sigops_cost=*/4, lp);
            if (changeset->CheckMemPoolPolicyLimits()) {
                changeset->Apply();
                --num_transactions;
            } else {
                success = false;
                // Add the inputs back to unspent prevouts
                for (const auto& [prevout, amount] : undo_info) {
                    unspent_prevouts.emplace_back(prevout, amount);
                    std::swap(unspent_prevouts.back(), unspent_prevouts[det_rand.randrange(unspent_prevouts.size())]);
                }
            }
        }
        if (success) {
            mempool_transactions.push_back(ptx);
            if (amount_per_output > 3000) {
                // If the value is high enough to fund another transaction + fees, keep track of it so
                // it can be used to build a more complex transaction graph. Insert randomly into
                // unspent_prevouts for extra randomness in the resulting structures.
                for (size_t n{0}; n < num_outputs; ++n) {
                    unspent_prevouts.emplace_back(COutPoint(ptx->GetHash(), n), amount_per_output);
                    std::swap(unspent_prevouts.back(), unspent_prevouts[det_rand.randrange(unspent_prevouts.size())]);
                }
            }
        }
        undo_info.clear();
    }
    assert(mempool_transactions.size() == requested);
    return mempool_transactions;
}

static void BlockAssemblerAddPackageTxns(benchmark::Bench& bench)
{
    FastRandomContext det_rand{true};
    auto testing_setup{MakeNoLogFileContext<TestChain100Setup>()};
    const auto transactions = PopulateBenchmarkMempool(*testing_setup, det_rand, /*num_transactions=*/1000, /*submit=*/true);
    assert(transactions.size() == 1000);
    assert(testing_setup->m_node.mempool->size() == 1000);
    BlockAssembler::Options assembler_options;
    assembler_options.test_block_validity = false;
    assembler_options.coinbase_output_script = P2WSH_OP_TRUE;

    bench.run([&] {
        PrepareBlock(testing_setup->m_node, assembler_options);
    });
}

BENCHMARK(AssembleBlock);
BENCHMARK(BlockAssemblerAddPackageTxns);
