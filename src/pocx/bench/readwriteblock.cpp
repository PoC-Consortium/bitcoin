// Copyright (c) 2023-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <bench/bench.h>
#include <flatfile.h>
#include <node/blockstorage.h>
#include <primitives/block.h>
#include <pocx/bench/block_fixture.h>
#include <primitives/transaction.h>
#include <serialize.h>
#include <span.h>
#include <streams.h>
#include <test/util/setup_common.h>
#include <validation.h>

#include <cassert>
#include <cstdint>
#include <memory>
#include <vector>

static void WriteBlockBench(benchmark::Bench& bench)
{
    const auto testing_setup{MakeNoLogFileContext<const TestingSetup>()};
    auto& blockman{testing_setup->m_node.chainman->m_blockman};
    const CBlock test_block{pocx::bench::MakeHistoricalTransactionBlock(*testing_setup)};
    bench.run([&] {
        const auto pos{blockman.WriteBlock(test_block, test_block.nHeight)};
        assert(!pos.IsNull());
    });
}

static void ReadBlockBench(benchmark::Bench& bench)
{
    const auto testing_setup{MakeNoLogFileContext<const TestingSetup>()};
    auto& blockman{testing_setup->m_node.chainman->m_blockman};
    const auto& test_block{pocx::bench::MakeHistoricalTransactionBlock(*testing_setup)};
    const auto& expected_hash{test_block.GetHash()};
    const auto& pos{blockman.WriteBlock(test_block, test_block.nHeight)};
    bench.run([&] {
        CBlock block;
        const auto success{blockman.ReadBlock(block, pos, expected_hash)};
        assert(success);
    });
}

static void ReadRawBlockBench(benchmark::Bench& bench)
{
    const auto testing_setup{MakeNoLogFileContext<const TestingSetup>()};
    auto& blockman{testing_setup->m_node.chainman->m_blockman};
    const auto test_block{pocx::bench::MakeHistoricalTransactionBlock(*testing_setup)};
    const auto pos{blockman.WriteBlock(test_block, test_block.nHeight)};
    bench.run([&] {
        const auto res{blockman.ReadRawBlock(pos)};
        assert(res);
    });
}

BENCHMARK(WriteBlockBench);
BENCHMARK(ReadBlockBench);
BENCHMARK(ReadRawBlockBench);
