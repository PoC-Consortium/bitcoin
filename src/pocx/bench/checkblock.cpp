// Copyright (c) 2016-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <bench/bench.h>
#include <chainparams.h>
#include <common/args.h>
#include <consensus/validation.h>
#include <primitives/block.h>
#include <pocx/bench/block_fixture.h>
#include <primitives/transaction.h>
#include <serialize.h>
#include <span.h>
#include <streams.h>
#include <util/chaintype.h>
#include <validation.h>

#include <cassert>
#include <cstddef>
#include <memory>
#include <optional>
#include <vector>

// These are the two major time-sinks which happen after we have fully received
// a block off the wire, but before we can relay the block on to peers using
// compact block relay.

static void DeserializeBlockTest(benchmark::Bench& bench)
{
    const auto testing_setup = MakeNoLogFileContext<const TestingSetup>();
    const CBlock fixture = pocx::bench::MakeHistoricalTransactionBlock(*testing_setup);
    DataStream stream;
    stream << TX_WITH_WITNESS(fixture);
    const size_t encoded_size = stream.size();
    std::byte a{0};
    stream.write({&a, 1}); // Prevent compaction

    bench.unit("block").run([&] {
        CBlock block;
        stream >> TX_WITH_WITNESS(block);
        bool rewound = stream.Rewind(encoded_size);
        assert(rewound);
    });
}

static void DeserializeAndCheckBlockTest(benchmark::Bench& bench)
{
    const auto testing_setup = MakeNoLogFileContext<const TestingSetup>();
    const CBlock fixture = pocx::bench::MakeHistoricalTransactionBlock(*testing_setup);
    DataStream stream;
    stream << TX_WITH_WITNESS(fixture);
    const size_t encoded_size = stream.size();
    std::byte a{0};
    stream.write({&a, 1}); // Prevent compaction

    const auto& consensus = testing_setup->m_node.chainman->GetConsensus();

    bench.unit("block").run([&] {
        CBlock block; // Note that CBlock caches its checked state, so we need to recreate it here
        stream >> TX_WITH_WITNESS(block);
        bool rewound = stream.Rewind(encoded_size);
        assert(rewound);

        BlockValidationState validationState;
        bool checked = CheckBlock(block, validationState, consensus);
        assert(checked);
    });
}

BENCHMARK(DeserializeBlockTest);
BENCHMARK(DeserializeAndCheckBlockTest);
