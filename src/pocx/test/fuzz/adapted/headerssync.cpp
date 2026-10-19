// Copyright (c) 2022-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit.

#include <arith_uint256.h>
#include <chain.h>
#include <chainparams.h>
#include <headerssync.h>
#include <pocx/consensus/difficulty.h>
#include <test/fuzz/fuzz.h>
#include <test/fuzz/util.h>
#include <test/util/setup_common.h>
#include <uint256.h>
#include <util/chaintype.h>
#include <util/time.h>
#include <validation.h>

#include <iterator>
#include <vector>

static void initialize_headers_sync_state_fuzz()
{
    static const auto testing_setup = MakeNoLogFileContext<>(
        /*chain_type=*/ChainType::MAIN);
}

void MakeHeadersContinuous(
    const CBlockHeader& genesis_header,
    const std::vector<CBlockHeader>& all_headers,
    std::vector<CBlockHeader>& new_headers)
{
    Assume(!new_headers.empty());

    const CBlockHeader* prev_header{
        all_headers.empty() ? &genesis_header : &all_headers.back()};

    for (auto& header : new_headers) {
        header.hashPrevBlock = prev_header->GetHash();
        header.nHeight = prev_header->nHeight + 1;
        header.nBaseTarget = prev_header->nBaseTarget;
        header.generationSignature = pocx::consensus::GetNextGenerationSignature(
            prev_header->generationSignature, prev_header->pocxProof.account_id);
        header.nTime = std::max(header.nTime, prev_header->nTime);
        header.pocxProof.quality = 0; // Zero deadline keeps repaired chains admissible.

        prev_header = &header;
    }
}

class FuzzedHeadersSyncState : public HeadersSyncState
{
public:
    FuzzedHeadersSyncState(const HeadersSyncParams& sync_params, const size_t commit_offset,
                           const CBlockIndex& chain_start, const arith_uint256& minimum_required_work)
        : HeadersSyncState(/*id=*/0, Params().GetConsensus(), sync_params, chain_start, minimum_required_work)
    {
        const_cast<size_t&>(m_commit_offset) = commit_offset;
    }
};

static void RunHeadersSyncState(FuzzBufferType buffer, const HeadersSyncParams& parameter_bounds)
{
    SeedRandomStateForTest(SeedRand::ZEROS);
    FuzzedDataProvider fuzzed_data_provider(buffer.data(), buffer.size());

    CBlockHeader genesis_header{Params().GenesisBlock()};
    CBlockIndex start_index(genesis_header);
    // Native presync requires the first header to match the parent's next target.
    // A bare CBlockIndex constructor leaves that derived field zero.
    start_index.nNextBaseTarget = genesis_header.nBaseTarget;

    SetMockTime(ConsumeTime(fuzzed_data_provider, /*min=*/start_index.GetMedianTimePast()));

    const uint256 genesis_hash = genesis_header.GetHash();
    start_index.phashBlock = &genesis_hash;

    const HeadersSyncParams params{
        .commitment_period = fuzzed_data_provider.ConsumeIntegralInRange<size_t>(1, parameter_bounds.commitment_period * 2),
        .redownload_buffer_size = fuzzed_data_provider.ConsumeIntegralInRange<size_t>(0, parameter_bounds.redownload_buffer_size * 2),
    };
    arith_uint256 min_work{UintToArith256(ConsumeUInt256(fuzzed_data_provider))};
    FuzzedHeadersSyncState headers_sync(
        params,
        /*commit_offset=*/fuzzed_data_provider.ConsumeIntegralInRange<size_t>(0, params.commitment_period - 1),
        /*chain_start=*/start_index,
        /*minimum_required_work=*/min_work);

    // Store headers for potential redownload phase.
    std::vector<CBlockHeader> all_headers;
    std::vector<CBlockHeader>::const_iterator redownloaded_it;
    bool presync{true};
    bool requested_more{true};

    while (requested_more) {
        std::vector<CBlockHeader> headers;

        // Consume headers from fuzzer or maybe replay headers if we got to the
        // redownload phase.
        if (presync || fuzzed_data_provider.ConsumeBool()) {
            auto deser_headers = ConsumeDeserializable<std::vector<CBlockHeader>>(fuzzed_data_provider);
            if (!deser_headers || deser_headers->empty()) return;

            if (fuzzed_data_provider.ConsumeBool()) {
                MakeHeadersContinuous(genesis_header, all_headers, *deser_headers);
            }

            headers.swap(*deser_headers);
        } else if (auto num_headers_left{std::distance(redownloaded_it, all_headers.cend())}; num_headers_left > 0) {
            // Consume some headers from the redownload buffer (At least one
            // header is consumed).
            auto begin_it{redownloaded_it};
            std::advance(redownloaded_it, fuzzed_data_provider.ConsumeIntegralInRange<int>(1, num_headers_left));
            headers.insert(headers.cend(), begin_it, redownloaded_it);
        }

        if (headers.empty()) return;
        auto result = headers_sync.ProcessNextHeaders(headers, fuzzed_data_provider.ConsumeBool());
        requested_more = result.request_more;

        if (result.request_more) {
            if (presync) {
                all_headers.insert(all_headers.cend(), headers.cbegin(), headers.cend());

                if (headers_sync.GetState() == HeadersSyncState::State::REDOWNLOAD) {
                    presync = false;
                    redownloaded_it = all_headers.cbegin();

                    // If we get to redownloading, the presynced headers need
                    // to have the min amount of work on them.
                    assert(CalculateClaimedHeadersWork(all_headers) >= min_work);
                }
            }

            (void)headers_sync.NextHeadersRequestLocator();
        }
    }
}

// Preserve the inherited target's actual network configuration dependency.
// Use the real mainnet commitment parameters, without a fallback configuration.
FUZZ_TARGET(headers_sync_state, .init = initialize_headers_sync_state_fuzz)
{
    RunHeadersSyncState(buffer, Params().HeadersSync());
}

FUZZ_TARGET(pocx_headers_sync_configuration, .init = initialize_headers_sync_state_fuzz)
{
    // HeadersSyncState's constructor also requires a positive commitment period.
    assert(Params().HeadersSync().commitment_period > 0);
}
