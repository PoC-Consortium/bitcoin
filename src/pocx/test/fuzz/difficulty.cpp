// Copyright (c) 2026 The Bitcoin PoCX developers
// Distributed under the MIT software license; see COPYING.

#include <chain.h>
#include <chainparams.h>
#include <hash.h>
#include <pocx/consensus/difficulty.h>
#include <pocx/consensus/params.h>
#include <test/fuzz/FuzzedDataProvider.h>
#include <test/fuzz/fuzz.h>
#include <test/util/setup_common.h>

#include <algorithm>
#include <array>
#include <cassert>
#include <cstdint>

FUZZ_TARGET(pocx_difficulty, .init = [] { static const auto setup = MakeNoLogFileContext<>(); })
{
    FuzzedDataProvider provider{buffer.data(), buffer.size()};
    // Consensus targets stay below 2^64/2, so +/-20% arithmetic cannot overflow.
    auto params = Params().GetConsensus();
    params.fPoCXLowCapacityCalibration = false;
    params.nPoCXRollingWindowSize = 24;
    const auto cap = pocx::consensus::CalculateGenesisBaseTarget(params.nPowTargetSpacing, false);
    const auto previous = provider.ConsumeIntegralInRange<uint64_t>(1, cap);
    const auto candidate = provider.ConsumeIntegral<uint64_t>();
    const bool permitted = candidate >= previous - previous / 5 && candidate <= previous + previous / 5;
    assert(pocx::consensus::PermittedBaseTargetTransition(previous, candidate) == permitted);
    assert(!pocx::consensus::PermittedBaseTargetTransition(previous, 0));

    std::array<CBlockIndex, 25> chain{};
    const uint32_t spacing = provider.ConsumeIntegralInRange<uint32_t>(1, 86400);
    for (size_t i = 0; i < chain.size(); ++i) {
        auto& block = chain[i];
        block.nHeight = i;
        block.nTime = 1000 + i * spacing;
        block.nBaseTarget = previous;
        if (i) {
            block.pprev = &chain[i - 1];
            block.BuildSkip();
        }
    }
    const auto target = pocx::consensus::GetNextBaseTarget(&chain.back(), params);
    assert(target >= previous - previous / 5);
    assert(target <= previous + previous / 5);
    const uint64_t timespan = std::clamp<uint64_t>(24ULL * spacing,
        24ULL * params.nPowTargetSpacing / 2, 48ULL * params.nPowTargetSpacing);
    const auto expected = std::min(cap, std::clamp<uint64_t>(
        previous * timespan / (24ULL * params.nPowTargetSpacing),
        previous - previous / 5, previous + previous / 5));
    assert(target == expected);

    auto& block = chain.back();
    auto bytes = provider.ConsumeBytes<uint8_t>(32);
    std::copy(bytes.begin(), bytes.end(), block.generationSignature.begin());
    for (auto& byte : block.pocxProof.account_id) byte = provider.ConsumeIntegral<uint8_t>();
    HashWriter reference;
    reference << block.generationSignature << block.pocxProof.account_id;
    assert(pocx::consensus::GetNextGenerationSignature(&block) == reference.GetHash());
}
