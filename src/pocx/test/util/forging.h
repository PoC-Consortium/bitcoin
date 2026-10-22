// Copyright (c) 2026 The Bitcoin PoCX developers
// Distributed under the MIT software license; see COPYING.
#ifndef BITCOIN_POCX_TEST_UTIL_FORGING_H
#define BITCOIN_POCX_TEST_UTIL_FORGING_H
#include <chain.h>
#include <pocx/consensus/difficulty.h>
#include <pocx/regtest/forging.h>
#include <util/time.h>
#include <stdexcept>

// Build fixtures on the specified branch rather than on the active tip. Only
// the existing regtest synthetic path is used; no production validation bypass.
inline void ForgeTestBlock(CBlock& block, const CBlockIndex& prev, const Consensus::Params& consensus)
{
    block.hashPrevBlock = prev.GetBlockHash();
    block.nHeight = prev.nHeight + 1;
    block.generationSignature = pocx::consensus::GetNextGenerationSignature(&prev);
    block.nBaseTarget = prev.nNextBaseTarget;
    // Fork fixtures need branch-relative time. Carrying the active tip's time
    // onto an older fork changes its difficulty and invalidates work parity.
    const auto saved_time = GetMockTime();
    SetMockTime(std::chrono::seconds{prev.GetBlockTime() + 1});
    std::string error;
    if (!pocx::regtest::ForgeRegtestBlock(block, consensus, prev.GetBlockTime(), error)) {
        SetMockTime(saved_time);
        throw std::runtime_error("PoCX test forging failed: " + error);
    }
    SetMockTime(std::max(saved_time, std::chrono::seconds{block.nTime}));
}
#endif // BITCOIN_POCX_TEST_UTIL_FORGING_H
