// Copyright (c) 2025 The Proof of Capacity Consortium
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <pocx/regtest/forging.h>

#include <chainparams.h>
#include <consensus/merkle.h>
#include <consensus/params.h>
#include <logging.h>
#include <pocx/algorithms/time_bending.h>
#include <pocx/consensus/params.h>
#include <pocx/mining/key_signing.h>
#include <primitives/block.h>
#include <tinyformat.h>
#include <util/time.h>

#include <algorithm>
#include <chrono>
#include <limits>

namespace pocx {
namespace regtest {

const std::array<uint8_t, 32> kRegtestForgingPrivKey = {
    0x0a, 0x15, 0x90, 0xdc, 0x88, 0x67, 0xab, 0x2a,
    0x1f, 0xc2, 0x84, 0x32, 0xdc, 0xc1, 0xc6, 0x14,
    0xfc, 0x0e, 0x5e, 0x0b, 0x16, 0x9b, 0x9c, 0xc9,
    0xf4, 0xdd, 0x72, 0x63, 0x23, 0x2c, 0x8f, 0xf8,
};


namespace {

bool ForgeRegtestBlockImpl(
    CBlock& block,
    int64_t prev_time,
    int64_t spacing,
    int64_t halving_interval,
    std::string& err)
{
    block.pocxProof.account_id = kRegtestForgingAccountId;
    block.pocxProof.seed       = kRegtestZeroSeed;

    const auto bounds = pocx::consensus::GetPoCXCompressionBounds(
        block.nHeight, halving_interval);
    block.pocxProof.compression = bounds.nPoCXMinCompression;

    uint64_t best_nonce    = 0;
    uint64_t best_quality  = 0;
    uint64_t best_poc_time = std::numeric_limits<uint64_t>::max();
    bool     found         = false;

    CBlockHeader candidate{block};
    for (uint64_t nonce = 0; nonce < kMaxRegtestNonces; ++nonce) {
        candidate.pocxProof.nonce = nonce;
        uint64_t quality{0};
        if (!ComputeRegtestHotPathQuality(candidate, &quality)) {
            err = "regtest: failed to compute synthetic quality";
            return false;
        }

        const uint64_t poc_time = pocx::algorithms::CalculateTimeBendedDeadline(
            quality, block.nBaseTarget, spacing);

        if (!found || poc_time < best_poc_time) {
            best_nonce    = nonce;
            best_quality  = quality;
            best_poc_time = poc_time;
            found         = true;
        }
    }

    block.pocxProof.nonce   = best_nonce;
    block.pocxProof.quality = best_quality;

    const int64_t min_time   = prev_time + static_cast<int64_t>(best_poc_time);
    const int64_t now        = GetTime();
    const int64_t block_time = std::max(min_time, now);

    if (Params().IsMockableChain() && GetMockTime().count() != 0) {
        if (now < block_time) SetMockTime(block_time);
        block.nTime = static_cast<uint32_t>(block_time);
    } else {
        if (now < min_time) {
            err = strprintf(
                "regtest: block not yet forgeable, wait %d seconds or enable setmocktime",
                min_time - now);
            return false;
        }
        block.nTime = static_cast<uint32_t>(now);
    }

    block.hashMerkleRoot = BlockMerkleRoot(block);

    if (!pocx::mining::SignPoCXBlockWithKey(block, kRegtestForgingPrivKey)) {
        err = "regtest: failed to sign block with hardcoded regtest key";
        return false;
    }

    LogDebug(BCLog::POCX,
             "ForgeRegtestBlock: height=%d nonce=%llu quality=%llu poc_time=%llu nTime=%u\n",
             block.nHeight, (unsigned long long)best_nonce,
             (unsigned long long)best_quality,
             (unsigned long long)best_poc_time, block.nTime);

    return true;
}

} // namespace

bool ForgeRegtestBlock(
    CBlock& block,
    const Consensus::Params& consensus,
    int64_t prev_time,
    std::string& err)
{
    return ForgeRegtestBlockImpl(
        block,
        prev_time,
        consensus.nPowTargetSpacing,
        consensus.nSubsidyHalvingInterval,
        err);
}

} // namespace regtest
} // namespace pocx
