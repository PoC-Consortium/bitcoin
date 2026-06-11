// Copyright (c) 2025 The Proof of Capacity Consortium
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <pocx/regtest/forging.h>

#include <chainparams.h>
#include <consensus/merkle.h>
#include <consensus/params.h>
#include <crypto/sha256.h>
#include <logging.h>
#include <pocx/algorithms/quality.h>
#include <pocx/algorithms/time_bending.h>
#include <pocx/consensus/params.h>
#include <pocx/crypto/shabal256_lite.h>
#include <pocx/mining/key_signing.h>
#include <primitives/block.h>
#include <tinyformat.h>
#include <util/time.h>

#include <algorithm>
#include <chrono>
#include <cstring>
#include <limits>

namespace pocx {
namespace regtest {

const std::array<uint8_t, 32> kRegtestForgingPrivKey = {
    0x0a, 0x15, 0x90, 0xdc, 0x88, 0x67, 0xab, 0x2a,
    0x1f, 0xc2, 0x84, 0x32, 0xdc, 0xc1, 0xc6, 0x14,
    0xfc, 0x0e, 0x5e, 0x0b, 0x16, 0x9b, 0x9c, 0xc9,
    0xf4, 0xdd, 0x72, 0x63, 0x23, 0x2c, 0x8f, 0xf8,
};

const std::array<uint8_t, 20> kRegtestForgingAccountId = {
    0x1e, 0x50, 0xbc, 0xc1, 0x7e, 0x3c, 0x6a, 0xb4,
    0x2d, 0x39, 0xa6, 0xa5, 0xd7, 0x9b, 0x0d, 0x7a,
    0x69, 0x83, 0xa7, 0x65,
};

const std::array<uint8_t, 32> kRegtestZeroSeed = {};

void ComputeRegtestFakeScoop(
    const std::array<uint8_t, 20>& account,
    const std::array<uint8_t, 32>& seed,
    uint64_t nonce,
    int scoop_num,
    uint32_t compression,
    uint8_t out[64])
{
    // [tag(1) | account(20) | seed(32) | nonce_be(8) | scoop_be(4) | compression_be(4)]
    constexpr size_t INPUT_LEN = 1 + 20 + 32 + 8 + 4 + 4;
    uint8_t input[INPUT_LEN];

    std::memcpy(input + 1,  account.data(), 20);
    std::memcpy(input + 21, seed.data(),    32);

    for (int i = 0; i < 8; ++i) {
        input[53 + i] = static_cast<uint8_t>((nonce >> (56 - 8 * i)) & 0xFF);
    }
    const uint32_t scoop_u32 = static_cast<uint32_t>(scoop_num);
    for (int i = 0; i < 4; ++i) {
        input[61 + i] = static_cast<uint8_t>((scoop_u32 >> (24 - 8 * i)) & 0xFF);
    }
    for (int i = 0; i < 4; ++i) {
        input[65 + i] = static_cast<uint8_t>((compression >> (24 - 8 * i)) & 0xFF);
    }

    input[0] = 0xA0;
    CSHA256().Write(input, INPUT_LEN).Finalize(out);
    input[0] = 0xA1;
    CSHA256().Write(input, INPUT_LEN).Finalize(out + 32);
}

bool IsRegtestHotPathProof(const PoCXProof& proof)
{
    return proof.account_id == kRegtestForgingAccountId &&
           proof.seed == kRegtestZeroSeed;
}

namespace {

void ReverseGenSig(const uint8_t src[32], uint8_t dst[32])
{
    for (int i = 0; i < 32; ++i) dst[i] = src[31 - i];
}

uint64_t ComputeQualityForNonce(
    const std::array<uint8_t, 20>& account,
    const std::array<uint8_t, 32>& seed,
    uint64_t nonce,
    uint64_t height,
    uint32_t compression,
    const uint8_t gen_sig_reversed[32])
{
    const int scoop_num = pocx::algorithms::CalculateScoop(height, gen_sig_reversed);
    uint8_t fake_scoop[64];
    ComputeRegtestFakeScoop(account, seed, nonce, scoop_num, compression, fake_scoop);
    return pocx::crypto::Shabal256Lite(fake_scoop, gen_sig_reversed);
}

} // namespace

bool ComputeRegtestHotPathQuality(const CBlockHeader& block, uint64_t* out_quality)
{
    if (!out_quality) return false;
    if (block.pocxProof.nonce >= kMaxRegtestNonces) return false;

    uint8_t gen_sig_reversed[32];
    ReverseGenSig(block.generationSignature.data(), gen_sig_reversed);

    *out_quality = ComputeQualityForNonce(
        block.pocxProof.account_id,
        block.pocxProof.seed,
        block.pocxProof.nonce,
        static_cast<uint64_t>(block.nHeight),
        block.pocxProof.compression,
        gen_sig_reversed);
    return true;
}

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

    uint8_t gen_sig_reversed[32];
    ReverseGenSig(block.generationSignature.data(), gen_sig_reversed);

    uint64_t best_nonce    = 0;
    uint64_t best_quality  = 0;
    uint64_t best_poc_time = std::numeric_limits<uint64_t>::max();
    bool     found         = false;

    for (uint64_t nonce = 0; nonce < kMaxRegtestNonces; ++nonce) {
        const uint64_t quality = ComputeQualityForNonce(
            kRegtestForgingAccountId,
            kRegtestZeroSeed,
            nonce,
            static_cast<uint64_t>(block.nHeight),
            block.pocxProof.compression,
            gen_sig_reversed);

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
