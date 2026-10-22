// Copyright (c) 2025 The Proof of Capacity Consortium
// Distributed under the MIT software license; see COPYING.

#include <pocx/regtest/proof.h>
#include <crypto/sha256.h>
#include <pocx/algorithms/quality.h>
#include <pocx/crypto/shabal256_lite.h>
#include <primitives/block.h>

#include <cstring>

namespace pocx {
namespace regtest {

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


} // namespace regtest
} // namespace pocx
