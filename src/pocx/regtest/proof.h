// Copyright (c) 2025 The Proof of Capacity Consortium
// Distributed under the MIT software license; see COPYING.
#ifndef BITCOIN_POCX_REGTEST_PROOF_H
#define BITCOIN_POCX_REGTEST_PROOF_H

#include <array>
#include <cstdint>

class CBlockHeader;
struct PoCXProof;

namespace pocx {
namespace regtest {

// HASH160 of the compressed pubkey for kRegtestForgingPrivKey.
// Address: rpocx1qregtest7834tgtfe56ja0xcd0f5c8fm97s2veu
extern const std::array<uint8_t, 20> kRegtestForgingAccountId;

extern const std::array<uint8_t, 32> kRegtestZeroSeed;

// Synthetic plot size: 2^(64-58) = 64 nonces, matching POWER_58 calibration.
constexpr uint64_t kMaxRegtestNonces = 64;

// Pure function: synthetic 64-byte scoop from (account, seed, nonce, scoop, compression).
// Used by both forge and validation so they agree on quality.
void ComputeRegtestFakeScoop(
    const std::array<uint8_t, 20>& account,
    const std::array<uint8_t, 32>& seed,
    uint64_t nonce,
    int scoop_num,
    uint32_t compression,
    uint8_t out[64]);

// True if account + seed match the hardcoded hot-path triple. Caller must
// verify the chain is regtest.
bool IsRegtestHotPathProof(const PoCXProof& proof);

// Validation fast path: recompute the expected synthetic quality for a
// hot-path proof. Caller compares to block.pocxProof.quality. Returns
// false if the nonce is out of range.
bool ComputeRegtestHotPathQuality(const CBlockHeader& block, uint64_t* out_quality);

} // namespace regtest
} // namespace pocx

#endif // BITCOIN_POCX_REGTEST_PROOF_H
