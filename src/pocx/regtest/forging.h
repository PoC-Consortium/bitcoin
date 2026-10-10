// Copyright (c) 2025 The Proof of Capacity Consortium
// Distributed under the MIT software license; see COPYING.
#ifndef BITCOIN_POCX_REGTEST_FORGING_H
#define BITCOIN_POCX_REGTEST_FORGING_H

#include <pocx/regtest/proof.h>

#include <array>
#include <cstdint>
#include <string>

class CBlock;
namespace Consensus { struct Params; }

namespace pocx {
namespace regtest {

// Wallet-free synthetic-plot mining, restricted to the regtest chain and the
// reserved account/zero seed. Real plots use a different account.
// Hardcoded compressed private key, WIF:
// cMvJbCxo3qCee5EFHSYVuK7UP69ijvHtXmrikzKtjbtEvzUYU5T5
extern const std::array<uint8_t, 32> kRegtestForgingPrivKey;

// Fill the proof and minimum deadline, recompute the merkle root and sign the
// template. Advance mocktime if enabled; otherwise report the required wait.
bool ForgeRegtestBlock(
    CBlock& block,
    const Consensus::Params& consensus,
    int64_t prev_time,
    std::string& err);

} // namespace regtest
} // namespace pocx

#endif // BITCOIN_POCX_REGTEST_FORGING_H
