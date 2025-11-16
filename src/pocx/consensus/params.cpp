// Copyright (c) 2025 The Proof of Capacity Consortium
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <pocx/consensus/params.h>

namespace pocx {
namespace consensus {

uint64_t CalculateGenesisBaseTarget(int64_t target_spacing_seconds, bool low_capacity_calibration) {
    // Genesis base target calculation for 1 TiB starting network capacity
    //
    // Formula: 2^42 / block_time_seconds
    //
    // Derivation:
    // - Each nonce represents 256 KiB (64 bytes * 4096 scoops)
    // - 1 TiB = 2^22 nonces
    // - Expected minimum quality for n nonces ≈ 2^64 / n
    // - For 1 TiB: E(quality) = 2^64 / 2^22 = 2^42
    // - quality_adjusted = quality / base_target
    // - For target block time: base_target = E(quality) / block_time
    // - Therefore: base_target = 2^42 / block_time
    //
    // Regtest uses 2^60 for low capacity mode (16 nonces = 4 MiB) to enable development mining without plotted storage.

    const uint64_t POWER_42 = 4398046511104ULL;        // 2^42 for 1 TiB (mainnet)
    const uint64_t POWER_60 = 1152921504606846976ULL;  // 2^60 for 16 nonces (regtest)

    uint64_t base_power = low_capacity_calibration ? POWER_60 : POWER_42;
    uint64_t genesis_base_target = base_power / target_spacing_seconds;

    // Ensure we don't go to zero
    if (genesis_base_target == 0) {
        genesis_base_target = 1;
    }

    return genesis_base_target;
}

PoCXCompressionBounds GetPoCXCompressionBounds(int64_t nHeight, int64_t nSubsidyHalvingInterval) {
    uint8_t min_compression = 1;

    // Stepwise adjustments at years: 4, 12, 28, 60, 124
    // Convert years to block heights using nSubsidyHalvingInterval (1 Halving = 4 years)
    if (nHeight >= (4  / 4) * nSubsidyHalvingInterval)  min_compression = 2;  // Year 4
    if (nHeight >= (12 / 4) * nSubsidyHalvingInterval) min_compression = 3;  // Year 12
    if (nHeight >= (28 / 4) * nSubsidyHalvingInterval) min_compression = 4;  // Year 28
    if (nHeight >= (60 / 4) * nSubsidyHalvingInterval) min_compression = 5;  // Year 60
    if (nHeight >= (124/ 4) * nSubsidyHalvingInterval) min_compression = 6;  // Year 124

    uint8_t target_compression = min_compression + 1; // Max_Param = Min + 1

    return {min_compression, target_compression};
}

} // namespace consensus
} // namespace pocx
