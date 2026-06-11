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
    // Regtest uses 2^58 for low capacity mode (64 nonces = 16 MiB) to enable development mining without plotted storage.
    // POWER_58 is the largest safe value that keeps the difficulty-adjustment multiplication in uint64.

    const uint64_t POWER_42 = 4398046511104ULL;        // 2^42 for 1 TiB (mainnet/testnet)
    const uint64_t POWER_58 = 288230376151711744ULL;   // 2^58 for 64 nonces (regtest)

    // Difficulty adjustment computes avg_base_target * actual_timespan / target_timespan
    // where avg_base_target <= POWER_58/spacing and actual_timespan <= 2*window*spacing,
    // so the product is bounded by POWER_58 * 2 * window (spacing cancels).
    // Regtest uses window=24 -> POWER_58 * 48 < 2^64.
    static_assert(POWER_58 <= (UINT64_MAX / (2 * 24)),
                  "POWER_58 * 2 * rolling_window overflows uint64 in difficulty math");

    uint64_t base_power = low_capacity_calibration ? POWER_58 : POWER_42;
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
