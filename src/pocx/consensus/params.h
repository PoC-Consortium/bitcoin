// Copyright (c) 2025 The Proof of Capacity Consortium
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_POCX_CONSENSUS_PARAMS_H
#define BITCOIN_POCX_CONSENSUS_PARAMS_H

#include <cstdint>

namespace pocx {
namespace consensus {

/** PoCX compression bounds for a given block height */
struct PoCXCompressionBounds {
    uint32_t nPoCXMinCompression;
    uint32_t nPoCXTargetCompression;
};

/** Calculate genesis base target for 1 TiB starting network capacity (mainnet) or 16 nonces (regtest) */
uint64_t CalculateGenesisBaseTarget(int64_t target_spacing_seconds, bool is_regtest = false);

/** Get PoCX compression bounds for a given height */
PoCXCompressionBounds GetPoCXCompressionBounds(int64_t nHeight, int64_t nSubsidyHalvingInterval);

} // namespace consensus
} // namespace pocx

#endif // BITCOIN_POCX_CONSENSUS_PARAMS_H
