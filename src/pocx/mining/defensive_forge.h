// Copyright (c) 2025 The Proof of Capacity Consortium
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_POCX_MINING_DEFENSIVE_FORGE_H
#define BITCOIN_POCX_MINING_DEFENSIVE_FORGE_H

#include <uint256.h>

#include <cstdint>
#include <functional>

namespace pocx {
namespace mining {

// Callback type: (tip_hash, incoming_quality) -> should_reject
using DefensiveForgeCallback = std::function<bool(const uint256&, uint64_t)>;

void RegisterDefensiveForgeCallback(DefensiveForgeCallback cb);
void UnregisterDefensiveForgeCallback();
bool TryDefensiveForgeViaCallback(const uint256& tip_hash, uint64_t incoming_quality);

} // namespace mining
} // namespace pocx

#endif // BITCOIN_POCX_MINING_DEFENSIVE_FORGE_H
