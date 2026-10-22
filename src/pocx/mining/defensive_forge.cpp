// Copyright (c) 2025 The Proof of Capacity Consortium
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <pocx/mining/defensive_forge.h>

#include <mutex>

namespace pocx {
namespace mining {

static std::mutex g_defensive_forge_mutex;
static DefensiveForgeCallback g_defensive_forge_callback;

void RegisterDefensiveForgeCallback(DefensiveForgeCallback cb)
{
    std::lock_guard<std::mutex> lock(g_defensive_forge_mutex);
    g_defensive_forge_callback = std::move(cb);
}

void UnregisterDefensiveForgeCallback()
{
    std::lock_guard<std::mutex> lock(g_defensive_forge_mutex);
    g_defensive_forge_callback = nullptr;
}

bool TryDefensiveForgeViaCallback(const uint256& tip_hash, uint64_t incoming_quality)
{
    std::lock_guard<std::mutex> lock(g_defensive_forge_mutex);
    if (g_defensive_forge_callback) {
        return g_defensive_forge_callback(tip_hash, incoming_quality);
    }
    return false; // No callback registered - accept block
}

} // namespace mining
} // namespace pocx
