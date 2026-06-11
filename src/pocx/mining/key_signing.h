// Copyright (c) 2025 The Proof of Capacity Consortium
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_POCX_MINING_KEY_SIGNING_H
#define BITCOIN_POCX_MINING_KEY_SIGNING_H

#include <array>
#include <cstdint>

class CBlock;

namespace pocx {
namespace mining {

// Sign a PoCX block with a raw 32-byte compressed private key.
// No wallet involved. Caller ensures the key matches pocxProof.account_id.
bool SignPoCXBlockWithKey(CBlock& block, const std::array<uint8_t, 32>& privkey_bytes);

} // namespace mining
} // namespace pocx

#endif // BITCOIN_POCX_MINING_KEY_SIGNING_H
