// Copyright (c) 2025 The Proof of Capacity Consortium
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_POCX_MINING_WALLET_SIGNING_H
#define BITCOIN_POCX_MINING_WALLET_SIGNING_H

#include <string>
#include <uint256.h>

class CBlock;

namespace interfaces {
class Wallet;
}

namespace node {
struct NodeContext;
}

namespace pocx {
namespace mining {

/** Check if wallet has the key for a PoCX account */
bool HaveAccountKey(
    const std::string& account_id,
    interfaces::Wallet* wallet
);

/** Sign a PoCX block using wallet keys (supports descriptor and legacy wallets) */
bool SignPoCXBlock(
    interfaces::Wallet* wallet,
    const uint256& block_hash,
    const std::string& account_id,
    CBlock& block
);

/** Sign a PoCX block with available wallet (handles assignment resolution) */
bool SignPoCXBlockWithAvailableWallet(
    ::node::NodeContext* context,
    CBlock& block,
    const std::string& plot_account_id
);

} // namespace mining
} // namespace pocx

#endif // BITCOIN_POCX_MINING_WALLET_SIGNING_H
