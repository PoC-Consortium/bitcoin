// Copyright (c) 2025 The Proof of Capacity Consortium
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_POCX_MINING_BLOCK_SIGNING_H
#define BITCOIN_POCX_MINING_BLOCK_SIGNING_H

#include <optional>
#include <string>

class CBlock;
class ChainstateManager;

namespace node {
struct NodeContext;
} // namespace node

namespace pocx {
namespace mining {

//! If a submitted PoCX block is unsigned (all-zero signature), sign it in place
//! using a loaded, unlocked wallet that holds the key for the block's effective
//! signer, then return std::nullopt. An already-signed block is left untouched
//! (no-op success), so default processing is byte-identical to before.
//!
//! Returns a human-readable error when an unsigned block cannot be signed (no
//! wallet loaded, key absent, or the holding wallet is locked); the block is
//! left unchanged in that case.
//!
//! Node-side only: keys are accessed exclusively through the abstract
//! interfaces::Wallet, so bitcoin_node never links bitcoin_wallet.
std::optional<std::string> MaybeSignPoCXBlock(CBlock& block,
                                              ChainstateManager& chainman,
                                              const node::NodeContext& node);

} // namespace mining
} // namespace pocx

#endif // BITCOIN_POCX_MINING_BLOCK_SIGNING_H
