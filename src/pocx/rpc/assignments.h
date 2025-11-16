// Copyright (c) 2025 The Proof of Capacity Consortium
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_POCX_RPC_ASSIGNMENTS_H
#define BITCOIN_POCX_RPC_ASSIGNMENTS_H

#include <rpc/util.h>
#include <rpc/server.h>
#include <span.h>

namespace pocx {
namespace rpc {

/** Get node-category assignment RPC commands (no wallet access required) */
std::span<const CRPCCommand> GetAssignmentsNodeRPCCommands();

} // namespace rpc
} // namespace pocx

#endif // BITCOIN_POCX_RPC_ASSIGNMENTS_H

