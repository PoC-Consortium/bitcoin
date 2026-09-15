// Copyright (c) 2025 The Proof of Capacity Consortium
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_POCX_RPC_MINING_H
#define BITCOIN_POCX_RPC_MINING_H

#include <span.h>

class CRPCTable;
class CRPCCommand;

namespace pocx {
namespace rpc {

std::span<const CRPCCommand> GetMiningRPCCommands();
void RegisterPoCXRPCCommands(CRPCTable& t);

/** Stop and destroy the forging scheduler (joins its worker, unregisters the
 *  defensive-forge callback) and refuse any later initialization. Safe to call
 *  when never initialized and safe to call repeatedly. */
void ShutdownPoCXScheduler();

} // namespace rpc
} // namespace pocx

#endif // BITCOIN_POCX_RPC_MINING_H
