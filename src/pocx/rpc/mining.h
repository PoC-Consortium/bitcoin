// Copyright (c) 2025 The Proof of Capacity Consortium
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_POCX_RPC_MINING_H
#define BITCOIN_POCX_RPC_MINING_H

#include <span.h>

class CRPCTable;
struct CRPCCommand;

namespace pocx {
namespace rpc {

std::span<const CRPCCommand> GetMiningRPCCommands();
void RegisterPoCXRPCCommands(CRPCTable& t);

} // namespace rpc
} // namespace pocx

#endif // BITCOIN_POCX_RPC_MINING_H