// Copyright (c) 2025 The Proof of Capacity Consortium
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <bitcoin-build-config.h> // IWYU pragma: keep

#include <pocx/rpc/assignments.h>
#include <rpc/server.h>
#include <rpc/util.h>
#include <rpc/server_util.h>
#include <validation.h>
#include <key_io.h>
#include <coins.h>
#include <pocx/assignments/assignment_state.h>
#include <uint256.h>
#include <node/context.h>

using node::NodeContext;

namespace pocx {
namespace rpc {

//
// Node-Category RPC Commands (no wallet required)
//

static RPCHelpMan get_assignment()
{
    return RPCHelpMan{"get_assignment",
        "Get assignment details for a specific plot address\n"
        "Returns the current assignment status and details for a plot address.\n",
        {
            {"plot_address", RPCArg::Type::STR, RPCArg::Optional::NO, "The plot address to query (bech32)"},
            {"height", RPCArg::Type::NUM, RPCArg::Optional::OMITTED, "Block height to check (default: current tip)"},
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::STR, "plot_address", "The plot address"},
                {RPCResult::Type::NUM, "height", "Block height checked"},
                {RPCResult::Type::BOOL, "has_assignment", "Whether plot has an active assignment"},
                {RPCResult::Type::STR, "state", "Assignment state (UNASSIGNED/ASSIGNING/ASSIGNED/REVOKING/REVOKED)"},
                {RPCResult::Type::STR, "forging_address", "Address assigned to forge (if any)"},
                {RPCResult::Type::STR_HEX, "assignment_txid", "Transaction that created the assignment"},
                {RPCResult::Type::NUM, "assignment_height", "Block height when assignment was created"},
                {RPCResult::Type::NUM, "activation_height", "Block height when assignment became active"},
                {RPCResult::Type::BOOL, "revoked", "Whether the assignment has been revoked"},
            }
        },
        RPCExamples{
            HelpExampleCli("get_assignment", "\"pocx1qplot...\"")
            + HelpExampleCli("get_assignment", "\"pocx1qplot...\" 800000")
            + HelpExampleRpc("get_assignment", "\"pocx1qplot...\"")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
        {
            std::string plot_address = request.params[0].get_str();

            // Parse plot address
            CTxDestination plot_dest = DecodeDestination(plot_address);
            if (!IsValidDestination(plot_dest)) {
                throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid plot address");
            }

            const WitnessV0KeyHash* plot_keyhash = std::get_if<WitnessV0KeyHash>(&plot_dest);
            if (!plot_keyhash) {
                throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Plot address must be P2WPKH (bech32)");
            }

            std::array<uint8_t, 20> plot_array;
            std::copy(plot_keyhash->begin(), plot_keyhash->end(), plot_array.begin());

            // Get assignment from chainstate
            LOCK(cs_main);
            CCoinsViewCache& view = EnsureAnyChainman(request.context).ActiveChainstate().CoinsTip();

            // Use provided height or default to current tip
            int height = request.params[1].isNull()
                ? EnsureAnyChainman(request.context).ActiveChainstate().m_chain.Height()
                : request.params[1].getInt<int>();

            auto assignment = view.GetForgingAssignment(plot_array, height);

            UniValue result(UniValue::VOBJ);
            result.pushKV("plot_address", plot_address);
            result.pushKV("height", height);

            if (assignment.has_value()) {
                result.pushKV("has_assignment", true);

                ForgingState currentState = assignment->GetStateAtHeight(height);
                std::string state_str;
                switch (currentState) {
                    case ForgingState::UNASSIGNED: state_str = "UNASSIGNED"; break;
                    case ForgingState::ASSIGNING: state_str = "ASSIGNING"; break;
                    case ForgingState::ASSIGNED: state_str = "ASSIGNED"; break;
                    case ForgingState::REVOKING: state_str = "REVOKING"; break;
                    case ForgingState::REVOKED: state_str = "REVOKED"; break;
                    default: state_str = "UNKNOWN"; break;
                }
                result.pushKV("state", state_str);

                // Convert forging address to bech32
                uint160 forging_hash;
                std::copy(assignment->forgingAddress.begin(), assignment->forgingAddress.end(), forging_hash.begin());
                WitnessV0KeyHash forging_keyhash(forging_hash);
                std::string forging_address = EncodeDestination(forging_keyhash);
                result.pushKV("forging_address", forging_address);

                result.pushKV("assignment_txid", assignment->assignment_txid.ToString());
                result.pushKV("assignment_height", assignment->assignment_height);
                result.pushKV("activation_height", assignment->assignment_effective_height);

                if (assignment->revoked) {
                    result.pushKV("revoked", true);
                    result.pushKV("revocation_txid", assignment->revocation_txid.ToString());
                    result.pushKV("revocation_height", assignment->revocation_height);
                    result.pushKV("revocation_effective_height", assignment->revocation_effective_height);
                } else {
                    result.pushKV("revoked", false);
                }
            } else {
                result.pushKV("has_assignment", false);
                result.pushKV("state", "UNASSIGNED");
                result.pushKV("forging_address", "");
            }

            return result;
        },
    };
}

//
// Command Registration
//

static const CRPCCommand commands[] = {
    // Node commands (mining category - no wallet required)
    {"mining", &get_assignment},
};

std::span<const CRPCCommand> GetAssignmentsNodeRPCCommands()
{
    return commands;
}

} // namespace rpc
} // namespace pocx

