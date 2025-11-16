// Copyright (c) 2025 The Proof of Capacity Consortium
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <bitcoin-build-config.h> // IWYU pragma: keep

#include <pocx/rpc/assignments_wallet.h>
#include <wallet/rpc/util.h>
#include <pocx/assignments/transactions.h>
#include <wallet/coincontrol.h>
#include <wallet/wallet.h>
#include <rpc/server.h>
#include <rpc/util.h>
#include <chainparams.h>
#include <util/translation.h>
#include <core_io.h>

namespace pocx {
namespace rpc {

using ::wallet::GetWalletForJSONRPCRequest;

//
// Wallet-Category RPC Commands (require wallet access)
//

static RPCHelpMan create_assignment()
{
    return RPCHelpMan{"create_assignment",
        "Create a forging assignment transaction (OP_RETURN-only architecture)\n"
        "Creates an OP_RETURN output with POCX marker + plot address + forging address (46 bytes total).\n"
        "Transaction must be signed by plot owner to prove ownership.\n"
        "Assignment becomes active after nForgingAssignmentDelay blocks.\n",
        {
            {"plot_address", RPCArg::Type::STR, RPCArg::Optional::NO, "The plot owner address (bech32)"},
            {"forging_address", RPCArg::Type::STR, RPCArg::Optional::NO, "The address to assign forging rights to (bech32)"},
            {"fee_rate", RPCArg::Type::AMOUNT, RPCArg::Default{0}, "Fee rate in " + CURRENCY_UNIT + "/kvB"},
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::STR_HEX, "txid", "The transaction id"},
                {RPCResult::Type::STR_HEX, "hex", "The transaction hex"},
                {RPCResult::Type::STR, "plot_address", "The plot address"},
                {RPCResult::Type::STR, "forging_address", "The forging address"},
            }
        },
        RPCExamples{
            HelpExampleCli("create_assignment", "\"bc1qplot...\" \"bc1qforger...\"")
            + HelpExampleCli("create_assignment", "\"bc1qplot...\" \"bc1qforger...\" 0.0001")
            + HelpExampleRpc("create_assignment", "\"bc1qplot...\", \"bc1qforger...\"")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
        {
            std::shared_ptr<::wallet::CWallet> const pwallet = GetWalletForJSONRPCRequest(request);
            if (!pwallet) {
                throw JSONRPCError(RPC_WALLET_NOT_FOUND, "No wallet available");
            }

            if (pwallet->IsLocked()) {
                throw JSONRPCError(RPC_WALLET_UNLOCK_NEEDED, "Error: Please enter the wallet passphrase with walletpassphrase first.");
            }

            std::string plot_address = request.params[0].get_str();
            std::string forging_address = request.params[1].get_str();

            ::wallet::CCoinControl coin_control;
            if (request.params.size() > 2 && !request.params[2].isNull()) {
                coin_control.m_feerate = CFeeRate(AmountFromValue(request.params[2]), 1000);
            }

            CAmount fee;
            auto tx_result = pocx::assignments::CreateForgingAssignmentTransaction(*pwallet, plot_address, forging_address, coin_control, fee);
            if (!tx_result) {
                throw JSONRPCError(RPC_WALLET_ERROR, "Failed to create assignment transaction: " + util::ErrorString(tx_result).original);
            }

            CTransactionRef tx = *tx_result;

            pwallet->CommitTransaction(tx, /*mapValue=*/{}, /*orderForm=*/{});

            UniValue result(UniValue::VOBJ);
            result.pushKV("txid", tx->GetHash().GetHex());
            result.pushKV("hex", EncodeHexTx(*tx));
            result.pushKV("plot_address", plot_address);
            result.pushKV("forging_address", forging_address);

            return result;
        },
    };
}

static RPCHelpMan revoke_assignment()
{
    return RPCHelpMan{"revoke_assignment",
        "Revoke a forging assignment (OP_RETURN-only architecture)\n"
        "Creates an OP_RETURN output with XCOP marker + plot address (26 bytes total).\n"
        "Transaction must be signed by plot owner to prove ownership.\n"
        "Revocation becomes effective after nForgingRevocationDelay blocks.\n",
        {
            {"plot_address", RPCArg::Type::STR, RPCArg::Optional::NO, "The plot address to revoke assignment for"},
            {"fee_rate", RPCArg::Type::AMOUNT, RPCArg::Default{0}, "Fee rate in " + CURRENCY_UNIT + "/kvB"},
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::STR_HEX, "txid", "The revocation transaction id"},
                {RPCResult::Type::STR_HEX, "hex", "The revocation transaction hex"},
                {RPCResult::Type::STR, "plot_address", "The plot address"},
            }
        },
        RPCExamples{
            HelpExampleCli("revoke_assignment", "\"bc1qplot...\"")
            + HelpExampleRpc("revoke_assignment", "\"bc1qplot...\"")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
        {
            std::shared_ptr<::wallet::CWallet> const pwallet = GetWalletForJSONRPCRequest(request);
            if (!pwallet) {
                throw JSONRPCError(RPC_WALLET_NOT_FOUND, "No wallet available");
            }

            if (pwallet->IsLocked()) {
                throw JSONRPCError(RPC_WALLET_UNLOCK_NEEDED, "Error: Please enter the wallet passphrase with walletpassphrase first.");
            }

            std::string plot_address = request.params[0].get_str();

            ::wallet::CCoinControl coin_control;
            if (request.params.size() > 1 && !request.params[1].isNull()) {
                coin_control.m_feerate = CFeeRate(AmountFromValue(request.params[1]), 1000);
            }

            CAmount fee;
            auto tx_result = pocx::assignments::CreateForgingRevocationTransaction(*pwallet, plot_address, coin_control, fee);
            if (!tx_result) {
                throw JSONRPCError(RPC_WALLET_ERROR, "Failed to create revocation transaction: " + util::ErrorString(tx_result).original);
            }

            CTransactionRef tx = *tx_result;

            pwallet->CommitTransaction(tx, /*mapValue=*/{}, /*orderForm=*/{});

            UniValue result(UniValue::VOBJ);
            result.pushKV("txid", tx->GetHash().GetHex());
            result.pushKV("hex", EncodeHexTx(*tx));
            result.pushKV("plot_address", plot_address);

            return result;
        },
    };
}

//
// Command Registration
//

static const CRPCCommand commands[] = {
    {"wallet", &create_assignment},
    {"wallet", &revoke_assignment},
};

std::span<const CRPCCommand> GetAssignmentsWalletRPCCommands()
{
    return commands;
}

} // namespace rpc
} // namespace pocx

