// Copyright (c) 2025 The Proof of Capacity Consortium
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

//
// WALLET INTEGRATION: COMPLETE
//
// This file contains wallet functions for creating forging assignment transactions.
// Updated for the OP_RETURN-only architecture.
//
// OP_RETURN-only transaction format:
//   Assignment: Input (plot owner) → OP_RETURN (POCX + plot + forge) → Change
//   Revocation: Input (plot owner) → OP_RETURN (XCOP + plot) → Change
//

#include <pocx/assignments/transactions.h>
#include <pocx/assignments/opcodes.h>
#include <wallet/spend.h>
#include <wallet/wallet.h>
#include <wallet/coincontrol.h>
#include <wallet/fees.h>
#include <consensus/amount.h>
#include <policy/policy.h>
#include <util/strencodings.h>
#include <util/moneystr.h>
#include <key_io.h>
#include <addresstype.h>
#include <script/signingprovider.h>
#include <script/script.h>
#include <coins.h>
#include <logging.h>
#include <algorithm>

namespace pocx {
namespace assignments {

using ::wallet::CCoinControl;
using ::wallet::CRecipient;
using ::wallet::CWalletTx;

namespace {

enum class TransactionType { ASSIGNMENT, REVOCATION };

util::Result<CTransactionRef> CreateForgingTransactionImpl(
    ::wallet::CWallet& wallet,
    const std::string& plotAddressStr,
    const std::optional<std::string>& forgingAddressStr,
    const ::wallet::CCoinControl& coin_control,
    TransactionType type,
    CAmount& fee
) {
    // OP_RETURN-only architecture:
    // Transaction format:
    //   Assignment: Input (plot owner) → OP_RETURN (POCX + plot + forge) → Change
    //   Revocation: Input (plot owner) → OP_RETURN (XCOP + plot) → Change

    // Parse and validate plot address
    CTxDestination plotDest = DecodeDestination(plotAddressStr);
    const WitnessV0KeyHash* plotKeyHash = std::get_if<WitnessV0KeyHash>(&plotDest);
    if (!plotKeyHash) {
        return util::Error{_("Plot address must be P2WPKH (bech32)")};
    }

    // Convert plot address to 20-byte array
    std::array<uint8_t, 20> plotAddress;
    std::copy(plotKeyHash->begin(), plotKeyHash->end(), plotAddress.begin());

    // Parse and validate forging address (assignment only)
    std::array<uint8_t, 20> forgingAddress;
    if (type == TransactionType::ASSIGNMENT) {
        if (!forgingAddressStr.has_value()) {
            return util::Error{_("Forging address required for assignment")};
        }
        CTxDestination forgingDest = DecodeDestination(*forgingAddressStr);
        const WitnessV0KeyHash* forgeKeyHash = std::get_if<WitnessV0KeyHash>(&forgingDest);
        if (!forgeKeyHash) {
            return util::Error{_("Forging address must be P2WPKH (bech32)")};
        }
        std::copy(forgeKeyHash->begin(), forgeKeyHash->end(), forgingAddress.begin());
    }

    LOCK(wallet.cs_wallet);

    // Configure coin control first - set min_depth to avoid unconfirmed coins
    CCoinControl plotCoinControl = coin_control;
    if (!plotCoinControl.m_feerate.has_value()) {
        plotCoinControl.m_feerate = GetMinimumFeeRate(wallet, plotCoinControl, nullptr);
    }
    plotCoinControl.m_min_depth = 1;  // Only use confirmed coins
    plotCoinControl.m_allow_other_inputs = true;  // Allow other inputs if plot coin insufficient for fees

    // Find largest UTXO from plot address to prove ownership
    CScript plotScript = GetScriptForDestination(plotDest);
    auto availableCoins = AvailableCoins(wallet, &plotCoinControl);

    COutPoint largestPlotCoin;
    CAmount largestAmount = 0;
    bool hasPlotCoins = false;

    for (const auto& coin : availableCoins.All()) {
        if (coin.txout.scriptPubKey == plotScript) {
            if (coin.txout.nValue > largestAmount) {
                largestPlotCoin = coin.outpoint;
                largestAmount = coin.txout.nValue;
                hasPlotCoins = true;
            }
        }
    }

    if (!hasPlotCoins) {
        return util::Error{_("No coins available at the plot address. Cannot prove ownership.")};
    }

    // Force selection of largest plot address coin
    plotCoinControl.Select(largestPlotCoin);

    // Create dummy recipient (we'll replace with OP_RETURN)
    std::vector<CRecipient> recipients;
    recipients.push_back({plotDest, 1000, false});  // Temporary output

    // Create transaction - force change to position 1 to ensure output 0 is dummy
    // Sign it so we can get accurate size including witness data
    auto res = CreateTransaction(wallet, recipients, /*change_pos=*/1, plotCoinControl, /*sign=*/true);
    if (!res) {
        return util::Error{util::ErrorString(res)};
    }

    // Get size and fee BEFORE modification
    size_t size_before = GetVirtualTransactionSize(*res->tx);
    CAmount fee_before = res->fee;  // Actual calculated fee (not including 1000 sat dummy)

    // Replace first output with OP_RETURN
    CMutableTransaction mtx(*res->tx);
    CScript opReturnScript = (type == TransactionType::ASSIGNMENT)
        ? CreateAssignmentOpReturn(plotAddress, forgingAddress)
        : CreateRevocationOpReturn(plotAddress);
    mtx.vout[0] = CTxOut(0, opReturnScript);

    // Get size AFTER modification (witness data still intact from signing)
    size_t size_after = GetVirtualTransactionSize(CTransaction(mtx));

    // Scale fee proportionally using ceiling division to avoid underpayment from rounding
    CAmount fee_after = (fee_before * size_after + size_before - 1) / size_before;

    // Calculate additional fee needed beyond what CreateTransaction already allocated
    CAmount additional_fee = fee_after - fee_before;

    // Verify dummy amount is sufficient for fee adjustment
    if (additional_fee > 1000) {
        return util::Error{strprintf(
            _("Transaction size increase requires %d sat additional fee, but only 1000 sat dummy available"),
            additional_fee
        )};
    }

    // Return from dummy what doesn't compromise the fee (1000 sat dummy minus additional fee)
    CAmount safe_to_return = 1000 - additional_fee;
    if (safe_to_return > 0 && mtx.vout.size() > 1) {
        mtx.vout[1].nValue += safe_to_return;
    }

    // Re-sign the transaction
    std::map<COutPoint, Coin> coins;
    for (const auto& input : mtx.vin) {
        const CWalletTx* wtx = wallet.GetWalletTx(input.prevout.hash);
        if (!wtx) {
            return util::Error{_("Failed to find input transaction")};
        }
        coins[input.prevout] = Coin(wtx->tx->vout[input.prevout.n], 1, false);
    }

    std::map<int, bilingual_str> input_errors;
    bool complete = wallet.SignTransaction(mtx, coins, SIGHASH_ALL, input_errors);
    if (!complete) {
        const char* tx_type = (type == TransactionType::ASSIGNMENT) ? "assignment" : "revocation";
        return util::Error{strprintf(_("Failed to sign forging %s transaction"), tx_type)};
    }

    fee = fee_after;
    return MakeTransactionRef(std::move(mtx));
}

} // anonymous namespace

util::Result<CTransactionRef> CreateForgingAssignmentTransaction(
    ::wallet::CWallet& wallet,
    const std::string& plotAddress,
    const std::string& forgingAddress,
    const ::wallet::CCoinControl& coin_control,
    CAmount& fee
) {
    return CreateForgingTransactionImpl(wallet, plotAddress, forgingAddress,
                                        coin_control, TransactionType::ASSIGNMENT, fee);
}

util::Result<CTransactionRef> CreateForgingRevocationTransaction(
    ::wallet::CWallet& wallet,
    const std::string& plotAddress,
    const ::wallet::CCoinControl& coin_control,
    CAmount& fee
) {
    return CreateForgingTransactionImpl(wallet, plotAddress, std::nullopt,
                                        coin_control, TransactionType::REVOCATION, fee);
}

} // namespace assignments
} // namespace pocx