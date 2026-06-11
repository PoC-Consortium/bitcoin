// Copyright (c) 2025 The Proof of Capacity Consortium
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

//
// Hand-rolled forging transaction builder.
//
// Shape:
//   Assignment: inputs → OP_RETURN (POCX + plot + forge) [+ change]
//   Revocation: inputs → OP_RETURN (XCOP + plot)         [+ change]
//
// At least one input must pay from the plot address (P2WPKH ownership proof).
// Extra inputs (plot or foreign) are pulled in only when needed to cover fee.
// A change output is emitted only when the excess above fee exceeds dust;
// otherwise the tx is built changeless and the sub-dust excess goes to fee
// (same tradeoff Core applies to normal change).
//
// Change, when emitted, goes to a fresh wallet change address reserved via
// ReserveDestination, matching normal Bitcoin Core wallet behavior.
//
// Fee estimation uses CalculateMaximumSignedTxSize, which places max-size
// dummy witnesses via the wallet's key info and measures actual vsize —
// any drift vs. the real signed tx is one-sided (over-estimate), so the
// computed change value is never invalid.
//

#include <pocx/assignments/transactions.h>
#include <pocx/assignments/opcodes.h>
#include <wallet/spend.h>
#include <wallet/wallet.h>
#include <wallet/coincontrol.h>
#include <wallet/fees.h>
#include <consensus/amount.h>
#include <policy/policy.h>
#include <policy/feerate.h>
#include <outputtype.h>
#include <util/strencodings.h>
#include <util/moneystr.h>
#include <util/rbf.h>
#include <key_io.h>
#include <addresstype.h>
#include <script/signingprovider.h>
#include <script/script.h>
#include <coins.h>
#include <logging.h>
#include <algorithm>
#include <vector>

namespace pocx {
namespace assignments {

using ::wallet::CCoinControl;
using ::wallet::ReserveDestination;
using ::wallet::TxSize;

namespace {

enum class TransactionType { ASSIGNMENT, REVOCATION };

// One P2WPKH output is a fixed 31 vB (8B value + 1B scriptlen + 22B scriptPubKey).
// Used only to translate between "with change" and "changeless" vsize.
constexpr int32_t kP2WPKHOutputVsize = 31;

util::Result<CTransactionRef> CreateForgingTransactionImpl(
    ::wallet::CWallet& wallet,
    const std::string& plotAddressStr,
    const std::optional<std::string>& forgingAddressStr,
    const ::wallet::CCoinControl& coin_control,
    TransactionType type,
    CAmount& fee
) {
    // --- 1. Parse and validate addresses ---
    CTxDestination plotDest = DecodeDestination(plotAddressStr);
    const WitnessV0KeyHash* plotKeyHash = std::get_if<WitnessV0KeyHash>(&plotDest);
    if (!plotKeyHash) {
        return util::Error{_("Plot address must be P2WPKH (bech32)")};
    }
    std::array<uint8_t, 20> plotAddress;
    std::copy(plotKeyHash->begin(), plotKeyHash->end(), plotAddress.begin());

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

    // --- 2. Build OP_RETURN script ---
    CScript opReturnScript = (type == TransactionType::ASSIGNMENT)
        ? CreateAssignmentOpReturn(plotAddress, forgingAddress)
        : CreateRevocationOpReturn(plotAddress);

    // --- 3. Resolve feerate ---
    CCoinControl cc = coin_control;
    if (!cc.m_feerate.has_value()) {
        FeeCalculation feeCalc;
        cc.m_feerate = GetMinimumFeeRate(wallet, cc, &feeCalc);
        if (feeCalc.reason == FeeReason::FALLBACK && !wallet.m_allow_fallback_fee) {
            return util::Error{strprintf(_("Fee estimation failed. Fallbackfee is disabled. Wait a few blocks or enable %s."), "-fallbackfee")};
        }
    }
    cc.m_min_depth = 1;
    const CFeeRate feerate = *cc.m_feerate;

    LOCK(wallet.cs_wallet);

    // --- 4. Reserve a fresh change address (bech32 P2WPKH) ---
    // Held via ReserveDestination so it's only consumed if we actually emit change.
    ReserveDestination change_reserve(&wallet, OutputType::BECH32);
    auto op_change_dest = change_reserve.GetReservedDestination(/*internal=*/true);
    if (!op_change_dest) {
        return util::Error{strprintf(_("Failed to reserve change address: %s"),
                                     util::ErrorString(op_change_dest).original)};
    }
    const CScript changeScript = GetScriptForDestination(*op_change_dest);

    // --- 5. Partition available coins into plot vs. other ---
    CScript plotScript = GetScriptForDestination(plotDest);
    auto available = AvailableCoins(wallet, &cc);

    struct SelUtxo { COutPoint outpoint; CTxOut txout; };
    std::vector<SelUtxo> plotUtxos, otherUtxos;
    for (const auto& c : available.All()) {
        if (c.txout.scriptPubKey == plotScript) {
            plotUtxos.push_back({c.outpoint, c.txout});
        } else {
            otherUtxos.push_back({c.outpoint, c.txout});
        }
    }
    if (plotUtxos.empty()) {
        return util::Error{_("No coins available at the plot address. Cannot prove ownership.")};
    }

    auto byValueDesc = [](const SelUtxo& a, const SelUtxo& b) {
        return a.txout.nValue > b.txout.nValue;
    };
    std::sort(plotUtxos.begin(), plotUtxos.end(), byValueDesc);
    std::sort(otherUtxos.begin(), otherUtxos.end(), byValueDesc);

    // --- 6. Assemble a shape-A candidate (OP_RETURN + change placeholder) ---
    // We always size as shape A; shape B's vsize is vsize_A minus one P2WPKH output.
    CMutableTransaction mtx;
    mtx.version = 2;
    mtx.nLockTime = 0;
    mtx.vout.emplace_back(0, opReturnScript);
    mtx.vout.emplace_back(0, changeScript); // placeholder value, set at finalization

    std::vector<SelUtxo> selected;
    std::vector<CTxOut> input_txouts;
    CAmount input_sum = 0;
    auto addInput = [&](const SelUtxo& u) {
        CTxIn in(u.outpoint);
        in.nSequence = MAX_BIP125_RBF_SEQUENCE;
        mtx.vin.push_back(std::move(in));
        selected.push_back(u);
        input_txouts.push_back(u.txout);
        input_sum += u.txout.nValue;
    };

    // First input must be from the plot address (ownership proof).
    addInput(plotUtxos.front());
    size_t plot_idx = 1, other_idx = 0;

    const CFeeRate dust_relay_fee{DUST_RELAY_TX_FEE};
    const CAmount dust_change = GetDustThreshold(CTxOut(0, changeScript), dust_relay_fee);

    enum class Shape { NeedMore, WithChange, Changeless };
    auto classify = [&](Shape& out) -> bool {
        TxSize sizes = CalculateMaximumSignedTxSize(CTransaction(mtx), &wallet, input_txouts, &cc);
        if (sizes.vsize < 0) return false;
        const int32_t vsize_A = sizes.vsize;
        const int32_t vsize_B = vsize_A - kP2WPKHOutputVsize;
        const CAmount fee_A = feerate.GetFee(vsize_A);
        const CAmount fee_B = feerate.GetFee(vsize_B);
        if (input_sum >= fee_A + dust_change) { out = Shape::WithChange; return true; }
        if (input_sum >= fee_B && (input_sum - fee_B) < dust_change) { out = Shape::Changeless; return true; }
        out = Shape::NeedMore;
        return true;
    };

    Shape shape;
    if (!classify(shape)) return util::Error{_("Failed to estimate transaction size")};
    while (shape == Shape::NeedMore) {
        if (plot_idx < plotUtxos.size()) {
            addInput(plotUtxos[plot_idx++]);
        } else if (other_idx < otherUtxos.size()) {
            addInput(otherUtxos[other_idx++]);
        } else {
            return util::Error{_("Insufficient funds for forging transaction")};
        }
        if (!classify(shape)) return util::Error{_("Failed to estimate transaction size")};
    }

    // --- 7. Finalize vout and fee ---
    CAmount final_fee;
    if (shape == Shape::WithChange) {
        TxSize sizes = CalculateMaximumSignedTxSize(CTransaction(mtx), &wallet, input_txouts, &cc);
        if (sizes.vsize < 0) return util::Error{_("Failed to estimate transaction size")};
        final_fee = feerate.GetFee(sizes.vsize);
        mtx.vout[1].nValue = input_sum - final_fee;
        change_reserve.KeepDestination();
    } else { // Changeless: drop the change output.
        mtx.vout.resize(1); // keep only OP_RETURN
        final_fee = input_sum; // entire input sum becomes fee
        // change_reserve destructor returns the unused address to the keypool.
    }

    // --- 8. Sign ---
    std::map<COutPoint, Coin> coins;
    for (const auto& u : selected) {
        coins[u.outpoint] = Coin(u.txout, /*nHeightIn=*/1, /*fCoinBaseIn=*/false);
    }
    std::map<int, bilingual_str> input_errors;
    if (!wallet.SignTransaction(mtx, coins, SIGHASH_ALL, input_errors)) {
        const char* tx_type = (type == TransactionType::ASSIGNMENT) ? "assignment" : "revocation";
        return util::Error{strprintf(_("Failed to sign forging %s transaction"), tx_type)};
    }

    fee = final_fee;
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
