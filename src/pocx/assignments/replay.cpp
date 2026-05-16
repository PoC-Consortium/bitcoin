// Copyright (c) 2025 The Proof of Capacity Consortium
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <pocx/assignments/replay.h>

#include <pocx/assignments/opcodes.h>

#include <coins.h>
#include <consensus/params.h>
#include <crypto/hex_base.h>
#include <logging.h>

#include <utility>

namespace pocx {
namespace assignments {

void ApplyAssignmentEffectsForReplay(
    const CTransaction& tx,
    int nHeight,
    const Consensus::Params& consensus_params,
    CCoinsViewCache& view)
{
    // Scan outputs for assignment / revocation OP_RETURNs, mirroring the
    // side-effects of ConnectBlock without re-running consensus checks. All writes
    // are idempotent: assignment keys are (plot, height, txid), and UpdateForgingAssignment
    // overwrites the matching pending entry or appends a new one.
    for (const CTxOut& output : tx.vout) {
        if (IsAssignmentOpReturn(output)) {
            auto parsed = ParseAssignmentOpReturn(output);
            if (!parsed.has_value()) continue;
            const auto& [plot_addr, forge_addr] = *parsed;
            const int effective_height = nHeight + consensus_params.nForgingAssignmentDelay;
            view.AddForgingAssignment(
                ForgingAssignment(plot_addr, forge_addr, tx.GetHash().ToUint256(),
                                  nHeight, effective_height));
        } else if (IsRevocationOpReturn(output)) {
            auto plot_addr_opt = ParseRevocationOpReturn(output);
            if (!plot_addr_opt.has_value()) continue;
            const auto& plot_addr = *plot_addr_opt;
            auto existing = view.LookupForgingAssignmentForReplay(plot_addr);
            if (!existing.has_value()) {
                // The block was previously valid, so the assignment must exist somewhere
                // in the replay window or DB. Reaching this branch indicates inconsistency.
                LogPrintf("PoCX: replay revocation for plot %s tx %s found no prior assignment\n",
                          HexStr(plot_addr), tx.GetHash().ToString());
                continue;
            }
            ForgingAssignment revoked = *existing;
            revoked.revoked = true;
            revoked.revocation_txid = tx.GetHash().ToUint256();
            revoked.revocation_height = nHeight;
            revoked.revocation_effective_height = nHeight + consensus_params.nForgingRevocationDelay;
            view.UpdateForgingAssignment(revoked);
        }
    }
}

} // namespace assignments
} // namespace pocx
