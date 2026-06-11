// Copyright (c) 2025 The Proof of Capacity Consortium
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <pocx/assignments/replay.h>

#include <pocx/assignments/opcodes.h>

#include <coins.h>
#include <consensus/params.h>
#include <crypto/hex_base.h>
#include <logging.h>

#include <limits>
#include <utility>

namespace pocx {
namespace assignments {

bool ApplyAssignmentEffectsForReplay(
    const CTransaction& tx,
    int nHeight,
    const Consensus::Params& consensus_params,
    CCoinsViewCache& view)
{
    // Scan outputs for assignment / revocation OP_RETURNs, mirroring the
    // side-effects of ConnectBlock without re-running consensus checks. All writes
    // are idempotent: assignment keys are (plot, height, txid), and UpdateForgingAssignment
    // overwrites the matching pending entry or appends a new one. A non-assignment
    // output yields nullopt and is skipped; the only hard failure is a revocation
    // with no prior assignment, which means the assignment DB is inconsistent.
    for (const CTxOut& output : tx.vout) {
        if (auto parsed = ParseAssignmentOpReturn(output)) {
            const auto& [plot_addr, forge_addr] = *parsed;
            const int effective_height = nHeight + consensus_params.nForgingAssignmentDelay;
            view.AddForgingAssignment(
                ForgingAssignment(plot_addr, forge_addr, tx.GetHash().ToUint256(),
                                  nHeight, effective_height));
        } else if (auto plot_addr_opt = ParseRevocationOpReturn(output)) {
            const auto& plot_addr = *plot_addr_opt;
            auto existing = view.GetForgingAssignment(plot_addr, std::numeric_limits<int>::max());
            if (!existing.has_value()) {
                LogInfo("PoCX: replay revocation for plot %s tx %s found no prior assignment\n",
                          HexStr(plot_addr), tx.GetHash().ToString());
                return false;
            }
            ForgingAssignment revoked = *existing;
            revoked.revoked = true;
            revoked.revocation_txid = tx.GetHash().ToUint256();
            revoked.revocation_height = nHeight;
            revoked.revocation_effective_height = nHeight + consensus_params.nForgingRevocationDelay;
            view.UpdateForgingAssignment(revoked);
        }
    }
    return true;
}

} // namespace assignments
} // namespace pocx
