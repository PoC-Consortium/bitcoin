// Copyright (c) 2025 The Proof of Capacity Consortium
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_POCX_ASSIGNMENTS_REPLAY_H
#define BITCOIN_POCX_ASSIGNMENTS_REPLAY_H

#include <primitives/transaction.h>

class CCoinsViewCache;
namespace Consensus { struct Params; }

namespace pocx {
namespace assignments {

/** Re-apply assignment/revocation OP_RETURN effects of a transaction during
 *  RollforwardBlock / ReplayBlocks. Idempotent and skips consensus checks
 *  (the block was already validated when first connected). Writes match the
 *  side-effects performed by ConnectBlock for the same transaction.
 *
 *  Returns false if replay cannot reproduce those effects (e.g. a revocation
 *  whose prior assignment is missing) — a corrupt/inconsistent assignment DB
 *  the caller must treat as a fatal replay failure rather than continue with
 *  divergent state.
 *
 *  Lives outside opcodes.cpp because it mutates CCoinsViewCache (common lib)
 *  and logs (util lib), neither of which the consensus library may depend on.
 */
bool ApplyAssignmentEffectsForReplay(
    const CTransaction& tx,
    int nHeight,
    const Consensus::Params& consensus_params,
    CCoinsViewCache& view);

} // namespace assignments
} // namespace pocx

#endif // BITCOIN_POCX_ASSIGNMENTS_REPLAY_H
