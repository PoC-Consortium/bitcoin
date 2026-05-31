// Copyright (c) 2025 The Proof of Capacity Consortium
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <pocx/mining/block_signing.h>

#include <coins.h>
#include <interfaces/wallet.h>
#include <key_io.h>
#include <node/context.h>
#include <pocx/assignments/assignment_state.h>
#include <pocx/mining/wallet_signing.h> // pocx::mining::AccountKeyAvailability
#include <primitives/block.h>
#include <sync.h>
#include <tinyformat.h>
#include <uint256.h>
#include <util/strencodings.h>
#include <validation.h>

#include <algorithm>
#include <array>
#include <cstdint>

namespace pocx {
namespace mining {

std::optional<std::string> MaybeSignPoCXBlock(CBlock& block,
                                              ChainstateManager& chainman,
                                              const node::NodeContext& node)
{
    // Already signed (non-zero signature) -> nothing to do. Leaves today's path
    // byte-identical for every block that arrives with a signature.
    if (std::any_of(block.vchSignature.begin(), block.vchSignature.end(),
                    [](uint8_t b) { return b != 0; })) {
        return std::nullopt;
    }

    // Resolve the effective signer for this plot at this height (considers
    // forging assignments), mirroring submit_nonce / the forger.
    std::array<uint8_t, 20> signer;
    {
        LOCK(cs_main);
        const CCoinsViewCache& view = chainman.ActiveChainstate().CoinsTip();
        signer = pocx::assignments::GetEffectiveSigner(block.pocxProof.account_id, block.nHeight, view);
    }
    const std::string signer_hex = HexStr(signer);

    // bech32 P2WPKH rendering for user-facing messages (same path the forger uses).
    uint160 u;
    std::copy(signer.begin(), signer.end(), u.begin());
    const std::string signer_address = EncodeDestination(WitnessV0KeyHash{u});

    if (!node.wallet_loader) {
        return strprintf("unsigned block: no wallet loaded to sign for effective signer %s", signer_address);
    }

    // Probe every loaded wallet. Sign via the abstract interface exactly like the
    // forger (scheduler.cpp). Track Locked so a locked-but-present key yields an
    // "unlock first" message rather than a generic "no key" error
    // (mirrors submit_nonce's categorization).
    auto availability = AccountKeyAvailability::Absent;
    for (auto& wallet : node.wallet_loader->getWallets()) {
        const auto r = wallet->haveAccountKey(signer_hex);
        if (r == AccountKeyAvailability::Available) {
            if (wallet->signPoCXBlock(signer_hex, block)) {
                return std::nullopt;
            }
            return strprintf("unsigned block: failed to sign for effective signer %s", signer_address);
        }
        if (r == AccountKeyAvailability::Locked) {
            availability = AccountKeyAvailability::Locked;
        }
    }

    if (availability == AccountKeyAvailability::Locked) {
        return strprintf("unsigned block: wallet holding key for effective signer %s is locked - "
                         "unlock with walletpassphrase first", signer_address);
    }
    return strprintf("unsigned block: no wallet holds the key for effective signer %s", signer_address);
}

} // namespace mining
} // namespace pocx
