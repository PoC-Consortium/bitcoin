// Copyright (c) 2025 The Proof of Capacity Consortium
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <pocx/mining/wallet_signing.h>

#include <pocx/assignments/assignment_state.h>
#include <pocx/algorithms/encoding.h>
#include <addresstype.h>
#include <interfaces/wallet.h>
#include <key_io.h>
#include <logging.h>
#include <node/context.h>
#include <primitives/block.h>
#include <sync.h>
#include <util/strencodings.h>
#include <validation.h>
#include <wallet/scriptpubkeyman.h>
#include <wallet/wallet.h>

using wallet::CWallet;
using wallet::ScriptPubKeyMan;

namespace pocx {
namespace mining {

bool HaveAccountKey(
    const std::string& account_id,
    interfaces::Wallet* wallet
) {
    if (!wallet) {
        LogDebug(BCLog::POCX, "HaveAccountKey: No wallet provided\n");
        return false;
    }

    // Convert account_id to bytes
    std::vector<uint8_t> account_bytes;
    if (account_id.size() == 40 && IsHex(account_id)) {
        // 40-char hex string to bytes
        account_bytes = ParseHex(account_id);
    } else if (account_id.size() == 20) {
        // Assume raw 20-byte payload
        account_bytes.assign(account_id.begin(), account_id.end());
    } else {
        LogDebug(BCLog::POCX, "HaveAccountKey: Invalid account_id format (size=%zu)\n", account_id.size());
        return false;
    }

    // Validate we have exactly 20 bytes
    if (account_bytes.size() != 20) {
        LogDebug(BCLog::POCX, "HaveAccountKey: Account bytes not 20 bytes (size=%zu)\n", account_bytes.size());
        return false;
    }

    // For PoCX, account_id is the CKeyID (20-byte HASH160 of pubkey)
    // Create P2WPKH address from this key ID
    CKeyID ckeyid{uint160(account_bytes)};
    PKHash pkhash{ckeyid};
    CTxDestination dest = WitnessV0KeyHash(pkhash);

    // Check if wallet has this key (can spend from this address)
    bool has_key = wallet->isSpendable(dest);

    return has_key;
}

bool SignPoCXBlock(
    interfaces::Wallet* wallet,
    const uint256& block_hash,
    const std::string& account_id,
    CBlock& block
) {
    if (!wallet) {
        LogPrintf("PoCX: No wallet provided for signing\n");
        return false;
    }

    // Convert account_id to bytes
    std::vector<uint8_t> account_bytes;
    if (account_id.size() == 40 && IsHex(account_id)) {
        // 40-char hex string to bytes
        account_bytes = ParseHex(account_id);
    } else {
        LogPrintf("PoCX: Invalid account_id format (size=%zu)\n", account_id.size());
        return false;
    }

    // Validate we have exactly 20 bytes
    if (account_bytes.size() != 20) {
        LogPrintf("PoCX: Account bytes not 20 bytes (size=%zu)\n", account_bytes.size());
        return false;
    }

    // Create P2WPKH script from account_id (same as HaveAccountKey)
    CKeyID ckeyid{uint160(account_bytes)};
    PKHash pkhash{ckeyid};
    CTxDestination dest = WitnessV0KeyHash(pkhash);
    CScript script = GetScriptForDestination(dest);

    LogPrintf("PoCX: Account ID: %s -> CKeyID: %s\n", account_id.c_str(), ckeyid.ToString().c_str());

    CWallet* cwallet = wallet->wallet();
    if (!cwallet) {
        LogPrintf("PoCX: Could not access underlying CWallet\n");
        return false;
    }

    // Check if wallet is unlocked
    if (cwallet->IsLocked()) {
        LogPrintf("PoCX: Wallet is locked - unlock with walletpassphrase first\n");
        return false;
    }

    // Find the responsible ScriptPubKeyMan and use two-step signing
    for (ScriptPubKeyMan* spkm : cwallet->GetAllScriptPubKeyMans()) {
        if (spkm->IsMine(script)) {
            LogPrintf("PoCX: Found responsible ScriptPubKeyMan for two-step signing\n");

            CPubKey pubkey;

            // Step 1: Get the public key
            if (!spkm->GetPoCXPubKey(script, pubkey)) {
                LogPrintf("PoCX: ScriptPubKeyMan failed to get public key\n");
                continue;
            }

            // Step 2: Set pubkey in block first (before getting final hash)
            std::copy_n(pubkey.begin(), 33, block.vchPubKey.begin());

            // Step 3: Get the final block hash (now includes pubkey)
            uint256 final_hash = block.GetHash();

            // Step 4: Sign with the final hash
            std::vector<unsigned char> signature;
            if (spkm->SignPoCXHash(final_hash, script, signature)) {
                // Store the signature in the block (convert vector to array)
                if (signature.size() != 65) {
                    LogPrintf("PoCX: Invalid signature size: %zu (expected 65)\n", signature.size());
                    continue;
                }
                std::copy_n(signature.begin(), 65, block.vchSignature.begin());

                LogPrintf("PoCX: Block signed successfully using two-step approach\n");
                LogPrintf("PoCX: Final signing hash: %s\n", final_hash.ToString().c_str());
                LogPrintf("PoCX: PubKey: %s\n", HexStr(pubkey).c_str());
                LogPrintf("PoCX: Signature size: %zu bytes, PubKey size: %zu bytes\n",
                         signature.size(), pubkey.size());
                return true;
            } else {
                LogPrintf("PoCX: ScriptPubKeyMan failed to sign with final hash\n");
            }
        }
    }

    LogPrintf("PoCX: No ScriptPubKeyMan found that can sign for account %s\n", account_id.c_str());
    return false;
}

bool SignPoCXBlockWithAvailableWallet(
    ::node::NodeContext* context,
    CBlock& block,
    const std::string& plot_account_id
) {
    if (!context || !context->wallet_loader) {
        LogPrintf("PoCX: No wallet available for signing block\n");
        return false;
    }

    // Parse plot account ID
    auto plot_id = pocx::algorithms::ParseAccountID(plot_account_id.c_str());
    if (!plot_id) {
        LogPrintf("PoCX: Invalid plot account ID format\n");
        return false;
    }

    // Get effective signer considering assignments
    std::string effective_signer = plot_account_id;

    if (context->chainman) {
        LOCK(cs_main);
        auto& chainstate = context->chainman->ActiveChainstate();
        const CCoinsViewCache& view = chainstate.CoinsTip();

        // Get effective signer considering assignments
        std::array<uint8_t, 20> signer = pocx::assignments::GetEffectiveSigner(*plot_id, block.nHeight, view);
        effective_signer = HexStr(signer);
    }

    LogPrintf("PoCX: Plot: %s, Effective signer: %s at height %d\n",
              plot_account_id.c_str(),
              effective_signer.c_str(),
              block.nHeight);

    // Try to sign with any available wallet that has the key
    auto wallets = context->wallet_loader->getWallets();
    LogPrintf("PoCX: Found %zu wallet(s) available\n", wallets.size());

    for (auto& wallet : wallets) {
        if (HaveAccountKey(effective_signer, wallet.get())) {
            LogPrintf("PoCX: Found wallet with key for effective signer %s\n",
                     effective_signer.c_str());

            if (SignPoCXBlock(wallet.get(), block.GetHash(), effective_signer, block)) {
                LogPrintf("PoCX: Block signed successfully\n");
                LogPrintf("PoCX:   Block pubkey: %s\n", HexStr(block.vchPubKey).c_str());
                LogPrintf("PoCX:   Block signature size: %zu\n", block.vchSignature.size());
                return true;
            } else {
                LogPrintf("PoCX: Signing failed for effective signer %s\n",
                         effective_signer.c_str());
            }
        }
    }

    LogPrintf("PoCX: No wallet has key for effective signer %s\n",
              effective_signer.c_str());
    return false;
}

} // namespace mining
} // namespace pocx
