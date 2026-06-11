// Copyright (c) 2025 The Proof of Capacity Consortium
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <pocx/mining/wallet_signing.h>

#include <addresstype.h>
#include <interfaces/wallet.h>
#include <key_io.h>
#include <logging.h>
#include <primitives/block.h>
#include <script/sign.h>
#include <sync.h>
#include <util/strencodings.h>
#include <wallet/scriptpubkeyman.h>
#include <wallet/wallet.h>

using wallet::CWallet;
using wallet::ScriptPubKeyMan;

namespace pocx {
namespace mining {

AccountKeyAvailability HaveAccountKey(
    const std::string& account_id,
    interfaces::Wallet* wallet
) {
    if (!wallet) {
        LogDebug(BCLog::POCX, "HaveAccountKey: No wallet provided\n");
        return AccountKeyAvailability::Absent;
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
        return AccountKeyAvailability::Absent;
    }

    // Validate we have exactly 20 bytes
    if (account_bytes.size() != 20) {
        LogDebug(BCLog::POCX, "HaveAccountKey: Account bytes not 20 bytes (size=%zu)\n", account_bytes.size());
        return AccountKeyAvailability::Absent;
    }

    // For PoCX, account_id is the CKeyID (20-byte HASH160 of pubkey).
    // Build the P2WPKH script we'd actually sign for.
    CKeyID ckeyid{uint160(account_bytes)};
    PKHash pkhash{ckeyid};
    CScript script = GetScriptForDestination(WitnessV0KeyHash(pkhash));

    CWallet* cwallet = wallet->wallet();
    if (!cwallet) return AccountKeyAvailability::Absent;

    // Probe the same path the signer will take. IsMine / isSpendable alone is
    // true for watch-only descriptors (script registered, no private key), so
    // gating on it would ACK nonces we can never sign for. GetPoCXPubKey
    // performs IsMine + GetSigningProvider(include_private=true) + GetKey,
    // which is the actual signability predicate.
    //
    // Lock pattern mirrors CWallet::SignMessage: CanProvide is a cheap script
    // match and runs unlocked; cs_wallet is taken just before GetPoCXPubKey
    // because the SPKM internally reaches back into the wallet (GetKeys ->
    // m_storage.IsLocked) and we must establish cs_wallet -> cs_desc_man
    // ordering to avoid the reverse-order deadlock.
    //
    // Tri-state outcome: an Available match short-circuits immediately; a
    // Locked match (script ours, GetPoCXPubKey failed while the wallet is
    // locked - presumably an encrypted privkey we can't decrypt) is kept as
    // a fallback in case another SPKM is Available, otherwise reported so
    // the caller can suggest walletpassphrase. Watch-only matches leave the
    // outcome at Absent.
    AccountKeyAvailability outcome = AccountKeyAvailability::Absent;
    for (ScriptPubKeyMan* spkm : cwallet->GetAllScriptPubKeyMans()) {
        SignatureData sigdata;
        if (!spkm->CanProvide(script, sigdata)) continue;
        LOCK(cwallet->cs_wallet);
        CPubKey pubkey;
        if (spkm->GetPoCXPubKey(script, pubkey)) return AccountKeyAvailability::Available;
        if (cwallet->IsLocked()) outcome = AccountKeyAvailability::Locked;
    }
    return outcome;
}

bool SignPoCXBlock(
    interfaces::Wallet* wallet,
    const uint256& block_hash,
    const std::string& account_id,
    CBlock& block
) {
    if (!wallet) {
        LogInfo("PoCX: No wallet provided for signing\n");
        return false;
    }

    // Convert account_id to bytes
    std::vector<uint8_t> account_bytes;
    if (account_id.size() == 40 && IsHex(account_id)) {
        // 40-char hex string to bytes
        account_bytes = ParseHex(account_id);
    } else {
        LogInfo("PoCX: Invalid account_id format (size=%zu)\n", account_id.size());
        return false;
    }

    // Validate we have exactly 20 bytes
    if (account_bytes.size() != 20) {
        LogInfo("PoCX: Account bytes not 20 bytes (size=%zu)\n", account_bytes.size());
        return false;
    }

    // Create P2WPKH script from account_id (same as HaveAccountKey)
    CKeyID ckeyid{uint160(account_bytes)};
    PKHash pkhash{ckeyid};
    CTxDestination dest = WitnessV0KeyHash(pkhash);
    CScript script = GetScriptForDestination(dest);

    const std::string account_address = EncodeDestination(dest);
    LogInfo("PoCX: Signing for account %s\n", account_address);

    CWallet* cwallet = wallet->wallet();
    if (!cwallet) {
        LogInfo("PoCX: Could not access underlying CWallet\n");
        return false;
    }

    // Check if wallet is unlocked
    if (cwallet->IsLocked()) {
        LogInfo("PoCX: Wallet is locked - unlock with walletpassphrase first\n");
        return false;
    }

    // Find the responsible ScriptPubKeyMan and use two-step signing.
    // Lock pattern mirrors CWallet::SignMessage (see HaveAccountKey above):
    // CanProvide runs unlocked; cs_wallet is taken just before the SPKM calls
    // that reach back into the wallet via GetKeys -> m_storage.IsLocked.
    for (ScriptPubKeyMan* spkm : cwallet->GetAllScriptPubKeyMans()) {
        SignatureData sigdata;
        if (!spkm->CanProvide(script, sigdata)) continue;

        LOCK(cwallet->cs_wallet);
        LogInfo("PoCX: Found responsible ScriptPubKeyMan for two-step signing\n");

        CPubKey pubkey;

        // Step 1: Get the public key
        if (!spkm->GetPoCXPubKey(script, pubkey)) {
            LogInfo("PoCX: ScriptPubKeyMan recognizes script but cannot provide private key (watch-only?)\n");
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
                LogInfo("PoCX: Invalid signature size: %zu (expected 65)\n", signature.size());
                continue;
            }
            std::copy_n(signature.begin(), 65, block.vchSignature.begin());

            LogInfo("PoCX: Block signed successfully using two-step approach\n");
            LogInfo("PoCX: Final signing hash: %s\n", final_hash.ToString().c_str());
            LogInfo("PoCX: PubKey: %s\n", HexStr(pubkey).c_str());
            LogInfo("PoCX: Signature size: %zu bytes, PubKey size: %zu bytes\n",
                     signature.size(), pubkey.size());
            return true;
        } else {
            LogInfo("PoCX: ScriptPubKeyMan failed to sign with final hash\n");
        }
    }

    LogInfo("PoCX: No ScriptPubKeyMan found that can sign for account %s\n", account_address);
    return false;
}

} // namespace mining
} // namespace pocx
