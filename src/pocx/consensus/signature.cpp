// Copyright (c) 2025 The Proof of Capacity Consortium
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <pocx/consensus/signature.h>

#include <pocx/consensus/proof.h>
#include <pocx/assignments/assignment_state.h>
#include <pocx/algorithms/time_bending.h>
#include <util/strencodings.h>
#include <algorithm>
#include <hash.h>
#include <logging.h>

namespace pocx {
namespace consensus {

ValidationResult ValidateProofOfCapacity(const uint256& generationSignature,
                                         const PoCXProof& proof,
                                         uint64_t baseTarget,
                                         uint64_t blockHeight,
                                         uint32_t compression,
                                         int64_t block_time) {
    ValidationResult result;

    // Basic proof structure validation
    if (proof.IsNull()) {
        return result; // is_valid = false
    }

    // Basic account ID validation (20 bytes - all zeros means invalid)
    bool account_id_null = std::all_of(proof.account_id.begin(),
                                      proof.account_id.end(),
                                      [](uint8_t b) { return b == 0; });
    if (account_id_null) {
        return result; // is_valid = false
    }

    // Convert generation signature to hex string for core validation
    std::string gen_sig_hex = generationSignature.ToString();

    // Use raw payloads directly
    const uint8_t* account_payload = proof.account_id.data();
    uint64_t nonce = proof.nonce;
    const uint8_t* seed_data = proof.seed.data();

    // Call consensus validation function
    ValidationResult core_result;
    bool success = pocx_validate_block(
        gen_sig_hex.c_str(),
        baseTarget,
        account_payload,
        blockHeight,
        nonce,
        seed_data,
        compression,
        &core_result
    );

    // Transfer results
    result.is_valid = success && core_result.is_valid;
    result.error_code = core_result.error_code;
    result.quality = core_result.quality;
    // Use Time Bending for deadline calculation
    result.deadline = pocx::algorithms::CalculateTimeBendedDeadline(core_result.quality, baseTarget, block_time);

    return result;
}



std::array<uint8_t, 20> ExtractAccountIDFromPubKey(const CPubKey& pubkey) {
    std::array<uint8_t, 20> account_id;
    account_id.fill(0);
    
    if (!pubkey.IsValid() || !pubkey.IsCompressed()) {
        return account_id;
    }
    
    // For PoCX, account ID is the HASH160 of the compressed public key
    // This matches the P2PKH/P2WPKH address format
    CKeyID keyid = pubkey.GetID();
    static_assert(sizeof(keyid) == 20, "CKeyID must be 20 bytes");
    std::copy(keyid.begin(), keyid.end(), account_id.begin());
    
    return account_id;
}

std::array<uint8_t, 20> ExtractAccountIDFromScript(const CScript& script) {
    std::array<uint8_t, 20> account_id;
    account_id.fill(0);
    
    // PoCX mining only supports P2WPKH (witness v0 keyhash)
    // Format: OP_0 <20 bytes>
    if (script.size() == 22 && 
        script[0] == 0x00 && // OP_0 (witness version 0)
        script[1] == 0x14) { // Push 20 bytes
        
        // Extract the 20-byte keyhash
        std::copy(script.begin() + 2, script.begin() + 22, account_id.begin());
    }
    
    return account_id;
}

bool AccountIDsMatch(const std::array<uint8_t, 20>& id1, const std::array<uint8_t, 20>& id2) {
    return std::equal(id1.begin(), id1.end(), id2.begin());
}

// PoCX Block Signing Magic String
const std::string POCX_BLOCK_MAGIC = "POCX Signed Block:\n";

uint256 PoCXBlockSignatureHash(const uint256& block_hash) {
    // Create hash with PoCX magic prefix (like MessageHash but with our prefix)
    HashWriter hasher{};
    hasher << POCX_BLOCK_MAGIC << block_hash.ToString();
    return hasher.GetHash();
}

bool VerifyPoCXBlockCompactSignature(const CBlock& block) {
    // Validate public key format
    CPubKey stored_pubkey(block.vchPubKey.begin(), block.vchPubKey.end());
    if (!stored_pubkey.IsFullyValid()) {
        LogPrintf("PoCX: Signature validation FAILED - invalid pubkey\n");
        return false;
    }

    // Get the raw block hash first
    uint256 raw_block_hash = block.GetHash();
    // Get the prefixed hash (same as used during signing)
    uint256 hash_to_verify = PoCXBlockSignatureHash(raw_block_hash);

    // Recover public key from compact signature
    std::vector<unsigned char> sig_vec(block.vchSignature.begin(), block.vchSignature.end());
    CPubKey recovered_pubkey;
    if (!recovered_pubkey.RecoverCompact(hash_to_verify, sig_vec)) {
        LogPrintf("PoCX: Signature validation FAILED - cannot recover pubkey from signature\n");
        LogPrintf("PoCX:   Hash: %s\n", hash_to_verify.ToString().c_str());
        LogPrintf("PoCX:   Signature: %s\n", HexStr(block.vchSignature).c_str());
        return false;
    }

    // Verify the recovered public key matches what's stored in the block
    if (!std::equal(recovered_pubkey.begin(), recovered_pubkey.end(), block.vchPubKey.begin())) {
        LogPrintf("PoCX: Signature validation FAILED - pubkey mismatch\n");
        LogPrintf("PoCX:   Recovered: %s\n", HexStr(recovered_pubkey).c_str());
        LogPrintf("PoCX:   Stored:    %s\n", HexStr(block.vchPubKey).c_str());
        return false;
    }

    LogDebug(BCLog::POCX, "Signature valid for block %s\n", raw_block_hash.ToString().c_str());
    return true;
}

bool VerifyPoCXBlockCompactSignature(const CBlock& block, const CCoinsViewCache& view, int nHeight) {
    // First do all the basic signature validation
    if (!VerifyPoCXBlockCompactSignature(block)) {
        LogPrintf("PoCX: Extended validation FAILED - basic signature validation failed at height %d\n", nHeight);
        return false;
    }

    // Now check if the signer matches the effective signer considering assignments
    CPubKey stored_pubkey(block.vchPubKey);
    std::array<uint8_t, 20> pubkey_account = ExtractAccountIDFromPubKey(stored_pubkey);

    // Get the effective signer for the plot address at this height
    std::array<uint8_t, 20> effective_signer = pocx::assignments::GetEffectiveSigner(block.pocxProof.account_id, nHeight, view);

    // The pubkey account must match the effective signer
    if (!AccountIDsMatch(pubkey_account, effective_signer)) {
        LogPrintf("PoCX: Extended validation FAILED - account mismatch at height %d\n", nHeight);
        LogPrintf("PoCX:   Plot address:     %s\n", HexStr(block.pocxProof.account_id).c_str());
        LogPrintf("PoCX:   Pubkey account:   %s\n", HexStr(pubkey_account).c_str());
        LogPrintf("PoCX:   Effective signer: %s\n", HexStr(effective_signer).c_str());
        return false;
    }

    LogDebug(BCLog::POCX, "Extended validation passed at height %d - plot=%s, signer=%s, effective=%s\n",
             nHeight,
             HexStr(block.pocxProof.account_id).c_str(),
             HexStr(pubkey_account).c_str(),
             HexStr(effective_signer).c_str());
    return true;
}



} // namespace consensus
} // namespace pocx

