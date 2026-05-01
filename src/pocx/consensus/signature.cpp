// Copyright (c) 2025 The Proof of Capacity Consortium
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <pocx/consensus/signature.h>

#include <pocx/consensus/proof.h>
#include <pocx/assignments/assignment_state.h>
#include <pocx/algorithms/time_bending.h>
#include <algorithm>
#include <hash.h>

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
    CPubKey stored_pubkey(block.vchPubKey.begin(), block.vchPubKey.end());
    if (!stored_pubkey.IsFullyValid()) {
        return false;
    }

    uint256 raw_block_hash = block.GetHash();
    uint256 hash_to_verify = PoCXBlockSignatureHash(raw_block_hash);

    std::vector<unsigned char> sig_vec(block.vchSignature.begin(), block.vchSignature.end());
    CPubKey recovered_pubkey;
    if (!recovered_pubkey.RecoverCompact(hash_to_verify, sig_vec)) {
        return false;
    }

    if (!std::equal(recovered_pubkey.begin(), recovered_pubkey.end(), block.vchPubKey.begin())) {
        return false;
    }

    return true;
}

bool VerifyPoCXBlockCompactSignature(const CBlock& block, const CCoinsViewCache& view, int nHeight) {
    if (!VerifyPoCXBlockCompactSignature(block)) {
        return false;
    }

    CPubKey stored_pubkey(block.vchPubKey);
    std::array<uint8_t, 20> pubkey_account = ExtractAccountIDFromPubKey(stored_pubkey);

    std::array<uint8_t, 20> effective_signer = pocx::assignments::GetEffectiveSigner(block.pocxProof.account_id, nHeight, view);

    if (!AccountIDsMatch(pubkey_account, effective_signer)) {
        return false;
    }

    return true;
}



} // namespace consensus
} // namespace pocx

