// Copyright (c) 2025 The Proof of Capacity Consortium
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_POCX_CONSENSUS_POCX_H
#define BITCOIN_POCX_CONSENSUS_POCX_H

#include <primitives/block.h>
#include <uint256.h>
#include <consensus/params.h>
#include <chain.h>
#include <key.h>
#include <pubkey.h>
#include <script/script.h>
#include <pocx/consensus/proof.h>
#include <array>

class CCoinsViewCache;

namespace interfaces {
class Wallet;
}

namespace pocx {
namespace consensus {

/** Validate Proof of Capacity (context-free, similar to CheckProofOfWork) */
ValidationResult ValidateProofOfCapacity(const uint256& generationSignature,
                                         const PoCXProof& proof,
                                         uint64_t baseTarget,
                                         uint64_t blockHeight,
                                         uint32_t compression,
                                         int64_t block_time);



/** Extract account ID from a public key (20-byte identifier) */
std::array<uint8_t, 20> ExtractAccountIDFromPubKey(const CPubKey& pubkey);

/** Extract account ID from a script (all zeros if extraction fails) */
std::array<uint8_t, 20> ExtractAccountIDFromScript(const CScript& script);

/** Check if two account IDs match */
bool AccountIDsMatch(const std::array<uint8_t, 20>& id1, const std::array<uint8_t, 20>& id2);

// PoCX Block Signing Magic String
extern const std::string POCX_BLOCK_MAGIC;

/** PoCX-specific block hash for signing (adds magic prefix to prevent signature reuse) */
uint256 PoCXBlockSignatureHash(const uint256& block_hash);

/** Verify compact signature of a PoCX block */
bool VerifyPoCXBlockCompactSignature(const CBlock& block);

/** Verify compact signature of a PoCX block with assignment support */
bool VerifyPoCXBlockCompactSignature(const CBlock& block, const CCoinsViewCache& view, int nHeight);



} // namespace consensus
} // namespace pocx

#endif // BITCOIN_POCX_CONSENSUS_POCX_H

