// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_PRIMITIVES_BLOCK_H
#define BITCOIN_PRIMITIVES_BLOCK_H

#include <primitives/transaction.h>
#include <serialize.h>
#include <uint256.h>
#include <util/time.h>

#ifdef ENABLE_POCX
#include <array>
#include <algorithm>
#include <pubkey.h>
#endif

#ifdef ENABLE_POCX
/**
 * PoCX proof of capacity mining data
 * Contains plot-specific information for mining validation
 */
struct PoCXProof {
    std::array<uint8_t, 32> seed;            // 32-byte plot seed
    std::array<uint8_t, 20> account_id;      // 20-byte account identifier
    uint32_t compression;                    // Compression level used (1-6)
    uint64_t nonce;                          // Mining nonce (64-bit)
    uint64_t quality;                        // Claimed quality (PoC hash output)

    PoCXProof() {
        SetNull();
    }

    PoCXProof(const std::string& account_hex, const std::string& seed_hex, uint64_t nonce_val,
              uint64_t quality_val = 0, uint32_t compression_val = 0) {
        std::string error;
        if (!SetAccountId(account_hex, error)) {
            throw std::runtime_error("Failed to set account ID: " + error);
        }
        if (!SetSeed(seed_hex, error)) {
            throw std::runtime_error("Failed to set seed: " + error);
        }
        nonce = nonce_val;
        quality = quality_val;
        compression = compression_val;
    }

    void SetNull() {
        seed.fill(0);
        account_id.fill(0);
        compression = 0;
        nonce = 0;
        quality = 0;
    }

    bool IsNull() const {
        return nonce == 0 &&
               std::all_of(account_id.begin(), account_id.end(), [](uint8_t b) { return b == 0; });
    }

    SERIALIZE_METHODS(PoCXProof, obj) {
        READWRITE(obj.seed, obj.account_id, obj.compression, obj.nonce, obj.quality);
    }

    // Utility functions for string conversion
    bool SetAccountId(const std::string& hex_str, std::string& error);
    std::string GetAccountIdHex() const;
    bool SetSeed(const std::string& hex_str, std::string& error);
    std::string GetSeedHex() const;
};
#endif

/** Nodes collect new transactions into a block, hash them into a hash tree,
 * and scan through nonce values to make the block's hash satisfy proof-of-work
 * requirements.  When they solve the proof-of-work, they broadcast the block
 * to everyone and the block is added to the block chain.  The first transaction
 * in the block is a special one that creates a new coin owned by the creator
 * of the block.
 */
class CBlockHeader
{
public:
    // header
    int32_t nVersion;
    uint256 hashPrevBlock;
    uint256 hashMerkleRoot;
    uint32_t nTime;
    
#ifdef ENABLE_POCX
    // PoCX consensus fields (replace PoW fields)
    int nHeight;                             // Block height for context-free validation
    uint256 generationSignature;            // PoCX: Generation signature for context-free validation
    uint64_t nBaseTarget;                    // PoCX difficulty target (like nBits)
    PoCXProof pocxProof;                     // Plot-specific mining data
    
    // Block signature fields (prove plot ownership)
    std::array<uint8_t, 33> vchPubKey;      // Public key of block generator (33 bytes compressed)
    std::array<uint8_t, 65> vchSignature;   // Compact signature (65 bytes)
#else
    // PoW consensus fields (only when PoCX disabled)
    uint32_t nBits;
    uint32_t nNonce;
#endif

    CBlockHeader()
    {
        SetNull();
    }
    
#ifdef ENABLE_POCX
    SERIALIZE_METHODS(CBlockHeader, obj) {
        READWRITE(obj.nVersion, obj.hashPrevBlock, obj.hashMerkleRoot, obj.nTime,
                  obj.nHeight, obj.generationSignature, obj.nBaseTarget, obj.pocxProof,
                  obj.vchPubKey, obj.vchSignature);
    }
#else
    SERIALIZE_METHODS(CBlockHeader, obj) { READWRITE(obj.nVersion, obj.hashPrevBlock, obj.hashMerkleRoot, obj.nTime, obj.nBits, obj.nNonce); }
#endif

    void SetNull()
    {
        nVersion = 0;
        hashPrevBlock.SetNull();
        hashMerkleRoot.SetNull();
        nTime = 0;
#ifdef ENABLE_POCX
        generationSignature.SetNull();
        nHeight = 0;
        nBaseTarget = 0;
        pocxProof.SetNull();
        vchPubKey.fill(0);
        vchSignature.fill(0);
#else
        nBits = 0;
        nNonce = 0;
#endif
    }

    bool IsNull() const
    {
#ifdef ENABLE_POCX
        return (nBaseTarget == 0);
#else
        return (nBits == 0);
#endif
    }

    uint256 GetHash() const;

    NodeSeconds Time() const
    {
        return NodeSeconds{std::chrono::seconds{nTime}};
    }

    int64_t GetBlockTime() const
    {
        return (int64_t)nTime;
    }
};


class CBlock : public CBlockHeader
{
public:
    // network and disk
    std::vector<CTransactionRef> vtx;

    // Memory-only flags for caching expensive checks
    mutable bool fChecked;                            // CheckBlock()
    mutable bool m_checked_witness_commitment{false}; // CheckWitnessCommitment()
    mutable bool m_checked_merkle_root{false};        // CheckMerkleRoot()

    CBlock()
    {
        SetNull();
    }

    CBlock(const CBlockHeader &header)
    {
        SetNull();
        *(static_cast<CBlockHeader*>(this)) = header;
    }

    SERIALIZE_METHODS(CBlock, obj)
    {
        READWRITE(AsBase<CBlockHeader>(obj), obj.vtx);
    }

    void SetNull()
    {
        CBlockHeader::SetNull();
        vtx.clear();
        fChecked = false;
        m_checked_witness_commitment = false;
        m_checked_merkle_root = false;
    }

    CBlockHeader GetBlockHeader() const
    {
        CBlockHeader block;
        block.nVersion       = nVersion;
        block.hashPrevBlock  = hashPrevBlock;
        block.hashMerkleRoot = hashMerkleRoot;
        block.nTime          = nTime;
#ifdef ENABLE_POCX
        block.nHeight        = nHeight;
        block.generationSignature = generationSignature;
        block.nBaseTarget    = nBaseTarget;
        block.pocxProof      = pocxProof;
        block.vchPubKey      = vchPubKey;
        block.vchSignature   = vchSignature;
#else
        block.nBits          = nBits;
        block.nNonce         = nNonce;
#endif
        return block;
    }

    std::string ToString() const;
};

/** Describes a place in the block chain to another node such that if the
 * other node doesn't have the same branch, it can find a recent common trunk.
 * The further back it is, the further before the fork it may be.
 */
struct CBlockLocator
{
    /** Historically CBlockLocator's version field has been written to network
     * streams as the negotiated protocol version and to disk streams as the
     * client version, but the value has never been used.
     *
     * Hard-code to the highest protocol version ever written to a network stream.
     * SerParams can be used if the field requires any meaning in the future,
     **/
    static constexpr int DUMMY_VERSION = 70016;

    std::vector<uint256> vHave;

    CBlockLocator() = default;

    explicit CBlockLocator(std::vector<uint256>&& have) : vHave(std::move(have)) {}

    SERIALIZE_METHODS(CBlockLocator, obj)
    {
        int nVersion = DUMMY_VERSION;
        READWRITE(nVersion);
        READWRITE(obj.vHave);
    }

    void SetNull()
    {
        vHave.clear();
    }

    bool IsNull() const
    {
        return vHave.empty();
    }
};

#endif // BITCOIN_PRIMITIVES_BLOCK_H
