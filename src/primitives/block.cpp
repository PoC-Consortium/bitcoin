// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2019 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <primitives/block.h>

#include <hash.h>
#include <tinyformat.h>
#ifdef ENABLE_POCX
#include <util/strencodings.h>
#endif

uint256 CBlockHeader::GetHash() const
{
#ifdef ENABLE_POCX
    // For PoCX blocks, we need to exclude the signature from the hash
    // Create a temporary copy without the signature
    CBlockHeader temp = *this;
    temp.vchSignature.fill(0);
    return (HashWriter{} << temp).GetHash();
#else
    return (HashWriter{} << *this).GetHash();
#endif
}

std::string CBlock::ToString() const
{
    std::stringstream s;
#ifdef ENABLE_POCX
    s << strprintf("CBlock(hash=%s, ver=0x%08x, hashPrevBlock=%s, hashMerkleRoot=%s, nTime=%u, height=%d, genSig=%s, nBaseTarget=%llu, nonce=%llu, quality=%llu, compression=%u, account=%s, seed=%s, vtx=%u)\n",
        GetHash().ToString(),
        nVersion,
        hashPrevBlock.ToString(),
        hashMerkleRoot.ToString(),
        nTime,
        nHeight,
        generationSignature.ToString(),
        nBaseTarget,
        pocxProof.nonce,
        pocxProof.quality,
        pocxProof.compression,
        pocxProof.GetAccountIdHex(),
        pocxProof.GetSeedHex(),
        vtx.size());
#else
    s << strprintf("CBlock(hash=%s, ver=0x%08x, hashPrevBlock=%s, hashMerkleRoot=%s, nTime=%u, nBits=%08x, nNonce=%u, vtx=%u)\n",
        GetHash().ToString(),
        nVersion,
        hashPrevBlock.ToString(),
        hashMerkleRoot.ToString(),
        nTime, nBits, nNonce,
        vtx.size());
#endif
    for (const auto& tx : vtx) {
        s << "  " << tx->ToString() << "\n";
    }
    return s.str();
}

#ifdef ENABLE_POCX
// PoCXProof utility function implementations
bool PoCXProof::SetAccountId(const std::string& hex_str, std::string& error) {
    auto bytes = ParseHex(hex_str);
    if (bytes.size() != 20) {
        error = "Account ID must be exactly 20 bytes (40 hex characters)";
        return false;
    }
    std::copy(bytes.begin(), bytes.end(), account_id.begin());
    return true;
}

std::string PoCXProof::GetAccountIdHex() const {
    return HexStr(account_id);
}

bool PoCXProof::SetSeed(const std::string& hex_str, std::string& error) {
    auto bytes = ParseHex(hex_str);
    if (bytes.size() != 32) {
        error = "Seed must be exactly 32 bytes (64 hex characters)";
        return false;
    }
    std::copy(bytes.begin(), bytes.end(), seed.begin());
    return true;
}

std::string PoCXProof::GetSeedHex() const {
    return HexStr(seed);
}

#endif
