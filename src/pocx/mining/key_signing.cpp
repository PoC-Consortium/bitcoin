// Copyright (c) 2025 The Proof of Capacity Consortium
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <pocx/mining/key_signing.h>

#include <key.h>
#include <logging.h>
#include <pocx/consensus/signature.h>
#include <primitives/block.h>
#include <pubkey.h>
#include <uint256.h>
#include <util/strencodings.h>

#include <vector>

namespace pocx {
namespace mining {

bool SignPoCXBlockWithKey(CBlock& block, const std::array<uint8_t, 32>& privkey_bytes)
{
    CKey key;
    key.Set(privkey_bytes.begin(), privkey_bytes.end(), /*fCompressedIn=*/true);
    if (!key.IsValid()) {
        LogInfo("PoCX: SignPoCXBlockWithKey: invalid private key bytes\n");
        return false;
    }

    CPubKey pubkey = key.GetPubKey();
    if (!pubkey.IsValid() || !pubkey.IsCompressed()) {
        LogInfo("PoCX: SignPoCXBlockWithKey: derived pubkey invalid\n");
        return false;
    }
    // vchPubKey must be stamped before GetHash() since it is part of the header.
    std::copy_n(pubkey.begin(), 33, block.vchPubKey.begin());

    const uint256 prefixed_hash = pocx::consensus::PoCXBlockSignatureHash(block.GetHash());

    std::vector<unsigned char> signature;
    if (!key.SignCompact(prefixed_hash, signature)) {
        LogInfo("PoCX: SignPoCXBlockWithKey: SignCompact failed\n");
        return false;
    }
    if (signature.size() != 65) {
        LogInfo("PoCX: SignPoCXBlockWithKey: unexpected signature size %zu\n", signature.size());
        return false;
    }
    std::copy_n(signature.begin(), 65, block.vchSignature.begin());
    return true;
}

} // namespace mining
} // namespace pocx
