// Copyright (c) 2026 The Bitcoin PoCX developers
// Distributed under the MIT software license; see COPYING.
#include <key.h>
#include <pocx/consensus/signature.h>
#include <pocx/mining/key_signing.h>
#include <primitives/block.h>
#include <test/fuzz/FuzzedDataProvider.h>
#include <test/fuzz/fuzz.h>
#include <test/util/setup_common.h>
#include <algorithm>
#include <cassert>

namespace {
void InitializeSignature()
{
    static const auto setup = MakeNoLogFileContext<>();
}
std::array<uint8_t, 20> Account(const std::array<uint8_t, 32>& secret)
{
    CKey key;
    key.Set(secret.begin(), secret.end(), true);
    const auto id = key.GetPubKey().GetID();
    std::array<uint8_t, 20> out;
    std::copy(id.begin(), id.end(), out.begin());
    return out;
}
}

FUZZ_TARGET(pocx_signature, .init = InitializeSignature)
{
    FuzzedDataProvider provider{buffer.data(), buffer.size()};
    CBlock original;
    original.nVersion = provider.ConsumeIntegral<int32_t>();
    original.nTime = provider.ConsumeIntegral<uint32_t>();
    original.nHeight = 100;
    original.nBaseTarget = provider.ConsumeIntegral<uint64_t>();
    original.pocxProof.nonce = provider.ConsumeIntegral<uint64_t>();
    original.pocxProof.quality = provider.ConsumeIntegral<uint64_t>();
    std::array<uint8_t, 32> owner_secret{}, signer_secret{};
    owner_secret.back() = 1;
    signer_secret.back() = 2;
    const auto owner = Account(owner_secret), signer = Account(signer_secret);
    original.pocxProof.account_id = owner;
    ForgingAssignment assignment{owner, signer, uint256::ONE, 70, 74};
    assignment.revoked = true;
    assignment.revocation_height = 130;
    assignment.revocation_effective_height = 138;
    const int random_height = provider.ConsumeIntegralInRange<int>(0, 200);
    for (const bool is_owner : {true, false}) {
        CBlock block = original;
        assert(pocx::mining::SignPoCXBlockWithKey(block, is_owner ? owner_secret : signer_secret));
        assert(pocx::consensus::VerifyPoCXBlockCompactSignature(block));
        assert(pocx::consensus::VerifyPoCXBlockCompactSignature(block, std::nullopt, 100) == is_owner);
        for (int height : {69, 70, 73, 74, 129, 130, 137, 138, random_height}) {
            const bool delegated = height >= 74 && height < 138;
            assert(pocx::consensus::VerifyPoCXBlockCompactSignature(block, assignment, height) == (is_owner != delegated));
        }
        CBlock mutation = block;
        mutation.vchSignature[provider.ConsumeIntegralInRange<size_t>(0, 64)] ^= 1;
        assert(!pocx::consensus::VerifyPoCXBlockCompactSignature(mutation));
        mutation = block;
        mutation.nBaseTarget ^= 1;
        assert(!pocx::consensus::VerifyPoCXBlockCompactSignature(mutation));
        mutation = block;
        mutation.pocxProof.account_id[0] ^= 1;
        assert(!pocx::consensus::VerifyPoCXBlockCompactSignature(mutation));
        // A signature over the raw header hash is not a PoCX-domain signature.
        CKey key;
        const auto& secret = is_owner ? owner_secret : signer_secret;
        key.Set(secret.begin(), secret.end(), true);
        std::vector<unsigned char> raw_signature;
        assert(key.SignCompact(block.GetHash(), raw_signature));
        std::copy(raw_signature.begin(), raw_signature.end(), mutation.vchSignature.begin());
        mutation.pocxProof.account_id = block.pocxProof.account_id;
        assert(!pocx::consensus::VerifyPoCXBlockCompactSignature(mutation));
    }
    assert(pocx::mining::SignPoCXBlockWithKey(original, owner_secret));
    original.vchSignature.fill(0);
    std::copy_n(buffer.begin(), std::min(buffer.size(), original.vchSignature.size()), original.vchSignature.begin());
    (void)pocx::consensus::VerifyPoCXBlockCompactSignature(original);
    (void)pocx::consensus::VerifyPoCXBlockCompactSignature(original, assignment, random_height);
    std::array<uint8_t, 32> invalid_key{};
    assert(!pocx::mining::SignPoCXBlockWithKey(original, invalid_key));
}
