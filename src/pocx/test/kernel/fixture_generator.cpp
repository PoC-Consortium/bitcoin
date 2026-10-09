// Copyright (c) 2026 The Bitcoin PoCX developers
// Distributed under the MIT software license; see COPYING.
// Test-only real-proof chains. Kernel validation intentionally has no synthetic
// regtest shortcut, so merely wrapping Bitcoin fixtures cannot establish parity.
#include <chain.h>
#include <chainparams.h>
#include <common/args.h>
#include <consensus/amount.h>
#include <consensus/merkle.h>
#include <hash.h>
#include <kernel/context.h>
#include <key.h>
#include <pocx/algorithms/time_bending.h>
#include <pocx/consensus/difficulty.h>
#include <pocx/consensus/proof.h>
#include <pocx/consensus/signature.h>
#include <pocx/mining/key_signing.h>
#include <primitives/block.h>
#include <script/sign.h>
#include <script/signingprovider.h>
#include <streams.h>
#include <univalue.h>
#include <util/strencodings.h>
#include <util/translation.h>
#include <algorithm>
#include <array>
#include <fstream>
#include <iostream>
#include <memory>
#include <stdexcept>
#include <vector>

const std::function<std::string(const char*)> G_TRANSLATION_FUN{nullptr};

namespace {
std::array<uint8_t, 32> KeyBytes()
{
    std::array<uint8_t, 32> key{};
    key.back() = 1;
    return key;
}

void Require(bool condition, const char* message)
{
    if (!condition) throw std::runtime_error(message);
}

std::string Hex(const CBlock& block)
{
    DataStream stream;
    stream << TX_WITH_WITNESS(block);
    return HexStr(stream);
}

void CommitWitness(CBlock& block)
{
    const std::array<uint8_t, 32> reserved{};
    CMutableTransaction coinbase(*block.vtx[0]);
    coinbase.vin[0].scriptWitness.stack.emplace_back(reserved.begin(), reserved.end());
    block.vtx[0] = MakeTransactionRef(coinbase);
    uint256 digest;
    CHash256().Write(BlockWitnessMerkleRoot(block)).Write(reserved).Finalize(digest);
    std::vector<uint8_t> commitment{0xaa, 0x21, 0xa9, 0xed};
    commitment.insert(commitment.end(), digest.begin(), digest.end());
    coinbase.vout.emplace_back(0, CScript() << OP_RETURN << commitment);
    block.vtx[0] = MakeTransactionRef(std::move(coinbase));
}

std::vector<CBlock> Chain(const CChainParams& params, size_t count, bool spend)
{
    using namespace pocx::consensus;
    const auto secret = KeyBytes();
    CKey key;
    key.Set(secret.begin(), secret.end(), true);
    const auto pubkey = key.GetPubKey();
    const auto account = ExtractAccountIDFromPubKey(pubkey);
    Require(HexStr(account) == "751e76e8199196d454941c45d1b3a323f1433bd6", "Unexpected fixed-key account");
    const CScript script = CScript() << OP_0 << std::vector<uint8_t>(account.begin(), account.end());
    FillableSigningProvider provider;
    Require(provider.AddKey(key), "Cannot add fixture signing key");
    const auto& consensus = params.GetConsensus();
    std::vector<CBlock> blocks;
    blocks.reserve(count);
    std::vector<uint256> hashes;
    hashes.reserve(count + 1);
    hashes.push_back(params.GenesisBlock().GetHash());
    std::vector<std::unique_ptr<CBlockIndex>> indexes;
    indexes.push_back(std::make_unique<CBlockIndex>(params.GenesisBlock()));
    indexes.back()->nHeight = 0;
    indexes.back()->phashBlock = &hashes.back();
    indexes.back()->nNextBaseTarget = GetNextBaseTarget(indexes.back().get(), consensus);
    CTransactionRef previous_spend;
    for (size_t height = 1; height <= count; ++height) {
        const auto& previous = *indexes.back();
        CBlock block;
        block.nVersion = 0x20000000;
        block.hashPrevBlock = previous.GetBlockHash();
        block.nHeight = height;
        block.generationSignature = GetNextGenerationSignature(&previous);
        block.nBaseTarget = previous.nNextBaseTarget;
        block.pocxProof.account_id = account;
        block.pocxProof.seed.fill(7);
        block.pocxProof.compression = 1;
        block.pocxProof.nonce = 1;
        ValidationResult result;
        Require(pocx_validate_block(block.generationSignature.ToString().c_str(), block.nBaseTarget,
                                   account.data(), height, 1, block.pocxProof.seed.data(), 1, &result),
                "Real proof generation failed");
        Require(result.is_valid, "Invalid generated proof");
        block.pocxProof.quality = result.quality;
        const auto delay = pocx::algorithms::CalculateTimeBendedDeadline(result.quality, block.nBaseTarget, consensus.nPowTargetSpacing);
        Require(delay < 100000, "Fixture deadline exceeds resource bound");
        block.nTime = previous.nTime + std::max<uint64_t>(delay, 1);

        CAmount fees{0};
        CTransactionRef payment;
        if (spend && height >= 101) {
            const auto& parent_tx = previous_spend ? previous_spend : blocks.front().vtx[0];
            const auto& output = parent_tx->vout[0];
            CMutableTransaction tx;
            tx.vin.emplace_back(COutPoint(parent_tx->GetHash(), 0));
            tx.vout.emplace_back(COIN, script);
            if (!previous_spend) {
                fees = 1000;
                tx.vout.emplace_back(output.nValue - COIN - fees, script);
            }
            SignatureData signature;
            Require(ProduceSignature(provider, MutableTransactionSignatureCreator(tx, 0, output.nValue, SIGHASH_ALL),
                                     output.scriptPubKey, signature), "Cannot sign fixture payment");
            UpdateInput(tx.vin[0], signature);
            payment = MakeTransactionRef(std::move(tx));
        }
        CMutableTransaction coinbase;
        coinbase.vin.resize(1);
        coinbase.vin[0].prevout.SetNull();
        coinbase.vin[0].scriptSig = CScript() << static_cast<int64_t>(height) << OP_0;
        coinbase.vout.emplace_back(10 * COIN + fees, script);
        block.vtx.push_back(MakeTransactionRef(std::move(coinbase)));
        if (payment) {
            block.vtx.push_back(payment);
            previous_spend = payment;
            CommitWitness(block);
        }
        block.hashMerkleRoot = BlockMerkleRoot(block);
        Require(pocx::mining::SignPoCXBlockWithKey(block, secret), "Cannot sign fixture block");
        Require(VerifyPoCXBlockCompactSignature(block, std::nullopt, height), "Fixture signer mismatch");
        hashes.push_back(block.GetHash());
        auto index = std::make_unique<CBlockIndex>(block);
        index->nHeight = height;
        index->phashBlock = &hashes.back();
        index->pprev = indexes.back().get();
        index->BuildSkip();
        index->nNextBaseTarget = GetNextBaseTarget(index.get(), consensus);
        indexes.push_back(std::move(index));
        blocks.push_back(std::move(block));
    }
    return blocks;
}
} // namespace

int main(int argc, char** argv)
{
    try {
        Require(argc == 2, "Usage: pocx_kernel_fixture_generator OUTPUT.json");
        kernel::Context context;
        ECC_Context ecc;
        ArgsManager args;
        const auto main = CreateChainParams(args, ChainType::MAIN);
        const auto regtest = CreateChainParams(args, ChainType::REGTEST);
        UniValue output(UniValue::VOBJ);
        output.pushKV("mainnet_genesis", Hex(main->GenesisBlock()));
        output.pushKV("regtest_genesis", Hex(regtest->GenesisBlock()));
        output.pushKV("mainnet", Hex(Chain(*main, 1, false).front()));
        UniValue chain(UniValue::VARR);
        for (const auto& block : Chain(*regtest, 206, true)) chain.push_back(Hex(block));
        output.pushKV("regtest", chain);
        std::ofstream file(argv[1]);
        Require(static_cast<bool>(file), "Cannot open fixture output");
        file << output.write(2) << '\n';
        Require(static_cast<bool>(file), "Cannot write fixture output");
        std::cout << "Generated one mainnet and 206 regtest real-proof blocks\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
