// Copyright (c) 2026 The Bitcoin PoCX developers
// Distributed under the MIT software license; see COPYING.
#include <test/data/real_proof_vectors.json.h>
#include <test/util/json.h>
#include <test/util/setup_common.h>
#include <pocx/algorithms/plot_generation.h>
#include <pocx/algorithms/quality.h>
#include <pocx/algorithms/time_bending.h>
#include <pocx/consensus/batch_validation.h>
#include <pocx/consensus/signature.h>
#include <pocx/crypto/shabal256_avx2.h>
#include <pocx/crypto/shabal256_sse2.h>
#include <pocx/crypto/shabal256_lite.h>
#include <pocx/mining/key_signing.h>
#include <pocx/regtest/forging.h>
#include <consensus/merkle.h>
#include <consensus/validation.h>
#include <chainparams.h>
#include <crypto/sha256.h>
#include <key.h>
#include <primitives/block.h>
#include <util/strencodings.h>
#include <validation.h>
#include <boost/test/unit_test.hpp>
#include <array>
#include <limits>
#include <vector>

namespace {
using namespace pocx::algorithms;
using namespace pocx::consensus;
struct Vector {
    std::array<uint8_t, 20> account;
    std::array<uint8_t, 32> seed, gensig;
    uint64_t nonce, height, target, quality, raw_deadline, bended_deadline;
    uint32_t compression;
    int scoop;
    std::string nonce_hash;
    std::vector<unsigned char> compressed_scoop;
    BlockValidationInput Input() const {
        return {gensig.data(), target, account.data(), height, nonce, seed.data(), compression, quality};
    }
};

template <size_t N> std::array<uint8_t, N> Bytes(const UniValue& value)
{
    const auto bytes = ParseHex(value.get_str());
    BOOST_REQUIRE_EQUAL(bytes.size(), N);
    std::array<uint8_t, N> out;
    std::copy(bytes.begin(), bytes.end(), out.begin());
    return out;
}

std::vector<Vector> Vectors()
{
    const auto json = read_json(json_tests::real_proof_vectors);
    BOOST_REQUIRE_EQUAL(json.size(), 8U);
    std::vector<Vector> vectors;
    for (const auto& row : json.getValues()) {
        Vector v;
        v.account = Bytes<20>(row["account"]);
        v.seed = Bytes<32>(row["seed"]);
        v.gensig = Bytes<32>(row["generation_signature"]);
        v.nonce = row["nonce"].getInt<uint64_t>();
        v.height = row["height"].getInt<uint64_t>();
        v.target = row["base_target"].getInt<uint64_t>();
        v.compression = row["compression"].getInt<uint32_t>();
        v.scoop = row["scoop"].getInt<int>();
        v.quality = row["quality"].getInt<uint64_t>();
        v.raw_deadline = row["raw_deadline"].getInt<uint64_t>();
        v.bended_deadline = row["bended_deadline"].getInt<uint64_t>();
        v.nonce_hash = row["nonce_sha256"].get_str();
        v.compressed_scoop = ParseHex(row["compressed_scoop"].get_str());
        BOOST_REQUIRE_EQUAL(v.compressed_scoop.size(), 64U);
        BOOST_REQUIRE(v.account != pocx::regtest::kRegtestForgingAccountId);
        BOOST_REQUIRE(v.seed != pocx::regtest::kRegtestZeroSeed);
        vectors.push_back(v);
    }
    return vectors;
}

std::string Hash(const std::vector<uint8_t>& bytes)
{
    std::array<uint8_t, 32> digest;
    CSHA256().Write(bytes.data(), bytes.size()).Finalize(digest.data());
    return HexStr(digest);
}

CBlock SyntheticBlock()
{
    CBlock block;
    block.nVersion = 0x20000000;
    block.hashPrevBlock = Params().GenesisBlock().GetHash();
    block.nTime = Params().GenesisBlock().nTime + 120;
    block.nHeight = 1;
    block.nBaseTarget = 36650387592;
    block.generationSignature = uint256{"0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"};
    block.pocxProof.account_id = pocx::regtest::kRegtestForgingAccountId;
    block.pocxProof.seed = pocx::regtest::kRegtestZeroSeed;
    block.pocxProof.compression = 1;
    block.pocxProof.nonce = 1;
    BOOST_REQUIRE(pocx::regtest::ComputeRegtestHotPathQuality(block, &block.pocxProof.quality));
    CMutableTransaction coinbase;
    coinbase.vin.resize(1);
    coinbase.vin[0].prevout.SetNull();
    coinbase.vin[0].scriptSig = CScript() << CScriptNum(1) << OP_0;
    coinbase.vout.emplace_back(10 * COIN, CScript() << OP_TRUE);
    block.vtx.push_back(MakeTransactionRef(coinbase));
    block.hashMerkleRoot = BlockMerkleRoot(block);
    BOOST_REQUIRE(pocx::mining::SignPoCXBlockWithKey(block, pocx::regtest::kRegtestForgingPrivKey));
    BOOST_REQUIRE(pocx::consensus::VerifyPoCXBlockCompactSignature(block));
    BOOST_REQUIRE(pocx::regtest::IsRegtestHotPathProof(block.pocxProof));
    return block;
}
} // namespace

BOOST_AUTO_TEST_SUITE(pocx_real_proof_tests)

BOOST_AUTO_TEST_CASE(scalar_independent_known_vectors)
{
    for (const auto& v : Vectors()) {
        BOOST_TEST_CONTEXT("height=" << v.height << " compression=" << v.compression) {
            std::vector<uint8_t> nonce(NONCE_SIZE);
            BOOST_REQUIRE_EQUAL(GenerateNonces(nonce.data(), nonce.size(), 0, v.account.data(), v.seed.data(), v.nonce, 1), 0);
            BOOST_CHECK_EQUAL(Hash(nonce), v.nonce_hash);
            BOOST_CHECK_EQUAL(CalculateScoop(v.height, v.gensig.data()), v.scoop);
            BOOST_CHECK_EQUAL(pocx::crypto::Shabal256Lite(v.compressed_scoop.data(), v.gensig.data()), v.quality);
            ValidationResult result;
            BOOST_REQUIRE(pocx_validate_block(HexStr(v.gensig).c_str(), v.target, v.account.data(), v.height, v.nonce, v.seed.data(), v.compression, &result));
            BOOST_CHECK(result.is_valid);
            BOOST_CHECK_EQUAL(result.error_code, VALIDATION_SUCCESS);
            BOOST_CHECK_EQUAL(result.quality, v.quality);
            BOOST_CHECK_EQUAL(result.deadline, v.raw_deadline);
            BOOST_CHECK_EQUAL(CalculateTimeBendedDeadline(v.quality, v.target, 120), v.bended_deadline);
            PoCXProof proof;
            proof.account_id = v.account;
            proof.seed = v.seed;
            proof.nonce = v.nonce;
            proof.compression = v.compression;
            proof.quality = v.quality;
            // Parse the displayed generation signature, preserving uint256's
            // reversed internal representation and the actual public wrapper.
            const auto wrapped = ValidateProofOfCapacity(uint256::FromHex(HexStr(v.gensig)).value(), proof, v.target, v.height, v.compression, 120);
            BOOST_CHECK(wrapped.is_valid);
            BOOST_CHECK_EQUAL(wrapped.quality, v.quality);
            BOOST_CHECK_EQUAL(wrapped.deadline, v.bended_deadline);
        }
    }
}

BOOST_AUTO_TEST_CASE(synthetic_proof_rejected_on_production_networks)
{
    for (const auto chain : {ChainType::MAIN, ChainType::TESTNET4}) {
        BasicTestingSetup setup{chain};
        auto block = SyntheticBlock();
        BlockValidationState state;
        // Exercise the normal block entry point, with proof and merkle checks
        // enabled. A valid compact signature cannot authorize fake plot data.
        BOOST_CHECK(!CheckBlock(block, state, Params().GetConsensus()));
        BOOST_CHECK_EQUAL(state.GetRejectReason(), "bad-pocx-quality-mismatch");
        BOOST_CHECK(state.GetResult() == BlockValidationResult::BLOCK_INVALID_HEADER);
        BOOST_TEST_MESSAGE("Synthetic proof rejected on " << ChainTypeToString(chain));
    }
}

BOOST_AUTO_TEST_CASE(synthetic_proof_regtest_positive_control)
{
    BasicTestingSetup setup{ChainType::REGTEST};
    auto block = SyntheticBlock();
    BlockValidationState state;
    BOOST_REQUIRE(CheckBlock(block, state, Params().GetConsensus()));
    BOOST_CHECK(state.IsValid());
    // This is stateless block validation, not contextual chain acceptance.
}

BOOST_AUTO_TEST_CASE(batch_independent_known_vectors)
{
    const auto vectors = Vectors();
    std::array<BlockValidationInput, 8> inputs;
    std::array<ValidationResult, 8> results;
    for (size_t i = 0; i < vectors.size(); ++i) inputs[i] = vectors[i].Input();
    BOOST_REQUIRE_EQUAL(pocx_validate_blocks(inputs.data(), inputs.size(), results.data()), 0);
    BOOST_TEST_MESSAGE("Real-vector batch path: " << pocx_batch_implementation_name() << "; threads: " << pocx_batch_thread_count());
    for (size_t i = 0; i < vectors.size(); ++i) {
        BOOST_CHECK(results[i].is_valid);
        BOOST_CHECK_EQUAL(results[i].error_code, VALIDATION_SUCCESS);
        BOOST_CHECK_EQUAL(results[i].quality, vectors[i].quality);
        BOOST_CHECK_EQUAL(results[i].deadline, vectors[i].raw_deadline);
    }
}

BOOST_AUTO_TEST_CASE(proof_field_mutations_and_compression_rejection)
{
    const auto original = Vectors().front();
    for (int mutation = 0; mutation < 7; ++mutation) {
        auto v = original;
        switch (mutation) {
        case 0: v.account[0] ^= 1; break;
        case 1: v.seed[31] ^= 1; break;
        case 2: v.nonce ^= 1; break;
        case 3: ++v.height; break;
        case 4: v.gensig[0] ^= 1; break;
        case 5: v.compression = 2; break;
        case 6: v.quality ^= 1; break;
        }
        auto input = v.Input();
        ValidationResult result;
        // The batch API returns -2 when early surrender detects a quality
        // mismatch; the per-proof result carries the specific rejection.
        BOOST_REQUIRE_EQUAL(pocx_validate_blocks(&input, 1, &result), -2);
        BOOST_CHECK(!result.is_valid);
        BOOST_CHECK_EQUAL(result.error_code, VALIDATION_ERROR_QUALITY_MISMATCH);
    }
    for (uint32_t compression : {0U, 8U, 31U, 32U, 63U, 64U, std::numeric_limits<uint32_t>::max()}) {
        auto input = original.Input();
        input.compression = compression;
        ValidationResult result;
        BOOST_CHECK_EQUAL(pocx_validate_blocks(&input, 1, &result), VALIDATION_ERROR_COMPRESSION_OUT_OF_RANGE);
        BOOST_CHECK(!result.is_valid);
        BOOST_CHECK_EQUAL(result.error_code, VALIDATION_ERROR_COMPRESSION_OUT_OF_RANGE);
    }
}

BOOST_AUTO_TEST_CASE(simd_nonces_independent_known_vectors)
{
    const auto vectors = Vectors();
    std::array<std::vector<uint8_t>, 8> buffers;
    std::array<uint8_t*, 8> output;
    std::array<const uint8_t*, 8> accounts, seeds;
    std::array<uint64_t, 8> nonces;
    for (size_t i = 0; i < vectors.size(); ++i) {
        buffers[i].resize(NONCE_SIZE);
        output[i] = buffers[i].data();
        accounts[i] = vectors[i].account.data();
        seeds[i] = vectors[i].seed.data();
        nonces[i] = vectors[i].nonce;
    }
#ifdef ENABLE_AVX2
    if (pocx::crypto::HaveAVX2()) {
        BOOST_REQUIRE_EQUAL(GenerateNonces8_avx2(output.data(), accounts.data(), seeds.data(), nonces.data()), 0);
        for (size_t i = 0; i < 8; ++i) BOOST_CHECK_EQUAL(Hash(buffers[i]), vectors[i].nonce_hash);
        BOOST_TEST_MESSAGE("Independent full-nonce vectors exercised AVX2");
    } else {
        BOOST_TEST_MESSAGE("AVX2 not exercised: unavailable on this host");
    }
#endif
#ifdef ENABLE_SSE2
    if (pocx::crypto::HaveSSE2()) {
        for (size_t i : {0U, 4U}) {
            BOOST_REQUIRE_EQUAL(GenerateNonces4_sse2(output.data() + i, accounts.data() + i, seeds.data() + i, nonces.data() + i), 0);
        }
        for (size_t i = 0; i < 8; ++i) BOOST_CHECK_EQUAL(Hash(buffers[i]), vectors[i].nonce_hash);
        BOOST_TEST_MESSAGE("Independent full-nonce vectors exercised SSE2");
    } else {
        BOOST_TEST_MESSAGE("SSE2 not exercised: unavailable on this host");
    }
#endif
}
BOOST_AUTO_TEST_SUITE_END()
