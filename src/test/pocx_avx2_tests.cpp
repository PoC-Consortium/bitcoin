// Copyright (c) 2025 The Proof of Capacity Consortium
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <pocx/crypto/shabal256.h>
#include <pocx/crypto/shabal256_avx2.h>
#include <pocx/consensus/batch_validation.h>
#include <pocx/consensus/proof.h>
#include <pocx/consensus/signature.h>
#include <pocx/algorithms/encoding.h>
#include <pocx/algorithms/plot_generation.h>
#include <primitives/block.h>
#include <uint256.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>
#include <cstring>
#include <vector>
#include <random>
#include <array>

using namespace pocx::crypto;
using namespace pocx::consensus;
using namespace pocx::algorithms;

// PoCX requires regtest for testing (mainnet is disabled)
struct PoCXTestingSetup : BasicTestingSetup {
    PoCXTestingSetup() : BasicTestingSetup{ChainType::REGTEST, {.extra_args = {"-regtest"}}} {}
};

BOOST_FIXTURE_TEST_SUITE(pocx_avx2_tests, PoCXTestingSetup)

BOOST_AUTO_TEST_CASE(avx2_detection)
{
    // Just test that detection works without crashing
    bool have_avx2 = HaveAVX2();
    BOOST_TEST_MESSAGE("AVX2 available: " << (have_avx2 ? "yes" : "no"));
    BOOST_TEST_MESSAGE("Batch implementation: " << pocx_batch_implementation_name());
}

#ifdef ENABLE_AVX2

BOOST_AUTO_TEST_CASE(generate_nonces_avx2_matches_scalar)
{
    // Critical test: Compare GenerateNonces8_avx2 output with GenerateNonces output byte-by-byte
    // This ensures the AVX2 nonce generation produces identical nonces to scalar

    if (!HaveAVX2()) {
        BOOST_TEST_MESSAGE("Skipping AVX2 test - AVX2 not available");
        return;
    }

    // Test with 8 different account/seed/nonce combinations
    uint8_t account_ids[8][20];
    uint8_t seeds[8][32];
    uint64_t nonces[8];

    std::mt19937 rng(0xF00DFACE);

    for (int i = 0; i < 8; i++) {
        for (int j = 0; j < 20; j++) {
            account_ids[i][j] = static_cast<uint8_t>(rng() & 0xFF);
        }
        for (int j = 0; j < 32; j++) {
            seeds[i][j] = static_cast<uint8_t>(rng() & 0xFF);
        }
        nonces[i] = rng() % 100000;
    }

    // Generate nonces with scalar GenerateNonces
    uint8_t scalar_buffers[8][pocx::algorithms::NONCE_SIZE];
    for (int i = 0; i < 8; i++) {
        int ret = pocx::algorithms::GenerateNonces(
            scalar_buffers[i], pocx::algorithms::NONCE_SIZE, 0,
            account_ids[i], seeds[i], nonces[i], 1
        );
        BOOST_REQUIRE_EQUAL(ret, 0);
    }

    // Generate nonces with AVX2
    uint8_t avx2_buffers[8][pocx::algorithms::NONCE_SIZE];
    uint8_t* buffer_ptrs[8];
    const uint8_t* account_ptrs[8];
    const uint8_t* seed_ptrs[8];

    for (int i = 0; i < 8; i++) {
        buffer_ptrs[i] = avx2_buffers[i];
        account_ptrs[i] = account_ids[i];
        seed_ptrs[i] = seeds[i];
    }

    int ret = pocx::algorithms::GenerateNonces8_avx2(buffer_ptrs, account_ptrs, seed_ptrs, nonces);
    BOOST_REQUIRE_EQUAL(ret, 0);

    // Compare byte-by-byte
    int mismatches = 0;
    for (int i = 0; i < 8; i++) {
        if (std::memcmp(scalar_buffers[i], avx2_buffers[i], pocx::algorithms::NONCE_SIZE) != 0) {
            mismatches++;
            // Find first mismatch
            for (size_t j = 0; j < pocx::algorithms::NONCE_SIZE; j++) {
                if (scalar_buffers[i][j] != avx2_buffers[i][j]) {
                    BOOST_ERROR("Nonce " << i << " mismatch at byte " << j
                        << ": scalar=0x" << std::hex << (int)scalar_buffers[i][j]
                        << " avx2=0x" << (int)avx2_buffers[i][j] << std::dec);
                    break;
                }
            }
        }
    }
    BOOST_CHECK_EQUAL(mismatches, 0);
    BOOST_TEST_MESSAGE("GenerateNonces8_avx2 matches scalar GenerateNonces for all 8 nonces");
}

BOOST_AUTO_TEST_CASE(shabal256_avx2_matches_scalar)
{
    // Skip if AVX2 not available
    if (!HaveAVX2()) {
        BOOST_TEST_MESSAGE("Skipping AVX2 test - AVX2 not available");
        return;
    }

    // Create 8 different test inputs
    uint8_t data[8][64];
    uint32_t term[8][16];
    uint8_t output_scalar[8][32];
    uint8_t output_avx2[8][32];

    std::mt19937 rng(12345); // Fixed seed for reproducibility

    for (int i = 0; i < 8; i++) {
        // Fill with pseudo-random data
        for (int j = 0; j < 64; j++) {
            data[i][j] = static_cast<uint8_t>(rng() & 0xFF);
        }
        // Create termination block
        std::memset(term[i], 0, sizeof(term[i]));
        term[i][0] = 0x80;

        // Scalar computation
        Shabal256(data[i], 64, nullptr, term[i], output_scalar[i]);
    }

    // AVX2 computation
    const uint8_t* data_ptrs[8];
    const uint32_t* term_ptrs[8];
    uint8_t* output_ptrs[8];

    for (int i = 0; i < 8; i++) {
        data_ptrs[i] = data[i];
        term_ptrs[i] = term[i];
        output_ptrs[i] = output_avx2[i];
    }

    const uint32_t* pre_term_ptrs[8] = {nullptr, nullptr, nullptr, nullptr,
                                         nullptr, nullptr, nullptr, nullptr};

    Shabal256_avx2(data_ptrs, 64, pre_term_ptrs, term_ptrs, output_ptrs);

    // Compare results
    for (int i = 0; i < 8; i++) {
        BOOST_CHECK_MESSAGE(
            std::memcmp(output_scalar[i], output_avx2[i], 32) == 0,
            "AVX2 output mismatch at lane " << i
        );
    }
}

BOOST_AUTO_TEST_CASE(shabal256_avx2_with_preterm)
{
    // Skip if AVX2 not available
    if (!HaveAVX2()) {
        BOOST_TEST_MESSAGE("Skipping AVX2 test - AVX2 not available");
        return;
    }

    // Test with pre-termination blocks (like in nonce generation)
    uint8_t data[8][64];
    uint32_t pre_term[8][16];
    uint32_t term[8][16];
    uint8_t output_scalar[8][32];
    uint8_t output_avx2[8][32];

    std::mt19937 rng(67890);

    for (int i = 0; i < 8; i++) {
        for (int j = 0; j < 64; j++) {
            data[i][j] = static_cast<uint8_t>(rng() & 0xFF);
        }
        for (int j = 0; j < 16; j++) {
            pre_term[i][j] = rng();
            term[i][j] = rng();
        }
        term[i][0] |= 0x80; // Ensure padding bit

        // Scalar computation with pre_term
        Shabal256(data[i], 64, pre_term[i], term[i], output_scalar[i]);
    }

    // AVX2 computation
    const uint8_t* data_ptrs[8];
    const uint32_t* pre_term_ptrs[8];
    const uint32_t* term_ptrs[8];
    uint8_t* output_ptrs[8];

    for (int i = 0; i < 8; i++) {
        data_ptrs[i] = data[i];
        pre_term_ptrs[i] = pre_term[i];
        term_ptrs[i] = term[i];
        output_ptrs[i] = output_avx2[i];
    }

    Shabal256_avx2(data_ptrs, 64, pre_term_ptrs, term_ptrs, output_ptrs);

    // Compare results
    for (int i = 0; i < 8; i++) {
        BOOST_CHECK_MESSAGE(
            std::memcmp(output_scalar[i], output_avx2[i], 32) == 0,
            "AVX2 output with pre_term mismatch at lane " << i
        );
    }
}

BOOST_AUTO_TEST_CASE(shabal256_avx2_known_vectors)
{
    // Skip if AVX2 not available
    if (!HaveAVX2()) {
        BOOST_TEST_MESSAGE("Skipping AVX2 test - AVX2 not available");
        return;
    }

    // Use same test vector as scalar test
    static const uint8_t EXPECTED[32] = {
        0xDA, 0x8F, 0x08, 0xC0, 0x2A, 0x67, 0xBA, 0x9A,
        0x56, 0xBD, 0xD0, 0x79, 0x8E, 0x48, 0xAE, 0x07,
        0x14, 0x21, 0x5E, 0x09, 0x3B, 0x5B, 0x85, 0x06,
        0x49, 0xA3, 0x77, 0x18, 0x99, 0x3F, 0x54, 0xA2
    };

    // Same input 8 times
    uint8_t data[8][64];
    uint32_t term[8][16];
    uint8_t output[8][32];

    for (int i = 0; i < 8; i++) {
        std::memset(data[i], 0, 64);
        std::memset(term[i], 0, sizeof(term[i]));
        term[i][0] = 0x80;
    }

    const uint8_t* data_ptrs[8];
    const uint32_t* pre_term_ptrs[8] = {nullptr};
    const uint32_t* term_ptrs[8];
    uint8_t* output_ptrs[8];

    for (int i = 0; i < 8; i++) {
        data_ptrs[i] = data[i];
        pre_term_ptrs[i] = nullptr;
        term_ptrs[i] = term[i];
        output_ptrs[i] = output[i];
    }

    Shabal256_avx2(data_ptrs, 64, pre_term_ptrs, term_ptrs, output_ptrs);

    // All 8 lanes should produce the known result
    for (int i = 0; i < 8; i++) {
        BOOST_CHECK_MESSAGE(
            std::memcmp(output[i], EXPECTED, 32) == 0,
            "AVX2 known vector mismatch at lane " << i
        );
    }
}

#endif // ENABLE_AVX2

BOOST_AUTO_TEST_CASE(batch_validation_single_block)
{
    // Test batch validation with a single block
    // Uses known test vector

    uint8_t gen_sig[32];
    const char* gen_sig_hex = "9821beb3b34d9a3b30127c05f8d1e9006f8a02f565a3572145134bbe34d37a76";
    DecodeGenerationSignature(gen_sig_hex, gen_sig);

    uint8_t account_id[20];
    const char* account_hex = "99BC78BA577A95A11F1A344D4D2AE55F2F857B98";
    for (int i = 0; i < 20; i++) {
        char hex_byte[3] = {account_hex[i * 2], account_hex[i * 2 + 1], 0};
        account_id[i] = static_cast<uint8_t>(std::strtoul(hex_byte, nullptr, 16));
    }

    uint8_t seed[32];
    const char* seed_hex = "AFFEAFFEAFFEAFFEAFFEAFFEAFFEAFFEAFFEAFFEAFFEAFFEAFFEAFFEAFFEAFFE";
    for (int i = 0; i < 32; i++) {
        char hex_byte[3] = {seed_hex[i * 2], seed_hex[i * 2 + 1], 0};
        seed[i] = static_cast<uint8_t>(std::strtoul(hex_byte, nullptr, 16));
    }

    BlockValidationInput input;
    input.generation_sig = gen_sig;
    input.base_target = 1000000;
    input.account_id = account_id;
    input.height = 100;
    input.nonce = 1337;
    input.seed = seed;
    input.compression = 1; // Minimum compression

    ValidationResult result;
    int ret = pocx_validate_blocks(&input, 1, &result);

    BOOST_CHECK_EQUAL(ret, 0);
    BOOST_CHECK(result.is_valid);
    BOOST_CHECK_EQUAL(result.error_code, VALIDATION_SUCCESS);
    BOOST_CHECK(result.quality > 0);
}

BOOST_AUTO_TEST_CASE(batch_validation_matches_single)
{
    // Compare batch validation to single block validation

    uint8_t gen_sig[32];
    const char* gen_sig_hex = "9821beb3b34d9a3b30127c05f8d1e9006f8a02f565a3572145134bbe34d37a76";
    DecodeGenerationSignature(gen_sig_hex, gen_sig);

    uint8_t account_id[20];
    const char* account_hex = "99BC78BA577A95A11F1A344D4D2AE55F2F857B98";
    for (int i = 0; i < 20; i++) {
        char hex_byte[3] = {account_hex[i * 2], account_hex[i * 2 + 1], 0};
        account_id[i] = static_cast<uint8_t>(std::strtoul(hex_byte, nullptr, 16));
    }

    uint8_t seed[32];
    const char* seed_hex = "AFFEAFFEAFFEAFFEAFFEAFFEAFFEAFFEAFFEAFFEAFFEAFFEAFFEAFFEAFFEAFFE";
    for (int i = 0; i < 32; i++) {
        char hex_byte[3] = {seed_hex[i * 2], seed_hex[i * 2 + 1], 0};
        seed[i] = static_cast<uint8_t>(std::strtoul(hex_byte, nullptr, 16));
    }

    // Validate single block using existing function
    ValidationResult single_result;
    bool success = pocx_validate_block(
        gen_sig_hex,
        1000000,
        account_id,
        100,
        1337,
        seed,
        1, // compression
        &single_result
    );
    BOOST_REQUIRE(success);

    // Validate same block using batch function
    BlockValidationInput input;
    input.generation_sig = gen_sig;
    input.base_target = 1000000;
    input.account_id = account_id;
    input.height = 100;
    input.nonce = 1337;
    input.seed = seed;
    input.compression = 1;

    ValidationResult batch_result;
    int ret = pocx_validate_blocks(&input, 1, &batch_result);

    BOOST_CHECK_EQUAL(ret, 0);
    BOOST_CHECK_EQUAL(batch_result.is_valid, single_result.is_valid);
    BOOST_CHECK_EQUAL(batch_result.quality, single_result.quality);
    BOOST_CHECK_EQUAL(batch_result.deadline, single_result.deadline);
}

BOOST_AUTO_TEST_CASE(batch_validation_multiple_blocks)
{
    // Test with multiple blocks with different parameters

    // Create 4 different block inputs
    uint8_t gen_sigs[4][32];
    uint8_t account_ids[4][20];
    uint8_t seeds[4][32];

    std::mt19937 rng(42);

    for (int i = 0; i < 4; i++) {
        for (int j = 0; j < 32; j++) {
            gen_sigs[i][j] = static_cast<uint8_t>(rng() & 0xFF);
            seeds[i][j] = static_cast<uint8_t>(rng() & 0xFF);
        }
        for (int j = 0; j < 20; j++) {
            account_ids[i][j] = static_cast<uint8_t>(rng() & 0xFF);
        }
    }

    BlockValidationInput inputs[4];
    for (int i = 0; i < 4; i++) {
        inputs[i].generation_sig = gen_sigs[i];
        inputs[i].base_target = 1000000 + i * 1000;
        inputs[i].account_id = account_ids[i];
        inputs[i].height = 100 + i;
        inputs[i].nonce = 1337 + i * 100;
        inputs[i].seed = seeds[i];
        inputs[i].compression = 1;
    }

    ValidationResult results[4];
    int ret = pocx_validate_blocks(inputs, 4, results);

    BOOST_CHECK_EQUAL(ret, 0);
    for (int i = 0; i < 4; i++) {
        BOOST_CHECK_MESSAGE(results[i].is_valid, "Block " << i << " validation failed");
        BOOST_CHECK_MESSAGE(results[i].quality > 0, "Block " << i << " has zero quality");
    }
}

BOOST_AUTO_TEST_CASE(batch_validation_mixed_compression)
{
    // Test with different compression levels

    uint8_t gen_sig[32];
    uint8_t account_id[20];
    uint8_t seed[32];

    std::mt19937 rng(99);
    for (int j = 0; j < 32; j++) {
        gen_sig[j] = static_cast<uint8_t>(rng() & 0xFF);
        seed[j] = static_cast<uint8_t>(rng() & 0xFF);
    }
    for (int j = 0; j < 20; j++) {
        account_id[j] = static_cast<uint8_t>(rng() & 0xFF);
    }

    // Create blocks with different compression levels
    BlockValidationInput inputs[3];
    for (int i = 0; i < 3; i++) {
        inputs[i].generation_sig = gen_sig;
        inputs[i].base_target = 1000000;
        inputs[i].account_id = account_id;
        inputs[i].height = 100;
        inputs[i].nonce = 0; // Use nonce 0 for simplicity
        inputs[i].seed = seed;
        inputs[i].compression = i + 1; // 1, 2, 3
    }

    ValidationResult results[3];
    int ret = pocx_validate_blocks(inputs, 3, results);

    BOOST_CHECK_EQUAL(ret, 0);
    for (int i = 0; i < 3; i++) {
        BOOST_CHECK_MESSAGE(results[i].is_valid,
            "Block with compression " << i << " validation failed");
    }

    // Different compression levels should produce different qualities
    // (same inputs but different number of nonces XORed)
    BOOST_CHECK(results[0].quality != results[1].quality ||
                results[1].quality != results[2].quality);
}

BOOST_AUTO_TEST_CASE(batch_validation_8_blocks_vs_single)
{
    // Critical test: Compare batch validation (which uses AVX2) against
    // single block validation for 8 random blocks with various compression levels.
    // This ensures AVX2 path produces identical results to scalar path.

    constexpr int NUM_BLOCKS = 8;

    // Storage for inputs
    uint8_t gen_sigs[NUM_BLOCKS][32];
    uint8_t account_ids[NUM_BLOCKS][20];
    uint8_t seeds[NUM_BLOCKS][32];
    char gen_sig_hex[NUM_BLOCKS][65]; // For pocx_validate_block which takes hex

    std::mt19937 rng(0xDEADBEEF); // Fixed seed for reproducibility

    // Generate random inputs with various compression levels
    BlockValidationInput inputs[NUM_BLOCKS];
    for (int i = 0; i < NUM_BLOCKS; i++) {
        // Generate random gen_sig
        for (int j = 0; j < 32; j++) {
            gen_sigs[i][j] = static_cast<uint8_t>(rng() & 0xFF);
        }
        // Convert to hex for single validation
        for (int j = 0; j < 32; j++) {
            snprintf(gen_sig_hex[i] + j * 2, 3, "%02x", gen_sigs[i][j]);
        }
        gen_sig_hex[i][64] = '\0';

        // Generate random account_id
        for (int j = 0; j < 20; j++) {
            account_ids[i][j] = static_cast<uint8_t>(rng() & 0xFF);
        }

        // Generate random seed
        for (int j = 0; j < 32; j++) {
            seeds[i][j] = static_cast<uint8_t>(rng() & 0xFF);
        }

        inputs[i].generation_sig = gen_sigs[i];
        inputs[i].base_target = 1000000 + (rng() % 1000000);
        inputs[i].account_id = account_ids[i];
        inputs[i].height = 100 + (rng() % 10000);
        inputs[i].nonce = rng() % 100000;
        inputs[i].seed = seeds[i];
        // Mix compression levels: 1, 2, 3, 4 (2 to 16 work units per block)
        inputs[i].compression = (i % 4) + 1;
    }

    // First: validate each block individually using pocx_validate_block
    ValidationResult single_results[NUM_BLOCKS];
    for (int i = 0; i < NUM_BLOCKS; i++) {
        bool success = pocx_validate_block(
            gen_sig_hex[i],
            inputs[i].base_target,
            account_ids[i],
            inputs[i].height,
            inputs[i].nonce,
            seeds[i],
            inputs[i].compression,
            &single_results[i]
        );
        BOOST_REQUIRE_MESSAGE(success, "Single validation failed for block " << i);
        BOOST_REQUIRE_MESSAGE(single_results[i].is_valid, "Single result invalid for block " << i);
    }

    // Second: validate all blocks using batch validation (triggers AVX2 with 8 blocks)
    ValidationResult batch_results[NUM_BLOCKS];
    int ret = pocx_validate_blocks(inputs, NUM_BLOCKS, batch_results);
    BOOST_REQUIRE_EQUAL(ret, 0);

    // Compare results - they must match exactly
    for (int i = 0; i < NUM_BLOCKS; i++) {
        BOOST_CHECK_MESSAGE(batch_results[i].is_valid,
            "Batch validation failed for block " << i);
        BOOST_CHECK_MESSAGE(batch_results[i].quality == single_results[i].quality,
            "Quality mismatch for block " << i
            << ": batch=" << batch_results[i].quality
            << " single=" << single_results[i].quality
            << " (compression=" << inputs[i].compression << ")");
        BOOST_CHECK_MESSAGE(batch_results[i].deadline == single_results[i].deadline,
            "Deadline mismatch for block " << i
            << ": batch=" << batch_results[i].deadline
            << " single=" << single_results[i].deadline);
    }

    BOOST_TEST_MESSAGE("Batch implementation used: " << pocx_batch_implementation_name());
    BOOST_TEST_MESSAGE("Thread count: " << pocx_batch_thread_count());
}

BOOST_AUTO_TEST_CASE(batch_validation_16_blocks_high_compression)
{
    // Test with 16 blocks at higher compression to stress test AVX2 batching
    // Compression 3 = 8 work units per block, so 16 blocks = 128 work units

    constexpr int NUM_BLOCKS = 16;

    uint8_t gen_sigs[NUM_BLOCKS][32];
    uint8_t account_ids[NUM_BLOCKS][20];
    uint8_t seeds[NUM_BLOCKS][32];
    char gen_sig_hex[NUM_BLOCKS][65];

    std::mt19937 rng(0xCAFEBABE);

    BlockValidationInput inputs[NUM_BLOCKS];
    for (int i = 0; i < NUM_BLOCKS; i++) {
        for (int j = 0; j < 32; j++) {
            gen_sigs[i][j] = static_cast<uint8_t>(rng() & 0xFF);
        }
        for (int j = 0; j < 32; j++) {
            snprintf(gen_sig_hex[i] + j * 2, 3, "%02x", gen_sigs[i][j]);
        }
        gen_sig_hex[i][64] = '\0';

        for (int j = 0; j < 20; j++) {
            account_ids[i][j] = static_cast<uint8_t>(rng() & 0xFF);
        }
        for (int j = 0; j < 32; j++) {
            seeds[i][j] = static_cast<uint8_t>(rng() & 0xFF);
        }

        inputs[i].generation_sig = gen_sigs[i];
        inputs[i].base_target = 500000 + (rng() % 500000);
        inputs[i].account_id = account_ids[i];
        inputs[i].height = 1000 + i;
        inputs[i].nonce = rng() % 50000;
        inputs[i].seed = seeds[i];
        inputs[i].compression = 3; // 8 work units each
    }

    // Single validation
    ValidationResult single_results[NUM_BLOCKS];
    for (int i = 0; i < NUM_BLOCKS; i++) {
        bool success = pocx_validate_block(
            gen_sig_hex[i],
            inputs[i].base_target,
            account_ids[i],
            inputs[i].height,
            inputs[i].nonce,
            seeds[i],
            inputs[i].compression,
            &single_results[i]
        );
        BOOST_REQUIRE_MESSAGE(success, "Single validation failed for block " << i);
    }

    // Batch validation
    ValidationResult batch_results[NUM_BLOCKS];
    int ret = pocx_validate_blocks(inputs, NUM_BLOCKS, batch_results);
    BOOST_REQUIRE_EQUAL(ret, 0);

    // Compare
    int mismatches = 0;
    for (int i = 0; i < NUM_BLOCKS; i++) {
        if (batch_results[i].quality != single_results[i].quality) {
            mismatches++;
            BOOST_ERROR("Quality mismatch for block " << i
                << ": batch=" << batch_results[i].quality
                << " single=" << single_results[i].quality);
        }
    }
    BOOST_CHECK_EQUAL(mismatches, 0);

    BOOST_TEST_MESSAGE("16-block test with compression 3:");
    BOOST_TEST_MESSAGE("  Implementation: " << pocx_batch_implementation_name());
    BOOST_TEST_MESSAGE("  Thread count: " << pocx_batch_thread_count());
    BOOST_TEST_MESSAGE("  Total work units: " << (NUM_BLOCKS * 8));
}

BOOST_AUTO_TEST_CASE(batch_validation_uint256_byte_order)
{
    // Critical test: Verify that batch validation handles uint256 generation signature
    // byte order correctly. uint256::ToString() reverses bytes, and the batch validation
    // caller must reverse bytes to match ValidateProofOfCapacity behavior.
    //
    // This test simulates the real-world scenario where:
    // 1. Generation signature is stored as uint256 in block header
    // 2. ValidateProofOfCapacity uses generationSignature.ToString() which reverses bytes
    // 3. Batch validation must receive the same reversed bytes

    // Create test data
    uint8_t account_id[20];
    uint8_t seed[32];
    std::mt19937 rng(0xB17E00DE);

    for (int j = 0; j < 20; j++) {
        account_id[j] = static_cast<uint8_t>(rng() & 0xFF);
    }
    for (int j = 0; j < 32; j++) {
        seed[j] = static_cast<uint8_t>(rng() & 0xFF);
    }

    // Create a uint256 generation signature (as stored in block header)
    uint256 gen_sig_uint256;
    for (int j = 0; j < 32; j++) {
        gen_sig_uint256.data()[j] = static_cast<uint8_t>(rng() & 0xFF);
    }

    uint64_t base_target = 1000000;
    uint64_t height = 100;
    uint64_t nonce = 12345;
    uint32_t compression = 1;

    // Method 1: Use ValidateProofOfCapacity (the reference - uses ToString() internally)
    PoCXProof proof;
    std::copy(account_id, account_id + 20, proof.account_id.begin());
    std::copy(seed, seed + 32, proof.seed.begin());
    proof.nonce = nonce;
    proof.compression = compression;

    ValidationResult ref_result = ValidateProofOfCapacity(
        gen_sig_uint256, proof, base_target, height, compression, 120 // Realistic block time
    );
    BOOST_REQUIRE(ref_result.is_valid);

    // Method 2: Use batch validation with REVERSED bytes (correct way)
    std::array<uint8_t, 32> gen_sig_reversed;
    for (size_t j = 0; j < 32; j++) {
        gen_sig_reversed[j] = gen_sig_uint256.data()[31 - j];
    }

    BlockValidationInput input_correct;
    input_correct.generation_sig = gen_sig_reversed.data();
    input_correct.base_target = base_target;
    input_correct.account_id = account_id;
    input_correct.height = height;
    input_correct.nonce = nonce;
    input_correct.seed = seed;
    input_correct.compression = compression;

    ValidationResult batch_result_correct;
    int ret = pocx_validate_blocks(&input_correct, 1, &batch_result_correct);
    BOOST_REQUIRE_EQUAL(ret, 0);
    BOOST_REQUIRE(batch_result_correct.is_valid);

    // Method 3: Use batch validation with RAW bytes (incorrect way - would fail before fix)
    BlockValidationInput input_wrong;
    input_wrong.generation_sig = gen_sig_uint256.data(); // Raw bytes, not reversed!
    input_wrong.base_target = base_target;
    input_wrong.account_id = account_id;
    input_wrong.height = height;
    input_wrong.nonce = nonce;
    input_wrong.seed = seed;
    input_wrong.compression = compression;

    ValidationResult batch_result_wrong;
    ret = pocx_validate_blocks(&input_wrong, 1, &batch_result_wrong);
    BOOST_REQUIRE_EQUAL(ret, 0);

    // Verify: correct method matches reference, wrong method doesn't
    BOOST_CHECK_MESSAGE(batch_result_correct.quality == ref_result.quality,
        "Batch with reversed bytes should match reference: "
        << "batch=" << batch_result_correct.quality
        << " ref=" << ref_result.quality);

    BOOST_CHECK_MESSAGE(batch_result_wrong.quality != ref_result.quality,
        "Batch with raw bytes should NOT match reference (proves byte order matters): "
        << "batch_wrong=" << batch_result_wrong.quality
        << " ref=" << ref_result.quality);

    BOOST_TEST_MESSAGE("uint256 byte order test passed:");
    BOOST_TEST_MESSAGE("  Reference quality: " << ref_result.quality);
    BOOST_TEST_MESSAGE("  Batch (reversed):  " << batch_result_correct.quality << " - MATCH");
    BOOST_TEST_MESSAGE("  Batch (raw):       " << batch_result_wrong.quality << " - MISMATCH (expected)");
}

BOOST_AUTO_TEST_SUITE_END()
