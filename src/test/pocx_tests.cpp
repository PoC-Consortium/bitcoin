// Copyright (c) 2025 The Proof of Capacity Consortium
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <pocx/crypto/shabal256.h>
#include <pocx/crypto/shabal256_lite.h>
#include <pocx/algorithms/quality.h>
#include <pocx/algorithms/plot_generation.h>
#include <pocx/algorithms/encoding.h>
#include <pocx/consensus/proof.h>
#include <test/util/setup_common.h>
#include <crypto/sha256.h>


#include <boost/test/unit_test.hpp>
#include <cstring>
#include <sstream>
#include <iomanip>

using namespace pocx::crypto;
using namespace pocx::consensus;
using namespace pocx::algorithms;

BOOST_FIXTURE_TEST_SUITE(pocx_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(shabal256_testvectors)
{
    // Test A: zero data with 0x80 term
    static const uint8_t TEST_A_RESULT[32] = {
        0xDA, 0x8F, 0x08, 0xC0, 0x2A, 0x67, 0xBA, 0x9A, 0x56, 0xBD, 0xD0, 0x79, 0x8E, 0x48, 0xAE,
        0x07, 0x14, 0x21, 0x5E, 0x09, 0x3B, 0x5B, 0x85, 0x06, 0x49, 0xA3, 0x77, 0x18, 0x99, 0x3F,
        0x54, 0xA2
    };

    uint8_t test_data_a[64] = {0};
    uint32_t test_term_a[16] = {0};
    test_term_a[0] = 0x80;
    uint8_t hash_a[32];

    Shabal256(test_data_a, 64, nullptr, test_term_a, hash_a);
    BOOST_CHECK(std::memcmp(hash_a, TEST_A_RESULT, 32) == 0);

    // Test B: specific data with specific term
    static const uint8_t TEST_B_RESULT[32] = {
        0xB4, 0x9F, 0x34, 0xBF, 0x51, 0x86, 0x4C, 0x30, 0x53, 0x3C, 0xC4, 0x6C, 0xC2, 0x54, 0x2B,
        0xDE, 0xC2, 0xF9, 0x6F, 0xD0, 0x6F, 0x5C, 0x53, 0x9A, 0xFF, 0x6E, 0xAD, 0x58, 0x83, 0xF7,
        0x32, 0x7A
    };

    static const uint32_t TEST_B_M1[16] = {
        0x64636261, 0x68676665, 0x6C6B6A69, 0x706F6E6D, 0x74737271, 0x78777675, 0x302D7A79,
        0x34333231, 0x38373635, 0x42412D39, 0x46454443, 0x4A494847, 0x4E4D4C4B, 0x5251504F,
        0x56555453, 0x5A595857
    };

    static const uint32_t TEST_B_M2[16] = {
        0x3231302D, 0x36353433, 0x2D393837, 0x64636261, 0x68676665, 0x6C6B6A69, 0x706F6E6D,
        0x74737271, 0x78777675, 0x00807A79, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
        0x00000000, 0x00000000
    };

    uint8_t hash_b[32];
    const uint8_t* test_data_b = reinterpret_cast<const uint8_t*>(TEST_B_M1);
    
    Shabal256(test_data_b, 64, nullptr, TEST_B_M2, hash_b);
    BOOST_CHECK(std::memcmp(hash_b, TEST_B_RESULT, 32) == 0);
}

BOOST_AUTO_TEST_CASE(shabal256_lite_testvectors)
{
    static const uint64_t TEST_C_RESULT = 0x9824d76d62cd4f2f;
    static const uint64_t TEST_D_RESULT = 0x2ACEA174774F5A6A;

    // Test C: zero data with zero gensig
    uint8_t test_data_c[64] = {0};
    uint8_t gensig_c[32] = {0};
    uint64_t result_c = Shabal256Lite(test_data_c, gensig_c);
    BOOST_CHECK_EQUAL(result_c, TEST_C_RESULT);

    // Test D: zero data with specific gensig
    uint8_t test_data_d[64] = {0};
    uint8_t gensig_d[32] = {
        0x4a, 0x6f, 0x68, 0x6e, 0x6e, 0x79, 0x46, 0x46, 0x4d, 0x20, 0x68, 0x61, 0x74, 0x20, 0x64, 0x65,
        0x6e, 0x20, 0x67, 0x72, 0xf6, 0xdf, 0x74, 0x65, 0x6e, 0x20, 0x50, 0x65, 0x6e, 0x69, 0x73, 0x21
    };
    uint64_t result_d = Shabal256Lite(test_data_d, gensig_d);
    BOOST_CHECK_EQUAL(result_d, TEST_D_RESULT);
}

BOOST_AUTO_TEST_CASE(calculate_scoop_basic)
{
    // Test parameters matching Rust test_calculate_scoop
    const uint64_t block_height = 0;
    const char* gen_sig_hex = "9821beb3b34d9a3b30127c05f8d1e9006f8a02f565a3572145134bbe34d37a76";
    uint8_t generation_signature[32];
    
    // Convert hex string to bytes
    int decode_result = DecodeGenerationSignature(gen_sig_hex, generation_signature);
    BOOST_CHECK_EQUAL(decode_result, 0); // Success
    
    // Test CalculateScoop function
    int scoop = CalculateScoop(block_height, generation_signature);
    BOOST_CHECK_EQUAL(scoop, 667); // Expected result from Rust test
}

BOOST_AUTO_TEST_CASE(generate_nonces_basic)
{
    // Test parameters matching Rust test_nonce_generation_scalar
    uint8_t seed[32];
    const char* seed_hex = "AFFEAFFEAFFEAFFEAFFEAFFEAFFEAFFEAFFEAFFEAFFEAFFEAFFEAFFEAFFEAFFE";
    
    // Convert hex seed to bytes
    for (int i = 0; i < 32; i++) {
        char hex_byte[3] = {seed_hex[i * 2], seed_hex[i * 2 + 1], 0};
        seed[i] = static_cast<uint8_t>(std::strtoul(hex_byte, nullptr, 16));
    }

    uint8_t address_payload[20];
    const char* addr_hex = "99BC78BA577A95A11F1A344D4D2AE55F2F857B98";
    
    // Convert hex address to bytes
    for (int i = 0; i < 20; i++) {
        char hex_byte[3] = {addr_hex[i * 2], addr_hex[i * 2 + 1], 0};
        address_payload[i] = static_cast<uint8_t>(std::strtoul(hex_byte, nullptr, 16));
    }

    const uint64_t start_nonce = 1337;
    const uint64_t nonce_count = 32;
    const size_t buf_size = nonce_count * NONCE_SIZE;
    
    std::vector<uint8_t> buf(buf_size, 0);

    // Test the function
    int result = GenerateNonces(buf.data(), buf_size, 0, address_payload, seed, start_nonce, nonce_count);

    BOOST_CHECK_EQUAL(result, 0); // Success

    // Calculate SHA256 hash of the buffer (exactly matching Rust test)
    CSHA256 hasher;
    hasher.Write(buf.data(), buf_size);
    uint8_t hash_result[32];
    hasher.Finalize(hash_result);
    
    // Convert hash to hex string
    std::stringstream ss;
    for (int i = 0; i < 32; i++) {
        ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<unsigned>(hash_result[i]);
    }
    std::string actual_hash = ss.str();
    
    // Expected hash from Rust test
    const std::string expected_hash = "acc0b40a22cf8ce8aabe361bd4b67bdb61b7367755ae9cb9963a68acaa6d322c";
    
    // Verify exact match with Rust implementation
    BOOST_CHECK_EQUAL(actual_hash, expected_hash);
}

BOOST_AUTO_TEST_SUITE_END()