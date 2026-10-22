// Copyright (c) 2026 The Bitcoin PoCX developers
// Distributed under the MIT software license; see COPYING.
#include <primitives/block.h>
#include <streams.h>
#include <util/strencodings.h>
#include <boost/test/unit_test.hpp>

BOOST_AUTO_TEST_SUITE(pocx_wire_tests)
BOOST_AUTO_TEST_CASE(header_fixed_vector)
{
    // Fixed bytes independently packed with Python struct, SHA256d via hashlib.
    // Also exercised by feature_pocx_wire.py; no consensus-valid proof is claimed.
    const auto raw = ParseHex("00000080000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3fffffffffffffff7f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f1032547698badcfe606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f90919293ffffffffffffffffffffffffa9cbed0f214365879495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5");
    const std::string expected{"461679027ee934ff00f10283b92fa4b9a13407eb2733ecf83c38e1727fcdb58f"};
    DataStream input{raw};
    CBlockHeader header;
    input >> header;
    BOOST_CHECK(input.empty());
    BOOST_CHECK_EQUAL(header.nVersion, INT32_MIN);
    BOOST_CHECK_EQUAL(header.nHeight, INT32_MAX);
    BOOST_CHECK_EQUAL(header.nTime, UINT32_MAX);
    BOOST_CHECK_EQUAL(header.nBaseTarget, 0xfedcba9876543210ULL);
    BOOST_CHECK_EQUAL(header.pocxProof.compression, UINT32_MAX);
    BOOST_CHECK_EQUAL(header.pocxProof.nonce, UINT64_MAX);
    BOOST_CHECK_EQUAL(header.pocxProof.quality, 0x876543210fedcba9ULL);
    DataStream output;
    output << header;
    BOOST_CHECK_EQUAL(HexStr(output), HexStr(raw));
    BOOST_CHECK_EQUAL(header.GetHash().GetHex(), expected);
    for (size_t offset{0}; offset < raw.size(); ++offset) {
        auto changed = raw;
        changed[offset] ^= 1;
        DataStream stream{changed};
        CBlockHeader mutation;
        stream >> mutation;
        BOOST_CHECK_EQUAL(mutation.GetHash().GetHex() == expected, offset >= 221);
    }
    for (size_t size{0}; size < raw.size(); ++size) {
        auto truncated = raw;
        truncated.resize(size);
        DataStream stream{truncated};
        CBlockHeader decoded;
        BOOST_CHECK_THROW(stream >> decoded, std::ios_base::failure);
    }
}
BOOST_AUTO_TEST_SUITE_END()
