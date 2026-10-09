// Copyright (c) 2026 The Bitcoin PoCX developers
// Distributed under the MIT software license; see COPYING.
#ifndef BITCOIN_POCX_TEST_UTIL_BITCOIN_BLOCK_FIXTURE_H
#define BITCOIN_POCX_TEST_UTIL_BITCOIN_BLOCK_FIXTURE_H
#include <primitives/block.h>
#include <streams.h>

// Preserve historical Bitcoin transactions and merkle roots in tests of filters
// and merkle trees. This is not a consensus-valid PoCX block or a wire decoder.
// It explicitly consumes Bitcoin's header layout, discards PoW-only fields, and
// gives the in-memory PoCX header a nonzero base target.
inline void ReadBitcoinBlockFixture(DataStream& stream, CBlock& block)
{
    block.SetNull();
    uint32_t bits, nonce;
    stream >> block.nVersion >> block.hashPrevBlock >> block.hashMerkleRoot >> block.nTime >> bits >> nonce;
    block.nBaseTarget = 1;
    stream >> TX_WITH_WITNESS(block.vtx);
}
#endif
