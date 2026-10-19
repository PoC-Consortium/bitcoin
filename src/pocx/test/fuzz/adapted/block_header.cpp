// Copyright (c) 2020-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <primitives/block.h>
#include <test/fuzz/FuzzedDataProvider.h>
#include <test/fuzz/fuzz.h>
#include <test/fuzz/util.h>
#include <uint256.h>

#include <cassert>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

FUZZ_TARGET(block_header)
{
    FuzzedDataProvider fuzzed_data_provider(buffer.data(), buffer.size());
    const auto block_header = [&]() -> std::optional<CBlockHeader> {
        SpanReader stream{buffer};
        CBlockHeader header;
        try { stream >> header; } catch (const std::ios_base::failure&) { return {}; }
        return header;
    }();
    if (!block_header) {
        return;
    }
    {
        const uint256 hash = block_header->GetHash();
        CBlockHeader changed = *block_header;
        changed.vchSignature.fill(0);
        assert(changed.GetHash() == hash);
        changed.vchSignature.fill(0xff);
        assert(changed.GetHash() == hash);
        DataStream encoded;
        encoded << *block_header;
        assert(encoded.size() == 286);
        assert(std::equal(encoded.begin(), encoded.end(), buffer.begin(), [](auto a, auto b) { return std::to_integer<uint8_t>(a) == b; }));
        constexpr uint256 u256_max{"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"};
        assert(hash != u256_max);
        assert(block_header->GetBlockTime() == block_header->nTime);
        assert(block_header->IsNull() == (block_header->nBaseTarget == 0));
    }
    {
        CBlockHeader mut_block_header = *block_header;
        mut_block_header.SetNull();
        assert(mut_block_header.IsNull());
        CBlock block{*block_header};
        assert(block.GetHash() == block_header->GetHash());
        (void)block.ToString();
        block.SetNull();
        assert(block.GetHash() == mut_block_header.GetHash());
    }
    {
        std::optional<CBlockLocator> block_locator = ConsumeDeserializable<CBlockLocator>(fuzzed_data_provider);
        if (block_locator) {
            (void)block_locator->IsNull();
            block_locator->SetNull();
            assert(block_locator->IsNull());
        }
    }
}
