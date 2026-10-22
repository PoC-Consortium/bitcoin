// Copyright (c) 2026 The Bitcoin PoCX developers
// Distributed under the MIT software license; see COPYING.
#include <pocx/algorithms/encoding.h>
#include <pocx/consensus/batch_validation.h>
#include <pocx/consensus/proof.h>
#include <test/fuzz/fuzz.h>
#include <util/strencodings.h>
#include <algorithm>
#include <array>
#include <cassert>
#include <cstring>
#include <limits>
#include <span>
#include <string>

namespace {
// Stable little-endian seed format; missing bytes are zero so truncations still
// exercise API argument checks. Full proof work is bounded to four plot nonces.
struct Reader {
    std::span<const uint8_t> remaining;
    uint8_t Byte() {
        if (remaining.empty()) return 0;
        const auto value = remaining.front();
        remaining = remaining.subspan(1);
        return value;
    }
    template <typename T> T Integer() {
        T value{0};
        for (size_t i = 0; i < sizeof(T); ++i) value |= T{Byte()} << (8 * i);
        return value;
    }
    template <size_t N> std::array<uint8_t, N> Bytes() {
        std::array<uint8_t, N> value;
        for (auto& byte : value) byte = Byte();
        return value;
    }
};
}

FUZZ_TARGET(pocx_proof_parameters)
{
    using namespace pocx::consensus;
    Reader reader{buffer.first(std::min(buffer.size(), size_t{512}))};
    const auto selector = reader.Byte();
    const auto mode = selector % 4;
    const auto raw_compression = reader.Integer<uint32_t>();
    // Half the inputs exercise full scalar/batch work. Keep the other half's
    // unrestricted uint32 domain to cover allocation-bound rejection.
    const auto compression = (selector & 4) ? raw_compression : 1 + raw_compression % 2;
    const auto target = reader.Integer<uint64_t>();
    const auto height = reader.Integer<uint64_t>();
    const auto nonce = reader.Integer<uint64_t>();
    const auto claimed = reader.Integer<uint64_t>();
    const auto gensig = reader.Bytes<32>();
    const auto account = reader.Bytes<20>();
    const auto seed = reader.Bytes<32>();
    BlockValidationInput input{gensig.data(), target, account.data(), height,
                              nonce, seed.data(), compression, claimed};
    ValidationResult batch;
    if (compression < 1 || compression > 7) {
        assert(pocx_validate_blocks(&input, 1, &batch) == VALIDATION_ERROR_COMPRESSION_OUT_OF_RANGE);
        assert(!batch.is_valid);
        assert(batch.error_code == VALIDATION_ERROR_COMPRESSION_OUT_OF_RANGE);
        return;
    }
    // Compressions 3..7 are expensive and covered by fixed native vectors.
    // Fuzz full uint32 rejection above, but bound valid crypto work to 1..2.
    if (compression > 2) return;
    const auto hex = HexStr(gensig);
    ValidationResult scalar;
    if (mode == 0) {
        const std::string candidate(reader.remaining.begin(), reader.remaining.end());
        std::array<uint8_t, 32> decoded;
        const auto size = std::strlen(candidate.c_str());
        bool valid = size == 64;
        for (size_t i = 0; i < size; ++i) {
            const char c = candidate[i];
            valid &= (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
        }
        const auto code = pocx::algorithms::DecodeGenerationSignature(candidate.c_str(), decoded.data());
        assert((code == 0) == valid);
        if (valid) assert(HexStr(decoded) == HexStr(ParseHex(candidate.substr(0, 64))));
        assert(pocx::algorithms::DecodeGenerationSignature(nullptr, decoded.data()) == -1);
        assert(pocx::algorithms::DecodeGenerationSignature(hex.c_str(), nullptr) == -1);
        return;
    }
    if (mode == 1) {
        assert(!pocx_validate_block(nullptr, target, account.data(), height, nonce, seed.data(), compression, &scalar));
        assert(!pocx_validate_block(hex.c_str(), target, nullptr, height, nonce, seed.data(), compression, &scalar));
        assert(!pocx_validate_block(hex.c_str(), target, account.data(), height, nonce, nullptr, compression, &scalar));
        assert(!pocx_validate_block(hex.c_str(), target, account.data(), height, nonce, seed.data(), compression, nullptr));
        assert(pocx_validate_blocks(nullptr, 1, &batch) == -1);
        assert(pocx_validate_blocks(&input, 1, nullptr) == -1);
        assert(pocx_validate_blocks(&input, 0, &batch) == -1);
        return;
    }
    assert(pocx_validate_block(hex.c_str(), target, account.data(), height, nonce, seed.data(), compression, &scalar));
    assert(scalar.is_valid && scalar.error_code == VALIDATION_SUCCESS);
    assert(scalar.deadline == (target ? scalar.quality / target : std::numeric_limits<uint64_t>::max()));
    // Exercise both an exact scalar-quality match and a guaranteed mismatch.
    // Compare the batch path with full scalar validation.
    input.claimed_quality = mode == 3 ? scalar.quality ^ 1 : scalar.quality;
    const bool matches = input.claimed_quality == scalar.quality;
    assert(pocx_validate_blocks(&input, 1, &batch) == (matches ? 0 : -2));
    assert(batch.is_valid == matches);
    assert(batch.error_code == (matches ? VALIDATION_SUCCESS : VALIDATION_ERROR_QUALITY_MISMATCH));
    assert(batch.quality == scalar.quality);
    assert(batch.deadline == scalar.deadline);
    // A two-proof batch reaches the optimized dispatch. Different nonce/seed
    // inputs prevent a warm scalar result from standing in for both lanes.
    auto other_seed = seed;
    other_seed[0] ^= 1;
    ValidationResult other_scalar;
    assert(pocx_validate_block(hex.c_str(), target, account.data(), height,
                              nonce ^ 1, other_seed.data(), compression, &other_scalar));
    BlockValidationInput pair[2]{input, input};
    pair[0].claimed_quality = scalar.quality;
    pair[1].nonce = nonce ^ 1;
    pair[1].seed = other_seed.data();
    pair[1].claimed_quality = other_scalar.quality;
    ValidationResult parallel[2];
    const int code = pocx_validate_blocks(pair, 2, parallel);
    assert(code == 0);
    assert(parallel[0].is_valid);
    assert(parallel[1].is_valid);
    assert(parallel[0].quality == scalar.quality);
    assert(parallel[1].quality == other_scalar.quality);
    assert(parallel[1].deadline == other_scalar.deadline);
}
