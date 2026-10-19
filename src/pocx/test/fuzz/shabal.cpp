// Copyright (c) 2026 The Bitcoin PoCX developers
// Distributed under the MIT software license; see COPYING.

#include <pocx/crypto/shabal256.h>
#include <pocx/crypto/shabal256_avx2.h>
#include <pocx/crypto/shabal256_sse2.h>
#include <crypto/sha256.h>
#include <test/fuzz/FuzzedDataProvider.h>
#include <test/fuzz/fuzz.h>
#include <util/check.h>

#include <array>
#include <cassert>
#include <cstdio>
#include <cstdlib>

namespace {
void KnownAnswer()
{
    // Independent fixed vector shared with the reviewed native crypto tests.
    const std::array<uint8_t, 32> expected{
        0xda, 0x8f, 0x08, 0xc0, 0x2a, 0x67, 0xba, 0x9a,
        0x56, 0xbd, 0xd0, 0x79, 0x8e, 0x48, 0xae, 0x07,
        0x14, 0x21, 0x5e, 0x09, 0x3b, 0x5b, 0x85, 0x06,
        0x49, 0xa3, 0x77, 0x18, 0x99, 0x3f, 0x54, 0xa2};
    std::array<uint8_t, 64> data{};
    std::array<uint32_t, 16> term{};
    term[0] = 0x80;
    std::array<uint8_t, 32> output{};
    pocx::crypto::Shabal256(data.data(), data.size(), nullptr, term.data(), output.data());
    assert(output == expected);
}

template <size_t LANES, typename Function>
void Compare(FuzzBufferType buffer, Function function)
{
    FuzzedDataProvider provider{buffer.data(), buffer.size()};
    const auto length = 64 * provider.ConsumeIntegralInRange<size_t>(0, 4);
    std::array<std::array<uint8_t, 256>, LANES> data{};
    std::array<std::array<uint32_t, 16>, LANES> pre{}, term{};
    std::array<std::array<uint8_t, 32>, LANES> scalar{}, parallel{};
    const uint8_t* inputs[LANES];
    const uint32_t* prefixes[LANES];
    const uint32_t* endings[LANES];
    uint8_t* outputs[LANES];
    // The SIMD interface processes one common pre-termination stage for all
    // lanes. Callers supply that stage for every lane or for none of them.
    const bool use_preterm = provider.ConsumeBool();
    for (size_t lane = 0; lane < LANES; ++lane) {
        for (auto& byte : data[lane]) byte = provider.ConsumeIntegral<uint8_t>();
        for (auto& word : pre[lane]) word = provider.ConsumeIntegral<uint32_t>();
        for (auto& word : term[lane]) word = provider.ConsumeIntegral<uint32_t>();
        inputs[lane] = data[lane].data();
        prefixes[lane] = use_preterm ? pre[lane].data() : nullptr;
        endings[lane] = term[lane].data();
        outputs[lane] = parallel[lane].data();
        pocx::crypto::Shabal256(inputs[lane], length, prefixes[lane], endings[lane], scalar[lane].data());
    }
    function(inputs, length, prefixes, endings, outputs);
    assert(scalar == parallel);
}
} // namespace

FUZZ_TARGET(pocx_shabal, .init = KnownAnswer)
{
    // Scalar determinism and independent lane isolation on all architectures.
    Compare<2>(buffer, [](const uint8_t** data, size_t length, const uint32_t** pre,
                          const uint32_t** term, uint8_t** output) {
        for (size_t lane = 0; lane < 2; ++lane) {
            pocx::crypto::Shabal256(data[lane], length, pre[lane], term[lane], output[lane]);
        }
    });
}

#ifdef ENABLE_SSE2
FUZZ_TARGET(pocx_shabal_sse2, .init = [] { Assert(pocx::crypto::HaveSSE2()); })
{
    Compare<4>(buffer, pocx::crypto::Shabal256_sse2);
}
#endif

#ifdef ENABLE_AVX2
FUZZ_TARGET(pocx_shabal_avx2, .init = [] {
    SHA256AutoDetect();
    if (!pocx::crypto::HaveAVX2()) {
        std::fputs("POCX_FUZZ_INACTIVE: AVX2 runtime unavailable\n", stderr);
        std::exit(77);
    }
})
{
    Compare<8>(buffer, pocx::crypto::Shabal256_avx2);
}
#endif
