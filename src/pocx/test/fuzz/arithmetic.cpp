// Copyright (c) 2026 The Bitcoin PoCX developers
// Distributed under the MIT software license; see COPYING.
#include <pocx/algorithms/time_bending.h>
#include <pocx/consensus/params.h>
#include <test/fuzz/FuzzedDataProvider.h>
#include <test/fuzz/fuzz.h>
#include <boost/multiprecision/cpp_int.hpp>
#include <cassert>

namespace {
using boost::multiprecision::cpp_int;
cpp_int CubeRoot(const cpp_int& value)
{
    cpp_int low{0}, high{cpp_int{1} << 86};
    while (high - low > 1) {
        cpp_int middle = (high + low) / 2;
        if (middle * middle * middle <= value) low = middle;
        else high = middle;
    }
    return low;
}
// Independent arbitrary-precision evaluation of the specified fixed-point formula;
// no production arith_uint256 operations or root/scale helpers are reused.
uint64_t Deadline(uint64_t quality, uint64_t target, uint64_t spacing)
{
    if (!quality) return 0;
    const cpp_int divisor = (CubeRoot(cpp_int{spacing} << 126) * 3927365422841ULL) >> 42;
    const cpp_int scale = ((cpp_int{spacing} << 84) + divisor / 2) / divisor;
    const cpp_int root = CubeRoot((cpp_int{quality} << 63) / target);
    return ((scale * root + (cpp_int{1} << 62)) >> 63).convert_to<uint64_t>();
}
}

FUZZ_TARGET(pocx_time_bending)
{
    FuzzedDataProvider provider{buffer.data(), buffer.size()};
    const auto quality = provider.ConsumeIntegral<uint64_t>();
    // Consensus callers require positive target/spacing. Bound spacing to a day;
    // quality and target retain their full uint64 domains, including extrema.
    const auto target = provider.ConsumeIntegralInRange<uint64_t>(1, UINT64_MAX);
    const auto spacing = provider.ConsumeIntegralInRange<uint64_t>(1, 86400);
    const auto actual = pocx::algorithms::CalculateTimeBendedDeadline(quality, target, spacing);
    assert(actual == Deadline(quality, target, spacing));
    if (quality < UINT64_MAX) assert(actual <= pocx::algorithms::CalculateTimeBendedDeadline(quality + 1, target, spacing));
    if (target < UINT64_MAX) assert(actual >= pocx::algorithms::CalculateTimeBendedDeadline(quality, target + 1, spacing));
}

FUZZ_TARGET(pocx_compression_bounds)
{
    FuzzedDataProvider provider{buffer.data(), buffer.size()};
    const int64_t interval = provider.ConsumeIntegralInRange<int64_t>(1, 1000000);
    const int64_t height = provider.ConsumeIntegralInRange<int64_t>(0, 1000000000);
    const auto bounds = pocx::consensus::GetPoCXCompressionBounds(height, interval);
    uint32_t expected{1};
    for (const int64_t multiple : {1, 3, 7, 15, 31}) if (height >= multiple * interval) ++expected;
    assert(bounds.nPoCXMinCompression == expected);
    assert(bounds.nPoCXTargetCompression == expected + 1);
    for (const int64_t multiple : {1, 3, 7, 15, 31}) {
        const auto before = pocx::consensus::GetPoCXCompressionBounds(multiple * interval - 1, interval);
        const auto at = pocx::consensus::GetPoCXCompressionBounds(multiple * interval, interval);
        assert(at.nPoCXMinCompression == before.nPoCXMinCompression + 1);
    }
}
