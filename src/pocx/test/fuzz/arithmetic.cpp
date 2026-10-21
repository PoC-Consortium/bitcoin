// Copyright (c) 2026 The Bitcoin PoCX developers
// Distributed under the MIT software license; see COPYING.
#include <pocx/algorithms/time_bending.h>
#include <pocx/consensus/params.h>
#include <test/fuzz/FuzzedDataProvider.h>
#include <test/fuzz/fuzz.h>
#include <array>
#include <cassert>
#include <cstdint>

namespace {
// Independent 256-bit unsigned arithmetic. Base-2^32 limbs keep every
// intermediate in uint64_t range, including under the integer sanitizer.
class Wide {
    std::array<uint32_t, 8> m{};

public:
    Wide() = default;
    Wide(uint64_t value) { m[0] = value; m[1] = value >> 32; }

    uint64_t Low64() const { return uint64_t{m[0]} | (uint64_t{m[1]} << 32); }

    int Compare(const Wide& other) const
    {
        for (int i = 7; i >= 0; --i) {
            if (m[i] != other.m[i]) return m[i] < other.m[i] ? -1 : 1;
        }
        return 0;
    }

    Wide Add(const Wide& other) const
    {
        Wide result;
        uint64_t carry{0};
        for (int i = 0; i < 8; ++i) {
            const uint64_t sum = uint64_t{m[i]} + other.m[i] + carry;
            result.m[i] = sum;
            carry = sum >> 32;
        }
        assert(!carry);
        return result;
    }

    Wide ShiftLeft(unsigned bits) const
    {
        assert(bits < 256);
        Wide result;
        const unsigned words = bits / 32, shift = bits % 32;
        for (unsigned i = words; i < 8; ++i) {
            uint64_t part = uint64_t{m[i - words]} << shift;
            if (shift && i > words) part |= uint64_t{m[i - words - 1]} >> (32 - shift);
            result.m[i] = part;
        }
        return result;
    }

    Wide ShiftRight(unsigned bits) const
    {
        assert(bits < 256);
        Wide result;
        const unsigned words = bits / 32, shift = bits % 32;
        for (unsigned i = 0; i + words < 8; ++i) {
            uint64_t part = m[i + words] >> shift;
            if (shift && i + words + 1 < 8) part |= uint64_t{m[i + words + 1]} << (32 - shift);
            result.m[i] = part;
        }
        return result;
    }

    Wide Mul32(uint32_t factor) const
    {
        Wide result;
        uint64_t carry{0};
        for (int i = 0; i < 8; ++i) {
            const uint64_t product = uint64_t{m[i]} * factor + carry;
            result.m[i] = product;
            carry = product >> 32;
        }
        assert(!carry);
        return result;
    }

    Wide Mul(uint64_t factor) const
    {
        return Mul32(factor).Add(Mul32(factor >> 32).ShiftLeft(32));
    }

    Wide Div(uint64_t divisor) const
    {
        assert(divisor);
        const Wide limit{divisor};
        Wide remainder, quotient;
        for (int bit = 255; bit >= 0; --bit) {
            remainder = remainder.ShiftLeft(1);
            remainder.m[0] |= (m[bit / 32] >> (bit % 32)) & 1;
            if (remainder.Compare(limit) >= 0) {
                uint64_t borrow{0};
                for (int i = 0; i < 8; ++i) {
                    const uint64_t sub = uint64_t{limit.m[i]} + borrow;
                    const uint64_t value = remainder.m[i];
                    remainder.m[i] = value < sub ? value + (uint64_t{1} << 32) - sub : value - sub;
                    borrow = value < sub;
                }
                assert(!borrow);
                quotient.m[bit / 32] |= uint32_t{1} << (bit % 32);
            }
        }
        return quotient;
    }
};

uint64_t CubeRoot(const Wide& value)
{
    // spacing <= 86400 makes the largest input < 2^143, so its root < 2^48.
    uint64_t low{0}, high{uint64_t{1} << 49};
    while (high - low > 1) {
        const uint64_t middle = (high + low) / 2;
        if (Wide{middle}.Mul(middle).Mul(middle).Compare(value) <= 0) low = middle;
        else high = middle;
    }
    return low;
}
// Independent wide-integer evaluation of the specified fixed-point formula;
// no production arith_uint256 operations or root/scale helpers are reused.
uint64_t Deadline(uint64_t quality, uint64_t target, uint64_t spacing)
{
    if (!quality) return 0;
    const uint64_t divisor = Wide{CubeRoot(Wide{spacing}.ShiftLeft(126))}.Mul(3927365422841ULL).ShiftRight(42).Low64();
    const uint64_t scale = Wide{spacing}.ShiftLeft(84).Add(Wide{divisor / 2}).Div(divisor).Low64();
    const uint64_t root = CubeRoot(Wide{quality}.ShiftLeft(63).Div(target));
    return Wide{scale}.Mul(root).Add(Wide{uint64_t{1} << 62}).ShiftRight(63).Low64();
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
