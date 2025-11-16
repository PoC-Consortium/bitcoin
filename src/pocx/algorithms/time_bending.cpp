// Copyright (c) 2025 The Proof of Capacity Consortium
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <pocx/algorithms/time_bending.h>
#include <arith_uint256.h>
#include <cstdint>

namespace pocx {
namespace algorithms {

static arith_uint256 int_cuberoot_u256(const arith_uint256& x) {
    arith_uint256 lo = 0;
    arith_uint256 hi = 1;

    while ((hi * hi * hi) < x) hi <<= 1;
    lo = hi >> 1;

    while (lo < hi) {
        arith_uint256 mid = (lo + hi + 1) >> 1;
        arith_uint256 mid3 = mid * mid * mid;
        if (mid3 <= x) {
            lo = mid;
        } else {
            hi = mid - 1;
        }
    }
    return lo;
}

// Compute SCALE_Q as integer-only function of block_time
static arith_uint256 calculate_qscale_uint(uint64_t block_time) {
    // Fixed-point fractional bits
    const int Q = 42;

    // Precomputed Gamma(4/3) in Q42 fixed point
    // Gamma(4/3) ≈ 0.892979511
    // 0.892979511 * 2^42 ≈ 3927365422840.906 ≈ 3927365422841
    const arith_uint256 GAMMA_FP(3927365422841ULL); // Gamma(4/3) * 2^42

    // Compute cube root of block_time in Q42 fixed point
    arith_uint256 t = arith_uint256(block_time);

    // Compute integer cube root in 256-bit arithmetic
    // t_cbrt = floor(block_time^(1/3) * 2^Q)
    arith_uint256 block_scaled = t << (3*Q);
    arith_uint256 t_cbrt = int_cuberoot_u256(block_scaled);

    // Formula: SCALE_Q = (block_time * 2^Q) / (cbrt * gamma / 2^Q)
    // This is: (block_time * 2^Q * 2^Q) / (cbrt * gamma)
    // numerator = block_time * 2^(2*Q)
    arith_uint256 numerator = t << (2*Q);

    // denominator = t_cbrt * GAMMA_FP >> Q
    arith_uint256 denominator = (t_cbrt * GAMMA_FP) >> Q;

    // SCALE_Q = round-half-up
    arith_uint256 scale_q = (numerator + (denominator >> 1)) / denominator;

    return scale_q;
}

uint64_t CalculateTimeBendedDeadline(uint64_t quality, uint64_t base_target, uint64_t block_time) {
    const int P = 21;
    const int Q = 42;

    if (quality == 0) return 0;

    // Calculate dynamic scale factor based on block_time
    arith_uint256 SCALE_Q = calculate_qscale_uint(block_time);

    arith_uint256 SHIFT_3P = arith_uint256(1) << (3 * P);
    arith_uint256 V = (arith_uint256(quality) * SHIFT_3P) / base_target;

    arith_uint256 r = int_cuberoot_u256(V);

    arith_uint256 numer = SCALE_Q * r;
    arith_uint256 denom = arith_uint256(1) << (P + Q);
    arith_uint256 rounded = (numer + (denom >> 1)) / denom;

    return rounded.GetLow64();
}

} // namespace algorithms
} // namespace pocx