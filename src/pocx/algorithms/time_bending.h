// Copyright (c) 2025 The Proof of Capacity Consortium
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_POCX_ALGORITHMS_TIME_BENDING_H
#define BITCOIN_POCX_ALGORITHMS_TIME_BENDING_H

#include <cstdint>

namespace pocx {
namespace algorithms {

/**
 * Time Bending
 * Exponential-to-Chi-squared block time transformation
 * Formula: Y = scale * (X^(1/3)) where X = quality/base_target
 * Scale = block_time / (block_time^(1/3) * Gamma(4/3))
 * where Gamma(4/3) ≈ 0.892979511
 */
uint64_t CalculateTimeBendedDeadline(uint64_t quality, uint64_t base_target, uint64_t block_time);

} // namespace algorithms
} // namespace pocx

#endif // BITCOIN_POCX_ALGORITHMS_TIME_BENDING_H