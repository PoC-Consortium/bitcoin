// Copyright (c) 2026 The Bitcoin PoCX developers
// Distributed under the MIT software license; see COPYING.
#ifndef BITCOIN_POCX_TEST_UTIL_SETUP_POCX_H
#define BITCOIN_POCX_TEST_UTIL_SETUP_POCX_H
#include <test/util/setup_common.h>

// Preserve the existing PoCX-specific suites' explicit regtest fixture.
struct PoCXTestingSetup : BasicTestingSetup {
    PoCXTestingSetup() : BasicTestingSetup{ChainType::REGTEST, {.extra_args = {"-regtest"}}} {}
};
#endif
