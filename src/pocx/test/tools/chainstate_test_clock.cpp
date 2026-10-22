// Copyright (c) 2026 The Bitcoin PoCX developers
// Distributed under the MIT software license; see COPYING.

#include <util/time.h>

#include <charconv>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <string_view>

namespace {
struct FixtureClock {
    FixtureClock()
    {
        const char* supplied{std::getenv("POCX_CHAINSTATE_TEST_TIME")};
        int64_t seconds{0};
        const std::string_view value{supplied ? supplied : ""};
        const auto [end, error]{std::from_chars(value.data(), value.data() + value.size(), seconds)};
        if (error != std::errc{} || end != value.data() + value.size() || seconds <= 0) {
            std::fputs("POCX_CHAINSTATE_TEST_TIME must contain a positive integer timestamp\n", stderr);
            std::_Exit(2);
        }
        SetMockTime(std::chrono::seconds{seconds});
    }
};
const FixtureClock fixture_clock;
} // namespace

// The unchanged original main is a separate source of this test executable.
// This translation unit initializes its fixture clock before main executes.
