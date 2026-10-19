// Copyright (c) 2026 The Bitcoin PoCX developers
// Distributed under the MIT software license; see COPYING.
#include <pocx/assignments/opcodes.h>
#include <test/fuzz/fuzz.h>
#include <algorithm>
#include <cassert>
#include <optional>

namespace {
// Independent byte-level OP_RETURN data-push decoder, including nonminimal pushes.
std::optional<std::vector<unsigned char>> Payload(std::span<const uint8_t> bytes)
{
    if (bytes.size() < 2 || bytes[0] != 0x6a) return {};
    size_t start{2};
    uint64_t length{bytes[1]};
    if (length >= 0x4c && length <= 0x4e) {
        const size_t count = size_t{1} << (length - 0x4c);
        if (bytes.size() < 2 + count) return {};
        length = 0;
        for (size_t i{0}; i < count; ++i) length |= uint64_t{bytes[2 + i]} << (8 * i);
        start += count;
    } else if (length > 0x4b) {
        return {};
    }
    if (length != bytes.size() - start) return {};
    return std::vector<unsigned char>{bytes.begin() + start, bytes.end()};
}
}

FUZZ_TARGET(pocx_assignment_opcodes)
{
    using namespace pocx::assignments;
    if (buffer.size() > 512) return; // OP_RETURN fields are small; bound allocations.
    CTxOut output{0, CScript{buffer.begin(), buffer.end()}};
    const auto payload = Payload(buffer);
    const std::vector<unsigned char> assign_marker{0x50, 0x4f, 0x43, 0x58};
    const std::vector<unsigned char> revoke_marker{0x58, 0x43, 0x4f, 0x50};
    const bool assignment = payload && payload->size() == 44 && std::equal(assign_marker.begin(), assign_marker.end(), payload->begin());
    const bool revocation = payload && payload->size() == 24 && std::equal(revoke_marker.begin(), revoke_marker.end(), payload->begin());
    assert(IsAssignmentOpReturn(output) == assignment);
    assert(IsRevocationOpReturn(output) == revocation);
    const auto parsed_assignment = ParseAssignmentOpReturn(output);
    const auto parsed_revocation = ParseRevocationOpReturn(output);
    assert(parsed_assignment.has_value() == assignment);
    assert(parsed_revocation.has_value() == revocation);
    if (assignment) {
        assert(std::equal(parsed_assignment->first.begin(), parsed_assignment->first.end(), payload->begin() + 4));
        assert(std::equal(parsed_assignment->second.begin(), parsed_assignment->second.end(), payload->begin() + 24));
    }
    if (revocation) assert(std::equal(parsed_revocation->begin(), parsed_revocation->end(), payload->begin() + 4));
    std::array<uint8_t, 20> plot{}, signer{};
    for (size_t i{0}; i < std::min(buffer.size(), size_t{40}); ++i) {
        (i < 20 ? plot[i] : signer[i - 20]) = buffer[i];
    }
    const auto a = ParseAssignmentOpReturn(CTxOut{0, CreateAssignmentOpReturn(plot, signer)});
    assert(a && a->first == plot && a->second == signer);
    const auto r = ParseRevocationOpReturn(CTxOut{0, CreateRevocationOpReturn(plot)});
    assert(r && *r == plot);
}
