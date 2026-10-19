// Copyright (c) 2026 The Bitcoin PoCX developers
// Distributed under the MIT software license; see COPYING.
#include <coins.h>
#include <pocx/assignments/assignment_state.h>
#include <streams.h>
#include <test/fuzz/fuzz.h>
#include <test/util/setup_common.h>
#include <txdb.h>
#include <algorithm>
#include <array>
#include <cassert>
#include <optional>

namespace {
using Model = std::array<std::optional<ForgingAssignment>, 4>;
using Address = std::array<uint8_t, 20>;
void Initialize()
{
    static const auto setup = MakeNoLogFileContext<>();
}
std::vector<std::byte> Encoded(const ForgingAssignment& row)
{
    DataStream stream;
    stream << row;
    return {stream.begin(), stream.end()};
}
void Check(CCoinsViewCache& view, const Model& model, int query)
{
    for (uint8_t plot_id : {0, 1}) {
        Address plot{};
        plot[0] = plot_id;
        std::vector<ForgingAssignment> expected;
        std::optional<ForgingAssignment> best;
        for (const auto& row : model) {
            if (!row || row->plotAddress != plot) continue;
            expected.push_back(*row);
            if (row->assignment_height <= query && (!best || row->assignment_height > best->assignment_height)) best = row;
        }
        auto actual = view.GetForgingAssignmentHistory(plot);
        auto sort = [](auto& rows) { std::sort(rows.begin(), rows.end(), [](const auto& a, const auto& b) { return a.assignment_txid < b.assignment_txid; }); };
        sort(actual);
        sort(expected);
        assert(actual.size() == expected.size());
        for (size_t i{0}; i < actual.size(); ++i) assert(Encoded(actual[i]) == Encoded(expected[i]));
        const auto selected = view.GetForgingAssignment(plot, query);
        assert(selected.has_value() == best.has_value());
        if (best) assert(Encoded(*selected) == Encoded(*best));
        ForgingState state{ForgingState::UNASSIGNED};
        if (best) {
            state = ForgingState::ASSIGNING;
            if (query >= best->assignment_effective_height) {
                state = ForgingState::ASSIGNED;
                if (best->revoked && query >= best->revocation_height) {
                    state = query < best->revocation_effective_height ? ForgingState::REVOKING : ForgingState::REVOKED;
                }
            }
        }
        assert(pocx::assignments::GetAssignmentState(query, selected) == state);
        const auto signer = state == ForgingState::ASSIGNED || state == ForgingState::REVOKING ? best->forgingAddress : plot;
        assert(pocx::assignments::GetEffectiveSigner(plot, query, selected) == signer);
    }
}
}

FUZZ_TARGET(pocx_assignment_state, .init = Initialize)
{
    // Real LevelDB memory environment, two cache layers, separate logical model.
    // New database/model each input; at most 64 operations and four live rows.
    CCoinsViewDB database{{.path = "", .cache_bytes = 1 << 20, .memory_only = true}, {}};
    CCoinsViewCache parent{&database, true};
    CCoinsViewCache child{&parent, true};
    parent.SetBestBlock(uint256::ONE);
    child.SetBestBlock(uint256::ONE);
    Model model{}, removed{};
    const size_t operations = std::min(buffer.size() / 4, size_t{64});
    for (size_t step{0}; step < operations; ++step) {
        const uint8_t operation = buffer[step * 4] % 8;
        const size_t slot = buffer[step * 4 + 1] % model.size();
        const int query = buffer[step * 4 + 2];
        const uint8_t value = buffer[step * 4 + 3];
        auto& row = model[slot];
        switch (operation) {
        case 0:
            if (!row) {
                ForgingAssignment fresh;
                fresh.plotAddress[0] = slot % 2;
                fresh.forgingAddress[0] = value;
                fresh.assignment_txid.begin()[0] = slot + 1;
                fresh.assignment_height = 1 + 4 * step;
                fresh.assignment_effective_height = fresh.assignment_height + 4;
                child.AddForgingAssignment(fresh);
                row = fresh;
            }
            break;
        case 1:
            if (row) {
                row->revoked = true;
                row->revocation_height = row->assignment_effective_height + value % 8;
                row->revocation_effective_height = row->revocation_height + 8;
                row->revocation_txid.begin()[0] = 100 + slot;
                child.UpdateForgingAssignment(*row);
            }
            break;
        case 2:
            if (row) {
                removed[slot] = row;
                child.RemoveForgingAssignment(row->plotAddress, row->assignment_txid);
                row.reset();
            }
            break;
        case 3:
            if (row) {
                row->revoked = false;
                row->revocation_height = row->revocation_effective_height = -1;
                row->revocation_txid.SetNull();
                child.RestoreForgingAssignment(*row);
            } else if (removed[slot]) {
                row = removed[slot];
                child.RestoreForgingAssignment(*row);
            }
            break;
        case 4:
            if (row) {
                child.RemoveForgingAssignment(row->plotAddress, row->assignment_txid);
                row->assignment_height = 1 + 4 * step;
                row->assignment_effective_height = row->assignment_height + 4;
                row->revoked = false;
                row->revocation_height = row->revocation_effective_height = -1;
                row->revocation_txid.SetNull();
                child.AddForgingAssignment(*row);
            }
            break;
        case 5:
            child.Flush();
            Check(parent, model, query);
            break;
        case 6:
            child.Sync();
            Check(parent, model, query);
            break;
        case 7:
            child.Flush();
            parent.Flush();
            {
                CCoinsViewCache cold{&database, true};
                Check(cold, model, query);
            }
            break;
        }
        Check(child, model, query);
        for (const auto& entry : model) {
            if (!entry) continue;
            // Explicit creation/activation/revocation boundaries after every op.
            for (int height : {entry->assignment_height - 1, entry->assignment_height,
                               entry->assignment_effective_height - 1, entry->assignment_effective_height,
                               entry->revocation_height, entry->revocation_effective_height}) {
                if (height >= 0) Check(child, model, height);
            }
        }
    }
    child.Flush();
    parent.Flush();
    CCoinsViewCache cold{&database, true};
    Check(cold, model, 1000);
}
