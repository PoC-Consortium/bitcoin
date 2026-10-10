# Functional parity with Bitcoin Core v31.1

All applicable functional cases pass in a fresh complete matrix under both global
transport modes. The declared build/environment profile has 17 explicit optional
feature skips, matching the unchanged Bitcoin baseline. Those combinations remain
unverified and are never counted as passes. One Bitcoin PoW-only case is excluded.

The pinned upstream revision is
`9be056a8a72b624dae9623b2f7bded92c2a21c91`. All 378 original functional-tree files
remain byte-identical to upstream, including the original runner and framework.
All eight recorded Bitcoin executables remain unchanged. Adaptations live in
separate PoCX-owned files; unchanged applicable tests are referenced directly.

## Counts and evidence

The original runner declares 287 entries: 284 base and 3 extended, representing 264
scripts with argument/transport variants. PoCX selects 150 adapted original scripts,
113 unchanged original scripts and 24 native scripts. Normalizing only explicit
transport variants gives 295 selected cases, each executed in both global modes.

| Original runner category | Current outcome | Entries |
| --- | --- | ---: |
| adapted | passed | 167 |
| excluded as PoW-only | excluded as inapplicable | 1 |
| reused | passed | 102 |
| reused | skipped | 17 |

The complete matrix executes 590 cases: 278 passed, zero failed and 17 explicitly
skipped **per transport**. All 24 PoCX-only cases pass in both modes. Original-entry
accounting is 269 passed, zero failed, 17 skipped and 1 excluded; the unchanged Bitcoin
baseline is 270 passed, zero failed and 17 skipped. All other applicable cases have passing evidence.

Current case-level status, source comparisons, exact commands and logs are in
`functional-status.json`, `upstream-functional-parity.json` and the sortable
`functional-cases.csv`. Final verification is
`artifacts/functional-green-20261009/verification-final.json`;
its complete execution report is `build-pocx-clean/pocx-results-fgwf4s35/results.json`.
A fresh standalone export of the staged package was independently configured,
built and verified with the same 278 passes and 17 skips per transport, 78 passing
infrastructure checks, and 727 original plus 33 native passing unit cases. Its
source audit, raw reports and logs are in
`artifacts/functional-checkpoint-20261009/summary.json`.
The Bitcoin baseline is
`artifacts/functional-bitcoin-fresh-20261009/verification.json`.

The 17 profile/environment skips comprise two unbuilt tools, five USDT cases,
five cases needing older-release binaries, three cases needing Python ZMQ/capnp
modules and two cases needing specific routable host addresses. Exact reasons
are retained for each case. They are separate from the reviewed PoW exclusion:
`mining_mainnet.py` consists entirely of Bitcoin nonce/nBits retarget vectors.
Mixed mining, block validation, Signet and P2P cases remain selected.

The later Ubuntu24/GCC13 standard CI checkpoint is separately scoped under
`artifacts/ci-parity-20261010/ubuntu-functional-{bitcoin,pocx}-checkpoint/`.
Original base execution has 269 passes and 15 reviewed optional skips. Native
execution has 280 passes and 15 optional skips per transport, including all 24
native-only cases passing in each mode. Only 11 network-sensitive native cases
per transport were rerun after supplying the missing local CI network interface;
568 unaffected case/transport results were retained. Every row points to its raw
execution report, and the first failed envelope remains preserved. The remaining
optional skips require the separate GCC13 enabled profile, currently queued;
these results do not establish other compilers or platforms.

The inherited Clang17/libc++ wallet-disabled run exposed a clock error in the
native eviction fixture: frozen time made every minimum ping zero, so compiler
sort ties could evict a peer the test marked protected. The adaptation now uses
the existing historical funding helper and real time for peer traffic. Both
original eviction assertions remain required. The focused repair passed both
transports using the unchanged compiled build; only those two failing rows were
rerun. Evidence is in
`artifacts/ci-parity-20261010/nowallet-eviction-repair-check/`. Combining that
proof with the unaffected full-run rows still requires independent verification;
the original failed envelope remains retained.

## Coverage preserved

Adapters retain original assertions and meaningful preconditions while replacing
native-dependent proof/header construction, address/reward fixtures, timestamps,
activation boundaries and pruning layouts. Full block-processing reorgs, all
SegWit and Taproot vectors, snapshots, pruning/redownload, policy and wallet
scenarios run without blanket exclusions. Specific PoW-only portions within
mixed tests are individually explained in their parity reviews.

The sendheaders fixture preserves 7/8 block reorg thresholds, 16 outstanding-download
limits, null locators and 100/99 unconnecting-header checks. Native equal-height
forks have matching proof/difficulty/time histories. Pruning synchronizes each
stale block before advancing native clocks, preserving all 24 stale blocks in each
of 12 rounds and the later pruned-redownload precondition under load.

Signet retains ten accepted signed blocks, the matching 2-of-2 rejection and exact
default/custom challenge configuration checks. Native headers require new BIP325
signatures, so controlled keys replace inaccessible upstream signers; extra nodes
retain the default challenge checks. Real storage proofs are independently checked
against the pinned Rust reference. The miner adapter preserves wallet signing,
PSBT and all trivial/nontrivial commitment assertions using unchanged upstream
BIP325 helpers. Bitcoin 80-byte-header CLI assembly and SHA256 nonce grinding are
specifically inapplicable and replaced by native proof construction.

All 18 inventoried wrapper assignment/mining scenarios and their shared helper are
mapped in `scenario-parity.json`. All 17 functional replacement files pass both
modes in the final complete matrix. Legacy wrapper-script deletion remains a
separate session.

Connected generation previews allow legitimate transaction relay while retaining
empty-body, parent, height, proof and clock checks. Quiet constructors still
assert exact mempool preservation. A deterministic native regression injects a
real transaction during preview and verifies inclusion by the actual mining call;
restoring the old strict call fails this regression in both modes. The runner
serializes the unchanged IPv4 bind test's fixed ports across transport copies,
with a real-socket infrastructure regression. Neither fix changes upstream files.

## Production fixes verified

Functional coverage exposed and verified seven production gaps: RPC conversion
metadata, early-height scheduler coinbases, native bootstrap linearization,
mining-info warnings, native regtest height-299 snapshot commitments, generic native
mining-info metrics, and uninitialized Signet difficulty calibration. Details and
before/after evidence are in `production-findings.json`. Snapshot commitments
were independently reconstructed from raw blocks and all snapshot bytes.
Bitcoin chainparams preprocessing remains byte-identical after native fixes.

Regression after the final Signet fix passes 727 applicable original unit cases
plus 33 native cases, with zero failures/skips, and all 16 kernel cases with 20,703
assertions. The original combined infrastructure run passed all 86 checks. The standalone
functional package retains 77 checks and adds one IPC scratch-path regression.
One CI staging check and eight fuzz-specific checks belong to their separate
packages. The separate mainnet headers-sync
configuration finding remains open in the unfinished fuzz package.

## Reproduce

```sh
python3 test/pocx/verify_functional.py --build-dir build-pocx-clean \
  --jobs 8 --timeout 2400 --transport matrix
```

This runs the complete selection and verifies all identities, current sources,
resources, binaries/configuration and external dependencies. It accepts only the
exact named optional-feature skip reasons in `functional-profile-skips.json`,
with required disabled build options. Unexpected skips, failures, incomplete
matrices and stale inputs fail. Skips retain their status and never count as
passes. The 2400-second timeout retains the original 40-iteration database-crash
test. Combined CI integration is delivered separately.

The low-level `test_runner.py` remains strict and exits nonzero for any skip.
For a focused individual case, run it directly with a filename or `--case`.
Transport flags set the upstream default; explicit mixed peers and downgrade
scenarios retain their original behavior.

The owned runner retains logs, wallets, configuration and fixtures. After each
passed case exits and its owned processes have been cleaned up, it removes only
direct `node[0-9]+/regtest/{blocks,chainstate,indexes}` database directories and
records their paths in the case result. Directory links are never traversed.
Failed and skipped cases retain their databases. A storage-cleanup error retains
the terminal test outcome but fails both the runner and profile verification.
This bounds scratch storage during a full matrix without changing test execution.

This checkpoint covers the declared local profile. CI feature/platform expansion
and resolution of the 17 environment-dependent skips are the next milestone.
Historical failed, interrupted and superseded runs remain in artifacts and are
never substituted for this final complete evidence.
