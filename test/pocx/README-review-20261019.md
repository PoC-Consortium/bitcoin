# Testing review disposition — 2026-10-19

This responds to `testing-review-20261018.md`, reviewed against `ec67ffaf1d` on
`test/ci-product-workflows-20261017`. Changes stay on this branch, on top of its
history. PoCX fuzz remains on hold.

## Findings and decisions

| Finding | Judgment | Resolution |
|---|---|---|
| F1: `mining_basic.test_timewarp` replaced with a log | Confirmed missing replacement coverage | Replace the log-only body with rejection at deadline minus one and acceptance at the exact independently calculated PoCX deadline. The BIP94 retarget rule itself is PoW-specific. |
| F1: successful IPC `submitSolution` replaced by RPC | Confirmed coverage distinction; no PoCX solution can be represented by this API | Explicit reviewed subcase exclusion. Keep IPC assembly, malformed input, mutation and `checkBlock` assertions. Label complete-block RPC submission separately; it does not establish IPC submission coverage. |
| F1: `feature_block` b55 timestamp slack | Confirmed | Replace the arbitrary 600 seconds with the exact PoCX deadline; require rejection one second before it and acceptance at it. Bitcoin's MTP rule is replaced by nondecreasing time and the forging deadline. |
| F2: zero consensus-rule coverage | Partially confirmed | Existing signature checks, real proof vectors and header-transition state-machine tests contradict a literal zero-coverage claim. Direct retarget and boundary coverage was missing. Add eight unit cases and a native functional case, detailed below. |
| F3: missing mainnet header-sync configuration | Confirmed production bug | Move inherited nonzero synchronization resource limits outside the Bitcoin-only branch. Construct `HeadersSyncState` with actual PoCX mainnet parameters in a regression. OFF values remain unchanged. |
| F3: zero mainnet minimum chain work | Intentional new-chain policy, not a value to copy from Bitcoin | Retain zero until an authenticated PoCX accumulated-work checkpoint exists. The regression records this decision. Zero does not excuse an invalid header-sync configuration. |
| F4: production fixes accompanying tests | Legitimate where tests expose real defects | Retain header-read validation, uniform regtest proof gating, low-height coinbase padding, RPC conversions, signet calibration, native assumeUTXO fixture and explicit linearizer format. Each has an identified regression and preserves the OFF path. |
| F4: quality cache | Production optimization requiring scrutiny, not a consensus-rule waiver | Retain after review of complete value-based keys, bounded memory, cold/warm independent comparisons, mutated inputs, changed deadline target and concurrent calls. Cache misses preserve the original calculation. Signatures, claimed quality, compression, context and timing still validate on hits. |
| F4: unconditional PoCX wallet compatibility dependency | Ownership problem confirmed; blindly gating it would remove a shared portability fix | Relocate the unchanged implementation to `src/wallet/windows_fs.h` in `wallet::detail`. Both products retain the MinGW correction. Explicit OFF exception: repair reparse-point classification in GCC's Windows filesystem implementation; Linux/MSVC retain standard calls. |
| F5: OFF uses an owned dispatcher | Fidelity caveat confirmed; no demonstrated missing test | Retain the reviewed dispatcher. It invokes the original functional runner and preserves inherited selection, arguments, assertions and strict prerequisite checks. Recipe/source guards and failure-path tests remain required. Running the shell script verbatim would remove the current structured accounting and reviewed platform fixes; that architectural change is not required to fix the findings. |

The IPC exclusion is narrowly the successful **nonce-only** `submitSolution`
path. Its public signature contains no PoCX proof, public key or compact
signature fields. Adding a PoCX submission method and schema would be a product
feature, not an adaptation of Bitcoin nonce grinding. The exclusion is visible
in `manifest.json`, matched by the drift review, and printed independently of
passed cases. The enclosing IPC test remains selected.

## Additional questions in the review

- The three `test_block_validity=false` fixture helpers already explain their
  purpose in source. They assemble unsigned or branch-retargeted templates and
  then validate the finished signed blocks through `ProcessNewBlockHeaders` or
  `ProcessNewBlock`. The miner selection-only check separately asserts that the
  invalid template fails full validation. Retain these deliberate phases.
- Fee-comparison input pinning in `wallet_fundrawtransaction.py` preserves the
  original fee-delta tolerance and asserts identical selected inputs for both
  compared transactions. Independent coin selection remains exercised elsewhere
  in the same inherited test. This is deterministic fixture control, not a
  loosened fee assertion.
- The signet miner CLI question is valid partial coverage: Bitcoin's unchanged
  CLI assembles 80-byte PoW headers and grinds nonce/nBits solutions. Record that
  replaced CLI path as a reviewed subcase exclusion. Native adaptation still
  calls the tool's PSBT and solution helpers and retains challenge, signing,
  commitment and height assertions. It does not claim to test a PoCX miner CLI.
- Testnet4 is explicitly a PoCX testnet alias. The unit alias regression checks
  that behavior; Bitcoin's distinct Testnet4 PoW sanity case remains excluded.
- Wallet fixture helpers are owned framework additions with source/dependency
  hashes and focused record-rebasing tests. They operate on detached fixture
  copies, preserve unrelated records, verify dump checksums and round-trip
  against genuine old wallet tools. They are not an unreviewed validation bypass.
- The small early-height scheduler test inherits the complete real-proof,
  accepted-block, signer, payout and `verifychain` assertions. Its fee hook is
  empty because height two has no mature funds. The mature scheduler test still
  exercises fees, over-budget rejection and retry. Retain the two distinct
  preconditions; the short file is not an empty test.

## New consensus checks

`src/pocx/test/pocx_consensus_tests.cpp` adds:

1. inclusive base-target envelope bounds and one-step-outside rejection;
2. retarget vectors for stable, fast and slow histories, weighted averaging,
   rolling-window isolation, hybrid deadline correction, minimum target and both
   genesis calibrations;
3. deadline minus one, equality and plus one, zero-quality, backwards time and
   timestamp-range boundaries;
4. a generation-signature known answer computed with independent SHA256d,
   predecessor-account mutations and both public entry points;
5. compact-signature rejection for changed headers, keys, signatures and recovery
   IDs, and separate signer-account authorization;
6. delegated signer activation and revocation boundaries;
7. actual mainnet header-sync configuration and constructor viability;
8. production mainnet batch-header height, target, generation-signature and
   timing rejection in both header positions, with structurally valid controls
   reaching proof validation instead.

`feature_pocx_consensus.py` uses the existing Rust-generated proof vectors to
reach `bad-gensig` and `bad-height` through real proof validation. It then checks
incorrect contextual targets, backwards/early timing, corrupt signatures and
acceptance at the exact deadline. Expected generation signatures and deadlines
are independently calculated in Python. It has no wallet dependency and is
selected in the existing product jobs, in their inherited transport mode.

No consensus acceptance rule was relaxed or changed to satisfy these tests.
In particular, the generic Bitcoin compact-signature decoder masks recovery
header bits. Tests corrupt the actual recovery ID rather than inventing a new
canonical-encoding consensus restriction.

## Maintenance and diagnostic changes

- Print functional case/status/duration/reason rows and the actual failed case
  names in inherited CI, preserving full artifact proofs and failure semantics.
- Add a source guard rejecting unreviewed subcase exclusions.
- Remove collected logs, JUnit and execution snapshots from the tracked
  `artifacts/` directory. Keep the static original source inventory under
  `test/pocx/baseline-inventory.json`.
- Reduce `coverage.json` to source classification and selection information;
  remove saved pass/fail histories from it and from per-test assertion reviews.
  Historical data remains in Git history. Runtime exports cannot overwrite the
  committed source inventory.
- Replace the checkpoint diary in `README-ci.md` with current operating
  instructions. Keep pinned baselines, source reviews, external vector
  provenance and regression infrastructure.
- Keep the existing branch history and add commits, as requested. Do not squash
  it now. A future merge strategy can be decided separately.

The review's proposed Core-bump delta/repin tools are future maintenance work.
A source inventory refresh must not automatically approve new adaptation
hashes. Keep immutable baseline checks and human review; tooling may prepare a
candidate update but cannot certify it. Fuzz modernization remains separate.

## Validation scope

The pre-change hosted baseline is green for both products at `ec67ffaf1d`.
Local validation completed:

- 768 unit cases across 155 suites: passed, with pinned external script vectors;
- 16 kernel cases and 20,703 assertions: passed;
- mining, block boundaries, native consensus and IPC mining: passed in v1 and v2
  (eight script/transport executions); IPC uses the existing optional-runtime
  container with its Cap'n Proto Python dependency;
- 81 infrastructure, 51 inherited-dispatch, 17 product-workflow, 30 wallet-helper
  and 64 Windows-infrastructure checks: 240 passed, three installer-tool
  prerequisite skips retained explicitly;
- source/recipe guards, inherited linter and Linux/MinGW header compilation:
  passed;
- OFF mainnet constructor preprocessing is unchanged; shared wallet helper code
  is byte-identical after normalizing its new ownership and namespace.

The full unit check initially rejected an inactive script-assets case because
its local data prerequisite was absent. Supplying the pinned 2,244 vectors
produced a complete strict pass; no skip was waived. Infrastructure testing also
found and fixed a source-freshness exporter omission for owned framework
additions. Detailed command outputs stay outside Git.

Native Windows/macOS and sanitizer execution of the new revision must be
established by its own hosted run. Local success and an earlier green revision
are not substitutes. No push or additional Actions run is implied by this review
response.
