# Product workflows: CI and CI-POCX

`CI` (`.github/workflows/ci.yml`) tests original Bitcoin with `ENABLE_POCX=OFF`.
`CI-POCX` (`.github/workflows/ci-pocx.yml`) tests Bitcoin PoCX with
`ENABLE_POCX=ON`. Each calls `ci-product.yml` with its own fixed product. The
shared file has only a `workflow_call` trigger; it is implementation, not a third
independently triggered workflow. Neither product depends on the other's jobs,
builds, test results or artifacts. Their concurrency groups are independent.

The active inherited non-fuzz matrix is preserved for both products. The earlier
fuzz variants were already inactive before this restructuring; fuzz modernization
remains a separate package. This change does not claim full hosted or fuzz CI is
green. Configuration and infrastructure checks are not platform execution proof.

## Migration inventory

| Previous jobs/checks | Destination in each product workflow | Coverage and cadence |
| --- | --- | --- |
| `CI` inherited `ci-matrix` OFF/ON pair | `ci-matrix`, one selected product | Same 12 environment recipes, runners, 120-minute limits, prerequisites and assertions; push, PR and normal manual dispatch |
| macOS native OFF/ON pair | `macos-native-arm64` | Same macOS 15 ARM64/Xcode 16.2 recipe, GUI, install/deploy and actual native runtime; ordinary cadence |
| Windows VS OFF/ON pair | `windows-native-dll` | Same VS2026 dynamic-library preset, vcpkg, manifests, lifecycle probes and all applicable frameworks; ordinary cadence |
| Windows UCRT/MSVCRT paired producers/consumers | `windows-cross` and `windows-native-test` | Each product produces its own immutable bundle per CRT, then executes it on Windows 2022 at the producer's frozen revision; ordinary cadence |
| Ancestor OFF/ON pairs | `test-each-commit` | Same ancestor range, compiler configuration and tests; multi-commit PRs only, explicit selected phase even for older executors |
| Lint | `lint` | Same inherited lint recipe, ordinary cadence; checks repository sources rather than product runtime |
| `PoCX tests` drift job | `source-review` | Source/test inventories, reviewed adaptations and fixture provenance remain guarded; workflow organization/isolation regression checks are separate checks |
| `bitcoin-core` / `pocx-core` unit and functional profiles | `linux-core` for the selected product | Preserve minimal Release, GUI/ZMQ/USDT-off profiles; unit and functional use one build because their configurations are identical |
| Separate `pocx-real-proof` job | Complete PoCX `linux-core` unit selection | Duplicate subset removed: `run_unit.py --all` already selects the real-proof, SIMD and wire suites, alongside Shabal, assignments and other PoCX-only cases |
| `bitcoin-features` / `pocx-features` | `linux-features`, selected product | Qt, wallet-disabled, IPC-disabled and kernel profiles, weekly/manual only |
| Paired optional functional job | `optional-functional`, selected product | Complete base/extended selections, both transports, previous releases, ZMQ, IPC, benchmark tools and USDT/BPF in an isolated network; weekly/manual only |
| Paired owned ASan | `asan`, selected product | Clang 22, instrumentation/runtime verification, Qt, kernel, auxiliary and complete strict optional functional scope; weekly/manual only |
| Paired owned TSan/MSan | `instrumented-sanitizers`, selected product | Pinned instrumented libc++/dependencies, sanitizer canaries and applicable complete frameworks; weekly/manual only |
| Manual `baseline_only` | `CI` original unit diagnostic | Explicit opt-in, other jobs skipped; not a full CI pass |

The 12 inherited environment recipes are IWYU, 32-bit ARM, i686/no IPC, ASan,
macOS cross ARM64, macOS cross Intel, no-wallet, previous releases, Alpine/musl,
tidy, TSan and MSan. Their original environment scripts and the original Bitcoin
test recipes remain unchanged. Cross-build success is not target-native runtime
success. Native Windows and native macOS requirements remain native requirements.

The minimal Linux profiles are useful negative feature configurations, rather
than copies of inherited dev-mode builds. The scheduled profiles retain their
independent verification purpose: explicit feature combinations, strict optional
dependency/no-skip gates, instrumented dependency provenance and sanitizer
canaries. They are not promoted to every push. The former standalone real-proof
build and duplicate minimal unit/functional builds are eliminated.

## Events and interpretation

Both product workflows accept push, pull request and manual dispatch. Weekly
supplements keep `19 2 * * 1` (Monday 02:19 UTC). A scheduled invocation runs the
source guards, minimal Linux core and weekly supplemental profiles; it does not
repeat the entire inherited platform matrix. A normal manual dispatch runs both
the inherited matrix and the supplements for that product.

`SKIP_BRANCH_PUSH=true` suppresses redundant inherited branch-push jobs, while PR
and manual invocations retain their intended scope. Minimal Linux/source checks
retain their former push coverage. The scope summary shows actual GitHub job
outcomes, including skipped jobs. Success on a weekly supplement, diagnostic or
limited event is evidence only for the jobs actually executed.

Runtime reports still distinguish failures, skips, configuration-inactive cases,
platform-disabled cases, reviewed exclusions and actual passes. No status is
converted into a pass by this restructuring. Reviewed PoW exclusions remain in
`unit-parity.json` and `manifest.json`; the replaced PoW algorithms are excluded
only for PoCX, with their recorded reasons. They remain part of Bitcoin OFF
coverage. PoCX-only cases remain additional required coverage in ON builds.

## Runner selection and Windows artifacts

Actions sets `CI_PRODUCT=bitcoin` or `CI_PRODUCT=pocx` explicitly. The inherited
POSIX, native Windows and revision planners select exactly that product and set
the corresponding CMake flag. Docker passes the selector through its allowlist;
elevated steps pass it explicitly through `sudo`. Unknown or empty selectors and
mismatched Linux profile prefixes fail rather than choosing a default product.

With `CI_PRODUCT` unset, the old original-first paired local commands remain
available for the platform handovers. Do not change another session's checkout,
in-progress binaries or cached artifact manifests to adopt the new organization.

Windows producers export format-2 single-product bundles. The legacy directory
name `windows-cross-pair` and manifest filename `pair.json` remain for transport
compatibility; the manifest's kind, format and one-element product inventory
identify the single-product format. Format-1 local pairs are still verified with
the original cross-product feature/configuration matching guard.

Actions consumers explicitly require exactly their selected product. They check
the frozen source revision, current source snapshot, functional support sources,
compiler feature/target metadata, complete required payload, PE architecture,
checksums and PoCX cross-unit provenance. Tests run on Windows against unchanged
payloads, with reports and relocated functional views outside the bundle. Each
product runs host process-lifecycle checks before its framework claims. Test or
build failure in the other product cannot prevent this producer or consumer.

Single-product export and verification are also available locally:

```sh
python3 test/pocx/windows_artifacts.py --build BUILD --product pocx --output NEW_BUNDLE
python3 test/pocx/windows_artifacts.py --verify NEW_BUNDLE --product pocx
```

Use `windows_artifact_ci.py --product pocx --artifacts NEW_BUNDLE --output NEW_REPORTS`
on Windows with the same prerequisites as the platform handover. Replace `pocx`
with `bitcoin` for OFF. Never relabel an old bundle with a new revision or product.

## Validation and platform coordination

`test_product_workflows.py` checks product isolation, matrix and event selection,
the removed real-proof subset, selector propagation, independent failure paths
and single-product artifact rejection. Existing inherited/revision/Windows and
source-evidence regression checks remain applicable. `actionlint` validates the
three workflow files, including their reusable workflow inputs and dependencies.

The original environment/test recipe hashes stay pinned. Current source maps in
`inherited-ci.json`, `windows-ci.json` and `windows-artifacts.json` explicitly
review the organizational change and extend guards to both wrappers, the shared
workflow, selector and regression test. Historical repair records and collected
execution evidence are not rewritten. New workflow/source snapshots require
their own matching execution evidence; prior Linux/Windows milestones remain
historical results for the revisions actually tested.

Platform work may continue with the default local paired entry points. Integrate
platform commits normally and reconcile any overlapping infrastructure changes;
do not replace their source hashes blindly. Recheck changed runners/configuration
and affected shared code without repeatedly replaying unaffected baselines.
