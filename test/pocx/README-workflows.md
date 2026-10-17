# Product workflows: CI and CI-POCX

`CI` (`ci.yml`) tests original Bitcoin with `ENABLE_POCX=OFF`.
`CI-POCX` (`ci-pocx.yml`) tests Bitcoin PoCX with `ENABLE_POCX=ON`.
Both use `ci-product.yml`; it accepts `workflow_call` only and is not a third
independently triggered workflow. Neither product depends on the other product's
builds, tests or artifacts. Their concurrency groups and caches are independent.

## Required scope

The upstream reference is Bitcoin Core revision
`9be056a8a72b624dae9623b2f7bded92c2a21c91`,
[CI run 28793907018](https://github.com/bitcoin/bitcoin/actions/runs/28793907018).
CI must match its matrix and original test selections, with no extra profiles.
CI-POCX uses the same configurations, with reviewed adaptations, justified PoW
exclusions and legitimate PoCX-only cases inside those configurations. Test
counts may differ; additional cases do not justify new matrix combinations.

PoCX fuzz conversion remains deferred. The four corresponding ON variants are
absent from the generated matrix and remain an explicit parity gap. Bitcoin OFF
retains all four upstream fuzz variants and ordinary fuzz-binary compilation.
The fuzz selector calls the original recipes with explicit OFF selection; it
preserves their compiler options, sanitizers, corpus handling and assertions.

`upstream-ci-matrix.json` contains the original Linux/macOS/VS matrix definitions.
`ci_matrix.py` checks their pinned revision and canonical digest before emitting
product matrices in the existing runner-selection job. Include-only matrices
ensure deferred fuzz variants cannot be reintroduced by include/exclude rules.

## Job mapping

| Job/check | Product workflow destination |
| --- | --- |
| Original 14 Linux/cross configurations | `ci-matrix`: all 14 for CI, 12 non-fuzz for CI-POCX |
| Native macOS standard and fuzz | `macos-native-arm64`: both for CI, standard for CI-POCX |
| Native Visual Studio standard and fuzz | `windows-native-dll`: both for CI, standard for CI-POCX |
| UCRT/MSVCRT producers and native consumers | `windows-cross` and `windows-native-test`, one selected product per CRT |
| Ancestor compilation/tests | `test-each-commit`, original multi-commit PR condition |
| Runner selection and immutable revision | Original `runners` and `record-frozen-commit` meta jobs |
| Inherited lint and source/adaptation guards | `lint`; guards are steps inside this inherited job |
| Extra `linux-core`, feature, optional-functional and sanitizer profiles | Removed from both product workflows; no supplemental schedule |
| Separate baseline/source-review/scope-summary jobs | Removed; useful checks/reporting remain within inherited jobs |

The original workflow's push/PR triggers and `SKIP_BRANCH_PUSH` policy remain.
There are no extra scheduled/manual product profiles. Existing local diagnostic
runners remain available for focused development; their existence does not add
coverage to the Actions matrix. The former top-level PoCX tests workflow stays
removed. PoCX-only unit/functional coverage belongs inside corresponding ON jobs.

## Execution and status

Original environment scripts, original POSIX recipes and original Windows drivers
remain unchanged. Owned runners select products explicitly and preserve inherited
features, assertions and native platform requirements. macOS cross compilation
does not establish native macOS runtime success; Windows payloads execute on
Windows. An omitted `CI_PRODUCT` retains legacy paired local commands for existing
platform handovers, including their equal non-fuzz feature profiles. Independent
Bitcoin Actions jobs retain original fuzz compilation. Invalid explicit product
selectors fail.

Reports distinguish passes, failures, skips, configuration-disabled cases,
unverified cases and reviewed exclusions. Cancelled or unexecuted jobs are not
passing coverage. Source/adaptation/provenance guards check current hashes without
rewriting historical execution evidence or converting missing evidence to passes.

The functional dispatcher follows each upstream job's BASE/EXTENDED selection,
reviewed exclusions and global transport flags. Case-specific v1/v2 variants
retain their actual effective transports. Format-11 proofs bind the expected
case/transport pairs; identical pairs share execution. PoCX-only cases use the
inherited job's transport. Separate developer transport matrices remain strict.
RPC coverage evaluates the complete inherited selection with the unchanged
upstream evaluator, rather than demanding separate coverage from partial groups.

BCC tracing remains required in ASan, as upstream. Other recipes retain their
original package selections and privilege limits. An `upstream-optional-skip`
requires a reviewed original recipe omission, an unchanged unconditional test
guard and an actually unavailable Python module. It remains skipped coverage;
a missing required prerequisite, unexpected skip or failed process stays red.
Original ARM/previous-release BCC activation is therefore corrected at its source,
without disabling compiled tracepoints or changing test assertions.

The changed configuration still needs hosted verification. Sanitizer time limits,
restored OFF fuzz execution and reported PoCX Windows failures remain open until
matching-revision executions provide evidence. Local checks do not establish a
green pipeline.

## Windows artifacts and diagnostics

Each CRT producer exports its selected product at `record-frozen-commit`'s exact
revision. Consumers require the matching product, source snapshot, configuration,
architecture, checksums and complete payload. Format-2 single-product artifacts
retain the legacy `windows-cross-pair` directory/`pair.json` transport names;
format-1 paired local artifacts retain their additional cross-product checks.
Neither product needs the other product's tests to pass to produce or consume its
own artifacts. Existing platform sessions' builds and cached artifacts stay intact.

Reports and relocated functional views live outside immutable binary payloads.
Collection includes canonical short temporary result paths, raw case logs and
framework logs, without walking node databases, wallets or linked directories.
Build output streams to the job console while identical raw log bytes are retained.
Collected diagnostics preserve failure status; collection does not verify a pass.

Local export/verification remains available:

```sh
python3 test/pocx/windows_artifacts.py --build BUILD --product pocx --output NEW_BUNDLE
python3 test/pocx/windows_artifacts.py --verify NEW_BUNDLE --product pocx
```

On Windows use `windows_artifact_ci.py --product pocx --artifacts NEW_BUNDLE
--output NEW_REPORTS` with the platform handover prerequisites; use `bitcoin` for
OFF. Never relabel artifacts with another product or revision.

## Validation

`test_product_workflows.py` checks the pinned upstream matrices, absence of extra
jobs/events, product isolation, restored OFF fuzz dispatch and immutable Windows
artifact rejection. Inherited/revision/Windows infrastructure tests cover failure
propagation, raw live logs and bounded report retention. `actionlint` validates
workflow syntax, dependencies and shell steps; the full inherited linter remains
required. Local infrastructure checks are not hosted platform execution evidence.
