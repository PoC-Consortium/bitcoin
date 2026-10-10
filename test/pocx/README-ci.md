# Bitcoin and PoCX CI verification

`ci.py` provides Linux entry points for the completed test packages. The workflow
in `.github/workflows/pocx-tests.yml` runs original Bitcoin baselines before the
matching PoCX jobs. The scheduled/manual feature jobs include both sides of the
Qt, kernel, wallet-disabled and IPC-disabled configurations. A configured job is
not passing evidence until it has actually executed successfully.

## Current local checkpoints

Some inherited unit/kernel checkpoints initially stripped `BOOST_TEST_RANDOM=1`.
Their original nonrandomized evidence remains valid within that scope. The
no-wallet pair and original i686/previous-release checkpoints now also have
verified randomized runs; other randomized CI conditions require their own proof.
The repair preserves this setting, records the actual chosen seeds and keeps
filters and report overrides out of the environment. The current case report
under `artifacts/ci-parity-20261010/required-ci-coverage/` distinguishes this gap
from test failures and preserves unaffected Qt, auxiliary and functional evidence.

The randomized local Clang17/libc++ no-wallet pair is now independently verified:
680 Bitcoin unit cases, 702 PoCX unit cases and all16 kernel cases on each side.
The unit runs used a180second per-suite deadline; the kernel runs retained the
inherited2400second deadline. Existing binaries were reused, with no compilation
or Qt/functional/auxiliary replay. Case reports and actual Boost seeds are under
`artifacts/ci-parity-20261010/randomized-nowallet-checkpoints/`. Other inherited
randomized configurations remain separate requirements.

The retained original i686 and previous-release builds also passed the missing
randomized unit/kernel conditions with the upstream 512 KiB stack and 2400 second
deadlines. The i686 run passed 737 unit cases, with two IPC cases inactive because
`ENABLE_IPC=OFF`, plus all 16 kernel cases. Both lock-order cases ran and passed.
The previous-release run passed 739 unit cases and all 16 kernel cases.
Independent verification checks actual seeds, every case, original sources,
build identities, loaded libraries and QA data. Compilation,
Qt, auxiliary and functional execution were not replayed. Reports are under
`artifacts/ci-parity-20261010/randomized-{i686,previous-releases}-original-checkpoint/`.
The matching native profiles remain queued and require their own execution proof.

The owned Ubuntu24/GCC13 prerequisite-complete optional functional pair is now
locally verified with both transports and zero skips: Bitcoin passed 918 rows
(459 per transport), and PoCX passed 590 rows (295 per transport). The PoCX rows
comprise 208 unchanged, 334 adapted and 48 PoCX-only passes. Bitcoin expands 173
benchmark entries per transport; PoCX uses an independently verified aggregate
covering every registered benchmark. These different counting representations
do not indicate missing tests or a conversion percentage. Actual CI reports,
source/build inputs, argument variants and retained artifacts were independently
checked without replaying execution. Evidence is under
`artifacts/ci-parity-20261010/ubuntu-functional-optional-{bitcoin,pocx}-checkpoint/`.
The original checkpoint watcher's host permission error is retained; its unchanged
exporter succeeded with the raw artifacts read inside the live container.
This local pair does not establish hosted, sanitizer or other platform passes.

## Retained verification notes

The following notes preserve intermediate failures, fixes and checkpoints.
Statements about queued or incomplete phases describe those observations; the
current case report identifies subsequently verified conditions.

Lint is also required by the inherited workflow. It checks the shared source
tree regardless of the PoCX build switch. The local 2026-10-10 comparison used
the unchanged upstream `ci/lint/06_script.sh` and installer-pinned tools:
all15 upstream groups passed; the fork passed12 and failed3 (`py_lint`,
`trailing_whitespace` and `all_python_linters`). The latter includes12 Python
scripts; these are nested checks rather than additional top-level groups.
Executable permissions have since been corrected for253 owned scripts, with
unchanged source bytes, and the unchanged `lint-files.py` now passes. The other
lint findings remain required. This local comparison does not establish the
original `ci/lint.py` Docker build, a pull-request merge range or hosted lint.
The retained comparison is under
`artifacts/ci-parity-20261010/lint-execution-checkpoint/`.

The owned Python statement-formatting cleanup now removes all E701/E702 findings.
All35 affected files retain identical runtime syntax trees and ordered comment
tokens. The25 affected standalone infrastructure scripts passed287 checks;
build-bound scripts use their explicit build argument rather than generic test
discovery. Current review hashes and their dependent manifests were refreshed,
including stale Windows pins for the already-reviewed controller and eviction
fixes. Evidence is under
`artifacts/ci-parity-20261010/lint-python-statement-formatting/`.
Other Python and source lint findings remain required; this is not a complete
lint pass or a replay of any original Bitcoin baseline.

The inherited workflow also includes the original 32-bit x86 without IPC and
previous-release compatibility profiles. Both retain their upstream environment
scripts and run through the Bitcoin-first PoCX controller. The previous-release
job retains its compiler, unsigned-char checks and RPC coverage settings. These
profiles require actual hosted build and runtime evidence; restoring a matrix
entry does not establish a passing result.

The local inherited Clang17/libc++ wallet-disabled pair is now independently
verified through its applicable native frameworks: 702 unit cases, 8 Qt methods,
16 kernel cases, 6 auxiliary executables and 386 functional case/transport rows
passed. The 204 disabled-feature functional rows remain separately recorded.
The native functional checkpoint reuses 588 unchanged rows and the two corrected
eviction rows; it preserves the original failed envelopes. Unconditional wallet
guards inherited through unambiguous single-base sibling test classes now identify
their actual declaration files. Overrides, conditional guards, ambiguous classes
and inheritance cycles do not justify omissions, and missing enabled prerequisites
remain unverified. Evidence is under
`artifacts/ci-parity-20261010/inherited-nowallet-native-complete-checkpoint/`.
This is a reconciled local checkpoint, not a rewritten recipe exit or hosted pass.

The inherited Ubuntu22/GCC12 previous-release Bitcoin-OFF build also passed its
local CTest phase with the original unsigned-char, Werror, Debug and Boost safe
settings: 739 unit cases, 9 Qt methods, 16 kernel cases and 6 auxiliary executables.
The source/build-checked checkpoint is under
`artifacts/ci-parity-20261010/inherited-previous-releases-original-ctest-checkpoint/`.
Its functional matrix and RPC coverage are still running; native execution remains
gated on that complete original baseline. No completed build or test was replayed
to export this phase.

The 2026-10-10 local i686 Bitcoin-OFF build completed with the inherited
Debian trixie/Clang19 environment, 32-bit dependencies, Debug configuration,
Boost safe mode, IPC disabled and the upstream512KiB test stack. Its actual
CTest entrypoint passed737 original unit cases,9 Qt methods,16 kernel cases
and5 auxiliary executables. The two IPC unit cases are inactive because IPC is
disabled in this configuration; both lock-order cases ran and passed. The
independent checkpoint in
`artifacts/ci-parity-20261010/inherited-i686-original-ctest-checkpoint/`
revalidates source/build identities, commands, raw reports and individual cases
without replaying compilation or tests. Original functional execution remains
incomplete and must pass before the matching PoCX profile starts. This checkpoint
does not establish a full i686 pair or hosted result.

The ongoing i686 original functional baseline has five confirmed USDT failures
(coin selection, mempool, networking, UTXO cache and validation). All five test
files are byte-identical to upstream. Actual probe metadata reports four-byte
pointer/size arguments; the host BPF code requests eight-byte destinations.
BCC rejects those reads and leaves zero values. An isolated32-bit USDT canary
reproduced the rejection and read the correct string/count with four-byte
destinations, without attaching to a Bitcoin process or replaying a test.
Evidence and the five retained failure logs are under
`artifacts/ci-parity-20261010/inherited-i686-usdt-argument-width-observation/`.
The compatibility fix remains required; native execution stays behind the
original baseline gate, and no tracing assertion is waived.

The previous-release profile runs RPC coverage separately for each transport.
Bitcoin uses its unchanged runner; PoCX retains raw coverage files and invokes
the unchanged upstream coverage evaluator. Missing references or uncovered RPC
commands fail the profile. Its historical database-crash exclusion is recorded
as a selection extension: the complete suite runs that slow case on both sides.

| Bitcoin baseline | PoCX selection |
| --- | --- |
| `bitcoin-unit` | `pocx-unit`, `pocx-real-proof` |
| `bitcoin-functional` | `pocx-functional` |
| `bitcoin-functional-optional` | `pocx-functional-optional` |
| `bitcoin-qt` | `pocx-qt` |
| `bitcoin-kernel` | `pocx-kernel` |
| `bitcoin-wallet-disabled` | `pocx-wallet-disabled` |
| `bitcoin-ipc-disabled` | `pocx-ipc-disabled` |
| `bitcoin-asan` (all four frameworks) | `pocx-asan` (all four frameworks) |
| `bitcoin-tsan` (headless frameworks) | `pocx-tsan` (headless frameworks) |
| `bitcoin-msan` (headless frameworks) | `pocx-msan` (headless frameworks) |

Each profile configures and builds an isolated directory by default. For example:

```sh
python3 test/pocx/ci.py --profile bitcoin-kernel --jobs 4
python3 test/pocx/ci.py --profile pocx-kernel --jobs 4
```

Run the second command only after the matching baseline passes. Native real-proof
checks extend the standard unit configuration; they have no original PoW proof
case counterpart. Fuzz implementation and its sanitizer execution remain a
separate, unfinished package and are not dispatched by this CI entry point.

Unit profiles provision an immutable, checksum-verified external script dataset.
Original and native unit runners enforce the applicable individual case inventory,
including feature-disabled cases and explicit PoW exclusions. Qt verifies actual
method names and rejects skips or expected failures. Kernel verifies all 16
original case identities and their detailed Boost results. Framework reports
retain the source/build checks specific to each package.

The outer CI report additionally records the runner/helper/review/fixture and
workflow source snapshot, build configuration, binaries, libraries, CTest
registrations, each required command and return code, and retained logs and child
artifacts. Changed inputs, missing steps or altered artifacts reject the proof.
This is not a complete compiler dependency graph. Results are written beneath
`BUILD/ci-results-*/`; independently recheck a saved passing report with:

```sh
python3 test/pocx/ci_evidence.py --report BUILD/ci-results-ID/results.json
```

`--skip-build --build-dir BUILD` uses an existing build with the required source
worktree and profile. The dedicated Qt/kernel runners still request their test
targets before execution. If that rebuild changes the initial binaries or build
inputs, the outer CI proof fails; bring the build up to date and rerun. A historical
passing report also becomes stale when its recorded source or build inputs change.

The standalone unit, Qt, kernel and functional runners accept explicit CMake
configurations for Visual Studio and Ninja Multi-Config builds. Pass
`--config Release` (or another configured name) to `run_bitcoin_unit.py`,
`run_unit.py`, `run_qt.py`, `run_kernel.py`, `test_runner.py` or
`verify_functional.py`. Qt/kernel runners build their selected targets; unit and
functional runners require those executables to be built already. The same
configuration selects the CTest invocation and executable under `bin/Release`.
Native unit discovery keeps separate input manifests, registrations and binary
evidence for each configuration. Functional execution pins every tool path and
the selected binary directory in `PATH`, including paths for unavailable tools,
and verifies the exact present executable inventory. Omitting the selection on a
multi-configuration build, or requesting a different single-configuration build
type, fails. Functional processes use an owned Unix session or Windows Job Object.
The Windows worker joins its job before starting a test; the parent retains the
job handle and requires all descendants to stop before releasing the port slot.
Format9 records the controller and actual worker invocation, and requires completed
cleanup for every case. `test_process_tree.py` exercises real child lifecycles on
its host platform; Windows API adapters on Linux do not prove Windows execution.
The native Visual Studio workflow now calls `windows_ci.py`: it preserves the
original generation options, retry, build fallback, manifest checks and functional
timeout, but requires the complete Bitcoin-OFF phase before PoCX-ON. It provisions
pinned unit assets, runs host process-lifecycle probes, dispatches strict unit,
Qt, kernel and auxiliary checks, and runs both functional transports. Success and
failure reports are uploaded from `artifacts/pocx-inherited`. `windows_ci.py --plan`
is read-only and establishes no execution coverage. Actual native Windows runtime
verification remains unverified. Cross-artifact consumers are implemented below;
their actual hosted execution remains unverified.
The Linux `ci.py` profiles remain single-configuration profiles.

Windows cross-builds defer owned unit runtime discovery until the Windows host.
The Linux post-build step records the PE binary and evaluated source/generated
inputs in `cross-build.json`; it does not execute that binary or invent test
registrations. `windows_artifacts.py` prepares separate Bitcoin/PoCX payloads
with the original compiler configuration, source and binary checksums, required
auxiliary executables, and configuration-specific expected unit inventories.
Verification rejects missing tools, changed inputs, wrong PE architecture,
unexpected files and stale discovery records. `windows_artifact_unit.py` adds a
unit-only target-host profile: all enabled cases run in one process with the
upstream default ordering, followed by detailed Boost leaf verification. It
rejects filters, unknown disabled cases, missing vectors and incomplete process
cleanup. The five unchanged upstream `mock_process` helpers are separately
identified as default-disabled subprocess fixtures outside the 737-case baseline.
The Bitcoin unit phase must pass before any PoCX unit execution. A real stateful
Boost probe verifies that replacing this with separate suite runs would fail.
The consensus and unit SSE2 gates accept AMD64/X86_64 spelling consistently, so
four applicable comparisons cannot disappear because of capitalization.
`windows_artifact_tests.py` extends that unit profile with genuine Qt method
verification, all five unchanged library executables in upstream order, and the
complete enabled kernel suite. The entire Bitcoin phase must pass before any
PoCX phase starts. The inherited Windows dev-mode preset enables kernel tests,
even though the unchanged original cross runtime driver does not execute them.
The owned profile requires all 16 registered kernel cases and their actual
Boost assertion reports. Cross builds render the independently verified kernel
fixture snapshot with host Python; native builds retain their generator. Neither
path changes the fixture bytes or kernel assertions.
Qt uses the same strict method verifier as the CTest runner, without fabricated
CTest reports. Missing enabled Qt, partial/skipped methods, failed libraries,
timeouts, incomplete process cleanup and changed payloads all reject the profile.
Only explicit GUI feature switches justify omitting Qt. Library rows count whole
executables, without inventing counts for their internal cases. Artifact pairs
must match feature switches, target, compiler and sanitizer flags apart from
`ENABLE_POCX`. Actual hosted builds and Windows test execution remain unverified. Artifact
and compiler checks never count as passing Bitcoin/PoCX cases.

`artifact_functional_view.py` prepares a disposable Windows functional runtime
tree outside the immutable bundle. It verifies the source revision, paired build
features and payload hashes before copying binaries and unchanged original test
sources. Only the source/build paths in the INTERNAL cache entries and the three
functional configuration paths are relocated; compiler options and component
flags are preserved and checked against each other. The retained manifest binds
every copied input, the original cache and each relocation. The original config
template and RPC authentication helper are also pinned by the artifact pair.
Reverification rejects changed or additional scripts/binaries and symlinks, while
allowing test caches and result files outside the input directories. This creates
execution inputs; it does not establish a local compiler build or any Windows
test pass. Consumers must set `PYTHONDONTWRITEBYTECODE=1`; unrecorded bytecode in
the input tree is rejected. Previous-release prerequisites use Windows `.exe` filenames;
owned wallet adapters use the configured executable suffix. Functional staging
now also binds its prerequisite helper, so changing that helper invalidates saved
execution evidence.

`windows_artifact_ci.py` is the complete paired artifact runtime consumer. It
checks the actual host process controller, executable versions and manifests,
then runs Qt/unit/libraries/kernel and functional tests in both transports for
Bitcoin before starting any PoCX executable. It preserves the original cross
driver's exact two manifest exemptions (`fuzz.exe` and `bench_bitcoin.exe`). All
other exported executables, including owned tools, require manifest validation.
Previous releases are required by this profile; missing dependencies fail. The
functional child uses an owned process tree and the parent independently checks
the exact original/native case inventory, executed commands, raw CSV/native
proofs, terminal exits, transport settings, logs and previous-release hashes.
Unknown skips fail; source-guarded feature/platform omissions remain separate
configuration-disabled rows. PoCX-only cases and reviewed PoW exclusions retain
their identities in the combined case report.

The original Windows old-release UTXO case executes separately and sequentially
in an ASCII-only directory in both transports, preserving every assertion. The
other cases keep the unchanged upstream runner's directory behavior. Both
`wallet_multiwallet.py` argument variants remain required. Explicitly disabled
benchmark builds retain the original unexpanded script and its source-guarded
skip; enabled builds require the actual complete benchmark listing. The native
runner requires its current process-controlled proof format. Runtime-view,
manifest, dispatch and verifier callback checks are infrastructure evidence,
never actual Windows or functional passes. Actual hosted execution still remains
required. `--plan` is read-only;
execution requires Windows and a new output directory inside this worktree.

Both inherited Windows cross profiles now export the paired build inside the
container, after both compilers succeed and before container cleanup. The export
retains raw compiler configuration, native discovery inputs, all required
executables and DLLs, original source hashes and the unchanged previous-release
downloader/checksum helpers. A cross-build success records no Windows test
passes. Publication keeps the payload at
`artifacts/pocx-inherited/windows-cross-pair` and bounded producer reports in a
separate sibling directory; container evidence capture copies both back to the
host. Existing native/POSIX recipe behavior and fuzz routing remain unchanged.

The MSVCRT/UCRT workflow jobs check out the same frozen source commit with LF
bytes. They upload/download each paired payload under a matching CRT-specific
artifact name, verify it before use, provision ZMQ/previous-release prerequisites
and call the complete owned runtime consumer. They retain success and failure
reports with `windows_cross.py --collect-runtime`. Collection preserves raw
case CSVs, Boost XML, commands/logs, native functional proofs and runtime path
provenance without uploading binaries, node data or caches. Collection itself
does not verify or promote test results. The unchanged original Windows driver
remains available as reviewed upstream source. Workflow/source checks and
synthetic producer/consumer fixtures are infrastructure evidence only; actual
hosted compilation and Windows execution remain required and unverified.

The initial functional checkpoint has 17 explicitly documented optional skips.
The 2026-10-10 local prerequisite-enabled checkpoint passes all 17 original entries
and their PoCX counterparts in both transports, with no skips. These entries
include all five USDT tracing cases, IPC, ZMQ, previous-release compatibility,
chainstate tools and the benchmark wrapper. The original benchmark entry expands
to all 173 registered benchmark cases per transport; the PoCX wrapper executes
its full registered list. Entry counts and expanded benchmark counts overlap and
must not be added together.

The five previous-release cases have separate owned adaptations for mempool
files, coinstats indexes, unsupported UTXO databases, wallet backward compatibility
and wallet migration. The migration adapter retains the original assertions and
scenarios, including backup, rollback, no-rescan, pruned-data and deliberate
wrong-chain failures. Mixed-chain fixtures preserve transaction bodies while
explicitly translating chain-specific context. Original source files remain
unchanged. Raw failed attempts remain available alongside corrected passing runs.
The case-level checkpoint is recorded in
`artifacts/ci-parity-20261010/optional-functional-cases.csv`, with scoped input
reuse checks in `optional-native-current-inputs.json` in that directory.

The complete original v1 selection reuses unchanged passing cases
and focused corrections for environment failures. The previously missing full
v2 selection now passes, including all 40 database-crash iterations and both
special-address cases: 459 original cases per transport. The complete native
optional CI entry point now passes its 295 selected cases per transport without
skips: 104 unchanged original scripts/argument cases, 167 separately adapted
original cases and 24 PoCX-only cases. The original `mining_mainnet.py` PoW-only
exclusion remains individually justified. Original fixed-transport duplicates
and the expanded benchmark selection map to the corresponding native executions;
the different raw counts do not imply missing conversions. The mapping and
case categories are retained in `functional-categorized-cases.csv` under
`artifacts/ci-parity-20261010/`.

The final outer retention check initially failed after completed tests' generated
block/index databases were removed to avoid exhausting disk space. Preserve that
failed check. `full-optional-retained-proof/results.json` independently rechecks
the unchanged sources, builds, exact case inventories, successful entrypoint,
process cleanup, logs and child reports under the corrected retention policy.
Future CI collection prunes only `node*/regtest/{blocks,chainstate,indexes}`;
reports, framework/node logs, configurations and wallet files remain retained.
This complete local optional checkpoint uses Linux GCC14. It does not establish
the owned Ubuntu24/GCC13 optional CI configuration, hosted runs or sanitizer
passes. The missing GCC13 optional pair is queued after the currently running
Ubuntu feature/functional pair; it requires the same complete prerequisites and
both transports, and starts the native configuration only after Bitcoin passes.
Required optional profiles reject skips with `--require-no-skips`; normal
functional profiles retain their explicitly documented limited-checkpoint policy.

The scheduled/manual `optional-functional` job provisions matching kernel headers,
BCC, ZMQ, IPC bindings and eight checksum-verified historical releases. It builds
the required tools, then runs the original optional baseline before PoCX in a
fresh network namespace. The two special fixture addresses exist only in that
namespace. Original USDT tests require root for BPF; this elevation is confined to
the hosted runtime step. This workflow configuration has not yet been executed
for the current package and does not establish passing evidence.

Both optional profiles reject every skip and require both transports. The original
profile uses the unchanged upstream runner, includes all extended tests and expands
each registered sanity benchmark. Its private build view ensures the attested
test copies are actually executed. The two shared address corrections receive
their own prerequisite flags in separate invocations. Original transport variants
keep their flags; reports record their effective transport and require both
transports for every case after transport flags are normalized. The PoCX profile
retains its full selection, including native and wrapper cases, and uses the
existing complete-matrix verifier with `--require-no-skips`. Missing prerequisites,
partial or duplicated cases, and a green aggregate hiding a skip all fail the gate.
For a prepared environment, run these sequentially:

```sh
python3 test/pocx/ci.py --profile bitcoin-functional-optional --previous-releases-dir VERIFIED_RELEASES
python3 test/pocx/ci.py --profile pocx-functional-optional --previous-releases-dir VERIFIED_RELEASES
```

Provision `VERIFIED_RELEASES` using the unchanged `test/get_previous_releases.py`
with `--remove-dir` and the eight explicitly listed versions in the workflow;
without that flag, upstream trusts existing release directories. The runners
record all 17 required executables and reject changes during execution. They
do not establish the provenance of arbitrary caller-supplied cached binaries.

Wallet backward compatibility constructs explicit native-context fixtures on
transaction-identical, independently validated chains. Detached wallet copies
change only address-book network encodings, block locators and confirmation
block hashes. All other records stay byte-identical, and reverse conversion is
checked. This requires the genuine v28.2 `bitcoin-wallet` tool in addition to the
previous-release daemons and CLI tools; the runner fingerprints all 17 binaries.
It does not claim that unmodified Bitcoin wallets are portable across chains.

Required platform and sanitizer coverage remains broader than the completed local
checkpoints. The actual owned Ubuntu24/GCC13 CI entrypoints now pass these pairs:

| Configuration | Original Bitcoin passes | Original cases passing under PoCX | PoCX-only passes |
| --- | ---: | ---: | ---: |
| Standard unit | 737 | 727 (522 unchanged, 205 adapted) | 33 |
| Wallet-disabled unit | 680 | 670 (481 unchanged, 189 adapted) | 32 |
| IPC-disabled unit | 735 | 725 (520 unchanged, 205 adapted) | 33 |
| Qt | 9 | 9 (7 unchanged, 2 adapted) | 1 |
| Kernel | 16 | 16 (10 unchanged logic, 6 adapted fixtures/checks) | 0 |

The original unit catalog contains 739 cases. Two `DEBUG_LOCKORDER` cases are
inactive in these Release builds; wallet-disabled additionally omits 57 original
wallet cases and one native wallet case, while IPC-disabled additionally omits
two original IPC cases. The ten PoW-only unit exclusions remain individually
reviewed. All auxiliary CTest executables pass: six for standard/wallet-disabled
and five for IPC-disabled. The dedicated native real-proof entrypoint passes
using the already built unit binary; its cases overlap the33 native unit cases
and are not additional unique passes.

Kernel case-logic reuse is distinct from direct source reuse: all 16 cases are
selected from the separately owned monolithic adaptation. These results do not
establish other compilers, platforms or sanitizer configurations. The standard
functional pair is now verified and reuses the verified unit builds.
Per-case reports and strict source/build/retained-artifact checks are under
`artifacts/ci-parity-20261010/ubuntu-{unit,wallet-disabled,ipc-disabled,qt,kernel}-{bitcoin,pocx}-checkpoint/`.
Exporting these reports does not rebuild or replay their completed tests.

The standard original functional checkpoint has 269 passes and 15 reviewed
optional skips from its 284 base entries, using the upstream default transport.
The native standard matrix has 280 passes and 15 reviewed optional skips per
transport: 560 passes and 30 skips across 590 case/transport rows. Its passing
rows comprise 200 unchanged original, 312 adapted original and 48 PoCX-only
executions. Original declared entries and native normalized argument cases use
different counting units; these totals are not a one-to-one inventory comparison.

The first native invocation had no failed assertions but unexpectedly skipped
`rpc_bind --nonloopback` in both transports because the local container lacked a
nonloopback interface. With the CI IPv4/IPv6 network restored, all 11 selected
network-sensitive cases pass in each transport except the reviewed compiled-out
ZMQ case. Only those 22 case/transport rows were rerun; the other 568 were reused.
An independent metadata-only check verifies complete case coverage, terminal
process cleanup, skip policy, unchanged sources/build inputs and all retained
artifacts. The immutable `ubuntu-functional-pocx-checkpoint/` binds each row to
its actual full or targeted execution. The original failed envelope and raw
skips remain unchanged. No source, assertion or skip policy was weakened.

The remaining 15 optional skips per transport remain required in the separately
enabled GCC13 optional profile. That original-first pair is now queued behind
shared compilation capacity, using the CI IPv4/IPv6 network, special-address
fixtures, matching-kernel BPF prerequisites and verified previous releases.
Neither this standard checkpoint nor the complete older GCC14 optional proof
establishes the GCC13 optional condition. No additional Actions run was started.

The inherited Clang17/libc++ no-wallet original ctest checkpoint separately
passes 680 unit cases, seven Qt methods, 16 kernel cases and six auxiliary
executables. Its 59 inactive unit cases include 57 wallet cases and two
`DEBUG_LOCKORDER` cases; two wallet Qt methods are inactive. The corrected
Makefiles evidence excludes only regenerated compiler dependency caches, while
declared rules, flags, link commands and binaries remain pinned. Raw failed
envelopes are retained, and the completed ctest cases are reused without replay.
The first original functional transport completed with 362 passes, 80
source-guarded feature omissions and two IPv6 failures (`interface_bitcoin_cli`
and `rpc_bind --ipv6`). The local reproduction omitted the IPv6 Docker network
already configured by `ci/test/02_run_container.py`. Both unchanged failing
cases reproduce before, and pass after, adding a private IPv6 interface.
Recovery uses the actual upstream `ci-ip6net`: all 12 IPv6/interface-sensitive
entries pass, yielding 364 v1 passes and 80 configuration-disabled entries.
The other 432 v1 entries and completed build/ctest are reused. The v2 transport
also completed with 364 passes and 80 configuration-disabled entries, completing
the applicable original baseline. Across both transports, 728 case executions
pass; the 160 inactive entries comprise 146 feature-disabled entries and 14
previous-release/special-address entries required separately in optional profiles.
An independent evidence check binds both CSV inventories, retained logs,
source/build snapshots and the completed ctest checkpoint without replaying a
build or test. The immutable original checkpoint is under
`inherited-nowallet-original-complete-checkpoint/`. Matching native compilation
started after the original gate passed. Its completed ctest phase now separately
passes 670 original unit cases (481 unchanged and 189 adapted), 32 native unit
cases, seven original Qt methods (six unchanged and one adapted), one native Qt
method, all 16 kernel cases and six auxiliary executables. The 59 original unit
cases, one native unit case and two original Qt methods inactive in this feature
configuration remain explicitly accounted for; ten original PoW-only unit cases
are justified exclusions. No active case failed or skipped. The independent
`inherited-nowallet-native-ctest-checkpoint/` binds actual case outputs, command
and artifact hashes, source/build snapshots and runtime inventories without
replaying tests or builds. Matching native functional execution is still running;
this ctest checkpoint does not establish a passing whole native profile.
Raw failures and the environment diagnostic remain under
`inherited-nowallet-ipv6-diagnostic/` and
`inherited-nowallet-ci-network-recovery/` in the artifact directory above.

Inherited functional failure reports retain parsed case rows before rejecting
a failed aggregate or process exit. Original case/transport entries without
valid evidence are explicitly unverified. A failed profile stays failed even
when some cases pass; the original-first gate remains strict. This reporting
correction changes no test assertions, selection or successful commands.

`required-ci-coverage/results.json` and `frameworks.csv` in the same artifact
directory inventory 22 owned profiles, 36 original/native inherited matrix
conditions and the runtime-expanded ancestor-commit job. They distinguish
configured coverage, scoped completed frameworks and complete profiles. Missing
runtime counts remain unknown; case catalogs are referenced rather than inventing
passes or combining benchmark/transport counting units. The single hosted
original unit baseline described below passes within its recorded scope; other
hosted conditions remain unverified. The goal remains active.

The original LLVM22 ASan build has a scoped passing checkpoint for all739
applicable original unit cases, all9 Qt methods, all16 kernel cases and all6
auxiliary CTest executables. The two additional original unit cases are compiled
only with `DEBUG_LOCKORDER`; the immutable737-case Release baseline is unchanged.
The corrected unit checkpoint reuses738 passing leaves and reruns only the
external-vector case that initially skipped because its artifact driver omitted
`DIR_UNIT_TEST_DATA`. The earlier failed/incomplete reports remain preserved.
Qt/kernel corrections execute the already verified build at the inherited512KiB
test stack limit. Build tools receive8MiB in their own subprocess; callers and
tests retain the restricted stack. The complete applicable original ASan
baseline now passes strict verification: both functional transports pass all
459 original cases each, with zero skips. The independent native-start gate
revalidates all corrected framework cases, full functional outputs, sanitizer
controls and unchanged source/build inputs. No completed tests or builds are
replayed. Its immutable `asan-original-complete-checkpoint/` combines 739 unit,
nine Qt, 16 kernel, six auxiliary and 918 functional case/transport rows, with
no failed, skipped or unverified applicable cases. The raw legacy wrapper
envelope remains failed and unchanged; the complete checkpoint explicitly binds
those raw bytes and the successful corrected evidence. Matching PoCX ASan is
queued behind compilation capacity after this original gate passes; native and
hosted sanitizer results remain unverified.

The complete original TSan baseline now passes strict verification. Its 737
active original unit cases, six auxiliary CTests, 16 kernel cases and all 459
functional cases in each transport pass with zero skips. Two original
`DEBUG_LOCKORDER` unit cases are configuration-inactive; Qt is explicitly disabled
by this upstream sanitizer recipe. The original raw CI envelope also passes.
The independent `tsan-original-complete-checkpoint/` binds every case, both full
functional inventories, actual instrumentation controls, unchanged source/build
inputs and retained artifacts. Exporting it neither reruns tests/builds nor
reexecutes the already passed native-start gate. Matching PoCX TSan started only
after that complete original gate passed and is queued behind shared compilation
capacity. Its runtime and hosted coverage remain unverified.

The original MSan build and runtime unit entrypoint pass all 739 original cases
across 149 suites, with no failures, skips or exclusions. MSan dependencies,
including all three selected libevent component archives, and instrumented C++
controls pass. Its six auxiliary executables and 16 kernel cases also pass;
the full functional matrix is still running. The first transport independently
passes all 459 original functional cases without skips; the second remains
incomplete. Its retained `msan-original-functional-progress/` binds completed
group logs, case inventories and source/build inputs, with the remaining 459 rows
explicitly unverified. No completed test or build is replayed when exporting
these checkpoints. Case-level unit
checkpoints are retained under
`artifacts/ci-parity-20261010/{tsan,msan}-original-unit-checkpoint/`.
Their revalidation checks recorded source/build inputs and retained execution
artifacts without replaying tests. Unit-only reports retain their original scope;
the separate complete ASan/TSan checkpoints establish their applicable original
profiles. PoCX sanitizer execution is not established by original-only evidence.
Auxiliary/kernel case reports are retained in the corresponding
`{tsan,msan}-original-aux-kernel-checkpoint/` directories.
Controls are prerequisite checks and never count as passing framework cases.

Actions dispatch now succeeds, resolving the earlier repository-disabled
response. The single authorized original unit baseline passed and is documented
below. Other hosted and target-platform conditions remain unverified; neither
that limited run nor local evidence establishes them.

The scheduled/manual `asan` job uses the inherited Clang 22 configuration:
`address,float-divide-by-zero,integer,undefined`, shared libraries, C++23,
pattern initialization, arena checks and lock-order checks. It runs complete
unit, auxiliary, Qt, kernel and optional functional selections. The original
profile must pass before PoCX starts. Missing tools reject the profile; there
is no fallback to an unsanitized build or an older compiler.

`sanitizer-ci.json` pins the inherited recipes and suppression files. The
sanitizer gate checks first-party C++ compilation flags and sanitizer symbols
in required executables, then verifies six runtime canaries: clean execution,
address bounds, integer overflow, signed overflow, floating-point division by
zero and memory leaks. Each intentional error must fail with its own diagnostic;
an unrelated environment failure cannot satisfy a canary. These checks are
infrastructure evidence, not additional Bitcoin/PoCX test cases. They do not
establish sanitizer coverage of Rust or vendored dependencies.

Runtime controls replace inherited environment overrides with fatal error/leak
settings and the reviewed upstream suppressions. All sanitizer profiles enforce
the inherited 512 KiB runtime stack limit, recorded and checked independently
by the parent and runtime gate. Unit, Qt and kernel retain the
inherited 2400-second sanitizer timeout. Functional waits scale by40; format6
records the scaling separately from case identity and verifies the actual
executed flag. Ordinary profiles retain their existing timeout defaults and
format5 evidence. Fuzz remains explicitly disabled in this package.

The local Clang 22 environment passes all six ASAN/UBSAN/LSAN runtime canaries
and a live BPF tracing prerequisite check. The complete applicable original ASan
baseline is verified as described above; matching native execution is pending
and hosted sanitizer execution remains unverified.
Toolchain provisioning follows the [LLVM package repository](https://apt.llvm.org/);
runtime controls follow the inherited recipes and the official
[ASan](https://clang.llvm.org/docs/AddressSanitizer.html) and
[UBSan](https://clang.llvm.org/docs/UndefinedBehaviorSanitizer.html) documentation.

The `bitcoin-tsan`/`pocx-tsan` and `bitcoin-msan`/`pocx-msan` profiles reproduce
the inherited headless configurations. Qt is explicitly configuration-disabled
because both upstream jobs set `BUILD_GUI=OFF` and depends `NO_QT=1`; its cases
remain required in the Qt and ASan profiles. Unit, auxiliary libraries, kernel,
and the full optional functional selections in both transports remain required.
Every applicable skip fails. The original profile must pass before PoCX runs.

`prepare_instrumented_dependencies.py` builds a separate libc++ runtime and the
inherited depends recipes in a fresh directory. LLVM22.1.0 source is checked
against the SHA256 published with its [official release assets](https://github.com/llvm/llvm-project/releases/expanded_assets/llvmorg-22.1.0).
The review pins88 recipe/suppression files. TSAN instruments the C++ dependencies;
MSAN also instruments C dependencies and retains origin tracking at level2,
the debug configuration and fortify controls. Native code generators remain host
build tools. Reusing system C++ libraries or an uninstrumented dependency prefix
cannot satisfy these profiles.

The 2026-10-10 local dependency reuse check confirms 14,752 checked runtime,
libc++, ABI, unwind, CMake and LLVM-header source files and their modes match
the original installer's `llvmorg-22.1.0` tag in both retained preparations.
The strict dependency checker also revalidates 6,430 installed inputs per profile,
the build logs, compiler identities, required sanitizer symbols and original
explicit libc++ configuration. A separate image adds only the original LLVM 22
compiler/symbolizer aliases; each resolves to the unchanged versioned binary.
No dependency build or original test baseline was replayed. The source and
installed-input proofs are retained under `artifacts/ci-parity-20261010/` in
`libcxx-upstream-tag-source-audit/` and
`sanitizer-inherited-dependency-input-checkpoint.json`. These prove prerequisites
for reuse; complete inherited sanitizer entrypoint execution remains unverified.

For example, after installing Clang22 and all runtime prerequisites:

```sh
python3 test/pocx/prepare_instrumented_dependencies.py --sanitizer tsan --directory .ci-instrumented-tsan --jobs 4
python3 test/pocx/ci.py --profile bitcoin-tsan --instrumented-dependencies-dir .ci-instrumented-tsan --previous-releases-dir releases --jobs 4
# Run only after the complete matching original baseline passes:
python3 test/pocx/ci.py --profile pocx-tsan --instrumented-dependencies-dir .ci-instrumented-tsan --previous-releases-dir releases --jobs 4
```

The runtime gates require complete executable inventories, preserved compile
flags, instrumented dependency/libc++ symbols, and correct diagnostics from a
clean canary plus a deliberate race or uninitialized read with origin information.
An unrelated runtime/environment error never counts as successful detection.
Runtime controls are fatal, timeouts scale by40, and the upstream512KiB stack
limit is retained. Canaries are infrastructure checks, not Bitcoin/PoCX cases.
See the official [TSAN](https://clang.llvm.org/docs/ThreadSanitizer.html) and
[MSAN](https://clang.llvm.org/docs/MemorySanitizer.html) documentation.

The scheduled/manual `instrumented-sanitizers` job provisions these dependencies
and runs each original/native pair in order. Its execution is unverified.
C++ instrumentation does not establish Rust sanitizer instrumentation; no
passing native sanitizer or hosted result is inferred from this implementation.

The inherited POSIX entrypoint now selects `inherited_ci.py` after the existing
container and dependency setup. It builds and tests Bitcoin with `ENABLE_POCX=OFF`
before starting the matching PoCX configuration. The original
`ci/test/03_test_script.sh` stays unchanged; the owned recipe preserves its build,
dependency and analysis settings and selects strict framework verification.
Dedicated fuzz jobs still use the original driver. Framework pairs explicitly
disable fuzz binaries on both sides.

An owned imagefile preserves the original environment scripts at their declared
paths, including the ASAN tracing wrapper. The eight inherited Linux functional
recipes with USDT receive BCC bindings/tools and isolated container kernel access
through a shared environment helper. The workflow provisions matching host kernel
headers; headers and modules are mounted read-only. Original compiler, dependency,
feature and test settings remain unchanged. Build-only and dedicated fuzz jobs
retain their environments. Docker input-stage checks verify copying and sourcing
for all eight recipes; they do not establish package installation, BPF execution
or framework/hosted success.

The same helper supplies Python ZeroMQ where Debian/Ubuntu recipes omitted it.
For ARM and previous-release recipes with IPC enabled, it also installs pip and
requests `pycapnp==2.2.4` when the original pip requirements contain no pycapnp.
The i686 recipe keeps IPC disabled and needs no Cap'n Proto binding. Existing
Python requirements are preserved; Ubuntu22.04's older pip does not receive the
unsupported `--break-system-packages` option. Added pip requirements are exported
through host/container setup as well as sourced inside image construction.
These prerequisites enable required tests; they do not themselves establish a
passing framework configuration.

Inherited functional execution preserves CLI and multiprocess settings and runs
the extended inventory with both transports. Tests guarded by features explicitly
disabled in that build are recorded as configuration-disabled and remain required
in their enabled profiles. Missing prerequisites for an enabled feature fail the
job. Format7 binds CLI and multiprocess settings to the executed command without
changing test identities.

Success and failure reports, framework XML/CSV, and execution logs are published
under `artifacts/pocx-inherited`. Container jobs export them before cleanup, and
the inherited POSIX workflow uploads them even after test failure. Collection
retains newly created report trees to a bounded depth; node data and build products
are excluded. Infrastructure checks exercise ordering, report retention and failure
propagation. Actual inherited recipes, platform execution, and hosted artifact
upload remain unverified; configured coverage does not establish execution.

Ancestor-commit CI selects `revision_ci.py`, preserving the unchanged upstream
executor's compiler flags and verbose build fallback. Each revision must pass
Bitcoin's strict unit/Qt/kernel/auxiliary and both-transport extended functional
selection before PoCX starts. Fuzz is explicitly disabled in this framework pair.
The hosted job provisions BCC, matching kernel headers and pinned pycapnp; original
USDT tests require root, so the hosted revision step runs with that prerequisite.
Published reports have readable artifact permissions after root execution. This
does not authorize running that elevated CI recipe locally. Actual ancestor CI,
BPF execution and artifact upload remain unverified.

For a limited hosted baseline, dispatch `ci.yml` with `baseline_only=true`.
This runs one Ubuntu24 original `bitcoin-unit` job with two build jobs and
uploads the actual unit/auxiliary reports and logs. It does not launch the
inherited matrices or PoCX jobs. The option defaults to false; ordinary pushes,
pull requests and default manual dispatch preserve all existing CI coverage.
A successful limited run proves only that original unit configuration, not
Qt, kernel, functional, sanitizer or other-platform coverage.

The limited [hosted baseline run 38055605854](https://github.com/PoC-Consortium/bitcoin/actions/runs/38055605854)
passed on 2026-10-10 at commit `71b1fcd1bd5b80ae2245a45eab2fdcd2125b008e`.
Its Ubuntu24/GCC13 Release build had PoCX disabled, wallet and IPC enabled,
and two build/test jobs. Archived Boost and JUnit results independently confirm
737 original unit cases in 149 suites and all six auxiliary CTest executables
passed, with zero failures or runtime skips. The remaining two cases in the 739-case
original catalog require `DEBUG_LOCKORDER` and are inactive in this Release build;
they remain required in enabled configurations.

The archive contains the raw reports and logs. All 12 recorded profile artifacts
and 2822 recorded source hashes were rechecked against that revision. The successful
hosted collector verified the runtime inventory, binary and configuration before
upload. Binary and CMake-cache bytes were not uploaded, so the downloaded reports
do not provide an independent local inspection of those bytes. This checkpoint
establishes only the selected original unit profile; every other hosted condition
remains unverified. No additional Actions run was launched for this checkpoint.

The inherited IWYU recipe retains its original fatal enforced analysis and later
warning analysis. The warning phase applies include suggestions and prints a diff,
which previously made the owned source guard reject an otherwise successful
baseline. The controller now retains a per-consensus suggestions patch with
original/analysis hashes, then restores the exact input C/C++ bytes and modes
before the next consensus phase. A failed enforced analysis remains failed and
never starts native analysis. Changes outside C/C++ inputs, and source edits in
other recipes, still fail the ordinary source guard. These are verified controller
contract checks; complete IWYU tool/source execution remains separately required.

Original i686 tracing uses a private, reviewed test view when USDT is enabled.
BCC compiles BPF for the host ABI, but the 32-bit daemon supplies four-byte
pointers and `size_t` arguments. Reading them directly into the original
eight-byte event fields returns an error. The shared `framework/bpf_abi.py`
adapter reads each argument using its actual BCC-declared type before assigning
the original field. It preserves reader errors, event layouts and assertions;
64-bit BPF programs pass through byte for byte. Unsupported or ambiguous input
fails instead of silently bypassing tracing.

Five separate original test copies change only the BPF constructor import.
`original_usdt.py` verifies their original/replacement hashes and normalized AST,
stages an isolated view, links the unchanged build, and verifies all inputs again
after both transports. Original tracked tests and binaries remain unchanged.
The same helper serves PoCX's two existing tracing adaptations and three shared
original tracing copies. All 295 native case identities and argument variants
remain selected; the three entries moving from reused to adapted change their
manifest iteration order.

On 2026-10-10, the five corrected original i686 tracing cases passed against the
existing binary with the CI's 512 KiB stack limit. Independent reconciliation
retained 445 prior passes and nine explicit configuration-disabled entries:
450 first-transport passes, nine inactive entries, zero failures. No completed
build, CTest phase or unaffected functional case was rerun. The raw failed recipe
and failure logs remain retained. The missing second transport is running;
complete i686 baseline and native execution remain unverified. Fourteen adapter
checks, 47 inherited controller checks, nine Windows controller checks, the
affected artifact/previous-release checks, source drift checks and focused pinned
Python lint passed. Isolated real-BCC canaries additionally verify the 32-bit
repair and unchanged 64-bit behavior; they do not substitute for domain tests.

The Ubuntu22.04 previous-release profile exposed a separate environment issue:
its BCC0.18 compiler predefines three byte-swap macros now defined by Linux6.12
headers, and omits x86 control-flow protection required by `nocf_check`.
The original runner rejects their compiler warnings on stderr. The owned
`framework/bcc_headers.py` backports modern BCC's removal of those predefines
and its `-fcf-protection` setting. It selects only the verified BCC0.18.0,
Linux6.12, x86_64 host pairing. Warnings remain enabled; other environments
retain their existing flags. ELF64 BPF source remains byte-identical.

The original private-view mechanism also selects this environment. No original
script, assertion, daemon, build configuration or previous-release binary is
changed. An actual old-image compiler probe and the production constructor
both emit identical BPF instructions with empty stderr. All five affected
original tracing cases then passed with the inherited512KiB stack and both
previous-release and coverage options enabled. Retaining452 previous passes
and two explicit inactive entries gives457 first-transport passes and no
remaining first-transport failures. The five-case repair retains its expected
partial-selection RPC coverage failure; the unchanged original full-selection
RPC coverage passed and remains independently required. The missing full
second transport is running with strict RPC coverage; the complete baseline
and native previous-release profile remain unverified. Sixteen BCC/staging
checks,47 inherited-controller checks, artifact/previous-release fixture
checks, source drift and focused pinned Python lint passed.

Shared CI lint preserves the original locale checker unchanged. Its separate
`lint/locale_dependence.py` policy copy transfers Bitcoin's existing exception
for `atoi64_legacy` to the same independent reference in the adapted unit file.
The original reference and complete locale test, including60 assertion calls,
remain byte-identical. The exception matches only the exact filename and one
complete call line. The checked original/copy source hashes and normalized
checker AST reject altered references, assertions, scanner rules, additional
exceptions and duplicate calls. Other locale-dependent uses remain failures.
The shared Rust entrypoint delegates only this checker through the separate
`lint/dispatch.rs`; all other original Python linters run directly. A missing
owned checker fails. Infrastructure checks exercise real checker exits for
new violations as well as source-policy rejection; they do not rerun units.
