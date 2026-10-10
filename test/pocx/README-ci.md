# Bitcoin and PoCX CI verification

`ci.py` provides Linux entry points for the completed test packages. The workflow
in `.github/workflows/pocx-tests.yml` runs original Bitcoin baselines before the
matching PoCX jobs. The scheduled/manual feature jobs include both sides of the
Qt, kernel, wallet-disabled and IPC-disabled configurations. A configured job is
not passing evidence until it has actually executed successfully.

The inherited workflow also includes the original 32-bit x86 without IPC and
previous-release compatibility profiles. Both retain their upstream environment
scripts and run through the Bitcoin-first PoCX controller. The previous-release
job retains its compiler, unsigned-char checks and RPC coverage settings. These
profiles require actual hosted build and runtime evidence; restoring a matrix
entry does not establish a passing result.

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

These focused local results do not establish complete optional-profile or hosted
CI success. The complete original v1 selection reuses unchanged passing cases
and focused corrections for environment failures. The previously missing full
v2 selection now passes, including all 40 database-crash iterations and both
special-address cases: 459 original cases per transport. The complete native
optional CI entry point remains in progress.
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

Required platform and sanitizer coverage remains broader than these local
checkpoints. Local wallet-enabled and wallet-disabled unit baselines and their
PoCX counterparts now pass with working socket/IPC prerequisites. The disabled
wallet checkpoint has 680 original passes; PoCX has 670 original passes and 32
native passes, with ten reviewed PoW exclusions. The 57 original wallet cases
and one additional native wallet case are configuration-disabled in that profile.
The local GCC14 result does not establish the inherited Clang/libc++ no-wallet
configuration. Local Qt/kernel proof likewise does not establish the complete
platform matrix. Dated artifacts retain exact executed configurations; the goal
remains active.

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
and a live BPF tracing prerequisite check. The original full ASAN build and
framework execution remain in progress; hosted execution remains unverified.
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
