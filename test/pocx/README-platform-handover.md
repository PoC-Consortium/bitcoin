# Windows and macOS test handover

For the current Actions organization, read [README-workflows.md](README-workflows.md).
`CI` selects Bitcoin OFF and `CI-POCX` selects PoCX ON independently through the
shared workflow. The paired local commands below remain supported when
`CI_PRODUCT` is unset. Portable status/checksums below record the earlier Linux
milestone; they are not refreshed execution claims for subsequent platform or
workflow commits. Preserve other sessions' checkouts and generated builds.

The Linux/current-machine milestone is complete. Continue target-native
verification from this repository; establish each target's original Bitcoin
baseline with `ENABLE_POCX=OFF` before its matching PoCX phase. The paired
runners below enforce that order.

## Repository and starting state

Clone **PoC-Consortium/bitcoin**, branch
`test/pocx-ci-parity-20261010`. The separate `bitcoin-pocx` wrapper's default
submodule pointer does not select this work.

```sh
git -c core.autocrlf=false clone --branch test/pocx-ci-parity-20261010 https://github.com/PoC-Consortium/bitcoin.git bitcoin-pocx-tests
cd bitcoin-pocx-tests
git config core.autocrlf false
git rev-parse HEAD
```

Use a short ASCII checkout path, for example `C:\src\pocx` on Windows or
`~/src/pocx` on macOS. LF bytes are required by source-hash guards; set
`core.autocrlf=false` before the first checkout. A normal clone includes the
history needed to inspect the milestone. Work on separate platform branches:

```sh
git switch -c test/pocx-windows-native
# On the Mac instead:
# git switch -c test/pocx-macos-native
```

The verified code/provenance milestone is commit
`c6576ae3e10665af15a2699d097652914baa9cae`. The publication commit adds only
handover documentation and status records. `handover/verified-source-files.json`
records the milestone's tracked-file hashes; subsequent runtime/source changes
must be assessed for their effect on retained results.

The previous goal closed 49 current-machine conditions and 135 required
framework/configuration entries. PoCX ASan passed 590/590 functional entries.
Its original-slot mapping has 1,676 passes and 12 reviewed PoW exclusions;
82 PoCX-only slots pass. Counts repeat across CI configurations, and named
benchmark slots are not additional aggregate executions.

Portable records:

- `handover/status.json`: scope, counts, source identity and evidence limits.
- `handover/framework-parity-counts.csv`: counts by framework/configuration.
- `handover/fully-enabled-framework-overview.csv`: fully enabled ASan overview.
- `handover/deferred-conditions.csv`: all ten platform conditions plus history.
- `handover/SHA256SUMS`: checksums of the portable records and prompts.

## What needs copying from the Linux machine?

| Work | Fresh clone sufficient? | Additional inputs |
|---|---|---|
| Native Windows VS/MSVC original/PoCX pair | Yes, with normal build dependencies and network access | vcpkg dependencies and pinned unit assets are provisioned locally |
| Native macOS original/PoCX pair | Yes, with normal build dependencies and network access | Homebrew dependencies and pinned unit assets are provisioned locally |
| Windows UCRT/MSVCRT artifact runtime pairs | Source is sufficient to rebuild the inputs; the consumer also requires binary packages | One verified Bitcoin/PoCX cross-build bundle per CRT, produced by WSL/Linux or obtained from a matching producer |
| Independently re-audit all previous Linux execution evidence | No | Retained raw reports, logs and build/source provenance on the Linux machine |

No existing node databases, wallets, private keys, plot files, compiler caches,
Docker overlays or wrapper-repository scripts are required for fresh native
testing. PoCX real-proof vectors and kernel fixtures are checked in. External
unit vectors are downloaded and checksum-verified by `unit_assets.py`; previous
release binaries, where the profile requires them, come from the unchanged
downloader. Offline runs require provisioning these public dependencies first.

The small records in Git are a portable handover summary, not a substitute for
the full Linux execution evidence. The original evidence remains at
`bitcoin-tests-m0-m1-20261007/artifacts/ci-parity-20261010/` on the Linux machine;
its final index is `current-required-ci-evidence-v160/results.json`. Absolute
paths in historical proofs describe that machine and should not be rewritten
to fabricate evidence on a new host. Native test execution does not need them.
For a later full audit, preserve that directory and the source/build inputs
referenced by its index, including references outside the artifact directory.
The compact handover files do not contain those binaries or raw logs.

## Windows: native VS/MSVC pair (two conditions)

Use real Windows x64 and Developer PowerShell with the toolchain selected by
`CMakePresets.json`: Visual Studio 2026, the C++ desktop workload, Windows SDK
(`mt.exe`), CMake, Git, Python and vcpkg. Read `doc/build-windows-msvc.md` for
the repository's version requirements. Record the actual Windows version,
compiler, SDK, Python, vcpkg revision, memory and free disk space. The workflow
uses `windows-2025-vs2026`; record differences from that environment explicitly.

Set `VCPKG_ROOT` to the installed vcpkg directory. Reproduce the vcpkg
release-build and CMake/libevent compatibility settings from the
`windows-native-dll` job in `.github/workflows/ci-product.yml` when applicable; use a
dedicated vcpkg installation rather than editing a shared installation blindly.
Do not replace the required `vs2026` dynamic-library preset with a static or
GUI-disabled build to work around failures.

From the checkout in Developer PowerShell:

```powershell
$env:PYTHONUTF8 = '1'
$env:PYTHONDONTWRITEBYTECODE = '1'
$env:TEST_RUNNER_TIMEOUT_FACTOR = '40'
$env:TEST_RUNNER_EXTRA = '--timeout-factor=40 --extended'
py -3 test/pocx/windows_ci.py --plan --jobs 2
py -3 test/pocx/windows_ci.py --jobs 2
if ($LASTEXITCODE -ne 0) { throw 'Native Windows verification failed; preserve its evidence.' }
```

The plan validates recipes and reports commands; it is not execution evidence.
The real run builds the complete Bitcoin-OFF phase before PoCX-ON, including
manifest checks, real Windows process-lifecycle checks, unit, Qt, kernel,
auxiliary and both functional transports. Preserve `artifacts/pocx-inherited/`
and `windows-ci-evidence/` plus raw child reports before cleaning generated data.
Choose concurrency for the machine; do not change test selection or warning
policy. Record execution failures even if their setup is later repaired.

## Windows: UCRT and MSVCRT runtime pairs (four conditions)

These are separate from the VS/MSVC pair. WSL/Linux builds the PE packages;
the tests themselves run on Windows. A Linux or WSL build is not Windows runtime
coverage. Use one immutable paired bundle for each CRT and separate output
directories for their consumers.

With Docker/buildx available in WSL2 or Linux, clone the same published commit
onto the Linux filesystem, not `/mnt/c`. For a fresh UCRT producer:

```sh
export FILE_ENV=./ci/test/00_setup_env_win64.sh
export MAKEJOBS=-j2
export BOOST_TEST_RANDOM=1
./ci/test_run_all.sh
```

The MSVCRT producer uses `FILE_ENV=./ci/test/00_setup_env_win64_msvcrt.sh`.
Use a separate producer checkout for it: publication intentionally refuses to
overwrite an existing `artifacts/pocx-inherited/windows-cross-pair`.
Each producer builds both consensuses, deploys and publishes that paired bundle.
Preserve `pair.json`, both payloads and their provenance. Copy the complete
UCRT/MSVCRT bundles into separate directories inside the Windows checkout,
for example `artifacts/windows-ucrt-pair` and `artifacts/windows-msvcrt-pair`.

The bundle's recorded revision must equal the Windows checkout's revision.
**Do not copy old Linux bundles into a newer checkout and edit their metadata.**
Rebuild at the matching revision or perform a separately verified input-reuse
and export operation. Existing Linux bundles are optional reuse candidates,
not automatically valid inputs for the publication commit.

In Developer PowerShell, install Python ZMQ and checksum-verified Windows
previous releases, then run one paired consumer per CRT:

```powershell
py -3 -m pip install pyzmq
$env:PREVIOUS_RELEASES_DIR = "$PWD\prev_releases"
$env:TEST_RUNNER_TIMEOUT_FACTOR = '40'
$env:TEST_RUNNER_EXTRA = '--timeout-factor=40 --extended'
py -3 test/get_previous_releases.py --target-dir "$env:PREVIOUS_RELEASES_DIR"
py -3 test/pocx/windows_artifacts.py --verify artifacts/windows-ucrt-pair
py -3 test/pocx/windows_artifact_ci.py --artifacts artifacts/windows-ucrt-pair --output artifacts/windows-ucrt-runtime --timeout-factor 40 --jobs 2
if ($LASTEXITCODE -ne 0) { throw 'Preserve failed UCRT runtime evidence.' }
py -3 test/pocx/windows_cross.py --collect-runtime artifacts/windows-ucrt-runtime --output artifacts/windows-ucrt-evidence
```

Repeat verification, execution and collection for MSVCRT with its own paths.
Check each prerequisite command's exit status before proceeding. The workflow
reference is `windows-native-test` in `.github/workflows/ci-product.yml`, with its
`windows-2022` environment. Preserve actual environment differences. The
collector retains bounded evidence; collection alone is not a test pass.

## macOS: native ARM64 pair (two conditions)

The deferred CI job is **native Apple Silicon**, configured as macOS 15 and
Xcode 16.2. An Intel Mac, cross-build or Rosetta process does not verify that
ARM64 condition. Record `uname -m`, `sw_vers`, `xcodebuild -version`, compiler
and SDK information. If the host differs from the configured environment,
report the difference and qualify coverage rather than silently marking the
exact CI environment passed.

Use a dedicated test account. The inherited host CI script deliberately creates
a sentinel at the default Bitcoin data path; inspect that behavior before
running it in an account used for real wallets or nodes. Keep personal data
separate without changing the user's home environment variable.

Install the packages used by the `macos-native-arm64` workflow, plus CMake if it
is not already installed:

```sh
brew install cmake python@3 coreutils ninja pkgconf ccache boost libevent zeromq qt@6 qrencode capnp
```

Select the matching installed Xcode toolchain, then run the inherited entrypoint
from the checkout as the dedicated test user:

```sh
export DANGER_RUN_CI_ON_HOST=1
export BASE_ROOT_DIR="$PWD"
export FILE_ENV=./ci/test/00_setup_env_mac_native.sh
export MAKEJOBS=-j2
export BOOST_TEST_RANDOM=1
export PYTHONDONTWRITEBYTECODE=1
./ci/test_run_all.sh
```

This invokes the original-first owned POSIX driver after dependency setup.
Preserve the recipe's GUI, wallet, IPC, ZMQ, deployment and 512 KiB linker-stack
settings, and keep fuzz disabled through the owned non-fuzz driver. Verify
install/deploy checks and all applicable frameworks in both consensuses and
functional transports. Results are published under `artifacts/pocx-inherited/`;
retain the underlying `ci/scratch/` reports and relevant logs as well.

## Reporting and coordination

Use `handover/windows-session-prompt.txt` or `handover/macos-session-prompt.txt`
to start the platform session. First inspect the host and run a plan/source
check; these instructions do not claim target-native tests already passed.

Keep original sources and assertions intact. Put PoCX adaptations in separate
files and justify replaced-PoW exclusions individually. Preserve failing runs.
Do not weaken flags, omit cases or turn missing prerequisites into passes.
Report inventory, unchanged/adapted passes, failures, raw skips, inactive cases,
exclusions and PoCX-only outcomes per framework and configuration. Determine
inventories from the target configuration; Linux counts are not assertions
about an unexecuted Windows or ARM64 inventory.

Reuse results only when source, compiler inputs, dependencies and execution
conditions remain applicable. After a repair, run focused affected checks first.
If shared code changes, list the Linux conditions needing revalidation; avoid
rerunning all Linux baselines for target-only adaptations. Keep Windows and Mac
repairs on their separate branches, and coordinate shared-file changes before
combining them.

The two Linux ARM conditions remain deferred after this Windows/Mac work.
Fuzz modernization and intermediate-history testing remain separate. Preserve
existing commits. One batched push publishes all commits; `[skip ci]` can
suppress push/pull-request workflow events during handover, with a deliberate
CI validation run later. Skipped required checks may stay pending until that
validation. Reference: https://docs.github.com/en/actions/how-tos/manage-workflow-runs/skip-workflow-runs
