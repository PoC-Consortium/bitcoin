# Kernel API baseline and PoCX parity

Verified on 2026-10-09 against original Bitcoin Core v31.1 revision
`9be056a8a72b624dae9623b2f7bded92c2a21c91`, using this fork at
`2019969136` with `ENABLE_POCX=OFF`. The profile is Linux Release, kernel
library/tests enabled, wallet/IPC/tests enabled, and GUI/fuzz/USDT disabled.
Only the kernel API target was built and executed for this checkpoint.

The fixed inventory in `kernel-baseline.json` contains **16 original Boost test
cases**. CTest registers one executable that runs all 16. The fresh run passed
all 16 cases and **3,582 assertions**, with zero failures, skips, inactive cases,
expected failures or missing cases. Runtime registration and detailed individual
case results match the independently extracted upstream case list exactly.

`src/test/kernel/test_kernel.cpp`, `block_data.h` and `CMakeLists.txt` all match
upstream byte-for-byte. The original public C and C++ wrapper headers also match
upstream. No inline PoCX adaptation remains in the original kernel test sources.
The actual kernel test/library compiler dependency graph contains 133 translation
units, with no selected PoCX source or `ENABLE_POCX` compiler definition.

The cases cover transactions, inputs/outputs, scripts and script verification;
logging and context setup; block headers, blocks and hashes; and chain managers,
block-tree entries, mainnet/regtest fixtures, in-memory state and persistence.

## Reproduce

```sh
cmake -S . -B build-kernel-bitcoin-baseline -G Ninja \
  -DCMAKE_BUILD_TYPE=Release -DENABLE_POCX=OFF \
  -DBUILD_KERNEL_LIB=ON -DBUILD_KERNEL_TEST=ON -DBUILD_TESTS=ON \
  -DENABLE_WALLET=ON -DENABLE_IPC=ON -DBUILD_GUI=OFF \
  -DBUILD_BENCH=OFF -DBUILD_FUZZ_BINARY=OFF -DWITH_ZMQ=OFF -DWITH_USDT=OFF
cmake --build build-kernel-bitcoin-baseline --target test_kernel -j 3
ctest --test-dir build-kernel-bitcoin-baseline/src/test/kernel \
  -R '^test_kernel$' --verbose --timeout 180 --no-tests=error
```

The retained audit additionally enables Boost's detailed XML report and checks
its exact 16-case membership, results and assertion counts. Full configure/build
commands, compiler-source audit, runtime listing, CTest XML/log and Boost XML are
in `artifacts/kernel-baseline-20261009/`; `verification.json` summarizes them.

## PoCX review and execution

The fresh PoCX rebuild and complete run on 2026-10-09 passed all **16 original
cases and 20,703 assertions**, with zero failures, skips, missing cases, expected
failures or exclusions. CTest runs one wrapper; the detailed Boost XML establishes
individual case membership and success. The run took approximately 185 seconds.

| Original-case category | Cases | Green | Red / inactive |
| --- | ---: | ---: | ---: |
| Original case logic unchanged | 10 | 10 | 0 |
| Adapted fixtures or checks | 6 | 6 | 0 |
| Disabled, needs repair | 0 | 0 | 0 |
| Excluded as inapplicable | 0 | 0 | 0 |
| Additional PoCX-only cases | 0 | 0 | 0 |

The ten unchanged cases cover transactions, scripts, logging, context, basic
chain-manager setup and block hashes. The six adapted cases are `btck_block`,
`btck_block_header_tests`, `btck_chainman_mainnet_tests`,
`btck_block_tree_entry_tests`, `btck_chainman_in_memory_tests` and
`btck_chainman_regtest_tests`. `kernel-parity.json` lists every case and its
ownership; `kernel/parity.json` explains the individual adaptations.

All 16 cases are currently compiled from one PoCX-owned copy of the upstream
translation unit. Thus ten unchanged case bodies/logic do **not** mean ten cases
directly reused from the original file: direct original-source reuse is zero.
The original file combines generic and block/chain tests, shared helpers and
fixtures. There are no inline PoCX changes in the original test sources.

Bitcoin PoW fixtures were replaced with actual signed PoCX proof blocks: one
mainnet block and a 206-block regtest chain. Header/accessor expectations follow
the PoCX layout and existing C API, including zero legacy `Bits()` and `Nonce()`.
All original checks remain; added checks reject every truncated native header,
require successful block acceptance and validate lookup reads. The transaction
lookup helper caches blocks on this fixed chain to avoid repeated proof work.
Explicit full-chain disk reads and post-file-deletion rejection checks remain
uncached, as do their assertions. Assertion totals alone do not establish parity.

The fixture bytes match the independently verified frozen snapshot exactly.
Fresh Python checks verified all 207 proofs' chain context and deterministic
header rendering. Earlier scalar/public Rust proof comparisons remain applicable
to those unchanged bytes and verifier sources; they were not rerun in this review.
See [kernel/README.md](kernel/README.md) for the reference verification procedure.

## Reproduce the native package

```sh
cmake -S . -B build-ci-pocx-kernel -G Ninja \
  -DCMAKE_BUILD_TYPE=Release -DENABLE_POCX=ON \
  -DBUILD_KERNEL_LIB=ON -DBUILD_KERNEL_TEST=ON -DBUILD_TESTS=ON \
  -DENABLE_WALLET=ON -DENABLE_IPC=ON -DBUILD_GUI=OFF \
  -DBUILD_BENCH=OFF -DBUILD_FUZZ_BINARY=OFF -DWITH_ZMQ=OFF -DWITH_USDT=OFF
python3 test/pocx/run_kernel.py --build-dir build-ci-pocx-kernel \
  --output-dir artifacts/kernel-package-20261009 --jobs 3
python3 test/pocx/kernel_parity.py --check
python3 test/pocx/kernel_parity.py --build-dir build-ci-pocx-kernel \
  --results artifacts/kernel-package-20261009/verification.json
python3 test/pocx/test_kernel_infrastructure.py build-ci-pocx-kernel \
  artifacts/kernel-package-20261009/verification.json -v
```

The standalone runner rebuilds the target, clears inherited Boost controls,
records binary/configuration/source hashes and checks both XML reports. The
guards reject changed sources, missing cases, skips, failures and stale evidence.
Seven infrastructure checks exercise those failure paths and fixture rejection.
This kernel package does not require the pending combined CI runner.

`kernel-verification.json` records the maintained summary. Detailed source review,
compiler audit, fixture checks and the initial fresh execution are retained in
`artifacts/kernel-pocx-review-20261009/`; the standalone runner's execution is in
`artifacts/kernel-package-20261009/`.

This establishes parity with the original kernel API suite for this Linux Release
profile. Extra coverage for PoCX signer transitions/revocations, competing
branches, scheduler behavior and persistence faults remains separate work.
