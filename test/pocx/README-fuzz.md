# Fuzz parity and reproduction

The inherited source baseline is Bitcoin Core revision
`9be056a8a72b624dae9623b2f7bded92c2a21c91`. Its 228 declared fuzz targets
include one hidden script-assets minimizer. A normal wallet-enabled build lists
227 runnable targets. The fixed source and target inventory is
[`fuzz-baseline.json`](fuzz-baseline.json); [`fuzz-parity.json`](fuzz-parity.json)
names every reviewed PoCX source choice and exclusion. Counts in reports are
derived from those records and the configured binary.

`ENABLE_POCX=OFF` selects the unchanged inherited fuzz sources and runner.
`ENABLE_POCX=ON` selects `src/pocx/test/fuzz/`. That target reuses original
sources directly, selects PoCX-owned adaptations where needed, and adds native
targets. The original `src/test/fuzz/CMakeLists.txt` is restored to its pinned
Bitcoin content. The build-sidecar `fuzz_provenance` target records the selected
source inputs, CMake cache and linked binary without executing cross-built code.
The strict PoCX runner checks those hashes, exact registered targets, corpus
inputs, target completion and saved logs. A source classification or successful
build is not an execution pass.

| Category | Declared targets | Normal wallet-enabled x86-64 selection |
| --- | ---: | ---: |
| Inherited, reused unchanged | 210 | 209 (one hidden minimizer) |
| Inherited, adapted in PoCX-owned files | 16 | 16 |
| Reviewed PoW exclusions | 2 | 0 |
| Native PoCX additions | 11 | 11 when AVX2 was compiled and available |
| Total executable | | 236 under those conditions |

`pow` checks Bitcoin SHA256/nBits hash thresholds and compact-target
adjustment. `pow_transition` checks the Bitcoin retarget transition period.
PoCX replaces both rules. `pocx_difficulty` checks its target envelope,
retarget and generation signature; generic chainwork arithmetic remains in
the inherited adapted integer and block-index-tree targets. These are two
separate reviewed exclusions, never passing test results. The hidden inherited
minimizer is available only through its specialized corpus workflow. Wallet
targets are configuration-disabled when wallet support is off. SIMD targets
must be reported as inactive if the compiled interface or runtime CPU feature
is unavailable; inactivity is not a pass.

The native additions check these invariants:

| Targets | Invariants |
| --- | --- |
| `pocx_assignment_opcodes`, `pocx_assignment_state` | Independent byte-level OP_RETURN decoding, parser/encoder round trips, assignment activation/revocation boundaries, undo and cache/DB state. |
| `pocx_signature` | Valid owner/delegate compact signatures, effective signer boundaries, mutated header/signature rejection and PoCX domain separation. |
| `pocx_proof_parameters` | Generation-signature parsing, null arguments, compression bounds, scalar quality/deadline, claimed-quality rejection and a two-proof batch compared with independent scalar calls. Full cryptographic fuzz work is bounded to compressions 1 and 2; fixed native vectors cover larger valid compressions. |
| `pocx_shabal`, `pocx_shabal_sse2`, `pocx_shabal_avx2` | Fixed scalar known answer, deterministic lane behavior and SIMD-to-scalar equality over varied whole-block inputs and common prefix modes. |
| `pocx_difficulty`, `pocx_time_bending`, `pocx_compression_bounds` | Native retarget envelope, rolling-window result, generation signature, fixed-point time bending and compression-height boundaries against independent arithmetic models. |
| `pocx_headers_sync_configuration` | Actual PoCX mainnet header-sync resource configuration remains enabled. |

The time-bending oracle uses a small, independent 256-bit integer in its fuzz
source. It does not share the consensus arithmetic implementation and needs no
additional dependency or sanitizer exception.

The inherited `rpc` target uses a PoCX-owned adaptation: the original argument
generator and Bitcoin command classifications remain intact. PoCX read-only
assignment/mining queries are allowed, while wallet transaction creation,
revocation and proof/block submission are explicitly unsafe for this generic
RPC fuzzer. Any new unclassified registered RPC command still fails setup.
The adapted transaction-pool fixture retains its fee and outpoint conservation
assertions, measuring the starting supply from PoCX's actual mature coinbase
outputs and respecting nondecreasing block time. The two snapshot targets
select regtest before their shared helper forges native headers. That helper
indexes each forged block so the height-200 chain uses production PoCX
retargeting. The PoCX-only regtest assumeUTXO checkpoint pins the resulting
height-200 block and serialized UTXO hashes; Bitcoin-OFF keeps the inherited
checkpoint. Fuzzed mock time cannot precede the native fixture tip, allowing
its valid headers to reach snapshot activation. All inherited valid and
invalid snapshot assertions remain selected.

Structured seeds deliberately reach valid assignment, signature, parser and
proof paths in addition to malformed inputs. The staged corpus copies **all**
inherited inputs for each selected target and adds deterministic PoCX seeds.
Its manifest records the qa-assets revision, inherited input hashes, generated
input hashes and generator versions. Report `targets` separately from corpus
files, replay executions and elapsed time: fuzzing has no finite case count.
The wrapper repository's `scripts/` has no Bitcoin fuzz launcher or corpus
generator to migrate. Its separate Rust plotter fuzz projects test the plotter,
not this Bitcoin Core fuzz binary.

The inherited CI matrix has two Linux fuzz configurations (LLVM libFuzzer with
ASan/UBSan/integer checks, and MSan with instrumented libc++), plus native
macOS arm64 and native Windows VS fuzz configurations. CI retains the original
OFF recipes. CI-POCX selects the same four rows with the PoCX sources and
runner. The optional inherited manual Valgrind flag remains available; it is
not added as a push/PR matrix row. No result from another platform is inferred
from a cross build or a syntax check.

For an existing Linux PoCX fuzz build and a local qa-assets checkout:

```sh
python3 -B test/pocx/fuzz_parity.py
python3 -B test/pocx/test_fuzz_parity.py
cmake --build build-fuzz-pocx --target fuzz_provenance -j 2
python3 -B test/pocx/stage_fuzz_corpus.py --build-dir build-fuzz-pocx \
  --upstream build-fuzz-qa-assets/fuzz_corpora
python3 -B test/pocx/run_fuzz.py --build-dir build-fuzz-pocx \
  --corpus build-fuzz-pocx/fuzz-corpus-EXAMPLE/corpus --jobs 2
```

Use the path printed by the staging command in place of `EXAMPLE`. The focused
form appends target names to `run_fuzz.py`; it records a focused selection and
does not claim full coverage. To configure a fresh local build, use
`cmake -S . -B build-fuzz-pocx -DENABLE_POCX=ON -DBUILD_FOR_FUZZING=ON` with
the inherited profile's compiler, sanitizers and other options. Build the
`fuzz_provenance` target before running. The OFF baseline uses the same profile
with `-DENABLE_POCX=OFF` and the unchanged `build/test/fuzz/test_runner.py`.

On native macOS arm64, from the checked-out source tree with the inherited
Homebrew dependencies, run:

```sh
CI_PRODUCT=pocx FILE_ENV=./ci/test/00_setup_env_mac_native_fuzz.sh ./ci/test_run_all.sh
```

On native Windows VS2026 with vcpkg and Python prepared, use the existing
CI entry point in PowerShell from the checked-out source tree:

```powershell
$env:CI_PRODUCT = 'pocx'
py -3 test/pocx/bitcoin_fuzz_ci.py --windows
```

The Windows entry point retains the upstream `vs2026` preset, wallet vcpkg
features, Release build, manifest step and qa-assets checkout. It passes
`--config Release` to the PoCX corpus and runner. On Linux, the inherited MSan
profile can be reproduced with
`CI_PRODUCT=pocx FILE_ENV=./ci/test/00_setup_env_native_fuzz_with_msan.sh ./ci/test_run_all.sh`
after provisioning the instrumented libc++ and dependency environment used by
that recipe. A local MSan binary linked to uninstrumented system libevent can
report a false uninitialized read in the inherited `http_request` target. Use
the recipe's MSan-instrumented depends libraries, including libevent, for a
valid full replay. These platform commands require actual native execution
before their status can become passed.
