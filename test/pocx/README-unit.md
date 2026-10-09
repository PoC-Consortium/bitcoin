# Bitcoin and PoCX unit tests

The normal wallet/IPC-enabled profile preserves the original Bitcoin unit tests
with `ENABLE_POCX=OFF`. With `ENABLE_POCX=ON`, it reuses applicable original sources,
selects reviewed PoCX-owned adaptations and adds native tests.

The fixed Bitcoin v31.1 baseline has 737 actual cases. PoCX runs 727 applicable
original cases plus 33 native cases: 760 cases in 154 Boost suites. Ten exact
Bitcoin-only cases are excluded explicitly in `unit-parity.json`: nine SHA256/nBits
proof/retarget tests and Bitcoin Testnet4 sanity. Supported-network sanity and
work/time equivalence remain covered; PoCX's Testnet4 alias has its own test.
The reused/adapted split is 507/220 original cases; shared native fixtures apply
to reused test sources too. These counts exclude Qt, kernel API, fuzz, functional
and six auxiliary library CTest groups.

## Reproduce

Use the repository's normal Linux build prerequisites, including Ninja, Python 3,
Boost, SQLite3, libevent and Cap'n Proto for this wallet/IPC profile. See
`doc/build-unix.md` and `doc/dependencies.md`. Build inside this checkout; keep
its absolute path short enough for Unix-domain IPC sockets. This profile uses
wallet and IPC ON, GUI/kernel/fuzz OFF and USDT OFF.

```sh
cmake -S . -B build-b -G Ninja -DCMAKE_BUILD_TYPE=Release -DENABLE_POCX=OFF -DBUILD_TESTS=ON -DENABLE_WALLET=ON -DENABLE_IPC=ON -DBUILD_GUI=OFF -DBUILD_BENCH=OFF -DBUILD_FUZZ_BINARY=OFF -DBUILD_KERNEL_LIB=OFF -DWITH_ZMQ=OFF -DWITH_USDT=OFF
cmake --build build-b -j 3
cmake -S . -B build-p -G Ninja -DCMAKE_BUILD_TYPE=Release -DENABLE_POCX=ON -DBUILD_TESTS=ON -DENABLE_WALLET=ON -DENABLE_IPC=ON -DBUILD_GUI=OFF -DBUILD_BENCH=OFF -DBUILD_FUZZ_BINARY=OFF -DBUILD_KERNEL_LIB=OFF -DWITH_ZMQ=OFF -DWITH_USDT=OFF
cmake --build build-p -j 3
```

The original script-assets case requires Bitcoin Core's external QA data. Pin
and verify the same data for both configurations; a skipped assets case does
not satisfy the complete PoCX baseline gate.

```sh
mkdir -p build-b/unit_test_data build-b/t
curl --location --fail https://raw.githubusercontent.com/bitcoin-core/qa-assets/0739b29cfb99e8de42298f550e9cdbf1a7659dcf/unit_test_data/script_assets_test.json -o build-b/unit_test_data/script_assets_test.json
python3 - <<'PY'
import hashlib
from pathlib import Path
path = Path('build-b/unit_test_data/script_assets_test.json')
assert hashlib.sha256(path.read_bytes()).hexdigest() == 'cd789a58ec45916e1721cdd14e82ca4c93100959f1cef4e229b22e3bf539f095'
PY
DIR_UNIT_TEST_DATA="$PWD/build-b/unit_test_data" TMPDIR="$PWD/build-b/t" ctest --test-dir build-b -j 3 --output-on-failure --timeout 180 --no-tests=error --output-junit "$PWD/build-b/unit-junit.xml"
DIR_UNIT_TEST_DATA="$PWD/build-b/unit_test_data" python3 test/pocx/run_unit.py --build-dir build-p --all --jobs 3
python3 test/pocx/test_unit_infrastructure.py build-p build-b
python3 test/pocx/unit_parity.py --check
```

A complete Bitcoin CTest run contains 149 original unit suites and six auxiliary
library groups. The PoCX runner's `--all` executes all registered unit suites,
retains their full Boost log/JUnit and checks exact case membership, source/binary
freshness and zero failed or skipped suites. Without `--all`, the default is the
seven-suite architecture smoke selection; use `--suite NAME` for focused runs.
Runners in the same build share a lock, so run infrastructure checks after the
full runner finishes.

`unit-baseline.json` pins the verified original case list. `unit-parity.json`
records applicable cases, explicit exclusions, native additions and reviewed
source hashes. Its review notes explain assertion/precondition adaptations;
source-name presence and passing tests alone are not semantic parity proof.
`restorations.json` records the ten original test/support files restored to
upstream after their owned replacements were reviewed and exercised. All 168
original unit/support source files now match upstream byte-for-byte; the coins
mock signature adaptation is selected from its PoCX-owned source. Reviewed
hashes require an actual review on upgrades; runners never approve changes.

`unit-verification.json` records the completed unit checkpoint and package
verification. Historical references to build/artifact paths in baseline and
provenance records identify retained local audit evidence; raw logs and build
outputs are not required repository files. Fresh commands above produce their
own execution evidence.

The disk-reader fix calls existing PoCX header signature, compression and proof
validation, rejecting non-genesis nonpositive heights. The original storage
rejection assertions are retained, with valid-read and corrupt-native-header
regressions. Existing consensus rule bodies and the Bitcoin disk-read path stay
unchanged. Disk reads now incur native proof-validation work.

Fixed native proof data and independent generation instructions are in
`vectors/README.md`. Normal unit execution does not require Rust. The broader
functional/fuzz migration and optional Qt/kernel profiles are separate work.
