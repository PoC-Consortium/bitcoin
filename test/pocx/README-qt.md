# Qt baseline and PoCX ownership cleanup

Verified on 2026-10-09 against original Bitcoin Core v31.1 revision
`9be056a8a72b624dae9623b2f7bded92c2a21c91`, on the implementation worktree at
`4733fb8c0598c38004f7fd8d277da34488be27a2` plus the Qt package prepared for this commit.
The existing build directories were regenerated and incrementally rebuilt before
execution. The Bitcoin run uses this fork with `ENABLE_POCX=OFF`; all original
Qt source/header files were independently compared byte-for-byte with upstream.

The verified profile is Linux, Qt 6.8.2, Release, with GUI, GUI tests, wallet and
IPC enabled; kernel API, fuzz and USDT disabled. Other configurations/platforms
are outside this checkpoint.

## Counts

The fixed baseline in `qt-baseline.json` contains **9 actual test methods in
6 classes**. PoCX runs those nine plus one separately registered native URI case
in a seventh class. Setup/cleanup entries are counted separately: Bitcoin has
21 passing log entries, PoCX has 24. The application test's GUI/console callbacks
and options setup hook are not additional cases.

| Category | Count | Result |
| --- | ---: | --- |
| Original Bitcoin cases with PoCX OFF | 9 | All green |
| Original cases reused unchanged under PoCX | 7 | All green |
| Original cases with adapted expectations under PoCX | 2 | All green |
| Original cases failing under PoCX | 0 | |
| Disabled cases needing a PoCX fix | 0 | |
| Cases excluded as inapplicable under PoCX | 0 | |
| Original cases unverified, inactive or missing | 0 | |
| Separately registered PoCX-only cases | 1 | Green |
| Assertions in that native URI case | 9 | All green |

## Case review

| Original case | PoCX behavior | Result in both configurations |
| --- | --- | --- |
| `AppTests::appTests` | Reused unchanged, including GUI/console callbacks | PASS |
| `OptionTests::migrateSettings` | Reused unchanged | PASS |
| `OptionTests::integerGetArgBug` | Reused unchanged | PASS |
| `OptionTests::parametersInteraction` | Reused unchanged | PASS |
| `OptionTests::extractFilter` | Reused unchanged | PASS |
| `AddressBookTests::addressBookTests` | Reused unchanged | PASS |
| `URITests::uriTests` | Reused unchanged | PASS |
| `RPCNestedTests::rpcNestedTests` | Owned copy expects PoCX genesis transaction ID | PASS |
| `WalletTests::walletTests` | Owned copy expects `btcx:` payment links | PASS |

`PoCXURITests::nativePaymentURIs` passes separately. It preserves exactly the nine
previously inline native assertions: native parsing and fields, uppercase scheme
acceptance, rejection of `pocx:`, and native output formatting. No assertion was
removed or weakened while relocating it.

## Ownership and guards

All **15 original Qt C++ source/header files match upstream exactly**, with no
inline PoCX adaptations. `src/qt/test/CMakeLists.txt` retains conditional source
selection. Only a PoCX build selects the owned RPC, wallet and runner sources
plus the native URI source/header. The owned runner adds one native registration
while retaining every original registration and lifecycle step. The original
URI source is reused directly in both builds.

The native build uses AUTOMOC's default include paths because original and owned
headers live in different directories. The Bitcoin build retains its upstream
MOC option. Compiler-command audits verify that the Bitcoin configuration selects
no native sources/macros and the native configuration selects the intended owned
sources without compiling their original counterparts too.

`qt-parity.json` records reviewed native hashes and transformation reasons.
`python3 test/pocx/qt_parity.py --check` protects the fixed original case/source
baseline, original source contents, owned inventory and reviewed adaptations/build
selection. The checker runs independently of future combined CI packages. Complete runtime
membership was explicitly checked in this checkpoint; integration of that runtime
check into the permanent packaged Qt CI runner remains separate work.

## Reproduce

Install the normal Linux build prerequisites plus Qt 6 development packages,
Qt tools and libqrencode (see `doc/build-unix.md` and `doc/dependencies.md`).
Run the standalone source guard, then build and run both profiles:

```sh
python3 test/pocx/qt_parity.py --check
for qt_mode in OFF ON; do
  qt_build="build-qt-${qt_mode}"
  cmake -S . -B "$qt_build" -G Ninja -DCMAKE_BUILD_TYPE=Release \
    -DENABLE_POCX="$qt_mode" -DBUILD_GUI=ON -DBUILD_GUI_TESTS=ON \
    -DBUILD_TESTS=ON -DENABLE_WALLET=ON -DENABLE_IPC=ON \
    -DBUILD_BENCH=OFF -DBUILD_FUZZ_BINARY=OFF -DBUILD_KERNEL_LIB=OFF \
    -DWITH_ZMQ=OFF -DWITH_USDT=OFF
  cmake --build "$qt_build" --target test_bitcoin-qt -j 3
  mkdir -p "$qt_build/xdg-config"
  qt_tmp=$(mktemp -d -t qt-tests.XXXXXXXX)
  TMPDIR="$qt_tmp" XDG_CONFIG_HOME="$PWD/$qt_build/xdg-config" \
    QT_QPA_PLATFORM=minimal ctest --test-dir "$qt_build/src/qt/test" \
      -R '^test_bitcoin-qt$' --verbose --timeout 180 --no-tests=error
  rmdir "$qt_tmp"
done
```

CTest registers one executable in each profile. Inspect its verbose method-level
results to confirm nine original methods with PoCX OFF and those same nine plus
`PoCXURITests::nativePaymentURIs` with PoCX ON. Use build-local Qt configuration and a short temporary path as above to keep
tests isolated from normal wallet settings and respect Unix socket path limits.

## Evidence and remaining work

`qt-verification.json` records the current checkpoint. Local full logs, CTest XML,
source/binary hashes, exact run commands and reviewed diffs are retained in
`artifacts/ownership-cleanup-20261009/`. The standalone package was also built
and executed on top of the unit commit without pending framework files; its
logs and compiler/source audits are in `artifacts/qt-package-20261009/`.
Earlier pre-cleanup evidence remains in
`artifacts/qt-baseline-20261009/`. The unit suite's separate ownership amendment is
recorded in `unit-verification.json`.

Qt ownership cleanup and original-suite parity are green. Dedicated native Qt coverage for forging-assignment/revocation dialogs
and their transaction presentation is still absent; original-suite parity does
not establish coverage of those added GUI features.
