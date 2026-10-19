# Bitcoin and PoCX CI

`CI` tests Bitcoin (`ENABLE_POCX=OFF`). `CI-POCX` independently tests Bitcoin
PoCX (`ENABLE_POCX=ON`). Both call `.github/workflows/ci-product.yml` and use the
matrix from the pinned Bitcoin revision
`9be056a8a72b624dae9623b2f7bded92c2a21c91`.

Read [README-workflows.md](README-workflows.md) for matrix selection, required
features, platform execution and immutable Windows artifact rules. Read
[README-review-20261019.md](README-review-20261019.md) for the testing review's
findings, decisions and remaining validation limits. Fuzz ownership, exclusions
and local/platform reproduction are in [README-fuzz.md](README-fuzz.md).

## Scope and results

Both products select the inherited 14 Linux, two macOS and two native VS
configurations, plus the inherited Windows cross-build and native-consumer
jobs. The four fuzz configurations use each product's own sources and runner.
Native PoCX additions extend cases within those jobs; they introduce no
additional platform combinations. Local fuzz verification is recorded
separately from native Windows/macOS and hosted status.

Both workflows completed successfully at `ec67ffaf1d`:

- [CI](https://github.com/PoC-Consortium/bitcoin/actions/runs/39139243521)
- [CI-POCX](https://github.com/PoC-Consortium/bitcoin/actions/runs/39139243536)

Those results establish that revision's status. Later commits need their own
validation; historical artifacts cannot certify changed inputs. Keep these
states separate in reports:

- passed: the selected test executed successfully;
- failed: a test or required prerequisite failed;
- configuration-disabled: a required feature is explicitly absent in that job;
- upstream-optional-skip: the inherited recipe omits an optional dependency;
- unverified/incomplete: execution or sufficient evidence is missing, including
  cancellation and timeout;
- reviewed exclusion: a specific replaced PoW behavior is inapplicable.

[manifest.json](manifest.json) declares functional selections, whole-test
exclusions and separately reviewed subcase exclusions. The latter do not count
as executed passes. Unit exclusions and additions are in
[unit-parity.json](unit-parity.json). Qt and kernel have corresponding records.

## Local validation

Use the existing build directories and rerun affected cases first. Repeating
completed Bitcoin baselines is unnecessary unless a change could affect them.
For example:

```sh
python3 test/pocx/check_drift.py
python3 test/pocx/unit_parity.py --check
python3 test/pocx/test_unit_matrix.py
python3 test/pocx/test_runner.py --build-dir build-pocx --transport matrix feature_pocx_consensus.py
```

Both workflows' existing lint job executes `test_unit_matrix.py` and
`test_fuzz_parity.py`. Their inventories come from named baseline and reviewed
PoCX records, so adding native tests does not leave duplicated totals stale.

For full framework verification when warranted:

```sh
python3 test/pocx/run_unit.py --build-dir build-pocx --all
python3 test/pocx/run_qt.py --build-dir build-pocx --output-dir build-pocx/qt-review
python3 test/pocx/run_kernel.py --build-dir build-pocx --output-dir build-pocx/kernel-review
```

`ci.py`, `windows_ci.py` and `windows_artifact_ci.py` are platform entry points.
The independent product selection comes from `CI_PRODUCT=bitcoin` or
`CI_PRODUCT=pocx`. A plan or syntax check is not runtime verification. Preserve
native execution for Windows and macOS; cross-compilation alone does not pass
those conditions. Platform setup is described in
[README-platform-handover.md](README-platform-handover.md).

## Source records and execution artifacts

`coverage.json` is a source inventory, not a saved pass/fail scoreboard.
`baseline-inventory.json` supplies its original source list. Parity records bind
reviewed source hashes, assertions, fixture provenance and case membership.
They remain committed; raw logs, generated execution snapshots and binaries do
not. The drift gate never approves changed source hashes automatically.

`update_inventory.py` writes a compact source-only inventory when no execution
inputs are supplied. Runtime-enriched exports require an explicit output other
than the committed inventory:

```sh
python3 test/pocx/update_inventory.py --wrapper /path/to/wrapper --output /tmp/source-inventory.json
python3 test/pocx/update_inventory.py --wrapper /path/to/wrapper --functional-results build-pocx/pocx-results-EXAMPLE/results.json --output /tmp/execution-inventory.json
```

Collected evidence belongs in local build/output directories or workflow
artifacts. For failure diagnosis, retain the matching revision, build options,
raw case logs and source/binary provenance. The inherited functional dispatcher
prints case names, statuses, durations and reviewed exclusions to the job log.

The former checkpoint diary and committed execution artifacts are available in
Git history at `ec67ffaf1d`. They are historical observations, not current
acceptance evidence. Source and recipe review guards remain active after the
cleanup. Do not squash or rewrite this branch during review; fixes are commits
on top. Publishing and any final history cleanup require separate instruction.
