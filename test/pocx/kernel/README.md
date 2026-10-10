# PoCX kernel API fixtures

The PoCX build selects `src/pocx/test/kernel/test_kernel.cpp`; the original
`src/test/kernel` sources remain available unchanged for Bitcoin builds. All 16
upstream case names are retained. `parity.json` records the adaptations and
preserved checks. Case/check counts support accounting, not proof of semantics.

Bitcoin's raw proof-of-work blocks cannot exercise the PoCX kernel. A standalone
native fixture generator creates one mainnet block and a 206-block regtest chain
using actual plot proofs, compact block signatures and valid coinbase/witness
transactions. The key-1 account and nonzero seed avoid the synthetic regtest
selector. The kernel library does not use that shortcut. Coinbase maturity and
the original spent-coin/undo checks remain exercised. Legacy kernel `Bits()` and
`Nonce()` accessors return zero in PoCX; their assertions follow that C API contract.

Native builds generate JSON and C++ headers under the build directory. Cross
builds copy `fixtures.json`, the byte-identical independently verified snapshot,
into that directory and render the same header with host Python. They never run
a target-platform fixture generator on the build host. Both paths require the
same fixed fixture hash and retain every kernel assertion. Python
computes expected header hashes and field values independently. Before rendering,
the JSON must match the independently verified SHA256 in `provenance.json`.
Normal builds need no Rust checkout. Drift checking also rejects changes to the
reviewed generator, renderer, verification scripts and kernel dependencies.

Run the standalone kernel package from a configured PoCX kernel build:

```sh
python3 test/pocx/run_kernel.py --build-dir build-ci-pocx-kernel \
  --output-dir artifacts/kernel-package-20261009 --jobs 3
```

See [../README-kernel.md](../README-kernel.md) for configuration, baseline,
case accounting and guard checks. Node units and auxiliary libraries have their
own package; a kernel pass does not waive failures there. This runner allows 900 seconds for
the real-proof API workload: repeated disk reads revalidate signatures and proofs,
including full-chain input/script and output checks. Transaction lookup keeps
its original per-input chain scan and every assertion, with a local per-height
block cache on the fixed chain to avoid repeating proof validation thousands of
times. The explicit disk reads and post-file-removal rejection checks use no
lookup cache.

To repeat independent verification, use a clean read-only Rust reference at
`f5081341a65fec065ffba1f37046ac74821b4c76`:

```sh
PYTHONDONTWRITEBYTECODE=1 python3 test/pocx/kernel/verify_fixtures.py \
  --reference-dir /path/to/pocx \
  --fixtures build-ci-pocx-kernel/src/pocx/test/kernel/kernel-fixtures.json \
  --generator-binary build-ci-pocx-kernel/bin/pocx_kernel_fixture_generator
```

Rust independently generates scalar nonce data and compares all 207 claimed
qualities, then cross-checks its public optimized API. Python checks chain links,
generation signatures, rolling base targets and time-bended deadlines. Cargo
runs offline with the existing pinned lockfile and writes only inside this
worktree. `build-kernel-proof-reference/results.json` records exact hashes,
commands and the reference revision. Changes require new independent verification
and review before updating the maintained provenance; the verifier does not
approve or rewrite it automatically.

This restores the upstream kernel API cases. Further PoCX signer transitions,
competing branches, scheduler and persistence fault coverage remain separate
requirements.
