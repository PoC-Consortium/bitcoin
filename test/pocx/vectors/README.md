# Fixed real-proof vectors

`src/pocx/test/data/real_proof_vectors.json` contains eight fixed vectors generated
from the separate Rust PoCX implementation at
`f5081341a65fec065ffba1f37046ac74821b4c76`. Accounts and seeds deliberately avoid
the synthetic regtest selector. The native unit tests consume the frozen JSON;
normal test execution does not require Rust or access to that repository.

The vectors cover compressed and uncompressed nonce boundaries, large nonces and
heights, compression levels 1, 2, 3 and 7, and base targets including 1 and the
maximum uint64 value. Each records a full uncompressed nonce SHA256 digest, scoop
number, compressed scoop bytes, quality, raw deadline and time-bended deadline.

`reference.rs` explicitly calls Rust scalar nonce generation, assembles compressed
scoops and computes their quality. It checks this result against the Rust public
optimized quality API. `generate.py` calculates expected time bending with Python
integer arithmetic and an independent binary-search cube root. No expected result
comes from the C++ implementation under test. This establishes agreement between
implementations; it is not an independent audit of the protocol specification.

With a clean, read-only checkout of that Rust revision and Rust/Cargo installed,
verify the fixtures from the isolated node worktree:

```sh
python3 test/pocx/vectors/generate.py --reference-dir /path/to/pocx --output src/pocx/test/data/real_proof_vectors.json --verify
```

Cargo uses the reviewed `Cargo.lock`, `--locked`, `--offline`, and a target directory
inside the node worktree. Registry dependencies must already be cached. The driver
checks that the reference checkout stays clean. Generation logs, compiler version
and source hashes are written under `build-proof-reference/`. Omitting `--verify`
regenerates the fixture and requires reviewing the output and updating maintained
`provenance.json` after successful verification. The unit parity check checks the fixture,
both generator sources and dependency lock against that maintained provenance.

Run the native real-proof, existing SIMD and wire suites:

```sh
python3 test/pocx/run_unit.py --build-dir build-p --suite pocx_real_proof_tests --suite pocx_simd_tests --suite pocx_wire_tests
```

The six new native cases check scalar and batch validation against all eight
vectors, proof-field mutations, compression allocation limits, and full nonce
digests from supported SSE2/AVX2 paths. They also send a signed synthetic proof
through ordinary stateless block validation on mainnet and testnet4, requiring
quality-mismatch rejection, with a successful regtest positive control. Hardware
paths actually exercised are recorded in the retained Boost log.

These tests do not claim contextual chain acceptance of known real blocks,
assignment-aware signer validation or full scheduler coverage. Those remain
separate requirements of M3.
