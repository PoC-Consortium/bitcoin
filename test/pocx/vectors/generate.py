#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin PoCX developers
# Distributed under the MIT software license; see COPYING.
"""Generate fixed real-proof fixtures from a pinned, read-only Rust reference."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess

ROOT = Path(__file__).resolve().parents[3]
REFERENCE = 'f5081341a65fec065ffba1f37046ac74821b4c76'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--reference-dir', required=True, type=Path)
    parser.add_argument('--build-dir', type=Path, default=ROOT / 'build-proof-reference')
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--verify', action='store_true', help='compare existing fixture without rewriting it')
    args = parser.parse_args()
    reference = args.reference_dir.resolve()
    build = args.build_dir.resolve()
    output = args.output.resolve()
    if build == ROOT or not build.is_relative_to(ROOT) or not output.is_relative_to(ROOT):
        raise SystemExit('Keep generated files and build artifacts inside the isolated worktree')
    revision = subprocess.check_output(['git', '-C', reference, 'rev-parse', 'HEAD'], text=True).strip()
    status_command = ['git', '-C', str(reference), 'status', '--porcelain']
    before = subprocess.check_output(status_command, text=True)
    if revision != REFERENCE or before:
        raise SystemExit(f'Reference must be a clean checkout at {REFERENCE}')
    build.mkdir(parents=True, exist_ok=True)
    (build / 'src').mkdir(exist_ok=True)
    source = Path(__file__).with_name('reference.rs')
    shutil.copyfile(source, build / 'src/main.rs')
    manifest = ('[package]\nname = "pocx-reference-vectors"\nversion = "0.1.0"\nedition = "2021"\n'
                '[workspace]\n[dependencies]\nsha2 = "0.10"\npocx_hashlib = { path = ' +
                json.dumps(str(reference / 'pocx_hashlib')) + ' }\n')
    (build / 'Cargo.toml').write_text(manifest)
    # A fresh build uses exactly the reviewed dependency resolution too.
    lock = Path(__file__).with_name('Cargo.lock')
    shutil.copyfile(lock, build / 'Cargo.lock')
    command = ['cargo', 'run', '--release', '--offline', '--manifest-path', str(build / 'Cargo.toml'),
               '--target-dir', str(build / 'target'), '--locked']
    result = subprocess.run(command, capture_output=True, text=True)
    (build / 'generation.log').write_text(result.stderr)
    result.check_returncode()
    vectors = json.loads(result.stdout)
    assert len(vectors) == 8
    # Fixed-point time bending uses independent Python big integers.
    def cuberoot(value):
        lo, hi = 0, 1 << ((value.bit_length() + 2) // 3)
        while lo + 1 < hi:
            mid = (lo + hi) // 2
            if mid ** 3 <= value:
                lo = mid
            else:
                hi = mid
        return hi if hi ** 3 == value else lo
    for vector in vectors:
        spacing = 120
        denominator = (cuberoot(spacing << 126) * 3927365422841) >> 42
        scale = ((spacing << 84) + denominator // 2) // denominator
        root = cuberoot((vector['quality'] << 63) // vector['base_target'])
        vector['bended_deadline'] = (scale * root + (1 << 62)) >> 63
    rendered = json.dumps(vectors, indent=2) + '\n'
    if subprocess.check_output(status_command, text=True) != before:
        raise SystemExit('Reference checkout changed while generating fixtures')
    if args.verify:
        if output.read_text() != rendered:
            raise SystemExit('Frozen fixtures differ from the pinned Rust reference')
    else:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(rendered)
    sources = [reference / 'Cargo.toml', reference / 'pocx_hashlib/Cargo.toml',
               *sorted((reference / 'pocx_hashlib/src').glob('*.rs'))]
    provenance = {'reference_repository': 'https://github.com/PoC-Consortium/pocx',
                  'revision': revision, 'scope': 'Rust scalar nonce/scoop/quality, cross-checked with public optimized Rust API; Python integer deadlines',
                  'rustc': subprocess.check_output(['rustc', '--version'], text=True).strip(),
                  'generator_sha256': hashlib.sha256(source.read_bytes()).hexdigest(),
                  'driver_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                  'cargo_lock_sha256': hashlib.sha256((build / 'Cargo.lock').read_bytes()).hexdigest(),
                  'fixture_sha256': hashlib.sha256(rendered.encode()).hexdigest(),
                  'reference_sources': {str(path.relative_to(reference)): hashlib.sha256(path.read_bytes()).hexdigest() for path in sources}}
    (build / 'provenance.json').write_text(json.dumps(provenance, indent=2) + '\n')
    print(f'{"Verified" if args.verify else "Generated"} {len(vectors)} real-proof vectors: {output}')


if __name__ == '__main__':
    main()
