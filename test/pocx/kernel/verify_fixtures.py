#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin PoCX developers
# Distributed under the MIT software license; see COPYING.
"""Independently verify generated kernel proof chains using Python and pinned Rust."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import struct
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[3]
REFERENCE = 'f5081341a65fec065ffba1f37046ac74821b4c76'


def hash256(raw):
    return hashlib.sha256(hashlib.sha256(raw).digest()).digest()


def cube_root(value):
    low, high = 0, 1 << ((value.bit_length() + 2) // 3)
    while low + 1 < high:
        mid = (low + high) // 2
        if mid ** 3 <= value:
            low = mid
        else:
            high = mid
    return high if high ** 3 == value else low


def deadline(quality, target):
    divisor = (cube_root(120 << 126) * 3927365422841) >> 42
    scale = ((120 << 84) + divisor // 2) // divisor
    return (scale * cube_root((quality << 63) // target) + (1 << 62)) >> 63


def fields(encoded):
    raw = bytes.fromhex(encoded)
    if len(raw) < 287:
        raise ValueError('Truncated PoCX fixture')
    return {'raw': raw, 'time': struct.unpack_from('<I', raw, 68)[0],
            'height': struct.unpack_from('<i', raw, 72)[0],
            'gensig': raw[76:108], 'target': struct.unpack_from('<Q', raw, 108)[0],
            'seed': raw[116:148], 'account': raw[148:168],
            'compression': struct.unpack_from('<I', raw, 168)[0],
            'nonce': struct.unpack_from('<Q', raw, 172)[0],
            'quality': struct.unpack_from('<Q', raw, 180)[0]}


def next_target(history, genesis_target):
    if len(history) == 1:
        return genesis_target
    last = history[-1]
    window = min(24, last['height'])
    weighted = last['target']
    raw_sum, bended_sum = 0, 0
    for index, block in enumerate(reversed(history[-window:])):
        raw_sum += block['quality'] // block['target']
        bended_sum += deadline(block['quality'], block['target'])
        if index:
            weighted = (weighted * (index + 1) + block['target']) // (index + 2)
    target_span = window * 120
    actual_span = last['time'] - history[-window - 1]['time'] - bended_sum + raw_sum
    actual_span = max(target_span // 2, min(2 * target_span, actual_span))
    adjusted = weighted * actual_span // target_span
    adjusted = max(last['target'] - last['target'] // 5,
                   min(last['target'] + last['target'] // 5, adjusted))
    return max(1, min(genesis_target, adjusted))


def verify_structure(fixtures):
    lines = []
    for name, encoded, genesis, genesis_target in (
            ('mainnet', [fixtures['mainnet']], fixtures['mainnet_genesis'], (1 << 42) // 120),
            ('regtest', fixtures['regtest'], fixtures['regtest_genesis'], (1 << 58) // 120)):
        history = [fields(genesis)]
        if history[0]['height'] != 0 or history[0]['target'] != genesis_target:
            raise ValueError(f'Unexpected {name} genesis parameters')
        for height, value in enumerate(encoded, 1):
            block = fields(value)
            previous = history[-1]
            previous_hash = hash256(previous['raw'][:221] + bytes(65))
            if block['height'] != height or block['raw'][4:36] != previous_hash:
                raise ValueError(f'Broken {name} chain at height {height}')
            if block['gensig'] != hash256(previous['gensig'] + previous['account']):
                raise ValueError(f'Generation-signature mismatch at {name} height {height}')
            if block['target'] != next_target(history, genesis_target):
                raise ValueError(f'Independent base-target mismatch at {name} height {height}')
            if block['time'] != previous['time'] + max(1, deadline(block['quality'], block['target'])):
                raise ValueError(f'Independent deadline mismatch at {name} height {height}')
            if (block['account'].hex() != '751e76e8199196d454941c45d1b3a323f1433bd6' or
                    block['seed'] != bytes([7]) * 32 or block['compression'] != 1 or block['nonce'] != 1):
                raise ValueError('Unexpected real-proof fixture selector')
            lines.append(','.join([block['gensig'][::-1].hex(), block['account'].hex(), block['seed'].hex(),
                                   str(block['nonce']), str(height), str(block['compression']), str(block['quality'])]))
            history.append(block)
    if len(lines) != 207:
        raise ValueError('Expected 207 actual real proofs')
    return '\n'.join(lines) + '\n'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--reference-dir', required=True, type=Path)
    parser.add_argument('--fixtures', required=True, type=Path)
    parser.add_argument('--generator-binary', required=True, type=Path)
    parser.add_argument('--build-dir', type=Path, default=ROOT / 'build-kernel-proof-reference')
    args = parser.parse_args()
    reference, build = args.reference_dir.resolve(), args.build_dir.resolve()
    fixture, binary = args.fixtures.resolve(), args.generator_binary.resolve()
    for path in (build, fixture, binary):
        if path == ROOT or not path.is_relative_to(ROOT):
            raise ValueError('Keep generated inputs and artifacts inside the isolated worktree')
    status_command = ['git', '-C', str(reference), 'status', '--porcelain']
    before = subprocess.check_output(status_command, text=True)
    revision = subprocess.check_output(['git', '-C', str(reference), 'rev-parse', 'HEAD'], text=True).strip()
    if before or revision != REFERENCE:
        raise ValueError(f'Use a clean read-only Rust reference at {REFERENCE}')
    build.mkdir(parents=True, exist_ok=True)
    (build / 'src').mkdir(exist_ok=True)
    (build / 'inputs.csv').write_text(verify_structure(json.loads(fixture.read_text())))
    source = Path(__file__).with_name('reference.rs')
    shutil.copyfile(source, build / 'src/main.rs')
    lock = ROOT / 'test/pocx/vectors/Cargo.lock'
    shutil.copyfile(lock, build / 'Cargo.lock')
    (build / 'Cargo.toml').write_text(
        '[package]\nname = "pocx-reference-vectors"\nversion = "0.1.0"\nedition = "2021"\n'
        '[workspace]\n[dependencies]\nsha2 = "0.10"\npocx_hashlib = { path = ' +
        json.dumps(str(reference / 'pocx_hashlib')) + ' }\n')
    command = ['cargo', 'run', '--release', '--offline', '--locked', '--manifest-path', str(build / 'Cargo.toml'),
               '--target-dir', str(build / 'target'), '--', str(build / 'inputs.csv')]
    result = subprocess.run(command, capture_output=True, text=True)
    (build / 'verification.log').write_text(result.stdout + result.stderr)
    if subprocess.check_output(status_command, text=True) != before:
        raise ValueError('Rust reference checkout changed during verification')
    result.check_returncode()
    def sha(path):
        return hashlib.sha256(path.read_bytes()).hexdigest()
    report = {'status': 'passed', 'scope': '207 Rust scalar/public proof comparisons; Python header hashes, generation signatures, deadlines and rolling difficulty',
              'reference_revision': revision, 'command': command,
              'fixtures': str(fixture.relative_to(ROOT)), 'fixture_sha256': sha(fixture),
              'generator_binary': str(binary.relative_to(ROOT)), 'generator_binary_sha256': sha(binary),
              'sources': {str(path.relative_to(ROOT)): sha(path) for path in (
                  source, Path(__file__), lock, ROOT / 'src/pocx/test/kernel/fixture_generator.cpp',
                  ROOT / 'test/pocx/kernel/render_fixtures.py')},
              'rustc': subprocess.check_output(['rustc', '--version'], text=True).strip()}
    (build / 'results.json').write_text(json.dumps(report, indent=2) + '\n')
    print(result.stdout, end='')
    print(f'Independent Python chain checks passed; results: {build / "results.json"}')


if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        print(str(error), file=sys.stderr)
        raise SystemExit(1)
