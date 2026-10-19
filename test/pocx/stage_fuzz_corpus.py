#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin PoCX developers
# Distributed under the MIT software license; see COPYING.
"""Combine complete inherited corpora with reproducible native input seeds."""
import argparse
import hashlib
import json
from pathlib import Path
import random
import shutil
import struct
import subprocess
import sys
import tempfile

from common import ROOT, sha256
import fuzz_parity


def native_seeds(target):
    rng = random.Random(20261019)
    seeds = {'empty': b'', 'zero-256': bytes(256), 'ff-256': bytes([255]) * 256,
             'sequence': bytes(range(256)), 'random-1024': rng.randbytes(1024),
             'random-4096': rng.randbytes(4096)}
    if target == 'pocx_proof_parameters':
        for selector in range(8):
            for compression in (0, 1, 2, 7, 8, (1 << 32) - 1):
                # Reader's front-byte controls: selector, compression, target,
                # height, nonce, quality, gensig, account and seed.
                data = bytes([selector]) + struct.pack('<IQQQQ', compression, 1000, 1, 0, 0)
                data += bytes(range(32)) + bytes(range(20)) + bytes(32)
                seeds[f'proof-{selector}-{compression}'] = data
        seeds['hex-valid'] = bytes(121) + b'0123456789abcdef' * 4
        seeds['hex-invalid'] = bytes(121) + b'z' * 64
    if target == 'pocx_assignment_state':
        # Add, revoke, flush, undo, remove, restore and cold-DB round trips.
        operations = [0, 1, 5, 3, 6, 2, 3, 4, 7]
        seeds['assignment-lifecycle'] = b''.join(bytes([op, 0, 30, 1]) for op in operations)
    if target == 'pocx_assignment_opcodes':
        seeds['assignment'] = b'\x6a\x2cPOCX' + bytes(range(40))
        seeds['revocation'] = b'\x6a\x18XCOP' + bytes(range(20))
    return seeds


def stage(build, upstream, *, selected_config=None, output=None):
    contract = fuzz_parity.inventory(build, selected_config=selected_config)
    expected = set(contract['expected'])
    if not upstream.is_dir():
        raise ValueError('Missing inherited fuzz corpus directory')
    if output is None:
        output = Path(tempfile.mkdtemp(prefix='fuzz-corpus-', dir=build))
    else:
        output.mkdir(parents=True, exist_ok=False)
    generated = output / 'generated'
    generators = ('generate_corpus.py', 'generate_index_corpus.py', 'generate_network_corpus.py')
    for name in generators:
        subprocess.run([sys.executable, str(ROOT / 'test/pocx/fuzz' / name), '--output', str(generated)],
                       check=True, stdout=sys.stderr)
    _, parity = fuzz_parity.records()
    corpora = output / 'corpus'
    revision = subprocess.run(['git', '-C', str(upstream.parent), 'rev-parse', 'HEAD'],
                              capture_output=True, text=True, check=True).stdout.strip()
    if len(revision) != 40 or any(character not in '0123456789abcdef' for character in revision):
        raise ValueError('Invalid inherited qa-assets revision')
    manifest = {'scope': 'Complete inherited target corpora plus supplemental generated PoCX seeds',
                'upstream_directory': str(upstream), 'upstream_revision': revision, 'targets': {},
                'stage_sha256': sha256(Path(__file__)),
                'generator_sha256': {name: sha256(ROOT / 'test/pocx/fuzz' / name) for name in generators}}
    for target in sorted(expected):
        destination = corpora / target
        destination.mkdir(parents=True)
        original = upstream / target
        original_files = sorted(original.iterdir()) if original.is_dir() else []
        if any(path.is_symlink() or not path.is_file() for path in original_files):
            raise ValueError('Unexpected inherited fuzz corpus entry: ' + str(original))
        inherited_hashes = {}
        for path in original_files:
            inherited_hashes[path.name] = sha256(path)
            shutil.copyfile(path, destination / path.name)
            if sha256(destination / path.name) != inherited_hashes[path.name]:
                raise ValueError('Inherited fuzz corpus changed during staging: ' + str(path))
        supplemental = generated / 'corpus' / target
        if supplemental.is_dir():
            for path in sorted(supplemental.iterdir()):
                shutil.copyfile(path, destination / ('pocx-' + sha256(path)))
        if target in parity['native_targets']:
            for data in native_seeds(target).values():
                (destination / ('pocx-' + hashlib.sha256(data).hexdigest())).write_bytes(data)
        if target == 'rpc':
            # ConsumeTime takes four control bytes from the tail. The RPC
            # command and a scalar argument are consumed from the front;
            # backslash plus a non-backslash byte delimits each string.
            address = b'bcrt1qjqmxmkpmxt80xz4y3746zgt0q3u3ferr34acd5'
            seeds = (
                b'get_mining_info\\X' + bytes(4),
                b'get_assignment\\X' + address + b'\\X\x00\x00\x01\x01' + bytes(4),
            )
            for data in seeds:
                (destination / ('pocx-' + hashlib.sha256(data).hexdigest())).write_bytes(data)
        files = {path.name: sha256(path) for path in sorted(destination.iterdir())}
        manifest['targets'][target] = {'inherited_inputs': len(original_files),
                                       'inherited_sha256': inherited_hashes, 'inputs': files}
    (output / 'provenance.json').write_text(json.dumps(manifest, indent=2) + '\n')
    return corpora


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--build-dir', required=True, type=Path)
    parser.add_argument('--upstream', required=True, type=Path)
    parser.add_argument('--config')
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    print(stage(args.build_dir.resolve(), args.upstream.resolve(),
                selected_config=args.config, output=args.output))
