#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin PoCX developers
# Distributed under the MIT software license; see COPYING.
"""Stage reviewed original i686 USDT imports without editing original tests/builds."""
import ast
import configparser
import json
from pathlib import Path
import shutil

from common import ROOT, sha256

TESTS = {'interface_usdt_' + name + '.py' for name in
         ('coinselection', 'mempool', 'net', 'utxocache', 'validation')}
REVIEW = 'test/pocx/bitcoin_baseline/usdt/review.json'
HELPER = 'test/pocx/framework/bpf_abi.py'


def required(binary, options):
    if options.get('target_system') != 'Linux' or options.get('WITH_USDT') != 'ON':
        return False
    with binary.open('rb') as stream:
        header = stream.read(20)
    if len(header) != 20 or header[:4] != b'\x7fELF' or header[4:6] not in (b'\x01\x01', b'\x02\x01'):
        raise ValueError('Expected a Linux little-endian ELF tracing executable')
    if header[4] == 2:
        return False
    if int.from_bytes(header[18:20], 'little') != 3:
        raise ValueError('Only the reviewed i686 original tracing adapter is supported')
    return True


def review(root, owned_root):
    record = json.loads((owned_root / REVIEW).read_text())
    if set(record['tests']) != {'test/functional/' + name for name in TESTS} or set(record['helpers']) != {HELPER}:
        raise ValueError('Incomplete original USDT adaptation review')
    sources = {REVIEW: sha256(owned_root / REVIEW)}
    for relative, expected in record['helpers'].items():
        if sha256(owned_root / relative) != expected:
            raise ValueError('Original USDT helper changed without review')
        sources[relative] = expected
    for original, row in record['tests'].items():
        replacement = 'test/pocx/bitcoin_baseline/usdt/' + Path(original).name
        if (row['replacement'] != replacement or sha256(root / original) != row['upstream_sha256'] or
                sha256(owned_root / replacement) != row['replacement_sha256']):
            raise ValueError('Original USDT test changed without review: ' + original)
        text = (root / original).read_text()
        old = '    from bcc import BPF, USDT'
        if text.count(old) != 1:
            raise ValueError('Original USDT constructor import is ambiguous')
        expected = text.replace(old, '    from bcc import USDT\n    from test_framework.bpf_abi import BPF')
        if ast.dump(ast.parse(expected), include_attributes=False) != ast.dump(
                ast.parse((owned_root / replacement).read_text()), include_attributes=False):
            raise ValueError('Original USDT scenario or assertion changed')
        sources[replacement] = row['replacement_sha256']
    return record, sources


def original_sources(root):
    directory = root / 'test/functional'
    return {str(path.relative_to(directory)): sha256(path)
            for path in sorted(directory.rglob('*')) if path.is_file() and
            '__pycache__' not in path.parts and path.suffix != '.pyc'}


def stage(build, output, *, root=ROOT, owned_root=None):
    owned_root = root if owned_root is None else owned_root
    record, owned_sources = review(root, owned_root)
    before = original_sources(root)
    view = output / 'original-usdt-view'
    if view.exists():
        raise ValueError('Never overwrite a retained original USDT view')
    tests = view / 'test/functional'
    shutil.copytree(root / 'test/functional', tests, ignore=shutil.ignore_patterns('__pycache__', '*.pyc'))
    for original, row in record['tests'].items():
        shutil.copyfile(owned_root / row['replacement'], tests / Path(original).name)
    shutil.copyfile(owned_root / HELPER, tests / 'test_framework/bpf_abi.py')
    for name in ('bin', 'lib'):
        (view / name).symlink_to(build / name, target_is_directory=True)
    config = configparser.ConfigParser()
    config.read(build / 'test/config.ini')
    config['environment']['BUILDDIR'] = str(view)
    with (view / 'test/config.ini').open('w') as stream:
        config.write(stream)
    proof = {'source_root': str(root), 'owned_root': str(owned_root), 'binary_build': str(build),
             'build_view': str(view), 'original_sources': before, 'owned_sources': owned_sources,
             'original_config_sha256': sha256(build / 'test/config.ini'),
             'files': original_sources(view), 'staged_config_sha256': sha256(view / 'test/config.ini')}
    (view / 'provenance.json').write_text(json.dumps(proof, indent=2) + '\n')
    verify(view, build, root=root, owned_root=owned_root)
    return view, proof


def verify(view, build, *, root=ROOT, owned_root=None):
    owned_root = root if owned_root is None else owned_root
    if any(path.is_symlink() for path in (view / 'test/functional').rglob('*')):
        raise ValueError('Original USDT staged inputs must be real files')
    proof = json.loads((view / 'provenance.json').read_text())
    record, owned_sources = review(root, owned_root)
    if (proof['source_root'] != str(root) or proof['owned_root'] != str(owned_root) or
            proof['binary_build'] != str(build) or proof['build_view'] != str(view) or
            proof['original_sources'] != original_sources(root) or proof['owned_sources'] != owned_sources or
            proof['original_config_sha256'] != sha256(build / 'test/config.ini') or
            proof['staged_config_sha256'] != sha256(view / 'test/config.ini') or
            proof['files'] != original_sources(view)):
        raise ValueError('Original USDT staging inputs changed')
    expected = dict(proof['original_sources'])
    for original, row in record['tests'].items():
        expected[Path(original).name] = row['replacement_sha256']
    expected['test_framework/bpf_abi.py'] = owned_sources[HELPER]
    if proof['files'] != expected:
        raise ValueError('Unexpected original USDT staged input inventory')
    if any(not (view / name).is_symlink() or (view / name).resolve() != (build / name).resolve()
           for name in ('bin', 'lib')):
        raise ValueError('Original USDT view selects a different binary build')
    config = configparser.ConfigParser()
    config.read(build / 'test/config.ini')
    config['environment']['BUILDDIR'] = str(view)
    staged = configparser.ConfigParser()
    staged.read(view / 'test/config.ini')
    if dict(staged) != dict(config):
        raise ValueError('Original USDT view changes more than the binary build path')
    return proof
