#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin PoCX developers
# Distributed under the MIT software license; see COPYING.
"""Reviewed Windows fixture corrections, without editing upstream test sources."""
import ast
import configparser
import json
import shutil

from common import ROOT, sha256

REVIEW = 'test/pocx/bitcoin_baseline/windows/review.json'
ORIGINAL = 'test/functional/rpc_signer.py'
REPLACEMENT = 'test/pocx/bitcoin_baseline/windows/rpc_signer.py'


def replacements(root=ROOT):
    review = json.loads((root / REVIEW).read_text())
    if (review['source'] != ORIGINAL or review['replacement'] != REPLACEMENT or
            sha256(root / ORIGINAL) != review['source_sha256'] or
            sha256(root / REPLACEMENT) != review['replacement_sha256']):
        raise ValueError('Windows signer fixture changed without review')
    original = (root / ORIGINAL).read_text()
    literal = '"CreateProcess failed: The system cannot find the file specified."'
    if original.count('import os\n') != 1 or original.count(literal) != 1:
        raise ValueError('Ambiguous original Windows signer fixture')
    expected = original.replace('import os\n', 'import os\nimport ctypes\n').replace(
        literal, '"CreateProcess failed: " + ctypes.FormatError(2).strip()')
    if ast.dump(ast.parse(expected)) != ast.dump(ast.parse((root / REPLACEMENT).read_text())):
        raise ValueError('Windows signer scenarios or assertions changed')
    wallet = review['multiwallet']
    source = root / wallet['source']
    replacement = root / wallet['replacement']
    if sha256(source) != wallet['source_sha256'] or sha256(replacement) != wallet['replacement_sha256']:
        raise ValueError('Windows multiwallet fixture changed without review')
    literal = '"filesystem error:" if platform.system() != \'Windows\' else "create_directories:"'
    updated = '"filesystem error: cannot create directories:" if self.config["environment"].getboolean("POCX_WINDOWS_MINGW", fallback=False) else ("filesystem error:" if platform.system() != \'Windows\' else "create_directories:")'
    text = source.read_text(encoding='utf8')
    if text.count(literal) != 1 or ast.dump(ast.parse(text.replace(literal, updated))) != ast.dump(ast.parse(replacement.read_text(encoding='utf8'))):
        raise ValueError('Windows multiwallet scenarios or assertions changed')
    return {'rpc_signer.py': root / REPLACEMENT, 'wallet_multiwallet.py': replacement}


def files(directory):
    return {p.relative_to(directory).as_posix(): sha256(p)
            for p in sorted(directory.rglob('*')) if p.is_file() and
            '__pycache__' not in p.parts and p.suffix != '.pyc'}


def stage(build, output, *, root=ROOT):
    replacements(root)
    view = output / 'original-windows-view'
    if view.exists():
        raise ValueError('Never overwrite retained Windows fixture evidence')
    original = files(root / 'test/functional')
    shutil.copytree(root / 'test/functional', view / 'test/functional',
                    ignore=shutil.ignore_patterns('__pycache__', '*.pyc'))
    for name, source in replacements(root).items():
        shutil.copyfile(source, view / 'test/functional' / name)
    for name in ('bin', 'lib'):
        (view / name).symlink_to(build / name, target_is_directory=True)
    config = configparser.ConfigParser(interpolation=None)
    config.read(build / 'test/config.ini')
    config['environment']['BUILDDIR'] = str(view)
    with (view / 'test/config.ini').open('w') as stream:
        config.write(stream)
    proof = {'scope': 'Reviewed Windows fixture view; not execution evidence',
             'build_view': str(view), 'binary_build': str(build),
             'original_sources': original, 'files': files(view / 'test/functional'),
             'original_config_sha256': sha256(build / 'test/config.ini'),
             'staged_config_sha256': sha256(view / 'test/config.ini'),
             'review_sha256': sha256(root / REVIEW)}
    (view / 'windows-fixture-view.json').write_text(json.dumps(proof, indent=2) + '\n')
    return view, verify(view, build, root=root)


def verify(view, build, *, root=ROOT):
    adapted = replacements(root)
    proof = json.loads((view / 'windows-fixture-view.json').read_text())
    expected = files(root / 'test/functional')
    if proof['original_sources'] != expected:
        raise ValueError('Original Windows fixture inputs changed')
    expected.update({name: sha256(path) for name, path in adapted.items()})
    if (proof['build_view'] != str(view) or proof['binary_build'] != str(build) or
            proof['files'] != expected or files(view / 'test/functional') != expected or
            proof['review_sha256'] != sha256(root / REVIEW) or
            proof['original_config_sha256'] != sha256(build / 'test/config.ini') or
            proof['staged_config_sha256'] != sha256(view / 'test/config.ini') or
            any((view / name).resolve() != (build / name).resolve() for name in ('bin', 'lib')) or
            any(p.is_symlink() for p in (view / 'test/functional').rglob('*'))):
        raise ValueError('Windows fixture view or binary selection changed')
    return proof
