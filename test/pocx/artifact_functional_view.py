#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin PoCX developers
# Distributed under the MIT software license; see COPYING.
"""Create an attested functional runtime view of an immutable Windows payload.

This relocates paths for execution, without claiming a new local compiler build.
The raw producer cache and payload remain unchanged in the artifact bundle.
"""
import argparse
import configparser
import hashlib
import io
import json
from pathlib import Path
import shutil
import tempfile

from common import ROOT, build_options, sha256
import build_configuration
import windows_artifacts

COMPONENTS = {
    'ENABLE_WALLET': 'ENABLE_WALLET', 'BUILD_BENCH': 'BUILD_BENCH',
    'ENABLE_CLI': 'BUILD_CLI', 'BUILD_BITCOIN_TX': 'BUILD_TX',
    'ENABLE_BITCOIN_UTIL': 'BUILD_UTIL', 'ENABLE_BITCOIN_CHAINSTATE': 'BUILD_UTIL_CHAINSTATE',
    'ENABLE_WALLET_TOOL': 'BUILD_WALLET_TOOL', 'ENABLE_BITCOIND': 'BUILD_DAEMON',
    'ENABLE_FUZZ_BINARY': 'BUILD_FUZZ_BINARY', 'ENABLE_ZMQ': 'WITH_ZMQ',
    'ENABLE_EMBEDDED_ASMAP': 'WITH_EMBEDDED_ASMAP', 'ENABLE_EXTERNAL_SIGNER': 'ENABLE_EXTERNAL_SIGNER',
    'ENABLE_USDT_TRACEPOINTS': 'WITH_USDT', 'ENABLE_IPC': 'ENABLE_IPC',
}
MANIFEST = 'artifact-functional-view.json'


def relocate_cache(text, root, destination):
    relocations = []
    for key, value, required in (('CMAKE_HOME_DIRECTORY', root, True),
                                  ('CMAKE_CACHEFILE_DIR', destination, False)):
        prefix = key + ':INTERNAL='
        lines = text.splitlines(keepends=True)
        matches = [i for i, line in enumerate(lines) if line.startswith(prefix)]
        if len(matches) > 1 or (required and len(matches) != 1):
            raise ValueError('Missing or ambiguous producer cache path: ' + key)
        if not matches:
            continue
        index = matches[0]
        old = lines[index][len(prefix):].rstrip('\r\n')
        if not old:
            raise ValueError('Empty producer cache path: ' + key)
        new = value.as_posix()
        relocations.append({'key': key, 'producer_value': old, 'runtime_value': new})
        lines[index] = prefix + new + '\n'
        text = ''.join(lines)
    return text, relocations


def relocated_config(text, options, root, destination):
    config = configparser.ConfigParser(interpolation=None)
    config.read_string(text)
    if config.defaults() or set(config.sections()) != {'environment', 'components'}:
        raise ValueError('Unexpected producer functional configuration sections')
    environment = config['environment']
    if environment.get('EXEEXT') != '.exe':
        raise ValueError('Windows functional configuration requires EXEEXT=.exe')
    if set(config['components']) - {name.lower() for name in COMPONENTS}:
        raise ValueError('Unknown producer functional component')
    for component, switch in COMPONENTS.items():
        value = options.get(switch)
        if value not in ('ON', 'OFF', 'TRUE', 'FALSE', 'YES', 'NO', '1', '0'):
            raise ValueError('Missing or ambiguous producer functional feature: ' + switch)
        enabled = value in ('ON', 'TRUE', 'YES', '1')
        if config['components'].getboolean(component, fallback=False) != enabled:
            raise ValueError('Functional component differs from compiler feature: ' + component)
    relocations = []
    for key, value in (('SRCDIR', root), ('BUILDDIR', destination),
                        ('RPCAUTH', root / 'share/rpcauth/rpcauth.py')):
        if not environment.get(key):
            raise ValueError('Missing producer functional path: ' + key)
        new = value.as_posix()
        relocations.append({'key': key, 'producer_value': environment[key], 'runtime_value': new})
        environment[key] = new
    stream = io.StringIO()
    config.write(stream)
    return stream.getvalue(), relocations


def inputs(bundle, consensus, destination, *, root=ROOT, revision=None):
    if consensus not in ('bitcoin', 'pocx'):
        raise ValueError('Unknown functional artifact consensus')
    root = root.resolve()
    if destination.is_symlink():
        raise ValueError('Symlinked functional runtime view')
    destination = destination.resolve()
    if bundle.is_symlink():
        raise ValueError('Symlinked Windows artifact bundle')
    bundle = bundle.resolve()
    if (destination == root or not destination.is_relative_to(root) or
            destination.is_relative_to(bundle) or bundle.is_relative_to(destination)):
        raise ValueError('Use a separate runtime directory inside the source worktree and outside the bundle')
    pair = windows_artifacts.verify_pair(bundle, root=root, revision=revision)
    row = next(row for row in pair['phases'] if row['consensus'] == consensus)
    payload = bundle / consensus
    raw_cache = (payload / 'provenance/CMakeCache.txt').read_text()
    cache, cache_paths = relocate_cache(raw_cache, root, destination)
    if build_options(cache) != build_options(raw_cache):
        raise ValueError('Relocation changed compiler features')
    build_configuration.require_source(cache, root)
    config, config_paths = relocated_config((payload / 'test/config.ini').read_text(),
                                            row['build_options'], root, destination)
    # Values are bytes or an existing source file. All runtime copies are bound
    # to the immutable bundle or the independently verified source snapshot.
    files = {'CMakeCache.txt': cache.encode(), 'test/config.ini': config.encode()}
    for name in row['files']:
        if name.startswith('bin/'):
            files[name] = payload / name
        elif name.startswith('provenance/CMakeFiles/'):
            files[name[len('provenance/'):]] = payload / name
    directory = root / 'test/functional'
    for path in sorted(directory.rglob('*')):
        if '__pycache__' in path.parts or path.suffix == '.pyc':
            continue
        if path.is_symlink():
            raise ValueError('Symlinked original functional source: ' + str(path))
        if path.is_file():
            files['test/functional/' + path.relative_to(directory).as_posix()] = path
    if 'test/functional/test_runner.py' not in files:
        raise ValueError('Original functional runner missing')
    hashes = {name: hashlib.sha256(value).hexdigest() if isinstance(value, bytes) else sha256(value)
              for name, value in files.items()}
    manifest = {'format': 1, 'kind': 'windows-artifact-functional-runtime-view',
        'scope': 'Relocated execution inputs; not a local compiler build or a test pass',
        'consensus': consensus, 'revision': pair['revision'], 'bundle': str(bundle),
        'pair_sha256': sha256(bundle / 'pair.json'), 'runtime_directory': str(destination),
        'functional_support_sha256': pair['functional_support_sha256'],
        'producer_cache_sha256': row['files']['provenance/CMakeCache.txt'],
        'cache_relocations': cache_paths, 'configuration_relocations': config_paths,
        'files': hashes}
    return files, manifest


def verify_view(bundle, consensus, destination, *, root=ROOT, revision=None):
    files, expected = inputs(bundle, consensus, destination, root=root, revision=revision)
    manifest_path = destination / MANIFEST
    if manifest_path.is_symlink() or json.loads(manifest_path.read_text()) != expected:
        raise ValueError('Functional runtime view provenance changed')
    for name, digest in expected['files'].items():
        path = destination / name
        if any(parent.is_symlink() for parent in (path, *path.parents)) or not path.is_file() or sha256(path) != digest:
            raise ValueError('Functional runtime input missing, changed or symlinked: ' + name)
    # New binaries or scripts could be selected implicitly by the upstream
    # runner. Reject them while allowing test caches and reports elsewhere.
    for directory in ('bin', 'test/functional'):
        actual = set()
        for path in (destination / directory).rglob('*'):
            if path.is_symlink():
                raise ValueError('Symlink in functional runtime input tree')
            if '__pycache__' in path.parts or path.suffix == '.pyc':
                raise ValueError('Unattested bytecode in functional runtime input tree; use PYTHONDONTWRITEBYTECODE=1')
            if path.is_file():
                actual.add(path.relative_to(destination).as_posix())
        if actual != {name for name in files if name.startswith(directory + '/')}:
            raise ValueError('Functional runtime input inventory changed: ' + directory)
    return expected


def create_view(bundle, consensus, destination, *, root=ROOT, revision=None):
    if destination.exists() or destination.is_symlink():
        raise ValueError('Runtime view destination already exists')
    files, manifest = inputs(bundle, consensus, destination, root=root, revision=revision)
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = Path(tempfile.mkdtemp(prefix='pocx-functional-view-', dir=destination.parent))
    try:
        for name, value in files.items():
            path = temporary / name
            path.parent.mkdir(parents=True, exist_ok=True)
            if isinstance(value, bytes):
                path.write_bytes(value)
            else:
                shutil.copyfile(value, path)
            if sha256(path) != manifest['files'][name]:
                raise ValueError('Functional input changed during copying')
        (temporary / MANIFEST).write_text(json.dumps(manifest, indent=2) + '\n')
        # Recheck the producer/source inputs immediately before publication.
        if inputs(bundle, consensus, destination, root=root, revision=revision)[1] != manifest:
            raise ValueError('Functional artifact inputs changed during relocation')
        temporary.rename(destination)
        return verify_view(bundle, consensus, destination, root=root, revision=revision)
    finally:
        if temporary.exists():
            shutil.rmtree(temporary)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--bundle', type=Path, required=True)
    parser.add_argument('--consensus', choices=('bitcoin', 'pocx'), required=True)
    parser.add_argument('--view', type=Path, required=True)
    parser.add_argument('--verify', action='store_true')
    args = parser.parse_args()
    windows_artifacts.verify_recipe()
    operation = verify_view if args.verify else create_view
    report = operation(args.bundle, args.consensus, args.view)
    print(json.dumps({'status': 'runtime inputs verified; tests not executed',
                      'consensus': report['consensus'], 'input_files': len(report['files'])}))


if __name__ == '__main__':
    main()
