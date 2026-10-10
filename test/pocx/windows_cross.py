#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin PoCX developers
# Distributed under the MIT software license; see COPYING.
"""Export completed Windows cross-build pairs before their container disappears.

This is build-input evidence only. Bitcoin/PoCX runtime baseline ordering is
enforced later by windows_artifact_ci.py on the target host.
"""
import argparse
import json
from pathlib import Path
import shutil
import tempfile

from common import ROOT, sha256
import windows_artifacts

HOSTS = {'x86_64-w64-mingw32', 'x86_64-w64-mingw32ucrt'}
BUNDLE_DIRECTORY = 'windows-artifacts'
PUBLISHED_DIRECTORY = 'windows-cross-pair'


def is_cross_pair(pairs):
    if [row['consensus'] for row in pairs] != ['bitcoin', 'pocx']:
        raise ValueError('Cross export requires the complete original/native build pair')
    hosts = [row['environment'].get('HOST', '') for row in pairs]
    cross = any('mingw' in host for host in hosts)
    if cross and (len(set(hosts)) != 1 or hosts[0] not in HOSTS):
        raise ValueError('Unknown or mismatched Windows cross-build target')
    return cross


def export(pairs, output, *, root=ROOT, revision=None):
    if not is_cross_pair(pairs):
        raise ValueError('Export requires a reviewed Windows cross-build pair')
    windows_artifacts.verify_recipe(root)
    for row in pairs:
        env = row['environment']
        if env.get('RUN_UNIT_TESTS') != 'false' or env.get('RUN_FUNCTIONAL_TESTS') != 'false':
            raise ValueError('Cross producer must defer target-host runtime execution explicitly')
    builds = [Path(row['environment']['BASE_BUILD_DIR']) for row in pairs]
    bundle = output / BUNDLE_DIRECTORY
    pair = windows_artifacts.export_pair(*builds, bundle, root=root, revision=revision)
    return {'status': 'built and input-verified; target-host execution not performed',
        'target': pairs[0]['environment']['HOST'], 'pair_sha256': sha256(bundle / 'pair.json'),
        'published_bundle_name': PUBLISHED_DIRECTORY, 'revision': pair['revision'],
        'phases': [row['consensus'] for row in pair['phases']],
        'payload_files': sum(len(row['files']) for row in pair['phases']),
        'actual_windows_cases_executed': 0}


def publish(bundle, destination, *, root=ROOT, revision=None):
    if destination.exists() or destination.is_symlink():
        raise ValueError('Refusing to replace an existing published Windows pair')
    pair = windows_artifacts.verify_pair(bundle, root=root, revision=revision)
    try:
        shutil.copytree(bundle, destination)
        if windows_artifacts.verify_pair(destination, root=root, revision=revision) != pair:
            raise ValueError('Windows pair changed during publication')
    except BaseException:
        if destination.is_dir():
            shutil.rmtree(destination)
        raise
    return destination


def collect_runtime(source, destination):
    """Retain bounded reports/logs, excluding binaries, caches and node data."""
    if source.is_symlink() or destination.is_symlink():
        raise ValueError('Symlinked runtime evidence root or destination')
    source, destination = source.resolve(), destination.resolve()
    if destination.exists() or destination.is_relative_to(source):
        raise ValueError('Use a new evidence destination outside the runtime tree')
    candidates = set()
    def add(path):
        if any(parent.is_symlink() for parent in (path, *path.parents)):
            raise ValueError('Symlinked runtime evidence input')
        if path.is_file():
            candidates.add(path)
    def shallow(directory, suffixes):
        if directory.is_symlink():
            raise ValueError('Symlinked runtime evidence directory')
        if directory.is_dir():
            for path in directory.iterdir():
                if path.suffix in suffixes:
                    add(path)
    for name in ('results.json', 'cases.csv'):
        add(source / name)
    for consensus in ('bitcoin', 'pocx'):
        phase = source / consensus
        shallow(phase, {'.log', '.manifest'})
        for relative in ('frameworks', 'frameworks/unit', 'functional', 'functional/execution'):
            shallow(phase / relative, {'.json', '.xml', '.csv', '.log'})
        runtime = phase / 'functional/runtime'
        for relative in ('artifact-functional-view.json', 'CMakeCache.txt', 'test/config.ini'):
            add(runtime / relative)
        if runtime.is_symlink():
            raise ValueError('Symlinked functional runtime tree')
        for result in runtime.glob('pocx-results-*'):
            if result.is_symlink():
                raise ValueError('Symlinked native functional result tree')
            add(result / 'results.json')
            shallow(result, {'.log'})
            shallow(result / 'v2', {'.log'})
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = Path(tempfile.mkdtemp(prefix='pocx-windows-evidence-', dir=destination.parent))
    try:
        files = {}
        for path in sorted(candidates):
            relative = path.relative_to(source)
            target = temporary / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            digest = sha256(path)
            shutil.copyfile(path, target)
            if sha256(target) != digest or sha256(path) != digest:
                raise ValueError('Runtime report changed during evidence collection')
            files[relative.as_posix()] = digest
        report = {'scope': 'Bounded runtime reports and raw logs; collection does not verify or promote execution results',
            'source': str(source), 'runtime_started': (source / 'results.json').is_file(), 'files': files}
        (temporary / 'collection.json').write_text(json.dumps(report, indent=2) + '\n')
        temporary.rename(destination)
    finally:
        if temporary.exists():
            shutil.rmtree(temporary)
    return report


def main():
    parser = argparse.ArgumentParser(description='Collect bounded Windows runtime evidence, including failures')
    parser.add_argument('--collect-runtime', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    report = collect_runtime(args.collect_runtime, args.output)
    print(json.dumps({'status': 'evidence retained; execution status unchanged',
                      'runtime_started': report['runtime_started'], 'files': len(report['files'])}))


if __name__ == '__main__':
    main()
