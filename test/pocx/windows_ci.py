#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin PoCX developers
# Distributed under the MIT software license; see COPYING.
"""Original-first native Windows CI, preserving the upstream VS/vcpkg recipe.

The original Windows driver stays unchanged. --plan is read-only; neither a plan
nor fake callback checks establish Windows or framework execution coverage.
"""
import argparse
import ast
import json
import math
import os
from pathlib import Path
import shlex
import subprocess
import sys
import tempfile
import time

from common import ROOT, sha256
import inherited_ci
import inherited_functional
import unit_assets

UPSTREAM_RECIPE_SHA256 = '9cec268ddaf98292b2067ae07ff99e8290a6e1a2e3a97aac9814c6642542e27b'
REVIEW_SOURCES = {'.github/ci-windows.py', '.github/workflows/ci.yml',
    'test/pocx/windows_ci.py', 'test/pocx/inherited_tests.py', 'test/pocx/inherited_functional.py',
    'test/pocx/inherited_ci.py', 'test/pocx/ci_evidence.py', 'test/pocx/unit_assets.py',
    'test/pocx/build_configuration.py', 'test/pocx/process_tree.py',
    'test/pocx/test_windows_ci.py', 'test/pocx/test_process_tree.py'}
MANIFEST_SKIPS = {'fuzz.exe', 'bench_bitcoin.exe', 'test_bitcoin-qt.exe', 'bitcoin-chainstate.exe'}


def verify_recipe(root=ROOT):
    review = json.loads((root / 'test/pocx/windows-ci.json').read_text())
    if (set(review['source_sha256']) != REVIEW_SOURCES or
            review['source_sha256']['.github/ci-windows.py'] != UPSTREAM_RECIPE_SHA256):
        raise ValueError('Incomplete Windows CI source review or changed original recipe')
    for name, expected in review['source_sha256'].items():
        if sha256(root / name) != expected:
            raise ValueError('Windows CI recipe changed without review: ' + name)
    inherited_ci.verify_recipe(root)
    return review


def upstream_options(root=ROOT):
    # Read constants without importing the original driver or running setup.
    tree = ast.parse((root / '.github/ci-windows.py').read_text())
    assignments = [node for node in tree.body if isinstance(node, ast.Assign) and
                   any(isinstance(target, ast.Name) and target.id == 'GENERATE_OPTIONS' for target in node.targets)]
    if len(assignments) != 1:
        raise ValueError('Missing or ambiguous original Windows generation options')
    value = ast.literal_eval(assignments[0].value)['standard']
    if not isinstance(value, list) or not all(isinstance(option, str) for option in value):
        raise ValueError('Invalid original Windows generation options')
    return value


def build_directory(consensus, root=ROOT):
    if consensus not in ('bitcoin', 'pocx'):
        raise ValueError('Unknown Windows consensus configuration')
    return root / ('build-bitcoin-baseline' if consensus == 'bitcoin' else 'build')


def configure_command(consensus, root=ROOT):
    return ['cmake', '-B', str(build_directory(consensus, root)), '-Werror=dev', '--preset', 'vs2026',
            *upstream_options(root), '-DENABLE_POCX=' + ('OFF' if consensus == 'bitcoin' else 'ON'),
            '-DBUILD_FUZZ_BINARY=OFF', '-DBUILD_FOR_FUZZING=OFF']


def validate_jobs(count):
    if type(count) is not int or count < 1:
        raise ValueError('Windows CI requires a positive integer job count')


def plan(count, environment, root=ROOT):
    validate_jobs(count)
    if environment.get('RUN_FUZZ_TESTS') == 'true':
        raise ValueError('Fuzz is a separate Windows package')
    inherited_functional.inherited_options(environment)
    factor = float(environment.get('TEST_RUNNER_TIMEOUT_FACTOR', '40'))
    if not math.isfinite(factor) or factor <= 0 or not math.isfinite(2400 * factor):
        raise ValueError('Windows functional timeout factor must be positive and finite')
    return [{'consensus': consensus,
             'command': [sys.executable, str(root / 'test/pocx/windows_ci.py'),
                         '--phase-consensus', consensus, '--jobs', str(count)],
             'environment': dict(environment, BASE_BUILD_DIR=str(build_directory(consensus, root)))}
            for consensus in ('bitcoin', 'pocx')]


def check_manifests(build, invoke):
    release = build / 'bin/Release'
    manifest = release / 'bitcoind.manifest'
    invoke(['mt.exe', '-nologo', '-inputresource:' + str(release / 'bitcoind.exe'), '-out:' + str(manifest)])
    print(manifest.read_text(), flush=True)
    executables = sorted(path for path in release.iterdir() if path.suffix.lower() == '.exe')
    if not executables:
        raise ValueError('Windows manifest checks have no executables')
    for executable in executables:
        if executable.name in MANIFEST_SKIPS:
            print('Skipping ' + executable.name + ' (unchanged upstream manifest exemption)', flush=True)
            continue
        invoke(['mt.exe', '-nologo', '-inputresource:' + str(executable), '-validate_manifest'])


def run_phase(consensus, count, *, root=ROOT, environment=None, run=subprocess.run,
              sleep=time.sleep, provision=unit_assets.provision):
    validate_jobs(count)
    build = build_directory(consensus, root)
    env = dict(os.environ if environment is None else environment)
    def invoke(command, *, check=True):
        print('+ ' + shlex.join(command), flush=True)
        result = run(command, cwd=root, env=env)
        if check and result.returncode:
            raise subprocess.CalledProcessError(result.returncode, command)
        return result
    configure = configure_command(consensus, root)
    if invoke(configure, check=False).returncode:
        print('Generate failure; preserving the upstream single retry.', flush=True)
        sleep(12)
        invoke(configure)
    command = ['cmake', '--build', str(build), '--config', 'Release']
    if invoke([*command, '-j', str(count)], check=False).returncode:
        print('Build failure. Verbose build follows.', flush=True)
        invoke([*command, '-j1', '--verbose'])
    check_manifests(build, invoke)
    invoke([sys.executable, '-m', 'pip', 'install', 'pyzmq'])
    assets = provision(root / 'unit_test_data')
    env['DIR_UNIT_TEST_DATA'] = assets['directory']
    print('Pinned original unit assets: ' + json.dumps(assets, sort_keys=True), flush=True)
    if consensus == 'bitcoin':
        # Real host lifecycle probes must pass before any framework claims.
        invoke([sys.executable, str(root / 'test/pocx/test_process_tree.py')])
    runtime = [sys.executable, str(root / 'test/pocx/inherited_tests.py'),
               '--build-dir', str(build), '--config', 'Release', '--jobs', str(count)]
    invoke([*runtime, '--phase', 'ctest', '--timeout', '2400'])
    invoke([*runtime, '--phase', 'functional', '--timeout-factor', env.get('TEST_RUNNER_TIMEOUT_FACTOR', '40')])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--jobs', type=int)
    parser.add_argument('--plan', action='store_true')
    parser.add_argument('--phase-consensus', choices=('bitcoin', 'pocx'), help=argparse.SUPPRESS)
    args = parser.parse_args()
    count = args.jobs if args.jobs is not None else (getattr(os, 'process_cpu_count', os.cpu_count)() or 1)
    validate_jobs(count)
    if args.plan and args.phase_consensus:
        parser.error('--plan describes the complete pair')
    verify_recipe()
    pairs = plan(count, os.environ)
    if args.plan:
        print(json.dumps({'status': 'configured only; not executed', 'phases': [
            {'consensus': row['consensus'], 'command': row['command'],
             'configure_command': configure_command(row['consensus'])} for row in pairs]}, indent=2))
        return 0
    if os.name != 'nt':
        parser.error('Actual native Windows CI requires a Windows host; use --plan for source inspection')
    if args.phase_consensus:
        run_phase(args.phase_consensus, count)
        return 0
    scratch = ROOT / 'windows-ci-evidence'
    scratch.mkdir(exist_ok=True)
    output = Path(tempfile.mkdtemp(prefix='pocx-inherited-windows-', dir=scratch)) / 'execution'
    inherited_ci.execute_and_publish(pairs, output)
    return 0


if __name__ == '__main__':
    sys.exit(main())
