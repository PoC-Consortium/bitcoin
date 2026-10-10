#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin PoCX developers
# Distributed under the MIT software license; see COPYING.
"""Original-first ancestor-commit CI with the inherited compiler configuration.

The unchanged upstream executor remains the recipe reference. Infrastructure
fixtures and --plan establish no framework or hosted execution coverage.
"""
import argparse
import json
import os
from pathlib import Path
import shlex
import subprocess
import sys
import tempfile

from common import ROOT
import inherited_ci


def configure_command(build, consensus):
    if consensus not in ('bitcoin', 'pocx'):
        raise ValueError('Unknown revision consensus configuration')
    return ['cmake', '-B', str(build), '-Werror=dev',
            '-DCMAKE_C_COMPILER=clang', '-DCMAKE_CXX_COMPILER=clang++',
            '-DCMAKE_EXE_LINKER_FLAGS=-fuse-ld=mold',
            "-DAPPEND_CXXFLAGS='-O3 -g2'", "-DAPPEND_CFLAGS='-O3 -g2'",
            '-DCMAKE_BUILD_TYPE=Debug', '-DCMAKE_COMPILE_WARNING_AS_ERROR=ON',
            '--preset=dev-mode', '-DCMAKE_CXX_FLAGS=-Wno-error=unused-member-function',
            '-DENABLE_POCX=' + ('OFF' if consensus == 'bitcoin' else 'ON'),
            '-DBUILD_FUZZ_BINARY=OFF', '-DBUILD_FOR_FUZZING=OFF']


def build_directory(consensus, root=ROOT):
    if consensus not in ('bitcoin', 'pocx'):
        raise ValueError('Unknown revision consensus configuration')
    return root / ('ci_build-bitcoin-baseline' if consensus == 'bitcoin' else 'ci_build')


def validate_jobs(count):
    if type(count) is not int or count < 1:
        raise ValueError('Revision CI requires a positive integer job count')


def plan(count, environment, root=ROOT):
    validate_jobs(count)
    if environment.get('RUN_FUZZ_TESTS') == 'true':
        raise ValueError('Dedicated fuzz execution is outside the revision framework pair')
    return [{'consensus': consensus,
             'command': [sys.executable, str(root / 'test/pocx/revision_ci.py'),
                         '--phase-consensus', consensus, '--jobs', str(count)],
             'environment': dict(environment, BASE_BUILD_DIR=str(build_directory(consensus, root)))}
            for consensus in ('bitcoin', 'pocx')]


def run_phase(consensus, count, *, root=ROOT, run=subprocess.run):
    validate_jobs(count)
    build = build_directory(consensus, root)
    def invoke(command, *, check=True):
        print('+ ' + shlex.join(command), flush=True)
        result = run(command, cwd=root)
        if check and result.returncode:
            raise subprocess.CalledProcessError(result.returncode, command)
        return result
    invoke(configure_command(build, consensus))
    if invoke(['cmake', '--build', str(build), '-j', str(count)], check=False).returncode:
        print('Build failure. Verbose build follows.', flush=True)
        invoke(['cmake', '--build', str(build), '-j1', '--verbose'])
    runtime = [sys.executable, str(root / 'test/pocx/inherited_tests.py'), '--build-dir', str(build)]
    invoke([*runtime, '--phase', 'ctest', '--jobs', str(count), '--timeout', '180'])
    invoke([*runtime, '--phase', 'functional', '--jobs', str(count * 2), '--timeout-factor', '1'])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--jobs', type=int)
    parser.add_argument('--plan', action='store_true')
    parser.add_argument('--phase-consensus', choices=('bitcoin', 'pocx'), help=argparse.SUPPRESS)
    args = parser.parse_args()
    count = args.jobs if args.jobs is not None else int(subprocess.check_output(['nproc'], text=True))
    validate_jobs(count)
    if args.plan and args.phase_consensus:
        parser.error('--plan describes the complete pair; it cannot execute a phase')
    inherited_ci.verify_recipe()
    if args.phase_consensus:
        run_phase(args.phase_consensus, count)
        return 0
    pairs = plan(count, os.environ)
    if args.plan:
        print(json.dumps({'status': 'configured only; not executed', 'phases': [
            {'consensus': row['consensus'], 'command': row['command'],
             'configure_command': configure_command(build_directory(row['consensus']), row['consensus'])}
            for row in pairs]}, indent=2))
        return 0
    print('Running original/native tests on commit ...', flush=True)
    subprocess.run(['git', 'log', '-1'], cwd=ROOT, check=True)
    scratch = ROOT / 'ci_build-evidence'
    scratch.mkdir(exist_ok=True)
    output = Path(tempfile.mkdtemp(prefix='pocx-inherited-revision-', dir=scratch)) / 'execution'
    inherited_ci.execute_and_publish(pairs, output)
    return 0


if __name__ == '__main__':
    sys.exit(main())
