#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin PoCX developers
# Distributed under the MIT software license; see COPYING.
"""Verify CTest registration and run the fixed M1 contract or the full inventory."""
import argparse
import fcntl
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
sys.dont_write_bytecode = True
from common import ROOT, sha256, build_options, short_tmpdir
from unit_build import verify
import unit_parity

REQUIRED = ['pocx_tests', 'pocx_simd_tests', 'crypto_tests', 'serialize_tests', 'uint256_tests', 'util_string_tests', 'util_check_tests']


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--build-dir', required=True)
    selection = parser.add_mutually_exclusive_group()
    selection.add_argument('--all', action='store_true', help='Include inherited failures; never suppress their exit status')
    selection.add_argument('--suite', action='append', help='Explicit suite selection; repeat for multiple suites; missing suites fail')
    parser.add_argument('--jobs', type=int, default=4)
    args = parser.parse_args()
    build = Path(args.build_dir).resolve()
    cache = (build / 'CMakeCache.txt').read_text()
    if 'ENABLE_POCX:BOOL=ON\n' not in cache or f'CMAKE_HOME_DIRECTORY:INTERNAL={ROOT}\n' not in cache:
        raise ValueError('Expected this worktree built with ENABLE_POCX=ON')
    if not build.is_relative_to(ROOT) or build == ROOT or args.jobs < 1:
        raise ValueError('Invalid build directory or job count')
    # CTest writes shared Testing/Temporary files; serialize runs in this build.
    lock = (build / 'pocx-unit.lock').open('w')
    fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    binary = build / 'bin/test_pocx'
    listing = subprocess.run([str(binary), '--list_content'], text=True, capture_output=True, check=True)
    discovered = set(re.findall(r'^([A-Za-z_][A-Za-z_0-9]*)\*?$', listing.stdout + listing.stderr, re.M))
    registered = json.loads(subprocess.check_output(['ctest', '--test-dir', str(build), '--show-only=json-v1'], text=True))
    registered = {t['name'] for t in registered['tests'] if t.get('command', [''])[0] == str(binary)}
    if not discovered or discovered != registered or not set(REQUIRED).issubset(discovered):
        raise ValueError(f'Empty/missing/extra registrations: discovered={discovered}, registered={registered}')
    provenance = build / 'src/pocx/test/discovered.build.json'
    evidence = verify(binary, build / 'src/pocx/test/unit-inputs.txt', build / 'CMakeCache.txt', provenance, discovered)
    options = build_options(cache)
    baseline_profile = args.all and all(options.get(key) == value for key, value in
        {'ENABLE_WALLET': 'ON', 'ENABLE_IPC': 'ON', 'WITH_USDT': 'OFF'}.items())
    if baseline_profile:
        issues = unit_parity.check(ROOT)
        if issues:
            raise ValueError(f'Unit baseline parity review failed: {issues}')
    results = Path(tempfile.mkdtemp(prefix='pocx-unit-', dir=build))
    # Unix IPC socket names must fit sockaddr_un; keep TMPDIR short.
    temp = short_tmpdir(build)
    env = dict(os.environ, TMPDIR=str(temp))
    selected = sorted(discovered) if args.all else sorted(set(args.suite)) if args.suite else REQUIRED
    if not set(selected).issubset(discovered):
        raise ValueError(f'Missing requested suites: {sorted(set(selected) - discovered)}')
    command = ['ctest', '--test-dir', str(build), '-j', str(args.jobs), '--output-on-failure',
               '--timeout', '180', '--no-tests=error', '-R', '^(' + '|'.join(selected) + ')$',
               '--output-junit', str(results / 'junit.xml')]
    with (results / 'ctest.log').open('w') as log:
        result = subprocess.run(command, env=env, stdout=log, stderr=subprocess.STDOUT)
    # CTest truncates successful output in JUnit; preserve the full Boost log too.
    shutil.copyfile(build / 'Testing/Temporary/LastTest.log', results / 'boost.log')
    (results / 'results.json').write_text(json.dumps({
        'command': command, 'selected': selected, 'registered': sorted(registered),
        'binary': str(binary), 'binary_sha256': sha256(binary),
        'unit_build_provenance': str(provenance), 'unit_build_provenance_sha256': sha256(provenance),
        'test_sources': evidence['sources'],
        'revision': subprocess.check_output(['git', '-C', str(ROOT), 'rev-parse', 'HEAD'], text=True).strip(),
        'cache_sha256': sha256(build / 'CMakeCache.txt'), 'build_options': build_options(cache), 'tmpdir': str(temp), 'returncode': result.returncode,
    }, indent=2) + '\n')
    if result.returncode == 0 and baseline_profile:
        baseline = json.loads((ROOT / 'test/pocx/unit-parity.json').read_text())
        parity = unit_parity.verify_execution(ROOT, build, results / 'results.json', baseline)
        report = json.loads((results / 'results.json').read_text())
        report['baseline_parity'] = parity
        (results / 'results.json').write_text(json.dumps(report, indent=2) + '\n')
        print(f'Unit baseline parity: {parity}')
    print(f'Registered {len(registered)} suites; selected {len(selected)}; return code {result.returncode}; results: {results}')
    return result.returncode


if __name__ == '__main__':
    sys.exit(main())
