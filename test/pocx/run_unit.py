#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin PoCX developers
# Distributed under the MIT software license; see COPYING.
"""Verify CTest registration and run the fixed M1 contract or the full inventory."""
import argparse
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import pocx_bootstrap as pocx_bootstrap
from common import ROOT, sha256, build_options, short_tmpdir, exclusive_lock
from unit_build import verify
import unit_parity
import unit_matrix
import build_configuration
import boost_runtime

REQUIRED = ['pocx_tests', 'pocx_simd_tests', 'crypto_tests', 'serialize_tests', 'uint256_tests', 'util_string_tests', 'util_check_tests']


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--build-dir', required=True)
    parser.add_argument('--config', help='Explicit CMake build configuration, required for multi-config generators')
    selection = parser.add_mutually_exclusive_group()
    selection.add_argument('--all', action='store_true', help='Include inherited failures; never suppress their exit status')
    selection.add_argument('--suite', action='append', help='Explicit suite selection; repeat for multiple suites; missing suites fail')
    parser.add_argument('--jobs', type=int, default=4)
    parser.add_argument('--timeout', type=int, default=180)
    args = parser.parse_args()
    build = Path(args.build_dir).resolve()
    cache = (build / 'CMakeCache.txt').read_text()
    build_configuration.require_source(cache, ROOT)
    selected_config = build_configuration.configuration(cache, args.config)
    if build_options(cache).get('ENABLE_POCX') != 'ON':
        raise ValueError('Expected this worktree built with ENABLE_POCX=ON')
    if not build.is_relative_to(ROOT) or build == ROOT or args.jobs < 1 or args.timeout < 1:
        raise ValueError('Invalid build directory or job count')
    # CTest writes shared Testing/Temporary files; serialize runs in this build.
    _lock = exclusive_lock(build / 'pocx-unit.lock')
    binary = build_configuration.executable(build, 'test_pocx', cache, selected_config)
    listing = subprocess.run([str(binary), '--list_content'], text=True, capture_output=True, check=True)
    discovered = set(re.findall(r'^([A-Za-z_][A-Za-z_0-9]*)\*?$', listing.stdout + listing.stderr, re.M))
    registrations = json.loads(subprocess.check_output(['ctest', '--test-dir', str(build), '--show-only=json-v1'] +
        build_configuration.ctest_arguments(selected_config), text=True))['tests']
    registered = unit_matrix.registered_suites(registrations, binary)
    if not discovered or discovered != registered or not set(REQUIRED).issubset(discovered):
        raise ValueError(f'Empty/missing/extra registrations: discovered={discovered}, registered={registered}')
    inputs, provenance = unit_matrix.provenance_paths(build, cache, selected_config)
    evidence = verify(binary, inputs, build / 'CMakeCache.txt', provenance, discovered)
    initial_provenance_sha256 = sha256(provenance)
    _options = build_options(cache)
    baseline_profile = args.all
    if baseline_profile:
        issues = unit_parity.check(ROOT)
        if issues:
            raise ValueError(f'Unit baseline parity review failed: {issues}')
        configuration, _ = unit_matrix.configuration(build, selected_config)
        expected = unit_matrix.inventory(ROOT, configuration)
        unit_matrix.runtime_inventory(binary, expected['expected'])
    results = Path(tempfile.mkdtemp(prefix='pocx-unit-', dir=build))
    # Unix IPC socket names must fit sockaddr_un; keep TMPDIR short.
    temp = short_tmpdir(build)
    env = boost_runtime.environment(os.environ)
    env.update(TMPDIR=str(temp), BOOST_TEST_REPORT_FORMAT='XML', BOOST_TEST_REPORT_LEVEL='detailed')
    helpers = {source: sha256(ROOT / source) for source in ('test/pocx/run_unit.py',
        'test/pocx/unit_matrix.py', 'test/pocx/unit_parity.py', 'test/pocx/common.py', 'test/pocx/unit_build.py',
        'test/pocx/build_configuration.py', 'test/pocx/boost_runtime.py')}
    _, system_file = unit_matrix.configuration(build, selected_config)
    initial_system_sha256 = sha256(system_file)
    selected = sorted(discovered) if args.all else sorted(set(args.suite)) if args.suite else REQUIRED
    if not set(selected).issubset(discovered):
        raise ValueError(f'Missing requested suites: {sorted(set(selected) - discovered)}')
    timing = unit_matrix.registered_timeouts(build, selected, args.timeout, registrations=registrations)
    command = ['ctest', '--test-dir', str(build), '-j', str(args.jobs), '--output-on-failure',
               '--timeout', str(args.timeout), '--no-tests=error', '-R', '^(' + '|'.join(selected) + ')$',
               '--output-junit', str(results / 'junit.xml')] + build_configuration.ctest_arguments(selected_config)
    with (results / 'ctest.log').open('w') as log:
        result = subprocess.run(command, env=env, stdout=log, stderr=subprocess.STDOUT)
    # CTest truncates successful output in JUnit; preserve the full Boost log too.
    shutil.copyfile(build / 'Testing/Temporary/LastTest.log', results / 'boost.log')
    (results / 'results.json').write_text(json.dumps({
        'command': command, 'suite_timeouts': timing, 'build_configuration': selected_config,
        'selected': selected, 'registered': sorted(registered),
        'binary': str(binary), 'binary_sha256': evidence['binary_sha256'],
        'execution_helpers': helpers, 'target_system_sha256': initial_system_sha256,
        'boost_runtime': boost_runtime.record(env, (results / 'boost.log').read_text()),
        'junit.xml_sha256': sha256(results / 'junit.xml'), 'boost.log_sha256': sha256(results / 'boost.log'),
        'unit_build_provenance': str(provenance), 'unit_build_provenance_sha256': initial_provenance_sha256,
        'test_sources': evidence['sources'],
        'revision': subprocess.check_output(['git', '-C', str(ROOT), 'rev-parse', 'HEAD'], text=True).strip(),
        'cache_sha256': evidence['cache_sha256'], 'build_options': build_options(cache), 'tmpdir': str(temp), 'returncode': result.returncode,
    }, indent=2) + '\n')
    if result.returncode == 0 and baseline_profile:
        parity = unit_matrix.verify_execution(ROOT, build, results / 'results.json', lock_held=True)
        (results / 'verification.json').write_text(json.dumps(parity, indent=2) + '\n')
        report = json.loads((results / 'results.json').read_text())
        report['baseline_parity'] = {key: value for key, value in parity.items() if key != 'cases'}
        (results / 'results.json').write_text(json.dumps(report, indent=2) + '\n')
        print(f'Unit configuration parity: {len(parity["cases"])} individual cases green')
    print(f'Registered {len(registered)} suites; selected {len(selected)}; return code {result.returncode}; results: {results}')
    return result.returncode


if __name__ == '__main__':
    sys.exit(main())
