#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin PoCX developers
# Distributed under the MIT software license; see COPYING.
"""Run unchanged Bitcoin CTest unit suites with configuration and leaf gates."""
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
from common import ROOT, sha256, short_tmpdir, exclusive_lock
import unit_matrix
import build_configuration
import boost_runtime


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--build-dir', type=Path, required=True)
    parser.add_argument('--config', help='Explicit CMake build configuration, required for multi-config generators')
    parser.add_argument('--jobs', type=int, default=4)
    parser.add_argument('--timeout', type=int, default=180)
    args = parser.parse_args()
    build = args.build_dir.resolve()
    if not build.is_relative_to(ROOT) or build == ROOT or args.jobs < 1 or args.timeout < 1:
        parser.error('Expected a separate build directory and positive job count')
    cache = (build / 'CMakeCache.txt').read_text()
    build_configuration.require_source(cache, ROOT)
    selected_config = build_configuration.configuration(cache, args.config)
    options, system = unit_matrix.configuration(build, selected_config)
    expected = unit_matrix.inventory(ROOT, options, bitcoin=True)
    binary = build_configuration.executable(build, 'test_bitcoin', cache, selected_config)
    _lock = exclusive_lock(build / 'pocx-unit.lock')
    unit_matrix.runtime_inventory(binary, expected['expected'])
    suites = {case.split('/')[0] for case in expected['expected']}
    tests = json.loads(subprocess.check_output(['ctest', '--test-dir', str(build), '--show-only=json-v1'] +
        build_configuration.ctest_arguments(selected_config), text=True))['tests']
    registered = unit_matrix.registered_suites(tests, binary)
    if registered != suites:
        raise ValueError('Original Bitcoin CTest registrations differ from runtime unit inventory')
    timing = unit_matrix.registered_timeouts(build, suites, args.timeout, registrations=tests)
    output = Path(tempfile.mkdtemp(prefix='bitcoin-unit-', dir=build))
    temp = short_tmpdir(build)
    env = boost_runtime.environment(os.environ)
    env.update(TMPDIR=str(temp), BOOST_TEST_REPORT_FORMAT='XML', BOOST_TEST_REPORT_LEVEL='detailed')
    review = json.loads((ROOT / 'test/pocx/unit-parity.json').read_text())
    report = {'binary': str(binary), 'binary_sha256': sha256(binary), 'suite_timeouts': timing,
              'build_configuration': selected_config,
              'cache_sha256': sha256(build / 'CMakeCache.txt'), 'build_options': options,
              'target_system_sha256': sha256(system), 'selected': sorted(suites), 'registered': sorted(registered),
              'test_sources': review['bitcoin_sources'], 'tmpdir': str(temp),
              'execution_helpers': {source: sha256(ROOT / source) for source in (
                  'test/pocx/run_bitcoin_unit.py', 'test/pocx/unit_matrix.py',
                  'test/pocx/unit_parity.py', 'test/pocx/common.py', 'test/pocx/build_configuration.py',
                  'test/pocx/boost_runtime.py')}}
    command = ['ctest', '--test-dir', str(build), '-j', str(args.jobs), '--output-on-failure',
               '--timeout', str(args.timeout), '--no-tests=error', '-R', '^(' + '|'.join(map(re.escape, sorted(suites))) + ')$',
               '--output-junit', str(output / 'junit.xml')] + build_configuration.ctest_arguments(selected_config)
    with (output / 'ctest.log').open('w') as log:
        result = subprocess.run(command, env=env, stdout=log, stderr=subprocess.STDOUT)
    shutil.copyfile(build / 'Testing/Temporary/LastTest.log', output / 'boost.log')
    report.update(command=command, returncode=result.returncode,
                  boost_runtime=boost_runtime.record(env, (output / 'boost.log').read_text()),
                  **{name + '_sha256': sha256(output / name) for name in ('junit.xml', 'boost.log')})
    result_path = output / 'results.json'
    result_path.write_text(json.dumps(report, indent=2) + '\n')
    if result.returncode == 0:
        verdict = unit_matrix.verify_execution(ROOT, build, result_path, bitcoin=True, lock_held=True)
        (output / 'verification.json').write_text(json.dumps(verdict, indent=2) + '\n')
        print(f'Original Bitcoin configuration parity: {len(verdict["cases"])} individual cases green')
    print(f'Bitcoin unit returncode={result.returncode}; results: {output}', flush=True)
    return result.returncode


if __name__ == '__main__':
    sys.exit(main())
