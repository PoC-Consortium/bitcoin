#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin PoCX developers
# Distributed under the MIT software license; see COPYING.
"""Rebuild Qt tests and require every configured original/native method to pass."""
import argparse
from collections import Counter
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import time
import xml.etree.ElementTree as ET

from common import ROOT, build_options, sha256
from build_configuration import configuration, executable, build_arguments, ctest_arguments, require_source
from build_environment import run_build
import qt_parity


def expected_cases(native, wallet):
    baseline = json.loads((ROOT / 'test/pocx/qt-baseline.json').read_text())
    cases = set(baseline['cases'])
    if not wallet:
        cases -= {'AddressBookTests::addressBookTests', 'WalletTests::walletTests'}
    if native:
        cases.update(json.loads((ROOT / 'test/pocx/qt-parity.json').read_text())['additional'])
    return cases


def verify_methods(log, native, wallet):
    """Verify real Qt output, shared by CTest and direct artifact execution."""
    if re.search(r'\b(?:FAIL!|SKIP|XFAIL|XPASS)\s*:', log):
        raise ValueError('Qt reported a failed, skipped or expected-failure test')
    passed = re.findall(r'\bPASS\s*:\s+(\w+::\w+)\([^\n]*\)', log)
    methods = Counter(case for case in passed
                      if not case.endswith(('::initTestCase', '::cleanupTestCase')))
    expected = expected_cases(native, wallet)
    if set(methods) != expected or any(count != 1 for count in methods.values()):
        raise ValueError(f'Qt method inventory mismatch: missing={sorted(expected - methods.keys())}, '
                         f'extra={sorted(methods.keys() - expected)}, counts={dict(methods)}')
    return {'original_green': len(expected) - int(native), 'native_only_green': int(native),
            'failed': 0, 'skipped': 0, 'methods': sorted(methods)}


def verify_output(log, junit, native, wallet):
    result = verify_methods(log, native, wallet)
    tests = list(ET.fromstring(junit).iter('testcase'))
    if (len(tests) != 1 or tests[0].get('name') != 'test_bitcoin-qt' or
            any(tests[0].find(tag) is not None for tag in ('failure', 'error', 'skipped'))):
        raise ValueError('Qt CTest wrapper failed, was skipped or did not run exactly once')
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--build-dir', type=Path, required=True)
    parser.add_argument('--output-dir', type=Path, required=True)
    parser.add_argument('--jobs', type=int, default=3)
    parser.add_argument('--timeout', type=int, default=180)
    parser.add_argument('--config', help='Required configuration for Visual Studio/Ninja Multi-Config builds')
    args = parser.parse_args()
    build, output = args.build_dir.resolve(), args.output_dir.resolve()
    if args.jobs < 1 or args.timeout < 1 or build == ROOT or not build.is_relative_to(ROOT):
        parser.error('Use a build directory in this worktree and positive --jobs')
    output.mkdir(parents=True, exist_ok=True)
    result = output / 'verification.json'
    report = {'status': 'failed', 'phase': 'preparing'}

    def save():
        result.write_text(json.dumps(report, indent=2) + '\n')

    save()
    issues = qt_parity.check(ROOT)
    if issues:
        raise ValueError(issues)
    cache = build / 'CMakeCache.txt'
    options = build_options(cache.read_text())
    selected = configuration(cache.read_text(), args.config)
    require_source(cache.read_text(), ROOT)
    if (any(options.get(key) != 'ON' for key in ('BUILD_GUI', 'BUILD_GUI_TESTS', 'BUILD_TESTS')) or
            options.get('ENABLE_POCX') not in ('ON', 'OFF')):
        raise ValueError('Configure Qt tests from this source worktree first')
    native, wallet = options['ENABLE_POCX'] == 'ON', options.get('ENABLE_WALLET') == 'ON'
    command = ['cmake', '--build', str(build), '--target', 'test_bitcoin-qt', '-j', str(args.jobs)]
    command += build_arguments(selected)
    with (output / 'build.log').open('w') as log:
        run_build(command, stdout=log, stderr=subprocess.STDOUT, check=True)
    review = json.loads((ROOT / 'test/pocx/qt-parity.json').read_text())
    baseline = json.loads((ROOT / 'test/pocx/qt-baseline.json').read_text())
    inputs = set(baseline['upstream_files_sha256']) | set(review['reviewed_build_sources'])
    inputs.update(('test/pocx/run_qt.py', 'test/pocx/build_configuration.py'))
    if native:
        inputs.update(review['owned_sources'])
    snapshot = {name: sha256(ROOT / name) for name in sorted(inputs)}
    binary = executable(build, 'test_bitcoin-qt', cache.read_text(), selected)
    report.update(phase='execution', source_revision=subprocess.check_output(
        ['git', '-C', str(ROOT), 'rev-parse', 'HEAD'], text=True).strip(),
        build_options=options, build_configuration=selected, binary=str(binary), executed_source_snapshot=snapshot,
        binary_sha256=sha256(binary), cache_sha256=sha256(cache), build_command=command)
    junit = output / 'ctest.xml'
    junit.unlink(missing_ok=True)
    command = ['ctest', '--test-dir', str(build / 'src/qt/test'), '-R', '^test_bitcoin-qt$',
               '--verbose', '--timeout', str(args.timeout), '--no-tests=error', '--output-junit', str(junit)]
    command += ctest_arguments(selected)
    started = time.monotonic()
    with tempfile.TemporaryDirectory(prefix='qt-config-', dir=build) as config:
        env = {key: value for key, value in os.environ.items() if not key.startswith('QTEST_')}
        env.update(QT_QPA_PLATFORM='minimal', XDG_CONFIG_HOME=config)
        with (output / 'ctest.log').open('w') as log:
            execution = subprocess.run(command, env=env, stdout=log, stderr=subprocess.STDOUT)
    report.update(command=command, exit_code=execution.returncode, seconds=time.monotonic() - started)
    save()
    if execution.returncode:
        raise ValueError('Qt execution failed; see ctest.log')
    if (sha256(binary) != report['binary_sha256'] or sha256(cache) != report['cache_sha256'] or
            snapshot != {name: sha256(ROOT / name) for name in snapshot} or qt_parity.check(ROOT)):
        raise ValueError('Qt inputs changed during execution')
    report.update(verify_output((output / 'ctest.log').read_text(), junit.read_text(), native, wallet),
                  status='passed', phase='complete', ctest_xml_sha256=sha256(junit),
                  ctest_log_sha256=sha256(output / 'ctest.log'))
    save()
    print(json.dumps({key: report[key] for key in ('status', 'original_green', 'native_only_green',
                                                  'failed', 'skipped')}, indent=2))


if __name__ == '__main__':
    main()
