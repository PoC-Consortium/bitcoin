#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin PoCX developers
# Distributed under the MIT software license; see COPYING.
"""Rebuild and run every applicable native kernel case, retaining checked evidence."""
import argparse
import datetime
import json
import os
from pathlib import Path
import subprocess
import tempfile
import time

import kernel_parity

ROOT = kernel_parity.ROOT


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--build-dir', type=Path, required=True)
    parser.add_argument('--output-dir', type=Path, required=True)
    parser.add_argument('--jobs', type=int, default=3)
    args = parser.parse_args()
    build, output = args.build_dir.resolve(), args.output_dir.resolve()
    if args.jobs < 1:
        parser.error('--jobs must be positive')
    output.mkdir(parents=True, exist_ok=True)
    results = output / 'verification.json'
    results.write_text(json.dumps({'status': 'failed', 'phase': 'preparing build and execution'}) + '\n')
    issues = kernel_parity.check(ROOT)
    if issues:
        raise ValueError(issues)
    required = {'ENABLE_POCX:BOOL=ON', 'BUILD_KERNEL_LIB:BOOL=ON',
                'BUILD_KERNEL_TEST:BOOL=ON', f'CMAKE_HOME_DIRECTORY:INTERNAL={ROOT}'}
    if not required.issubset((build / 'CMakeCache.txt').read_text().splitlines()):
        raise ValueError('Configure a native kernel build from this source tree first')
    review = json.loads((ROOT / 'test/pocx/kernel-parity.json').read_text())
    build_command = ['cmake', '--build', str(build), '--target', 'test_kernel', '-j', str(args.jobs)]
    with (output / 'build.log').open('w') as log:
        subprocess.run(build_command, stdout=log, stderr=subprocess.STDOUT, check=True)
    issues = kernel_parity.check(ROOT)
    if issues:
        raise ValueError(issues)
    snapshot = {name: kernel_parity.digest(ROOT / name) for name in review['execution_inputs']}
    report = {
        'source_revision': subprocess.check_output(['git', '-C', str(ROOT), 'rev-parse', 'HEAD'], text=True).strip(),
        'executed_source_snapshot': snapshot,
        'binary_sha256': kernel_parity.digest(build / 'bin/test_kernel'),
        'cache_sha256': kernel_parity.digest(build / 'CMakeCache.txt'),
        'build_command': build_command,
        'boost_report': str(output / 'boost-report.xml'),
        'ctest_xml': str(output / 'ctest.xml'),
    }
    command = ['ctest', '--test-dir', str(build / 'src/pocx/test/kernel'),
               '-R', '^test_kernel$', '--verbose', '--timeout', '900', '--no-tests=error',
               '--output-junit', report['ctest_xml']]
    # Prevent inherited Boost filters, disabled reports or exception controls
    # from turning a partial/empty execution into an apparent green result.
    env = {key: value for key, value in os.environ.items() if not key.startswith('BOOST_TEST_')}
    env.update(BOOST_TEST_REPORT_LEVEL='detailed', BOOST_TEST_REPORT_FORMAT='XML',
               BOOST_TEST_REPORT_SINK=report['boost_report'], BOOST_TEST_LOG_LEVEL='test_suite')
    for key in ('boost_report', 'ctest_xml'):
        Path(report[key]).unlink(missing_ok=True)
    started = time.monotonic()
    print('Running all 16 native kernel cases; detailed output is in', output / 'ctest.log', flush=True)
    with tempfile.TemporaryDirectory(prefix='pocx-kernel-') as scratch, (output / 'ctest.log').open('w') as log:
        env['TMPDIR'] = scratch
        execution = subprocess.run(command, env=env, stdout=log, stderr=subprocess.STDOUT)
    report.update(exit_code=execution.returncode, seconds=time.monotonic() - started,
                  command=command, verified_at_utc=datetime.datetime.now(datetime.timezone.utc).isoformat())
    # Store failures too; a failed run can never retain an old green summary.
    report['status'] = 'failed'
    results.write_text(json.dumps(report, indent=2) + '\n')
    for key in ('boost_report', 'ctest_xml'):
        report[key + '_sha256'] = kernel_parity.digest(Path(report[key]))
    results.write_text(json.dumps(report, indent=2) + '\n')
    issues = kernel_parity.check(ROOT)
    if issues:
        raise ValueError(issues)
    checked = kernel_parity.verify_execution(ROOT, build, results, review)
    report.update(checked, status='passed')
    results.write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(checked, indent=2))


if __name__ == '__main__':
    main()
