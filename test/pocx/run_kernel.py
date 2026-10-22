#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin PoCX developers
# Distributed under the MIT software license; see COPYING.
"""Rebuild and run the complete Bitcoin or PoCX kernel suite with checked evidence."""
import argparse
import datetime
import json
import os
from pathlib import Path
import subprocess
import tempfile
import time

import kernel_parity
from build_configuration import configuration, executable, build_arguments, ctest_arguments, require_source
from build_environment import run_build
import boost_runtime

ROOT = kernel_parity.ROOT


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--build-dir', type=Path, required=True)
    parser.add_argument('--output-dir', type=Path, required=True)
    parser.add_argument('--jobs', type=int, default=3)
    parser.add_argument('--timeout', type=int, default=900)
    parser.add_argument('--config', help='Required configuration for Visual Studio/Ninja Multi-Config builds')
    parser.add_argument('--bitcoin', action='store_true', help='Run the PoCX-disabled original kernel baseline')
    args = parser.parse_args()
    build, output = args.build_dir.resolve(), args.output_dir.resolve()
    if args.jobs < 1 or args.timeout < 1 or build == ROOT or not build.is_relative_to(ROOT):
        parser.error('Use a build directory in this worktree and positive --jobs')
    output.mkdir(parents=True, exist_ok=True)
    results = output / 'verification.json'
    results.write_text(json.dumps({'status': 'failed', 'phase': 'preparing build and execution'}) + '\n')
    issues = kernel_parity.check(ROOT)
    if issues:
        raise ValueError(issues)
    consensus = 'bitcoin' if args.bitcoin else 'pocx'
    required = {f'ENABLE_POCX:BOOL={"OFF" if args.bitcoin else "ON"}', 'BUILD_KERNEL_LIB:BOOL=ON',
                'BUILD_KERNEL_TEST:BOOL=ON'}
    cache = (build / 'CMakeCache.txt').read_text()
    selected = configuration(cache, args.config)
    require_source(cache, ROOT)
    if not required.issubset(cache.splitlines()):
        raise ValueError(f'Configure a {consensus} kernel build from this source tree first')
    review = json.loads((ROOT / 'test/pocx/kernel-parity.json').read_text())
    build_command = ['cmake', '--build', str(build), '--target', 'test_kernel', '-j', str(args.jobs)]
    build_command += build_arguments(selected)
    with (output / 'build.log').open('w') as log:
        run_build(build_command, stdout=log, stderr=subprocess.STDOUT, check=True)
    issues = kernel_parity.check(ROOT)
    if issues:
        raise ValueError(issues)
    inputs = kernel_parity.BITCOIN_INPUTS if args.bitcoin else review['execution_inputs']
    snapshot = {name: kernel_parity.digest(ROOT / name) for name in sorted(inputs)}
    binary = executable(build, 'test_kernel', cache, selected)
    report = {
        'source_revision': subprocess.check_output(['git', '-C', str(ROOT), 'rev-parse', 'HEAD'], text=True).strip(),
        'executed_source_snapshot': snapshot,
        'binary_sha256': kernel_parity.digest(binary),
        'binary': str(binary), 'build_configuration': selected,
        'consensus': consensus,
        'cache_sha256': kernel_parity.digest(build / 'CMakeCache.txt'),
        'build_command': build_command,
        'boost_report': str(output / 'boost-report.xml'),
        'ctest_xml': str(output / 'ctest.xml'),
    }
    test_dir = 'src/test/kernel' if args.bitcoin else 'src/pocx/test/kernel'
    command = ['ctest', '--test-dir', str(build / test_dir),
               '-R', '^test_kernel$', '--verbose', '--timeout', str(args.timeout), '--no-tests=error',
               '--output-junit', report['ctest_xml']]
    command += ctest_arguments(selected)
    # Prevent inherited Boost filters, disabled reports or exception controls
    # from turning a partial/empty execution into an apparent green result.
    env = boost_runtime.environment(os.environ)
    env.update(BOOST_TEST_REPORT_LEVEL='detailed', BOOST_TEST_REPORT_FORMAT='XML',
               BOOST_TEST_REPORT_SINK=report['boost_report'], BOOST_TEST_LOG_LEVEL='test_suite')
    for key in ('boost_report', 'ctest_xml'):
        Path(report[key]).unlink(missing_ok=True)
    started = time.monotonic()
    print(f'Running all 16 {consensus} kernel cases; detailed output is in', output / 'ctest.log', flush=True)
    with tempfile.TemporaryDirectory(prefix='pocx-kernel-') as scratch, (output / 'ctest.log').open('w') as log:
        env['TMPDIR'] = scratch
        execution = subprocess.run(command, env=env, stdout=log, stderr=subprocess.STDOUT)
    report.update(exit_code=execution.returncode, seconds=time.monotonic() - started,
                  ctest_log_sha256=kernel_parity.digest(output / 'ctest.log'),
                  boost_runtime=boost_runtime.record(env, (output / 'ctest.log').read_text()),
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
    checked = kernel_parity.verify_execution(ROOT, build, results, review, bitcoin=args.bitcoin)
    report.update(checked, status='passed')
    results.write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(checked, indent=2))


if __name__ == '__main__':
    main()
