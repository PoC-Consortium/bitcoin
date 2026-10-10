#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin PoCX developers
# Distributed under the MIT software license; see COPYING.
"""Check the fixed kernel baseline, reviewed sources and complete native execution."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import xml.etree.ElementTree as ET

from unit_parity import runtime_cases
from build_configuration import configuration, executable, build_arguments, ctest_arguments, require_source
import boost_runtime

ROOT = Path(__file__).resolve().parents[2]
BASELINE_SHA256 = 'a32650e8ac40ed89b2ff3c2fe296499cdc4eb0fb6c7d1ad26a3492566d9b2782'
BITCOIN_INPUTS = {
    'src/test/kernel/CMakeLists.txt', 'src/test/kernel/test_kernel.cpp', 'src/test/kernel/block_data.h',
    'src/kernel/bitcoinkernel.cpp', 'src/kernel/chainparams.cpp',
    'src/primitives/block.cpp', 'src/primitives/block.h', 'src/validation.cpp',
    'src/CMakeLists.txt', 'src/kernel/CMakeLists.txt',
    'src/kernel/bitcoinkernel.h', 'src/kernel/bitcoinkernel_wrapper.h',
    'test/pocx/run_kernel.py', 'test/pocx/kernel_parity.py', 'test/pocx/build_configuration.py',
    'test/pocx/build_environment.py', 'test/pocx/boost_runtime.py',
}


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def check(root, review=None):
    baseline_path = root / 'test/pocx/kernel-baseline.json'
    if not baseline_path.is_file() or digest(baseline_path) != BASELINE_SHA256:
        return [{'source': 'test/pocx/kernel-baseline.json', 'reason': 'fixed original kernel baseline changed'}]
    baseline = json.loads(baseline_path.read_text())
    if review is None:
        review = json.loads((root / 'test/pocx/kernel-parity.json').read_text())
    issues = []
    if (review.get('baseline_sha256') != BASELINE_SHA256 or
            review.get('applicable') != baseline['cases'] or
            len(baseline['cases']) != 16 or review.get('excluded') != {} or
            review.get('additional') != [] or
            {case['case'] for case in review.get('case_review', [])} != set(baseline['cases']) or
            len(review.get('case_review', [])) != 16):
        issues.append({'source': 'test/pocx/kernel-parity.json', 'reason': 'original kernel cases removed or ownership review changed'})
    provenance = json.loads((root / 'test/pocx/kernel/provenance.json').read_text())
    required = set(provenance['sources']) | set(provenance['reviewed_dependencies']) | {
        'src/CMakeLists.txt', 'src/kernel/CMakeLists.txt',
        'src/kernel/bitcoinkernel.h', 'src/kernel/bitcoinkernel_wrapper.h',
        'test/pocx/kernel/parity.json', 'test/pocx/kernel/provenance.json',
        'test/pocx/kernel_parity.py', 'test/pocx/run_kernel.py',
        'test/pocx/build_configuration.py', 'test/pocx/boost_runtime.py', 'test/pocx/test_boost_runtime.py',
        'test/pocx/build_environment.py', 'test/pocx/test_build_environment.py',
        'test/pocx/test_kernel_infrastructure.py', 'test/pocx/test_cross_kernel.py'}
    reviewed = review.get('reviewed_sources', {})
    if set(reviewed) != required:
        issues.append({'source': 'test/pocx/kernel-parity.json', 'reason': 'kernel source/dependency review inventory changed'})
    for name, expected in {**baseline['upstream_files_sha256'], **reviewed}.items():
        path = root / name
        if not path.is_file() or digest(path) != expected:
            issues.append({'source': name, 'reason': 'original kernel source or reviewed native input changed'})
    return issues


def verify_boost_report(text, expected):
    """Verify actual complete kernel XML, with or without a CTest wrapper."""
    try:
        document = ET.fromstring(text)
        if document.tag != 'TestResult' or len(document) != 1 or document[0].tag != 'TestSuite':
            raise ValueError('Expected one complete kernel Boost process report')
        suite = document[0]
        cases = list(suite)
        if (not expected or suite.get('result') != 'passed' or
                int(suite.get('test_cases_passed', '-1')) != len(expected) or
                len(cases) != len(expected) or {case.get('name') for case in cases} != set(expected) or
                any(case.tag != 'TestCase' or case.get('result') != 'passed' or
                    any(case.get(key) != '0' for key in ('assertions_failed', 'warnings_failed', 'expected_failures'))
                    for case in cases) or
                any(suite.get(key) != '0' for key in ('test_cases_failed', 'test_cases_skipped',
                    'test_cases_aborted', 'test_cases_timed_out', 'test_suites_timed_out',
                    'assertions_failed', 'warnings_failed', 'expected_failures'))):
            raise ValueError('Missing, failed, skipped or incomplete kernel cases')
        assertions = {case.get('name'): int(case.get('assertions_passed', '-1')) for case in cases}
        total = int(suite.get('assertions_passed', '-1'))
        # Upstream logging_tests intentionally has no Boost assertions. Preserve
        # it, while requiring real numeric assertion evidence for every leaf.
        if any(count < 0 for count in assertions.values()) or total <= 0 or total < sum(assertions.values()):
            raise ValueError('Missing or inconsistent kernel assertion evidence')
    except (ET.ParseError, TypeError) as error:
        raise ValueError('Invalid kernel Boost XML') from error
    return {'assertions_passed': total, 'cases': assertions}


def verify_execution(root, build, results, review, bitcoin=False):
    report = json.loads(results.read_text())
    cache_text = (build / 'CMakeCache.txt').read_text()
    require_source(cache_text, root)
    selected = configuration(cache_text, report.get('build_configuration'))
    binary = executable(build, 'test_kernel', cache_text, selected)
    cache = cache_text.splitlines()
    if selected is not None:
        for field, required in (('build_command', build_arguments(selected)),
                                ('command', ctest_arguments(selected))):
            command = report.get(field, [])
            if command.count(required[0]) != 1 or command[command.index(required[0]):][:2] != required:
                raise ValueError('Kernel commands do not select the recorded build configuration')
    if report.get('binary', str(binary)) != str(binary):
        raise ValueError('Kernel executable differs from selected configuration')
    consensus = 'bitcoin' if bitcoin else 'pocx'
    required_options = {f'ENABLE_POCX:BOOL={"OFF" if bitcoin else "ON"}', 'BUILD_KERNEL_LIB:BOOL=ON',
                        'BUILD_KERNEL_TEST:BOOL=ON'}
    if not required_options.issubset(cache) or report.get('consensus', 'pocx') != consensus:
        raise ValueError(f'Expected a {consensus} kernel build from this source tree')
    if report['exit_code'] != 0 or report['binary_sha256'] != digest(binary):
        raise ValueError('Failed or stale kernel execution')
    if report['cache_sha256'] != digest(build / 'CMakeCache.txt'):
        raise ValueError('Kernel build configuration changed since execution')
    for name, expected in report['executed_source_snapshot'].items():
        if digest(root / name) != expected:
            raise ValueError(f'Stale executed kernel input: {name}')
    inputs = BITCOIN_INPUTS if bitcoin else set(review['execution_inputs'])
    if set(report['executed_source_snapshot']) != inputs:
        raise ValueError('Kernel execution input inventory differs from review')
    for key in ('boost_report', 'ctest_xml'):
        if digest(root / report[key]) != report[key + '_sha256']:
            raise ValueError(f'Kernel execution evidence changed: {key}')
    listing = subprocess.run([str(binary), '--list_content'], capture_output=True, text=True, check=True)
    baseline = json.loads((root / 'test/pocx/kernel-baseline.json').read_text())
    expected = set(baseline['cases']) if bitcoin else set(review['applicable']) | set(review['additional'])
    if runtime_cases(listing.stdout + listing.stderr) != expected:
        raise ValueError('Kernel runtime registration differs from the fixed baseline')
    kernel = verify_boost_report((root / report['boost_report']).read_text(), expected)
    log = results.with_name('ctest.log')
    if digest(log) != report.get('ctest_log_sha256'):
        raise ValueError('Stale kernel CTest runtime output')
    runtime = boost_runtime.verify(log.read_text(), report.get('boost_runtime'), 1)
    tests = list(ET.parse(root / report['ctest_xml']).iter('testcase'))
    if (len(tests) != 1 or tests[0].get('name') != 'test_kernel' or
            any(tests[0].find(tag) is not None for tag in ('failure', 'error', 'skipped'))):
        raise ValueError('Kernel CTest wrapper failed or was skipped')
    return {'original_green': len(baseline['cases']), 'native_only_green': 0 if bitcoin else len(review['additional']),
            'assertions_passed': kernel['assertions_passed'], 'boost_runtime': runtime, 'failed': 0, 'skipped': 0}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check', action='store_true')
    parser.add_argument('--build-dir', type=Path)
    parser.add_argument('--results', type=Path)
    parser.add_argument('--bitcoin', action='store_true', help='Verify the PoCX-disabled original kernel baseline')
    args = parser.parse_args()
    issues = check(ROOT)
    if issues:
        raise ValueError(issues)
    if args.check:
        print(json.dumps({'status': 'passed', 'issues': []}))
        return
    if not args.build_dir or not args.results:
        parser.error('--build-dir and --results are required unless --check is used')
    review = json.loads((ROOT / 'test/pocx/kernel-parity.json').read_text())
    print(json.dumps(verify_execution(ROOT, args.build_dir.resolve(), args.results.resolve(), review,
                                      bitcoin=args.bitcoin), indent=2))


if __name__ == '__main__':
    main()
