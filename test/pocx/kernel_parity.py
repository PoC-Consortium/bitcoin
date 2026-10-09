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

ROOT = Path(__file__).resolve().parents[2]
BASELINE_SHA256 = 'a32650e8ac40ed89b2ff3c2fe296499cdc4eb0fb6c7d1ad26a3492566d9b2782'


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
        'test/pocx/test_kernel_infrastructure.py'}
    reviewed = review.get('reviewed_sources', {})
    if set(reviewed) != required:
        issues.append({'source': 'test/pocx/kernel-parity.json', 'reason': 'kernel source/dependency review inventory changed'})
    for name, expected in {**baseline['upstream_files_sha256'], **reviewed}.items():
        path = root / name
        if not path.is_file() or digest(path) != expected:
            issues.append({'source': name, 'reason': 'original kernel source or reviewed native input changed'})
    return issues


def verify_execution(root, build, results, review):
    report = json.loads(results.read_text())
    binary = build / 'bin/test_kernel'
    cache = (build / 'CMakeCache.txt').read_text().splitlines()
    required_options = {'ENABLE_POCX:BOOL=ON', 'BUILD_KERNEL_LIB:BOOL=ON',
                        'BUILD_KERNEL_TEST:BOOL=ON', f'CMAKE_HOME_DIRECTORY:INTERNAL={root}'}
    if not required_options.issubset(cache):
        raise ValueError('Expected a native kernel build from this source tree')
    if report['exit_code'] != 0 or report['binary_sha256'] != digest(binary):
        raise ValueError('Failed or stale kernel execution')
    if report['cache_sha256'] != digest(build / 'CMakeCache.txt'):
        raise ValueError('Kernel build configuration changed since execution')
    for name, expected in report['executed_source_snapshot'].items():
        if digest(root / name) != expected:
            raise ValueError(f'Stale executed kernel input: {name}')
    if set(report['executed_source_snapshot']) != set(review['execution_inputs']):
        raise ValueError('Kernel execution input inventory differs from review')
    for key in ('boost_report', 'ctest_xml'):
        if digest(root / report[key]) != report[key + '_sha256']:
            raise ValueError(f'Kernel execution evidence changed: {key}')
    listing = subprocess.run([str(binary), '--list_content'], capture_output=True, text=True, check=True)
    expected = set(review['applicable']) | set(review['additional'])
    if runtime_cases(listing.stdout + listing.stderr) != expected:
        raise ValueError('Kernel runtime registration differs from the fixed baseline')
    suite = ET.parse(root / report['boost_report']).getroot().find('TestSuite')
    cases = list(suite.iter('TestCase'))
    if (len(cases) != len(expected) or {case.get('name') for case in cases} != expected or
            any(case.get('result') != 'passed' or case.get('assertions_failed') != '0' or
                case.get('warnings_failed') != '0' or
                case.get('expected_failures') != '0' for case in cases) or
            any(suite.get(key) != '0' for key in ('test_cases_failed', 'test_cases_skipped',
                'test_cases_aborted', 'test_cases_timed_out', 'test_suites_timed_out',
                'assertions_failed', 'warnings_failed', 'expected_failures'))):
        raise ValueError('Missing, failed, skipped or incomplete kernel cases')
    tests = list(ET.parse(root / report['ctest_xml']).iter('testcase'))
    if (len(tests) != 1 or tests[0].get('name') != 'test_kernel' or
            any(tests[0].find(tag) is not None for tag in ('failure', 'error', 'skipped'))):
        raise ValueError('Kernel CTest wrapper failed or was skipped')
    return {'original_green': len(review['applicable']), 'native_only_green': len(review['additional']),
            'assertions_passed': int(suite.get('assertions_passed')), 'failed': 0, 'skipped': 0}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check', action='store_true')
    parser.add_argument('--build-dir', type=Path)
    parser.add_argument('--results', type=Path)
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
    print(json.dumps(verify_execution(ROOT, args.build_dir.resolve(), args.results.resolve(), review), indent=2))


if __name__ == '__main__':
    main()
