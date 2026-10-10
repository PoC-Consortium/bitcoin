#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin PoCX developers
# Distributed under the MIT software license; see COPYING.
"""Check the fixed Bitcoin unit baseline, reviewed adaptations and full execution."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import xml.etree.ElementTree as ET

BASELINE_SHA256 = '3775a5ee6d6e8cf268eec4d20265ec28c8e4b608b7edeb8b590d03ae16a3ec15'
EXCLUDED = {'pow_tests/' + name for name in (
    'get_next_work', 'get_next_work_pow_limit', 'get_next_work_lower_limit_actual',
    'get_next_work_upper_limit_actual', 'CheckProofOfWork_test_negative_target',
    'CheckProofOfWork_test_overflow_target', 'CheckProofOfWork_test_too_easy_target',
    'CheckProofOfWork_test_biger_hash_than_target', 'CheckProofOfWork_test_zero_target',
    'ChainParams_TESTNET4_sanity')}
SHARED_REVIEWS = {
    'src/CMakeLists.txt',
    'src/consensus/params.h',
    'src/kernel/CMakeLists.txt',
    'src/kernel/chainparams.cpp',
    'src/validation.cpp',
    'src/pocx/regtest/forging.cpp',
    'src/pocx/regtest/forging.h',
    'src/pocx/regtest/proof.cpp',
    'src/pocx/regtest/proof.h',

    'src/pocx/test/util/mining.cpp',
    'src/pocx/test/util/setup_common.cpp', 'src/pocx/test/util/forging.h',
    'src/pocx/test/util/bitcoin_block_fixture.h', 'src/node/blockstorage.cpp',
    'src/validation.cpp', 'src/validation.h', 'test/pocx/unit_parity.py',
    'test/pocx/common.py', 'test/pocx/run_unit.py', 'test/pocx/register_unit.py',
    'test/pocx/unit_build.py', 'test/pocx/test_unit_infrastructure.py',
    *(f'src/pocx/test/{name}.cpp' for name in ('pocx_tests', 'pocx_simd_tests',
       'pocx_wire_tests', 'pocx_real_proof_tests', 'pocx_block_builder_tests'))}


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def runtime_cases(output):
    lines = [(len(line) - len(line.lstrip()), line.strip().rstrip('*'),
              line.rstrip().endswith('*'))
             for line in output.splitlines() if line.strip()]
    cases, stack = set(), []
    for i, (indent, name, enabled) in enumerate(lines):
        while stack and stack[-1][0] >= indent:
            stack.pop()
        stack.append((indent, name))
        if enabled and (i + 1 == len(lines) or lines[i + 1][0] <= indent):
            case = '/'.join(item[1] for item in stack)
            if case in cases:
                raise ValueError(f'Duplicate runtime case: {case}')
            cases.add(case)
    return cases


def check(root, record=None):
    issues = []
    baseline_path = root / 'test/pocx/unit-baseline.json'
    manifest_path = root / 'test/pocx/unit-parity.json'
    if not baseline_path.is_file() or digest(baseline_path) != BASELINE_SHA256:
        return [{'source': 'test/pocx/unit-baseline.json', 'reason': 'fixed 737-case baseline changed'}]
    baseline = json.loads(baseline_path.read_text())
    if record is None:
        if not manifest_path.is_file():
            return [{'source': 'test/pocx/unit-parity.json', 'reason': 'unit parity review missing'}]
        record = json.loads(manifest_path.read_text())
    if (record.get('baseline_sha256') != BASELINE_SHA256 or
            set(record.get('excluded', {})) != EXCLUDED):
        issues.append({'source': 'test/pocx/unit-parity.json', 'reason': 'baseline or explicit exclusion membership changed'})
    applicable = set(baseline['cases']) - EXCLUDED
    if (len(baseline['cases']) != 737 or len(applicable) != 727 or
            set(record.get('applicable', [])) != applicable or
            len(record.get('applicable', [])) != len(applicable)):
        issues.append({'source': 'test/pocx/unit-parity.json', 'reason': 'applicable original unit case removed or duplicated'})
    added = record.get('additional', [])
    if len(added) != len(set(added)) or set(added) & set(baseline['cases']):
        issues.append({'source': 'test/pocx/unit-parity.json', 'reason': 'invalid additional native unit membership'})
    reviewed = record.get('reviewed_sources', {})
    selection = (root / 'src/pocx/test/sources.cmake').read_text()
    import re
    selected = {'src/pocx/test/' + name for name in
                re.findall(r'\$\{CMAKE_CURRENT_SOURCE_DIR\}/(adapted/[\w]+\.cpp)', selection)}
    if selected != {path for path in reviewed if '/adapted/' in path}:
        issues.append({'source': 'src/pocx/test/sources.cmake', 'reason': 'adapted unit source selection differs from parity review'})
    if not SHARED_REVIEWS.issubset(reviewed):
        issues.append({'source': 'test/pocx/unit-parity.json', 'reason': 'shared fixture or production storage review removed'})
    bitcoin_sources = record.get('bitcoin_sources', {})
    if len(bitcoin_sources) != 168:
        issues.append({'source': 'test/pocx/unit-parity.json', 'reason': 'original Bitcoin unit/support source inventory changed'})
    for source, expected in bitcoin_sources.items():
        path = root / source
        if not path.is_file() or digest(path) != expected:
            issues.append({'source': source, 'reason': 'original Bitcoin unit/support source changed since review'})
    for source, review in reviewed.items():
        path = root / source
        if not path.is_file() or digest(path) != review['sha256']:
            issues.append({'source': source, 'reason': 'unit adaptation, fixture or storage fix changed since parity review'})
        if 'upstream_source' in review:
            original = root / review['upstream_source']
            if not original.is_file() or digest(original) != review['upstream_sha256']:
                issues.append({'source': review['upstream_source'], 'reason': 'original test changed since adaptation review'})
    return issues


def verify_execution(root, build, result_path, record):
    report = json.loads(result_path.read_text())
    binary = build / 'bin/test_pocx'
    if Path(report['binary']) != binary or report['binary_sha256'] != digest(binary):
        raise ValueError('Wrong or stale PoCX unit binary')
    if report['returncode'] != 0 or report['cache_sha256'] != digest(build / 'CMakeCache.txt'):
        raise ValueError('Failed execution or changed build configuration')
    for source, expected in report['test_sources'].items():
        if digest(Path(source) if Path(source).is_absolute() else root / source) != expected:
            raise ValueError(f'Stale executed unit input: {source}')
    listing = subprocess.run([str(binary), '--list_content'], capture_output=True, text=True, check=True)
    current = runtime_cases(listing.stdout + listing.stderr)
    expected = set(record['applicable']) | set(record['additional'])
    if current != expected:
        raise ValueError(f'Runtime case mismatch: missing={sorted(expected-current)}, extra={sorted(current-expected)}')
    suites = {case.split('/')[0] for case in current}
    if set(report['selected']) != suites or set(report['registered']) != suites:
        raise ValueError('Full runtime suite selection was not executed')
    tests = list(ET.parse(result_path.with_name('junit.xml')).iter('testcase'))
    if (len(tests) != len(suites) or {t.get('name') for t in tests} != suites or
            any(t.find('failure') is not None or t.find('error') is not None or
                t.find('skipped') is not None for t in tests)):
        raise ValueError('Missing, failed or skipped unit suite')
    return {'applicable_original_green': len(record['applicable']),
            'additional_native_green': len(record['additional']), 'excluded': len(record['excluded']),
            'suites_green': len(suites), 'red': 0, 'skipped': 0}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--check', action='store_true', help='Check reviewed sources without executing tests')
    parser.add_argument('--build-dir', type=Path)
    parser.add_argument('--results', type=Path)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[2]
    issues = check(root)
    if issues:
        raise ValueError(issues)
    if args.check:
        print(json.dumps({'status': 'passed', 'issues': []}))
        return
    if not args.build_dir or not args.results:
        parser.error('--build-dir and --results are required unless --check is used')
    record = json.loads((root / 'test/pocx/unit-parity.json').read_text())
    print(json.dumps(verify_execution(root, args.build_dir.resolve(), args.results.resolve(), record), indent=2))


if __name__ == '__main__':
    main()
