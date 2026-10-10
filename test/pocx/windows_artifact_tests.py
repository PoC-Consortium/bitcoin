#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin PoCX developers
# Distributed under the MIT software license; see COPYING.
"""Run paired Windows artifact Qt, unit, auxiliary and kernel profiles, original first.

This profile covers the upstream run_unit_tests step. Functional execution,
manifest validation and hosted producer/consumer wiring remain separate and
required before claiming full Windows cross-artifact CI coverage.
"""
import argparse
import csv
import json
import os
from pathlib import Path
import sys
import time

from common import ROOT, sha256, short_tmpdir
import process_tree
import qt_parity
import run_qt
import kernel_parity
import unit_assets
import windows_artifact_unit as units
import windows_artifacts

SCOPE = 'Cross-artifact Qt, single-process unit, five auxiliary executables and enabled kernel suite; functional/manifest/hosted CI coverage remains required'


def qt_disabled_reason(options):
    disabled = [key + '=OFF' for key in ('BUILD_GUI', 'BUILD_GUI_TESTS') if options.get(key) == 'OFF']
    if disabled:
        return ', '.join(disabled)
    if any(options.get(key) != 'ON' for key in ('BUILD_GUI', 'BUILD_GUI_TESTS')):
        raise ValueError('Ambiguous Qt build feature configuration')
    return None


def kernel_disabled_reason(options):
    disabled = [key + '=OFF' for key in ('BUILD_KERNEL_LIB', 'BUILD_KERNEL_TEST') if options.get(key) == 'OFF']
    if disabled:
        return ', '.join(disabled)
    if any(options.get(key) != 'ON' for key in ('BUILD_KERNEL_LIB', 'BUILD_KERNEL_TEST')):
        raise ValueError('Ambiguous kernel build feature configuration')
    return None


def expected_rows(row):
    """Keep every known case visible even if an earlier executable fails."""
    native = row['consensus'] == 'pocx'
    options = row['build_options']
    review = json.loads((ROOT / 'test/pocx/unit-parity.json').read_text())
    adapted_suites = {suite for source in json.loads((ROOT / 'test/pocx/coverage.json').read_text())
                      if source['source'] in review['bitcoin_sources'] and source['classification'] == 'adapted'
                      for suite in source.get('covered_behavior', [])}
    rows = []
    def add(framework, case, counting, only, adaptation, *, status='unverified', reason='Not completed in this phase'):
        rows.append({'framework': framework, 'case': case, 'counting_unit': counting,
            'status': status, 'origin': 'pocx-only' if only else 'original',
            'adaptation': adaptation if native else 'original', 'reason': reason, 'assertions_passed': ''})
    disabled = qt_disabled_reason(options)
    for method in sorted(run_qt.expected_cases(native, True)):
        only = method == 'PoCXURITests::nativePaymentURIs'
        adaptation = 'pocx-only' if only else 'adapted' if method in (
            'RPCNestedTests::rpcNestedTests', 'WalletTests::walletTests') else 'unchanged'
        reason = disabled or ('ENABLE_WALLET=OFF' if options.get('ENABLE_WALLET') == 'OFF' and method in (
            'AddressBookTests::addressBookTests', 'WalletTests::walletTests') else None)
        add('qt', method, 'Qt method', only, adaptation, **(
            {'status': 'configuration-disabled', 'reason': reason} if reason else {}))
    unit = row['expected_unit']
    original = set(unit['original'])
    for case in sorted(original | set(unit['additional']) | set(unit['configuration_disabled']) | set(unit['excluded'])):
        only = case not in original
        adaptation = 'pocx-only' if only else 'adapted' if case.split('/')[0] in adapted_suites else 'unchanged'
        status, reason = 'unverified', 'Not completed in this phase'
        if case in unit['configuration_disabled']:
            status, reason = 'configuration-disabled', unit['configuration_disabled'][case]
        elif case in unit['excluded']:
            status, reason = 'reviewed-exclusion', json.dumps(review['excluded'][case], sort_keys=True)
        add('unit', case, 'Boost leaf case', only, adaptation, status=status, reason=reason)
    for binary in windows_artifacts.AUXILIARY:
        add('auxiliary', binary, 'Complete library executable; internal cases are not enumerated here', False, 'unchanged')
    kernel = json.loads((ROOT / 'test/pocx/kernel-parity.json').read_text())
    disabled = kernel_disabled_reason(options)
    for case in kernel['case_review']:
        add('kernel', case['case'], 'Boost leaf case', False, case['classification'], **(
            {'status': 'configuration-disabled', 'reason': disabled} if disabled else {}))
    return rows


def run_phase(payload, row, output, assets, *, environment=None, timeout=2400, execute=process_tree.execute):
    if type(timeout) is not int or timeout < 1:
        raise ValueError('Expected positive process timeout')
    payload, output = payload.resolve(), output.resolve()
    if output.is_relative_to(payload):
        raise ValueError('Reports must be outside immutable artifact payload')
    output.mkdir(parents=True, exist_ok=False)
    options = row['build_options']
    native = row['consensus'] == 'pocx'
    if options.get('ENABLE_POCX') != ('ON' if native else 'OFF'):
        raise ValueError('Artifact phase and compiler configuration differ')
    controller = process_tree.description()
    report = {'status': 'running', 'scope': SCOPE, 'full_windows_ci_pass': False,
        'consensus': row['consensus'], 'host_platform': sys.platform, 'controller': controller,
        'timeout': timeout, 'build_options': options, 'steps': [], 'cases': expected_rows(row)}
    cases = {(case['framework'], case['case']): case for case in report['cases']}
    def passed(framework, case, *, assertions=''):
        record = cases[(framework, case)]
        if record['status'] != 'unverified':
            raise ValueError('Duplicate or disabled artifact case executed: ' + case)
        record.update(status='passed', reason='', assertions_passed=assertions)
    def save():
        (output / 'results.json').write_text(json.dumps(report, indent=2) + '\n')
        with (output / 'cases.csv').open('w', newline='') as stream:
            writer = csv.DictWriter(stream, fieldnames=['framework', 'case', 'counting_unit', 'status', 'origin', 'adaptation', 'reason', 'assertions_passed'])
            writer.writeheader()
            writer.writerows(report['cases'])
    env = {key: value for key, value in (os.environ if environment is None else environment).items()
           if not key.startswith(('BOOST_TEST_', 'QTEST_')) and key != 'SECP256K1_TEST_ITERS'}
    temp = short_tmpdir(output)
    env.update(QT_QPA_PLATFORM='minimal', XDG_CONFIG_HOME=str(temp), TMP=str(temp), TEMP=str(temp), TMPDIR=str(temp))
    env['PATH'] = str(payload / 'bin') + os.pathsep + env.get('PATH', os.defpath)
    def check_binary(name):
        path = payload / name
        if name not in row['files'] or not path.is_file() or sha256(path) != row['files'][name]:
            raise ValueError('Missing or changed required artifact executable: ' + name)
        return path
    def invoke(name, binary, arguments=()):
        path = check_binary(binary)
        command = [str(path), *arguments]
        log = output / (name + '.log')
        step = {'name': name, 'status': 'running', 'command': command, 'binary_sha256': sha256(path)}
        report['steps'].append(step)
        save()
        start = time.monotonic()
        with log.open('w') as stream:
            result = execute(command, cwd=payload, env=env, log=stream, timeout=timeout)
        step.update(**result, seconds=time.monotonic() - start, log_sha256=sha256(log))
        save()
        process_tree.validate_control(controller, result['process_control'], command)
        if result['returncode'] or result['timed_out']:
            raise ValueError('Artifact process failed or timed out: ' + name)
        check_binary(binary)
        step['status'] = 'passed'
        save()
        return log.read_text()
    save()
    try:
        units.validate_assets(assets)
        disabled = qt_disabled_reason(options)
        if disabled:
            report['qt'] = {'status': 'configuration-disabled', 'reason': disabled,
                            'scope': 'Still required in GUI/tests enabled configurations'}
            save()
        else:
            issues = qt_parity.check(ROOT)
            if issues:
                raise ValueError('Qt source review failed: ' + str(issues))
            log = invoke('qt', 'bin/test_bitcoin-qt.exe')
            proof = run_qt.verify_methods(log, native, options.get('ENABLE_WALLET') == 'ON')
            report['qt'] = {'status': 'passed', **proof}
            for method in proof['methods']:
                passed('qt', method)
            save()
        # Preserve unchanged upstream order: Qt, one whole unit process, then
        # exhaustive/noverify/verify secp256k1 and the two univalue executables.
        step = {'name': 'unit', 'status': 'running'}
        report['steps'].append(step)
        save()
        unit_output = output / 'unit'
        child = units.run_phase(payload, row, unit_output, assets, environment=env, timeout=timeout, execute=execute)
        step.update(status=child['status'], report_sha256=sha256(unit_output / 'results.json'))
        for case in child['cases']:
            passed('unit', case['case'], assertions=case['assertions_passed'])
        save()
        for index, binary in enumerate(windows_artifacts.AUXILIARY):
            invoke('auxiliary-' + str(index), binary)
            passed('auxiliary', binary)
            save()
        disabled = kernel_disabled_reason(options)
        if disabled:
            report['kernel'] = {'status': 'configuration-disabled', 'reason': disabled,
                                'scope': 'Still required when kernel tests are enabled'}
        else:
            issues = kernel_parity.check(ROOT)
            if issues:
                raise ValueError('Kernel source review failed: ' + str(issues))
            expected = set(json.loads((ROOT / 'test/pocx/kernel-baseline.json').read_text())['cases'])
            listing = invoke('kernel-listing', 'bin/test_kernel.exe', ['--list_content'])
            if units.runtime_cases(listing, expected):
                raise ValueError('Unexpected disabled kernel registrations')
            xml = output / 'kernel-boost.xml'
            invoke('kernel', 'bin/test_kernel.exe', ['-l', 'test_suite', '--report_format=XML',
                '--report_level=detailed', '--report_sink=' + str(xml)])
            proof = kernel_parity.verify_boost_report(xml.read_text(), expected)
            report['kernel'] = {'status': 'passed', 'original_green': len(expected), 'native_only_green': 0,
                'xml_sha256': sha256(xml), 'assertions_passed': proof['assertions_passed']}
            for case, assertions in proof['cases'].items():
                passed('kernel', case, assertions=assertions)
        save()
        units.validate_assets(assets)
        for name in row['files']:
            if sha256(payload / name) != row['files'][name]:
                raise ValueError('Artifact changed during test phase: ' + name)
        if qt_parity.check(ROOT):
            raise ValueError('Qt source inputs changed during artifact execution')
        if kernel_parity.check(ROOT):
            raise ValueError('Kernel source inputs changed during artifact execution')
        if any(case['status'] == 'unverified' for case in report['cases']):
            raise ValueError('Artifact profile has unverified required cases')
        report['status'] = 'passed'
    except BaseException as error:
        for step in report['steps']:
            if step['status'] == 'running':
                step['status'] = 'failed'
        unit_report = output / 'unit/results.json'
        if unit_report.is_file():
            report['unit_report_sha256'] = sha256(unit_report)
        report.update(status='failed', error=str(error))
        save()
        raise
    save()
    return report


def run_pair(bundle, output, assets, *, root=ROOT, timeout=2400, execute=process_tree.execute, revision=None):
    bundle, output = bundle.resolve(), output.resolve()
    if output.is_relative_to(bundle):
        raise ValueError('Reports must be outside immutable artifact bundle')
    pair = windows_artifacts.verify_pair(bundle, root=root, revision=revision)
    output.mkdir(parents=True, exist_ok=False)
    report = {'status': 'running', 'scope': SCOPE, 'full_windows_ci_pass': False,
        'pair_sha256': sha256(bundle / 'pair.json'), 'phases': [], 'native_execution': 'deferred'}
    def save(): (output / 'results.json').write_text(json.dumps(report, indent=2) + '\n')
    save()
    try:
        for row in pair['phases']:
            if row['consensus'] == 'pocx':
                report['native_execution'] = 'started after original Qt/unit/auxiliary/kernel profile passed'
            phase = {'consensus': row['consensus'], 'status': 'running'}
            report['phases'].append(phase)
            save()
            child = run_phase(bundle / row['consensus'], row, output / row['consensus'], assets,
                              timeout=timeout, execute=execute)
            phase.update(status=child['status'], report_sha256=sha256(output / row['consensus'] / 'results.json'))
            save()
            windows_artifacts.verify_pair(bundle, root=root, revision=revision)
            if sha256(bundle / 'pair.json') != report['pair_sha256']:
                raise ValueError('Artifact manifest changed during test execution')
        report['status'] = 'passed'
    except BaseException as error:
        if report['phases'] and report['phases'][-1]['status'] == 'running':
            phase = report['phases'][-1]
            phase['status'] = 'failed'
            child = output / phase['consensus'] / 'results.json'
            if child.is_file():
                phase['report_sha256'] = sha256(child)
        report.update(status='failed', error=str(error))
        save()
        raise
    save()
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--artifacts', type=Path, required=True)
    parser.add_argument('--output', type=Path)
    parser.add_argument('--timeout', type=int, default=2400)
    parser.add_argument('--plan', action='store_true')
    args = parser.parse_args()
    if args.timeout < 1:
        parser.error('Expected positive --timeout')
    if not args.plan and os.name != 'nt':
        parser.error('Actual artifact Qt/unit/auxiliary/kernel execution requires Windows')
    windows_artifacts.verify_recipe()
    pair = windows_artifacts.verify_pair(args.artifacts)
    if args.plan:
        print(json.dumps({'status': 'configured only; not executed', 'scope': SCOPE, 'full_windows_ci_pass': False,
            'phases': [{'consensus': row['consensus'], 'qt_disabled_reason': qt_disabled_reason(row['build_options']),
                'kernel_disabled_reason': kernel_disabled_reason(row['build_options']),
                'expected_kernel_cases': len(json.loads((ROOT / 'test/pocx/kernel-baseline.json').read_text())['cases']),
                'expected_unit_cases': len(row['expected_unit']['expected']), 'auxiliary_executables': list(windows_artifacts.AUXILIARY)}
                for row in pair['phases']]}, indent=2))
        return 0
    if args.output is None:
        parser.error('Actual execution requires a new --output directory')
    assets = unit_assets.provision(ROOT / 'unit_test_data')
    run_pair(args.artifacts, args.output, assets, timeout=args.timeout)
    return 0


if __name__ == '__main__':
    sys.exit(main())
