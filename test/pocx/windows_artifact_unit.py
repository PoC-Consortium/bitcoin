#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin PoCX developers
# Distributed under the MIT software license; see COPYING.
"""Verify complete cross-artifact unit suites in one process on the target host.

The public pair profile covers units only. Qt, auxiliary and functional runtime
coverage remains required in the full Windows cross-artifact CI consumer.
"""
import argparse
import csv
import json
import os
from pathlib import Path
import re
import sys
import time
import xml.etree.ElementTree as ET

from common import ROOT, sha256, short_tmpdir
import process_tree
import unit_assets
import unit_matrix
import unit_parity
import windows_artifacts

# These unchanged upstream helper cases are disabled by default and run only
# when another test launches the executable as a subprocess fixture. They are
# absent from the fixed 737-case inventory and must never become waived tests.
SUBPROCESS_FIXTURES = {'mock_process/' + name for name in (
    'valid_json', 'nonzeroexit_nooutput', 'nonzeroexit_stderroutput', 'invalid_json', 'pass_stdin_to_stdout')}


def validate_assets(assets):
    if (assets.get('commit') != unit_assets.COMMIT or assets.get('sha256') != unit_assets.SHA256 or
            assets.get('vectors') != unit_assets.VECTORS):
        raise ValueError('Unit artifact execution requires pinned original script vectors')
    unit_assets.validate((Path(assets['directory']) / 'script_assets_test.json').read_bytes())


def runtime_cases(listing, expected):
    enabled = unit_parity.runtime_cases(listing)
    all_cases = unit_parity.runtime_cases('\n'.join(line.rstrip().rstrip('*') + '*' for line in listing.splitlines() if line.strip()))
    disabled = all_cases - enabled
    if enabled != set(expected) or not disabled.issubset(SUBPROCESS_FIXTURES):
        raise ValueError('Artifact unit runtime inventory differs from reviewed enabled cases or subprocess helpers')
    return disabled


def single_process_leaves(xml, expected, disabled):
    if not expected or not set(disabled).issubset(SUBPROCESS_FIXTURES):
        raise ValueError('Invalid single-process unit inventory')
    root = ET.fromstring(xml)
    if root.tag != 'TestResult' or len(root) != 1 or root[0].tag != 'TestSuite':
        raise ValueError('Expected one complete Boost process report')
    module = root[0]
    try:
        if (module.get('result') != 'passed' or int(module.get('assertions_failed')) != 0 or
                int(module.get('test_cases_passed')) != len(expected) or
                int(module.get('test_cases_skipped')) != len(disabled) or
                any(int(module.get(name, '0')) != 0 for name in
                    ('test_cases_failed', 'test_cases_aborted', 'test_cases_timed_out', 'test_suites_timed_out'))):
            raise ValueError('Failed, incomplete or unexpectedly skipped single-process unit report')
    except (TypeError, ValueError) as error:
        raise ValueError('Invalid single-process Boost summary') from error
    leaves, seen_suites = {}, set()
    def walk(node, path):
        name = node.get('name')
        if not name: raise ValueError('Unnamed Boost suite or case')
        case = '/'.join([*path, name])
        if node.tag == 'TestSuite':
            if case in seen_suites or node.get('result') not in ('passed', 'skipped'):
                raise ValueError('Duplicate or failed single-process Boost suite')
            seen_suites.add(case)
            for child in node: walk(child, [*path, name])
        elif node.tag == 'TestCase':
            if node.get('result') == 'skipped' and case in disabled: return
            if (case in leaves or case not in expected or node.get('result') != 'passed' or
                    node.get('assertions_failed') != '0'):
                raise ValueError('Unexpected, duplicate, failed or skipped unit case: ' + case)
            assertions = int(node.get('assertions_passed', '-1'))
            if assertions < 0 or case in unit_matrix.AVX2_CASES | unit_matrix.SSE2_CASES and assertions == 0:
                raise ValueError('Missing executed unit assertions: ' + case)
            leaves[case] = assertions
        else: raise ValueError('Unexpected Boost report node')
    for child in module: walk(child, [])
    if set(leaves) != set(expected): raise ValueError('Missing executed single-process unit leaf cases')
    return leaves


def run_phase(payload, row, output, assets, *, environment=None, timeout=2400, execute=process_tree.execute):
    if type(timeout) is not int or timeout < 1: raise ValueError('Expected a positive whole-process unit timeout')
    payload, output = payload.resolve(), output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    binary = payload / row['unit_binary']
    expected = set(row['expected_unit']['expected'])
    if sha256(binary) != row['files'][row['unit_binary']]: raise ValueError('Stale artifact unit executable')
    env = {key: value for key, value in (os.environ if environment is None else environment).items()
           if not key.startswith('BOOST_TEST_')}
    temp = short_tmpdir(output)
    env.update(DIR_UNIT_TEST_DATA=assets['directory'], TMP=str(temp), TEMP=str(temp), TMPDIR=str(temp))
    env['PATH'] = str(payload / 'bin') + os.pathsep + env.get('PATH', os.defpath)
    controller = process_tree.description()
    report = {'status': 'running', 'scope': 'Complete enabled unit inventory in one process; full Windows CI profile is separate',
        'consensus': row['consensus'], 'host_platform': sys.platform, 'timeout': timeout,
        'binary': str(binary), 'binary_sha256': sha256(binary), 'controller': controller,
        'expected_unit': row['expected_unit'], 'unit_assets': assets, 'steps': []}
    def save(): (output / 'results.json').write_text(json.dumps(report, indent=2) + '\n')
    def invoke(name, command):
        log = output / (name + '.log')
        started = time.monotonic()
        with log.open('w') as stream:
            result = execute(command, cwd=payload, env=env, log=stream, timeout=timeout)
        step = {'name': name, 'command': command, 'seconds': time.monotonic() - started,
                'log_sha256': sha256(log), **result}
        report['steps'].append(step); save()
        process_tree.validate_control(controller, result['process_control'], command)
        if result['returncode'] or result['timed_out']: raise ValueError('Artifact unit process failed or timed out')
        return log.read_text()
    save()
    try:
        if 'script_assets_tests/script_assets_test' in expected: validate_assets(assets)
        listing = invoke('listing', [str(binary), '--list_content'])
        disabled = runtime_cases(listing, expected)
        report['default_disabled_subprocess_helpers'] = sorted(disabled)
        # Preserve upstream's single process, default suite ordering and log
        # level. Only XML reporting is added; no suite/case filter is supplied.
        xml = output / 'boost.xml'
        command = [str(binary), '-l', 'test_suite', '--report_format=XML', '--report_level=detailed',
                   '--report_sink=' + str(xml)]
        log = invoke('unit', command)
        if re.search('skipping script_assets_test|skipping total_ram', log):
            raise ValueError('Required unit prerequisite was skipped')
        leaves = single_process_leaves(xml.read_text(), expected, disabled)
        if 'script_assets_tests/script_assets_test' in expected: validate_assets(assets)
        if sha256(binary) != report['binary_sha256']: raise ValueError('Artifact unit binary changed during execution')
        report.update(status='passed', xml_sha256=sha256(xml), cases=[
            {'case': case, 'status': 'passed', 'origin': 'original' if case in row['expected_unit']['original'] else 'native',
             'assertions_passed': assertions} for case, assertions in sorted(leaves.items())])
        with (output / 'cases.csv').open('w', newline='') as stream:
            writer = csv.DictWriter(stream, fieldnames=['case', 'status', 'origin', 'assertions_passed'])
            writer.writeheader(); writer.writerows(report['cases'])
    except BaseException as error:
        report.update(status='failed', error=str(error)); save(); raise
    save()
    return report


def run_pair(bundle, output, assets, *, root=ROOT, timeout=2400, execute=process_tree.execute, revision=None):
    bundle, output = bundle.resolve(), output.resolve()
    if output.resolve().is_relative_to(bundle.resolve()):
        raise ValueError('Unit reports must be outside the immutable artifact bundle')
    pair = windows_artifacts.verify_pair(bundle, root=root, revision=revision)
    output.mkdir(parents=True, exist_ok=False)
    report = {'status': 'running', 'scope': 'Unit-only artifact profile; Qt, auxiliary and functional CI coverage remain separate',
              'pair_sha256': sha256(bundle / 'pair.json'), 'phases': [], 'native_execution': 'deferred'}
    def save(): (output / 'results.json').write_text(json.dumps(report, indent=2) + '\n')
    save()
    try:
        for row in pair['phases']:
            if row['consensus'] == 'pocx': report['native_execution'] = 'started'
            phase = {'consensus': row['consensus'], 'status': 'running'}
            report['phases'].append(phase)
            save()
            validate_assets(assets)
            child = run_phase(bundle / row['consensus'], row, output / row['consensus'], assets,
                              timeout=timeout, execute=execute)
            validate_assets(assets)
            phase.update(status=child['status'], report_sha256=sha256(output / row['consensus'] / 'results.json'))
            save()
            windows_artifacts.verify_pair(bundle, root=root, revision=revision)
            if report['pair_sha256'] != sha256(bundle / 'pair.json'): raise ValueError('Artifact manifest changed during unit execution')
        report['status'] = 'passed'
    except BaseException as error:
        if report['phases'] and report['phases'][-1]['status'] == 'running':
            phase = report['phases'][-1]
            phase['status'] = 'failed'
            child = output / phase['consensus'] / 'results.json'
            if child.is_file(): phase['report_sha256'] = sha256(child)
        report.update(status='failed', error=str(error)); save(); raise
    save()
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--artifacts', type=Path, required=True)
    parser.add_argument('--output', type=Path)
    parser.add_argument('--timeout', type=int, default=2400)
    parser.add_argument('--plan', action='store_true')
    args = parser.parse_args()
    if args.timeout < 1: parser.error('Expected positive --timeout')
    if not args.plan and os.name != 'nt': parser.error('Actual cross-artifact unit execution requires Windows')
    windows_artifacts.verify_recipe()
    pair = windows_artifacts.verify_pair(args.artifacts)
    if args.plan:
        print(json.dumps({'status': 'configured only; not executed', 'scope': 'unit-only artifact profile',
            'phases': [{'consensus': row['consensus'], 'expected_cases': len(row['expected_unit']['expected'])}
                       for row in pair['phases']]}, indent=2))
        return 0
    if args.output is None: parser.error('Actual execution requires a new --output directory')
    assets = unit_assets.provision(ROOT / 'unit_test_data')
    run_pair(args.artifacts.resolve(), args.output.resolve(), assets, timeout=args.timeout)
    return 0


if __name__ == '__main__':
    sys.exit(main())
