#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin PoCX developers
# Distributed under the MIT software license; see COPYING.
"""Select strict original or owned tests from the actual inherited build cache."""
import argparse
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET

from common import ROOT, sha256, exclusive_lock
import build_configuration
from ci_evidence import source_snapshot, build_snapshot, require_unchanged
import inherited_functional
import unit_assets
import unit_matrix


def jobs(value):
    match = re.fullmatch(r'(?:-j\s*)?([1-9][0-9]*)', value)
    if not match:
        raise argparse.ArgumentTypeError('Expected a positive job count or inherited -jN')
    return int(match[1])


def verify_auxiliary(xml, expected):
    tests = list(ET.fromstring(xml).iter('testcase'))
    if (not expected or len(tests) != len(expected) or {test.get('name') for test in tests} != set(expected) or
            any(any(test.find(tag) is not None for tag in ('failure', 'error', 'skipped')) for test in tests)):
        raise ValueError('Missing, duplicate, failed or skipped auxiliary CTest execution')
    return sorted(expected)


def framework_commands(build, options, count, timeout, output, *, selected_config=None):
    native = options['ENABLE_POCX'] == 'ON'
    unit = [sys.executable, str(ROOT / 'test/pocx' / ('run_unit.py' if native else 'run_bitcoin_unit.py')),
            '--build-dir', str(build), '--jobs', str(count), '--timeout', str(timeout)]
    if native:
        unit.append('--all')
    if selected_config is not None:
        unit += ['--config', selected_config]
    commands = [('unit', unit)]
    disabled = {}
    for framework, switch, test_switch in (('qt', 'BUILD_GUI', 'BUILD_GUI_TESTS'),
                                           ('kernel', 'BUILD_KERNEL_LIB', 'BUILD_KERNEL_TEST')):
        if options.get(switch) not in ('ON', 'OFF'):
            raise ValueError('Unrecorded inherited feature configuration: ' + switch)
        if options.get(switch) != 'ON' or options.get(test_switch) == 'OFF':
            disabled[framework] = switch + '=OFF' if options.get(switch) != 'ON' else test_switch + '=OFF'
            continue
        if options.get(test_switch) != 'ON':
            raise ValueError('Unrecorded inherited test configuration: ' + test_switch)
        command = [sys.executable, str(ROOT / 'test/pocx' / ('run_' + framework + '.py')),
                   '--build-dir', str(build), '--output-dir', str(output / framework),
                   '--jobs', str(count), '--timeout', str(timeout)]
        if framework == 'kernel' and not native:
            command.append('--bitcoin')
        if selected_config is not None:
            command += ['--config', selected_config]
        commands.append((framework, command))
    return commands, disabled


def auxiliary_names(registrations, binary):
    unit_suites = unit_matrix.registered_suites(registrations, binary)
    names = [test['name'] for test in registrations]
    if not unit_suites or len(names) != len(set(names)):
        raise ValueError('Missing unit or duplicate inherited CTest registrations')
    auxiliary = sorted(set(names) - unit_suites - {'test_bitcoin-qt', 'test_kernel'})
    if not auxiliary:
        raise ValueError('Empty inherited auxiliary CTest selection')
    return auxiliary


def run(build, phase, count, timeout, factor, *, environment=None, selected_config=None):
    env = dict(os.environ if environment is None else environment)
    cache = (build / 'CMakeCache.txt').read_text()
    build_configuration.require_source(cache, ROOT)
    selected_config = build_configuration.configuration(cache, selected_config)
    options, _ = unit_matrix.configuration(build)
    from check_drift import check
    issues = check(ROOT)
    if issues:
        raise ValueError('Inherited runtime source review failed: ' + str(issues))
    if options.get('ENABLE_POCX') not in ('OFF', 'ON'):
        raise ValueError('Missing explicit inherited consensus configuration')
    output = Path(tempfile.mkdtemp(prefix='pocx-inherited-' + phase + '-', dir=build))
    report = {'status': 'running', 'phase': phase, 'build': str(build), 'build_options': options,
              'build_configuration': selected_config,
              'source_snapshot': source_snapshot(ROOT), 'build_snapshot': build_snapshot(build), 'steps': []}
    def save():
        (output / 'results.json').write_text(json.dumps(report, indent=2) + '\n')
    def execute(name, command):
        before = set(build.iterdir())
        log = output / (name + '.log')
        with log.open('w') as stream:
            result = subprocess.run(command, cwd=ROOT, env=env, stdout=stream, stderr=subprocess.STDOUT)
        children = sorted(path for path in set(build.iterdir()) - before if path.is_dir() and
                          path.name.startswith(('pocx-unit-', 'bitcoin-unit-')))
        report['steps'].append({'name': name, 'command': command, 'returncode': result.returncode,
            'status': 'passed' if result.returncode == 0 else 'failed', 'log_sha256': sha256(log),
            'child_evidence': {str(path): sha256(path) for child in children for path in child.rglob('*') if path.is_file()}})
        save()
        if result.returncode:
            raise ValueError('Inherited ' + name + ' test execution failed')
    save()
    print('Inherited test results:', output, flush=True)
    try:
        if phase == 'ctest':
            report['unit_assets'] = unit_assets.provision(env.get('DIR_UNIT_TEST_DATA', build / 'unit_test_data'))
            env['DIR_UNIT_TEST_DATA'] = report['unit_assets']['directory']
            commands, report['configuration_disabled'] = framework_commands(build, options, count, timeout, output,
                                                                           selected_config=selected_config)
            report['disabled_cases'] = {}
            for framework, reason in report['configuration_disabled'].items():
                cases = json.loads((ROOT / ('test/pocx/' + framework + '-baseline.json')).read_text())['cases']
                if framework == 'qt' and options['ENABLE_POCX'] == 'ON':
                    cases = [*cases, 'PoCXURITests::nativePaymentURIs']
                report['disabled_cases'][framework] = {case: reason for case in cases}
            if options.get('BUILD_GUI') == 'ON' and options.get('ENABLE_WALLET') == 'OFF':
                report['disabled_cases'].setdefault('qt', {}).update({case: 'ENABLE_WALLET=OFF' for case in
                    ('AddressBookTests::addressBookTests', 'WalletTests::walletTests')})
            for name, command in commands:
                execute(name, command)
            unit_name = 'test_pocx' if options['ENABLE_POCX'] == 'ON' else 'test_bitcoin'
            binary = build_configuration.executable(build, unit_name, cache, selected_config)
            # CTest metadata inspection also writes LastTest.log. Use the same
            # lock as unit execution even though the owned unit step has ended.
            with exclusive_lock(build / 'pocx-unit.lock'):
                tests = json.loads(subprocess.check_output(
                    ['ctest', '--test-dir', str(build), '--show-only=json-v1'] +
                    build_configuration.ctest_arguments(selected_config), text=True))['tests']
            auxiliary = auxiliary_names(tests, binary)
            junit = output / 'auxiliary.xml'
            execute('auxiliary', ['ctest', '--test-dir', str(build), '-j', str(count), '--output-on-failure',
                '--timeout', str(timeout), '--no-tests=error', '-R', '^(' + '|'.join(map(re.escape, auxiliary)) + ')$',
                '--output-junit', str(junit)] + build_configuration.ctest_arguments(selected_config))
            report['auxiliary_cases'] = verify_auxiliary(junit.read_text(), auxiliary)
        else:
            report['functional'] = inherited_functional.run(build, output / 'functional', options, count, factor,
                                                            environment=env, selected_config=selected_config)
        require_unchanged('Inherited source inputs', report['source_snapshot'], source_snapshot(ROOT))
        require_unchanged('Inherited build inputs', report['build_snapshot'], build_snapshot(build))
        report['status'] = 'passed'
    except Exception as error:
        report.update(status='failed', error=str(error))
        save()
        raise
    save()
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--build-dir', type=Path, required=True)
    parser.add_argument('--config', help='Explicit CMake configuration, required for multi-config builds')
    parser.add_argument('--phase', choices=['ctest', 'functional'], required=True)
    parser.add_argument('--jobs', type=jobs, default=4)
    parser.add_argument('--timeout', type=int, default=2400)
    parser.add_argument('--timeout-factor', type=float, default=40)
    args = parser.parse_args()
    build = args.build_dir.resolve()
    if build == ROOT or not build.is_relative_to(ROOT) or args.timeout < 1 or not 0 < args.timeout_factor < float('inf'):
        parser.error('Use a separate build directory and positive finite timeouts')
    run(build, args.phase, args.jobs, args.timeout, args.timeout_factor, selected_config=args.config)


if __name__ == '__main__':
    main()
