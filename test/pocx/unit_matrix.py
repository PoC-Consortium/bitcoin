#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin PoCX developers
# Distributed under the MIT software license; see COPYING.
"""Configuration-specific unit inventories and strict Boost leaf execution proof.

Feature/platform omissions are reported separately from the ten reviewed PoW
exclusions. This gate does not approve new baseline cases or source changes.
"""
import json
from contextlib import nullcontext
from pathlib import Path
import re
import shlex
import subprocess
import xml.etree.ElementTree as ET

from common import build_options, sha256, exclusive_lock
import unit_parity
import unit_build
import build_configuration

WALLET_SUITES = {
    'coinselection_tests', 'coinselector_tests', 'db_tests', 'feebumper_tests',
    'group_outputs_tests', 'init_tests', 'ismine_tests', 'psbt_wallet_tests',
    'scriptpubkeyman_tests', 'spend_tests', 'wallet_crypto_tests', 'wallet_rpc_tests',
    'wallet_tests', 'wallet_transaction_tests', 'walletdb_tests', 'walletload_tests',
}
AVX2_CASES = {'pocx_simd_tests/' + name for name in (
    'generate_nonces_avx2_matches_scalar', 'shabal256_avx2_matches_scalar',
    'shabal256_avx2_with_preterm', 'shabal256_avx2_known_vectors')}
SSE2_CASES = {'pocx_simd_tests/' + name for name in (
    'generate_nonces_sse2_matches_scalar', 'shabal256_sse2_matches_scalar',
    'shabal256_sse2_with_preterm', 'shabal256_sse2_known_vectors')}
WINDOWS_OMISSIONS = {'sock_tests/' + name for name in (
    'send_and_receive', 'wait', 'recv_until_terminator_limit')}


def configuration(build, selected_config=None):
    cache = (build / 'CMakeCache.txt').read_text()
    options = build_options(cache)
    files = list((build / 'CMakeFiles').glob('*/CMakeSystem.cmake'))
    if len(files) != 1:
        raise ValueError('Missing or ambiguous target system configuration')
    system = files[0].read_text()
    def field(name):
        matches = re.findall(r'^set\(' + name + r' "([^"\n]+)"\)', system, re.M)
        if len(matches) != 1:
            raise ValueError('Missing target configuration: ' + name)
        return matches[0]
    options.update(target_system=field('CMAKE_SYSTEM_NAME'),
                   target_processor=field('CMAKE_SYSTEM_PROCESSOR'),
                   unit_build_configuration=selected_config or options.get('CMAKE_BUILD_TYPE', ''),
                   avx2_compiled=bool(re.search(r'^HAVE_AVX2:INTERNAL=(1|ON|TRUE)$', cache, re.M)))
    # On Windows, the original cmake_dependent_option disables IPC and hides
    # its saved preference in an INTERNAL cache entry. That preference may be
    # ON; the effective value is OFF while the NOT WIN32 condition is false.
    if options['target_system'] == 'Windows' and 'ENABLE_IPC' not in options:
        preferences = re.findall(r'^ENABLE_IPC:INTERNAL=(ON|OFF)$', cache, re.M)
        if len(preferences) == 1:
            options['ENABLE_IPC'] = 'OFF'
    return options, files[0]


def debug_lockorder_enabled(options):
    selected = options.get('unit_build_configuration', options.get('CMAKE_BUILD_TYPE', ''))
    enabled = selected.lower() == 'debug'
    flags = shlex.split(' '.join(options.get(key, '') for key in (
        'CMAKE_CXX_FLAGS', 'CMAKE_CXX_FLAGS_' + selected.upper(), 'APPEND_CPPFLAGS', 'APPEND_CXXFLAGS')))
    tokens = iter(flags)
    for token in tokens:
        if token in ('-D', '/D', '-U', '/U'):
            token += next(tokens, '')
        if re.fullmatch(r'(?:-D|/D)DEBUG_LOCKORDER(?:=.*)?', token):
            enabled = True
        elif token in ('-UDEBUG_LOCKORDER', '/UDEBUG_LOCKORDER'):
            enabled = False
    return enabled


def inventory(root, options, *, bitcoin=False):
    issues = unit_parity.check(root)
    if issues:
        raise ValueError(f'Unit parity source review failed: {issues}')
    for key in ('ENABLE_WALLET', 'ENABLE_IPC', 'WITH_USDT'):
        if options.get(key) not in ('ON', 'OFF'):
            raise ValueError('Unrecorded unit feature configuration: ' + key)
    if options.get('ENABLE_POCX') != ('OFF' if bitcoin else 'ON'):
        raise ValueError('Wrong unit consensus configuration')
    if options.get('target_system') not in ('Linux', 'Darwin', 'Windows'):
        raise ValueError('Unreviewed unit platform configuration')
    if type(options.get('avx2_compiled')) is not bool or not options.get('target_processor'):
        raise ValueError('Unrecorded unit SIMD configuration')
    baseline = json.loads((root / 'test/pocx/unit-baseline.json').read_text())
    review = json.loads((root / 'test/pocx/unit-parity.json').read_text())
    original = set(baseline['cases']) | set(review['configuration_cases'])
    excluded = set() if bitcoin else set(review['excluded'])
    additional = set() if bitcoin else set(review['additional'])
    disabled = {}
    def omit(cases, reason):
        for case in cases:
            disabled[case] = reason
    if not debug_lockorder_enabled(options):
        omit(unit_parity.DEBUG_LOCKORDER_CASES, 'Original cases require DEBUG_LOCKORDER')
    if options['ENABLE_WALLET'] == 'OFF':
        omit({case for case in original if case.split('/')[0] in WALLET_SUITES}, 'ENABLE_WALLET=OFF')
        omit({case for case in additional if case.startswith('pocx_block_builder_tests/')}, 'ENABLE_WALLET=OFF')
    if options['ENABLE_IPC'] == 'OFF':
        omit({case for case in original if case.startswith('ipc_tests/')}, 'ENABLE_IPC=OFF')
    if options['target_system'] == 'Windows':
        omit(WINDOWS_OMISSIONS, 'Original upstream socketpair cases are compiled out on Windows')
    if not bitcoin:
        if not options['avx2_compiled']:
            omit(AVX2_CASES, 'HAVE_AVX2 is false')
        if not re.search(r'x86_64|amd64', options['target_processor'], re.I):
            omit(SSE2_CASES, 'Native CMake target does not define ENABLE_SSE2 for this processor')
    applicable = original - excluded - disabled.keys()
    native = additional - disabled.keys()
    return {'original': original, 'applicable': applicable, 'additional': native,
            'excluded': excluded, 'configuration_disabled': disabled,
            'expected': applicable | native}


def runtime_inventory(binary, expected):
    listing = subprocess.run([str(binary), '--list_content'], capture_output=True, text=True, check=True)
    current = unit_parity.runtime_cases(listing.stdout + listing.stderr)
    if current != expected:
        raise ValueError(f'Unit runtime inventory mismatch: missing={sorted(expected-current)}, extra={sorted(current-expected)}')
    return current


def provenance_paths(build, cache, selected_config=None):
    build_configuration.configuration(cache, selected_config)
    directory = build / 'src/pocx/test'
    if build_options(cache).get('CMAKE_CONFIGURATION_TYPES'):
        directory /= selected_config
    return directory / 'unit-inputs.txt', directory / 'discovered.build.json'


def registered_suites(registrations, binary):
    # CMake uses forward slashes even when Python's native Windows path uses
    # backslashes. Compare resolved identities rather than raw command strings.
    names = [test['name'] for test in registrations if test.get('command') and
             Path(test['command'][0]).resolve() == binary.resolve()]
    if len(names) != len(set(names)):
        raise ValueError('Duplicate unit CTest registrations')
    return set(names)


def registered_timeouts(build, selected, timeout, *, registrations=None, lock_held=False,
                        selected_config=None):
    """Require the requested deadline to be effective for every selected suite."""
    if type(timeout) is not int or timeout < 1 or not selected:
        raise ValueError('Expected selected unit suites and a positive integer timeout')
    if registrations is None:
        # Even CTest --show-only overwrites Testing/Temporary/LastTest.log.
        # External inspections must share the execution lock; callers already
        # holding it explicitly avoid acquiring a second nonblocking lock.
        with nullcontext() if lock_held else exclusive_lock(build / 'pocx-unit.lock'):
            registrations = json.loads(subprocess.check_output(
                ['ctest', '--test-dir', str(build), '--show-only=json-v1'] +
                build_configuration.ctest_arguments(selected_config), text=True))['tests']
    result = {}
    for test in registrations:
        name = test['name']
        if name not in selected:
            continue
        if name in result:
            raise ValueError('Duplicate unit timeout registration: ' + name)
        properties = test.get('properties', [])
        timing = [p for p in properties if p['name'] in ('TIMEOUT', 'TIMEOUT_AFTER_MATCH')]
        if (any(p['name'] == 'TIMEOUT_AFTER_MATCH' for p in timing) or len(timing) > 1 or
                any(type(p['value']) not in (int, float) or p['value'] != timeout for p in timing)):
            raise ValueError('CTest properties override requested unit timeout: ' + name)
        result[name] = timeout
    if set(result) != set(selected):
        raise ValueError('Missing selected unit timeout registration')
    return result


def leaf_results(log, selected):
    """Ignore root counts for unrelated suites; require every selected leaf."""
    reports = re.findall(r'<TestResult>.*?</TestResult>', log, re.S)
    seen_suites, leaves = set(), {}
    for raw in reports:
        root = ET.fromstring(raw)
        module = root.find('TestSuite')
        if module is None:
            raise ValueError('Missing Boost test module')
        suites = list(module)
        if len(suites) != 1 or suites[0].tag != 'TestSuite':
            raise ValueError('Expected one selected Boost suite per CTest invocation')
        suite = suites[0]
        name = suite.get('name')
        if name not in selected or name in seen_suites:
            raise ValueError('Unexpected or duplicate Boost suite report')
        seen_suites.add(name)
        if module.get('result') != 'passed' or suite.get('result') != 'passed':
            raise ValueError('Failed Boost unit suite')
        def walk(node, path):
            if node.tag == 'TestCase':
                case = '/'.join([*path, node.get('name')])
                if case in leaves:
                    raise ValueError('Duplicate Boost unit case')
                if node.get('result') != 'passed' or node.get('assertions_failed') != '0':
                    raise ValueError('Failed or skipped Boost unit case: ' + case)
                if case in AVX2_CASES | SSE2_CASES and int(node.get('assertions_passed', '0')) == 0:
                    raise ValueError('Compiled SIMD comparison was not exercised: ' + case)
                leaves[case] = dict(node.attrib)
            elif node.tag == 'TestSuite':
                for child in node:
                    walk(child, [*path, node.get('name')])
        walk(suite, [])
    if seen_suites != set(selected):
        raise ValueError('Missing selected Boost suite report')
    return leaves


def verify_execution(root, build, result_path, *, bitcoin=False, lock_held=False):
    report = json.loads(result_path.read_text())
    cache = (build / 'CMakeCache.txt').read_text()
    if 'build_configuration' not in report:
        raise ValueError('Missing recorded unit build configuration')
    selected_config = build_configuration.configuration(cache, report['build_configuration'])
    options, system = configuration(build, selected_config)
    expected = inventory(root, options, bitcoin=bitcoin)
    binary = build_configuration.executable(build, 'test_bitcoin' if bitcoin else 'test_pocx',
                                            cache, selected_config)
    if (report.get('returncode') != 0 or report.get('binary') != str(binary) or
            report.get('binary_sha256') != sha256(binary) or
            report.get('cache_sha256') != sha256(build / 'CMakeCache.txt')):
        raise ValueError('Failed or stale unit execution/binary/configuration')
    if report.get('target_system_sha256') != sha256(system):
        raise ValueError('Stale target system configuration')
    if bitcoin:
        original_sources = json.loads((root / 'test/pocx/unit-parity.json').read_text())['bitcoin_sources']
        if report.get('test_sources') != original_sources:
            raise ValueError('Incomplete original unit source provenance')
    else:
        inputs, provenance = provenance_paths(build, cache, selected_config)
        if (report.get('unit_build_provenance') != str(provenance) or
                report.get('unit_build_provenance_sha256') != sha256(provenance)):
            raise ValueError('Missing or stale native unit build provenance')
        evidence = unit_build.verify(binary, inputs,
                                     build / 'CMakeCache.txt', provenance, set(report['registered']))
        if report.get('test_sources') != evidence['sources']:
            raise ValueError('Incomplete native unit source provenance')
    for source, digest in report['test_sources'].items():
        if sha256(Path(source) if Path(source).is_absolute() else root / source) != digest:
            raise ValueError('Stale unit execution source: ' + source)
    helpers = report.get('execution_helpers', {})
    required_helpers = {'test/pocx/unit_matrix.py', 'test/pocx/unit_parity.py', 'test/pocx/common.py',
                        'test/pocx/build_configuration.py',
                        'test/pocx/run_bitcoin_unit.py' if bitcoin else 'test/pocx/run_unit.py'}
    if not bitcoin:
        required_helpers.add('test/pocx/unit_build.py')
    if not required_helpers.issubset(helpers):
        raise ValueError('Missing unit execution helper provenance')
    for source, digest in helpers.items():
        if sha256(root / source) != digest:
            raise ValueError('Stale unit execution helper: ' + source)
    runtime_inventory(binary, expected['expected'])
    suites = {case.split('/')[0] for case in expected['expected']}
    if (set(report['selected']) != suites or set(report['registered']) != suites or
            len(report['selected']) != len(suites) or len(report['registered']) != len(suites)):
        raise ValueError('Incomplete unit suite selection')
    command = report.get('command', [])
    if not isinstance(command, list) or command.count('--timeout') != 1:
        raise ValueError('Missing or ambiguous unit timeout command')
    if any(isinstance(argument, str) and (argument.startswith('--build-config=') or
           argument.startswith('-C')) for argument in command):
        raise ValueError('Ambiguous unit command build configuration')
    if selected_config is None:
        if '--build-config' in command:
            raise ValueError('Unexpected unit command build configuration')
    elif (command.count('--build-config') != 1 or
          command[command.index('--build-config') + 1:command.index('--build-config') + 2] != [selected_config]):
        raise ValueError('Unit command differs from recorded build configuration')
    try:
        timeout = int(command[command.index('--timeout') + 1])
    except (IndexError, TypeError, ValueError) as error:
        raise ValueError('Invalid unit timeout command') from error
    timing = registered_timeouts(build, suites, timeout, lock_held=lock_held, selected_config=selected_config)
    if report.get('suite_timeouts') != timing:
        raise ValueError('Missing or stale effective unit timeout proof')
    for name in ('junit.xml', 'boost.log'):
        if report.get(name + '_sha256') != sha256(result_path.with_name(name)):
            raise ValueError('Stale unit execution report: ' + name)
    tests = list(ET.parse(result_path.with_name('junit.xml')).iter('testcase'))
    if (len(tests) != len(suites) or {test.get('name') for test in tests} != suites or
            any(any(test.find(tag) is not None for tag in ('failure', 'error', 'skipped')) for test in tests)):
        raise ValueError('Missing, failed or skipped unit CTest result')
    leaves = leaf_results(result_path.with_name('boost.log').read_text(), suites)
    if set(leaves) != expected['expected']:
        raise ValueError('Missing or unexpected executed unit leaf cases')
    return {'scope': 'Strict local unit execution for the recorded configuration; not hosted CI attestation',
            'configuration': options, 'build_configuration': selected_config,
            'suite_timeouts': timing, 'original_inventory': len(expected['original']),
            'original_green': len(expected['applicable']), 'native_green': len(expected['additional']),
            'reviewed_exclusions': sorted(expected['excluded']),
            'configuration_disabled': expected['configuration_disabled'],
            'failed': 0, 'skipped': 0, 'suites_green': len(suites),
            'cases': [{'case': case, 'origin': 'original' if case in expected['original'] else 'native',
                       'status': 'passed', 'assertions_passed': int(leaves[case]['assertions_passed'])}
                      for case in sorted(leaves)]}
