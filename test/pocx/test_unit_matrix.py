#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin PoCX developers
# Distributed under the MIT software license; see COPYING.
"""Reject hidden case omissions, skips and forged unit execution evidence."""
from copy import deepcopy
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
import xml.etree.ElementTree as ET

from common import ROOT, sha256, exclusive_lock
import unit_matrix
import unit_parity
import build_configuration


class UnitMatrixTests(unittest.TestCase):
    def test_windows_hidden_ipc_preference_matches_original_cmake_effective_value(self):
        definitions = [line for line in (ROOT / 'CMakeLists.txt').read_text().splitlines()
                       if line.startswith('cmake_dependent_option(ENABLE_IPC ')]
        self.assertEqual(len(definitions), 1)
        with tempfile.TemporaryDirectory(prefix='unit-ipc-config-') as directory:
            source = Path(directory) / 'source'
            source.mkdir()
            (source / 'CMakeLists.txt').write_text('''cmake_minimum_required(VERSION 3.22)
project(ipc_configuration_probe NONE)
include(CMakeDependentOption)
option(ENABLE_POCX "Consensus fixture" OFF)
option(ENABLE_WALLET "Wallet fixture" ON)
option(WITH_USDT "Tracing fixture" OFF)
''' + definitions[0] + '''
file(WRITE "${CMAKE_BINARY_DIR}/effective-ipc.txt" "${ENABLE_IPC}")
''')
            for target in ('Windows', 'Linux'):
                for preference in ('ON', 'OFF'):
                    with self.subTest(target=target, preference=preference):
                        build = Path(directory) / (target + '-' + preference)
                        subprocess.run(['cmake', '-S', str(source), '-B', str(build), '-G', 'Ninja',
                                        '-DCMAKE_SYSTEM_NAME=' + target, '-DCMAKE_SYSTEM_PROCESSOR=x86_64',
                                        '-DENABLE_IPC=' + preference], capture_output=True, text=True, check=True)
                        effective = (build / 'effective-ipc.txt').read_text()
                        options, _ = unit_matrix.configuration(build)
                        self.assertEqual(options['ENABLE_IPC'], effective)
                        inventory = unit_matrix.inventory(ROOT, options, bitcoin=True)
                        ipc_cases = {case for case in inventory['original'] if case.startswith('ipc_tests/')}
                        self.assertTrue(ipc_cases)
                        self.assertEqual(ipc_cases <= inventory['applicable'], effective == 'ON')
                        if target == 'Windows':
                            cache = (build / 'CMakeCache.txt').read_text()
                            self.assertIn('ENABLE_IPC:INTERNAL=' + preference, cache)
                            self.assertEqual(effective, 'OFF')
                            for replacement in ('ENABLE_IPC:INTERNAL=invalid', ''):
                                (build / 'CMakeCache.txt').write_text(cache.replace(
                                    'ENABLE_IPC:INTERNAL=' + preference, replacement))
                                invalid, _ = unit_matrix.configuration(build)
                                with self.assertRaisesRegex(ValueError, 'ENABLE_IPC'):
                                    unit_matrix.inventory(ROOT, invalid, bitcoin=True)

    def test_configuration_specific_discovery_keeps_both_compiled_executables(self):
        # Execute the production CMake discovery block against small compiled
        # probes. These are infrastructure checks, not Bitcoin/PoCX case proof.
        with tempfile.TemporaryDirectory(prefix='unit-config-') as directory:
            root = Path(directory)
            build = root / 'build'
            source = root / 'src/pocx/test'
            source.mkdir(parents=True)
            scripts = root / 'test/pocx'
            scripts.mkdir(parents=True)
            for name in ('pocx_bootstrap.py', 'register_unit.py', 'unit_build.py'):
                (scripts / name).write_bytes((ROOT / 'test/pocx' / name).read_bytes())
            (root / 'CMakeLists.txt').write_text('''cmake_minimum_required(VERSION 3.22)
project(unit_config_probe LANGUAGES CXX)
enable_testing()
option(ENABLE_WALLET "Wallet fixture" OFF)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin")
add_subdirectory(src/pocx/test)
''')
            (source / 'fixture.cpp').write_text('''#include <iostream>
#include <string>
int main(int argc, char** argv) {
  if (argc > 1 && std::string(argv[1]) == "--list_content") {
    std::cout << "pocx_tests*\\npocx_simd_tests*\\npocx_wire_tests*\\npocx_real_proof_tests*\\n";
    return 0;
  }
#ifdef WRONG_CONFIGURATION
  return 7;
#else
  return 0;
#endif
}
''')
            production = (ROOT / 'src/pocx/test/CMakeLists.txt').read_text()
            discovery = production[production.index('set(unit_discovery_dir '):
                                   production.index('install_binary_component(test_pocx')]
            (source / 'CMakeLists.txt').write_text('''find_package(Python3 REQUIRED COMPONENTS Interpreter)
add_executable(test_pocx "${CMAKE_CURRENT_SOURCE_DIR}/fixture.cpp")
target_compile_definitions(test_pocx PRIVATE $<$<CONFIG:Debug>:WRONG_CONFIGURATION>)
set(POCX_UNIT_INPUTS "${CMAKE_CURRENT_SOURCE_DIR}/fixture.cpp")
list(APPEND POCX_UNIT_INPUTS "${PROJECT_SOURCE_DIR}/test/pocx/pocx_bootstrap.py")
''' + discovery)
            def run(command, check=True):
                return subprocess.run(command, capture_output=True, text=True, check=check)
            run(['cmake', '-S', str(root), '-B', str(build), '-G', 'Ninja Multi-Config'])
            cache = (build / 'CMakeCache.txt').read_text()
            records = {}
            for selected in ('Release', 'Debug'):
                run(['cmake', '--build', str(build)] + build_configuration.build_arguments(selected))
                binary = build_configuration.executable(build, 'test_pocx', cache, selected)
                inputs, provenance = unit_matrix.provenance_paths(build, cache, selected)
                rows = json.loads(run(['ctest', '--test-dir', str(build), '--show-only=json-v1'] +
                    build_configuration.ctest_arguments(selected)).stdout)['tests']
                suites = unit_matrix.registered_suites(rows, binary)
                self.assertEqual(suites, unit_matrix.unit_build.OWNED_SUITES)
                unit_matrix.unit_build.verify(binary, inputs, build / 'CMakeCache.txt', provenance, suites)
                records[selected] = provenance.read_bytes()
            self.assertNotEqual(records['Release'], records['Debug'])
            for selected in ('Release', 'Debug'):
                inputs, provenance = unit_matrix.provenance_paths(build, cache, selected)
                self.assertEqual(provenance.read_bytes(), records[selected])
                binary = build_configuration.executable(build, 'test_pocx', cache, selected)
                unit_matrix.unit_build.verify(binary, inputs, build / 'CMakeCache.txt', provenance,
                                               unit_matrix.unit_build.OWNED_SUITES)
                timing = unit_matrix.registered_timeouts(build, {'pocx_tests'}, 5, selected_config=selected)
                self.assertEqual(timing, {'pocx_tests': 5})
                result = run(['ctest', '--test-dir', str(build), '--no-tests=error', '-R', '^pocx_tests$'] +
                             build_configuration.ctest_arguments(selected), check=False)
                self.assertEqual(result.returncode == 0, selected == 'Release', result.stdout + result.stderr)
            implicit = run(['ctest', '--test-dir', str(build), '--show-only=json-v1'], check=False)
            self.assertNotEqual(implicit.returncode, 0)
            self.assertIn('explicit CTest build configuration', implicit.stderr)

    def test_registration_paths_use_resolved_identity_and_reject_duplicates(self):
        binary = ROOT / 'build/bin/Release/test_pocx'
        rows = [{'name': 'suite', 'command': [str(binary.parent / 'unused/../test_pocx')]}]
        self.assertEqual(unit_matrix.registered_suites(rows, binary), {'suite'})
        self.assertEqual(unit_matrix.registered_suites([{'name': 'other'}], binary), set())
        with self.assertRaisesRegex(ValueError, 'Duplicate'):
            unit_matrix.registered_suites(rows * 2, binary)

    @unittest.skipUnless(os.name == 'posix', 'Unix executable timing fixture; Windows runtime remains unverified')
    def test_registered_suites_obey_the_requested_ctest_timeout(self):
        # Actual registration and CTest execution catch a per-test TIMEOUT
        # silently overriding both ordinary and sanitizer runner settings.
        # This fake executable provides infrastructure evidence, not unit cases.
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            binary=root/'fixture-unit'
            source=root/'fixture.cpp'
            inputs=root/'inputs.txt'
            cache=root/'CMakeCache.txt'
            registration=root/'discovered.cmake'
            binary.write_text('#!'+sys.executable+'\nimport sys,time\n'
                'if "--list_content" in sys.argv:\n'
                ' print("pocx_tests*\\npocx_simd_tests*\\npocx_wire_tests*\\npocx_real_proof_tests*")\n'
                'else:\n time.sleep(2)\n print("infrastructure delay fixture complete")\n')
            binary.chmod(0o755)
            source.write_text('timing fixture\n')
            inputs.write_text(str(source)+'\n')
            cache.write_text('ENABLE_WALLET:BOOL=OFF\n')
            subprocess.run([sys.executable,str(ROOT/'test/pocx/register_unit.py'),
                '--binary',str(binary),'--output',str(registration),'--inputs',str(inputs),
                '--cache',str(cache)],capture_output=True,text=True,check=True)
            (root/'CTestTestfile.cmake').write_text('include([=['+str(registration)+']=])\n')
            command=['ctest','--test-dir',str(root),'-R','^pocx_tests$',
                     '--no-tests=error','--output-on-failure']
            short=subprocess.run([*command,'--timeout','1'],capture_output=True,text=True)
            self.assertNotEqual(short.returncode,0)
            self.assertIn('Timeout',short.stdout)
            longer=subprocess.run([*command,'--timeout','3'],capture_output=True,text=True)
            self.assertEqual(longer.returncode,0,longer.stdout+longer.stderr)
            self.assertIn('100% tests passed',longer.stdout)
            self.assertIn('infrastructure delay fixture complete',
                          (root/'Testing/Temporary/LastTest.log').read_text())

    def setUp(self):
        self.options = dict(ENABLE_POCX='ON', ENABLE_WALLET='ON', ENABLE_IPC='ON',
                            WITH_USDT='OFF', target_system='Linux',
                            target_processor='x86_64', avx2_compiled=True)

    def test_unit_timeout_gate_rejects_shorter_longer_disabled_and_dynamic_overrides(self):
        for value in (180, 3600, 0, -1, float('nan'), None, True, '2400'):
            registration=[{'name':'suite','properties':[{'name':'TIMEOUT','value':value}]}]
            with self.subTest(value=value),self.assertRaisesRegex(ValueError,'override'):
                unit_matrix.registered_timeouts(Path('unused'),{'suite'},2400,registrations=registration)
        dynamic=[{'name':'suite','properties':[{'name':'TIMEOUT_AFTER_MATCH','value':['10','pattern']}]}]
        with self.assertRaisesRegex(ValueError,'override'):
            unit_matrix.registered_timeouts(Path('unused'),{'suite'},2400,registrations=dynamic)

    def test_unit_timeout_gate_requires_complete_unambiguous_selected_registrations(self):
        registration={'name':'suite','properties':[{'name':'TIMEOUT','value':2400.0}]}
        for rows in ([],[registration,registration],
                     [{**registration,'properties':registration['properties']*2}]):
            with self.subTest(rows=rows),self.assertRaises(ValueError):
                unit_matrix.registered_timeouts(Path('unused'),{'suite'},2400,registrations=rows)
        for rows in ([registration],[{'name':'suite','properties':[]}],
                     [registration,{'name':'unselected','properties':[{'name':'TIMEOUT','value':180}]}]):
            self.assertEqual(unit_matrix.registered_timeouts(Path('unused'),{'suite'},2400,
                                                            registrations=rows),{'suite':2400})

    def test_ctest_registration_inspection_cannot_overwrite_an_active_unit_log(self):
        with tempfile.TemporaryDirectory() as directory:
            build=Path(directory)
            with exclusive_lock(build/'pocx-unit.lock'), \
                 patch.object(unit_matrix.subprocess,'check_output') as inspect:
                with self.assertRaises(OSError):
                    unit_matrix.registered_timeouts(build,{'suite'},180)
                inspect.assert_not_called()
                inspect.return_value=json.dumps({'tests':[{'name':'suite','properties':[]}]})
                self.assertEqual(unit_matrix.registered_timeouts(build,{'suite'},180,lock_held=True),{'suite':180})

    def test_full_optional_and_feature_disabled_case_contracts(self):
        for bitcoin in (True, False):
            options = dict(self.options, ENABLE_POCX='OFF' if bitcoin else 'ON')
            full = unit_matrix.inventory(ROOT, options, bitcoin=bitcoin)
            tracing = unit_matrix.inventory(ROOT, dict(options, WITH_USDT='ON'), bitcoin=bitcoin)
            self.assertEqual(full['expected'], tracing['expected'])
            self.assertEqual(len(full['expected']), 737 if bitcoin else 760)
            wallet = unit_matrix.inventory(ROOT, dict(options, ENABLE_WALLET='OFF'), bitcoin=bitcoin)
            self.assertEqual(len(wallet['applicable']), 680 if bitcoin else 670)
            self.assertEqual(len(wallet['additional']), 0 if bitcoin else 32)
            ipc = unit_matrix.inventory(ROOT, dict(options, ENABLE_IPC='OFF'), bitcoin=bitcoin)
            self.assertEqual(len(full['expected'] - ipc['expected']), 2)
            self.assertEqual(full['excluded'], wallet['excluded'])
            self.assertEqual(full['excluded'], ipc['excluded'])

    def test_simd_and_original_windows_omissions_are_explicit(self):
        reduced = unit_matrix.inventory(ROOT, dict(self.options, avx2_compiled=False,
                                                  target_processor='aarch64'))
        self.assertEqual(set(reduced['configuration_disabled']), unit_matrix.AVX2_CASES | unit_matrix.SSE2_CASES | unit_parity.DEBUG_LOCKORDER_CASES)
        for processor in ('x86_64', 'amd64', 'AMD64', 'X86_64'):
            windows = unit_matrix.inventory(ROOT, dict(self.options, target_system='Windows', target_processor=processor))
            self.assertEqual(set(windows['configuration_disabled']), unit_matrix.WINDOWS_OMISSIONS | unit_parity.DEBUG_LOCKORDER_CASES)
            self.assertEqual(len(windows['excluded']), 10)
            self.assertTrue(unit_matrix.SSE2_CASES.issubset(windows['expected']))

    def test_debug_only_original_cases_follow_effective_flags_and_selected_configuration(self):
        variants = [
            ({'CMAKE_BUILD_TYPE': 'Release'}, False),
            ({'CMAKE_BUILD_TYPE': 'Debug'}, True),
            ({'CMAKE_BUILD_TYPE': 'Release', 'APPEND_CPPFLAGS': '-DDEBUG_LOCKORDER'}, True),
            ({'CMAKE_BUILD_TYPE': 'Release', 'CMAKE_CXX_FLAGS': '-D DEBUG_LOCKORDER=0'}, True),
            ({'CMAKE_BUILD_TYPE': 'Debug', 'APPEND_CPPFLAGS': '-UDEBUG_LOCKORDER'}, False),
            ({'CMAKE_BUILD_TYPE': 'Release', 'APPEND_CPPFLAGS': '-DDEBUG_LOCKORDER', 'APPEND_CXXFLAGS': '-UDEBUG_LOCKORDER'}, False),
            ({'unit_build_configuration': 'Debug', 'CMAKE_CONFIGURATION_TYPES': 'Debug;Release'}, True),
            ({'unit_build_configuration': 'Release', 'CMAKE_CONFIGURATION_TYPES': 'Debug;Release'}, False),
            ({'CMAKE_BUILD_TYPE': 'Release', 'APPEND_CPPFLAGS': '/DDEBUG_LOCKORDER'}, True),
        ]
        for changes, enabled in variants:
            for bitcoin in (True, False):
                options = dict(self.options, **changes, ENABLE_POCX='OFF' if bitcoin else 'ON')
                result = unit_matrix.inventory(ROOT, options, bitcoin=bitcoin)
                with self.subTest(changes=changes, bitcoin=bitcoin):
                    self.assertEqual(result['original'] & unit_parity.DEBUG_LOCKORDER_CASES, unit_parity.DEBUG_LOCKORDER_CASES)
                    self.assertEqual(result['expected'] & unit_parity.DEBUG_LOCKORDER_CASES,
                                     unit_parity.DEBUG_LOCKORDER_CASES if enabled else set())
                    self.assertEqual(len(result['expected']), (737 if bitcoin else 760) + (2 if enabled else 0))

    def test_unknown_configuration_does_not_disable_parity_gate(self):
        for key, value in [('ENABLE_IPC', None), ('WITH_USDT', 'AUTO'),
                           ('target_system', 'unreviewed'), ('avx2_compiled', None)]:
            with self.subTest(key=key), self.assertRaises(ValueError):
                unit_matrix.inventory(ROOT, dict(self.options, **{key: value}))

    def test_runtime_case_missing_despite_registered_suite_is_rejected(self):
        completed = type('Listing', (), {'stdout': 'suite*\n    kept*\n', 'stderr': ''})()
        with patch.object(unit_matrix.subprocess, 'run', return_value=completed):
            with self.assertRaisesRegex(ValueError, 'missing='):
                unit_matrix.runtime_inventory(Path('unused'), {'suite/kept', 'suite/missing'})

    def boost(self):
        return ET.fromstring('''<TestResult><TestSuite name="Bitcoin Core Test Suite" result="passed" test_cases_skipped="740"><TestSuite name="suite" result="passed"><TestCase name="kept" result="passed" assertions_passed="3" assertions_failed="0"/><TestSuite name="nested" result="passed"><TestCase name="other" result="passed" assertions_passed="2" assertions_failed="0"/></TestSuite></TestSuite></TestSuite></TestResult>''')

    def test_unselected_root_counts_do_not_hide_or_create_skipped_leaves(self):
        xml = ET.tostring(self.boost(), encoding='unicode')
        self.assertEqual(set(unit_matrix.leaf_results(xml, {'suite'})), {'suite/kept', 'suite/nested/other'})
        with self.assertRaisesRegex(ValueError, 'duplicate'):
            unit_matrix.leaf_results(xml + xml, {'suite'})
        with self.assertRaisesRegex(ValueError, 'Missing selected'):
            unit_matrix.leaf_results(xml, {'suite', 'missing'})

    def test_green_suite_cannot_hide_failed_or_skipped_leaf(self):
        for result in ('skipped', 'failed', 'aborted'):
            xml = self.boost()
            xml.find('.//TestCase').set('result', result)
            with self.subTest(result=result), self.assertRaisesRegex(ValueError, 'Failed or skipped'):
                unit_matrix.leaf_results(ET.tostring(xml, encoding='unicode'), {'suite'})

    def test_hardware_skip_return_cannot_look_like_a_green_simd_comparison(self):
        xml = ET.fromstring('<TestResult><TestSuite name="Bitcoin Core Test Suite" result="passed"><TestSuite name="pocx_simd_tests" result="passed"><TestCase name="generate_nonces_avx2_matches_scalar" result="passed" assertions_passed="0" assertions_failed="0"/></TestSuite></TestSuite></TestResult>')
        with self.assertRaisesRegex(ValueError, 'not exercised'):
            unit_matrix.leaf_results(ET.tostring(xml, encoding='unicode'), {'pocx_simd_tests'})

    def test_duplicate_leaf_rejected(self):
        xml = self.boost()
        suite = xml.find('TestSuite/TestSuite')
        suite.append(deepcopy(suite.find('TestCase')))
        with self.assertRaisesRegex(ValueError, 'Duplicate'):
            unit_matrix.leaf_results(ET.tostring(xml, encoding='unicode'), {'suite'})

    def test_verifier_rejects_missing_case_and_stale_report_or_runner(self):
        # A synthetic execution fixture tests the verifier's failure paths. It
        # never establishes a passing Bitcoin/PoCX runtime checkpoint.
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            build = root / 'build'
            (build / 'bin').mkdir(parents=True)
            binary = build / 'bin/test_pocx'
            binary.write_bytes(b'fixture binary')
            cache = build / 'CMakeCache.txt'
            cache.write_text('fixture config')
            system = build / 'system.cmake'
            system.write_text('fixture target')
            helpers = {source: sha256(ROOT / source) for source in (
                'test/pocx/run_unit.py', 'test/pocx/unit_matrix.py',
                'test/pocx/unit_parity.py', 'test/pocx/common.py', 'test/pocx/unit_build.py',
                'test/pocx/build_configuration.py')}
            for source in helpers:
                path = root / source
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes((ROOT / source).read_bytes())
            provenance = build / 'src/pocx/test/discovered.build.json'
            provenance.parent.mkdir(parents=True)
            provenance.write_text('{}')
            boost = build / 'boost.log'
            boost.write_text(ET.tostring(self.boost(), encoding='unicode'))
            junit = build / 'junit.xml'
            junit.write_text('<testsuites><testsuite><testcase name="suite"/></testsuite></testsuites>')
            expected = {'original': {'suite/kept', 'suite/nested/other'}, 'applicable': {'suite/kept', 'suite/nested/other'},
                        'additional': set(), 'excluded': set(), 'configuration_disabled': {},
                        'expected': {'suite/kept', 'suite/nested/other'}}
            record = {'returncode': 0, 'binary': str(binary), 'binary_sha256': sha256(binary),
                      'command':['ctest','--timeout','180'],'suite_timeouts':{'suite':180},
                      'build_configuration': None,
                      'cache_sha256': sha256(cache), 'target_system_sha256': sha256(system),
                      'test_sources': {}, 'execution_helpers': helpers,
                      'unit_build_provenance': str(provenance), 'unit_build_provenance_sha256': sha256(provenance), 'selected': ['suite'], 'registered': ['suite'],
                      'boost.log_sha256': sha256(boost), 'junit.xml_sha256': sha256(junit)}
            path = build / 'results.json'
            path.write_text(json.dumps(record))
            with patch.object(unit_matrix, 'configuration', return_value=(self.options, system)), \
                 patch.object(unit_matrix, 'inventory', return_value=expected), \
                 patch.object(unit_matrix, 'runtime_inventory', return_value=expected['expected']), \
                 patch.object(unit_matrix, 'registered_timeouts', return_value={'suite':180}), \
                 patch.object(unit_matrix.unit_build, 'verify', return_value={'sources': {}}):
                self.assertEqual(unit_matrix.verify_execution(root, build, path)['original_green'], 2)
                broken = deepcopy(record)
                broken.pop('build_configuration')
                path.write_text(json.dumps(broken))
                with self.assertRaisesRegex(ValueError, 'recorded unit build configuration'):
                    unit_matrix.verify_execution(root, build, path)
                for extra in (['--build-config', 'Debug'], ['--build-config=Debug'], ['-CDebug']):
                    broken = deepcopy(record)
                    broken['command'] += extra
                    path.write_text(json.dumps(broken))
                    with self.subTest(extra=extra), self.assertRaisesRegex(ValueError, 'build configuration'):
                        unit_matrix.verify_execution(root, build, path)
                # Bind the command and executable path to the recorded
                # selection, including duplicate/alternate flag attacks.
                cache.write_text('CMAKE_CONFIGURATION_TYPES:STRING=Debug;Release\n')
                selected_binary = build / 'bin/Release/test_pocx'
                selected_binary.parent.mkdir()
                selected_binary.write_bytes(binary.read_bytes())
                selected_provenance = provenance.parent / 'Release/discovered.build.json'
                selected_provenance.parent.mkdir()
                selected_provenance.write_bytes(provenance.read_bytes())
                selected_record = deepcopy(record)
                selected_record.update(build_configuration='Release', binary=str(selected_binary),
                    cache_sha256=sha256(cache), unit_build_provenance=str(selected_provenance),
                    command=record['command'] + ['--build-config', 'Release'])
                path.write_text(json.dumps(selected_record))
                self.assertEqual(unit_matrix.verify_execution(root, build, path)['build_configuration'], 'Release')
                for command in (record['command'], record['command'] + ['--build-config', 'Debug'],
                                selected_record['command'] + ['--build-config', 'Debug'],
                                selected_record['command'] + ['-CDebug']):
                    broken = deepcopy(selected_record)
                    broken['command'] = command
                    path.write_text(json.dumps(broken))
                    with self.subTest(command=command), self.assertRaisesRegex(ValueError, 'build configuration'):
                        unit_matrix.verify_execution(root, build, path)
                cache.write_text('fixture config')
                for field in ('binary_sha256', 'cache_sha256', 'target_system_sha256', 'boost.log_sha256', 'junit.xml_sha256', 'unit_build_provenance_sha256', 'suite_timeouts'):
                    broken = deepcopy(record)
                    broken[field] = '0' * 64
                    path.write_text(json.dumps(broken))
                    with self.subTest(field=field), self.assertRaises(ValueError):
                        unit_matrix.verify_execution(root, build, path)
                broken = deepcopy(record)
                broken['execution_helpers'].pop('test/pocx/run_unit.py')
                path.write_text(json.dumps(broken))
                with self.assertRaisesRegex(ValueError, 'helper provenance'):
                    unit_matrix.verify_execution(root, build, path)
                broken = deepcopy(record)
                broken['test_sources'] = {'fabricated.cpp': '0' * 64}
                path.write_text(json.dumps(broken))
                with self.assertRaisesRegex(ValueError, 'source provenance'):
                    unit_matrix.verify_execution(root, build, path)
                xml = self.boost()
                suite = xml.find('TestSuite/TestSuite')
                suite.remove(suite.find('TestCase'))
                boost.write_text(ET.tostring(xml, encoding='unicode'))
                broken = deepcopy(record)
                broken['boost.log_sha256'] = sha256(boost)
                path.write_text(json.dumps(broken))
                with self.assertRaisesRegex(ValueError, 'executed unit leaf'):
                    unit_matrix.verify_execution(root, build, path)


if __name__ == '__main__':
    unittest.main()
