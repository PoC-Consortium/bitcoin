#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin PoCX developers
# Distributed under the MIT software license; see COPYING.
"""Exercise artifact phase ordering and rejection; fixtures are not Windows proof."""
from copy import deepcopy
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from common import ROOT, sha256
import process_tree
import windows_artifact_tests as tests
import test_windows_artifact_unit as unit_fixture


class ArtifactTestsTest(unittest.TestCase):
    def fixture(self, root, consensus='bitcoin', *, gui=True, kernel=False):
        payload = root / consensus
        row = unit_fixture.ArtifactUnitTest().row(payload, consensus)
        row['build_options'] = {'ENABLE_POCX': 'ON' if consensus == 'pocx' else 'OFF',
            'ENABLE_WALLET': 'ON', 'BUILD_GUI': 'ON' if gui else 'OFF', 'BUILD_GUI_TESTS': 'ON',
            'BUILD_KERNEL_LIB': 'ON' if kernel else 'OFF', 'BUILD_KERNEL_TEST': 'ON' if kernel else 'OFF'}
        for name in ('bin/test_bitcoin-qt.exe', 'bin/test_kernel.exe', *tests.windows_artifacts.AUXILIARY):
            path = payload / name; path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text('Synthetic artifact executable; injected process callbacks only\n')
            row['files'][name] = sha256(path)
        return payload, row

    def qt_log(self, native):
        return '\n'.join('PASS : ' + method + '()' for method in sorted(tests.run_qt.expected_cases(native, True)))

    def kernel_xml(self):
        cases = json.loads((ROOT / 'test/pocx/kernel-baseline.json').read_text())['cases']
        zeros = ' '.join(key + '="0"' for key in ('test_cases_failed', 'test_cases_skipped',
            'test_cases_aborted', 'test_cases_timed_out', 'test_suites_timed_out',
            'assertions_failed', 'warnings_failed', 'expected_failures'))
        return '<TestResult><TestSuite name="kernel" result="passed" assertions_passed="15" test_cases_passed="16" ' + zeros + '>' + ''.join(
            '<TestCase name="' + case + '" result="passed" assertions_passed="' + ('0' if case == 'logging_tests' else '1') +
            '" assertions_failed="0" warnings_failed="0" expected_failures="0"/>' for case in cases) + '</TestSuite></TestResult>'

    def callback(self, calls, *, failed=None, code=7, timed_out=False, cleanup=True, qt_log=None, kernel_xml=None, mutate=None):
        fixture = unit_fixture.ArtifactUnitTest()
        unit_callback = fixture.callback([], code=code if failed == 'unit' else 0)
        controller = process_tree.description()
        def execute(command, **kwargs):
            calls.append((command, kwargs['env']))
            binary = Path(command[0])
            if binary.name in ('test_bitcoin.exe', 'test_pocx.exe'):
                return unit_callback(command, **kwargs)
            if binary.name == 'test_bitcoin-qt.exe':
                kwargs['log'].write(self.qt_log(binary.parent.parent.name == 'pocx') if qt_log is None else qt_log)
            elif binary.name == 'test_kernel.exe':
                if '--list_content' in command:
                    kwargs['log'].write('\n'.join(case + '*' for case in json.loads((ROOT / 'test/pocx/kernel-baseline.json').read_text())['cases']))
                else:
                    sink = next(arg.split('=', 1)[1] for arg in command if arg.startswith('--report_sink='))
                    Path(sink).write_text(self.kernel_xml() if kernel_xml is None else kernel_xml)
                    kwargs['log'].write('Synthetic kernel callback\n')
            else: kwargs['log'].write('Synthetic auxiliary completion callback\n')
            control = {'kind': controller['kind'], 'cleanup_complete': cleanup, 'invocation': command}
            if controller['kind'] == 'windows-job':
                control['job'] = 'Local\\pocx-functional-' + 'a' * 32
                control['invocation'] = [controller['interpreter'], controller['path'], '--windows-worker', control['job'], '--', *command]
            if mutate is not None: mutate(binary)
            return {'returncode': code if failed == binary.name else 0,
                    'timed_out': timed_out, 'process_control': control}
        return execute

    def run_phase(self, payload, row, output, calls, **kwargs):
        with patch.object(tests.units, 'validate_assets'):
            return tests.run_phase(payload, row, output, {'directory': str(output.parent)},
                environment={'QTEST_FUNCTION_TIMEOUT': '1', 'BOOST_TEST_RUN_FILTERS': 'missing',
                             'SECP256K1_TEST_ITERS': '0', 'QT_QPA_PLATFORM': 'invalid'},
                execute=self.callback(calls, **kwargs))

    def test_preserves_upstream_qt_whole_unit_and_five_auxiliary_process_order(self):
        for consensus, methods in (('bitcoin', 9), ('pocx', 10)):
            with self.subTest(consensus=consensus), tempfile.TemporaryDirectory() as directory:
                root = Path(directory); payload, row = self.fixture(root, consensus); calls = []
                report = self.run_phase(payload, row, root / 'reports', calls)
                self.assertEqual(report['status'], 'passed'); self.assertFalse(report['full_windows_ci_pass'])
                self.assertEqual(report['qt']['original_green'], 9)
                self.assertEqual(report['qt']['native_only_green'], int(consensus == 'pocx'))
                names = [Path(command[0]).name for command, _ in calls]
                unit = 'test_pocx.exe' if consensus == 'pocx' else 'test_bitcoin.exe'
                self.assertEqual(names, ['test_bitcoin-qt.exe', unit, unit,
                    *[Path(name).name for name in tests.windows_artifacts.AUXILIARY]])
                self.assertTrue(all(len(command) == 1 for command, _ in calls if Path(command[0]).name not in (unit,)))
                for _, env in calls:
                    self.assertFalse(any(key.startswith(('QTEST_', 'BOOST_TEST_')) for key in env))
                    self.assertNotIn('SECP256K1_TEST_ITERS', env)
                    self.assertEqual(env['QT_QPA_PLATFORM'], 'minimal')
                self.assertEqual(sum(case['framework'] == 'qt' for case in report['cases']), methods)
                auxiliary = [case for case in report['cases'] if case['framework'] == 'auxiliary']
                self.assertEqual(len(auxiliary), 5)
                self.assertTrue(all('internal cases are not enumerated' in case['counting_unit'] for case in auxiliary))
                self.assertFalse((root / 'reports/ctest.xml').exists())

    def test_zero_exit_cannot_hide_partial_skipped_or_duplicate_qt_methods(self):
        good = self.qt_log(False)
        for log in (good.replace('PASS : URITests::uriTests()', ''),
                    good + '\nSKIP : URITests::uriTests()', good + '\nPASS : URITests::uriTests()'):
            with self.subTest(log=log), tempfile.TemporaryDirectory() as directory:
                root = Path(directory); payload, row = self.fixture(root); calls = []
                with self.assertRaises(ValueError): self.run_phase(payload, row, root / 'reports', calls, qt_log=log)
                self.assertEqual(len(calls), 1)
                report = json.loads((root / 'reports/results.json').read_text())
                self.assertEqual(report['status'], 'failed')
                self.assertEqual(len(report['cases']), 32)
                self.assertTrue(all(case['status'] == ('configuration-disabled' if case['framework'] == 'kernel' else 'unverified')
                                    for case in report['cases']))

    def test_auxiliary_nonzero_timeout_and_incomplete_cleanup_are_rejected(self):
        for binary in tests.windows_artifacts.AUXILIARY:
            with self.subTest(binary=binary), tempfile.TemporaryDirectory() as directory:
                root = Path(directory); payload, row = self.fixture(root); calls = []
                with self.assertRaises(ValueError):
                    self.run_phase(payload, row, root / 'reports', calls, failed=Path(binary).name)
                report = json.loads((root / 'reports/results.json').read_text())
                self.assertEqual(report['status'], 'failed')
                self.assertEqual(report['steps'][-1]['status'], 'failed')
        for kwargs in ({'timed_out': True}, {'cleanup': False}):
            with self.subTest(kwargs=kwargs), tempfile.TemporaryDirectory() as directory:
                root = Path(directory); payload, row = self.fixture(root)
                with self.assertRaises(ValueError): self.run_phase(payload, row, root / 'reports', [], **kwargs)

    def test_enabled_missing_qt_or_auxiliary_and_changed_executables_never_pass(self):
        for name in ('bin/test_bitcoin-qt.exe', *tests.windows_artifacts.AUXILIARY):
            with self.subTest(name=name), tempfile.TemporaryDirectory() as directory:
                root = Path(directory); payload, row = self.fixture(root)
                (payload / name).unlink()
                with self.assertRaises(ValueError): self.run_phase(payload, row, root / 'reports', [])
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); payload, row = self.fixture(root)
            with self.assertRaisesRegex(ValueError, 'changed'):
                self.run_phase(payload, row, root / 'reports', [], mutate=lambda path: path.write_text('changed executable'))

    def test_only_explicitly_disabled_gui_features_omit_qt_execution(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); payload, row = self.fixture(root, gui=False); calls = []
            report = self.run_phase(payload, row, root / 'reports', calls)
            self.assertEqual(report['qt']['status'], 'configuration-disabled')
            self.assertIn('BUILD_GUI=OFF', report['qt']['reason'])
            self.assertFalse(any(Path(command[0]).name == 'test_bitcoin-qt.exe' for command, _ in calls))
            self.assertTrue(all(case['status'] == 'configuration-disabled' for case in report['cases'] if case['framework'] == 'qt'))
        with self.assertRaises(ValueError): tests.qt_disabled_reason({'BUILD_GUI': 'ON'})

    def test_expected_inventory_preserves_exclusions_disabled_cases_and_adaptation_categories(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); payload, row = self.fixture(root, 'pocx')
            excluded = next(iter(json.loads((ROOT / 'test/pocx/unit-parity.json').read_text())['excluded']))
            row['expected_unit']['original'].extend([excluded, 'disabled/case'])
            row['expected_unit']['excluded'] = [excluded]
            row['expected_unit']['configuration_disabled'] = {'disabled/case': 'Explicit synthetic disabled feature'}
            cases = {(case['framework'], case['case']): case for case in tests.expected_rows(row)}
            self.assertEqual(cases[('unit', excluded)]['status'], 'reviewed-exclusion')
            self.assertEqual(cases[('unit', 'disabled/case')]['status'], 'configuration-disabled')
            self.assertEqual(cases[('qt', 'WalletTests::walletTests')]['adaptation'], 'adapted')
            self.assertEqual(cases[('qt', 'URITests::uriTests')]['adaptation'], 'unchanged')
            self.assertEqual(cases[('qt', 'PoCXURITests::nativePaymentURIs')]['adaptation'], 'pocx-only')

    def test_enabled_kernel_requires_complete_inventory_and_actual_assertion_results(self):
        for consensus in ('bitcoin', 'pocx'):
            with self.subTest(consensus=consensus), tempfile.TemporaryDirectory() as directory:
                root = Path(directory); payload, row = self.fixture(root, consensus, kernel=True); calls = []
                report = self.run_phase(payload, row, root / 'reports', calls)
                self.assertEqual(report['kernel']['status'], 'passed')
                self.assertEqual(report['kernel']['original_green'], 16)
                self.assertEqual(report['kernel']['assertions_passed'], 15)
                self.assertEqual(calls[-2][0], [str(payload / 'bin/test_kernel.exe'), '--list_content'])
                self.assertFalse(any('--run_test' in argument for argument in calls[-1][0]))
                self.assertEqual(sum(case['framework'] == 'kernel' and case['status'] == 'passed' for case in report['cases']), 16)
                self.assertFalse((root / 'reports/ctest.xml').exists())

    def test_zero_exit_cannot_hide_missing_skipped_failed_or_corrupt_kernel_report(self):
        good = self.kernel_xml()
        for xml in (good.replace('name="btck_block"', 'name="missing"'),
                    good.replace('test_cases_passed="16"', 'test_cases_passed="15"'),
                    good.replace('test_cases_skipped="0"', 'test_cases_skipped="1"'),
                    good.replace('assertions_failed="0"', 'assertions_failed="1"', 1),
                    good.replace('name="btck_block" result="passed"', 'name="btck_block" result="skipped"'),
                    '<TestResult/>', good + good):
            with self.subTest(xml=xml), tempfile.TemporaryDirectory() as directory:
                root = Path(directory); payload, row = self.fixture(root, kernel=True)
                with self.assertRaises(ValueError): self.run_phase(payload, row, root / 'reports', [], kernel_xml=xml)
                report = json.loads((root / 'reports/results.json').read_text())
                self.assertEqual(report['status'], 'failed')
                self.assertTrue(all(case['status'] == 'unverified' for case in report['cases'] if case['framework'] == 'kernel'))

    def test_missing_enabled_kernel_and_ambiguous_feature_flags_are_not_omissions(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); payload, row = self.fixture(root, kernel=True)
            (payload / 'bin/test_kernel.exe').unlink()
            with self.assertRaises(ValueError): self.run_phase(payload, row, root / 'reports', [])
        with self.assertRaises(ValueError): tests.kernel_disabled_reason({'BUILD_KERNEL_LIB': 'ON'})
        self.assertEqual(tests.kernel_disabled_reason({'BUILD_KERNEL_LIB': 'OFF'}), 'BUILD_KERNEL_LIB=OFF')

    def test_any_original_framework_failure_defers_all_native_tests(self):
        for failed in ('test_bitcoin-qt.exe', 'unit', 'unitester.exe', 'test_kernel.exe'):
            with self.subTest(failed=failed), tempfile.TemporaryDirectory() as directory:
                root = Path(directory); bundle = root / 'bundle'; bundle.mkdir()
                (bundle / 'pair.json').write_text('Synthetic pair metadata; mocked verifier\n')
                pair = {'phases': [self.fixture(bundle, consensus, kernel=failed == 'test_kernel.exe')[1] for consensus in ('bitcoin', 'pocx')]}
                calls = []
                with patch.object(tests.windows_artifacts, 'verify_pair', return_value=pair), patch.object(tests.units, 'validate_assets'):
                    with self.assertRaises(ValueError): tests.run_pair(bundle, root / 'reports',
                        {'directory': str(root)}, execute=self.callback(calls, failed=failed))
                report = json.loads((root / 'reports/results.json').read_text())
                self.assertEqual(report['native_execution'], 'deferred')
                self.assertEqual(report['phases'][0]['status'], 'failed')
                self.assertEqual(len(report['phases']), 1)
                self.assertTrue(all('pocx' not in Path(command[0]).parts for command, _ in calls))

    def test_pair_is_reverified_before_native_and_retains_failed_evidence(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); bundle = root / 'bundle'; bundle.mkdir()
            (bundle / 'pair.json').write_text('Synthetic pair metadata; mocked verifier\n')
            pair = {'phases': [self.fixture(bundle, consensus)[1] for consensus in ('bitcoin', 'pocx')]}
            with patch.object(tests.windows_artifacts, 'verify_pair', side_effect=[pair, ValueError('Changed immutable artifact')]), patch.object(tests.units, 'validate_assets'):
                with self.assertRaisesRegex(ValueError, 'immutable'): tests.run_pair(bundle, root / 'reports',
                    {'directory': str(root)}, execute=self.callback([]))
            report = json.loads((root / 'reports/results.json').read_text())
            self.assertEqual(report['status'], 'failed'); self.assertEqual(report['native_execution'], 'deferred')
            self.assertEqual(report['phases'][0]['status'], 'passed')
            self.assertEqual(report['phases'][0]['report_sha256'], sha256(root / 'reports/bitcoin/results.json'))

    def test_non_windows_cli_and_output_inside_payload_fail_before_execution(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); payload, row = self.fixture(root)
            with self.assertRaises(ValueError): self.run_phase(payload, row, payload / 'reports', [])
            self.assertFalse((payload / 'reports').exists())
            if os.name != 'nt':
                result = subprocess.run([sys.executable, str(ROOT / 'test/pocx/windows_artifact_tests.py'),
                    '--artifacts', str(root / 'missing'), '--output', str(root / 'reports')], capture_output=True, text=True)
                self.assertEqual(result.returncode, 2); self.assertIn('requires Windows', result.stderr)
                self.assertFalse((root / 'reports').exists())


if __name__ == '__main__':
    unittest.main()
