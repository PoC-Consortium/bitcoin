#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin PoCX developers
# Distributed under the MIT software license; see COPYING.
"""Strict direct Boost artifact checks; fixtures do not establish Windows passes."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from common import ROOT, sha256
import process_tree
import windows_artifact_unit as units


class ArtifactUnitTest(unittest.TestCase):
    expected = {'first/set_state', 'second/check_state'}

    def xml(self):
        return '''<TestResult><TestSuite name="module" result="passed" assertions_failed="0" test_cases_passed="2" test_cases_skipped="1" test_cases_failed="0">
<TestSuite name="first" result="passed"><TestCase name="set_state" result="passed" assertions_passed="1" assertions_failed="0"/></TestSuite>
<TestSuite name="second" result="passed"><TestCase name="check_state" result="passed" assertions_passed="2" assertions_failed="0"/></TestSuite>
</TestSuite></TestResult>'''

    def listing(self):
        return 'first*\n    set_state*\nsecond*\n    check_state*\nmock_process \n    valid_json \n'

    def row(self, payload, consensus='bitcoin'):
        name = 'bin/test_bitcoin.exe' if consensus == 'bitcoin' else 'bin/test_pocx.exe'
        binary = payload / name
        binary.parent.mkdir(parents=True, exist_ok=True)
        binary.write_text('synthetic executable; callbacks only')
        return {'consensus': consensus, 'unit_binary': name, 'files': {name: sha256(binary)},
            'expected_unit': {'expected': sorted(self.expected), 'original': sorted(self.expected),
                'applicable': sorted(self.expected), 'additional': [], 'excluded': [], 'configuration_disabled': {}}}

    def test_single_process_report_allows_only_original_disabled_subprocess_helpers(self):
        disabled = units.runtime_cases(self.listing(), self.expected)
        self.assertEqual(disabled, {'mock_process/valid_json'})
        self.assertEqual(units.single_process_leaves(self.xml(), self.expected, disabled),
                         {'first/set_state': 1, 'second/check_state': 2})
        with self.assertRaises(ValueError):
            units.runtime_cases(self.listing() + 'hidden\n    case\n', self.expected)
        with self.assertRaises(ValueError):
            units.runtime_cases(self.listing().replace('check_state*', 'check_state'), self.expected)

    def test_green_summary_cannot_hide_missing_skipped_failed_or_duplicate_cases(self):
        original = self.xml()
        variants = [original.replace('name="check_state"', 'name="missing"'),
            original.replace('name="check_state" result="passed"', 'name="check_state" result="skipped"'),
            original.replace('assertions_failed="0"', 'assertions_failed="1"', 1),
            original.replace('test_cases_passed="2"', 'test_cases_passed="1"'),
            original.replace('test_cases_skipped="1"', 'test_cases_skipped="2"'), original + original,
            original.replace('</TestSuite></TestResult>', '<TestCase name="extra" result="passed" assertions_passed="1" assertions_failed="0"/></TestSuite></TestResult>')]
        for xml in variants:
            with self.subTest(xml=xml), self.assertRaises((ValueError, units.ET.ParseError)):
                units.single_process_leaves(xml, self.expected, {'mock_process/valid_json'})

    def test_compiled_simd_comparison_needs_executed_assertions(self):
        case = next(iter(units.unit_matrix.SSE2_CASES))
        suite, name = case.split('/')
        xml = f'<TestResult><TestSuite name="module" result="passed" assertions_failed="0" test_cases_passed="1" test_cases_skipped="0"><TestSuite name="{suite}" result="passed"><TestCase name="{name}" result="passed" assertions_passed="0" assertions_failed="0"/></TestSuite></TestSuite></TestResult>'
        with self.assertRaisesRegex(ValueError, 'assertions'):
            units.single_process_leaves(xml, {case}, set())

    def callback(self, calls, *, code=0, cleanup=True, timeout=False):
        controller = process_tree.description()
        def execute(command, **kwargs):
            calls.append((command, kwargs['env']))
            if '--list_content' in command:
                kwargs['log'].write(self.listing())
            else:
                sink = next(arg.split('=', 1)[1] for arg in command if arg.startswith('--report_sink='))
                Path(sink).write_text(self.xml())
                kwargs['log'].write('synthetic unit callback\n')
            control = {'kind': controller['kind'], 'cleanup_complete': cleanup, 'invocation': command}
            if controller['kind'] == 'windows-job':
                control['job'] = 'Local\\pocx-functional-' + 'a' * 32
                control['invocation'] = [controller['interpreter'], controller['path'], '--windows-worker', control['job'], '--', *command]
            return {'returncode': code if '--list_content' not in command else 0,
                    'timed_out': timeout, 'process_control': control}
        return execute

    def test_phase_preserves_one_unfiltered_unit_process_and_clears_boost_overrides(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            payload = root / 'payload'
            row = self.row(payload)
            calls = []
            report = units.run_phase(payload, row, root / 'results', {'directory': str(root)},
                environment={'BOOST_TEST_RUN_FILTERS': 'first', 'BOOST_TEST_REPORT_SINK': 'wrong'},
                execute=self.callback(calls))
            self.assertEqual(report['status'], 'passed')
            self.assertEqual(len(report['cases']), 2)
            self.assertEqual(len(calls), 2)
            self.assertEqual(calls[0][0], [str(payload / row['unit_binary']), '--list_content'])
            self.assertEqual(calls[1][0][1:3], ['-l', 'test_suite'])
            self.assertFalse(any('--run_test' in argument for argument in calls[1][0]))
            self.assertFalse(any(key.startswith('BOOST_TEST_') for key in calls[1][1]))

    def test_failures_timeouts_and_incomplete_cleanup_remain_failed(self):
        for options in ({'code': 7}, {'cleanup': False}, {'timeout': True}):
            with self.subTest(options=options), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                payload = root / 'payload'
                row = self.row(payload)
                with self.assertRaises(ValueError):
                    units.run_phase(payload, row, root / 'results',
                    {'directory': str(root)}, execute=self.callback([], **options))
                self.assertEqual(json.loads((root / 'results/results.json').read_text())['status'], 'failed')

    def test_original_failure_prevents_any_native_unit_execution(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            bundle = root / 'bundle'
            bundle.mkdir()
            (bundle / 'pair.json').write_text('synthetic fixture')
            pair = {'phases': [self.row(bundle / consensus, consensus) for consensus in ('bitcoin', 'pocx')]}
            calls = []
            with patch.object(units.windows_artifacts, 'verify_pair', return_value=pair), patch.object(units, 'validate_assets'):
                with self.assertRaises(ValueError):
                    units.run_pair(bundle, root / 'results',
                    {'directory': str(root)}, execute=self.callback(calls, code=7))
            report = json.loads((root / 'results/results.json').read_text())
            self.assertEqual(report['native_execution'], 'deferred')
            self.assertEqual(report['phases'][0]['status'], 'failed')
            self.assertEqual(len(calls), 2)
            self.assertTrue(all('test_bitcoin.exe' in command[0] for command, _ in calls))

    @unittest.skipUnless(os.name == 'posix' and shutil.which('c++') and
                         Path('/usr/include/boost/test/included/unit_test.hpp').is_file(), 'Native Boost/compiler fixture prerequisite unavailable')
    def test_real_boost_fixture_catches_replacing_one_process_with_per_suite_runs(self):
        with tempfile.TemporaryDirectory(prefix='boost-artifact-') as directory:
            root = Path(directory)
            payload = root / 'payload'
            row = self.row(payload)
            cpp = root / 'fixture.cpp'
            cpp.write_text('''#define BOOST_TEST_MODULE StateOrderProbe
#include <boost/test/included/unit_test.hpp>
static int state = 0;
BOOST_AUTO_TEST_SUITE(first)
BOOST_AUTO_TEST_CASE(set_state) { state = 7; BOOST_CHECK_EQUAL(state, 7); }
BOOST_AUTO_TEST_SUITE_END()
BOOST_AUTO_TEST_SUITE(second)
BOOST_AUTO_TEST_CASE(check_state) { BOOST_CHECK_EQUAL(state, 7); }
BOOST_AUTO_TEST_SUITE_END()
BOOST_AUTO_TEST_SUITE(mock_process, *boost::unit_test::disabled())
BOOST_AUTO_TEST_CASE(valid_json, *boost::unit_test::disabled()) {}
BOOST_AUTO_TEST_SUITE_END()
''')
            binary = payload / row['unit_binary']
            subprocess.run(['c++', '-std=c++17', str(cpp), '-o', str(binary)], capture_output=True, text=True, check=True)
            row['files'][row['unit_binary']] = sha256(binary)
            report = units.run_phase(payload, row, root / 'results', {'directory': str(root)}, timeout=30)
            self.assertEqual(report['status'], 'passed')
            self.assertEqual(report['default_disabled_subprocess_helpers'], ['mock_process/valid_json'])
            isolated = subprocess.run([str(binary), '--run_test=second'], capture_output=True, text=True)
            self.assertNotEqual(isolated.returncode, 0)

    def test_missing_or_corrupt_assets_and_non_windows_cli_never_run_tests(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with self.assertRaises(ValueError):
                units.validate_assets({'directory': str(root)})
            assets = {'directory': str(root), 'commit': units.unit_assets.COMMIT,
                      'sha256': units.unit_assets.SHA256, 'vectors': units.unit_assets.VECTORS}
            with self.assertRaises(FileNotFoundError):
                units.validate_assets(assets)
            (root / 'script_assets_test.json').write_text('corrupt vectors')
            with self.assertRaises(ValueError):
                units.validate_assets(assets)
            if os.name != 'nt':
                result = subprocess.run([sys.executable, str(ROOT / 'test/pocx/windows_artifact_unit.py'),
                    '--artifacts', str(root / 'missing'), '--output', str(root / 'reports')], capture_output=True, text=True)
                self.assertEqual(result.returncode, 2)
                self.assertIn('requires Windows', result.stderr)
                self.assertFalse((root / 'reports').exists())


if __name__ == '__main__':
    unittest.main()
