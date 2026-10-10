#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin PoCX developers
# Distributed under the MIT software license; see COPYING.
"""Complete-phase ordering and manifest checks; fixtures are not Windows proof."""
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from common import sha256
import process_tree
import windows_artifact_ci as ci


class WindowsArtifactCITest(unittest.TestCase):
    def fixture(self, directory):
        root = Path(directory)
        bundle = root / 'bundle'
        bundle.mkdir()
        (bundle / 'pair.json').write_text('Synthetic pair fixture\n')
        source = root / 'test/functional'
        source.mkdir(parents=True)
        (source / 'test_runner.py').write_text("BASE_SCRIPTS=['p2p_ping.py']\nEXTENDED_SCRIPTS=['pow_only.py']\n")
        manifest = root / 'test/pocx/manifest.json'
        manifest.parent.mkdir(parents=True)
        manifest.write_text(json.dumps({'tests': {'p2p_ping.py': 'functional/p2p_ping.py', 'native_only.py': 'functional/native_only.py'},
            'reused_tests': [], 'excluded_tests': {'pow_only.py': 'Original PoW algorithm replaced by PoCX'}}))
        rows = []
        for consensus in ('bitcoin', 'pocx'):
            files = {}
            for name in ('bitcoind.exe', 'test_pocx.exe' if consensus == 'pocx' else 'test_bitcoin.exe',
                         'bench_bitcoin.exe', 'pocx_chainstate_test_clock.exe'):
                path = bundle / consensus / 'bin' / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text('Synthetic non-executed artifact\n')
                files['bin/' + name] = sha256(path)
            rows.append({'consensus': consensus, 'files': files, 'build_options': {'ENABLE_POCX': 'ON' if consensus == 'pocx' else 'OFF'}})
        return root, bundle, {'phases': rows}

    def run_fixture(self, directory, *, failure=None, cleanup=True, mutation=None):
        root, bundle, pair = self.fixture(directory)
        calls = []
        controller = process_tree.description()
        def verify(*args, **kwargs):
            for row in pair['phases']:
                for name, digest in row['files'].items():
                    if sha256(bundle / row['consensus'] / name) != digest:
                        raise ValueError('Changed immutable payload')
            return pair
        def execute(command, **kwargs):
            calls.append(('process', command))
            kwargs['log'].write('Synthetic prerequisite callback\n')
            for arg in command:
                if arg.startswith('-out:'):
                    Path(arg[len('-out:'):]).write_text('<assembly/>\n')
            control = {'kind': controller['kind'], 'cleanup_complete': cleanup, 'invocation': command}
            if controller['kind'] == 'windows-job':
                control['job'] = 'Local\\pocx-functional-' + 'a' * 32
                control['invocation'] = [controller['interpreter'], controller['path'], '--windows-worker', control['job'], '--', *command]
            return {'returncode': 9 if failure == 'manifest' and command[0] == 'mt.exe' else 0,
                    'timed_out': False, 'process_control': control}
        def frameworks(payload, row, output, assets, **kwargs):
            calls.append(('frameworks', row['consensus']))
            output.mkdir(parents=True)
            report = {'status': 'passed', 'cases': [{'framework': 'unit', 'case': 'fixture/case', 'status': 'passed',
                'counting_unit': 'Boost leaf case', 'origin': 'original', 'adaptation': 'unchanged', 'reason': '', 'assertions_passed': 1}]}
            (output / 'results.json').write_text(json.dumps(report))
            if mutation:
                (payload / 'bin/bitcoind.exe').write_text('Changed during framework callback')
            if failure == 'frameworks':
                raise ValueError('Synthetic framework failure')
            return report
        def functional(bundle, row, output, jobs, factor, **kwargs):
            calls.append(('functional', row['consensus']))
            output.mkdir(parents=True)
            self.assertEqual(kwargs['environment']['DOWNLOAD_PREVIOUS_RELEASES'], 'true')
            self.assertEqual(kwargs['environment']['PYTHONDONTWRITEBYTECODE'], '1')
            report = {'status': 'passed', 'cases': [{'case': name, 'transport': mode, 'effective_transport': mode,
                'status': 'passed', 'reason': '', 'execution_status': 'Passed', 'seconds': 0.1}
                for name in (['p2p_ping.py', 'native_only.py'] if row['consensus'] == 'pocx' else ['p2p_ping.py', 'pow_only.py'])
                for mode in ('v1', 'v2')]}
            (output / 'results.json').write_text(json.dumps(report))
            if failure == 'functional':
                raise ValueError('Synthetic functional failure')
            return report
        output = root / 'results'
        with patch.object(ci.windows_artifacts, 'verify_pair', side_effect=verify), \
                patch.object(ci.frameworks, 'run_phase', side_effect=frameworks), \
                patch.object(ci.functional, 'run_phase', side_effect=functional):
            try:
                ci.run_pair(bundle, output, {}, 3, 7.5, root=root, revision='a' * 40,
                environment={'PREVIOUS_RELEASES_DIR': str(root / 'releases')}, execute=execute)
            except ValueError:
                pass
        return json.loads((output / 'results.json').read_text()), calls, output, pair

    def test_entire_original_phase_precedes_all_native_execution(self):
        with tempfile.TemporaryDirectory() as directory:
            report, calls, output, _ = self.run_fixture(directory)
            self.assertEqual(report['status'], 'passed')
            self.assertTrue(report['full_windows_runtime_pass'])
            self.assertFalse(report['full_windows_ci_pass'])
            self.assertEqual([(kind, value) for kind, value in calls if kind != 'process'],
                [('frameworks', 'bitcoin'), ('functional', 'bitcoin'), ('frameworks', 'pocx'), ('functional', 'pocx')])
            original_end = calls.index(('functional', 'bitcoin'))
            native_start = next(i for i, (kind, value) in enumerate(calls) if kind == 'process' and
                                any('/bundle/pocx/' in arg.replace('\\', '/') for arg in value))
            self.assertGreater(native_start, original_end)
            self.assertEqual(len(report['cases']), 12)
            self.assertEqual(len((output / 'cases.csv').read_text().splitlines()), 13)

    def test_manifest_framework_or_functional_baseline_failure_defers_native(self):
        for failure in ('manifest', 'frameworks', 'functional'):
            with self.subTest(failure=failure), tempfile.TemporaryDirectory() as directory:
                report, calls, _, _ = self.run_fixture(directory, failure=failure)
                self.assertEqual(report['status'], 'failed')
                self.assertFalse(report['full_windows_runtime_pass'])
                self.assertEqual(report['native_execution'], 'deferred')
                self.assertEqual([row['consensus'] for row in report['phases']], ['bitcoin'])
                self.assertFalse(any(value == 'pocx' for kind, value in calls if kind != 'process'))

    def test_original_manifest_exemptions_are_exact_and_owned_tools_are_validated(self):
        with tempfile.TemporaryDirectory() as directory:
            report, calls, _, _ = self.run_fixture(directory)
            validation = [command for kind, command in calls if kind == 'process' and '-validate_manifest' in command]
            self.assertEqual(len(validation), 6)
            self.assertEqual(sum('pocx_chainstate_test_clock.exe' in ' '.join(command) for command in validation), 2)
            self.assertFalse(any('bench_bitcoin.exe' in ' '.join(command) for command in validation))
            self.assertEqual(ci.MANIFEST_SKIPS, {'fuzz.exe', 'bench_bitcoin.exe'})
            self.assertTrue(all(len(phase['manifest_exemptions']) == 1 for phase in report['phases']))

    def test_incomplete_process_cleanup_and_payload_mutation_stop_the_pair(self):
        for kwargs in ({'cleanup': False}, {'mutation': True}):
            with self.subTest(kwargs=kwargs), tempfile.TemporaryDirectory() as directory:
                report, _, _, _ = self.run_fixture(directory, **kwargs)
                self.assertEqual(report['status'], 'failed')
                self.assertEqual(report['native_execution'], 'deferred')

    def test_case_report_preserves_original_adapted_native_and_reviewed_excluded_categories(self):
        with tempfile.TemporaryDirectory() as directory:
            report, _, _, _ = self.run_fixture(directory)
            native = [row for row in report['cases'] if row['consensus'] == 'pocx' and row['framework'] == 'functional']
            self.assertEqual({row['adaptation'] for row in native}, {'adapted', 'pocx-only', 'excluded'})
            self.assertEqual(sum(row['status'] == 'reviewed-exclusion' for row in native), 2)
            self.assertEqual(sum(row['origin'] == 'pocx-only' for row in native), 2)


if __name__ == '__main__':
    unittest.main()
