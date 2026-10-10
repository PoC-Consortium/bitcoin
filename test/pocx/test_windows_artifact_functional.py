#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin PoCX developers
# Distributed under the MIT software license; see COPYING.
"""Functional dispatch/retained-proof checks; callbacks are not Windows passes."""
from copy import deepcopy
import csv
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from common import sha256
import inherited_functional as functional
import windows_artifact_functional as artifact
import process_tree
import test_artifact_functional_view


class ArtifactFunctionalTest(unittest.TestCase):
    def controlled_fixture(self, directory, *, code=0, timed_out=False, cleanup=True, mutation=None):
        helper = test_artifact_functional_view.FunctionalArtifactViewTest()
        helper.setUp()
        self.addCleanup(helper.doCleanups)
        root, bundle = helper.fixture(directory)
        pair = artifact.windows_artifacts.verify_pair(bundle, root=root, revision='a' * 40)
        row = pair['phases'][0]
        release = root / 'release-wallet.exe'
        release.write_text('Synthetic pinned prerequisite\n')
        controller = process_tree.description()
        def execute(command, **kwargs):
            self.assertEqual(kwargs['env']['PYTHONDONTWRITEBYTECODE'], '1')
            self.assertNotIn('PYTHONPATH', kwargs['env'])
            child = Path(command[command.index('--output') + 1])
            child.mkdir()
            (child / 'results.json').write_text('{"status":"passed"}\n')
            kwargs['log'].write('Synthetic functional process callback\n')
            if mutation == 'release':
                release.write_text('Changed prerequisite\n')
            if mutation == 'runtime':
                view = Path(command[command.index('--build-dir') + 1])
                (view / 'bin/bitcoind.exe').write_text('Changed runtime binary\n')
            if mutation == 'payload':
                (bundle / 'bitcoin/bin/bitcoind.exe').write_text('Changed payload\n')
            control = {'kind': controller['kind'], 'cleanup_complete': cleanup, 'invocation': command}
            if controller['kind'] == 'windows-job':
                control['job'] = 'Local\\pocx-functional-' + 'a' * 32
                control['invocation'] = [controller['interpreter'], controller['path'], '--windows-worker', control['job'], '--', *command]
            return {'returncode': code, 'timed_out': timed_out, 'process_control': control}
        output = root / 'functional-results'
        cases = [{'case': 'fixture.py', 'transport': mode, 'status': 'passed', 'seconds': 0.1} for mode in ('v1', 'v2')]
        with patch.object(artifact, 'verify_child', return_value=cases), \
                patch.object(artifact.functional_environment, 'release_binaries', return_value={'v28.2/bitcoin-wallet': release}):
            try:
                artifact.run_phase(bundle, row, output, 3, 7.5, root=root, revision='a' * 40,
                environment={'PREVIOUS_RELEASES_DIR': str(root / 'releases'), 'DOWNLOAD_PREVIOUS_RELEASES': 'true',
                             'PYTHONPATH': '/unreviewed'}, execute=execute)
            except ValueError:
                pass
        return json.loads((output / 'results.json').read_text())

    def test_controlled_phase_preserves_real_view_and_previous_release_inputs(self):
        with tempfile.TemporaryDirectory() as directory:
            report = self.controlled_fixture(directory)
            self.assertEqual(report['status'], 'passed')
            self.assertFalse(report['full_windows_ci_pass'])
            self.assertEqual(report['counts'], {'passed': 2})
            self.assertEqual(report['previous_release_binaries']['v28.2/bitcoin-wallet']['sha256'],
                             sha256(Path(report['previous_release_binaries']['v28.2/bitcoin-wallet']['path'])))

    def test_controlled_phase_rejects_failure_timeout_cleanup_and_input_mutation(self):
        for kwargs in ({'code': 9}, {'timed_out': True}, {'cleanup': False},
                       {'mutation': 'release'}, {'mutation': 'runtime'}, {'mutation': 'payload'}):
            with self.subTest(kwargs=kwargs), tempfile.TemporaryDirectory() as directory:
                report = self.controlled_fixture(directory, **kwargs)
                self.assertEqual(report['status'], 'failed')
                self.assertFalse(report['full_windows_ci_pass'])

    def original_fixture(self, directory, *, bench=True, previous=True, legacy_code=0, omit=None):
        root = Path(directory)
        build = root / 'runtime'
        build.mkdir()
        directory = root / 'test/functional'
        directory.mkdir(parents=True)
        (directory / 'test_runner.py').write_text(
            "TOOL_BENCH_SANITY_CHECK='tool_bench_sanity_check.py'\n"
            "BASE_SCRIPTS=['p2p_ping.py','feature_bind_port_discover.py','feature_bind_port_externalip.py','feature_unsupported_utxo_db.py',"
            "'wallet_multiwallet.py','wallet_multiwallet.py --usecli',TOOL_BENCH_SANITY_CHECK]\n"
            "EXTENDED_SCRIPTS=['feature_long.py']\n")
        (directory / 'tool_bench_sanity_check.py').write_text(
            'class Test:\n def skip_test_if_missing_module(self):\n  self.skip_if_no_bitcoin_bench()\n')
        for name in ('p2p_ping.py', 'feature_unsupported_utxo_db.py', 'wallet_multiwallet.py', 'feature_long.py', *functional.ADDRESS):
            (directory / name).write_text('class Test:\n def skip_test_if_missing_module(self):\n  pass\n')
        (build / 'CMakeCache.txt').write_text('ENABLE_POCX:BOOL=OFF\nBUILD_BENCH:BOOL=' + ('ON' if bench else 'OFF') + '\n')
        paths = {name: build / 'bin' / (name + '.exe') for name in functional.functional_execution.BINARY_NAMES}
        env = {'DOWNLOAD_PREVIOUS_RELEASES': 'true', 'PREVIOUS_RELEASES_DIR': str(root / 'releases')} if previous else {}
        options = {'ENABLE_POCX': 'OFF', 'BUILD_BENCH': 'ON' if bench else 'OFF', 'target_system': 'Windows'}
        output = root / 'execution'
        calls = []
        expected = functional.original_inventory(directory / 'test_runner.py', ['Alpha', 'Beta'] if bench else [], bench)
        def run(command, **kwargs):
            calls.append(command)
            self.assertEqual(kwargs['env']['PYTHONDONTWRITEBYTECODE'], '1')
            kwargs['stdout'].write('Synthetic original dispatcher callback\n')
            if command[1].endswith(functional.LEGACY_UTXO):
                self.assertTrue(next(arg for arg in command if arg.startswith('--tmpdir=')).isascii())
                return subprocess.CompletedProcess(command, legacy_code)
            self.assertIn('--exclude=' + functional.LEGACY_UTXO, command)
            self.assertFalse(any('wallet_multiwallet' in arg for arg in command if arg.startswith('--exclude')))
            path = Path(next(arg.split('=', 1)[1] for arg in command if arg.startswith('--resultsfile=')))
            with path.open('w', newline='') as stream:
                writer = csv.writer(stream)
                writer.writerow(['test', 'status', 'duration(seconds)'])
                for case in expected:
                    if case in (functional.LEGACY_UTXO, omit):
                        continue
                    writer.writerow([case, 'Skipped' if case in functional.ADDRESS or
                        (not bench and case == 'tool_bench_sanity_check.py') else 'Passed', 0.1])
                writer.writerow(['ALL', 'Passed', 0.1])
            return subprocess.CompletedProcess(command, 0)
        with patch.object(functional, 'ROOT', root), patch.object(functional, 'dependency_hashes', return_value={}), \
                patch.object(functional.functional_execution, 'binary_paths', return_value=paths), \
                patch.object(functional.subprocess, 'check_output', return_value='Alpha\nBeta\n'), \
                patch.object(functional.subprocess, 'run', side_effect=run):
            try:
                functional.run(build, output, options, 3, 7.5, environment=env)
            except ValueError:
                pass
        return root, build, output, options, env, json.loads((output / 'results.json').read_text()), calls

    def verify(self, root, build, output, options, env, report):
        with patch.object(artifact, 'dependency_hashes', return_value={}):
            return artifact.verify_child(report, output, build, options, 3, 7.5, env, root=root)

    def test_original_windows_inventory_keeps_every_variant_and_both_transports(self):
        with tempfile.TemporaryDirectory() as directory:
            root, build, output, options, env, report, calls = self.original_fixture(directory)
            self.assertEqual(report['status'], 'passed')
            cases = self.verify(root, build, output, options, env, report)
            self.assertEqual(len(cases), 18)
            for mode in ('v1', 'v2'):
                self.assertEqual({row['case'] for row in cases if row['transport'] == mode}, set(report['expected_cases']))
                self.assertIn('wallet_multiwallet.py --usecli', report['expected_cases'])
            self.assertEqual([row['name'] for row in report['runs']], ['v1', 'v1-legacy-utxo', 'v2', 'v2-legacy-utxo'])
            self.assertEqual(len(calls), 4)

    def test_disabled_benchmarks_keep_source_guarded_case_without_executing_listing(self):
        with tempfile.TemporaryDirectory() as directory:
            root, build, output, options, env, report, _ = self.original_fixture(directory, bench=False)
            self.assertNotIn('benchmark_discovery', report)
            self.assertEqual(report['benchmarks'], [])
            self.assertEqual(report['counts'], {'passed': 10, 'configuration-disabled': 6})
            self.verify(root, build, output, options, env, report)
            disabled = [row for row in report['cases'] if row['case'] == 'tool_bench_sanity_check.py']
            self.assertTrue(all('BUILD_BENCH=OFF' in row['reason'] for row in disabled))

    def test_previous_release_disabled_skip_is_visible_and_enabled_skip_fails(self):
        for previous, wanted in ((False, 'passed'), (True, 'failed')):
            with self.subTest(previous=previous), tempfile.TemporaryDirectory() as directory:
                root, build, output, options, env, report, _ = self.original_fixture(directory, previous=previous, legacy_code=77)
                self.assertEqual(report['status'], wanted)
                if previous:
                    with self.assertRaises(ValueError):
                        self.verify(root, build, output, options, env, report)
                else:
                    self.verify(root, build, output, options, env, report)
                    self.assertEqual(report['counts']['configuration-disabled'], 6)

    def test_failed_legacy_process_and_missing_original_case_fail(self):
        for kwargs in ({'legacy_code': 9}, {'omit': 'wallet_multiwallet.py --usecli'}):
            with self.subTest(kwargs=kwargs), tempfile.TemporaryDirectory() as directory:
                root, build, output, options, env, report, _ = self.original_fixture(directory, **kwargs)
                self.assertEqual(report['status'], 'failed')
                with self.assertRaises(ValueError):
                    self.verify(root, build, output, options, env, report)

    def test_green_child_report_cannot_hide_raw_case_command_or_log_changes(self):
        with tempfile.TemporaryDirectory() as directory:
            root, build, output, options, env, original, _ = self.original_fixture(directory)
            for mutation in ('case', 'command', 'returncode', 'log', 'inventory', 'transport', 'factor', 'counts', 'benchmarks'):
                report = deepcopy(original)
                if mutation == 'case':
                    report['cases'].pop()
                elif mutation == 'command':
                    report['runs'][0]['command'].append('--exclude=wallet_multiwallet.py')
                elif mutation == 'returncode':
                    report['runs'][1]['returncode'] = 77
                elif mutation == 'log':
                    report['runs'][0]['log_sha256'] = '0' * 64
                elif mutation == 'inventory':
                    report['expected_cases'].pop()
                elif mutation == 'transport':
                    report['cases'][0]['transport'] = 'v2'
                elif mutation == 'factor':
                    report['profile']['effective_timeout_factor'] = 1
                elif mutation == 'counts':
                    report['counts']['passed'] += 1
                else:
                    report['benchmarks'] = ['Alpha']
                with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                    self.verify(root, build, output, options, env, report)
            path = output / 'v1.csv'
            path.write_text(path.read_text().replace('p2p_ping.py,Passed', 'p2p_ping.py,Skipped'))
            with self.assertRaises(ValueError):
                self.verify(root, build, output, options, env, original)

    def test_ascii_directory_requirement_and_invalid_features_are_explicit(self):
        profile = functional.inherited_options({})
        with self.assertRaisesRegex(ValueError, 'ASCII-only'):
            functional.original_command(Path('/runtime'), Path('/tmp/₿'), ('legacy-utxo', [functional.LEGACY_UTXO], True),
                'v1', 3, 7.5, profile, windows=True)
        with self.assertRaises(ValueError):
            functional.original_groups(['p2p_ping.py'], {'target_system': 'Windows'})
        with self.assertRaises(ValueError):
            functional.original_inventory(Path('unused'), [], None)
        for factor in (0, -1, float('nan'), float('inf'), True):
            with self.subTest(factor=factor), self.assertRaises(ValueError):
                artifact.execution_profile({}, factor)

    def test_native_verification_requires_complete_selected_matrix_and_terminal_results(self):
        from functional_cases import case_spec, selection_digest
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            view = root / 'runtime'
            proof_dir = view / 'native-proof'
            proof_dir.mkdir(parents=True)
            execution = root / 'execution'
            execution.mkdir()
            original_dir = root / 'test/functional'
            original_dir.mkdir(parents=True)
            (original_dir / 'test_runner.py').write_text("BASE_SCRIPTS=['p2p_ping.py']\nEXTENDED_SCRIPTS=['feature_long.py']\n")
            (original_dir / 'p2p_ping.py').write_text('class Test:\n def skip_test_if_missing_module(self):\n  pass\n')
            spec = case_spec('p2p_ping.py', [])
            manifest = {'tests': {}, 'reused_tests': ['p2p_ping.py']}
            profile = artifact.execution_profile({}, 7.5)
            provenance = {'format_version': 9, 'selected_cases': [spec], 'selected_tests': [spec['test']],
                'transport_modes': ['v1', 'v2'], 'build_configuration': None, 'timeout_factor': 7.5,
                'environment_profile': {'previous_releases': False, 'network_addresses': False},
                'execution_options': {'use_cli': False, 'multiprocess': False},
                'case_selection': {'selected_cases_sha256': selection_digest([spec])}}
            controller = process_tree.description()
            provenance['process_controller'] = controller
            results = []
            for mode in ('v1', 'v2'):
                flags = ['--timeout-factor=7.5', '--' + mode + 'transport']
                results.append({'case': spec['id'], 'test': spec['test'], 'case_arguments': [], 'transport': mode,
                    'test_arguments': flags, 'command': ['python3', spec['test'], *flags],
                    'execution_options': provenance['execution_options'], 'returncode': 0, 'timed_out': False,
                    'status': 'passed', 'seconds': 0.1})
                command = results[-1]['command']
                control = {'kind': controller['kind'], 'cleanup_complete': True, 'invocation': command}
                if controller['kind'] == 'windows-job':
                    control['job'] = 'Local\\pocx-functional-' + 'a' * 32
                    control['invocation'] = [controller['interpreter'], controller['path'], '--windows-worker', control['job'], '--', *command]
                results[-1]['process_control'] = control
            proof_path = proof_dir / 'results.json'
            proof_path.write_text(json.dumps({'provenance': provenance, 'results': results}))
            log = execution / 'native.log'
            log.write_text('Synthetic native proof fixture\n')
            options = {'ENABLE_POCX': 'ON', 'target_system': 'Windows'}
            with patch.object(functional, 'ROOT', root), patch.object(artifact, 'dependency_hashes', return_value={}), \
                    patch.object(artifact, 'verify_current_inputs', return_value=manifest):
                report = {'status': 'passed', 'profile': profile, 'build_options': options, 'build_configuration': None,
                    'native': True, 'external_dependencies': {}, 'expected_cases': [spec['id']],
                    'native_proof': {'path': str(proof_path), 'sha256': sha256(proof_path)},
                    'runs': [{'name': 'native', 'command': functional.native_command(view, 3, 7.5, profile, {}),
                              'returncode': 0, 'seconds': 0.1, 'log_sha256': sha256(log)}],
                    'counts': {'passed': 2}, 'cases': [{'case': spec['id'], 'transport': mode, 'effective_transport': mode,
                        'status': 'passed', 'reason': '', 'execution_status': 'passed', 'seconds': 0.1} for mode in ('v1', 'v2')]}
                self.assertEqual(len(artifact.verify_child(report, execution, view, options, 3, 7.5, {}, root=root)), 2)
                results.pop()
                proof_path.write_text(json.dumps({'provenance': provenance, 'results': results}))
                report['native_proof']['sha256'] = sha256(proof_path)
                with self.assertRaises(ValueError):
                    artifact.verify_child(report, execution, view, options, 3, 7.5, {}, root=root)


if __name__ == '__main__':
    unittest.main()
