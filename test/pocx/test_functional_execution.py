#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin PoCX developers
# Distributed under the MIT software license; see COPYING.
"""Require inherited execution modes to match actual functional arguments/binaries."""
from copy import deepcopy
from contextlib import redirect_stdout
import builtins
import importlib.util
import io
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

from common import OWNED
import functional_execution as execution
import build_configuration
import process_tree
from functional_cases import case_spec, selection_digest
from functional_results import transport_results


class ExecutionTest(unittest.TestCase):
    def test_actual_owned_dispatch_cleans_children_and_retains_success_skip_failure_results(self):
        # Actual dispatcher and subprocess lifecycles around synthetic scripts.
        # These executable placeholders never run Bitcoin or PoCX test cases.
        from test_process_tree import alive
        spec = importlib.util.spec_from_file_location('owned_process_dispatch_fixture', OWNED / 'test_runner.py')
        runner = importlib.util.module_from_spec(spec);spec.loader.exec_module(runner)
        with tempfile.TemporaryDirectory(prefix='process-dispatch-') as directory:
            build = Path(directory);tree = build / 'staged';framework = tree / 'test_framework'
            framework.mkdir(parents=True);(build / 'bin').mkdir()
            (framework / '__init__.py').write_text('')
            (framework / 'test_framework.py').write_text('')
            (framework / 'util.py').write_text('MAX_NODES = 12\nPORT_RANGE = 5000\n')
            cache = build / 'CMakeCache.txt';cache.write_text('ENABLE_POCX:BOOL=ON\n')
            for name in ('bitcoind', 'bitcoin-cli'):
                path = build_configuration.executable(build, name, cache.read_text())
                path.write_bytes(b'placeholder, never executed')
            script = '''import pathlib, subprocess, sys, time
directory = pathlib.Path(next(arg.split('=',1)[1] for arg in sys.argv if arg.startswith('--tmpdir=')))
directory.mkdir(parents=True)
for name in ('node0/regtest/blocks/blk00000.dat', 'node0/regtest/chainstate/CURRENT',
             'node0/regtest/indexes/txindex/CURRENT', 'node0/regtest/debug.log',
             'node0/regtest/wallets/default/wallet.dat', 'fixtures/blocks/retained'):
    path = directory / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text('retained fixture')
pidfile = directory / 'child.pid'
child = "import os,pathlib,sys,time; pathlib.Path(sys.argv[1]).write_text(str(os.getpid())); time.sleep(120)"
subprocess.Popen([sys.executable, '-c', child, str(pidfile)])
deadline = time.monotonic() + 5
while not pidfile.is_file() or not pidfile.read_text().strip():
    if time.monotonic() >= deadline: raise RuntimeError('child did not start')
    time.sleep(.01)
if pathlib.Path(__file__).name == 'interface_ipc.py':
    print('Test Skipped: synthetic disabled IPC fixture')
    sys.exit(77)
if pathlib.Path(__file__).name == 'feature_abort.py':
    sys.exit(1)
'''
            manifest = {'tests': {name:'synthetic' for name in ('p2p_ping.py','interface_ipc.py','feature_abort.py')}, 'reused_tests': []}
            for name in manifest['tests']:(tree / name).write_text(script)
            provenance = {'build_configuration': None, 'build_options': {'ENABLE_POCX':'ON'}}
            output = io.StringIO()
            with patch.object(runner, 'stage', return_value=(tree, manifest, provenance)), \
                 patch.object(sys, 'argv', ['runner', '--build-dir', str(build), '--transport', 'matrix',
                                           '--jobs', '2', '--timeout', '10']), redirect_stdout(output):
                code = runner.main()
            self.assertEqual(code, 1, output.getvalue())
            reports = list(build.glob('pocx-results-*/results.json'))
            self.assertEqual(len(reports), 1)
            report = json.loads(reports[0].read_text())
            self.assertEqual(report['provenance']['format_version'], 9)
            pairs = transport_results(report)
            self.assertEqual(len(pairs), 6)
            self.assertEqual({(mode,row['status']) for mode,row in pairs},
                             {(mode,status) for mode in ('v1','v2') for status in ('passed','skipped','failed')})
            for _, row in pairs:
                pid = int((Path(row['output_dir']) / 'child.pid').read_text())
                self.assertFalse(alive(pid), 'Dispatcher released a slot before descendant cleanup')
                self.assertIs(row['process_control']['cleanup_complete'], True)
                case = Path(row['output_dir'])
                expected = ['node0/regtest/' + name for name in ('blocks','chainstate','indexes')]
                self.assertEqual(row['pruned_databases'], expected if row['status'] == 'passed' else [])
                for name in expected:
                    self.assertEqual((case / name).exists(), row['status'] != 'passed')
                for name in ('node0/regtest/debug.log', 'node0/regtest/wallets/default/wallet.dat',
                             'fixtures/blocks/retained'):
                    self.assertEqual((case / name).read_text(), 'retained fixture')

            # A storage failure must fail the dispatcher, while retaining the
            # passed subprocess outcome and its full diagnostic files.
            with patch.object(runner, 'stage', return_value=(tree, manifest, provenance)), \
                 patch.object(runner.functional_retention, 'prune_passed_case', side_effect=OSError('storage fixture')), \
                 patch.object(sys, 'argv', ['runner', '--build-dir', str(build), '--timeout', '10',
                                           'p2p_ping.py']), redirect_stdout(output):
                self.assertEqual(runner.main(), 1)
            report = next(json.loads(path.read_text()) for path in build.glob('pocx-results-*/results.json')
                          if 'retention_error' in json.loads(path.read_text())['results'][0])
            self.assertEqual(len(report['results']), 1)
            row = report['results'][0]
            self.assertEqual(row['status'], 'passed')
            self.assertEqual(row['retention_error'], 'storage fixture')
            self.assertTrue((Path(row['output_dir']) / 'node0/regtest/blocks/blk00000.dat').is_file())
            self.assertFalse(alive(int((Path(row['output_dir']) / 'child.pid').read_text())))
            from verify_functional import verify
            with self.assertRaisesRegex(ValueError, 'database retention failed'):
                verify(report, report['provenance']['selected_cases'], ['v1'], {'cases': {}},
                       report['provenance']['build_options'])

    def test_current_controller_report_requires_completed_command_bound_cleanup(self):
        report = self.report()
        controller = dict(process_tree.description(), kind='posix-session')
        report['provenance'].update(format_version=9, build_configuration='Release', process_controller=controller)
        row = report['results'][0]
        row['process_control'] = {'kind': 'posix-session', 'cleanup_complete': True, 'invocation': row['command']}
        self.assertEqual(len(transport_results(report)), 1)
        for field in ('process_controller',):
            broken = deepcopy(report);broken['provenance'].pop(field)
            with self.assertRaisesRegex(ValueError, 'controller provenance'):transport_results(broken)
        for field, value in [('cleanup_complete', False), ('invocation', ['different test']), ('kind', 'windows-job')]:
            broken = deepcopy(report);broken['results'][0]['process_control'][field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):transport_results(broken)

    def test_windows_controller_report_requires_the_exact_worker_and_owned_job(self):
        report = self.report();row = report['results'][0]
        controller = dict(process_tree.description(), kind='windows-job')
        job = 'Local\\pocx-functional-' + 'c' * 32
        report['provenance'].update(format_version=9, build_configuration='Release', process_controller=controller)
        row['process_control'] = {'kind': 'windows-job', 'cleanup_complete': True, 'job': job,
            'invocation': [controller['interpreter'], controller['path'], '--windows-worker', job, '--', *row['command']]}
        self.assertEqual(len(transport_results(report)), 1)
        for field, value in [('job', 'foreign-job'), ('job', None), ('invocation', row['command'])]:
            broken = deepcopy(report);broken['results'][0]['process_control'][field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):transport_results(broken)

    def test_all_tool_paths_and_environment_select_one_configuration(self):
        build = Path('/build')
        multi = 'CMAKE_CONFIGURATION_TYPES:STRING=Debug;Release\n'
        for platform, suffix in (('posix', ''), ('nt', '.exe')):
            with self.subTest(platform=platform), patch.object(build_configuration.os, 'name', platform):
                paths = execution.binary_paths(build, multi, 'Release')
                self.assertEqual(set(paths), set(execution.BINARY_NAMES))
                for name, path in paths.items():
                    self.assertEqual(path, build / 'bin/Release' / (name + suffix))
                environment = execution.binary_environment(paths, 'inherited-path')
                for name, variable in execution.BINARY_ENVIRONMENT.items():
                    self.assertEqual(environment[variable], str(paths[name]))
                self.assertEqual(environment['PATH'], str(build / 'bin/Release') + os.pathsep + 'inherited-path')
        with self.assertRaisesRegex(ValueError, 'require --config'):
            execution.binary_paths(build, multi)
        with self.assertRaisesRegex(ValueError, 'Unknown build configuration'):
            execution.binary_paths(build, multi, 'Unknown')

    def test_current_report_format_requires_recorded_configuration(self):
        report = self.report();report['provenance'].update(format_version=8, build_configuration='Release')
        self.assertEqual(len(transport_results(report)), 1)
        for value in ('', True, 42, []):
            report['provenance']['build_configuration'] = value
            with self.subTest(value=value), self.assertRaisesRegex(ValueError, 'build configuration'):
                transport_results(report)
        report['provenance'].pop('build_configuration')
        with self.assertRaisesRegex(ValueError, 'build configuration'):
            transport_results(report)

    def test_functional_runner_imports_without_unix_only_fcntl(self):
        original=builtins.__import__
        def load(name,*args,**kwargs):
            if name=='fcntl':raise ModuleNotFoundError('Unix module unavailable in portability fixture')
            return original(name,*args,**kwargs)
        with patch('builtins.__import__',side_effect=load):
            spec=importlib.util.spec_from_file_location('functional_lock_fixture',OWNED/'test_runner.py')
            module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)

    def report(self, arguments=None):
        case = case_spec('p2p_ping.py', arguments or [])
        flags = [*case['arguments'], *([] if '--usecli' in case['arguments'] else ['--usecli']),
                 '--timeout-factor=40', '--v1transport']
        options = execution.settings(True, True)
        return {'provenance': {'format_version': 7, 'execution_options': options, 'timeout_factor': 40,
            'environment_profile': {'previous_releases': False, 'network_addresses': False},
            'selected_tests': [case['test']], 'selected_cases': [case], 'transport_modes': ['v1'],
            'case_selection': {'selected_cases_sha256': selection_digest([case])}},
            'results': [{'test': case['test'], 'case': case['id'], 'case_arguments': case['arguments'],
                'transport': 'v1', 'execution_options': options, 'test_arguments': flags,
                'command': ['python3', case['test'], *flags], 'returncode': 0, 'timed_out': False, 'status': 'passed'}]}

    def test_cli_does_not_change_case_identity(self):
        report = self.report()
        self.assertEqual(len(transport_results(report)), 1)
        self.assertEqual(report['results'][0]['case'], 'p2p_ping.py')

    def test_existing_cli_case_is_not_duplicated(self):
        report = self.report(['--usecli'])
        self.assertEqual(report['results'][0]['command'].count('--usecli'), 1)
        self.assertEqual(len(transport_results(report)), 1)

    def test_missing_cli_flag_rejects_a_green_result(self):
        report = self.report()
        for field in ('command', 'test_arguments'): report['results'][0][field].remove('--usecli')
        with self.assertRaises(ValueError): transport_results(report)

    def test_missing_malformed_or_unknown_settings_rejected(self):
        for value in (None, {}, {'use_cli': True}, {'use_cli': 1, 'multiprocess': False},
                      {'use_cli': True, 'multiprocess': False, 'other': True}):
            report = self.report();report['provenance']['execution_options'] = value
            with self.subTest(value=value), self.assertRaises(ValueError): transport_results(report)

    def test_changed_row_settings_rejected(self):
        report = deepcopy(self.report());report['results'][0]['execution_options']['multiprocess'] = False
        report['provenance']['execution_options'] = execution.settings(True, True)
        with self.assertRaises(ValueError): transport_results(report)

    def test_legacy_reports_cannot_claim_new_modes(self):
        report = self.report();report['provenance']['format_version'] = 6
        with self.assertRaisesRegex(ValueError, 'unrecorded'): transport_results(report)

    def test_multiprocess_binds_the_built_wrapper_and_node(self):
        provenance = self.report()['provenance']
        binaries = {'bitcoin': Path('/build/bin/bitcoin'), 'bitcoin-node': Path('/build/bin/bitcoin-node')}
        self.assertEqual(execution.environment(provenance, binaries, {'ENABLE_IPC': 'ON'}),
                         {'BITCOIN_CMD': '/build/bin/bitcoin -m'})
        for missing in ('bitcoin', 'bitcoin-node'):
            with self.subTest(missing=missing), self.assertRaises(ValueError):
                execution.environment(provenance, {k:v for k,v in binaries.items() if k != missing}, {'ENABLE_IPC': 'ON'})
        with self.assertRaises(ValueError): execution.environment(provenance, binaries, {'ENABLE_IPC': 'OFF'})


if __name__ == '__main__':
    unittest.main()
