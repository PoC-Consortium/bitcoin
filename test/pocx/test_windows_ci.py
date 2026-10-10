#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin PoCX developers
# Distributed under the MIT software license; see COPYING.
"""Native Windows recipe checks; callbacks never establish Windows coverage."""
import ast
import contextlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from common import ROOT, sha256
import inherited_ci
import windows_ci as windows


class WindowsCITest(unittest.TestCase):
    def fixture(self, directory):
        root = Path(directory)
        original = root / '.github/ci-windows.py'
        original.parent.mkdir()
        original.write_bytes((ROOT / '.github/ci-windows.py').read_bytes())
        for name in ('CMakeLists.txt', 'CMakePresets.json', '.github/workflows/pocx-tests.yml'):
            path = root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text('fixture source only\n')
        for consensus in ('bitcoin', 'pocx'):
            release = windows.build_directory(consensus, root) / 'bin/Release'
            release.mkdir(parents=True)
            for name in ('bitcoind.exe', 'bitcoin-cli.exe', 'test_bitcoin.exe',
                         'bench_bitcoin.exe', 'test_bitcoin-qt.exe', 'bitcoin-chainstate.exe', 'fuzz.exe'):
                (release / name).write_text('placeholder; never executed\n')
            if consensus == 'pocx':
                (release / 'test_pocx.exe').write_text('placeholder; never executed\n')
        return root

    def test_original_recipe_options_and_manifest_exemptions_preserved(self):
        self.assertEqual(sha256(ROOT / '.github/ci-windows.py'), windows.UPSTREAM_RECIPE_SHA256)
        self.assertEqual(windows.upstream_options(), ['-DBUILD_BENCH=ON', '-DBUILD_KERNEL_LIB=ON',
            '-DBUILD_UTIL_CHAINSTATE=ON', '-DCMAKE_COMPILE_WARNING_AS_ERROR=ON'])
        tree = ast.parse((ROOT / '.github/ci-windows.py').read_text())
        function = next(node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == 'check_manifests')
        skips = next(node.value for node in ast.walk(function) if isinstance(node, ast.Assign) and
                     any(isinstance(target, ast.Name) and target.id == 'skips' for target in node.targets))
        self.assertEqual(windows.MANIFEST_SKIPS, ast.literal_eval(skips))

    def test_pair_selects_distinct_builds_and_preserves_functional_settings(self):
        env = {'TEST_RUNNER_EXTRA': '--timeout-factor=40 --extended', 'VCPKG_ROOT': 'fixture-vcpkg'}
        pairs = windows.plan(3, env)
        self.assertEqual([row['consensus'] for row in pairs], ['bitcoin', 'pocx'])
        for row, enabled in zip(pairs, ('OFF', 'ON')):
            command = windows.configure_command(row['consensus'])
            self.assertIn('--preset', command)
            self.assertIn('vs2026', command)
            self.assertEqual(command[-3:], ['-DENABLE_POCX=' + enabled,
                '-DBUILD_FUZZ_BINARY=OFF', '-DBUILD_FOR_FUZZING=OFF'])
            self.assertEqual(row['environment']['TEST_RUNNER_EXTRA'], env['TEST_RUNNER_EXTRA'])
            self.assertEqual(row['environment']['VCPKG_ROOT'], env['VCPKG_ROOT'])
        self.assertNotEqual(pairs[0]['environment']['BASE_BUILD_DIR'], pairs[1]['environment']['BASE_BUILD_DIR'])

    def test_invalid_jobs_fuzz_and_timeout_settings_rejected_before_execution(self):
        for count in (0, -1, True, 1.5):
            with self.subTest(count=count), self.assertRaises(ValueError):
                windows.plan(count, {})
        for env in ({'RUN_FUZZ_TESTS': 'true'}, {'TEST_RUNNER_EXTRA': '--timeout-factor=nan'},
                    *({'TEST_RUNNER_TIMEOUT_FACTOR': value} for value in ('bad', '0', '-1', 'nan', 'inf', '1e308'))):
            with self.subTest(env=env), self.assertRaises(ValueError):
                windows.plan(2, env)

    def phase(self, root, consensus, *, configure_codes=(0,), build_codes=(0,), failure=None):
        calls, sleeps, provisioned = [], [], []
        configs, builds = iter(configure_codes), iter(build_codes)
        def run(command, **kwargs):
            calls.append((list(command), dict(kwargs['env'])))
            self.assertEqual(kwargs['cwd'], root)
            code = 0
            if command[0] == 'cmake':
                code = next(builds if '--build' in command else configs)
            elif command[0] == 'mt.exe' and command[-1].startswith('-out:'):
                Path(command[-1][5:]).write_text('<assembly/>\n')
            if failure and failure(command):
                code = 9
            return subprocess.CompletedProcess(command, code)
        def provision(directory):
            provisioned.append(directory)
            return {'directory': str(directory), 'scope': 'fake pinned assets, never downloaded'}
        with contextlib.redirect_stdout(io.StringIO()):
            windows.run_phase(consensus, 3, root=root, environment={'TEST_RUNNER_TIMEOUT_FACTOR': '40'},
                             run=run, sleep=sleeps.append, provision=provision)
        return calls, sleeps, provisioned

    def test_release_phase_preserves_manifests_assets_and_strict_dispatch(self):
        with tempfile.TemporaryDirectory() as directory:
            root = self.fixture(directory)
            for consensus in ('bitcoin', 'pocx'):
                calls, sleeps, provisioned = self.phase(root, consensus)
                self.assertEqual(sleeps, [])
                self.assertEqual(provisioned, [root / 'unit_test_data'])
                manifest = [cmd for cmd, _ in calls if cmd[0] == 'mt.exe' and '-validate_manifest' in cmd]
                names = {Path(cmd[2].removeprefix('-inputresource:')).name for cmd in manifest}
                self.assertEqual(names, {'bitcoind.exe', 'bitcoin-cli.exe', 'test_bitcoin.exe'} |
                                 ({'test_pocx.exe'} if consensus == 'pocx' else set()))
                runtime = [(cmd, env) for cmd, env in calls if any(arg.endswith('/inherited_tests.py') for arg in cmd)]
                self.assertEqual([cmd[cmd.index('--phase') + 1] for cmd, _ in runtime], ['ctest', 'functional'])
                for cmd, env in runtime:
                    self.assertEqual(cmd[cmd.index('--config') + 1], 'Release')
                    self.assertEqual(cmd[cmd.index('--build-dir') + 1], str(windows.build_directory(consensus, root)))
                    self.assertEqual(env['DIR_UNIT_TEST_DATA'], str(root / 'unit_test_data'))
                self.assertEqual(runtime[0][0][-2:], ['--timeout', '2400'])
                self.assertEqual(runtime[1][0][-2:], ['--timeout-factor', '40'])
                lifecycle = [cmd for cmd, _ in calls if any(arg.endswith('/test_process_tree.py') for arg in cmd)]
                self.assertEqual(len(lifecycle), 1 if consensus == 'bitcoin' else 0)
                if lifecycle:
                    self.assertLess([cmd for cmd, _ in calls].index(lifecycle[0]), [cmd for cmd, _ in calls].index(runtime[0][0]))

    def test_upstream_generation_retry_and_verbose_build_fallback(self):
        with tempfile.TemporaryDirectory() as directory:
            root = self.fixture(directory)
            calls, sleeps, _ = self.phase(root, 'bitcoin', configure_codes=(1, 0), build_codes=(1, 0))
            self.assertEqual(sleeps, [12])
            configurations = [cmd for cmd, _ in calls if cmd[0] == 'cmake' and '--build' not in cmd]
            self.assertEqual(configurations, [windows.configure_command('bitcoin', root)] * 2)
            builds = [cmd for cmd, _ in calls if '--build' in cmd]
            self.assertEqual(builds[0][-2:], ['-j', '3'])
            self.assertEqual(builds[1][-2:], ['-j1', '--verbose'])

    def test_second_generate_build_manifest_and_runtime_failure_abort(self):
        with tempfile.TemporaryDirectory() as directory:
            root = self.fixture(directory)
            for kwargs in ({'configure_codes': (1, 2)}, {'build_codes': (1, 2)},
                           {'failure': lambda cmd: cmd[0] == 'mt.exe'},
                           {'failure': lambda cmd: '--phase' in cmd and 'ctest' in cmd},
                           {'failure': lambda cmd: any(arg.endswith('/test_process_tree.py') for arg in cmd)}):
                with self.subTest(kwargs=kwargs), self.assertRaises(subprocess.CalledProcessError):
                    self.phase(root, 'bitcoin', **kwargs)

    def test_baseline_failure_gates_native_and_retains_failed_case_evidence(self):
        with tempfile.TemporaryDirectory() as directory:
            root = self.fixture(directory)
            pairs = windows.plan(2, {}, root)
            calls = []
            def run(command, **kwargs):
                calls.append(command)
                child = Path(kwargs['env']['BASE_BUILD_DIR']) / 'bitcoin-unit-fixture'
                child.mkdir()
                (child / 'cases.csv').write_text('case,status\nfixture,failed\n')
                return subprocess.CompletedProcess(command, 8)
            output = root / 'pocx-inherited-windows-fixture/execution'
            with self.assertRaisesRegex(ValueError, 'bitcoin inherited CI recipe failed'):
                inherited_ci.execute_and_publish(pairs, output, root=root, run=run)
            self.assertEqual(calls, [pairs[0]['command']])
            published = root / 'artifacts/pocx-inherited/pocx-inherited-windows-fixture'
            report = json.loads((published / 'results.json').read_text())
            self.assertEqual(report['native_execution'], 'deferred')
            self.assertEqual(report['status'], 'failed')
            self.assertTrue((published / 'bitcoin-evidence/bitcoin-unit-fixture/cases.csv').is_file())

    def test_recipe_review_and_workflow_wiring(self):
        review = windows.verify_recipe()
        self.assertEqual(review['execution_status'], 'unverified; no actual native Windows execution recorded')
        original = windows.sha256
        for name in ('.github/ci-windows.py', 'test/pocx/windows_ci.py', '.github/workflows/ci.yml'):
            with self.subTest(name=name), patch.object(windows, 'sha256', side_effect=lambda path:
                    '0' * 64 if path == ROOT / name else original(path)):
                with self.assertRaisesRegex(ValueError, 'changed without review'):
                    windows.verify_recipe()
        workflow = (ROOT / '.github/workflows/ci.yml').read_text()
        job = workflow.split('  windows-native-dll:\n', 1)[1].split('  record-frozen-commit:\n', 1)[0]
        self.assertIn('py -3 test/pocx/windows_ci.py', job)
        self.assertIn('py -3 .github/ci-windows.py "standard" github_import_vs_env', job)
        self.assertNotIn('${{ matrix.job-type }} run_tests', job)
        self.assertIn("GIT_CONFIG_VALUE_0: 'false'", job)
        self.assertIn('if: always()', job)
        self.assertIn('path: artifacts/pocx-inherited', job)
        self.assertIn("case(github.event_name == 'pull_request', '', '--extended')", job)

    def test_readonly_plan_and_non_windows_execution_guard(self):
        env = dict(os.environ)
        for key in ('RUN_FUZZ_TESTS', 'TEST_RUNNER_EXTRA', 'TEST_RUNNER_TIMEOUT_FACTOR'):
            env.pop(key, None)
        before = {path.name for path in ROOT.iterdir()}
        result = subprocess.run([sys.executable, str(ROOT / 'test/pocx/windows_ci.py'), '--plan', '--jobs', '2'],
                                cwd=ROOT, env=env, text=True, capture_output=True, check=True)
        report = json.loads(result.stdout)
        self.assertEqual(report['status'], 'configured only; not executed')
        self.assertEqual([row['consensus'] for row in report['phases']], ['bitcoin', 'pocx'])
        self.assertEqual(before, {path.name for path in ROOT.iterdir()})
        if os.name != 'nt':
            result = subprocess.run([sys.executable, str(ROOT / 'test/pocx/windows_ci.py'), '--jobs', '2'],
                                    cwd=ROOT, env=env, text=True, capture_output=True)
            self.assertEqual(result.returncode, 2)
            self.assertIn('requires a Windows host', result.stderr)
            self.assertEqual(before, {path.name for path in ROOT.iterdir()})


if __name__ == '__main__':
    unittest.main()
