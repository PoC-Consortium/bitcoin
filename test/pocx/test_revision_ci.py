#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin PoCX developers
# Distributed under the MIT software license; see COPYING.
"""Ancestor CI wiring and failure checks; fake commands are not suite evidence."""
import ast
from contextlib import redirect_stdout, redirect_stderr
import io
import json
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from common import ROOT, sha256
import inherited_ci
import revision_ci


class RevisionTest(unittest.TestCase):
    def test_configure_preserves_unchanged_upstream_recipe_flags(self):
        source = ROOT / '.github/ci-test-each-commit-exec.py'
        self.assertEqual(sha256(source), inherited_ci.UPSTREAM_REVISION_RECIPE_SHA256)
        tree = ast.parse(source.read_text())
        commands = [node.args[0].elts for node in ast.walk(tree)
                    if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == 'run'
                    and node.args and isinstance(node.args[0], ast.List)
                    and isinstance(node.args[0].elts[0], ast.Constant)
                    and node.args[0].elts[0].value == 'cmake']
        original = next(command for command in commands if ast.literal_eval(command[1]) == '-B')
        for consensus, mode in [('bitcoin', 'OFF'), ('pocx', 'ON')]:
            build = revision_ci.build_directory(consensus)
            expected = [str(build) if isinstance(item, ast.Name) and item.id == 'build_dir'
                        else ast.literal_eval(item) for item in original]
            actual = revision_ci.configure_command(build, consensus)
            self.assertEqual(actual, [*expected, '-DENABLE_POCX=' + mode,
                                     '-DBUILD_FUZZ_BINARY=OFF', '-DBUILD_FOR_FUZZING=OFF'])

    def test_plan_is_original_first_with_isolated_builds_and_preserved_environment(self):
        pair = revision_ci.plan(4, {'TEST_RUNNER_PORT_MIN': '14000'})
        self.assertEqual([row['consensus'] for row in pair], ['bitcoin', 'pocx'])
        self.assertNotEqual(pair[0]['environment']['BASE_BUILD_DIR'], pair[1]['environment']['BASE_BUILD_DIR'])
        self.assertEqual(pair[1]['environment']['BASE_BUILD_DIR'], str(ROOT / 'ci_build'))
        for row in pair:
            self.assertEqual(row['environment']['TEST_RUNNER_PORT_MIN'], '14000')
            self.assertEqual(row['command'][-2:], ['--jobs', '4'])

    def test_invalid_jobs_consensus_and_fuzz_rejected(self):
        for count in (0, -1, True, 2.5, '4'):
            with self.subTest(count=count), self.assertRaises(ValueError):
                revision_ci.plan(count, {})
        with self.assertRaises(ValueError):
            revision_ci.plan(4, {'RUN_FUZZ_TESTS': 'true'})
        with self.assertRaises(ValueError):
            revision_ci.build_directory('unknown')
        with self.assertRaises(ValueError):
            revision_ci.configure_command(ROOT/'ci_build', 'unknown')

    def phase(self, codes):
        commands = []
        def run(command, **kwargs):
            commands.append(command)
            return subprocess.CompletedProcess(command, codes[len(commands) - 1])
        with redirect_stdout(io.StringIO()):
            try:
                revision_ci.run_phase('bitcoin', 4, run=run)
            except subprocess.CalledProcessError:
                pass
        return commands

    def test_phase_uses_strict_ctest_then_full_functional_runtime(self):
        commands = self.phase([0, 0, 0, 0])
        self.assertEqual(len(commands), 4)
        self.assertIn('--phase', commands[2])
        self.assertIn('ctest', commands[2])
        self.assertEqual(commands[2][-2:], ['--timeout', '180'])
        self.assertIn('functional', commands[3])
        self.assertIn('inherited_tests.py', commands[3][1])
        self.assertEqual(commands[3][-4:], ['--jobs', '8', '--timeout-factor', '1'])

    def test_configure_failure_stops_build_and_runtime(self):
        self.assertEqual(len(self.phase([7])), 1)

    def test_parallel_build_failure_preserves_upstream_verbose_fallback(self):
        commands = self.phase([0, 7, 0, 0, 0])
        self.assertEqual(commands[2], ['cmake', '--build', str(ROOT/'ci_build-bitcoin-baseline'), '-j1', '--verbose'])
        self.assertEqual(len(commands), 5)
        self.assertEqual(len(self.phase([0, 7, 8])), 3)

    def test_failed_ctest_never_launches_functional(self):
        self.assertEqual(len(self.phase([0, 0, 7])), 3)

    def test_actual_workflow_routes_revision_job_and_uploads_failure_evidence(self):
        workflow = (ROOT/'.github/workflows/ci.yml').read_text()
        job = re.search(r'^  test-each-commit:\n(.*?)(?=^  [\w-]+:)', workflow, re.M | re.S)[1]
        self.assertIn('.ci-venv/bin/python ./test/pocx/revision_ci.py && git reset --hard', job)
        self.assertNotIn('python3 ./.github/ci-test-each-commit-exec.py', job)
        self.assertIn('python3-bpfcc bpfcc-tools "linux-headers-$(uname -r)"', job)
        self.assertIn('sudo env GIT_CONFIG_COUNT=1 GIT_CONFIG_KEY_0=safe.directory', job)
        self.assertIn('.ci-venv/bin/pip install pycapnp==2.2.4', job)
        self.assertIn('if: always()\n        uses: actions/upload-artifact@v7', job)
        self.assertIn('path: artifacts/pocx-inherited', job)

    def test_readonly_cli_plan_describes_both_builds_without_running_them(self):
        before = set(ROOT.iterdir())
        result = subprocess.run([sys.executable, str(ROOT/'test/pocx/revision_ci.py'), '--plan', '--jobs', '4'],
                                cwd=ROOT, capture_output=True, text=True, check=True)
        data = json.loads(result.stdout)
        self.assertEqual(data['status'], 'configured only; not executed')
        self.assertEqual([row['consensus'] for row in data['phases']], ['bitcoin', 'pocx'])
        self.assertEqual(set(ROOT.iterdir()), before)

    def test_failed_original_phase_is_published_without_native_launch(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            output=root/'pocx-inherited-fixture/execution'
            calls=[]
            def run(command, **kwargs):
                calls.append(command)
                return subprocess.CompletedProcess(command,7)
            with patch.object(inherited_ci, 'source_snapshot', return_value={}), redirect_stdout(io.StringIO()):
                with self.assertRaises(ValueError):
                    inherited_ci.execute_and_publish(revision_ci.plan(4,{},root), output, root=root, run=run)
            self.assertEqual(len(calls),1)
            report=json.loads((root/'artifacts/pocx-inherited/pocx-inherited-fixture/results.json').read_text())
            self.assertEqual(report['status'],'failed')
            self.assertEqual(report['native_execution'],'deferred')

    def test_publication_failure_cannot_turn_success_green_or_hide_original_failure(self):
        for code, expected in [(0, OSError), (7, ValueError)]:
            with self.subTest(code=code), tempfile.TemporaryDirectory() as directory:
                root=Path(directory)
                output=root/'pocx-inherited-fixture/execution'
                with patch.object(inherited_ci,'source_snapshot',return_value={}), \
                     patch.object(inherited_ci,'publish',side_effect=OSError('copy failed')), \
                     redirect_stderr(io.StringIO()), self.assertRaises(expected):
                    inherited_ci.execute_and_publish(revision_ci.plan(4,{},root), output, root=root,
                        run=lambda command,**_kw:subprocess.CompletedProcess(command,code))

    def test_source_mutation_stops_native_phase(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            output=root/'pocx-inherited-fixture/execution'
            calls=[]
            def run(command, **kwargs):
                calls.append(command)
                return subprocess.CompletedProcess(command,0)
            with patch.object(inherited_ci,'source_snapshot',side_effect=[{}, {'changed':'hash'}]), \
                 redirect_stdout(io.StringIO()), self.assertRaisesRegex(ValueError,'Source inputs changed'):
                inherited_ci.execute_and_publish(revision_ci.plan(4,{},root),output,root=root,run=run)
            self.assertEqual(len(calls),1)


if __name__ == '__main__':
    unittest.main()
