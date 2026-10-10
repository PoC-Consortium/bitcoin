#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin PoCX developers
# Distributed under the MIT software license; see COPYING.
"""RPC coverage infrastructure checks; synthetic scripts are not domain tests."""
from contextlib import redirect_stdout
from copy import deepcopy
import importlib.util
import io
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

from common import OWNED, sha256
from functional_results import transport_results
import inherited_functional
import rpc_coverage
import verify_functional


class CoverageTest(unittest.TestCase):
    def report(self, root, *, uncovered=False):
        results = []
        records = {}
        for mode in ('v1', 'v2'):
            directory = root / mode / 'rpc-coverage'
            directory.mkdir(parents=True)
            (directory / 'rpc_interface.txt').write_text('generate\ngetblockcount\n' + ('missingrpc\n' if uncovered else ''))
            (directory / 'coverage.123.node0').write_text('getblockcount\n')
            records[mode] = rpc_coverage.evaluate(directory, os.environ)
            results.append({'transport': mode, 'log': str(directory.parent / 'case.log')})
        return {'provenance': {'format_version': 10, 'rpc_coverage': True, 'transport_modes': ['v1', 'v2'],
                              'rpc_coverage_helper_sha256': sha256(Path(rpc_coverage.__file__))},
                'results': results, 'rpc_coverage': records}

    def test_actual_upstream_evaluator_and_raw_mutation_detection(self):
        with tempfile.TemporaryDirectory() as tmp:
            report = self.report(Path(tmp))
            self.assertTrue(rpc_coverage.verify(report))
            for mode in ('v1', 'v2'):
                self.assertEqual(report['rpc_coverage'][mode]['returncode'], 0)
                self.assertIn('All RPC commands covered.', Path(report['rpc_coverage'][mode]['log']).read_text())
            for mutation in ('record', 'mode', 'source', 'uncovered'):
                broken = deepcopy(report)
                if mutation == 'record': broken['rpc_coverage']['v1']['files'] = {}
                if mutation == 'mode': broken['rpc_coverage'].pop('v2')
                if mutation == 'source': broken['rpc_coverage']['v1']['source_sha256'] = '0' * 64
                if mutation == 'uncovered': broken['rpc_coverage']['v1']['uncovered'] = ['made-up']
                with self.subTest(mutation=mutation), self.assertRaises(ValueError): rpc_coverage.verify(broken)
            (Path(tmp) / 'v2/rpc-coverage/coverage.123.node0').write_text('altered\n')
            with self.assertRaises(ValueError): rpc_coverage.verify(report)

    def test_uncovered_rpc_is_a_failed_gate_even_when_cases_pass(self):
        with tempfile.TemporaryDirectory() as tmp:
            report = self.report(Path(tmp), uncovered=True)
            self.assertFalse(rpc_coverage.verify(report))
            self.assertEqual(report['rpc_coverage']['v1']['uncovered'], ['missingrpc'])
            # Isolate the coverage gate from case membership checks here.
            with patch.object(verify_functional, 'transport_results', return_value=[]):
                with self.assertRaisesRegex(ValueError, 'uncovered commands'):
                    verify_functional.verify(report, [], ['v1', 'v2'], {}, {})

    def test_missing_empty_and_symlinked_inputs_fail(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            with self.assertRaisesRegex(ValueError, 'Missing.*reference'): rpc_coverage.inputs(directory)
            (directory / 'rpc_interface.txt').write_text('')
            with self.assertRaisesRegex(ValueError, 'Empty'): rpc_coverage.inputs(directory)
            (directory / 'rpc_interface.txt').write_text('generate\n')
            (directory / 'coverage.1').symlink_to(directory / 'rpc_interface.txt')
            with self.assertRaisesRegex(ValueError, 'symlinks'): rpc_coverage.inputs(directory)

    def test_historical_proof_cannot_claim_rpc_coverage(self):
        for report in ({'provenance': {'format_version': 9, 'rpc_coverage': True}},
                       {'provenance': {'format_version': 9}, 'rpc_coverage': {}}):
            with self.assertRaisesRegex(ValueError, 'unrecorded'): rpc_coverage.verify(report)

    def test_previous_release_arguments_preserve_coverage_and_extend_slow_case(self):
        for exclusion in ('--exclude feature_dbcrash', '--exclude=feature_dbcrash'):
            profile = inherited_functional.inherited_options({'TEST_RUNNER_EXTRA':
                '--previous-releases --coverage --extended ' + exclusion})
            self.assertTrue(profile['coverage'])
            self.assertEqual(profile['selection_extensions'], ['feature_dbcrash.py'])
            original = inherited_functional.original_command(Path('/build'), Path('/out'),
                ('complete', [], False), 'v1', 4, 40, profile)
            native = inherited_functional.native_command(Path('/build'), 4, 40, profile,
                {'PREVIOUS_RELEASES_DIR': '/releases'})
            for command in (original, native):
                self.assertIn('--coverage', command)
                self.assertFalse(any(arg.startswith('--exclude') for arg in command))
        for exclusion in ('--exclude wallet_basic', '--exclude=wallet_basic', '--exclude'):
            with self.assertRaises(ValueError): inherited_functional.inherited_options({'TEST_RUNNER_EXTRA': exclusion})

    def test_actual_owned_dispatch_retains_separate_transport_coverage(self):
        spec = importlib.util.spec_from_file_location('coverage_dispatch_fixture', OWNED / 'test_runner.py')
        runner = importlib.util.module_from_spec(spec); spec.loader.exec_module(runner)
        with tempfile.TemporaryDirectory() as tmp:
            build = Path(tmp); tree = build / 'staged'; framework = tree / 'test_framework'
            framework.mkdir(parents=True); (build / 'bin').mkdir()
            for name in ('__init__.py', 'test_framework.py'): (framework / name).write_text('')
            (framework / 'util.py').write_text('MAX_NODES = 12\nPORT_RANGE = 5000\n')
            (build / 'CMakeCache.txt').write_text('ENABLE_POCX:BOOL=ON\n')
            for name in ('bitcoind', 'bitcoin-cli'): (build / 'bin' / name).write_bytes(b'never executed')
            (tree / 'p2p_ping.py').write_text('''import pathlib, sys
directory = pathlib.Path(next(arg.split('=', 1)[1] for arg in sys.argv if arg.startswith('--coveragedir=')))
(directory / 'rpc_interface.txt').write_text('generate\\ngetblockcount\\n')
(directory / 'coverage.123.node0').write_text('getblockcount\\n')
''')
            manifest = {'tests': {'p2p_ping.py': 'synthetic'}, 'reused_tests': []}
            provenance = {'build_configuration': None, 'build_options': {'ENABLE_POCX': 'ON'}}
            with patch.object(runner, 'stage', return_value=(tree, manifest, provenance)), \
                 patch.object(sys, 'argv', ['runner', '--build-dir', str(build), '--transport', 'matrix',
                     '--coverage', '--jobs', '2', '--timeout', '10']), redirect_stdout(io.StringIO()):
                self.assertEqual(runner.main(), 0)
            report = json.loads(next(build.glob('pocx-results-*/results.json')).read_text())
            self.assertEqual(len(transport_results(report)), 2)
            self.assertTrue(rpc_coverage.verify(report))
            directories = {row['directory'] for row in report['rpc_coverage'].values()}
            self.assertEqual(len(directories), 2)
            broken = deepcopy(report)
            broken['results'][0]['test_arguments'] = [arg for arg in broken['results'][0]['test_arguments']
                                                     if not arg.startswith('--coveragedir=')]
            with self.assertRaises(ValueError): transport_results(broken)
            evaluate = rpc_coverage.evaluate
            def leave_uncovered(directory, environment):
                reference = directory / 'rpc_interface.txt'
                reference.write_text(reference.read_text() + 'missingrpc\n')
                return evaluate(directory, environment)
            with patch.object(runner, 'stage', return_value=(tree, manifest, provenance)), \
                 patch.object(rpc_coverage, 'evaluate', side_effect=leave_uncovered), \
                 patch.object(sys, 'argv', ['runner', '--build-dir', str(build), '--transport', 'matrix',
                     '--coverage', '--jobs', '2', '--timeout', '10']), redirect_stdout(io.StringIO()):
                self.assertEqual(runner.main(), 1)
            reports = [json.loads(path.read_text()) for path in build.glob('pocx-results-*/results.json')]
            failed = next(row for row in reports if row['rpc_coverage']['v1']['returncode'] == 1)
            self.assertTrue(all(row['status'] == 'passed' for row in failed['results']))
            self.assertEqual(len(transport_results(failed)), 2)
            with self.assertRaisesRegex(ValueError, 'uncovered commands'):
                verify_functional.verify(failed, failed['provenance']['selected_cases'], ['v1', 'v2'], {}, {})


if __name__ == '__main__':
    unittest.main()
