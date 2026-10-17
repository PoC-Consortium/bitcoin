#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin PoCX developers
# Distributed under the MIT software license; see COPYING.
"""Upstream scope equivalence and actual dispatcher contracts; no domain pass claims."""
import ast
from contextlib import redirect_stdout
from copy import deepcopy
import importlib.util
import io
import json
from pathlib import Path
import shlex
import sys
import tempfile
import unittest
from unittest.mock import patch

from common import ROOT
from functional_cases import upstream_cases
from functional_results import transport_results
import inherited_functional
import inherited_selection
import inherited_prerequisites
import rpc_coverage
import verify_functional


class InheritedSelectionTest(unittest.TestCase):
    def scopes(self):
        for extra in ('', '--extended', '--v2transport', '--extended --v1transport',
                      '--extended --v2transport', '--v1transport --v2transport',
                      '--previous-releases --coverage --extended --exclude feature_dbcrash'):
            yield inherited_functional.inherited_options({'TEST_RUNNER_EXTRA': extra})['case_selection']

    def original_lists(self):
        # Independently read the original declarations: do not use the native
        # selection helper to calculate the expected original execution pairs.
        constants = {}
        for node in ast.parse((ROOT / 'test/functional/test_runner.py').read_text()).body:
            if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
                if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
                    constants[node.targets[0].id] = node.value.value
                elif node.targets[0].id in ('BASE_SCRIPTS', 'EXTENDED_SCRIPTS'):
                    constants[node.targets[0].id] = [constants[value.id] if isinstance(value, ast.Name)
                        else ast.literal_eval(value) for value in node.value.elts]
        return constants

    def test_native_projection_matches_original_cases_and_effective_transports(self):
        original = self.original_lists()
        rows = upstream_cases(ROOT / 'test/functional/test_runner.py')
        manifest = json.loads((ROOT / 'test/pocx/manifest.json').read_text())
        original_tests = {row['test'] for row in rows}
        additions = (set(manifest['tests']) | set(manifest['reused_tests'])) - original_tests
        self.assertTrue(additions, 'Fixture must exercise actual PoCX-only additions')
        for scope in self.scopes():
            with self.subTest(scope=scope):
                declared = original['BASE_SCRIPTS'] + (original['EXTENDED_SCRIPTS'] if scope['extended'] else [])
                expected = set()
                for case in declared:
                    name, *arguments = shlex.split(case)
                    if name in manifest['excluded_tests'] or name in scope['excluded']:
                        continue
                    flags = [*arguments, *scope['transport_flags']]
                    mode = 'v1' if '--v1transport' in flags or '--v2transport' not in flags else 'v2'
                    identity = shlex.join([name, *[flag for flag in arguments if flag not in ('--v1transport', '--v2transport')]])
                    expected.add((identity, mode))
                selection, mapping, _ = inherited_selection.native_selection(manifest, rows, scope)
                actual = {(case['id'], mode) for case in selection if case['test'] in original_tests
                          for mode in mapping[case['id']]}
                self.assertEqual(actual, expected)
                self.assertEqual({case['test'] for case in selection} - original_tests, additions)

    def test_original_scope_keeps_dynamic_benchmarks_and_reviewed_exclusions(self):
        source = ROOT / 'test/functional/test_runner.py'
        for scope in self.scopes():
            expected = inherited_functional.original_inventory(source, ['BenchOne', 'BenchTwo'], True, scope)
            self.assertEqual(any(case.startswith('feature_dbcrash.py') for case in expected),
                             scope['extended'] and not scope['excluded'])
            self.assertEqual(sum(case.startswith('tool_bench_sanity_check.py --bench=') for case in expected), 2)
            profile = inherited_functional.inherited_options({})
            profile['case_selection'] = scope
            command = inherited_functional.original_command(ROOT / 'build', ROOT / 'out',
                ('complete', expected, False), 'v1', 2, 40, profile)
            self.assertEqual('--extended' in command, scope['extended'])
            self.assertEqual([flag for flag in command if flag in ('--v1transport', '--v2transport')],
                             scope['transport_flags'])
            self.assertEqual([flag for flag in command if flag.startswith('--exclude=')],
                             ['--exclude=' + name for name in scope['excluded']])

    def test_invalid_scope_and_unreviewed_exclusions_are_rejected(self):
        good = {'extended': False, 'excluded': [], 'transport_flags': []}
        for change in ({'extended': 1}, {'excluded': ['wallet_basic.py']},
                       {'transport_flags': ['--v3transport']}, {'unknown': True},
                       {'transport_flags': ['--v1transport', '--v1transport']}):
            with self.subTest(change=change), self.assertRaises(ValueError):
                inherited_selection.validate(dict(good, **change))

    def test_original_optional_dependencies_remain_skips_and_required_ones_fail(self):
        for case, module, optional, required, options in (
                ('interface_usdt_mempool.py', 'bcc', 'ci_arm_linux', 'ci_native_asan',
                 {'target_system': 'Linux', 'WITH_USDT': 'ON'}),
                ('interface_ipc.py', 'capnp', 'ci_native_previous_releases', 'ci_native_msan',
                 {'target_system': 'Linux', 'ENABLE_IPC': 'ON'}),
                ('interface_zmq.py', 'zmq', 'ci_i686_no_multiprocess', 'ci_native_tsan',
                 {'target_system': 'Linux', 'WITH_ZMQ': 'ON'})):
            for native in (False, True):
                for recipe in (optional, required, 'unknown'):
                    profile = inherited_functional.inherited_options({'CONTAINER_NAME': recipe})
                    with self.subTest(case=case, recipe=recipe, native=native), \
                            patch.object(inherited_prerequisites, 'available', return_value=False):
                        state, reason = inherited_functional.classify(case, 'Skipped', options, profile, native=native)
                        self.assertEqual(state, 'upstream-optional-skip' if recipe == optional else 'unverified')
                        if recipe == optional:
                            self.assertIn(module, reason)
                    with patch.object(inherited_prerequisites, 'available', return_value=True):
                        self.assertEqual(inherited_functional.classify(case, 'Skipped', options,
                                                                     profile, native=native)[0], 'unverified')
        profile = inherited_functional.inherited_options({'CONTAINER_NAME': 'ci_arm_linux'})
        with patch.object(inherited_prerequisites, 'available', return_value=False):
            self.assertEqual(inherited_functional.classify('wallet_basic.py', 'Skipped',
                             {'ENABLE_WALLET': 'ON'}, profile)[0], 'unverified')
            self.assertEqual(inherited_functional.classify('interface_ipc.py', 'Failed',
                             {'ENABLE_IPC': 'ON'}, profile)[0], 'failed')

    def dispatcher(self, root, *, coverage):
        spec = importlib.util.spec_from_file_location('inherited_dispatch_fixture', ROOT / 'test/pocx/test_runner.py')
        runner = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(runner)
        tree = root / 'staged'
        framework = tree / 'test_framework'
        framework.mkdir(parents=True)
        (root / 'bin').mkdir()
        for name in ('__init__.py', 'test_framework.py'):
            (framework / name).write_text('')
        (framework / 'util.py').write_text('MAX_NODES=12\nPORT_RANGE=5000\n')
        (root / 'CMakeCache.txt').write_text('ENABLE_POCX:BOOL=ON\n')
        for name in ('bitcoind', 'bitcoin-cli'):
            (root / 'bin' / name).write_bytes(b'synthetic inventory, never executed')
        names = ['p2p_ping.py', 'p2p_handshake.py', 'feature_pocx_owned.py', 'feature_dbcrash.py']
        for name in names:
            (tree / name).write_text('''import os,pathlib,sys
coverage = next((arg.split('=',1)[1] for arg in sys.argv if arg.startswith('--coveragedir=')), None)
if coverage:
    directory=pathlib.Path(coverage)
    (directory/'rpc_interface.txt').write_text('generate\\npingrpc\\nhandshakerpc\\nownedrpc\\n')
    command={'p2p_ping.py':'pingrpc','p2p_handshake.py':'handshakerpc','feature_pocx_owned.py':'ownedrpc'}[pathlib.Path(__file__).name]
    (directory/('coverage.'+str(os.getpid())+'.node0')).write_text(command+'\\n')
''')
        manifest = {'tests': dict.fromkeys(names, 'synthetic'), 'reused_tests': []}
        provenance = {'build_configuration': None, 'build_options': {'ENABLE_POCX': 'ON'}}
        scope = {'extended': True, 'excluded': ['feature_dbcrash.py'], 'transport_flags': []}
        command = ['runner', '--build-dir', str(root), '--jobs', '2', '--timeout', '10',
                   '--inherited-selection', json.dumps(scope)] + (['--coverage'] if coverage else [])
        with patch.object(runner, 'stage', return_value=(tree, manifest, deepcopy(provenance))), \
                patch.object(sys, 'argv', command), redirect_stdout(io.StringIO()):
            self.assertEqual(runner.main(), 0)
        report = json.loads(next(root.glob('pocx-results-*/results.json')).read_text())
        return report, manifest, scope

    def test_actual_dispatch_executes_only_required_pairs_and_preserves_owned_cases(self):
        for coverage in (False, True):
            with self.subTest(coverage=coverage), tempfile.TemporaryDirectory() as directory:
                report, manifest, scope = self.dispatcher(Path(directory), coverage=coverage)
                pairs = transport_results(report)
                self.assertEqual({(row['case'], mode) for mode, row in pairs},
                    {('p2p_ping.py', 'v1'), ('p2p_handshake.py', 'v1'),
                     ('p2p_handshake.py', 'v2'), ('feature_pocx_owned.py', 'v1')})
                inherited_selection.verify(report['provenance'], manifest,
                    upstream_cases(ROOT / 'test/functional/test_runner.py'))
                self.assertEqual(report['provenance']['inherited_selection'], scope)
                self.assertTrue(rpc_coverage.verify(report))
                if coverage:
                    self.assertEqual(set(report['rpc_coverage']), {'inherited'})
                    self.assertEqual(report['rpc_coverage']['inherited']['uncovered'], [])
                else:
                    self.assertNotIn('rpc_coverage', report)
                with self.assertRaisesRegex(ValueError, 'Complete declared'):
                    verify_functional.verify(report, report['provenance']['selected_cases'], ['v1', 'v2'], {}, {})
                broken = deepcopy(report)
                broken['results'].pop()
                with self.assertRaises(ValueError):
                    transport_results(broken)
                broken = deepcopy(report)
                broken['provenance']['case_transports']['p2p_ping.py'].append('v2')
                with self.assertRaises(ValueError):
                    inherited_selection.verify(broken['provenance'], manifest,
                        upstream_cases(ROOT / 'test/functional/test_runner.py'))
                if coverage:
                    path = next((Path(directory) / Path(report['rpc_coverage']['inherited']['directory'])).glob('coverage.*'))
                    path.write_text('altered\n')
                    with self.assertRaises(ValueError):
                        rpc_coverage.verify(report)


if __name__ == '__main__':
    unittest.main()
