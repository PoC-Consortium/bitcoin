#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin PoCX developers
# Distributed under the MIT software license; see COPYING.
"""Executable M1 failure-path checks; all scratch data stays in the build."""
import json
import ast
from copy import deepcopy
from pathlib import Path
import re
import subprocess
import socket
import sys
import tempfile
import threading
import unittest
from unittest.mock import patch
import pocx_bootstrap as pocx_bootstrap
from stage import stage, ROOT, OWNED, sha256
import check_drift
import common
import unit_build
import unit_parity
from functional_results import transport_results
from functional_cases import case_spec, selected_cases, selection_digest, upstream_cases
from test_runner import port_seeds, run_in_port_slots, shared_resource

BUILD = Path(sys.argv.pop(1)).resolve()
BITCOIN = Path(sys.argv.pop(1)).resolve()


class InfrastructureTest(unittest.TestCase):
    def test_long_checkout_keeps_unique_short_ipc_scratch_paths(self):
        root = Path('/' + 'r' * 65)
        with patch.object(common, 'ROOT', root), patch.object(Path, 'mkdir'):
            first = common.short_tmpdir(root / 'build-ci-pocx-functional')
            second = common.short_tmpdir(root / 'build-ci-pocx-unit')
            self.assertEqual(first.parent, root)
            self.assertTrue(first.name.startswith('build'))
            self.assertLessEqual(len(str(first).encode()), 80)
            self.assertNotEqual(first, second)
        with patch.object(common, 'ROOT', Path('/' + 'r' * 80)):
            with self.assertRaisesRegex(ValueError, 'Source path is too long'):
                common.short_tmpdir(Path('/' + 'r' * 80) / 'build-ci-pocx-unit')

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir=BUILD, prefix='infrastructure-')
        self.addCleanup(self.temp.cleanup)
        self.manifest = json.loads((OWNED / 'manifest.json').read_text())

    def stage_manifest(self):
        path = Path(self.temp.name) / 'manifest.json'
        path.write_text(json.dumps(self.manifest))
        return stage(BUILD, path)

    @staticmethod
    def rpc_mapping_parser(source):
        tree = ast.parse(source.read_text())
        functions = [node for node in tree.body if isinstance(node, ast.FunctionDef)
                     and node.name in ('parse_string', 'process_mapping')]
        namespace = {'re': re, 'Path': Path}
        exec(compile(ast.Module(body=functions, type_ignores=[]), str(source), 'exec'), namespace)
        return namespace['process_mapping']

    def test_rpc_native_rows_are_separate_and_preserved(self):
        original = self.rpc_mapping_parser(ROOT / 'test/functional/rpc_help.py')
        owned = self.rpc_mapping_parser(OWNED / 'functional/rpc_help.py')
        common = original(ROOT / 'src/rpc/client.cpp')
        self.assertEqual(common, owned(ROOT / 'src/rpc/client.cpp', pocx_enabled=False))
        native = owned(ROOT / 'src/rpc/client.cpp', pocx_enabled=True)
        self.assertEqual(set(native[0]) - set(common[0]), {
            ('create_assignment', 2, 'fee_rate'), ('revoke_assignment', 1, 'fee_rate'),
            ('get_assignment', 1, 'height'), ('submit_nonce', 1, 'height'),
            ('submit_nonce', 3, 'base_target'), ('submit_nonce', 6, 'nonce'),
            ('submit_nonce', 7, 'compression'), ('submit_nonce', 8, 'raw_quality'),
            ('submit_nonce', 9, 'coinbase_outputs')})
        self.assertEqual(set(common[0]) - set(native[0]), {
            ('getnetworkhashps', 0, 'nblocks'), ('getnetworkhashps', 1, 'height')})
        self.assertEqual(native[1], common[1])

    def test_rpc_native_fragment_rejects_unreviewed_syntax(self):
        owned = self.rpc_mapping_parser(OWNED / 'functional/rpc_help.py')
        source = Path(self.temp.name) / 'fragment.inc'
        for text in ('#if 1\n', 'unparsed native row\n',
                     '{ "submit_nonce", 1, "height", UnreviewedFormat },\n'):
            source.write_text(text)
            with self.subTest(text=text), self.assertRaises(AssertionError):
                owned(source, pocx_enabled=True, initializer_fragment=True)

    def test_rpc_native_dependencies_cannot_drift_or_disappear(self):
        self.assertEqual(check_drift.check(ROOT), [])
        original = check_drift.digest
        for source in ('src/rpc/client.cpp', 'src/pocx/rpc/client_conversion_params.inc'):
            with self.subTest(source=source), patch.object(check_drift, 'digest',
                    side_effect=lambda path: '0' * 64 if path == ROOT / source else original(path)):
                self.assertIn({'source': source, 'reason': 'functional consumer dependency changed since review'},
                              check_drift.check(ROOT))
        path = OWNED / 'upstream-functional-parity.json'
        record = json.loads(path.read_text())
        record['results']['rpc_help.py']['dependencies'].pop('src/pocx/rpc/client_conversion_params.inc')
        original_read = Path.read_text
        with patch.object(Path, 'read_text', lambda current, *args, **kwargs:
                          json.dumps(record) if current == path else original_read(current, *args, **kwargs)):
            self.assertIn({'source': 'test/functional/rpc_help.py',
                           'reason': 'functional consumer dependency inventory requires review'}, check_drift.check(ROOT))


    def test_loadblock_native_dependencies_cannot_drift_or_disappear(self):
        original = check_drift.digest
        for source in ('contrib/linearize/linearize-data.py', 'contrib/linearize/linearize-hashes.py'):
            with self.subTest(source=source), patch.object(check_drift, 'digest',
                    side_effect=lambda path: '0' * 64 if path == ROOT / source else original(path)):
                self.assertIn({'source': source, 'reason': 'functional consumer dependency changed since review'},
                              check_drift.check(ROOT))
        path = OWNED / 'upstream-functional-parity.json'
        record = json.loads(path.read_text())
        record['results']['feature_loadblock.py']['dependencies'].pop('contrib/linearize/linearize-data.py')
        original_read = Path.read_text
        with patch.object(Path, 'read_text', lambda current, *args, **kwargs:
                          json.dumps(record) if current == path else original_read(current, *args, **kwargs)):
            self.assertIn({'source': 'test/functional/feature_loadblock.py',
                           'reason': 'functional consumer dependency inventory requires review'}, check_drift.check(ROOT))

    def test_native_forging_clock_cannot_drift_or_lose_dependencies(self):
        original = check_drift.digest
        for source in ('test/pocx/framework/test_framework.py', 'test/pocx/framework/blocktools.py'):
            with self.subTest(source=source), patch.object(check_drift, 'digest',
                    side_effect=lambda path: '0' * 64 if path == ROOT / source else original(path)):
                self.assertIn({'source': source, 'reason': 'native forging clock changed since review'},
                              check_drift.check(ROOT))
        path = OWNED / 'upstream-functional-parity.json'
        record = json.loads(path.read_text())
        record.pop('native_forging_clock')
        original_read = Path.read_text
        with patch.object(Path, 'read_text', lambda current, *args, **kwargs:
                          json.dumps(record) if current == path else original_read(current, *args, **kwargs)):
            self.assertIn({'source': 'test/pocx/upstream-functional-parity.json',
                           'reason': 'native forging clock dependency inventory requires review'}, check_drift.check(ROOT))

    def test_empty_selection(self):
        self.manifest['tests'] = {}
        self.manifest['reused_tests'] = []
        with self.assertRaisesRegex(ValueError, 'Empty'):
            self.stage_manifest()

    def test_missing_source(self):
        self.manifest['tests']['missing.py'] = 'functional/does_not_exist.py'
        with self.assertRaisesRegex(ValueError, 'missing source'):
            self.stage_manifest()

    def test_conflicting_destination(self):
        self.manifest['reused_tests'] = [next(iter(self.manifest['tests']))]
        with self.assertRaisesRegex(ValueError, 'Conflicting'):
            self.stage_manifest()

    def test_unknown_replacement(self):
        self.manifest['replacements']['test_framework/unknown.py'] = 'framework/test_framework.py'
        with self.assertRaisesRegex(ValueError, 'no upstream destination'):
            self.stage_manifest()

    def test_conflicting_framework_copy(self):
        self.manifest['framework_copies']['test_framework/test_node.py'] = 'test_framework/test_node.py'
        with self.assertRaisesRegex(ValueError, 'Conflicting framework copy'):
            self.stage_manifest()

    def test_framework_copy_cannot_escape(self):
        self.manifest['framework_copies']['test_framework/escaped.py'] = '../../CMakeLists.txt'
        with self.assertRaisesRegex(ValueError, 'outside upstream framework'):
            self.stage_manifest()

    def test_conflicting_support_copy(self):
        self.manifest['support_copies']['test_framework/test_node.py'] = 'data/invalid_txs.py'
        with self.assertRaisesRegex(ValueError, 'Conflicting support copy'):
            self.stage_manifest()

    def test_support_copy_cannot_escape(self):
        for destination, source in [('data/escaped.py', '../../CMakeLists.txt'),
                                    ('data/../escaped.py', 'data/invalid_txs.py'),
                                    ('/data/escaped.py', 'data/invalid_txs.py')]:
            with self.subTest(destination=destination):
                self.manifest['support_copies'] = {destination: source}
                with self.assertRaisesRegex(ValueError, 'outside upstream data'):
                    self.stage_manifest()

    def test_support_replacement_requires_known_destination_and_owned_source(self):
        for destination, source in [('data/unknown.json', 'data/rpc_decodescript.json'),
                                    ('data/rpc_decodescript.json', '../../CMakeLists.txt')]:
            with self.subTest(destination=destination, source=source):
                self.manifest['support_replacements'] = {destination: source}
                with self.assertRaisesRegex(ValueError, 'Unknown or escaping native support replacement'):
                    self.stage_manifest()

    def test_wrong_profile(self):
        with self.assertRaisesRegex(ValueError, 'ENABLE_POCX=ON'):
            stage(BITCOIN)

    def test_deterministic_and_independent_copies(self):
        tree, _, first = stage(BUILD)
        replacement = tree / 'test_framework/test_framework.py'
        replacement.write_text('corruption\n')
        (tree / 'stale.py').write_text('stale\n')
        tree, _, second = stage(BUILD)
        self.assertEqual(first, second)
        self.assertFalse((tree / 'stale.py').exists())
        self.assertEqual(sha256(replacement), sha256(OWNED / 'framework/test_framework.py'))
        self.assertNotEqual(replacement.stat().st_ino, (OWNED / 'framework/test_framework.py').stat().st_ino)
        upstream = ROOT / 'test/functional/test_framework/test_framework.py'
        self.assertNotEqual(sha256(upstream), sha256(replacement))
        copied_node = tree / 'test_framework/bitcoin_test_node.py'
        upstream_node = ROOT / 'test/functional/test_framework/test_node.py'
        self.assertEqual(sha256(copied_node), sha256(upstream_node))
        self.assertNotEqual(copied_node.stat().st_ino, upstream_node.stat().st_ino)
        copied_blocks = tree / 'test_framework/bitcoin_blocktools.py'
        upstream_blocks = ROOT / 'test/functional/test_framework/blocktools.py'
        self.assertEqual(sha256(copied_blocks), sha256(upstream_blocks))
        self.assertNotEqual(copied_blocks.stat().st_ino, upstream_blocks.stat().st_ino)
        for source in (ROOT / 'test/functional/test_framework').rglob('*.csv'):
            destination = tree / source.relative_to(ROOT / 'test/functional')
            self.assertEqual(destination.read_bytes(), source.read_bytes())
            self.assertEqual(second['files'][str(destination.relative_to(tree))]['sha256'], sha256(source))
        for destination, source in self.manifest.get('support_copies', {}).items():
            replacement = self.manifest.get('support_replacements', {}).get(destination)
            original = OWNED / replacement if replacement else ROOT / 'test/functional' / source
            copy = tree / destination
            self.assertEqual(sha256(copy), sha256(original))
            self.assertNotEqual(copy.stat().st_ino, original.stat().st_ino)

    def test_unknown_runner_selection(self):
        result = subprocess.run([sys.executable, str(OWNED / 'test_runner.py'), '--build-dir', str(BUILD), 'missing.py'], capture_output=True, text=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('unknown test selection', result.stderr)

    def test_unknown_runner_case_selection(self):
        result = subprocess.run([sys.executable, str(OWNED / 'test_runner.py'),
                                 '--build-dir', str(BUILD), '--case',
                                 'wallet_multiwallet.py --usecli --test_methods=missing_method'],
                                capture_output=True, text=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('unknown functional case selection', result.stderr)

    @staticmethod
    def transport_report():
        # A mixed outcome must retain its v2 failure after a v1 success.
        return {'provenance': {'format_version': 2, 'selected_tests': ['p2p_ping.py'],
                               'transport_modes': ['v1', 'v2']},
                'results': [{'test': 'p2p_ping.py', 'transport': mode,
                             'test_arguments': [f'--{mode}transport'],
                             'command': ['python3', 'p2p_ping.py', f'--{mode}transport'],
                             'returncode': 0 if mode == 'v1' else 1, 'timed_out': False,
                             'status': 'passed' if mode == 'v1' else 'failed'}
                            for mode in ['v1', 'v2']]}

    def test_missing_transport_execution(self):
        report = self.transport_report()
        del report['results'][1]
        with self.assertRaisesRegex(ValueError, 'Incomplete'):
            transport_results(report)

    def test_duplicate_transport_execution(self):
        report = self.transport_report()
        report['results'].append(deepcopy(report['results'][0]))
        with self.assertRaisesRegex(ValueError, 'duplicate'):
            transport_results(report)

    def test_transport_label_must_be_explicit(self):
        report = self.transport_report()
        del report['results'][0]['transport']
        with self.assertRaisesRegex(ValueError, 'Invalid'):
            transport_results(report)

    def test_transport_label_matches_execution(self):
        for command in [['python3', 'p2p_ping.py', '--v1transport'],
                        ['python3', 'p2p_ping.py', '--v2transport', '--v1transport'],
                        ['python3', 'p2p_ping.py', '--v2transport', '--v2transport']]:
            with self.subTest(command=command):
                report = self.transport_report()
                report['results'][1]['command'] = command
                with self.assertRaisesRegex(ValueError, 'label differs'):
                    transport_results(report)

    def test_transport_failure_cannot_be_reported_as_pass(self):
        for code, timed_out in [(1, False), (0, True)]:
            with self.subTest(code=code, timed_out=timed_out):
                report = self.transport_report()
                report['results'][0].update(returncode=code, timed_out=timed_out)
                with self.assertRaisesRegex(ValueError, 'terminal execution'):
                    transport_results(report)

    def test_transport_requires_terminal_result(self):
        for field, value in [('returncode', None), ('returncode', False),
                             ('timed_out', None), ('timed_out', 0)]:
            with self.subTest(field=field, value=value):
                report = self.transport_report()
                report['results'][0][field] = value
                with self.assertRaisesRegex(ValueError, 'Missing terminal'):
                    transport_results(report)

    def test_historical_results_cannot_claim_v2_execution(self):
        report = {'provenance': {}, 'results': [deepcopy(self.transport_report()['results'][0])]}
        del report['results'][0]['transport']
        del report['results'][0]['test_arguments']
        report['results'][0]['command'] = ['python3', 'p2p_ping.py']
        self.assertEqual(transport_results(report), [('v1', report['results'][0])])
        report['results'][0]['command'].append('--v2transport')
        with self.assertRaisesRegex(ValueError, 'unrecorded transport'):
            transport_results(report)

    def test_inventory_preserves_both_transport_results(self):
        report = self.transport_report()
        _, _, provenance = stage(BUILD)
        report['provenance'].update(provenance)
        report['provenance']['runner'] = {'source': 'test/pocx/test_runner.py',
                                        'sha256': sha256(OWNED / 'test_runner.py')}
        evidence = Path(self.temp.name) / 'results.json'
        snapshot = Path(self.temp.name) / 'coverage.json'
        evidence.write_text(json.dumps(report))
        command = [sys.executable, str(OWNED / 'update_inventory.py'),
                   '--wrapper', str(ROOT.parent), '--functional-results', str(evidence),
                   '--output', str(snapshot)]
        result = subprocess.run(command, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        entry = next(item for item in json.loads(snapshot.read_text())
                     if item['source'] == 'test/functional/p2p_ping.py')
        self.assertEqual(entry['execution'], 'failed')
        for profile, mode, status in [('pocx', 'v1', 'passed'), ('pocx-v2', 'v2', 'failed')]:
            recorded = entry['execution_by_profile'][profile]['p2p_ping.py']
            self.assertEqual(recorded['global_transport'], mode)
            self.assertEqual(recorded['status'], status)
            self.assertTrue(recorded['recorded_tree_matches_current_sources'])
        # Invalid evidence must fail without replacing the last valid snapshot.
        before = snapshot.read_bytes()
        for defect, message in [('missing_case', 'Incomplete functional transport selection'),
                                ('missing_source', 'Unrecorded functional case source'),
                                ('missing_runner', 'Missing functional runner source attestation')]:
            with self.subTest(defect=defect):
                altered = deepcopy(report)
                if defect == 'missing_case':
                    del altered['results'][1]
                elif defect == 'missing_source':
                    del altered['provenance']['files']['p2p_ping.py']
                else:
                    del altered['provenance']['runner']
                evidence.write_text(json.dumps(altered))
                result = subprocess.run(command, capture_output=True, text=True)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(message, result.stderr)
                self.assertEqual(snapshot.read_bytes(), before)









    def test_transport_infrastructure_cannot_drift(self):
        self.assertEqual(check_drift.check(ROOT), [])
        original_digest = check_drift.digest
        sources = json.loads((OWNED / 'upstream-functional-parity.json').read_text())['execution_infrastructure']['sources']
        for source in sources:
            with self.subTest(source=source):
                with patch.object(check_drift, 'digest', side_effect=lambda path:
                                  '0' * 64 if path == ROOT / source else original_digest(path)):
                    issues = check_drift.check(ROOT)
                expected = [{'source': source,
                             'reason': 'functional execution infrastructure changed since review'}]
                if source == 'test/pocx/stage.py':
                    expected.append({'source': source,
                                     'reason': 'native fork fixture or dependency changed since parity review'})
                self.assertEqual(issues, expected)

    def test_transport_infrastructure_review_cannot_be_dropped(self):
        path = OWNED / 'upstream-functional-parity.json'
        records = json.loads(path.read_text())
        original_read = Path.read_text
        for source in records['execution_infrastructure']['sources']:
            with self.subTest(source=source):
                altered = deepcopy(records)
                del altered['execution_infrastructure']['sources'][source]
                with patch.object(Path, 'read_text', lambda current, *args, **kwargs:
                                  json.dumps(altered) if current == path else original_read(current, *args, **kwargs)):
                    issues = check_drift.check(ROOT)
                self.assertEqual(issues, [{'source': source,
                                          'reason': 'functional execution infrastructure requires review'}])

    def test_upstream_argument_variants_selected_completely(self):
        upstream = upstream_cases(ROOT / 'test/functional/test_runner.py')
        cases = selected_cases(self.manifest, upstream)
        self.assertEqual([c['arguments'] for c in cases if c['test'] == 'wallet_multiwallet.py'],
                         [[], ['--usecli']])
        # A file with only argument-bearing entries must retain every entry,
        # rather than inventing a default invocation with different coverage.
        bind = selected_cases({'tests': {}, 'reused_tests': ['rpc_bind.py']}, upstream)
        self.assertEqual([c['arguments'] for c in bind], [['--ipv4'], ['--ipv6'], ['--nonloopback']])
        self.assertEqual(len(upstream), 287)

    def test_functional_exclusions_require_specific_review(self):
        path = OWNED / 'manifest.json'
        changed = deepcopy(self.manifest)
        changed['excluded_tests']['mining_mainnet.py'] = 'Different exclusion rationale'
        original_read = Path.read_text
        with patch.object(Path, 'read_text', lambda current, *args, **kwargs:
                          json.dumps(changed) if current == path else original_read(current, *args, **kwargs)):
            self.assertEqual(check_drift.check(ROOT), [
                {'source': 'test/pocx/manifest.json', 'reason': 'functional exclusions changed since specific review'}])

    def test_functional_exclusion_cannot_also_be_selected(self):
        changed = deepcopy(self.manifest)
        changed['reused_tests'].append('mining_mainnet.py')
        with self.assertRaisesRegex(ValueError, 'overlapping'):
            selected_cases(changed, upstream_cases(ROOT / 'test/functional/test_runner.py'))

    def test_benchmark_aggregate_selection_requires_review(self):
        changed = deepcopy(self.manifest)
        changed['dynamic_tests'].clear()
        with self.assertRaisesRegex(ValueError, 'build-specific expansion'):
            selected_cases(changed, upstream_cases(ROOT / 'test/functional/test_runner.py'))

    def test_unknown_upstream_selection_expression(self):
        path = Path(self.temp.name) / 'runner.py'
        path.write_text("BASE_SCRIPTS = ['test.py', build_specific_cases()]\nEXTENDED_SCRIPTS = ['other.py']\n")
        with self.assertRaisesRegex(ValueError, 'Unreviewed'):
            upstream_cases(path)

    @staticmethod
    def variant_report():
        specs = [case_spec('wallet_multiwallet.py', args) for args in [[], ['--usecli']]]
        report = {'provenance': {'format_version': 3, 'selected_tests': ['wallet_multiwallet.py'],
                                'selected_cases': specs, 'transport_modes': ['v1', 'v2'],
                                'case_selection': {'selected_cases_sha256': selection_digest(specs)}}, 'results': []}
        for spec in specs:
            for mode in ['v1', 'v2']:
                arguments = [*spec['arguments'], f'--{mode}transport']
                report['results'].append({'test': spec['test'], 'case': spec['id'],
                                          'case_arguments': spec['arguments'], 'transport': mode,
                                          'test_arguments': arguments, 'command': ['python3', spec['test'], *arguments],
                                          'returncode': 1 if spec['arguments'] else 0, 'timed_out': False,
                                          'status': 'failed' if spec['arguments'] else 'passed'})
        return report

    def test_missing_argument_variant_cannot_pass(self):
        report = self.variant_report()
        report['results'] = [row for row in report['results'] if not row['case_arguments']]
        with self.assertRaisesRegex(ValueError, 'Incomplete'):
            transport_results(report)

    def test_reported_skip_cannot_be_counted_as_pass(self):
        report = self.variant_report()
        report['provenance']['format_version'] = 4
        row = report['results'][0]
        row.update(returncode=77, status='skipped', skip_reason='Required optional module unavailable')
        self.assertEqual(transport_results(report)[0], ('v1', row))
        row['status'] = 'passed'
        with self.assertRaisesRegex(ValueError, 'status differs'):
            transport_results(report)
        row['status'] = 'failed'
        with self.assertRaisesRegex(ValueError, 'status differs'):
            transport_results(report)
        row['status'] = 'skipped'
        row.pop('skip_reason')
        with self.assertRaisesRegex(ValueError, 'skip requires'):
            transport_results(report)

    def test_argument_variant_must_match_executed_command(self):
        report = self.variant_report()
        row = next(row for row in report['results'] if row['case_arguments'])
        row['command'].remove('--usecli')
        with self.assertRaisesRegex(ValueError, 'differs from executed flag'):
            transport_results(report)

    def test_argument_variant_identity_cannot_be_relabelled(self):
        report = self.variant_report()
        row = next(row for row in report['results'] if row['case_arguments'])
        row['case'] = row['test']
        with self.assertRaisesRegex(ValueError, 'identity differs'):
            transport_results(report)

    def test_argument_selection_digest_cannot_hide_missing_case(self):
        report = self.variant_report()
        report['provenance']['selected_cases'].pop()
        with self.assertRaisesRegex(ValueError, 'mismatched functional case selection'):
            transport_results(report)

    def test_inventory_preserves_default_and_cli_outcomes(self):
        report = self.variant_report()
        _, _, provenance = stage(BUILD)
        report['provenance'].update(provenance)
        for field, source in [('runner', 'test/pocx/test_runner.py'),
                              ('case_selection', 'test/pocx/functional_cases.py'),
                              ('upstream_runner', 'test/functional/test_runner.py')]:
            report['provenance'].setdefault(field, {}).update(source=source, sha256=sha256(ROOT / source))
        path = Path(self.temp.name) / 'results.json'
        snapshot = Path(self.temp.name) / 'coverage.json'
        path.write_text(json.dumps(report))
        command = [sys.executable, str(OWNED / 'update_inventory.py'), '--wrapper', str(ROOT.parent),
                   '--functional-results', str(path), '--output', str(snapshot)]
        result = subprocess.run(command, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        entry = next(row for row in json.loads(snapshot.read_text())
                     if row['source'] == 'test/functional/wallet_multiwallet.py')
        self.assertEqual(entry['execution'], 'failed')
        for mode, profile in [('v1', 'pocx'), ('v2', 'pocx-v2')]:
            rows = entry['execution_by_profile'][profile]
            self.assertEqual(set(rows), {'wallet_multiwallet.py', 'wallet_multiwallet.py --usecli'})
            self.assertEqual(rows['wallet_multiwallet.py']['status'], 'passed')
            self.assertEqual(rows['wallet_multiwallet.py --usecli']['status'], 'failed')
            self.assertTrue(all(row['recorded_tree_matches_current_sources'] for row in rows.values()))
        self.assertEqual(len(entry['upstream_functional_cases']), 2)

    def test_port_seed_slots_do_not_overlap_including_boundary_node(self):
        max_nodes, port_range = 12, 5000
        for base in [0, 414, 415, 4986, 19381]:
            occupied = set()
            for seed in port_seeds(base, 207, max_nodes, port_range):
                first = max_nodes * seed % (port_range - 1 - max_nodes)
                ports = set(range(first, first + max_nodes + 1))
                self.assertFalse(occupied & ports)
                occupied.update(ports)
        with self.assertRaisesRegex(ValueError, 'jobs must be'):
            port_seeds(0, 208, max_nodes, port_range)

    def test_large_selection_reuses_only_released_port_slots(self):
        # Keep the first case live across more than one upstream seed wrap.
        # Later cases must bind their complete node-port set without touching
        # its still-bound ports. The real functional runner uses this executor.
        released = threading.Event()
        slots = port_seeds(0, 4, 12, 5000)
        def run(index, seed):
            sockets = []
            try:
                for offset in range(13):
                    sock = socket.socket()
                    sockets.append(sock)
                    sock.bind(('127.0.0.1', 50000 + 12 * seed % 4987 + offset))
                if index == 0:
                    self.assertTrue(released.wait(timeout=10))
                if index == 415:
                    released.set()
                return index
            finally:
                for sock in sockets:
                    sock.close()
        self.assertEqual(run_in_port_slots(range(600), slots, run), list(range(600)))

    def test_fixed_rpc_bind_ports_serialize_without_blocking_independent_cases(self):
        # Reproduce two transport copies binding one literal socket address.
        # An unrelated case must still run while the first copy owns the port.
        cases = [(case_spec('rpc_bind.py', ['--ipv4']), mode) for mode in ['v1', 'v2']]
        cases.append((case_spec('rpc_bind.py', ['--ipv6']), 'v1'))
        self.assertEqual(shared_resource(cases[0]), shared_resource(cases[1]))
        self.assertIsNotNone(shared_resource(cases[0]))
        self.assertIsNone(shared_resource(cases[2]))
        ready = threading.Event()
        release = threading.Event()
        with socket.socket() as probe:
            probe.bind(('127.0.0.1', 0))
            address = probe.getsockname()

        def run(case, seed):
            if shared_resource(case):
                with socket.socket() as sock:
                    sock.bind(address)
                    sock.listen()
                    ready.set()
                    self.assertTrue(release.wait(timeout=10))
            else:
                self.assertTrue(ready.wait(timeout=10))
                try:
                    with socket.socket() as probe:
                        with self.assertRaises(OSError):
                            probe.bind(address)
                finally:
                    release.set()
            return case

        self.assertEqual(run_in_port_slots(cases, [0, 2, 4], run, shared_resource), cases)

    def test_empty_unit_binary(self):
        fake = Path(self.temp.name) / 'empty'
        fake.write_text('#!/bin/sh\nexit 0\n')
        fake.chmod(0o755)
        result = subprocess.run([sys.executable, str(OWNED / 'register_unit.py'), '--binary', str(fake), '--output', str(fake.with_suffix('.cmake'))], capture_output=True, text=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('empty discovery', result.stderr)

    def test_bitcoin_unit_suites_match_runtime(self):
        # Conditional source expressions can compile a suite while hiding it
        # from upstream's source-based CTest discovery (previously pow_tests).
        binary = BITCOIN / 'bin/test_bitcoin'
        listing = subprocess.run([str(binary), '--list_content'],
                                 capture_output=True, text=True, check=True)
        suites = set(re.findall(r'^([A-Za-z_][A-Za-z_0-9]*)\*$',
                                listing.stdout + listing.stderr, re.M))
        self.assertIn('pow_tests', suites)
        selection = subprocess.run(['ctest', '--test-dir', str(BITCOIN),
                                    '--show-only=json-v1'],
                                   capture_output=True, text=True, check=True)
        tests = json.loads(selection.stdout)['tests']
        registered = {test['name'] for test in tests
                      if Path(test['command'][0]).resolve() == binary.resolve()}
        self.assertEqual(suites, registered)

    def test_unit_baseline_cases_and_exclusions_cannot_be_dropped(self):
        reviewed = json.loads((OWNED / 'unit-parity.json').read_text())
        self.assertEqual(unit_parity.check(ROOT, reviewed), [])
        for mutate in ('applicable', 'excluded'):
            broken = deepcopy(reviewed)
            if mutate == 'applicable':
                broken[mutate].pop()
            else:
                del broken[mutate][next(iter(broken[mutate]))]
            self.assertTrue(unit_parity.check(ROOT, broken))
        broken = deepcopy(reviewed)
        del broken['reviewed_sources']['src/node/blockstorage.cpp']
        self.assertTrue(unit_parity.check(ROOT, broken))

    def test_unit_adaptation_and_storage_reviews_cannot_drift(self):
        reviewed = json.loads((OWNED / 'unit-parity.json').read_text())
        original = unit_parity.digest
        for source in ('src/pocx/test/adapted/pow_tests.cpp',
                       'src/pocx/test/adapted/blockmanager_tests.cpp',
                       'src/node/blockstorage.cpp'):
            with self.subTest(source=source), patch.object(unit_parity, 'digest',
                    side_effect=lambda path: '0' * 64 if path == ROOT / source else original(path)):
                issues = unit_parity.check(ROOT, reviewed)
                self.assertEqual({issue['source'] for issue in issues}, {source})

    def test_unit_case_parser_distinguishes_helpers_and_nested_suites(self):
        listing = 'suite*\n    case*\n    nested*\n        other*\nmock_process \n    helper \n'
        self.assertEqual(unit_parity.runtime_cases(listing), {'suite/case', 'suite/nested/other'})
        with self.assertRaisesRegex(ValueError, 'Duplicate'):
            unit_parity.runtime_cases('suite*\n    case*\n    case*\n')

    def test_duplicate_manifest_key(self):
        path = Path(self.temp.name) / 'duplicate.json'
        path.write_text('{"tests": {}, "tests": {}}')
        with self.assertRaisesRegex(ValueError, 'Duplicate'):
            stage(BUILD, path)

    def test_missing_explicit_unit_suite(self):
        result = subprocess.run([sys.executable, str(OWNED / 'run_unit.py'),
                                 '--build-dir', str(BUILD), '--suite', 'missing_proof_suite'],
                                capture_output=True, text=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('Missing requested suites', result.stderr)

    def test_reviewed_real_proof_inputs_cannot_drift(self):
        self.assertEqual(check_drift.check(ROOT), [])
        original_digest = check_drift.digest
        for source in ('src/pocx/test/data/real_proof_vectors.json',
                       'test/pocx/vectors/reference.rs', 'test/pocx/vectors/generate.py',
                       'test/pocx/vectors/Cargo.lock'):
            with self.subTest(source=source):
                # Inject an observed content change without touching source files.
                with patch.object(check_drift, 'digest', side_effect=lambda path:
                                  '0' * 64 if path == ROOT / source else original_digest(path)):
                    issues = check_drift.check(ROOT)
                self.assertEqual({issue['source'] for issue in issues}, {source})

    def test_kernel_fixture_provenance_cannot_drift(self):
        self.assertEqual(check_drift.check(ROOT), [])
        original_digest = check_drift.digest
        sources = json.loads((OWNED / 'kernel/provenance.json').read_text())['sources']
        for source in sources:
            with self.subTest(source=source):
                with patch.object(check_drift, 'digest', side_effect=lambda path:
                                  '0' * 64 if path == ROOT / source else original_digest(path)):
                    issues = check_drift.check(ROOT)
                self.assertEqual({issue['source'] for issue in issues}, {source})

    def test_unverified_kernel_fixtures_rejected(self):
        source = Path(self.temp.name) / 'unverified.json'
        output = source.with_suffix('.h')
        source.write_text('{}\n')
        result = subprocess.run([sys.executable, str(OWNED / 'kernel/render_fixtures.py'),
                                 str(source), str(output)], capture_output=True, text=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('differ from the independently verified snapshot', result.stderr)
        self.assertFalse(output.exists())

    def unit_provenance_fixture(self):
        directory = Path(self.temp.name)
        binary, source, inputs, cache, record = [directory / name for name in (
            'test_pocx', 'proof.cpp', 'inputs.txt', 'CMakeCache.txt', 'discovered.build.json')]
        binary.write_bytes(b'compiled proof test')
        source.write_text('required proof checks\n')
        inputs.write_text(str(source) + '\n')
        cache.write_text('ENABLE_WALLET:BOOL=ON\n')
        suites = unit_build.OWNED_SUITES | {'pocx_block_builder_tests'}
        record.write_text(json.dumps(unit_build.snapshot(binary, inputs, cache, suites)))
        return binary, source, inputs, cache, record, suites

    def test_stale_unit_source_rejected(self):
        binary, source, inputs, cache, record, suites = self.unit_provenance_fixture()
        unit_build.verify(binary, inputs, cache, record, suites)
        source.write_text('new required proof checks\n')
        with self.assertRaisesRegex(ValueError, 'Stale unit build provenance'):
            unit_build.verify(binary, inputs, cache, record, suites)

    def test_changed_unit_source_selection_rejected(self):
        binary, source, inputs, cache, record, suites = self.unit_provenance_fixture()
        extra = source.with_name('new_real_proof.cpp')
        extra.write_text('another required suite\n')
        inputs.write_text(str(source) + '\n' + str(extra) + '\n')
        with self.assertRaisesRegex(ValueError, 'Stale unit build provenance'):
            unit_build.verify(binary, inputs, cache, record, suites)

    def test_unit_binary_or_options_change_rejected(self):
        binary, _, inputs, cache, record, suites = self.unit_provenance_fixture()
        binary.write_bytes(b'older executable missing checks')
        with self.assertRaisesRegex(ValueError, 'Stale unit build provenance'):
            unit_build.verify(binary, inputs, cache, record, suites)
        binary.write_bytes(b'compiled proof test')
        cache.write_text('ENABLE_WALLET:BOOL=OFF\n')
        with self.assertRaisesRegex(ValueError, 'Stale unit build provenance'):
            unit_build.verify(binary, inputs, cache, record, suites)

    def test_missing_owned_unit_suite_rejected(self):
        binary, _, inputs, cache, _, suites = self.unit_provenance_fixture()
        for missing in ('pocx_real_proof_tests', 'pocx_block_builder_tests'):
            with self.subTest(missing=missing):
                with self.assertRaisesRegex(ValueError, 'Missing required owned suites'):
                    unit_build.snapshot(binary, inputs, cache, suites - {missing})
        cache.write_text('ENABLE_WALLET:BOOL=OFF\n')
        unit_build.snapshot(binary, inputs, cache, suites - {'pocx_block_builder_tests'})

    def test_missing_unit_build_provenance_rejected(self):
        binary, _, inputs, cache, record, suites = self.unit_provenance_fixture()
        record.unlink()
        with self.assertRaisesRegex(ValueError, 'Missing unit build provenance'):
            unit_build.verify(binary, inputs, cache, record, suites)

    def test_new_owned_test_requires_classification(self):
        original_glob, original_is_file = Path.glob, Path.is_file
        for directory, pattern, name in (
                ('src/pocx/test', '**/*.cpp', 'new_unclassified_proof_tests.cpp'),
                ('test/pocx/functional', '*.py', 'feature_new_unclassified.py')):
            with self.subTest(directory=directory):
                source = ROOT / directory / name
                def observed_glob(path, selection, **kwargs):
                    existing = list(original_glob(path, selection, **kwargs))
                    return existing + ([source] if path == ROOT / directory and selection == pattern else [])
                with patch.object(Path, 'glob', observed_glob), patch.object(Path, 'is_file',
                        lambda path: path == source or original_is_file(path)):
                    issues = check_drift.check(ROOT)
                self.assertEqual(issues, [{'source': str(source.relative_to(ROOT)),
                                           'reason': 'new source requires classification'}])

    def test_restoration_review_cannot_drift(self):
        self.assertEqual(check_drift.check(ROOT), [])
        original_digest = check_drift.digest
        records = json.loads((OWNED / 'restorations.json').read_text())['files']
        for source, record in records.items():
            for path in (source, record['replacement']):
                with self.subTest(path=path):
                    with patch.object(check_drift, 'digest', side_effect=lambda current:
                                      '0' * 64 if current == ROOT / path else original_digest(current)):
                        issues = check_drift.check(ROOT)
                    self.assertEqual({issue['source'] for issue in issues}, {path})

    def test_restoration_record_must_match_upstream(self):
        path = OWNED / 'restorations.json'
        records = json.loads(path.read_text())
        source = next(iter(records['files']))
        records['files'][source]['upstream_revision'] = 'unreviewed-version'
        original_read = Path.read_text
        with patch.object(Path, 'read_text', lambda current, *args, **kwargs:
                          json.dumps(records) if current == path else original_read(current, *args, **kwargs)):
            issues = check_drift.check(ROOT)
        self.assertEqual(issues, [{'source': source,
                                  'reason': 'restoration record does not match the pinned upstream inventory'}])

    def test_functional_parity_cannot_drift(self):
        self.assertEqual(check_drift.check(ROOT), [])
        original_digest = check_drift.digest
        records = json.loads((OWNED / 'upstream-functional-parity.json').read_text())['results']
        for record in records.values():
            source = record['replacement'] or record['source']
            with self.subTest(source=source):
                with patch.object(check_drift, 'digest', side_effect=lambda path:
                                  '0' * 64 if path == ROOT / source else original_digest(path)):
                    issues = check_drift.check(ROOT)
                self.assertEqual({issue['source'] for issue in issues}, {source})
                self.assertTrue(any('parity review' in issue['reason'] for issue in issues))

    def test_functional_parity_record_must_match_upstream(self):
        path = OWNED / 'upstream-functional-parity.json'
        records = json.loads(path.read_text())
        name = next(iter(records['results']))
        records['results'][name]['source_sha256'] = '0' * 64
        original_read = Path.read_text
        with patch.object(Path, 'read_text', lambda current, *args, **kwargs:
                          json.dumps(records) if current == path else original_read(current, *args, **kwargs)):
            issues = check_drift.check(ROOT)
        self.assertEqual(issues, [{'source': records['results'][name]['source'],
                                  'reason': 'functional parity record does not match the pinned upstream inventory'}])

    def test_reviewed_functional_consumer_cannot_be_dropped(self):
        path = OWNED / 'manifest.json'
        records = json.loads((OWNED / 'upstream-functional-parity.json').read_text())['results']
        original_read = Path.read_text
        for name, record in records.items():
            with self.subTest(name=name):
                manifest = json.loads(original_read(path))
                if name in manifest['tests']:
                    del manifest['tests'][name]
                elif name in manifest.get('excluded_tests', {}):
                    del manifest['excluded_tests'][name]
                else:
                    manifest['reused_tests'].remove(name)
                    manifest.get('dynamic_tests', {}).pop(name, None)
                with patch.object(Path, 'read_text', lambda current, *args, **kwargs:
                                  json.dumps(manifest) if current == path else original_read(current, *args, **kwargs)):
                    issues = check_drift.check(ROOT)
                expected = ([{'source': 'test/pocx/manifest.json',
                              'reason': 'functional exclusions changed since specific review'}]
                            if name in self.manifest.get('excluded_tests', {}) else
                            [{'source': 'test/pocx/manifest.json',
                              'reason': 'functional case selection changed since review'},
                             {'source': record['source'],
                              'reason': 'reviewed functional consumer removed or replaced without parity review'}])
                self.assertEqual(issues, expected)

    def test_reviewed_argument_variant_cannot_be_dropped(self):
        path = OWNED / 'upstream-functional-parity.json'
        records = json.loads(path.read_text())
        records['case_selection']['selected_cases'] = [case for case in records['case_selection']['selected_cases']
                                                       if case['id'] != 'wallet_multiwallet.py --usecli']
        original_read = Path.read_text
        with patch.object(Path, 'read_text', lambda current, *args, **kwargs:
                          json.dumps(records) if current == path else original_read(current, *args, **kwargs)):
            issues = check_drift.check(ROOT)
        self.assertEqual(issues, [{'source': 'test/pocx/manifest.json',
                                  'reason': 'functional case selection changed since review'}])

    def test_upstream_argument_selection_requires_review(self):
        source = ROOT / 'test/functional/test_runner.py'
        original_digest = check_drift.digest
        with patch.object(check_drift, 'digest', side_effect=lambda path:
                          '0' * 64 if path == source else original_digest(path)):
            issues = check_drift.check(ROOT)
        self.assertIn({'source': str(source.relative_to(ROOT)),
                       'reason': 'upstream functional argument selections changed since review'}, issues)
        self.assertEqual({issue['source'] for issue in issues}, {str(source.relative_to(ROOT))})

    def test_native_fork_fixture_cannot_drift(self):
        self.assertEqual(check_drift.check(ROOT), [])
        original_digest = check_drift.digest
        records = json.loads((OWNED / 'upstream-functional-parity.json').read_text())['framework_replacements']
        for record in records.values():
            for source in [record['replacement'], *record['dependencies']]:
                with self.subTest(source=source):
                    with patch.object(check_drift, 'digest', side_effect=lambda path:
                                      '0' * 64 if path == ROOT / source else original_digest(path)):
                        issues = check_drift.check(ROOT)
                    self.assertIn({'source': source,
                                   'reason': 'native fork fixture or dependency changed since parity review'}, issues)
                    # Shared consensus/key sources can also trigger the kernel
                    # and upstream dependency gates; every issue must still
                    # identify this injected change.
                    self.assertEqual({issue['source'] for issue in issues}, {source})

    def test_native_fork_alias_cannot_be_dropped(self):
        path = OWNED / 'manifest.json'
        manifest = json.loads(path.read_text())
        records = json.loads((OWNED / 'upstream-functional-parity.json').read_text())['framework_replacements']
        source, record = next(iter(records.items()))
        del manifest['framework_copies'][record['copied_upstream_alias']]
        original_read = Path.read_text
        with patch.object(Path, 'read_text', lambda current, *args, **kwargs:
                          json.dumps(manifest) if current == path else original_read(current, *args, **kwargs)):
            issues = check_drift.check(ROOT)
        self.assertEqual(issues, [{'source': source,
                                  'reason': 'reviewed framework replacement or upstream alias changed without parity review'}])

    def test_reviewed_support_copy_cannot_be_dropped(self):
        path = OWNED / 'manifest.json'
        records = json.loads((OWNED / 'upstream-functional-parity.json').read_text())['support_copies']
        original_read = Path.read_text
        for destination, record in records.items():
            with self.subTest(destination=destination):
                manifest = json.loads(original_read(path))
                del manifest['support_copies'][destination]
                with patch.object(Path, 'read_text', lambda current, *args, **kwargs:
                                  json.dumps(manifest) if current == path else original_read(current, *args, **kwargs)):
                    issues = check_drift.check(ROOT)
                self.assertEqual(issues, [{'source': record['source'],
                                          'reason': 'reviewed support module removed or replaced without parity review'}])

    def test_reviewed_support_copy_cannot_drift(self):
        records = json.loads((OWNED / 'upstream-functional-parity.json').read_text())['support_copies']
        original_digest = check_drift.digest
        for record in records.values():
            with self.subTest(source=record['source']):
                with patch.object(check_drift, 'digest', side_effect=lambda path:
                                  '0' * 64 if path == ROOT / record['source'] else original_digest(path)):
                    issues = check_drift.check(ROOT)
                self.assertIn({'source': record['source'],
                               'reason': 'support module changed since parity review'}, issues)

    def test_reviewed_native_support_resource_cannot_drift_or_be_dropped(self):
        records = json.loads((OWNED / 'upstream-functional-parity.json').read_text())['support_copies']
        manifest_path = OWNED / 'manifest.json'
        original_digest = check_drift.digest
        original_read = Path.read_text
        for destination, record in records.items():
            if 'replacement' not in record:
                continue
            with self.subTest(destination=destination):
                source = record['replacement']
                with patch.object(check_drift, 'digest', side_effect=lambda path:
                                  '0' * 64 if path == ROOT / source else original_digest(path)):
                    self.assertIn({'source': source, 'reason': 'native support resource changed since parity review'},
                                  check_drift.check(ROOT))
                manifest = json.loads(original_read(manifest_path))
                del manifest['support_replacements'][destination]
                with patch.object(Path, 'read_text', lambda current, *args, **kwargs:
                                  json.dumps(manifest) if current == manifest_path else original_read(current, *args, **kwargs)):
                    self.assertIn({'source': record['source'],
                                   'reason': 'native support replacement changed since parity review'}, check_drift.check(ROOT))

    @staticmethod
    def reviewed_skip_report():
        report = InfrastructureTest.variant_report()
        report['provenance']['format_version'] = 4
        for row in report['results']:
            if row['case_arguments']:
                row.update(returncode=77, status='skipped', skip_reason='Disabled optional test feature')
        policy = {'cases': {'wallet_multiwallet.py --usecli': {
            'reasons': ['Disabled optional test feature'], 'build_options': {'OPTIONAL_FEATURE': 'OFF'},
            'limitation': 'Optional test feature disabled'}}}
        return report, policy

    def test_complete_profile_keeps_reviewed_skips_separate_from_passes(self):
        from verify_functional import verify
        report, policy = self.reviewed_skip_report()
        verified = verify(report, report['provenance']['selected_cases'], ['v1', 'v2'], policy, {'OPTIONAL_FEATURE': 'OFF'})
        self.assertEqual(verified['counts_by_transport'], {mode: {'passed': 1, 'skipped': 1} for mode in ['v1', 'v2']})
        self.assertEqual(len(verified['skips']), 2)
        self.assertTrue(all(row['status'] == 'skipped' for row in report['results'] if row['case_arguments']))

    def test_complete_profile_rejects_unreviewed_skip_case_or_reason(self):
        from verify_functional import verify
        for mutate in ['case', 'reason']:
            report, policy = self.reviewed_skip_report()
            if mutate == 'case':
                policy['cases'].clear()
            else:
                report['results'][2]['skip_reason'] = 'Unexpected prerequisite missing'
            with self.subTest(mutation=mutate), self.assertRaisesRegex(ValueError, 'Unreviewed functional skip'):
                verify(report, report['provenance']['selected_cases'], ['v1', 'v2'], policy, {'OPTIONAL_FEATURE': 'OFF'})

    def test_complete_profile_rejects_skip_when_feature_is_enabled(self):
        from verify_functional import verify
        report, policy = self.reviewed_skip_report()
        with self.assertRaisesRegex(ValueError, 'does not match build'):
            verify(report, report['provenance']['selected_cases'], ['v1', 'v2'], policy, {'OPTIONAL_FEATURE': 'ON'})

    def test_complete_profile_does_not_waive_failure_in_optional_case(self):
        from verify_functional import verify
        report, policy = self.reviewed_skip_report()
        report['results'][2].update(returncode=1, status='failed')
        with self.assertRaisesRegex(ValueError, 'Functional failure'):
            verify(report, report['provenance']['selected_cases'], ['v1', 'v2'], policy, {'OPTIONAL_FEATURE': 'OFF'})

    def test_complete_profile_rejects_partial_declared_selection(self):
        from verify_functional import verify
        report, policy = self.reviewed_skip_report()
        expected = report['provenance']['selected_cases'] + [case_spec('missing_required_test.py', [])]
        with self.assertRaisesRegex(ValueError, 'Complete declared'):
            verify(report, expected, ['v1', 'v2'], policy, {'OPTIONAL_FEATURE': 'OFF'})

    def test_complete_profile_rejects_all_skipped_transport(self):
        from verify_functional import verify
        report, policy = self.reviewed_skip_report()
        for row in report['results']:
            row.update(returncode=77, status='skipped', skip_reason='Disabled optional test feature')
        policy['cases']['wallet_multiwallet.py'] = policy['cases']['wallet_multiwallet.py --usecli']
        with self.assertRaisesRegex(ValueError, 'No passing functional'):
            verify(report, report['provenance']['selected_cases'], ['v1', 'v2'], policy, {'OPTIONAL_FEATURE': 'OFF'})

    def test_complete_profile_rejects_missing_required_transport(self):
        from verify_functional import verify
        report, policy = self.reviewed_skip_report()
        with self.assertRaisesRegex(ValueError, 'Complete declared'):
            verify(report, report['provenance']['selected_cases'], ['v1'], policy, {'OPTIONAL_FEATURE': 'OFF'})


if __name__ == '__main__':
    unittest.main()
