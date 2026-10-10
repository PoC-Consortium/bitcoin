#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin PoCX developers
# Distributed under the MIT software license; see COPYING.
"""Reject optional CI success with incomplete inventories or skipped cases.

Synthetic CSV/JSON fixtures below test evidence rejection, not runtime parity.
"""
from copy import deepcopy
import csv
import json
from pathlib import Path
import tempfile
import unittest

from common import ROOT, sha256
from ci import options, validate_build
from ci_evidence import required_steps, verify_required_functional
from functional_cases import selected_cases, upstream_cases
from run_bitcoin_functional import ADDRESS_TESTS, case_groups, effective_transport, expected_cases, read_cases, runner_arguments, verify_cases


class RequiredFunctionalTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name)

    def write_csv(self, rows):
        path = self.directory / 'results.csv'
        with path.open('w', newline='') as stream:
            writer = csv.writer(stream)
            writer.writerow(['test', 'status', 'duration(seconds)'])
            writer.writerows(rows)
        return path

    def test_all_upstream_variants_extended_and_benchmarks_are_required(self):
        source = ROOT / 'test/functional/test_runner.py'
        benchmarks = ['BenchOne', 'BenchTwo']
        cases = expected_cases(source, benchmarks)
        upstream = upstream_cases(source)
        self.assertEqual(len(cases), len(upstream) - 1 + len(benchmarks))
        self.assertTrue({row['upstream_case'] for row in upstream if row['selection'] == 'EXTENDED_SCRIPTS'}.issubset(cases))
        self.assertIn('tool_bench_sanity_check.py --bench=BenchOne', cases)
        self.assertIn('p2p_node_network_limited.py --v2transport', cases)
        self.assertIn('p2p_node_network_limited.py --v1transport', cases)
        groups = case_groups(cases)
        self.assertEqual(sorted(case for _, group, _ in groups for case in group), sorted(cases))

    def test_empty_duplicate_and_malformed_benchmark_inventory_rejected(self):
        for names in ([], ['A', 'A'], [''], ['A --skip'], ['A\nB']):
            with self.subTest(names=names), self.assertRaisesRegex(ValueError, 'benchmark inventory'):
                expected_cases(ROOT / 'test/functional/test_runner.py', names)

    def test_effective_transport_respects_unchanged_upstream_flag_precedence(self):
        self.assertEqual(effective_transport('a.py --v1transport', 'v2'), 'v1')
        self.assertEqual(effective_transport('a.py --v2transport', 'v1'), 'v1')
        self.assertEqual(effective_transport('a.py --v2transport', 'v2'), 'v2')
        self.assertEqual(effective_transport('a.py', 'v2'), 'v2')

    def test_group_commands_preserve_full_runner_and_isolate_address_flags(self):
        for mode in ('v1', 'v2'):
            for group in (None, *ADDRESS_TESTS):
                command = runner_arguments(Path('/staged/test_runner.py'), group, 4,
                                           self.directory, self.directory / 'results.csv', mode)
                self.assertIn(f'--{mode}transport', command)
                self.assertIn('--previous-releases', command)
                if group is None:
                    self.assertIn('--extended', command)
                    self.assertIn('--exclude=feature_bind_port_discover.py', command)
                    self.assertIn('--exclude=feature_bind_port_externalip.py', command)
                    self.assertNotIn('--ihave1111', command)
                    self.assertNotIn('--ihave1111and2222', command)
                else:
                    self.assertEqual(command[-1], group)
                    self.assertNotIn('--extended', command)
                    flag = '--ihave1111and2222' if group == ADDRESS_TESTS[0] else '--ihave1111'
                    self.assertIn(flag, command)

    def test_original_asan_invocations_retain_timeout_scaling(self):
        for group in (None, *ADDRESS_TESTS):
            command = runner_arguments(Path('/staged/test_runner.py'), group, 4,
                                       self.directory, self.directory / 'results.csv', 'v2', 40)
            self.assertIn('--timeout-factor=40', command)
        for value in (0, -1, float('inf'), float('nan'), True):
            with self.subTest(value=value), self.assertRaises(ValueError):
                runner_arguments(Path('/runner'), None, 4, self.directory, self.directory / 'r.csv', 'v1', value)

    def test_pass_requires_every_case_and_one_terminal_summary(self):
        path = self.write_csv([['a.py', 'Passed', '1'], ['b.py --argument', 'Passed', '0'], ['ALL', 'Passed', '1']])
        rows, summary = read_cases(path, ['a.py', 'b.py --argument'])
        verify_cases(rows, summary, 0)
        for replacement in (['a.py'], ['a.py', 'a.py'], ['a.py', 'b.py --argument', 'c.py']):
            with self.subTest(replacement=replacement), self.assertRaisesRegex(ValueError, 'Missing, duplicate or unexpected'):
                read_cases(path, replacement)
        for bad in ([['a.py', 'Passed', '1']],
                    [['ALL', 'Passed', '1'], ['a.py', 'Passed', '1']],
                    [['a.py', 'Passed', '1'], ['ALL', 'Passed', '1'], ['ALL', 'Passed', '1']]):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                read_cases(self.write_csv(bad), ['a.py'])

    def test_green_all_and_zero_exit_cannot_hide_skips_or_failures(self):
        for status, code, overall in [('Skipped', 0, 'Passed'), ('Failed', 0, 'Passed'),
                                      ('Passed', 1, 'Passed'), ('Passed', 0, 'Failed')]:
            rows, summary = read_cases(self.write_csv([['a.py', status, '0'], ['ALL', overall, '0']]), ['a.py'])
            with self.subTest(status=status, code=code), self.assertRaisesRegex(ValueError, 'failed or skipped'):
                verify_cases(rows, summary, code)

    def test_unknown_status_or_invalid_duration_rejected(self):
        for status, duration in [('Unknown', '1'), ('Passed', 'nan'), ('Passed', '-1'), ('Passed', 'infinity')]:
            with self.subTest(status=status, duration=duration), self.assertRaises(ValueError):
                read_cases(self.write_csv([['a.py', status, duration], ['ALL', 'Passed', '0']]), ['a.py'])

    def test_optional_build_requires_all_tools_tracing_and_messaging(self):
        for profile in ('bitcoin-functional-optional', 'pocx-functional-optional'):
            expected = options(profile)
            self.assertEqual(expected['ENABLE_POCX'], 'OFF' if profile.startswith('bitcoin-') else 'ON')
            path = self.directory / 'CMakeCache.txt'
            def write(values):
                path.write_text(f'CMAKE_HOME_DIRECTORY:INTERNAL={ROOT}\n' +
                                ''.join(f'{key}:STRING={value}\n' for key, value in values.items()))
            write(expected)
            validate_build(self.directory, profile)
            for key in ('WITH_USDT', 'WITH_ZMQ', 'BUILD_BENCH', 'BUILD_UTIL_CHAINSTATE',
                        'BUILD_KERNEL_LIB', 'BUILD_BITCOIN_BIN', 'BUILD_DAEMON', 'BUILD_CLI',
                        'BUILD_TX', 'BUILD_UTIL', 'BUILD_WALLET_TOOL', 'ENABLE_IPC', 'ENABLE_WALLET'):
                write({**expected, key: 'OFF'})
                with self.subTest(profile=profile, key=key), self.assertRaisesRegex(ValueError, 'Wrong CI build profile'):
                    validate_build(self.directory, profile)
            self.assertEqual(required_steps(profile, True), ['drift', 'functional'])
            self.assertEqual(required_steps(profile, False), ['drift', 'configure', 'build', 'functional'])

    def child_proof(self, native):
        proof_path = self.directory / 'functional-verification.json'
        profile = ('pocx' if native else 'bitcoin') + '-functional-optional'
        script = 'verify_functional.py' if native else 'run_bitcoin_functional.py'
        command = ['python3', str(ROOT / 'test/pocx' / script), '--output', str(proof_path)]
        report = {'profile': profile, 'functional_transports': ['v1', 'v2'],
                  'steps': [{'name': 'functional', 'command': command}]}
        child = {'status': 'passed', 'required_no_skips': True}
        if native:
            manifest = json.loads((ROOT / 'test/pocx/manifest.json').read_text())
            count = len(selected_cases(manifest, upstream_cases(ROOT / 'test/functional/test_runner.py')))
            child.update(counts_by_transport={mode: {'passed': count} for mode in ('v1', 'v2')}, skips=[])
            command += ['--require-no-skips', '--previous-releases', '--previous-releases-dir',
                        '/verified/releases', '--network-addresses', '--transport', 'matrix']
        else:
            cases = expected_cases(ROOT / 'test/functional/test_runner.py', ['BenchOne'])
            child.update(expected_cases=cases, benchmarks=['BenchOne'], transport_modes=['v1', 'v2'],
                         cases=[{'case': case, 'requested_transport': mode,
                                 'transport': effective_transport(case, mode), 'status': 'passed'}
                                for case in cases for mode in ('v1', 'v2')])
        return report, child

    def save_child(self, report, child):
        path = self.directory / 'functional-verification.json'
        path.write_text(json.dumps(child))
        report['artifacts'] = {str(path): sha256(path)}

    def test_required_profile_proof_rejects_skip_policy_or_single_transport(self):
        for native in (False, True):
            report, child = self.child_proof(native)
            self.save_child(report, child)
            proof = verify_required_functional(ROOT, report, self.directory)
            self.assertEqual(proof['transports'], ['v1', 'v2'])
            for changed in ({'required_no_skips': False}, {'status': 'failed'}):
                self.save_child(report, {**child, **changed})
                with self.subTest(native=native, changed=changed), self.assertRaises(ValueError):
                    verify_required_functional(ROOT, report, self.directory)
            self.save_child(report, child)
            report['functional_transports'] = ['v1']
            with self.assertRaisesRegex(ValueError, 'both transports'):
                verify_required_functional(ROOT, report, self.directory)

    def test_required_native_proof_rejects_missing_flags_and_partial_counts(self):
        report, child = self.child_proof(True)
        self.save_child(report, child)
        for flag in ('--require-no-skips', '--previous-releases', '--network-addresses', '--previous-releases-dir'):
            changed = deepcopy(report)
            changed['steps'][0]['command'].remove(flag)
            with self.subTest(flag=flag), self.assertRaises(ValueError):
                verify_required_functional(ROOT, changed, self.directory)
        child['counts_by_transport']['v1']['passed'] -= 1
        self.save_child(report, child)
        with self.assertRaises(ValueError):
            verify_required_functional(ROOT, report, self.directory)

    def test_required_original_proof_rejects_missing_duplicate_and_skipped_rows(self):
        report, child = self.child_proof(False)
        for variant in ('missing', 'duplicate', 'skipped', 'wrong_transport'):
            changed = deepcopy(child)
            if variant == 'missing':
                changed['cases'].pop()
            elif variant == 'duplicate':
                changed['cases'].append(changed['cases'][0])
            elif variant == 'skipped':
                changed['cases'][0]['status'] = 'skipped'
            else:
                changed['cases'][0]['transport'] = 'v2'
            self.save_child(report, changed)
            with self.subTest(variant=variant), self.assertRaises(ValueError):
                verify_required_functional(ROOT, report, self.directory)


if __name__ == '__main__':
    unittest.main()
