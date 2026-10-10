#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin PoCX developers
# Distributed under the MIT software license; see COPYING.
"""Reject prerequisite flags that are missing, misreported or change test selection."""
from copy import deepcopy
from pathlib import Path
from types import SimpleNamespace
import tempfile
from unittest.mock import patch
import json
import unittest

from functional_cases import case_spec, selection_digest
from functional_environment import PREVIOUS_RELEASES, arguments, release_binaries, verify_network_addresses
from functional_results import transport_results
from verify_functional import verify
from verify_functional import verify_current_inputs
from common import ROOT, sha256
from stage import stage
import functional_execution
import process_tree


class FunctionalEnvironmentTest(unittest.TestCase):
    def test_staging_and_verification_bind_configuration_binary_and_helpers(self):
        # Source staging and fake executable bytes exercise strict provenance.
        # No test process or functional case is counted as executed here.
        with tempfile.TemporaryDirectory(prefix='build-config-proof-', dir=ROOT) as scratch:
            build = Path(scratch)
            (build / 'test').mkdir()
            cache = (f'ENABLE_POCX:BOOL=ON\nCMAKE_HOME_DIRECTORY:INTERNAL={ROOT / "unused/.."}\n'
                     'CMAKE_CONFIGURATION_TYPES:STRING=Debug;Release\n')
            (build / 'CMakeCache.txt').write_text(cache)
            (build / 'test/config.ini').write_text('[environment]\n[components]\n')
            with patch('stage.subprocess.check_output', return_value='source-only-fixture'):
                with self.assertRaisesRegex(ValueError, 'require --config'):
                    stage(build)
                self.assertFalse((build / 'pocx-functional').exists())
                _, manifest, provenance = stage(build, selected_config='Release')
            paths = functional_execution.binary_paths(build, cache, 'Release')
            binaries = {}
            for name in ('bitcoind', 'bitcoin-cli'):
                path = paths[name]
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(b'fake executable, not a test run')
                binaries[name] = {'path': str(path), 'sha256': sha256(path)}
            provenance.update(format_version=8, binaries=binaries,
                execution_options=functional_execution.settings(),
                environment_profile={'previous_releases': False, 'network_addresses': False},
                previous_releases_directory=None, previous_release_binaries={},
                runner={'source': 'test/pocx/test_runner.py', 'sha256': sha256(ROOT / 'test/pocx/test_runner.py')})
            report = {'provenance': provenance}
            self.assertEqual(verify_current_inputs(report, build), manifest)
            controlled = deepcopy(report)
            controlled['provenance'].update(format_version=9, process_controller=process_tree.description())
            self.assertEqual(verify_current_inputs(controlled, build), manifest)
            for value in (None, dict(process_tree.description(), sha256='0' * 64)):
                broken = deepcopy(controlled)
                broken['provenance']['process_controller'] = value
                with self.subTest(controller=value), self.assertRaisesRegex(ValueError, 'process controller provenance'):
                    verify_current_inputs(broken, build)
            for selected in (None, 'Debug', 'Unknown'):
                broken = deepcopy(report)
                broken['provenance']['build_configuration'] = selected
                with self.subTest(selected=selected), self.assertRaises(ValueError):
                    verify_current_inputs(broken, build)
            for helper in provenance['staging_helpers']:
                broken = deepcopy(report)
                broken['provenance']['staging_helpers'].pop(helper)
                with self.subTest(helper=helper), self.assertRaisesRegex(ValueError, 'staging helper'):
                    verify_current_inputs(broken, build)
            for name in ('bitcoind', 'bitcoin-cli'):
                wrong = build / 'bin' / paths[name].name
                wrong.write_bytes(paths[name].read_bytes())
                broken = deepcopy(report)
                broken['provenance']['binaries'][name]['path'] = str(wrong)
                with self.subTest(name=name), self.assertRaisesRegex(ValueError, 'binary changed'):
                    verify_current_inputs(broken, build)
            broken = deepcopy(report)
            broken['provenance']['build_options']['ENABLE_IPC'] = 'ON'
            with self.assertRaisesRegex(ValueError, 'recorded features'):
                verify_current_inputs(broken, build)
            broken = deepcopy(report)
            broken['provenance']['binaries'].pop('bitcoin-cli')
            with self.assertRaisesRegex(ValueError, 'required functional binaries'):
                verify_current_inputs(broken, build)
            paths['bitcoin-util'].write_bytes(b'optional tool added after execution')
            with self.assertRaisesRegex(ValueError, 'executable inventory changed'):
                verify_current_inputs(report, build)

    def test_current_input_verification_includes_owned_framework_additions(self):
        # Real source staging, synthetic build metadata only; no functional
        # runtime pass is inferred from this infrastructure check.
        with tempfile.TemporaryDirectory(prefix='build-source-proof-', dir=ROOT) as scratch:
            build = Path(scratch)
            (build / 'test').mkdir()
            (build / 'CMakeCache.txt').write_text(
                f'ENABLE_POCX:BOOL=ON\nCMAKE_HOME_DIRECTORY:INTERNAL={ROOT}\n')
            (build / 'test/config.ini').write_text('[environment]\n[components]\n')
            with patch('stage.subprocess.check_output', return_value='source-only-fixture'):
                _, manifest, provenance = stage(build)
            provenance.update(binaries={}, runner={
                'source': 'test/pocx/test_runner.py',
                'sha256': sha256(ROOT / 'test/pocx/test_runner.py')})
            report = {'provenance': provenance}
            self.assertTrue(manifest['framework_additions'])
            self.assertEqual(verify_current_inputs(report, build), manifest)
            for name in manifest['framework_additions']:
                changed = deepcopy(report)
                changed['provenance']['files'].pop(name)
                with self.subTest(name=name), self.assertRaisesRegex(ValueError, 'source/resource snapshot'):
                    verify_current_inputs(changed, build)
                changed = deepcopy(report)
                changed['provenance']['files'][name]['sha256'] = 'stale'
                with self.subTest(name=name), self.assertRaisesRegex(ValueError, 'source/resource snapshot'):
                    verify_current_inputs(changed, build)

    def report(self, test='feature_bind_port_discover.py'):
        spec = case_spec(test, [])
        profile = {'previous_releases': True, 'network_addresses': True}
        rows = []
        for mode in ('v1', 'v2'):
            flags = arguments(test, profile) + [f'--{mode}transport']
            rows.append({'test': test, 'case': spec['id'], 'case_arguments': [], 'transport': mode,
                         'test_arguments': flags, 'command': ['python3', test, *flags],
                         'returncode': 0, 'timed_out': False, 'status': 'passed'})
        return {'provenance': {'format_version': 5, 'selected_tests': [test], 'selected_cases': [spec],
                              'transport_modes': ['v1', 'v2'], 'environment_profile': profile,
                              'case_selection': {'selected_cases_sha256': selection_digest([spec])}},
                'results': rows}

    def test_prerequisites_keep_original_case_identity_and_both_transports(self):
        report = self.report()
        self.assertEqual(len(transport_results(report)), 2)
        self.assertTrue(all(row['case'] == 'feature_bind_port_discover.py' for row in report['results']))
        self.assertEqual(arguments('p2p_ping.py', report['provenance']['environment_profile']),
                         ['--previous-releases'])
        self.assertEqual(arguments('feature_bind_port_externalip.py', report['provenance']['environment_profile']),
                         ['--previous-releases', '--ihave1111'])

    def test_missing_or_false_prerequisite_attestation_is_rejected(self):
        for change in ('missing_flag', 'false_profile', 'extra_flag', 'unknown_feature'):
            report = self.report()
            if change == 'missing_flag':
                report['results'][0]['command'].remove('--ihave1111and2222')
            elif change == 'false_profile':
                report['provenance']['environment_profile']['network_addresses'] = False
            elif change == 'extra_flag':
                report['results'][0]['command'].append('--skip-required-assertions')
            else:
                report['provenance']['environment_profile']['exclude_tests'] = True
            with self.subTest(change=change), self.assertRaises(ValueError):
                transport_results(report)

    def test_address_profile_rejects_down_or_loopback_only_prerequisites(self):
        for flags in (['LOOPBACK', 'UP'], [], ['UP']):
            interfaces = [{'flags': flags, 'addr_info': [{'local': '1.1.1.1'}, {'local': '2.2.2.2'}]}]
            with self.subTest(flags=flags), patch('functional_environment.subprocess.check_output', return_value=json.dumps(interfaces)):
                if flags == ['UP']:
                    self.assertEqual(verify_network_addresses(), interfaces)
                else:
                    with self.assertRaisesRegex(ValueError, 'up, non-loopback'):
                        verify_network_addresses()

    def test_previous_release_prerequisites_require_every_binary(self):
        with tempfile.TemporaryDirectory() as scratch:
            root = Path(scratch)
            for version in PREVIOUS_RELEASES:
                (root / version / 'bin').mkdir(parents=True)
                for name in ('bitcoind', 'bitcoin-cli'):
                    (root / version / 'bin' / name).write_bytes(b'verified elsewhere')
            with self.assertRaisesRegex(ValueError, 'bitcoin-wallet'):
                release_binaries(root)
            (root / 'v28.2/bin/bitcoin-wallet').write_bytes(b'verified elsewhere')
            self.assertEqual(len(release_binaries(root)), 17)
            (root / 'v28.2/bin/bitcoin-cli').unlink()
            with self.assertRaisesRegex(ValueError, 'Missing required previous-release binary'):
                release_binaries(root)

    def test_windows_previous_releases_require_exe_files_and_keep_logical_names(self):
        with tempfile.TemporaryDirectory() as scratch:
            root = Path(scratch)
            for version in PREVIOUS_RELEASES:
                (root / version / 'bin').mkdir(parents=True)
                names = ('bitcoind', 'bitcoin-cli', 'bitcoin-wallet') if version == 'v28.2' else ('bitcoind', 'bitcoin-cli')
                for name in names:
                    (root / version / 'bin' / name).write_bytes(b'wrong-platform binary')
                    (root / version / 'bin' / (name + '.exe')).write_bytes(b'Windows prerequisite fixture')
            # Patch only this module's platform input, leaving pathlib native.
            with patch('functional_environment.os', SimpleNamespace(name='nt')):
                paths = release_binaries(root)
                self.assertEqual(len(paths), 17)
                self.assertEqual(paths['v28.2/bitcoin-wallet'], root / 'v28.2/bin/bitcoin-wallet.exe')
                self.assertTrue(all(path.suffix == '.exe' for path in paths.values()))
                (root / 'v28.2/bin/bitcoin-wallet.exe').unlink()
                with self.assertRaisesRegex(ValueError, 'bitcoin-wallet.exe'):
                    release_binaries(root)

    def test_required_profile_rejects_even_previously_reviewed_skip(self):
        report = self.report()
        for row in report['results']:
            row.update(status='skipped', returncode=77, skip_reason='optional feature unavailable')
        policy = {'cases': {'feature_bind_port_discover.py': {'reasons': ['optional feature unavailable']}}}
        with self.assertRaisesRegex(ValueError, 'Required functional feature was skipped'):
            verify(report, report['provenance']['selected_cases'], ['v1', 'v2'], policy, {}, require_no_skips=True)

    def test_historical_reports_do_not_gain_unrecorded_prerequisites(self):
        report = self.report('p2p_ping.py')
        report['provenance']['format_version'] = 4
        with self.assertRaises(ValueError):
            transport_results(report)
        for row in report['results']:
            row['test_arguments'].remove('--previous-releases')
            row['command'].remove('--previous-releases')
        self.assertEqual(len(transport_results(report)), 2)

    def test_timeout_scaling_is_attested_without_changing_case_identity(self):
        report = self.report('p2p_ping.py')
        report['provenance'].update(format_version=6, timeout_factor=40.0)
        for row in report['results']:
            row['test_arguments'].insert(-1, '--timeout-factor=40.0')
            row['command'].insert(-1, '--timeout-factor=40.0')
        self.assertEqual(len(transport_results(report)), 2)
        self.assertEqual(report['provenance']['selected_cases'], [case_spec('p2p_ping.py', [])])
        for value in (0, -1, float('inf'), float('nan'), True, '40', None):
            changed = deepcopy(report)
            changed['provenance']['timeout_factor'] = value
            with self.subTest(value=value), self.assertRaises(ValueError):
                transport_results(changed)
        changed = deepcopy(report)
        changed['results'][0]['command'].remove('--timeout-factor=40.0')
        with self.assertRaises(ValueError):
            transport_results(changed)
        report['provenance']['format_version'] = 5
        with self.assertRaisesRegex(ValueError, 'unrecorded timeout'):
            transport_results(report)


if __name__ == '__main__':
    unittest.main()
