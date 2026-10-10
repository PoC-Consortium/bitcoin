#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin PoCX developers
# Distributed under the MIT software license; see COPYING.
"""Producer/publication/workflow checks; synthetic PE files are not test passes."""
from copy import deepcopy
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import yaml

from common import ROOT, sha256
import inherited_ci
import test_windows_artifacts
import windows_artifacts
import windows_cross as cross


class WindowsCrossTest(unittest.TestCase):
    def setUp(self):
        self.helper = test_windows_artifacts.WindowsArtifactsTest()
        inventory = patch.object(windows_artifacts.unit_matrix, 'inventory', side_effect=self.helper.inventory)
        inventory.start()
        self.addCleanup(inventory.stop)

    def fixture(self, directory):
        root, builds, _ = self.helper.fixture(directory)
        pairs = [{'consensus': consensus, 'command': ['synthetic-build-recipe'], 'environment': {
            'HOST': 'x86_64-w64-mingw32', 'BASE_BUILD_DIR': str(build), 'BASE_OUTDIR': str(build / 'out'),
            'RUN_UNIT_TESTS': 'false', 'RUN_FUNCTIONAL_TESTS': 'false'}}
            for consensus, build in zip(('bitcoin', 'pocx'), builds)]
        return root, builds, pairs, root / 'scratch/execution'

    def recipe_context(self):
        return patch.object(windows_artifacts, 'verify_recipe', return_value={'scope': 'synthetic fixture review bypass only'})

    def test_both_crt_plans_keep_original_settings_and_explicit_runtime_deferral(self):
        for host in sorted(cross.HOSTS):
            env = {'BASE_ROOT_DIR': str(ROOT), 'BASE_SCRATCH_DIR': str(ROOT / 'build-cross-fixture'),
                'BASE_OUTDIR': str(ROOT / 'build-cross-fixture/out'), 'HOST': host, 'GOAL': 'deploy',
                'RUN_UNIT_TESTS': 'false', 'RUN_FUNCTIONAL_TESTS': 'false',
                'BITCOIN_CONFIG': '--preset=dev-mode -DENABLE_IPC=OFF -DWITH_USDT=OFF -DREDUCE_EXPORTS=ON'}
            pairs = inherited_ci.plan(env)
            self.assertTrue(cross.is_cross_pair(pairs))
            self.assertNotEqual(pairs[0]['environment']['BASE_BUILD_DIR'], pairs[1]['environment']['BASE_BUILD_DIR'])
            for row, enabled in zip(pairs, ('OFF', 'ON')):
                self.assertIn('-DENABLE_POCX=' + enabled, row['environment']['BITCOIN_CONFIG'])
                for key in ('HOST', 'GOAL', 'RUN_UNIT_TESTS', 'RUN_FUNCTIONAL_TESTS'):
                    self.assertEqual(row['environment'][key], env[key])
            mismatched = deepcopy(pairs)
            mismatched[1]['environment']['HOST'] = 'x86_64-w64-mingw32-unknown'
            with self.assertRaises(ValueError):
                cross.is_cross_pair(mismatched)

    def test_real_export_and_publication_preserve_exact_paired_payload(self):
        with tempfile.TemporaryDirectory() as directory, self.recipe_context():
            root, _, pairs, output = self.fixture(directory)
            report = cross.export(pairs, output, root=root, revision='a' * 40)
            self.assertEqual(report['actual_windows_cases_executed'], 0)
            self.assertEqual(report['phases'], ['bitcoin', 'pocx'])
            source = output / cross.BUNDLE_DIRECTORY
            target = root / 'published' / cross.PUBLISHED_DIRECTORY
            cross.publish(source, target, root=root, revision='a' * 40)
            self.assertEqual(windows_artifacts.verify_pair(source, root=root, revision='a' * 40),
                             windows_artifacts.verify_pair(target, root=root, revision='a' * 40))
            self.assertEqual(report['pair_sha256'], sha256(target / 'pair.json'))
            with self.assertRaises(ValueError):
                cross.publish(source, target, root=root, revision='a' * 40)

    def test_inherited_controller_exports_before_container_cleanup_and_publishes_one_payload_copy(self):
        with tempfile.TemporaryDirectory() as directory, self.recipe_context(), \
                patch.object(windows_artifacts, 'revision_id', return_value='a' * 40):
            root, _, pairs, output = self.fixture(directory)
            calls = []
            def recipe(command, **kwargs):
                calls.append(command)
                kwargs['stdout'].write('Synthetic cross compiler callback\n')
                return subprocess.CompletedProcess(command, 0)
            report = inherited_ci.execute(pairs, output, root=root, run=recipe)
            self.assertEqual(report['status'], 'passed')
            self.assertEqual(len(calls), 2)
            self.assertIn('target-host baseline still required', report['native_execution'])
            self.assertEqual(report['windows_artifacts']['actual_windows_cases_executed'], 0)
            destination = inherited_ci.publish(output, root)
            published = destination.parent / cross.PUBLISHED_DIRECTORY
            windows_artifacts.verify_pair(published, root=root, revision='a' * 40)
            self.assertFalse((destination / cross.BUNDLE_DIRECTORY).exists())
            self.assertTrue((destination / 'bitcoin.log').is_file())
            self.assertTrue((destination / 'pocx.log').is_file())
            self.assertTrue(all(path.stat().st_mode & 0o4 for path in published.rglob('*') if path.is_file()))

    def test_failed_original_or_native_build_never_exports_a_pair(self):
        for codes in ((9,), (0, 9)):
            with self.subTest(codes=codes), tempfile.TemporaryDirectory() as directory, self.recipe_context():
                root, _, pairs, output = self.fixture(directory)
                statuses = iter(codes)
                calls = []
                def recipe(command, **kwargs):
                    calls.append(command)
                    return subprocess.CompletedProcess(command, next(statuses))
                with self.assertRaises(ValueError):
                    inherited_ci.execute(pairs, output, root=root, run=recipe)
                self.assertEqual(len(calls), len(codes))
                self.assertFalse((output / cross.BUNDLE_DIRECTORY).exists())
                report = json.loads((output / 'results.json').read_text())
                self.assertEqual(report['status'], 'failed')
                if len(codes) == 1:
                    self.assertEqual(report['native_execution'], 'deferred')

    def test_incomplete_export_and_target_execution_flags_fail_the_producer(self):
        with tempfile.TemporaryDirectory() as directory, self.recipe_context(), \
                patch.object(windows_artifacts, 'revision_id', return_value='a' * 40):
            root, builds, pairs, output = self.fixture(directory)
            (builds[1] / 'bin/test_pocx.exe').unlink()
            with self.assertRaises(ValueError):
                inherited_ci.execute(pairs, output, root=root,
                run=lambda command, **kwargs: subprocess.CompletedProcess(command, 0))
            self.assertFalse((output / cross.BUNDLE_DIRECTORY).exists())
            self.assertEqual(json.loads((output / 'results.json').read_text())['status'], 'failed')
            pairs[0]['environment']['RUN_UNIT_TESTS'] = 'true'
            with self.assertRaisesRegex(ValueError, 'defer'):
                cross.export(pairs, root / 'other', root=root)

    def test_runtime_collection_retains_failure_proofs_without_binaries_caches_or_node_data(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / 'runtime'
            retained = ['results.json', 'cases.csv', 'bitcoin/version.log', 'bitcoin/bitcoind.manifest',
                'bitcoin/frameworks/results.json', 'bitcoin/frameworks/unit/boost.xml',
                'bitcoin/functional/execution/v1.csv', 'bitcoin/functional/execution/v1-legacy-utxo.log',
                'pocx/functional/runtime/CMakeCache.txt', 'pocx/functional/runtime/test/config.ini',
                'pocx/functional/runtime/artifact-functional-view.json',
                'pocx/functional/runtime/pocx-results-fixture/results.json',
                'pocx/functional/runtime/pocx-results-fixture/p2p_ping.py.log',
                'pocx/functional/runtime/pocx-results-fixture/v2/p2p_ping.py.log']
            ignored = ['bitcoin/functional/runtime/bin/bitcoind.exe',
                'bitcoin/functional/execution/legacy-utxo-v1/node0/regtest/state.json',
                'pocx/functional/runtime/pocx-results-fixture/p2p_ping/node0/regtest/state.json',
                'pocx/functional/runtime/pocx-results-fixture/cache/state.json']
            for name in retained + ignored:
                path = source / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text('Retained failure fixture\n')
            output = root / 'evidence'
            report = cross.collect_runtime(source, output)
            self.assertTrue(report['runtime_started'])
            self.assertEqual(set(report['files']), set(retained))
            self.assertEqual(set(path.relative_to(output).as_posix() for path in output.rglob('*') if path.is_file()),
                             set(retained) | {'collection.json'})
            self.assertTrue(all(sha256(source / name) == sha256(output / name) == digest for name, digest in report['files'].items()))

    def test_runtime_collection_records_not_started_and_rejects_symlinks_or_overwrite(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            report = cross.collect_runtime(root / 'missing', root / 'empty-evidence')
            self.assertFalse(report['runtime_started'])
            self.assertEqual(report['files'], {})
            source = root / 'runtime'
            source.mkdir()
            (source / 'results.json').symlink_to(root / 'empty-evidence/collection.json')
            with self.assertRaises(ValueError):
                cross.collect_runtime(source, root / 'bad-evidence')
            with self.assertRaises(ValueError):
                cross.collect_runtime(source, root / 'empty-evidence')

    def test_workflow_pairs_frozen_crt_artifacts_and_runs_owned_complete_consumer(self):
        document = yaml.safe_load((ROOT / '.github/workflows/ci.yml').read_text())
        producer = document['jobs']['windows-cross']
        consumer = document['jobs']['windows-native-test']
        self.assertEqual(producer['strategy']['matrix']['crt'], ['msvcrt', 'ucrt'])
        self.assertEqual(producer['strategy']['matrix'], {'crt': ['msvcrt', 'ucrt'], 'include': [
            {'crt': 'msvcrt', 'file-env': './ci/test/00_setup_env_win64_msvcrt.sh', 'artifact-name': 'x86_64-w64-mingw32-bitcoin-pocx-tests'},
            {'crt': 'ucrt', 'file-env': './ci/test/00_setup_env_win64.sh', 'artifact-name': 'x86_64-w64-mingw32ucrt-bitcoin-pocx-tests'}]})
        self.assertEqual({row['crt']: row['artifact-name'] for row in producer['strategy']['matrix']['include']},
                         {row['crt']: row['artifact-name'] for row in consumer['strategy']['matrix']['include']})
        for job in (producer, consumer):
            checkout = next(step for step in job['steps'] if step.get('uses', '').startswith('actions/checkout@'))
            self.assertEqual(checkout['with']['ref'], '${{ needs.record-frozen-commit.outputs.commit }}')
            self.assertEqual(job['env']['GIT_CONFIG_KEY_0'], 'core.autocrlf')
            self.assertEqual(job['env']['GIT_CONFIG_VALUE_0'], 'false')
        upload = next(step for step in producer['steps'] if step.get('name') == 'Upload verified Bitcoin and PoCX cross-build pair')
        download = next(step for step in consumer['steps'] if step.get('uses', '').startswith('actions/download-artifact@'))
        self.assertEqual(upload['with']['name'], download['with']['name'])
        self.assertEqual(upload['with']['path'], 'artifacts/pocx-inherited/' + cross.PUBLISHED_DIRECTORY)
        self.assertEqual(upload['with']['if-no-files-found'], 'error')
        self.assertEqual(download['with']['path'], 'artifacts/windows-cross-pair')
        commands = '\n'.join(step.get('run', '') for step in consumer['steps'])
        self.assertNotIn('.github/ci-windows-cross.py', commands)
        self.assertIn('windows_artifacts.py --verify artifacts/windows-cross-pair', commands)
        self.assertIn('windows_artifact_ci.py --artifacts artifacts/windows-cross-pair', commands)
        self.assertIn('get_previous_releases.py --target-dir', commands)
        self.assertEqual(consumer['env']['PREVIOUS_RELEASES_DIR'], '${{ github.workspace }}/prev_releases')
        for step in consumer['steps']:
            if '$env:' in step.get('run', ''):
                self.assertEqual(step.get('shell'), 'pwsh')
        runtime = next(step for step in consumer['steps'] if 'windows_artifact_ci.py' in step.get('run', ''))
        self.assertIn('--extended', runtime['env']['TEST_RUNNER_EXTRA'])
        collector = next(step for step in consumer['steps'] if 'windows_cross.py --collect-runtime' in step.get('run', ''))
        evidence = next(step for step in consumer['steps'] if step.get('uses', '').startswith('actions/upload-artifact@'))
        self.assertEqual(collector['if'], 'always()')
        self.assertEqual(evidence['if'], 'always()')
        self.assertEqual(evidence['with']['path'], 'artifacts/windows-cross-evidence')


if __name__ == '__main__':
    unittest.main()
