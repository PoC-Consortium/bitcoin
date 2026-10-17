#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin PoCX developers
# Distributed under the MIT software license; see COPYING.
"""Product isolation, inherited scope and artifact rejection checks; no runtime claims."""
import importlib.util
import json
import os
import shutil
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

import yaml

import ci_product
from common import ROOT
import inherited_ci
import revision_ci
import windows_ci
import windows_artifacts
import windows_cross
import test_windows_artifacts
import test_windows_artifact_ci
import test_windows_ci


def workflow(name):
    document = yaml.safe_load((ROOT / '.github/workflows' / name).read_text())
    document['on'] = document.pop(True, document.get('on', {}))
    return document


class ProductWorkflowsTest(unittest.TestCase):
    def test_only_two_triggered_workflows_select_independent_products(self):
        documents = {p.name: workflow(p.name) for p in (ROOT / '.github/workflows').glob('*.yml')}
        self.assertEqual(set(documents), {'ci.yml', 'ci-pocx.yml', 'ci-product.yml'})
        for name, product, title in [('ci.yml', 'bitcoin', 'CI'), ('ci-pocx.yml', 'pocx', 'CI-POCX')]:
            document = documents[name]
            self.assertEqual(document['name'], title)
            self.assertEqual(set(document['on']), {'push', 'pull_request', 'schedule', 'workflow_dispatch'})
            self.assertEqual(document['on']['schedule'], [{'cron': '19 2 * * 1'}])
            self.assertEqual(set(document['jobs']), {'product'})
            job = document['jobs']['product']
            self.assertEqual(job['uses'], './.github/workflows/ci-product.yml')
            self.assertEqual(job['with']['product'], product)
            self.assertNotIn('needs', job)
            self.assertIn('github.workflow', document['concurrency']['group'])
        shared = documents['ci-product.yml']
        self.assertEqual(set(shared['on']), {'workflow_call'})
        self.assertEqual(shared['env']['CI_PRODUCT'], '${{ inputs.product }}')
        self.assertNotIn('concurrency', shared)

    def test_complete_inherited_platform_matrix_and_cadence_remain(self):
        jobs = workflow('ci-product.yml')['jobs']
        matrix = jobs['ci-matrix']['strategy']['matrix']['include']
        names = ['native_iwyu', 'arm', 'i686_no_ipc', 'native_asan', 'mac_cross',
                 'mac_cross_intel', 'native_nowallet', 'native_previous_releases',
                 'native_alpine_musl', 'native_tidy', 'native_tsan', 'native_msan']
        self.assertEqual([row['file-env'] for row in matrix],
                         ['./ci/test/00_setup_env_' + name + '.sh' for name in names])
        self.assertTrue(all(row['timeout-minutes'] == 120 for row in matrix))
        arm = matrix[1]
        self.assertEqual((arm['fallback-runner'], arm['warp-runner'], arm['provider']),
                         ('ubuntu-24.04-arm', 'ubuntu-24.04-arm', 'gha'))
        for job, runner in [('macos-native-arm64', 'macos-15'),
                            ('windows-native-dll', 'windows-2025-vs2026'),
                            ('windows-native-test', 'windows-2022')]:
            self.assertEqual(jobs[job]['runs-on'], runner)
        for job in ('runners', 'ci-matrix', 'macos-native-arm64', 'windows-native-dll',
                    'windows-cross', 'windows-native-test', 'lint'):
            self.assertIn("github.event_name != 'schedule'", jobs[job]['if'])
        for job in ('linux-features', 'optional-functional', 'asan', 'instrumented-sanitizers'):
            self.assertIn("github.event_name == 'schedule'", jobs[job]['if'])
            self.assertIn("github.event_name == 'workflow_dispatch'", jobs[job]['if'])
            self.assertNotIn('bitcoin-core', jobs[job].get('needs', []))
        core = jobs['linux-core']
        self.assertNotIn('strategy', core)
        commands = '\n'.join(step.get('run', '') for step in core['steps'])
        self.assertIn('--profile \"$CI_PRODUCT-unit\"', commands)
        self.assertIn('--profile \"$CI_PRODUCT-functional\"', commands)
        self.assertEqual(commands.count('--build-dir \"$CI_BUILD\"'), 2)
        self.assertIn('--skip-build', commands)
        self.assertEqual(jobs['linux-features']['strategy']['matrix']['profile'],
                         ['qt', 'wallet-disabled', 'ipc-disabled', 'kernel'])
        self.assertEqual(jobs['instrumented-sanitizers']['strategy']['matrix']['sanitizer'], ['tsan', 'msan'])
        self.assertNotIn('pocx-core', jobs)
        self.assertIn('Skipped jobs are not passing execution evidence', str(jobs['scope-summary']))

    def test_product_selection_survives_container_and_privilege_boundaries(self):
        spec = importlib.util.spec_from_file_location('product_container', ROOT / 'ci/test/02_run_container.py')
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        tree = (ROOT / 'ci/test/02_run_container.py').read_text()
        self.assertIn('"CI_PRODUCT",', tree)
        self.assertEqual(module.test_script('/root', {}), ['python3', '/root/test/pocx/inherited_ci.py'])
        jobs = workflow('ci-product.yml')['jobs']
        for name in ('test-each-commit', 'optional-functional', 'asan', 'instrumented-sanitizers'):
            commands = '\n'.join(step.get('run', '') for step in jobs[name]['steps'])
            self.assertIn('sudo env CI_PRODUCT=', commands)
        # Historical executors do not understand the new environment selector;
        # their existing explicit phase option must also be passed.
        self.assertIn('--phase-consensus', str(jobs['test-each-commit']['steps']))

    def test_posix_windows_and_revision_plans_select_exactly_one_product(self):
        environment = {'BASE_ROOT_DIR': str(ROOT), 'BASE_SCRATCH_DIR': str(ROOT / 'build-product-fixture'),
                       'BASE_OUTDIR': str(ROOT / 'build-product-fixture/out'), 'HOST': 'x86_64-pc-linux-gnu',
                       'BITCOIN_CONFIG': '--preset=dev-mode -DENABLE_WALLET=OFF -DSANITIZERS=thread'}
        for product, enabled in ci_product.PRODUCTS.items():
            env = dict(environment, CI_PRODUCT=product)
            for rows in (inherited_ci.plan(env), windows_ci.plan(2, env), revision_ci.plan(2, env)):
                self.assertEqual([row['consensus'] for row in rows], [product])
                self.assertEqual(rows[0]['environment']['CI_PRODUCT'], product)
            flags = inherited_ci.plan(env)[0]['environment']['BITCOIN_CONFIG']
            self.assertIn('-DENABLE_POCX=' + enabled, flags)
            self.assertIn('-DENABLE_WALLET=OFF', flags)
            self.assertIn('-DSANITIZERS=thread', flags)
        for invalid in ('', 'OFF', 'ON', 'both', 'pocx '):
            for planner in (lambda env: inherited_ci.plan(env),
                            lambda env: windows_ci.plan(2, env), lambda env: revision_ci.plan(2, env)):
                with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                    planner(dict(environment, CI_PRODUCT=invalid))

    def test_actual_compiler_configuration_must_match_workflow_product(self):
        for product, enabled in ci_product.PRODUCTS.items():
            env = {'CI_PRODUCT': product}
            ci_product.require_configuration({'ENABLE_POCX': enabled}, env)
            for mismatch in ({}, {'ENABLE_POCX': 'ON' if enabled == 'OFF' else 'OFF'}):
                with self.assertRaisesRegex(ValueError, 'Compiled ENABLE_POCX'):
                    ci_product.require_configuration(mismatch, env)
        self.assertIn('ci_product.require_configuration(options, env)',
                      (ROOT / 'test/pocx/inherited_tests.py').read_text())

    def test_failed_bitcoin_invocation_does_not_prevent_independent_pocx(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(inherited_ci, 'source_snapshot', return_value={}):
            root = Path(directory)
            environment = {'BASE_ROOT_DIR': str(root), 'BASE_SCRATCH_DIR': str(root / 'scratch'),
                           'BASE_OUTDIR': str(root / 'scratch/out'), 'HOST': 'x86_64-pc-linux-gnu'}
            calls = []
            def invoke(command, **kwargs):
                product = kwargs['env']['CI_PRODUCT']
                calls.append(product)
                return subprocess.CompletedProcess(command, 9 if product == 'bitcoin' else 0)
            with self.assertRaises(ValueError):
                inherited_ci.execute(inherited_ci.plan(dict(environment, CI_PRODUCT='bitcoin'), root),
                                     root / 'off', root=root, run=invoke)
            report = inherited_ci.execute(inherited_ci.plan(dict(environment, CI_PRODUCT='pocx'), root),
                                          root / 'on', root=root, run=invoke)
            self.assertEqual(calls, ['bitcoin', 'pocx'])
            self.assertEqual(report['status'], 'passed')
            self.assertEqual(report['products'], ['pocx'])
            self.assertNotIn('after successful original', report['native_execution'])

    def test_linux_profile_rejects_opposite_product_before_build(self):
        for product, profile in [('bitcoin', 'pocx-unit'), ('pocx', 'bitcoin-unit')]:
            result = subprocess.run([sys.executable, '-B', str(ROOT / 'test/pocx/ci.py'), '--profile', profile],
                                    env=dict(os.environ, CI_PRODUCT=product), capture_output=True, text=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn('CI profile does not match CI_PRODUCT', result.stderr)

    def test_removed_real_proof_profile_is_a_subset_of_complete_pocx_unit(self):
        import ci
        import unit_matrix
        options = dict(ci.options('pocx-unit'), target_system='Linux', target_processor='x86_64',
                       avx2_compiled=True)
        inventory = unit_matrix.inventory(ROOT, options, bitcoin=False)
        suites = {name.split('/')[0] for name in inventory['additional']}
        self.assertTrue({'pocx_real_proof_tests', 'pocx_simd_tests', 'pocx_wire_tests'}.issubset(suites))
        self.assertEqual(ci.options('pocx-unit'), ci.options('pocx-functional'))
        self.assertEqual(ci.options('bitcoin-unit'), ci.options('bitcoin-functional'))
        self.assertTrue(inventory['additional'].issubset(inventory['expected']))

    def test_windows_single_product_export_rejects_wrong_revision_product_and_tampering(self):
        helper = test_windows_artifacts.WindowsArtifactsTest()
        with patch.object(windows_artifacts.unit_matrix, 'inventory', side_effect=helper.inventory):
            for product, index in [('bitcoin', 0), ('pocx', 1)]:
                with self.subTest(product=product), tempfile.TemporaryDirectory() as directory:
                    root, builds, bundle = helper.fixture(directory)
                    shutil.rmtree(builds[1 - index])
                    report = windows_artifacts.export_product(builds[index], product, bundle, root=root, revision='a' * 40)
                    self.assertEqual([row['consensus'] for row in report['phases']], [product])
                    self.assertEqual(report['execution_status'], 'not executed')
                    self.assertEqual(windows_artifacts.verify_pair(bundle, root=root, revision='a' * 40, product=product), report)
                    other = 'pocx' if product == 'bitcoin' else 'bitcoin'
                    for kwargs in ({'revision': 'b' * 40, 'product': product},
                                   {'revision': 'a' * 40, 'product': other}):
                        with self.assertRaises(ValueError):
                            windows_artifacts.verify_pair(bundle, root=root, **kwargs)
                    binary = bundle / product / report['phases'][0]['unit_binary']
                    binary.write_bytes(binary.read_bytes() + b'tampered')
                    with self.assertRaises(ValueError):
                        windows_artifacts.verify_pair(bundle, root=root, revision='a' * 40, product=product)

    def test_windows_independent_runtime_keeps_all_frameworks_exclusions_and_lifecycle_probe(self):
        helper = test_windows_artifact_ci.WindowsArtifactCITest()
        for product in ('bitcoin', 'pocx'):
            with tempfile.TemporaryDirectory() as directory:
                report, calls, _, _ = helper.run_fixture(directory, product=product)
                self.assertEqual(report['status'], 'passed')
                self.assertEqual(report['products'], [product])
                self.assertEqual([(kind, value) for kind, value in calls if kind != 'process'],
                                 [('frameworks', product), ('functional', product)])
                lifecycle = [command for kind, command in calls if kind == 'process' and
                             any(Path(arg).name == 'test_process_tree.py' for arg in command)]
                self.assertEqual(len(lifecycle), 1)
                if product == 'pocx':
                    self.assertTrue(any(case['status'] == 'reviewed-exclusion' for case in report['cases']))
                    self.assertTrue(any(case['origin'] == 'pocx-only' for case in report['cases']))

    def test_native_windows_selected_phase_keeps_lifecycle_and_frameworks(self):
        helper = test_windows_ci.WindowsCITest()
        with tempfile.TemporaryDirectory() as directory:
            root = helper.fixture(directory)
            for product in ci_product.PRODUCTS:
                calls, _, _ = helper.phase(root, product, product=product)
                commands = [command for command, _ in calls]
                self.assertEqual(sum(any(Path(arg).name == 'test_process_tree.py' for arg in command)
                                     for command in commands), 1)
                phases = [command[command.index('--phase') + 1] for command in commands
                          if any(Path(arg).name == 'inherited_tests.py' for arg in command)]
                self.assertEqual(phases, ['ctest', 'functional'])
            with self.assertRaisesRegex(ValueError, 'phase does not match'):
                helper.phase(root, 'bitcoin', product='pocx')

    def test_cross_controller_exports_and_publishes_without_other_product_build(self):
        helper = test_windows_artifacts.WindowsArtifactsTest()
        with patch.object(windows_artifacts.unit_matrix, 'inventory', side_effect=helper.inventory), \
                patch.object(windows_artifacts, 'verify_recipe', return_value={}), \
                patch.object(windows_artifacts, 'revision_id', return_value='a' * 40):
            for product, index in [('bitcoin', 0), ('pocx', 1)]:
                for host in sorted(windows_cross.HOSTS):
                    with self.subTest(product=product, host=host), tempfile.TemporaryDirectory() as directory:
                        root, builds, _ = helper.fixture(directory)
                        shutil.rmtree(builds[1 - index])
                        rows = [{'consensus': product, 'command': ['synthetic-build'], 'environment': {
                            'CI_PRODUCT': product, 'HOST': host, 'BASE_BUILD_DIR': str(builds[index]),
                            'BASE_OUTDIR': str(builds[index] / 'out'), 'RUN_UNIT_TESTS': 'false',
                            'RUN_FUNCTIONAL_TESTS': 'false'}}]
                        output = root / 'scratch/execution'
                        report = inherited_ci.execute(rows, output, root=root,
                            run=lambda command, **kwargs: subprocess.CompletedProcess(command, 0))
                        self.assertEqual(report['windows_artifacts']['actual_windows_cases_executed'], 0)
                        destination = inherited_ci.publish(output, root)
                        bundle = destination.parent / windows_cross.PUBLISHED_DIRECTORY
                        manifest = windows_artifacts.verify_pair(bundle, root=root, revision='a' * 40, product=product)
                        self.assertEqual([row['consensus'] for row in manifest['phases']], [product])

    def test_windows_workflow_producer_and_consumer_bind_product_and_frozen_revision(self):
        jobs = workflow('ci-product.yml')['jobs']
        producer, consumer = jobs['windows-cross'], jobs['windows-native-test']
        self.assertEqual(producer['strategy']['matrix']['crt'], ['msvcrt', 'ucrt'])
        self.assertEqual(consumer['needs'], ['windows-cross', 'record-frozen-commit'])
        for job in (producer, consumer):
            checkout = next(step for step in job['steps'] if step.get('uses', '').startswith('actions/checkout@'))
            self.assertEqual(checkout['with']['ref'], '${{ needs.record-frozen-commit.outputs.commit }}')
        upload = next(step for step in producer['steps'] if step.get('name', '').startswith('Upload verified'))
        download = next(step for step in consumer['steps'] if step.get('uses', '').startswith('actions/download-artifact@'))
        self.assertEqual(upload['with']['name'], download['with']['name'])
        self.assertIn('${{ inputs.product }}', upload['with']['name'])
        commands = '\n'.join(step.get('run', '') for step in consumer['steps'])
        self.assertEqual(commands.count('--product "${{ inputs.product }}"'), 2)
        self.assertNotIn('needs.CI', str(jobs))


if __name__ == '__main__':
    unittest.main()
