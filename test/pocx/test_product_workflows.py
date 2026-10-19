#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin PoCX developers
# Distributed under the MIT software license; see COPYING.
"""Product isolation, inherited scope and artifact rejection checks; no runtime claims."""
import importlib.util
import hashlib
import json
import os
import shutil
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch

import yaml

import ci_product
import ci_matrix
import bitcoin_fuzz_ci
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
    def test_lint_executes_unit_matrix_self_tests_in_both_products(self):
        steps = workflow('ci-product.yml')['jobs']['lint']['steps']
        script = next(step['run'] for step in steps if step.get('name') == 'CI script')
        commands = script.splitlines()
        guard = 'python3 -B ../lint-worktree/test/pocx/check_drift.py'
        tests = 'python3 -B ../lint-worktree/test/pocx/test_unit_matrix.py'
        fuzz_tests = 'python3 -B ../lint-worktree/test/pocx/test_fuzz_parity.py'
        self.assertIn(tests, commands)
        self.assertIn(fuzz_tests, commands)
        self.assertLess(commands.index(guard), commands.index(tests))
        self.assertLess(commands.index(tests), commands.index(fuzz_tests))
        self.assertLess(commands.index(fuzz_tests), commands.index('../lint-worktree/ci/lint.py'))

    def test_only_two_triggered_workflows_select_independent_products(self):
        documents = {p.name: workflow(p.name) for p in (ROOT / '.github/workflows').glob('*.yml')}
        self.assertEqual(set(documents), {'ci.yml', 'ci-pocx.yml', 'ci-product.yml'})
        for name, document in documents.items():
            for job_name, job in document['jobs'].items():
                with self.subTest(workflow=name, job=job_name):
                    self.assertNotIn('timeout-minutes', job)
                    for step in job.get('steps', []):
                        self.assertNotIn('timeout-minutes', step)
        for name, product, title in [('ci.yml', 'bitcoin', 'CI'), ('ci-pocx.yml', 'pocx', 'CI-POCX')]:
            document = documents[name]
            self.assertEqual(document['name'], title)
            self.assertEqual(set(document['on']), {'push', 'pull_request'})
            self.assertEqual(document['on']['push'], {'branches': ['**'], 'tags-ignore': ['**']})
            self.assertEqual(set(document['jobs']), {'product'})
            job = document['jobs']['product']
            self.assertEqual(job['uses'], './.github/workflows/ci-product.yml')
            self.assertEqual(job['with'], {'product': product})
            self.assertNotIn('needs', job)
            self.assertIn('github.workflow', document['concurrency']['group'])
        shared = documents['ci-product.yml']
        self.assertEqual(set(shared['on']), {'workflow_call'})
        self.assertEqual(shared['env']['CI_PRODUCT'], '${{ inputs.product }}')
        self.assertNotIn('concurrency', shared)

    def test_complete_inherited_platform_matrix_without_supplements(self):
        jobs = workflow('ci-product.yml')['jobs']
        self.assertEqual(set(jobs), {'runners', 'test-each-commit', 'macos-native-arm64',
            'windows-native-dll', 'record-frozen-commit', 'windows-cross', 'windows-native-test',
            'ci-matrix', 'lint'})
        reference = json.loads((ROOT / 'test/pocx/upstream-ci-matrix.json').read_text())
        self.assertEqual(reference['upstream_revision'], '9be056a8a72b624dae9623b2f7bded92c2a21c91')
        # This digest is computed from the matrices in bitcoin/bitcoin run
        # 28793907018's workflow at the pinned revision, not our workflow.
        encoded = json.dumps(reference['matrices'], sort_keys=True, separators=(',', ':')).encode()
        self.assertEqual(hashlib.sha256(encoded).hexdigest(),
                         '5281faede86e2a69eb775c39c48dc28e9542d247458149af94e405231df126ff')
        original = ci_matrix.matrices('bitcoin')
        native = ci_matrix.matrices('pocx')
        self.assertEqual({k: len(v['include']) for k, v in original.items()},
                         {'linux': 14, 'macos': 2, 'windows': 2})
        self.assertEqual({k: len(v['include']) for k, v in native.items()},
                         {'linux': 14, 'macos': 2, 'windows': 2})
        for output, job in ci_matrix.JOBS.items():
            self.assertEqual(original[output]['include'], reference['matrices'][job]['include'])
            self.assertEqual(native[output]['include'], original[output]['include'])
            self.assertEqual(jobs[job]['strategy']['matrix'],
                             '${{ fromJSON(needs.runners.outputs.' + output + ') }}')
            self.assertIn('runners', jobs[job]['needs'])
        for job, runner in [('macos-native-arm64', 'macos-15'),
                            ('windows-native-dll', 'windows-2025-vs2026'),
                            ('windows-native-test', 'windows-2022')]:
            self.assertEqual(jobs[job]['runs-on'], runner)
        self.assertEqual(jobs['windows-cross']['strategy']['matrix']['crt'], ['msvcrt', 'ucrt'])
        self.assertEqual(jobs['windows-native-test']['strategy']['matrix']['crt'], ['msvcrt', 'ucrt'])
        guards = '\n'.join(step.get('run', '') for step in jobs['lint']['steps'])
        self.assertIn('check_drift.py', guards)
        self.assertIn('ci/lint.py', guards)

    def test_product_selection_survives_container_and_privilege_boundaries(self):
        spec = importlib.util.spec_from_file_location('product_container', ROOT / 'ci/test/02_run_container.py')
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        tree = (ROOT / 'ci/test/02_run_container.py').read_text()
        self.assertIn('"CI_PRODUCT",', tree)
        self.assertEqual(module.test_script('/root', {}), ['python3', '/root/test/pocx/inherited_ci.py'])
        self.assertEqual(module.test_script('/root', {'RUN_FUZZ_TESTS': 'true'}),
                         ['python3', '/root/test/pocx/bitcoin_fuzz_ci.py'])
        commands = '\n'.join(step.get('run', '') for step in
                             workflow('ci-product.yml')['jobs']['test-each-commit']['steps'])
        self.assertIn('env CI_PRODUCT=', commands)
        self.assertIn('--phase-consensus', commands)

    def test_matrix_cli_selects_only_the_requested_product_and_rejects_unknown(self):
        for product in ('bitcoin', 'pocx', 'bad'):
            run = subprocess.run([sys.executable, '-B', str(ROOT / 'test/pocx/ci_matrix.py')],
                                 env=dict(os.environ, CI_PRODUCT=product), capture_output=True, text=True)
            if product == 'bad':
                self.assertNotEqual(run.returncode, 0)
                self.assertEqual(run.stdout, '')
            else:
                self.assertEqual(run.returncode, 0, run.stderr)
                self.assertEqual(dict((key, json.loads(value)) for key, value in
                    (line.split('=', 1) for line in run.stdout.splitlines())), ci_matrix.matrices(product))

    def test_inherited_fuzz_recipe_selects_one_product(self):
        flags = '-DBUILD_FOR_FUZZING=ON -DSANITIZERS=fuzzer,address -DENABLE_POCX=ON'
        for product, enabled in ci_product.PRODUCTS.items():
            result = bitcoin_fuzz_ci.environment_for_fuzz({'CI_PRODUCT': product, 'BITCOIN_CONFIG': flags})
            self.assertEqual(result['BITCOIN_CONFIG'], flags + ' -DENABLE_POCX=' + enabled)
        for product in (None, '', 'other'):
            with self.assertRaises(ValueError):
                bitcoin_fuzz_ci.environment_for_fuzz({'CI_PRODUCT': product})
        original = (ROOT / 'ci/test/03_test_script.sh').read_text()
        converted = bitcoin_fuzz_ci.pocx_posix_recipe(original)
        marker = '\nif [ "$RUN_FUZZ_TESTS" = "true" ]; then\n'
        self.assertEqual(converted.rpartition(marker)[0], original.rpartition(marker)[0])
        self.assertIn('test/pocx/ci_fuzz_run.py', converted.rpartition(marker)[2])
        self.assertNotIn('test/fuzz/test_runner.py', converted.rpartition(marker)[2])
        with self.assertRaisesRegex(ValueError, 'dispatch changed'):
            bitcoin_fuzz_ci.pocx_posix_recipe(original.rsplit(marker, 1)[0] + '\n# removed fuzz dispatch\n')
        for product, enabled in ci_product.PRODUCTS.items():
            with tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                (root / 'build').mkdir()
                (root / 'build/CMakeCache.txt').write_text('ENABLE_POCX:BOOL=' + enabled + '\n')
                calls = []
                driver = SimpleNamespace(GENERATE_OPTIONS={'fuzz': ['-DBUILD_FOR_FUZZING=ON']})
                for name in ('generate', 'build', 'check_manifests', 'prepare_tests', 'run_tests'):
                    setattr(driver, name, lambda kind, name=name: calls.append((name, kind)))
                bitcoin_fuzz_ci.run_windows(root, product=product, load=lambda: driver,
                                            run_pocx=lambda: calls.append(('pocx_runner', 'fuzz')))
                ending = 'run_tests' if product == 'bitcoin' else 'pocx_runner'
                self.assertEqual(calls, [(name, 'fuzz') for name in
                    ('generate', 'build', 'check_manifests', 'prepare_tests', ending)])
                self.assertEqual(driver.GENERATE_OPTIONS['fuzz'],
                                 ['-DBUILD_FOR_FUZZING=ON', '-DENABLE_POCX=' + enabled])

    def test_matrix_rejects_an_added_profile_before_creating_jobs(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / 'test/pocx/upstream-ci-matrix.json'
            path.parent.mkdir(parents=True)
            reference = json.loads((ROOT / 'test/pocx/upstream-ci-matrix.json').read_text())
            reference['matrices']['ci-matrix']['include'].append({'name': 'extra profile'})
            path.write_text(json.dumps(reference))
            for product in ('bitcoin', 'pocx'):
                with self.assertRaisesRegex(ValueError, 'upstream scope review'):
                    ci_matrix.matrices(product, root)

    def test_original_recipe_change_is_rejected_before_creating_platform_jobs(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            reference = json.loads((ROOT / 'test/pocx/upstream-ci-matrix.json').read_text())
            for name in ['test/pocx/upstream-ci-matrix.json', *reference['recipe_sha256']]:
                path = root / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes((ROOT / name).read_bytes())
            self.assertEqual(ci_matrix.matrices('bitcoin', root), ci_matrix.matrices('bitcoin'))
            path = root / 'ci/test/00_setup_env_arm.sh'
            path.write_text(path.read_text() + '\nexport RUN_FUNCTIONAL_TESTS=false\n')
            for product in ('bitcoin', 'pocx'):
                with self.assertRaisesRegex(ValueError, 'Original CI recipe changed'):
                    ci_matrix.matrices(product, root)

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
            if product == 'bitcoin':
                self.assertNotIn('-DBUILD_FUZZ_BINARY=OFF', flags)
                self.assertNotIn('-DBUILD_FOR_FUZZING=OFF', flags)
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
