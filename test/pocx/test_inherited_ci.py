#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin PoCX developers
# Distributed under the MIT software license; see COPYING.
"""Inherited CI ordering, feature selection and failure-propagation checks.

These are infrastructure checks; fake recipe callbacks are never framework or
hosted execution evidence. No container, installation or privileged recipe runs.
"""
from copy import deepcopy
import importlib.util
import json
import os
from pathlib import Path
import re
import shlex
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

import inherited_ci
import inherited_functional as functional
import inherited_tests as tests
from common import ROOT


class InheritedTest(unittest.TestCase):
    def test_manual_baseline_dispatch_is_single_job_and_default_matrix_remains_enabled(self):
        workflow = (ROOT/'.github/workflows/ci.yml').read_text()
        header, jobs = workflow.split('\njobs:\n', 1)
        self.assertRegex(header, r'baseline_only:\n(?:[^\n]*\n)*?        default: false')
        self.assertNotIn('    if:', header)
        blocks = re.split(r'(?=^  [a-z][a-z0-9-]*:\n)', jobs, flags=re.MULTILINE)
        blocks = {block.split(':',1)[0].strip(): block for block in blocks if block.strip()}
        baseline = blocks.pop('bitcoin-baseline')
        self.assertIn("if: github.event_name == 'workflow_dispatch' && inputs.baseline_only", baseline)
        self.assertIn('--profile bitcoin-unit --jobs 2', baseline)
        self.assertIn('if: always()', baseline)
        self.assertNotIn('matrix:', baseline)
        self.assertEqual(set(blocks), {'runners','test-each-commit','macos-native-arm64',
            'windows-native-dll','record-frozen-commit','windows-cross','windows-native-test','ci-matrix','lint'})
        for name, block in blocks.items():
            condition = re.search(r'^    if: (.+)$', block, re.MULTILINE)
            self.assertIsNotNone(condition, name)
            self.assertIn("(github.event_name != 'workflow_dispatch' || !inputs.baseline_only)", condition[1])

    def env(self):
        return {'BASE_ROOT_DIR': str(ROOT), 'BASE_SCRATCH_DIR': str(ROOT/'build-inherited-fixture'),
                'BASE_OUTDIR': str(ROOT/'build-inherited-fixture/out'), 'HOST': 'x86_64-pc-linux-gnu',
                'BITCOIN_CONFIG': '--preset=dev-mode -DENABLE_WALLET=OFF -DSANITIZERS=thread',
                'RUN_UNIT_TESTS': 'true', 'RUN_FUNCTIONAL_TESTS': 'true', 'MAKEJOBS': '-j4'}

    def test_pair_is_original_first_and_preserves_features(self):
        pair = inherited_ci.plan(self.env())
        self.assertEqual([row['consensus'] for row in pair], ['bitcoin', 'pocx'])
        for row, mode in zip(pair, ('OFF', 'ON')):
            flags = shlex.split(row['environment']['BITCOIN_CONFIG'])
            self.assertIn('-DENABLE_WALLET=OFF', flags);self.assertIn('-DSANITIZERS=thread', flags)
            self.assertEqual(flags[-3:], ['-DENABLE_POCX='+mode, '-DBUILD_FUZZ_BINARY=OFF', '-DBUILD_FOR_FUZZING=OFF'])
        for key in ('BASE_BUILD_DIR', 'BASE_OUTDIR'):
            self.assertNotEqual(pair[0]['environment'][key], pair[1]['environment'][key])
        self.assertEqual(pair[1]['environment']['BASE_OUTDIR'], self.env()['BASE_OUTDIR'])

    def test_fuzz_and_unsafe_source_build_paths_rejected(self):
        for change in ({'RUN_FUZZ_TESTS':'true'}, {'BASE_ROOT_DIR':'/other'},
                       {'BASE_BUILD_DIR':str(ROOT)}, {'BASE_OUTDIR':'/tmp/outside'}):
            with self.subTest(change=change), self.assertRaises(ValueError):
                inherited_ci.plan({**self.env(), **change})

    def test_actual_container_entrypoint_dispatch(self):
        spec = importlib.util.spec_from_file_location('container_entry', ROOT/'ci/test/02_run_container.py')
        module = importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
        self.assertEqual(module.test_script('/source', {}), ['python3','/source/test/pocx/inherited_ci.py'])
        self.assertEqual(module.test_script('/source', {'RUN_FUZZ_TESTS':'true'}), ['/source/ci/test/03_test_script.sh'])
        self.assertEqual(module.imagefile('/source', {}), '/source/test/pocx/ci/test_imagefile')
        self.assertEqual(module.imagefile('/source', {'RUN_FUZZ_TESTS':'true'}), '/source/ci/test_imagefile')

    def test_enabled_linux_tracing_prerequisites_preserve_compiler_and_feature_settings(self):
        spec = importlib.util.spec_from_file_location('container_runtime', ROOT/'ci/test/02_run_container.py')
        module = importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
        names = ('ci_native_asan', 'ci_native_tsan', 'ci_native_msan', 'ci_native_nowallet',
                 'ci_native_previous_releases', 'ci_native_alpine_musl',
                 'ci_i686_no_multiprocess', 'ci_arm_linux')
        for name in names:
            with self.subTest(name=name):
                original = dict(os.environ, CONTAINER_NAME=name, RUN_FUNCTIONAL_TESTS='true',
                    RUN_FUZZ_TESTS='false', CI_IMAGE_NAME_TAG='alpine:3.23' if 'alpine' in name else 'ubuntu:24.04',
                    PACKAGES='compiler python3', CI_CONTAINER_CAP='--security-opt seccomp=unconfined',
                    BITCOIN_CONFIG='--preset=dev-mode -DENABLE_WALLET=OFF', DEP_OPTS='NO_WALLET=1 CC=clang-17')
                result = module.configure_runtime_environment(ROOT, original)
                expected = ('py3-bcc', 'bcc-tools') if 'alpine' in name else ('python3-bpfcc', 'bpfcc-tools','python3-zmq')
                for package in expected:self.assertEqual(result['PACKAGES'].split().count(package), 1)
                for flag in ('--security-opt seccomp=unconfined', '--privileged',
                             '/usr/src:/usr/src:ro', '/lib/modules:/lib/modules:ro'):
                    self.assertIn(flag, result['CI_CONTAINER_CAP'])
                permitted = ('PACKAGES','PIP_PACKAGES','CI_CONTAINER_CAP')
                self.assertEqual({k:v for k,v in original.items() if k not in permitted},
                                 {k:v for k,v in result.items() if k not in permitted})
                self.assertEqual(module.configure_runtime_environment(ROOT, result), result)
                self.assertEqual(original['PACKAGES'], 'compiler python3')
        for flags in ({'RUN_FUZZ_TESTS':'true'}, {'RUN_FUNCTIONAL_TESTS':'false'},
                      {'CONTAINER_NAME':'ci_native_tidy'}, {'CONTAINER_NAME':'ci_win64'}):
            original = dict(os.environ, CONTAINER_NAME='ci_native_nowallet', RUN_FUZZ_TESTS='false',
                            RUN_FUNCTIONAL_TESTS='true', PACKAGES='compiler', CI_CONTAINER_CAP='existing')
            original.update(flags)
            self.assertEqual(module.configure_runtime_environment(ROOT, original), original)

    def test_actual_recipes_have_python_bindings_for_enabled_functional_features(self):
        spec = importlib.util.spec_from_file_location('python_runtime', ROOT/'ci/test/02_run_container.py')
        module = importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
        for name in ('arm','i686_no_ipc','native_asan','native_tsan','native_msan',
                     'native_nowallet','native_previous_releases','native_alpine_musl'):
            command=['bash','-ec','source ./ci/test/00_setup_env.sh >/dev/null 2>&1; python3 -c "import json,os; print(json.dumps(dict(os.environ)))"']
            original=json.loads(subprocess.check_output(command,cwd=ROOT,text=True,
                env={'PATH':os.environ['PATH'],'FILE_ENV':'./ci/test/00_setup_env_'+name+'.sh','MAKEJOBS':'-j1'}))
            result=module.configure_runtime_environment(ROOT,original)
            packages=result.get('PACKAGES','').split()
            pip=result.get('PIP_PACKAGES','').split()
            with self.subTest(recipe=name):
                self.assertTrue('python3-zmq' in packages or any(p in ('pyzmq','zmq') for p in pip))
                if name=='i686_no_ipc':
                    self.assertEqual(result.get('PIP_PACKAGES'),original.get('PIP_PACKAGES'))
                else:
                    self.assertTrue(any(p=='pycapnp' or p.startswith('pycapnp==') for p in pip))
                if name=='native_previous_releases':
                    self.assertNotIn('--break-system-packages',pip)
                    self.assertIn('python3-pip',packages)
                if name=='arm':
                    self.assertIn('--break-system-packages',pip)
                    self.assertIn('python3-pip',packages)
                self.assertEqual(result['BITCOIN_CONFIG'],original['BITCOIN_CONFIG'])
                self.assertEqual(result.get('DEP_OPTS'),original.get('DEP_OPTS'))
                self.assertEqual(module.configure_runtime_environment(ROOT,result),result)

    def test_review_rejects_recipe_drift(self):
        self.assertTrue(inherited_ci.verify_recipe()['source_sha256'])
        original = inherited_ci.sha256
        with patch.object(inherited_ci, 'sha256', side_effect=lambda p: '0'*64 if p.name=='03_test_script.sh' else original(p)):
            with self.assertRaisesRegex(ValueError, 'changed without review'): inherited_ci.verify_recipe()

    def test_actual_tracing_recipes_match_host_header_provisioning(self):
        workflow = (ROOT/'.github/workflows/ci.yml').read_text()
        step = workflow.split('- name: Provision matching headers for enabled Linux USDT tests', 1)[1].split('\n      - name:', 1)[0]
        profiles = json.loads(re.search(r"fromJSON\('([^']+)'\)", step).group(1))
        self.assertEqual(len(profiles), len(set(profiles)))
        spec = importlib.util.spec_from_file_location('tracing_entry', ROOT/'ci/test/02_run_container.py')
        module = importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
        seen = set()
        for recipe in sorted((ROOT/'ci/test').glob('00_setup_env*.sh')):
            if recipe.name == '00_setup_env.sh':
                continue
            command = ['bash', '-ec', 'source "$1"; python3 -c "import json,os; print(json.dumps(dict(os.environ)))"', 'bash', str(recipe)]
            environment = json.loads(subprocess.check_output(command, cwd=ROOT,
                env={'PATH':os.environ['PATH'], 'RUN_FUNCTIONAL_TESTS':'true', 'RUN_FUZZ_TESTS':'false'}))
            result = module.configure_runtime_environment(ROOT, environment)
            if result.get('CI_CONTAINER_CAP') != environment.get('CI_CONTAINER_CAP'):
                seen.add(result['CONTAINER_NAME'])
                self.assertIn(result['CONTAINER_NAME'], profiles)
                self.assertEqual(result['BITCOIN_CONFIG'], environment['BITCOIN_CONFIG'])
                self.assertEqual(result.get('DEP_OPTS'), environment.get('DEP_OPTS'))
                self.assertEqual(result.get('CI_IMAGE_PLATFORM'), environment.get('CI_IMAGE_PLATFORM'))
        self.assertEqual(seen, set(profiles))

    def execute_fixture(self, codes):
        with tempfile.TemporaryDirectory() as directory:
            called = []
            def recipe(command, **kwargs):
                called.append(kwargs['env']['BITCOIN_CONFIG'])
                return subprocess.CompletedProcess(command, codes[len(called)-1])
            path = Path(directory)/'execution'
            try: inherited_ci.execute(inherited_ci.plan(self.env()), path, run=recipe)
            except ValueError: pass
            return json.loads((path/'results.json').read_text()), called

    def test_original_failure_never_launches_native(self):
        report, calls = self.execute_fixture([7])
        self.assertEqual(report['status'], 'failed');self.assertEqual(len(calls), 1)
        self.assertEqual(report['native_execution'], 'deferred')

    def test_evidence_retention_is_new_bounded_and_avoids_symlinks(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory);build = root/'build';build.mkdir()
            old = build/'bitcoin-unit-old';old.mkdir();(old/'results.json').write_text('old')
            before = inherited_ci.evidence_directories(build)
            current = build/'pocx-inherited-functional-new';current.mkdir()
            (current/'results.json').write_text('new')
            nested = current/'functional';nested.mkdir();(nested/'cases.csv').write_text('cases')
            deep = nested/'node-data';deep.mkdir();(deep/'debug.log').write_text('not a report')
            (current/'binary.dat').write_text('not a report')
            (current/'linked.log').symlink_to(old/'results.json')
            (current/'linked-directory').symlink_to(old, target_is_directory=True)
            ignored = build/'other-tests';ignored.mkdir();(ignored/'results.json').write_text('other')
            destination = root/'output'
            retained = inherited_ci.retain_evidence(build, before, destination)
            self.assertEqual(set(retained), {'pocx-inherited-functional-new/results.json',
                                            'pocx-inherited-functional-new/functional/cases.csv'})
            self.assertEqual(len([p for p in destination.rglob('*') if p.is_file()]), 2)

    def test_both_transport_raw_rpc_coverage_is_retained_without_node_data(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); build = root / 'build'
            report = build / 'pocx-results-fixture'; report.mkdir(parents=True)
            for prefix in ('rpc-coverage', 'v2/rpc-coverage'):
                directory = report / prefix; directory.mkdir(parents=True)
                (directory / 'rpc_interface.txt').write_text('getblockcount\n')
                (directory / 'coverage.123.node0').write_text('getblockcount\n')
                (directory / 'node-data.dat').write_text('not coverage')
                (directory / 'coverage.link').symlink_to(directory / 'node-data.dat')
            retained = inherited_ci.retain_evidence(build, set(), root / 'out')
            expected = {'pocx-results-fixture/' + prefix + '/' + name
                        for prefix in ('rpc-coverage', 'v2/rpc-coverage')
                        for name in ('rpc_interface.txt', 'coverage.123.node0')}
            self.assertEqual(set(retained), expected)

    def test_failed_recipe_reports_are_copied_and_publishable(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);env=self.env();env['BASE_BUILD_DIR']=str(root/'build')
            pair=inherited_ci.plan(self.env());pair[0]['environment']=env
            def recipe(command, **kwargs):
                evidence=Path(env['BASE_BUILD_DIR'])/'bitcoin-unit-failed';evidence.mkdir(parents=True)
                (evidence/'results.json').write_text('{"status":"failed"}')
                return subprocess.CompletedProcess(command,9)
            output=root/'pocx-inherited-fixture/execution'
            with self.assertRaises(ValueError):inherited_ci.execute(pair,output,run=recipe)
            report=json.loads((output/'results.json').read_text())
            self.assertEqual(set(report['steps'][0]['retained_evidence']), {'bitcoin-unit-failed/results.json'})
            destination=inherited_ci.publish(output,root)
            self.assertEqual((destination/'results.json').read_bytes(),(output/'results.json').read_bytes())
            self.assertTrue((destination/'bitcoin-evidence/bitcoin-unit-failed/results.json').is_file())

    def test_launch_exception_marks_step_failed(self):
        with tempfile.TemporaryDirectory() as directory:
            output=Path(directory)/'execution'
            with self.assertRaises(OSError):
                inherited_ci.execute(inherited_ci.plan(self.env()),output,
                    run=lambda *a,**kw: (_ for _ in ()).throw(OSError('launch failed')))
            report=json.loads((output/'results.json').read_text())
            self.assertEqual(report['status'],'failed');self.assertEqual(report['steps'][0]['status'],'failed')
            self.assertEqual(report['native_execution'],'deferred')

    @unittest.skipUnless(sys.platform != 'win32', 'POSIX artifact permission proof')
    def test_published_root_step_reports_are_readable_by_artifact_uploader(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);output=root/'pocx-inherited-fixture/execution';output.mkdir(parents=True,mode=0o700)
            log=output/'bitcoin.log';log.write_text('report');log.chmod(0o600)
            nested=output/'bitcoin-evidence';nested.mkdir(mode=0o700)
            (nested/'results.json').write_text('{"status":"failed"}')
            (root/'artifacts/pocx-inherited').mkdir(parents=True,mode=0o700)
            (root/'artifacts').chmod(0o700)
            with patch('builtins.print'):
                destination=inherited_ci.publish(output,root)
            for path in [root/'artifacts',destination.parent,destination,*destination.rglob('*')]:
                required=0o5 if path.is_dir() else 0o4
                self.assertEqual(path.stat().st_mode & required,required)

    def test_container_evidence_copy_is_structured_and_failure_is_fatal(self):
        spec=importlib.util.spec_from_file_location('container_capture',ROOT/'ci/test/02_run_container.py')
        module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
        with tempfile.TemporaryDirectory() as directory:
            env={'BASE_READ_ONLY_DIR':directory,'BASE_ROOT_DIR':'/guest/source tree'};calls=[]
            def invoke(command,**kwargs):
                calls.append((command,kwargs));return subprocess.CompletedProcess(command,0)
            module.capture_evidence('container-id',env,invoke=invoke)
            self.assertEqual(calls,[(['docker','cp','container-id:/guest/source tree/artifacts/pocx-inherited',
                                     str(Path(directory)/'artifacts')],{'check':False})])
            with self.assertRaises(RuntimeError):module.capture_evidence('container-id',env,
                invoke=lambda command,**kwargs:subprocess.CompletedProcess(command,1))

    def test_native_failure_does_not_hide_original_result(self):
        report, calls = self.execute_fixture([0,8])
        self.assertEqual([s['status'] for s in report['steps']], ['passed','failed'])
        self.assertEqual(report['status'], 'failed');self.assertEqual(len(calls),2)

    def test_success_requires_both_recipes(self):
        report, calls = self.execute_fixture([0,0])
        self.assertEqual(report['status'], 'passed');self.assertEqual(len(calls),2)
        with tempfile.TemporaryDirectory() as directory:
            for pairs in ([], list(reversed(inherited_ci.plan(self.env())))):
                with self.assertRaises(ValueError): inherited_ci.execute(pairs, Path(directory)/'unused')

    def test_cli_and_multiprocess_settings_preserved(self):
        profile = functional.inherited_options({'TEST_RUNNER_EXTRA':'--v2transport --usecli --extended', 'BITCOIN_CMD':'bitcoin -m'})
        self.assertTrue(profile['use_cli']);self.assertTrue(profile['multiprocess'])
        self.assertEqual(profile['transports'], ['v1','v2'])
        for env in ({'TEST_RUNNER_EXTRA':'--exclude=wallet_basic'}, {'BITCOIN_CMD':'other-command'}):
            with self.subTest(env=env), self.assertRaises(ValueError): functional.inherited_options(env)

    def test_inherited_timeout_factor_is_explicit_finite_and_unambiguous(self):
        for text in ('--timeout-factor=40','--timeout-factor 40'):
            profile=functional.inherited_options({'TEST_RUNNER_EXTRA':text+' --usecli'})
            self.assertEqual(profile['timeout_factor'],40);self.assertTrue(profile['use_cli'])
        for text in ('--timeout-factor','--timeout-factor=','--timeout-factor=0',
                     '--timeout-factor=-1','--timeout-factor=nan','--timeout-factor=inf',
                     '--timeout-factor=1 --timeout-factor=2','--timeout-factor=40 --exclude=wallet_basic'):
            with self.subTest(text=text),self.assertRaises(ValueError):
                functional.inherited_options({'TEST_RUNNER_EXTRA':text})

    def test_missing_enabled_dependencies_are_unverified(self):
        profile = functional.inherited_options({})
        self.assertEqual(functional.classify('interface_ipc.py','Skipped',{'ENABLE_IPC':'ON'},profile)[0], 'unverified')
        self.assertEqual(functional.classify('wallet_basic.py','Failed',{'ENABLE_WALLET':'OFF'},profile)[0], 'failed')

    def test_disabled_wallet_and_ipc_have_source_guards(self):
        profile = functional.inherited_options({})
        for case, flag in [('wallet_basic.py','ENABLE_WALLET'),('interface_ipc.py','ENABLE_IPC')]:
            state,reason = functional.classify(case,'Skipped',{flag:'OFF'},profile)
            self.assertEqual(state,'configuration-disabled');self.assertIn(flag+'=OFF',reason)

    def test_only_unconditional_guards_allow_feature_omissions(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);path=root/'test/functional/feature_probe.py';path.parent.mkdir(parents=True)
            path.write_text('class Probe:\n def skip_test_if_missing_module(self):\n  if condition:\n   self.skip_if_no_wallet()\n')
            self.assertIsNone(functional.disabled_reason(path.name, {'ENABLE_WALLET':'OFF'}, functional.inherited_options({}), root=root))

    def test_auxiliary_zero_missing_duplicate_failed_or_skipped_rejected(self):
        valid='<testsuite><testcase name="library"/></testsuite>'
        self.assertEqual(tests.verify_auxiliary(valid,['library']), ['library'])
        for xml in ('<testsuite/>',valid.replace('/>','><skipped/></testcase>'),
                    valid.replace('/>','><failure/></testcase>'),
                    valid.replace('</testsuite>','<testcase name="library"/></testsuite>')):
            with self.subTest(xml=xml), self.assertRaises(ValueError): tests.verify_auxiliary(xml,['library'])

    def test_framework_dispatch_requires_native_full_unit_and_original_kernel(self):
        options={'ENABLE_POCX':'ON','BUILD_GUI':'ON','BUILD_GUI_TESTS':'ON','BUILD_KERNEL_LIB':'ON','BUILD_KERNEL_TEST':'ON'}
        commands,disabled=tests.framework_commands(ROOT/'build-probe',options,4,2400,ROOT/'build-output')
        self.assertEqual([name for name,_ in commands], ['unit','qt','kernel']);self.assertFalse(disabled)
        self.assertIn('--all',commands[0][1]);self.assertNotIn('--bitcoin',commands[-1][1])
        commands,_=tests.framework_commands(ROOT/'build-probe',{**options,'ENABLE_POCX':'OFF'},4,2400,ROOT/'build-output')
        self.assertIn('--bitcoin',commands[-1][1]);self.assertIn('run_bitcoin_unit.py',commands[0][1][1])
        configured,_=tests.framework_commands(ROOT/'build-probe',options,4,2400,ROOT/'build-output',selected_config='Release')
        self.assertTrue(all(command[-2:]==['--config','Release'] for _,command in configured))

    def test_auxiliary_selection_uses_configuration_binary_identity(self):
        binary=ROOT/'build-probe/bin/Release/test_pocx.exe'
        rows=[{'name':'unit_suite','command':[str(binary.parent/'unused/../test_pocx.exe')]},
              {'name':'test_bitcoin-qt'},{'name':'test_kernel'},{'name':'library'}]
        self.assertEqual(tests.auxiliary_names(rows,binary),['library'])
        for registration in (rows+rows[-1:],rows[1:],rows[:-1]):
            with self.subTest(rows=registration),self.assertRaises(ValueError):
                tests.auxiliary_names(registration,binary)

    def functional_build_fixture(self, root, *, multiprocess=False, multi=False):
        (root/'CMakeCache.txt').write_text(
            'CMAKE_CONFIGURATION_TYPES:STRING=Debug;Release\n' if multi else '')
        directory=root/'bin'
        if multi:directory/='Release'
        directory.mkdir(parents=True)
        if multiprocess:
            for name in ('bitcoin','bitcoin-node'):
                # Match the native host suffix; this is only a fake inventory.
                import build_configuration
                path=build_configuration.executable(root,name,(root/'CMakeCache.txt').read_text(),'Release' if multi else None)
                path.write_bytes(b'never executed fixture binary')

    def test_jobs_and_disabled_frameworks_are_explicit(self):
        for value in ('4','-j4','-j 4'):self.assertEqual(tests.jobs(value),4)
        for value in ('0','-j0','-1','-j4 --other'):
            with self.subTest(value=value),self.assertRaises(Exception):tests.jobs(value)
        commands,disabled=tests.framework_commands(ROOT/'build-probe',{'ENABLE_POCX':'OFF','BUILD_GUI':'OFF','BUILD_KERNEL_LIB':'OFF'},4,2400,ROOT/'build-output')
        self.assertEqual([name for name,_ in commands],['unit']);self.assertEqual(set(disabled),{'qt','kernel'})

    def original_functional_fixture(self, status, *, multi=False, extra='', raw_exit=0, aggregate='Passed'):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);output=root/'output';self.functional_build_fixture(root,multi=multi)
            def original_runner(command, **kwargs):
                import functional_execution
                paths=functional_execution.binary_paths(root,(root/'CMakeCache.txt').read_text(),'Release' if multi else None)
                for name,variable in functional_execution.BINARY_ENVIRONMENT.items():
                    self.assertEqual(kwargs['env'][variable],str(paths[name]))
                path=Path(next(arg.split('=',1)[1] for arg in command if arg.startswith('--resultsfile=')))
                path.write_text('test,status,duration(seconds)\np2p_ping.py,'+status+',0.1\nALL,'+aggregate+',0.1\n')
                return subprocess.CompletedProcess(command,raw_exit)
            with patch.object(functional,'dependency_hashes',return_value={}), \
                    patch.object(functional,'expected_cases',return_value=['p2p_ping.py']), \
                    patch.object(functional.subprocess,'check_output',return_value='FixtureBenchmark\n'), \
                    patch.object(functional.subprocess,'run',side_effect=original_runner):
                try:functional.run(root,output,{'ENABLE_POCX':'OFF','BUILD_BENCH':'ON'},4,40,
                    environment={'TEST_RUNNER_EXTRA':extra},selected_config='Release' if multi else None)
                except ValueError:pass
            self.assertTrue((output/'cases.csv').is_file())
            return json.loads((output/'results.json').read_text())

    def test_original_functional_dispatch_retains_both_transports(self):
        report=self.original_functional_fixture('Passed')
        self.assertEqual(report['status'],'passed')
        self.assertEqual({row['transport'] for row in report['cases']},{'v1','v2'})
        self.assertEqual(report['counts'],{'passed':2})

    def test_original_green_aggregate_cannot_hide_missing_enabled_case(self):
        report=self.original_functional_fixture('Skipped')
        self.assertEqual(report['status'],'failed')
        self.assertEqual(report['counts'],{'unverified':2})

    def test_original_failure_preserves_red_cases_and_missing_transport(self):
        report=self.original_functional_fixture('Failed',raw_exit=1,aggregate='Failed')
        self.assertEqual(report['status'],'failed')
        self.assertEqual(report['counts'],{'failed':1,'unverified':1})
        self.assertEqual([(row['transport'],row['status']) for row in report['cases']],
                         [('v1','failed'),('v2','unverified')])
        self.assertEqual(len(report['runs']),1)
        self.assertEqual(report['runs'][0]['returncode'],1)

    def test_original_abnormal_exit_keeps_passed_rows_without_promoting_profile(self):
        report=self.original_functional_fixture('Passed',raw_exit=2)
        self.assertEqual(report['status'],'failed')
        self.assertEqual(report['counts'],{'passed':1,'unverified':1})
        self.assertEqual(len(report['runs']),1)

    def test_original_multi_configuration_preserves_inherited_timeout_and_binary_paths(self):
        report=self.original_functional_fixture('Passed',multi=True,extra='--timeout-factor=7.5')
        self.assertEqual(report['status'],'passed')
        self.assertEqual(report['build_configuration'],'Release')
        self.assertEqual(report['profile']['effective_timeout_factor'],7.5)
        self.assertTrue(all('--timeout-factor=7.5' in row['command'] for row in report['runs']))

    def test_native_functional_report_and_cli_modes_are_retained(self):
        from functional_cases import case_spec,selection_digest
        import functional_execution
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);output=root/'output';proof=root/'native-proof';proof.mkdir()
            self.functional_build_fixture(root,multiprocess=True)
            spec=case_spec('p2p_ping.py',[]);execution=functional_execution.settings(True,True)
            rows=[]
            for mode in ('v1','v2'):
                flags=['--usecli','--timeout-factor=40','--'+mode+'transport']
                rows.append({'case':spec['id'],'test':spec['test'],'case_arguments':[],
                    'transport':mode,'execution_options':execution,'test_arguments':flags,
                    'command':['python3',spec['test'],*flags],'returncode':0,'timed_out':False,'status':'passed','seconds':0.1})
            data={'provenance':{'format_version':7,'execution_options':execution,'timeout_factor':40,
                'environment_profile':{'previous_releases':False,'network_addresses':False},
                'selected_tests':[spec['test']],'selected_cases':[spec],'transport_modes':['v1','v2'],
                'case_selection':{'selected_cases_sha256':selection_digest([spec])}},'results':rows}
            (proof/'results.json').write_text(json.dumps(data))
            def native_runner(command,**kwargs):
                kwargs['stdout'].write('Results: '+str(proof)+'\n')
                return subprocess.CompletedProcess(command,0)
            with patch.object(functional,'dependency_hashes',return_value={}), \
                    patch.object(functional,'verify_current_inputs',return_value={}), \
                    patch.object(functional,'selected_cases',return_value=[spec]), \
                    patch.object(functional.subprocess,'run',side_effect=native_runner):
                report=functional.run(root,output,{'ENABLE_POCX':'ON','ENABLE_IPC':'ON'},4,40,
                    environment={'TEST_RUNNER_EXTRA':'--usecli','BITCOIN_CMD':'bitcoin -m'})
            self.assertEqual(report['status'],'passed');self.assertEqual(report['counts'],{'passed':2})
            self.assertIn('--usecli',report['runs'][0]['command']);self.assertIn('--multiprocess',report['runs'][0]['command'])
            self.assertEqual(len((output/'cases.csv').read_text().splitlines()),3)

    def native_feature_fixture(self, feature, status, raw_exit=1, *, multi=False, extra='', fallback_factor=40):
        from functional_cases import case_spec,selection_digest
        import functional_execution
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);output=root/'output';proof=root/'native-proof';proof.mkdir()
            self.functional_build_fixture(root,multi=multi)
            specs=[case_spec(name,[]) for name in ('p2p_ping.py','interface_ipc.py')]
            execution=functional_execution.settings();rows=[]
            for spec in specs:
                for mode in ('v1','v2'):
                    case_status='passed' if spec['test']=='p2p_ping.py' else status
                    flags=['--timeout-factor=40','--'+mode+'transport']
                    row={'case':spec['id'],'test':spec['test'],'case_arguments':[],
                        'transport':mode,'execution_options':execution,'test_arguments':flags,
                        'command':['python3',spec['test'],*flags],
                        'returncode':0 if case_status=='passed' else 77 if case_status=='skipped' else 1,
                        'timed_out':False,'status':case_status,'seconds':0.1}
                    if case_status=='skipped':row['skip_reason']='IPC not configured'
                    rows.append(row)
            data={'provenance':{'format_version':7,'execution_options':execution,'timeout_factor':40,
                'build_configuration':'Release' if multi else None,
                'environment_profile':{'previous_releases':False,'network_addresses':False},
                'selected_tests':[spec['test'] for spec in specs],'selected_cases':specs,'transport_modes':['v1','v2'],
                'case_selection':{'selected_cases_sha256':selection_digest(specs)}},'results':rows}
            (proof/'results.json').write_text(json.dumps(data))
            def native_runner(command,**kwargs):
                kwargs['stdout'].write('Results: '+str(proof)+'\n')
                return subprocess.CompletedProcess(command,raw_exit)
            with patch.object(functional,'dependency_hashes',return_value={}), \
                    patch.object(functional,'verify_current_inputs',return_value={}), \
                    patch.object(functional,'selected_cases',return_value=specs), \
                    patch.object(functional.subprocess,'run',side_effect=native_runner):
                try:functional.run(root,output,{'ENABLE_POCX':'ON','ENABLE_IPC':feature},4,fallback_factor,
                    environment={'TEST_RUNNER_EXTRA':extra},selected_config='Release' if multi else None)
                except ValueError:pass
            return json.loads((output/'results.json').read_text())

    def test_native_disabled_feature_keeps_skips_explicit_without_rejecting_the_profile(self):
        report=self.native_feature_fixture('OFF','skipped')
        self.assertEqual(report['status'],'passed')
        self.assertEqual(report['counts'],{'passed':2,'configuration-disabled':2})
        disabled=[row for row in report['cases'] if row['status']=='configuration-disabled']
        self.assertEqual(len(disabled),2)
        self.assertTrue(all(row['execution_status']=='skipped' and 'ENABLE_IPC=OFF' in row['reason'] for row in disabled))
        self.assertEqual(report['runs'][0]['returncode'],1)

    def test_native_multi_configuration_and_effective_timeout_reach_the_child(self):
        report=self.native_feature_fixture('OFF','skipped',multi=True,extra='--timeout-factor 40',fallback_factor=1)
        self.assertEqual(report['status'],'passed')
        self.assertEqual(report['build_configuration'],'Release')
        self.assertEqual(report['profile']['effective_timeout_factor'],40)
        command=report['runs'][0]['command']
        self.assertEqual(command[command.index('--config')+1],'Release')
        self.assertEqual(command[command.index('--timeout-factor')+1],'40.0')
        self.assertEqual(command[command.index('--timeout')+1],'96000')

    def test_native_recorded_timing_cannot_differ_from_effective_inherited_timing(self):
        report=self.native_feature_fixture('OFF','skipped',extra='--timeout-factor=5')
        self.assertEqual(report['status'],'failed')
        self.assertIn('configuration or timing differs',report['error'])

    def test_native_enabled_feature_skip_and_disabled_feature_failure_remain_red(self):
        for feature,status,category in [('ON','skipped','unverified'),('OFF','failed','failed')]:
            with self.subTest(feature=feature,status=status):
                report=self.native_feature_fixture(feature,status)
                self.assertEqual(report['status'],'failed')
                self.assertEqual(report['counts'],{'passed':2,category:2})

    def test_native_case_results_must_match_the_raw_exit_status(self):
        for status,raw_exit in [('passed',1),('skipped',0),('failed',2)]:
            with self.subTest(status=status,raw_exit=raw_exit):
                report=self.native_feature_fixture('OFF',status,raw_exit)
                self.assertEqual(report['status'],'failed')
                self.assertIn('exit status differs',report['error'])


if __name__ == '__main__':
    unittest.main()
