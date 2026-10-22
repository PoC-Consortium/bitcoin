#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin PoCX developers
# Distributed under the MIT software license; see COPYING.
"""Inherited CI ordering, feature selection and failure-propagation checks.

These are infrastructure checks; fake recipe callbacks are never framework or
hosted execution evidence. No container, installation or privileged recipe runs.
"""
import importlib.util
import io
from contextlib import redirect_stdout
import hashlib
import json
import os
from pathlib import Path
import shlex
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

import inherited_ci
import inherited_functional as functional
import inherited_selection
import process_tree
import inherited_tests as tests
from common import ROOT


class InheritedTest(unittest.TestCase):
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
            self.assertIn('-DENABLE_WALLET=OFF', flags)
            self.assertIn('-DSANITIZERS=thread', flags)
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
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        self.assertEqual(module.test_script('/source', {}), ['python3','/source/test/pocx/inherited_ci.py'])
        self.assertEqual(module.test_script('/source', {'RUN_FUZZ_TESTS':'true'}), ['python3','/source/test/pocx/bitcoin_fuzz_ci.py'])
        self.assertEqual(module.imagefile('/source', {}), '/source/test/pocx/ci/test_imagefile')
        self.assertEqual(module.imagefile('/source', {'RUN_FUZZ_TESTS':'true'}), '/source/ci/test_imagefile')

    def test_runtime_prerequisites_preserve_original_scope_and_only_bind_asan_headers(self):
        spec = importlib.util.spec_from_file_location('container_runtime', ROOT/'ci/test/02_run_container.py')
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        for name in ('arm','i686_no_ipc','native_asan','native_tsan','native_msan',
                     'native_nowallet','native_previous_releases','native_alpine_musl'):
            command=['bash','-ec','source ./ci/test/00_setup_env.sh >/dev/null 2>&1; python3 -c "import json,os; print(json.dumps(dict(os.environ)))"']
            original=json.loads(subprocess.check_output(command,cwd=ROOT,text=True,
                env={'PATH':os.environ['PATH'],'FILE_ENV':'./ci/test/00_setup_env_'+name+'.sh','MAKEJOBS':'-j1'}))
            result=module.configure_runtime_environment(ROOT,original)
            self.assertEqual(result.get('PACKAGES'), original.get('PACKAGES'))
            self.assertEqual(result.get('PIP_PACKAGES'), original.get('PIP_PACKAGES'))
            if name == 'native_asan':
                self.assertIn('/usr/src:/usr/src:ro', result['CI_CONTAINER_CAP'])
                self.assertIn('/lib/modules:/lib/modules:ro', result['CI_CONTAINER_CAP'])
                for flag in ({'RUN_FUZZ_TESTS':'true'}, {'RUN_FUNCTIONAL_TESTS':'false'}):
                    inactive = dict(original, **flag)
                    self.assertEqual(module.configure_runtime_environment(ROOT, inactive), inactive)
            else:
                self.assertEqual(result, original)
            self.assertEqual(module.configure_runtime_environment(ROOT,result),result)

    def test_review_rejects_recipe_drift(self):
        self.assertTrue(inherited_ci.verify_recipe()['source_sha256'])
        original = inherited_ci.sha256
        with patch.object(inherited_ci, 'sha256', side_effect=lambda p: '0'*64 if p.name=='03_test_script.sh' else original(p)):
            with self.assertRaisesRegex(ValueError, 'changed without review'):
                inherited_ci.verify_recipe()

    def test_actual_tracing_recipes_match_host_header_provisioning(self):
        workflow = (ROOT/'.github/workflows/ci-product.yml').read_text()
        step = workflow.split('- name: Provision matching headers for enabled Linux USDT tests', 1)[1].split('\n      - name:', 1)[0]
        self.assertIn("env.CONTAINER_NAME == 'ci_native_asan'", step)
        profiles = ['ci_native_asan']
        self.assertEqual(len(profiles), len(set(profiles)))
        spec = importlib.util.spec_from_file_location('tracing_entry', ROOT/'ci/test/02_run_container.py')
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
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
            try:
                inherited_ci.execute(inherited_ci.plan(self.env()), path, run=recipe)
            except ValueError:
                pass
            return json.loads((path/'results.json').read_text()), called

    def test_original_failure_never_launches_native(self):
        report, calls = self.execute_fixture([7])
        self.assertEqual(report['status'], 'failed')
        self.assertEqual(len(calls), 1)
        self.assertEqual(report['native_execution'], 'deferred')

    def include_edit_fixture(self, *, iwyu=True, returncode=0, other_source=False):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            cpp = root / 'src/example.cpp'
            cpp.parent.mkdir()
            original = b'#include <vector>\nint main(){return 0;}\n'
            cpp.write_bytes(original)
            helper = root / 'test/pocx/helper.py'
            helper.parent.mkdir(parents=True)
            helper.write_text('original\n')
            def snapshot(directory):
                return {str(p.relative_to(root)): hashlib.sha256(p.read_bytes()).hexdigest()
                        for p in (cpp, helper)}
            pair = [{'consensus': name, 'command': ['controlled-include-analysis'],
                     'environment': {'HOST': 'x86_64-pc-linux-gnu',
                         'RUN_IWYU': 'true' if iwyu else 'false',
                         'BASE_BUILD_DIR': str(root / ('build-' + name)),
                         'BASE_OUTDIR': str(root / ('out-' + name)),
                         'BITCOIN_CONFIG': '-DENABLE_POCX=' + enabled}}
                    for name, enabled in (('bitcoin', 'OFF'), ('pocx', 'ON'))]
            calls = []
            def recipe(command, **kwargs):
                calls.append(kwargs['env']['BITCOIN_CONFIG'])
                if len(calls) == 2:
                    self.assertEqual(cpp.read_bytes(), original)
                cpp.write_text('int main(){return 0;}\n')
                if other_source:
                    helper.write_text('unexpected source edit\n')
                return subprocess.CompletedProcess(command, returncode)
            output = root / 'execution'
            with patch.object(inherited_ci, 'source_snapshot', side_effect=snapshot):
                try:
                    inherited_ci.execute(pair, output, root=root, run=recipe)
                except ValueError:
                    pass
            report = json.loads((output / 'results.json').read_text())
            suggestions = [(output / (name + '-iwyu-suggestions.patch')).read_text()
                           for name in ('bitcoin', 'pocx')
                           if (output / (name + '-iwyu-suggestions.patch')).is_file()]
            return report, calls, cpp.read_bytes(), original, suggestions

    def test_iwyu_warning_edits_retained_and_restored_before_native(self):
        report, calls, actual, original, suggestions = self.include_edit_fixture()
        self.assertEqual(report['status'], 'passed')
        self.assertEqual(len(calls), 2)
        self.assertEqual(actual, original)
        self.assertEqual(len(suggestions), 2)
        self.assertTrue(all('-#include <vector>' in suggestion for suggestion in suggestions))
        for step in report['steps']:
            proof = step['iwyu_source_restoration']
            self.assertTrue(proof['inputs_restored'])
            self.assertEqual([row['path'] for row in proof['changes']], ['src/example.cpp'])
            self.assertNotEqual(proof['changes'][0]['before_sha256'], proof['changes'][0]['analysis_sha256'])

    def test_iwyu_enforced_failure_stays_failed_and_native_deferred(self):
        report, calls, actual, original, suggestions = self.include_edit_fixture(returncode=1)
        self.assertEqual(report['status'], 'failed')
        self.assertEqual(report['steps'][0]['returncode'], 1)
        self.assertEqual(report['native_execution'], 'deferred')
        self.assertEqual(len(calls), 1)
        self.assertEqual(actual, original)
        self.assertEqual(len(suggestions), 1)

    def test_iwyu_does_not_accept_unrelated_source_changes(self):
        report, calls, actual, original, _ = self.include_edit_fixture(other_source=True)
        self.assertEqual(report['status'], 'failed')
        self.assertIn('Source inputs changed', report['error'])
        self.assertEqual(report['native_execution'], 'deferred')
        self.assertEqual(len(calls), 1)
        self.assertEqual(actual, original)

    def test_other_recipes_still_reject_cpp_source_changes(self):
        report, calls, actual, original, suggestions = self.include_edit_fixture(iwyu=False)
        self.assertEqual(report['status'], 'failed')
        self.assertIn('Source inputs changed', report['error'])
        self.assertEqual(report['native_execution'], 'deferred')
        self.assertEqual(len(calls), 1)
        self.assertNotEqual(actual, original)
        self.assertEqual(suggestions, [])

    def test_evidence_retention_is_new_bounded_and_avoids_symlinks(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            build = root/'build'
            build.mkdir()
            old = build/'bitcoin-unit-old'
            old.mkdir()
            (old/'results.json').write_text('old')
            before = inherited_ci.evidence_directories(build)
            current = build/'pocx-inherited-functional-new'
            current.mkdir()
            (current/'results.json').write_text('new')
            nested = current/'functional'
            nested.mkdir()
            (nested/'cases.csv').write_text('cases')
            deep = nested/'node-data'
            deep.mkdir()
            (deep/'debug.log').write_text('not a report')
            (current/'binary.dat').write_text('not a report')
            (current/'linked.log').symlink_to(old/'results.json')
            (current/'linked-directory').symlink_to(old, target_is_directory=True)
            ignored = build/'other-tests'
            ignored.mkdir()
            (ignored/'results.json').write_text('other')
            destination = root/'output'
            retained = inherited_ci.retain_evidence(build, before, destination)
            self.assertEqual(set(retained), {'pocx-inherited-functional-new/results.json',
                                            'pocx-inherited-functional-new/functional/cases.csv'})
            self.assertEqual(len([p for p in destination.rglob('*') if p.is_file()]), 2)

    def test_both_transport_raw_rpc_coverage_is_retained_without_node_data(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            build = root / 'build'
            report = build / 'pocx-results-fixture'
            report.mkdir(parents=True)
            for prefix in ('rpc-coverage', 'v2/rpc-coverage'):
                directory = report / prefix
                directory.mkdir(parents=True)
                (directory / 'rpc_interface.txt').write_text('getblockcount\n')
                (directory / 'coverage.123.node0').write_text('getblockcount\n')
                (directory / 'node-data.dat').write_text('not coverage')
                (directory / 'coverage.link').symlink_to(directory / 'node-data.dat')
            retained = inherited_ci.retain_evidence(build, set(), root / 'out')
            expected = {'pocx-results-fixture/' + prefix + '/' + name
                        for prefix in ('rpc-coverage', 'v2/rpc-coverage')
                        for name in ('rpc_interface.txt', 'coverage.123.node0')}
            self.assertEqual(set(retained), expected)

    def test_short_native_result_paths_retain_proofs_and_case_logs_without_node_data(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            build = root / 'build'
            build.mkdir()
            before = inherited_ci.evidence_directories(build)
            result = build / 't/pocx-results-native'
            files = ['results.json', 'wallet_basic.py.log', 'wallet_basic/test_framework.log',
                     'v2/wallet_basic.py.log', 'v2/wallet_basic/test_framework.log']
            for name in files + ['wallet_basic/node0/regtest/wallets/wallet.dat']:
                path = result / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text('raw failure details')
            (result / 'wallet_basic/node0/loop').symlink_to(result, target_is_directory=True)
            retained = inherited_ci.retain_evidence(build, before, root / 'retained')
            self.assertEqual(set(retained), {'t/pocx-results-native/' + name for name in files})

    def test_read_only_result_discovery_does_not_create_scratch_directories(self):
        with tempfile.TemporaryDirectory() as directory:
            build = Path(directory) / 'missing-build'
            self.assertEqual(inherited_ci.evidence_directories(build), set())
            self.assertFalse(build.exists())

    def test_live_recipe_output_arrives_before_exit_and_preserves_bytes_and_failure(self):
        import ci_logging
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            gate = root / 'console-observed'
            class ConsoleBuffer(io.BytesIO):
                def write(self, block):
                    if b'ready' in block:
                        gate.touch()
                    return super().write(block)
            console = io.TextIOWrapper(ConsoleBuffer(), encoding='utf8', errors='replace')
            code = ("import os,pathlib,time; os.write(1,b'ready\\n'); "
                    "gate=pathlib.Path('console-observed'); deadline=time.monotonic()+5\n"
                    "while not gate.exists() and time.monotonic()<deadline: time.sleep(.01)\n"
                    "assert gate.exists(), 'console only received output after termination'\n"
                    "os.write(2,b'raw\\xff\\n'); raise SystemExit(7)")
            log = root / 'raw.log'
            with log.open('w') as stream, redirect_stdout(console):
                result = ci_logging.run_live([sys.executable, '-c', code], cwd=root,
                    env=dict(os.environ), stdout=stream, stderr=subprocess.STDOUT)
            self.assertEqual(result.returncode, 7)
            self.assertEqual(log.read_bytes(), b'ready\nraw\xff\n')
            self.assertEqual(console.buffer.getvalue(), log.read_bytes())

    def test_failed_recipe_reports_are_copied_and_publishable(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            env=self.env()
            env['BASE_BUILD_DIR']=str(root/'build')
            pair=inherited_ci.plan(self.env())
            pair[0]['environment']=env
            def recipe(command, **kwargs):
                evidence=Path(env['BASE_BUILD_DIR'])/'bitcoin-unit-failed'
                evidence.mkdir(parents=True)
                (evidence/'results.json').write_text('{"status":"failed"}')
                return subprocess.CompletedProcess(command,9)
            output=root/'pocx-inherited-fixture/execution'
            with self.assertRaises(ValueError):
                inherited_ci.execute(pair,output,run=recipe)
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
                    run=lambda *a,**_kw: (_ for _ in ()).throw(OSError('launch failed')))
            report=json.loads((output/'results.json').read_text())
            self.assertEqual(report['status'],'failed')
            self.assertEqual(report['steps'][0]['status'],'failed')
            self.assertEqual(report['native_execution'],'deferred')

    @unittest.skipUnless(sys.platform != 'win32', 'POSIX artifact permission proof')
    def test_published_root_step_reports_are_readable_by_artifact_uploader(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            output=root/'pocx-inherited-fixture/execution'
            output.mkdir(parents=True,mode=0o700)
            log=output/'bitcoin.log'
            log.write_text('report')
            log.chmod(0o600)
            nested=output/'bitcoin-evidence'
            nested.mkdir(mode=0o700)
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
        module=importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        with tempfile.TemporaryDirectory() as directory:
            env={'BASE_READ_ONLY_DIR':directory,'BASE_ROOT_DIR':'/guest/source tree'}
            calls=[]
            def invoke(command,**kwargs):
                calls.append((command,kwargs))
                return subprocess.CompletedProcess(command,0)
            module.capture_evidence('container-id',env,invoke=invoke)
            self.assertEqual(calls,[(['docker','cp','container-id:/guest/source tree/artifacts/pocx-inherited',
                                     str(Path(directory)/'artifacts')],{'check':False})])
            with self.assertRaises(RuntimeError):
                module.capture_evidence('container-id',env,
                invoke=lambda command,**kwargs:subprocess.CompletedProcess(command,1))

    def test_native_failure_does_not_hide_original_result(self):
        report, calls = self.execute_fixture([0,8])
        self.assertEqual([s['status'] for s in report['steps']], ['passed','failed'])
        self.assertEqual(report['status'], 'failed')
        self.assertEqual(len(calls),2)

    def test_success_requires_both_recipes(self):
        report, calls = self.execute_fixture([0,0])
        self.assertEqual(report['status'], 'passed')
        self.assertEqual(len(calls),2)
        with tempfile.TemporaryDirectory() as directory:
            for pairs in ([], list(reversed(inherited_ci.plan(self.env())))):
                with self.assertRaises(ValueError):
                    inherited_ci.execute(pairs, Path(directory)/'unused')

    def test_cli_and_multiprocess_settings_preserved(self):
        profile = functional.inherited_options({'TEST_RUNNER_EXTRA':'--v2transport --usecli --extended', 'BITCOIN_CMD':'bitcoin -m'})
        self.assertTrue(profile['use_cli'])
        self.assertTrue(profile['multiprocess'])
        self.assertEqual(profile['transports'], ['v2'])
        for env in ({'TEST_RUNNER_EXTRA':'--exclude=wallet_basic'}, {'BITCOIN_CMD':'other-command'}):
            with self.subTest(env=env), self.assertRaises(ValueError):
                functional.inherited_options(env)

    def test_inherited_timeout_factor_is_explicit_finite_and_unambiguous(self):
        for text in ('--timeout-factor=40','--timeout-factor 40'):
            profile=functional.inherited_options({'TEST_RUNNER_EXTRA':text+' --usecli'})
            self.assertEqual(profile['timeout_factor'],40)
            self.assertTrue(profile['use_cli'])
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
            self.assertEqual(state,'configuration-disabled')
            self.assertIn(flag+'=OFF',reason)

    def test_only_unconditional_guards_allow_feature_omissions(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            path=root/'test/functional/feature_probe.py'
            path.parent.mkdir(parents=True)
            path.write_text('class Probe:\n def skip_test_if_missing_module(self):\n  if condition:\n   self.skip_if_no_wallet()\n')
            self.assertIsNone(functional.disabled_reason(path.name, {'ENABLE_WALLET':'OFF'}, functional.inherited_options({}), root=root))

    def test_cli_opt_outs_require_cli_profile_and_explicit_executed_source(self):
        cli = functional.inherited_options({'TEST_RUNNER_EXTRA': '--usecli --previous-releases'})
        rpc = functional.inherited_options({'TEST_RUNNER_EXTRA': '--previous-releases'})
        for native, names in [(False, ['feature_dbcrash.py', 'mining_getblocktemplate_longpoll.py',
                                       'interface_rest.py', 'interface_rpc.py', 'rpc_rawtransaction.py']),
                              (True, ['mining_getblocktemplate_longpoll.py', 'interface_rest.py', 'wallet_migration.py'])]:
            for name in names:
                with self.subTest(native=native, name=name):
                    state, reason = functional.classify(name, 'Skipped', {}, cli, native=native)
                    self.assertEqual(state, 'configuration-disabled')
                    self.assertIn('supports_cli=False', reason)
                    self.assertIn(name, reason)
                    self.assertEqual(functional.classify(name, 'Skipped', {}, rpc, native=native)[0], 'unverified')
                    self.assertEqual(functional.classify(name, 'Failed', {}, cli, native=native)[0], 'failed')
        self.assertEqual(functional.classify('p2p_ping.py', 'Skipped', {}, cli)[0], 'unverified')

    def test_cli_guard_does_not_execute_modules_or_accept_ambiguous_opt_outs(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / 'test/functional/feature_probe.py'
            path.parent.mkdir(parents=True)
            profile = functional.inherited_options({'TEST_RUNNER_EXTRA': '--usecli'})
            prefix = 'raise RuntimeError("do not import test modules")\n'
            suffix = '\nif __name__ == "__main__":\n Probe(__file__).main()\n'
            for body in ['self.supports_cli = False',
                         'if condition:\n   self.supports_cli = False',
                         'self.supports_cli = False\n  self.supports_cli = True',
                         'return\n  self.supports_cli = False',
                         'if condition:\n   return\n  self.supports_cli = False',
                         'self.supports_cli = 0']:
                with self.subTest(body=body):
                    path.write_text(prefix + 'class Probe(BitcoinTestFramework):\n def set_test_params(self):\n  ' + body + suffix)
                    state, _ = functional.classify(path.name, 'Skipped', {}, profile, root=root)
                    self.assertEqual(state, 'configuration-disabled' if body == 'self.supports_cli = False' else 'unverified')
            for source in [
                    'class Helper(BitcoinTestFramework):\n def set_test_params(self):\n  self.supports_cli = False\nclass Probe(BitcoinTestFramework):\n pass',
                    'class Probe(Other, BitcoinTestFramework):\n def set_test_params(self):\n  self.supports_cli = False',
                    'class Probe(Parent):\n def set_test_params(self):\n  self.supports_cli = False',
                    'class Probe(BitcoinTestFramework):\n def set_test_params(self):\n  self.supports_cli = False\n def run_test(self):\n  self.supports_cli = True']:
                with self.subTest(source=source):
                    path.write_text(prefix + source + suffix)
                    self.assertEqual(functional.classify(path.name, 'Skipped', {}, profile, root=root)[0], 'unverified')

    def test_cli_mixins_must_resolve_without_overriding_runtime_setup(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / 'test/functional/feature_probe.py'
            path.parent.mkdir(parents=True)
            profile = functional.inherited_options({'TEST_RUNNER_EXTRA': '--usecli'})
            for body in ['def helper(self):\n  pass', 'def setup(self):\n  pass',
                         'def __init__(self):\n  pass', 'def set_test_params(self):\n  pass',
                         'def helper(self):\n  self.supports_cli = True']:
                with self.subTest(body=body):
                    path.write_text('class Mixin:\n ' + body + '\nclass Probe(Mixin, BitcoinTestFramework):\n'
                                    ' def set_test_params(self):\n  self.supports_cli = False\n'
                                    'if __name__ == "__main__":\n Probe(__file__).main()\n')
                    state, _ = functional.classify(path.name, 'Skipped', {}, profile, root=root)
                    self.assertEqual(state, 'configuration-disabled' if body == 'def helper(self):\n  pass' else 'unverified')

    def test_native_inherited_wallet_guards_require_disabled_wallet(self):
        profile = functional.inherited_options({})
        for name, origin in [
                ('feature_pocx_assignment_multinode.py', 'feature_pocx_assignment_lifecycle.py'),
                ('feature_pocx_assignment_multinode_attacks.py', 'feature_pocx_assignment_lifecycle.py'),
                ('feature_pocx_scheduler_early_height.py', 'feature_pocx_scheduler_payout.py')]:
            with self.subTest(name=name):
                state, reason = functional.classify(name, 'skipped', {'ENABLE_WALLET': 'OFF'}, profile, native=True)
                self.assertEqual(state, 'configuration-disabled')
                self.assertIn(origin, reason)
                self.assertEqual(functional.classify(name, 'skipped', {'ENABLE_WALLET': 'ON'}, profile, native=True)[0], 'unverified')
                self.assertEqual(functional.classify(name, 'failed', {'ENABLE_WALLET': 'OFF'}, profile, native=True)[0], 'failed')

    def test_inherited_guards_parse_aliases_without_importing_test_modules(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            package = root / 'test/functional'
            package.mkdir(parents=True)
            (package / 'guard_parent.py').write_text(
                'raise RuntimeError("must not execute test modules during classification")\n'
                'class Parent:\n def skip_test_if_missing_module(self):\n  self.skip_if_no_wallet()\n')
            (package / 'guard_middle.py').write_text('from guard_parent import Parent as Renamed\nclass Middle(Renamed):\n pass\n')
            child = package / 'feature_probe.py'
            child.write_text('from guard_middle import Middle\nclass Child(Middle):\n pass\n')
            reason = functional.disabled_reason(child.name, {'ENABLE_WALLET': 'OFF'}, functional.inherited_options({}), root=root)
            self.assertIn('guard_parent.py', reason)

    def test_inherited_guards_do_not_bypass_overrides_or_conditional_guards(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            package = root / 'test/functional'
            package.mkdir(parents=True)
            parent = package / 'guard_parent.py'
            parent.write_text('class Parent:\n def skip_test_if_missing_module(self):\n  self.skip_if_no_wallet()\n')
            child = package / 'feature_probe.py'
            for body in ['def skip_test_if_missing_module(self):\n  pass',
                         'def skip_test_if_missing_module(self):\n  if condition:\n   super().skip_test_if_missing_module()',
                         'def skip_test_if_missing_module(self):\n  return\n  self.skip_if_no_wallet()']:
                with self.subTest(body=body):
                    child.write_text('from guard_parent import Parent\nclass Child(Parent):\n ' + body + '\n')
                    self.assertIsNone(functional.disabled_reason(child.name, {'ENABLE_WALLET': 'OFF'}, functional.inherited_options({}), root=root))
            parent.write_text('class Parent:\n def skip_test_if_missing_module(self):\n  if condition:\n   self.skip_if_no_wallet()\n')
            child.write_text('from guard_parent import Parent\nclass Child(Parent):\n pass\n')
            self.assertIsNone(functional.disabled_reason(child.name, {'ENABLE_WALLET': 'OFF'}, functional.inherited_options({}), root=root))

    def test_inherited_guard_cycles_and_ambiguous_bases_remain_unverified(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            package = root / 'test/functional'
            package.mkdir(parents=True)
            (package / 'guard_parent.py').write_text('from feature_probe import Child\nclass Parent(Child):\n pass\n')
            child = package / 'feature_probe.py'
            child.write_text('from guard_parent import Parent\nclass Child(Parent):\n pass\n')
            self.assertIsNone(functional.disabled_reason(child.name, {'ENABLE_WALLET': 'OFF'}, functional.inherited_options({}), root=root))
            (package / 'guard_parent.py').write_text('class Parent:\n def skip_test_if_missing_module(self):\n  self.skip_if_no_wallet()\n')
            child.write_text('from guard_parent import Parent\nclass Child(Other, Parent):\n pass\n')
            self.assertIsNone(functional.disabled_reason(child.name, {'ENABLE_WALLET': 'OFF'}, functional.inherited_options({}), root=root))
            child.write_text('from guard_parent import Parent\nclass Helper(Parent):\n pass\nclass ActualTest:\n pass\n')
            self.assertIsNone(functional.disabled_reason(child.name, {'ENABLE_WALLET': 'OFF'}, functional.inherited_options({}), root=root))

    def test_auxiliary_zero_missing_duplicate_failed_or_skipped_rejected(self):
        valid='<testsuite><testcase name="library"/></testsuite>'
        self.assertEqual(tests.verify_auxiliary(valid,['library']), ['library'])
        for xml in ('<testsuite/>',valid.replace('/>','><skipped/></testcase>'),
                    valid.replace('/>','><failure/></testcase>'),
                    valid.replace('</testsuite>','<testcase name="library"/></testsuite>')):
            with self.subTest(xml=xml), self.assertRaises(ValueError):
                tests.verify_auxiliary(xml,['library'])

    def test_framework_dispatch_requires_native_full_unit_and_original_kernel(self):
        options={'ENABLE_POCX':'ON','BUILD_GUI':'ON','BUILD_GUI_TESTS':'ON','BUILD_KERNEL_LIB':'ON','BUILD_KERNEL_TEST':'ON'}
        commands,disabled=tests.framework_commands(ROOT/'build-probe',options,4,2400,ROOT/'build-output')
        self.assertEqual([name for name,_ in commands], ['unit','qt','kernel'])
        self.assertFalse(disabled)
        self.assertIn('--all',commands[0][1])
        self.assertNotIn('--bitcoin',commands[-1][1])
        commands,_=tests.framework_commands(ROOT/'build-probe',{**options,'ENABLE_POCX':'OFF'},4,2400,ROOT/'build-output')
        self.assertIn('--bitcoin',commands[-1][1])
        self.assertIn('run_bitcoin_unit.py',commands[0][1][1])
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
        if multi:
            directory/='Release'
        directory.mkdir(parents=True)
        if multiprocess:
            for name in ('bitcoin','bitcoin-node'):
                # Match the native host suffix; this is only a fake inventory.
                import build_configuration
                path=build_configuration.executable(root,name,(root/'CMakeCache.txt').read_text(),'Release' if multi else None)
                path.write_bytes(b'never executed fixture binary')

    def test_jobs_and_disabled_frameworks_are_explicit(self):
        for value in ('4','-j4','-j 4'):
            self.assertEqual(tests.jobs(value),4)
        for value in ('0','-j0','-1','-j4 --other'):
            with self.subTest(value=value),self.assertRaises(Exception):
                tests.jobs(value)
        commands,disabled=tests.framework_commands(ROOT/'build-probe',{'ENABLE_POCX':'OFF','BUILD_GUI':'OFF','BUILD_KERNEL_LIB':'OFF'},4,2400,ROOT/'build-output')
        self.assertEqual([name for name,_ in commands],['unit'])
        self.assertEqual(set(disabled),{'qt','kernel'})

    def original_functional_fixture(self, status, *, multi=False, extra='', raw_exit=0, aggregate='Passed',
                                    abi_adapter=False, changed_view=False):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            output=root/'output'
            self.functional_build_fixture(root,multi=multi)
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
                    patch.object(functional.original_usdt,'required',return_value=abi_adapter), \
                    patch.object(functional.original_usdt,'stage',return_value=(root/'private-view',{'fixture':True})) as stage_view, \
                    patch.object(functional.original_usdt,'verify',return_value={'fixture':not changed_view}) as verify_view, \
                    patch.object(functional.subprocess,'run',side_effect=original_runner):
                try:
                    functional.run(root,output,{'ENABLE_POCX':'OFF','BUILD_BENCH':'ON'},4,40,
                    environment={'TEST_RUNNER_EXTRA':extra},selected_config='Release' if multi else None)
                except ValueError:
                    pass
                if abi_adapter and raw_exit == 0 and status == 'Passed':
                    stage_view.assert_called_once_with(root,output)
                    verify_view.assert_called_once_with(root/'private-view',root)
            self.assertTrue((output/'cases.csv').is_file())
            return json.loads((output/'results.json').read_text())

    def test_original_functional_dispatch_retains_upstream_default_selection(self):
        report=self.original_functional_fixture('Passed')
        self.assertEqual(report['status'],'passed')
        self.assertEqual({row['transport'] for row in report['cases']},{'v1'})
        self.assertEqual(report['counts'],{'passed':1})

    def test_original_i686_dispatch_uses_verified_view_for_selected_transport(self):
        report=self.original_functional_fixture('Passed',abi_adapter=True)
        self.assertEqual(report['status'],'passed')
        self.assertEqual(report['original_usdt_staging'],{'fixture':True})
        self.assertEqual({row['transport'] for row in report['cases']},{'v1'})
        self.assertTrue(all('private-view/test/functional/test_runner.py' in row['command'][1]
                            for row in report['runs']))

    def test_changed_original_i686_view_cannot_promote_completed_cases(self):
        report=self.original_functional_fixture('Passed',abi_adapter=True,changed_view=True)
        self.assertEqual(report['status'],'failed')
        self.assertEqual(report['counts'],{'passed':1})
        self.assertIn('staging changed',report['error'])

    def test_original_green_aggregate_cannot_hide_missing_enabled_case(self):
        report=self.original_functional_fixture('Skipped')
        self.assertEqual(report['status'],'failed')
        self.assertEqual(report['counts'],{'unverified':1})

    def test_original_failure_preserves_red_cases_and_missing_transport(self):
        report=self.original_functional_fixture('Failed',raw_exit=1,aggregate='Failed')
        self.assertEqual(report['status'],'failed')
        self.assertEqual(report['counts'],{'failed':1})
        self.assertEqual([(row['transport'],row['status']) for row in report['cases']],
                         [('v1','failed')])
        self.assertEqual(len(report['runs']),1)
        self.assertEqual(report['runs'][0]['returncode'],1)

    def test_original_abnormal_exit_keeps_passed_rows_without_promoting_profile(self):
        report=self.original_functional_fixture('Passed',raw_exit=2)
        self.assertEqual(report['status'],'failed')
        self.assertEqual(report['counts'],{'passed':1})
        self.assertEqual(len(report['runs']),1)

    def test_original_multi_configuration_preserves_inherited_timeout_and_binary_paths(self):
        report=self.original_functional_fixture('Passed',multi=True,extra='--timeout-factor=7.5')
        self.assertEqual(report['status'],'passed')
        self.assertEqual(report['build_configuration'],'Release')
        self.assertEqual(report['profile']['effective_timeout_factor'],7.5)
        self.assertTrue(all('--timeout-factor=7.5' in row['command'] for row in report['runs']))

    def scoped_native_fixture(self, data, extra):
        # Synthetic process-control proof for controller contract checks only.
        manifest = {'tests': {spec['test']: 'synthetic' for spec in data['provenance']['selected_cases']},
                    'reused_tests': []}
        scope = functional.inherited_options({'TEST_RUNNER_EXTRA': extra})['case_selection']
        selection, mapping, modes = inherited_selection.native_selection(manifest,
            functional.upstream_cases(ROOT / 'test/functional/test_runner.py'), scope)
        provenance = data['provenance']
        provenance.update(format_version=11, inherited_selection=scope, case_transports=mapping,
                          transport_modes=modes, selected_cases=selection, rpc_coverage=False,
                          build_configuration=provenance.get('build_configuration'),
                          process_controller=process_tree.description())
        data['results'] = [row for row in data['results'] if row['transport'] in mapping[row['case']]]
        for row in data['results']:
            kind = provenance['process_controller']['kind']
            control = {'kind': kind, 'cleanup_complete': True, 'invocation': row['command']}
            if kind == 'windows-job':
                control['job'] = 'Local\\pocx-functional-' + '1' * 32
                control['invocation'] = [sys.executable, str(process_tree.FILE), '--windows-worker',
                                         control['job'], '--', *row['command']]
            row['process_control'] = control
        return manifest

    def test_native_functional_report_and_cli_modes_are_retained(self):
        from functional_cases import case_spec,selection_digest
        import functional_execution
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            output=root/'output'
            proof=root/'native-proof'
            proof.mkdir()
            self.functional_build_fixture(root,multiprocess=True)
            spec=case_spec('p2p_ping.py',[])
            execution=functional_execution.settings(True,True)
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
            manifest = self.scoped_native_fixture(data, '--usecli')
            (proof/'results.json').write_text(json.dumps(data))
            def native_runner(command,**kwargs):
                kwargs['stdout'].write('Results: '+str(proof)+'\n')
                return subprocess.CompletedProcess(command,0)
            with patch.object(functional,'dependency_hashes',return_value={}), \
                    patch.object(functional,'verify_current_inputs',return_value=manifest), \
                    patch.object(functional.subprocess,'run',side_effect=native_runner):
                report=functional.run(root,output,{'ENABLE_POCX':'ON','ENABLE_IPC':'ON'},4,40,
                    environment={'TEST_RUNNER_EXTRA':'--usecli','BITCOIN_CMD':'bitcoin -m'})
            self.assertEqual(report['status'],'passed')
            self.assertEqual(report['counts'],{'passed':1})
            self.assertIn('--usecli',report['runs'][0]['command'])
            self.assertIn('--multiprocess',report['runs'][0]['command'])
            self.assertEqual(len((output/'cases.csv').read_text().splitlines()),2)

    def native_feature_fixture(self, feature, status, raw_exit=1, *, multi=False, extra='', fallback_factor=40):
        from functional_cases import case_spec,selection_digest
        import functional_execution
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            output=root/'output'
            proof=root/'native-proof'
            proof.mkdir()
            self.functional_build_fixture(root,multi=multi)
            specs=[case_spec(name,[]) for name in ('p2p_ping.py','interface_ipc.py')]
            execution=functional_execution.settings()
            rows=[]
            for spec in specs:
                for mode in ('v1','v2'):
                    case_status='passed' if spec['test']=='p2p_ping.py' else status
                    flags=['--timeout-factor=40','--'+mode+'transport']
                    row={'case':spec['id'],'test':spec['test'],'case_arguments':[],
                        'transport':mode,'execution_options':execution,'test_arguments':flags,
                        'command':['python3',spec['test'],*flags],
                        'returncode':0 if case_status=='passed' else 77 if case_status=='skipped' else 1,
                        'timed_out':False,'status':case_status,'seconds':0.1}
                    if case_status=='skipped':
                        row['skip_reason']='IPC not configured'
                    rows.append(row)
            data={'provenance':{'format_version':7,'execution_options':execution,'timeout_factor':40,
                'build_configuration':'Release' if multi else None,
                'environment_profile':{'previous_releases':False,'network_addresses':False},
                'selected_tests':[spec['test'] for spec in specs],'selected_cases':specs,'transport_modes':['v1','v2'],
                'case_selection':{'selected_cases_sha256':selection_digest(specs)}},'results':rows}
            manifest = self.scoped_native_fixture(data, '--usecli' if execution['use_cli'] else extra)
            (proof/'results.json').write_text(json.dumps(data))
            def native_runner(command,**kwargs):
                kwargs['stdout'].write('Results: '+str(proof)+'\n')
                return subprocess.CompletedProcess(command,raw_exit)
            with patch.object(functional,'dependency_hashes',return_value={}), \
                    patch.object(functional,'verify_current_inputs',return_value=manifest), \
                    patch.object(functional.subprocess,'run',side_effect=native_runner):
                try:
                    functional.run(root,output,{'ENABLE_POCX':'ON','ENABLE_IPC':feature},4,fallback_factor,
                    environment={'TEST_RUNNER_EXTRA':extra},selected_config='Release' if multi else None)
                except ValueError:
                    pass
            return json.loads((output/'results.json').read_text())

    def test_native_disabled_feature_keeps_skips_explicit_without_rejecting_the_profile(self):
        report=self.native_feature_fixture('OFF','skipped')
        self.assertEqual(report['status'],'passed')
        self.assertEqual(report['counts'],{'passed':1,'configuration-disabled':1})
        disabled=[row for row in report['cases'] if row['status']=='configuration-disabled']
        self.assertEqual(len(disabled),1)
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
                self.assertEqual(report['counts'],{'passed':1,category:1})

    def test_native_case_results_must_match_the_raw_exit_status(self):
        for status,raw_exit in [('passed',1),('skipped',0),('failed',2)]:
            with self.subTest(status=status,raw_exit=raw_exit):
                report=self.native_feature_fixture('OFF',status,raw_exit)
                self.assertEqual(report['status'],'failed')
                self.assertIn('exit status differs',report['error'])


if __name__ == '__main__':
    unittest.main()
