#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin PoCX developers
# Distributed under the MIT software license; see COPYING.
"""Source-only sanitizer gate checks; fixtures below are not runtime parity."""
from copy import deepcopy
import json
from pathlib import Path
import shlex
import tempfile
import unittest
from unittest.mock import patch

from common import ROOT, sha256
from ci import options
from ci_evidence import required_steps, source_snapshot, verify_sanitizer_execution, verify_steps
import sanitizer_ci


class SanitizerInfrastructureTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.output = Path(self.temp.name)

    def test_configuration_preserves_required_upstream_asan_and_full_frameworks(self):
        for profile, consensus in [('bitcoin-asan', 'OFF'), ('pocx-asan', 'ON')]:
            flags = options(profile)
            self.assertEqual(flags['ENABLE_POCX'], consensus)
            self.assertEqual(flags['SANITIZERS'], 'address,float-divide-by-zero,integer,undefined')
            self.assertEqual(flags['CMAKE_CXX_COMPILER'], 'clang++-22')
            self.assertEqual(flags['APPEND_CPPFLAGS'], '-DARENA_DEBUG -DDEBUG_LOCKORDER')
            for feature in ('BUILD_TESTS', 'BUILD_GUI_TESTS', 'BUILD_KERNEL_TEST', 'BUILD_SHARED_LIBS',
                            'BUILD_BENCH', 'BUILD_UTIL_CHAINSTATE', 'ENABLE_WALLET', 'ENABLE_IPC', 'WITH_USDT', 'WITH_ZMQ'):
                self.assertEqual(flags[feature], 'ON')
            self.assertEqual(flags['BUILD_FUZZ_BINARY'], 'OFF')
            self.assertEqual(flags['BUILD_FOR_FUZZING'], 'OFF')

    def test_runtime_environment_overrides_inherited_nonfatal_or_disabled_checks(self):
        with patch.dict('os.environ', {'ASAN_OPTIONS': 'detect_leaks=0:halt_on_error=0:exitcode=0',
                                      'UBSAN_OPTIONS': 'halt_on_error=0', 'LSAN_OPTIONS': 'exitcode=0'}):
            env = sanitizer_ci.runtime_environment()
        self.assertIn('detect_leaks=1', env['ASAN_OPTIONS'])
        self.assertIn('halt_on_error=1', env['ASAN_OPTIONS'])
        self.assertIn('exitcode=1', env['ASAN_OPTIONS'])
        self.assertIn('halt_on_error=1', env['UBSAN_OPTIONS'])
        self.assertIn('exitcode=23', env['LSAN_OPTIONS'])
        self.assertIn(str(ROOT / 'test/sanitizer_suppressions/ubsan'), env['UBSAN_OPTIONS'])

    def test_missing_toolchain_is_an_error_not_an_unsanitized_fallback(self):
        with patch('sanitizer_ci.shutil.which', return_value=None):
            with self.assertRaisesRegex(ValueError, 'Missing required sanitizer tool: clang-22'):
                sanitizer_ci.tools()

    def test_wrong_toolchain_major_version_is_rejected(self):
        with patch('sanitizer_ci.shutil.which', return_value='/synthetic/compiler'), \
             patch('sanitizer_ci.subprocess.check_output', return_value='clang version 19.1.7'):
            with self.assertRaisesRegex(ValueError, 'Wrong required sanitizer tool version'):
                sanitizer_ci.tools()

    def compile_line(self):
        return ['clang++-22', '-std=c++20', '-ftrivial-auto-var-init=pattern',
                '-fsanitize=' + sanitizer_ci.specification()['sanitizers'],
                '-c', str(ROOT / 'src/validation.cpp'), '-o', 'validation.o',
                '-DARENA_DEBUG', '-DDEBUG_LOCKORDER', '-std=c++23']

    def test_compile_evidence_rejects_missing_overridden_and_weakened_flags(self):
        command = self.compile_line()
        result = sanitizer_ci.verify_compile_commands(shlex.join(command))
        self.assertIn(str(ROOT / 'src/validation.cpp'), result)
        for variant in ('missing', 'partial', 'disabled', 'recover', 'wrong_standard', 'missing_debug', 'missing_pattern', 'wrong_compiler'):
            tokens = command.copy()
            if variant == 'missing':
                tokens.remove('-fsanitize=' + sanitizer_ci.specification()['sanitizers'])
            elif variant == 'partial':
                tokens[tokens.index('-fsanitize=' + sanitizer_ci.specification()['sanitizers'])] = '-fsanitize=address'
            elif variant == 'disabled': tokens.append('-fno-sanitize=undefined')
            elif variant == 'recover': tokens.append('-fsanitize-recover=all')
            elif variant == 'wrong_standard': tokens.append('-std=c++20')
            elif variant == 'missing_debug': tokens.remove('-DDEBUG_LOCKORDER')
            elif variant == 'missing_pattern': tokens.remove('-ftrivial-auto-var-init=pattern')
            else: tokens[0] = 'clang++-19'
            with self.subTest(variant=variant), self.assertRaisesRegex(ValueError, 'compile flags'):
                sanitizer_ci.verify_compile_commands(shlex.join(tokens))

    def test_ninja_custom_shell_commands_are_not_mistaken_for_compilations(self):
        command = self.compile_line()
        lines = ['bash -c "cargo build"', 'python3 -c "print(1)"', shlex.join(command)]
        records = sanitizer_ci.verify_compile_commands('\n'.join(lines))
        self.assertEqual(len(records), 1)
        command[command.index('-c') + 1] = '../src/validation.cpp'
        records = sanitizer_ci.verify_compile_commands(shlex.join(command), build=ROOT / 'build-fixture')
        self.assertEqual(len(records), 1)

    def test_only_vendor_or_no_compile_commands_cannot_prove_instrumentation(self):
        for source in (ROOT / 'src/leveldb/db/db_impl.cc', ROOT / 'src/ipc/libmultiprocess/foo.cpp'):
            command = self.compile_line()
            command[command.index('-c') + 1] = str(source)
            with self.subTest(source=source), self.assertRaisesRegex(ValueError, 'No first-party'):
                sanitizer_ci.verify_compile_commands(shlex.join(command))

    def test_suppression_and_upstream_recipe_changes_invalidate_review(self):
        original = sanitizer_ci.sha256
        for name in sanitizer_ci.specification()['source_sha256']:
            with self.subTest(name=name), patch('sanitizer_ci.sha256', side_effect=lambda path:
                    'changed' if path == ROOT / name else original(path)):
                with self.assertRaisesRegex(ValueError, 'source changed since review'):
                    sanitizer_ci.specification()

    def test_suppression_sources_are_part_of_outer_execution_snapshot(self):
        for name in ['CMakeLists.txt', 'CMakePresets.json', '.github/workflows/pocx-tests.yml',
                     'test/sanitizer_suppressions/ubsan', 'ci/test/00_setup_env_native_asan.sh']:
            path = self.output / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(name)
        sources = source_snapshot(self.output)
        self.assertIn('test/sanitizer_suppressions/ubsan', sources)
        self.assertIn('ci/test/00_setup_env_native_asan.sh', sources)

    def test_sanitizer_step_inventory_requires_every_framework_and_both_gates(self):
        expected = ['drift', 'sanitizer-tools', 'sanitizer', 'unit', 'auxiliary', 'qt', 'kernel', 'functional']
        for profile in ('bitcoin-asan', 'pocx-asan'):
            self.assertEqual(required_steps(profile, True), expected)
            self.assertEqual(required_steps(profile, False), expected[:2] + ['configure', 'build'] + expected[2:])
            steps = []
            for name in expected:
                log = self.output / (name + '.log')
                log.write_text(name)
                steps.append({'name': name, 'status': 'passed', 'returncode': 0,
                              'command': ['synthetic-runner'], 'log_sha256': sha256(log)})
            report = {'profile': profile, 'skip_build': True, 'steps': steps}
            verify_steps(report, self.output)
            for name in expected:
                with self.subTest(profile=profile, name=name), self.assertRaisesRegex(ValueError, 'inventory'):
                    verify_steps({**report, 'steps': [s for s in steps if s['name'] != name]}, self.output)

    def proof(self):
        path = self.output / 'sanitizer/verification.json'
        path.parent.mkdir(exist_ok=True)
        env = sanitizer_ci.runtime_environment()
        child = {'status': 'passed', 'environment': env, 'stack_limit': 524288,
                 'instrumentation': {'compile_commands': {str(ROOT / 'src/validation.cpp'): [shlex.join(self.compile_line())]},
                                     'binaries': {}},
                 'canaries': [{'canary': name, 'status': 'passed',
                               'expected_diagnostic': diagnostic, 'returncode': 0 if diagnostic is None else 1}
                              for name, (_, diagnostic) in sanitizer_ci.CANARIES.items()]}
        report = {'profile': 'bitcoin-asan', 'build': str(ROOT / 'build-fixture'),
                  'execution_build_snapshot': {}, 'sanitizer_environment': env, 'sanitizer_stack_limit': 524288, 'steps': [
            {'name': name, 'command': ['synthetic-runner', '--timeout', '2400']}
            for name in ('unit', 'auxiliary', 'qt', 'kernel')] + [
            {'name': 'functional', 'command': ['synthetic-runner', '--timeout-factor', '40']}]}
        for name in sanitizer_ci.required_binaries(False):
            log = path.parent / 'symbols' / (name + '-symbols.log')
            log.parent.mkdir(exist_ok=True)
            log.write_text('0000 T __asan_init\n0001 T __ubsan_handle_add_overflow\n')
            child['instrumentation']['binaries'][name] = {
                'sha256': 'synthetic-binary-hash', 'symbols_log': str(log), 'symbols_sha256': sha256(log)}
            report['execution_build_snapshot']['bin/' + name] = 'synthetic-binary-hash'
        for row in child['canaries']:
            log = path.parent / 'canaries' / (row['canary'] + '.log')
            log.parent.mkdir(exist_ok=True)
            log.write_text(row['expected_diagnostic'] or '')
            row.update(log=str(log), log_sha256=sha256(log))
        (self.output / 'functional-verification.json').write_text(json.dumps({'timeout_factor': 40}))
        return path, report, child

    def save_proof(self, path, report, child):
        path.write_text(json.dumps(child))
        report['artifacts'] = {str(path): sha256(path)}

    def test_saved_proof_rejects_missing_failed_or_nonfatal_canaries(self):
        path, report, child = self.proof()
        self.save_proof(path, report, child)
        self.assertEqual(verify_sanitizer_execution(ROOT, report, self.output)['canaries'], 6)
        for variant in ('missing', 'duplicate', 'failed', 'nonfatal', 'no_instrumentation'):
            changed = deepcopy(child)
            if variant == 'missing': changed['canaries'].pop()
            elif variant == 'duplicate': changed['canaries'].append(changed['canaries'][0])
            elif variant == 'failed': changed['canaries'][1]['status'] = 'failed'
            elif variant == 'nonfatal': changed['canaries'][1]['returncode'] = 0
            else: changed['instrumentation'] = {}
            self.save_proof(path, report, changed)
            with self.subTest(variant=variant), self.assertRaises(ValueError):
                verify_sanitizer_execution(ROOT, report, self.output)

    def test_saved_proof_rejects_weakened_environment_or_unscaled_timeouts(self):
        path, report, child = self.proof()
        self.save_proof(path, report, child)
        changed = deepcopy(report)
        changed['sanitizer_environment']['UBSAN_OPTIONS'] = 'halt_on_error=0'
        with self.assertRaisesRegex(ValueError, 'environment'):
            verify_sanitizer_execution(ROOT, changed, self.output)
        changed = deepcopy(report)
        changed['steps'][0]['command'][-1] = '180'
        with self.assertRaisesRegex(ValueError, 'timeout'):
            verify_sanitizer_execution(ROOT, changed, self.output)
        (self.output / 'functional-verification.json').write_text(json.dumps({'timeout_factor': 1}))
        with self.assertRaisesRegex(ValueError, 'unscaled'):
            verify_sanitizer_execution(ROOT, report, self.output)

    def test_saved_proof_rejects_missing_or_wrong_runtime_stack_limits(self):
        path, report, child = self.proof()
        for target, key in (('parent', 'sanitizer_stack_limit'), ('child', 'stack_limit')):
            for value in (None, 8388608, -1):
                changed_report, changed_child = deepcopy(report), deepcopy(child)
                record = changed_report if target == 'parent' else changed_child
                if value is None:
                    record.pop(key)
                else:
                    record[key] = value
                self.save_proof(path, changed_report, changed_child)
                with self.subTest(target=target, value=value), self.assertRaises(ValueError):
                    verify_sanitizer_execution(ROOT, changed_report, self.output)

    def test_runtime_gate_rejects_unrestricted_stack_before_instrumentation(self):
        path = self.output / 'stack-rejection.json'
        with patch('sys.argv', ['sanitizer_ci.py', '--build-dir', str(ROOT / 'build-fixture'),
                                '--output', str(path)]), \
             patch('sanitizer_ci.tools', return_value={}), \
             patch('sanitizer_ci.resource.getrlimit', return_value=(8388608, -1)), \
             patch('sanitizer_ci.instrumentation') as instrumentation:
            self.assertEqual(sanitizer_ci.main(), 1)
        instrumentation.assert_not_called()
        report = json.loads(path.read_text())
        self.assertEqual(report['status'], 'failed')
        self.assertEqual(report['stack_limit'], 8388608)
        self.assertIn('512 KiB', report['error'])

    def test_saved_proof_requires_all_executables_and_actual_compile_flags(self):
        path, report, child = self.proof()
        for variant in ('missing_binary', 'wrong_binary_hash', 'empty_compile_commands', 'unsanitized_compile'):
            changed = deepcopy(child)
            if variant == 'missing_binary':
                changed['instrumentation']['binaries'].pop('bitcoin-cli')
            elif variant == 'wrong_binary_hash':
                changed['instrumentation']['binaries']['bitcoin-cli']['sha256'] = 'other-build'
            elif variant == 'empty_compile_commands':
                changed['instrumentation']['compile_commands'][str(ROOT / 'src/validation.cpp')] = []
            else:
                changed['instrumentation']['compile_commands'][str(ROOT / 'src/validation.cpp')] = [
                    shlex.join([token for token in self.compile_line() if not token.startswith('-fsanitize=')])]
            self.save_proof(path, report, changed)
            with self.subTest(variant=variant), self.assertRaises(ValueError):
                verify_sanitizer_execution(ROOT, report, self.output)

    def test_saved_proof_requires_runtime_symbols_and_correct_canary_logs(self):
        path, report, child = self.proof()
        log = Path(child['instrumentation']['binaries']['bitcoin-cli']['symbols_log'])
        log.write_text('0000 T main\n')
        child['instrumentation']['binaries']['bitcoin-cli']['symbols_sha256'] = sha256(log)
        self.save_proof(path, report, child)
        with self.assertRaisesRegex(ValueError, 'runtime symbols'):
            verify_sanitizer_execution(ROOT, report, self.output)
        path, report, child = self.proof()
        log = Path(child['canaries'][1]['log'])
        log.write_text('LeakSanitizer has encountered a fatal error\n')
        child['canaries'][1]['log_sha256'] = sha256(log)
        self.save_proof(path, report, child)
        with self.assertRaisesRegex(ValueError, 'diagnostic did not match'):
            verify_sanitizer_execution(ROOT, report, self.output)


if __name__ == '__main__':
    unittest.main()
