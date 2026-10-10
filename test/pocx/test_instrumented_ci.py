#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin PoCX developers
# Distributed under the MIT software license; see COPYING.
"""Source-only TSAN/MSAN rejection tests; synthetic artifacts are not runtime parity."""
from copy import deepcopy
import json
import io
from pathlib import Path
import shlex
import tempfile
import unittest
from unittest.mock import patch

from common import ROOT, sha256
from ci import options
from ci_evidence import required_steps, verify_instrumented_execution
import instrumented_ci as gate
from prepare_instrumented_dependencies import prepare
from sanitizer_ci import required_binaries


class InstrumentedInfrastructureTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='build-instrumented-fixture-', dir=ROOT)
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name)
        self.prefix = self.directory / 'depends/x86_64-pc-linux-gnu'
        (self.directory / 'preparation.json').write_text(json.dumps({'prefix': str(self.prefix)}))

    def line(self, kind):
        return shlex.join(['clang++-22', *shlex.split(gate.dependency_flags(kind, self.directory)[1]),
                           *shlex.split(gate.specification(kind)['profiles'][kind]['build_options']['APPEND_CPPFLAGS']),
                           '-std=c++20', '-c', str(ROOT / 'src/validation.cpp'), '-o', 'validation.o'])

    def test_profiles_keep_upstream_features_and_explicit_headless_boundary(self):
        for kind in ('tsan', 'msan'):
            for consensus in ('bitcoin', 'pocx'):
                result = options(consensus + '-' + kind, self.directory)
                self.assertEqual(result['ENABLE_POCX'], 'OFF' if consensus == 'bitcoin' else 'ON')
                self.assertEqual(result['SANITIZERS'], 'thread' if kind == 'tsan' else 'memory')
                for key in ('BUILD_TESTS', 'BUILD_KERNEL_TEST', 'BUILD_KERNEL_LIB', 'BUILD_SHARED_LIBS',
                            'BUILD_BENCH', 'BUILD_UTIL_CHAINSTATE', 'WITH_USDT', 'WITH_ZMQ', 'ENABLE_IPC', 'ENABLE_WALLET'):
                    self.assertEqual(result[key], 'ON')
                for key in ('BUILD_GUI', 'BUILD_GUI_TESTS', 'BUILD_FUZZ_BINARY', 'BUILD_FOR_FUZZING'):
                    self.assertEqual(result[key], 'OFF')
                self.assertEqual(result['CMAKE_COMPILE_WARNING_AS_ERROR'], 'ON')
                self.assertEqual(result['CMAKE_TOOLCHAIN_FILE'], str(self.prefix / 'toolchain.cmake'))
        with self.assertRaisesRegex(ValueError, 'preparation directory'):
            options('bitcoin-tsan')

    def test_memory_origins_and_debug_flags_are_preserved(self):
        result = options('bitcoin-msan', self.directory)
        self.assertEqual(result['CMAKE_BUILD_TYPE'], 'Debug')
        self.assertEqual(result['CMAKE_C_FLAGS_DEBUG'], '')
        self.assertEqual(result['CMAKE_CXX_FLAGS_DEBUG'], '')
        self.assertEqual(result['APPEND_CPPFLAGS'], '-U_FORTIFY_SOURCE')
        self.assertIn('-fsanitize-memory-track-origins=2', result['CMAKE_C_FLAGS'])
        self.assertIn('-fsanitize-memory-track-origins=2', result['CMAKE_CXX_FLAGS'])
        result = options('bitcoin-tsan', self.directory)
        self.assertEqual(result['APPEND_CPPFLAGS'], '-DARENA_DEBUG -DDEBUG_LOCKCONTENTION -D_LIBCPP_REMOVE_TRANSITIVE_INCLUDES')

    def test_dependency_flags_instrument_the_required_languages(self):
        thread = gate.dependency_options('tsan', self.directory)
        memory = gate.dependency_options('msan', self.directory)
        self.assertIn('NO_QT=1', thread)
        self.assertFalse(any(item.startswith('CFLAGS=') for item in thread))
        self.assertIn('DEBUG=1', memory)
        self.assertTrue(any(item.startswith('CFLAGS=-fsanitize=memory') for item in memory))
        for values in (thread, memory):
            flags = next(item for item in values if item.startswith('CXXFLAGS='))
            for required in ('-nostdinc++', '-nostdlib++', '-lc++', '-lc++abi'):
                self.assertIn(required, flags)

    def test_missing_or_old_toolchain_cannot_fall_back(self):
        with patch('instrumented_ci.shutil.which', return_value=None):
            with self.assertRaisesRegex(ValueError, 'Missing required sanitizer tool: clang-22'):
                gate.tools('tsan')
        with patch('instrumented_ci.shutil.which', return_value='/synthetic/compiler'), \
             patch('instrumented_ci.subprocess.check_output', return_value='clang version 19.1.7'):
            with self.assertRaisesRegex(ValueError, 'Wrong required sanitizer tool version'):
                gate.tools('msan')

    def test_recipe_and_suppression_changes_invalidate_preparation(self):
        original = gate.sha256
        for name in ('depends/toolchain.cmake.in', 'depends/packages/capnp.mk', 'test/sanitizer_suppressions/tsan'):
            with self.subTest(name=name), patch('instrumented_ci.sha256', side_effect=lambda path:
                    'changed' if path == ROOT / name else original(path)):
                with self.assertRaisesRegex(ValueError, 'recipe changed'):
                    gate.specification('tsan')

    def test_compile_proof_rejects_system_cpp_and_weakened_instrumentation(self):
        for kind in ('tsan', 'msan'):
            command = self.line(kind)
            self.assertEqual(len(gate.compile_commands(command, kind, self.directory, ROOT / 'build-fixture')), 1)
            tokens = shlex.split(command)
            variants = [tokens + ['-fno-sanitize=all'], tokens + ['-fsanitize=address'],
                        [value for value in tokens if value != '-nostdlib++'],
                        ['clang++-19', *tokens[1:]]]
            variants.append(tokens + ['-fsanitize-memory-track-origins=0'] if kind == 'msan'
                            else [value for value in tokens if value != '-DDEBUG_LOCKCONTENTION'])
            for variant in variants:
                with self.subTest(kind=kind, variant=variant), self.assertRaises(ValueError):
                    gate.compile_commands(shlex.join(variant), kind, self.directory, ROOT / 'build-fixture')

    def test_custom_commands_and_vendor_only_inputs_do_not_prove_instrumentation(self):
        for kind in ('tsan', 'msan'):
            text = 'bash -c "cargo build"\n' + self.line(kind)
            self.assertEqual(len(gate.compile_commands(text, kind, self.directory, ROOT / 'build-fixture')), 1)
            text = self.line(kind).replace('src/validation.cpp', 'src/leveldb/db/db_impl.cc')
            with self.assertRaisesRegex(ValueError, 'No instrumented first-party'):
                gate.compile_commands(text, kind, self.directory, ROOT / 'build-fixture')

    def dependencies(self, kind):
        spec = deepcopy(gate.specification(kind))
        archive = self.directory / 'llvm.src.tar.xz'
        archive.write_bytes(b'Synthetic pinned archive fixture; not LLVM sources')
        spec['llvm']['sha256'] = sha256(archive)
        files = {'libcxx/CMakeCache.txt': '\n'.join(f'{key}:STRING={value}' for key, value in {
            **spec['libcxx_options'], 'LLVM_USE_SANITIZER': spec['profiles'][kind]['libcxx_sanitizer']}.items()),
            'libcxx/build.ninja': 'synthetic', 'libcxx/CMakeFiles/rules.ninja': 'synthetic',
            'depends/x86_64-pc-linux-gnu/toolchain.cmake': 'synthetic'}
        for name, text in files.items():
            path = self.directory / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text)
        report = {'status': 'passed', 'sanitizer': kind, 'source_sha256': spec['source_sha256'],
                  'llvm_archive_sha256': spec['llvm']['sha256'],
                  'builder_sha256': sha256(ROOT / 'test/pocx/prepare_instrumented_dependencies.py'),
                  'host': self.prefix.name, 'prefix': str(self.prefix), 'depends_options': gate.dependency_options(kind, self.directory),
                  'tools': {'synthetic-toolchain': kind}, 'steps': {}, 'archive_instrumentation': {}, 'libcxx_instrumentation': {}}
        for name in ('libcxx-configure', 'libcxx-build', 'depends-build'):
            path = self.directory / (name + '.log')
            path.write_text('synthetic passing build fixture')
            report['steps'][name] = {'returncode': 0, 'log_sha256': sha256(path)}
        archives = ['libcapnp.a', 'libkj.a', 'libzmq.a'] + (['libevent.a', 'libsqlite3.a'] if kind == 'msan' else [])
        for name in archives + ['libc++.so.1', 'libc++abi.so.1']:
            path = (self.prefix / 'lib' if name.endswith('.a') else self.directory / 'libcxx/lib') / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text('Synthetic instrumented library fixture')
            log = self.directory / (name + '-symbols.log')
            log.write_text('__tsan_init' if kind == 'tsan' else '__msan_init')
            field = 'archive_instrumentation' if name.endswith('.a') else 'libcxx_instrumentation'
            report[field][name] = {'sha256': sha256(path), 'symbols_sha256': sha256(log)}
        report['installed_inputs'] = gate.installed_inputs(self.directory, self.prefix)
        (self.directory / 'preparation.json').write_text(json.dumps(report))
        return spec, report

    def test_dependency_preparation_requires_every_archive_and_correct_provenance(self):
        for kind in ('tsan', 'msan'):
            spec, report = self.dependencies(kind)
            with patch('instrumented_ci.specification', return_value=spec), \
                 patch('instrumented_ci.tools', return_value=report['tools']):
                self.assertEqual(gate.verify_dependencies(kind, self.directory)['status'], 'passed')
                for variant in ('failed_build', 'missing_archive', 'wrong_kind', 'wrong_builder', 'changed_inputs', 'wrong_flags'):
                    changed = deepcopy(report)
                    if variant == 'failed_build': changed['steps']['depends-build']['returncode'] = 1
                    elif variant == 'missing_archive': changed['archive_instrumentation'].pop('libcapnp.a')
                    elif variant == 'wrong_kind': changed['sanitizer'] = 'other'
                    elif variant == 'wrong_builder': changed['builder_sha256'] = 'other'
                    elif variant == 'changed_inputs': changed['installed_inputs'] = {}
                    else: changed['depends_options'] = ['NO_QT=1']
                    (self.directory / 'preparation.json').write_text(json.dumps(changed))
                    with self.subTest(kind=kind, variant=variant), self.assertRaises(ValueError):
                        gate.verify_dependencies(kind, self.directory)

    def test_builder_stops_before_download_when_toolchain_is_missing(self):
        directory = self.directory / 'new-preparation'
        with patch('prepare_instrumented_dependencies.tools', side_effect=ValueError('Missing required sanitizer tool: clang-22')), \
             patch('prepare_instrumented_dependencies.urllib.request.urlopen') as download:
            with self.assertRaisesRegex(ValueError, 'Missing required sanitizer tool'):
                prepare('msan', directory, 1)
            download.assert_not_called()
        self.assertEqual(json.loads((directory / 'preparation.json').read_text())['status'], 'failed')

    def test_builder_rejects_an_archive_that_does_not_match_the_published_pin(self):
        directory = self.directory / 'bad-archive'
        with patch('prepare_instrumented_dependencies.tools', return_value={'synthetic': 'toolchain'}), \
             patch('prepare_instrumented_dependencies.urllib.request.urlopen', return_value=io.BytesIO(b'wrong archive')):
            with self.assertRaisesRegex(ValueError, 'source archive SHA256 mismatch'):
                prepare('tsan', directory, 1)
        report = json.loads((directory / 'preparation.json').read_text())
        self.assertEqual(report['status'], 'failed')
        self.assertEqual(report['steps'], {})

    def test_cpp_runtime_symbols_cannot_be_replaced_by_other_sanitizer_evidence(self):
        spec, report = self.dependencies('msan')
        log = self.directory / 'libc++.so.1-symbols.log'
        log.write_text('__asan_init')
        report['libcxx_instrumentation']['libc++.so.1']['symbols_sha256'] = sha256(log)
        (self.directory / 'preparation.json').write_text(json.dumps(report))
        with patch('instrumented_ci.specification', return_value=spec), \
             patch('instrumented_ci.tools', return_value=report['tools']):
            with self.assertRaisesRegex(ValueError, r'libc\+\+ runtime instrumentation'):
                gate.verify_dependencies('msan', self.directory)

    def proof(self, kind):
        # Dependencies are independently tested above. This fixture isolates
        # rejection of saved outer/runtime proof without building any code.
        output = self.directory / 'execution'
        output.mkdir(exist_ok=True)
        environment = gate.runtime_environment(kind, self.directory)
        child = {'status': 'passed', 'sanitizer': kind, 'environment': environment, 'stack_limit': 524288,
                 'dependency_proof': {'synthetic': 'verified'},
                 'instrumentation': {'compile_commands': {str(ROOT / 'src/validation.cpp'): [self.line(kind)]}, 'binaries': {}},
                 'canaries': []}
        report = {'profile': 'bitcoin-' + kind, 'build': str(ROOT / 'build-fixture'),
                  'instrumented_dependencies_directory': str(self.directory), 'sanitizer_environment': environment,
                  'sanitizer_stack_limit': 524288, 'execution_build_snapshot': {},
                  'steps': [{'name': name, 'command': ['synthetic', '--timeout', '2400']}
                            for name in ('unit', 'auxiliary', 'kernel')] +
                           [{'name': 'functional', 'command': ['synthetic', '--timeout-factor', '40']}]}
        for name in set(required_binaries(False)) - {'test_bitcoin-qt'}:
            log = output / 'sanitizer/symbols' / (name + '-symbols.log')
            log.parent.mkdir(parents=True, exist_ok=True)
            log.write_text('__tsan_init' if kind == 'tsan' else '__msan_init')
            child['instrumentation']['binaries'][name] = {'sha256': 'synthetic', 'symbols_log': str(log), 'symbols_sha256': sha256(log)}
            report['execution_build_snapshot']['bin/' + name] = 'synthetic'
        for name, (_, diagnostics) in gate.CANARIES[kind].items():
            log = output / 'sanitizer/canaries' / (name + '.log')
            log.parent.mkdir(parents=True, exist_ok=True)
            log.write_text('\n'.join(diagnostics))
            child['canaries'].append({'canary': name, 'status': 'passed', 'returncode': 1 if diagnostics else 0,
                                     'expected_diagnostics': diagnostics, 'log': str(log), 'log_sha256': sha256(log)})
        (output / 'functional-verification.json').write_text(json.dumps({'timeout_factor': 40}))
        return output, report, child

    def save(self, output, report, child):
        path = output / 'sanitizer/verification.json'
        path.write_text(json.dumps(child))
        report['artifacts'] = {str(path): sha256(path)}

    def test_saved_runtime_proof_rejects_missing_nonfatal_or_unrelated_failures(self):
        for kind in ('tsan', 'msan'):
            output, report, child = self.proof(kind)
            with patch('instrumented_ci.verify_dependencies', return_value={'synthetic': 'verified'}):
                self.save(output, report, child)
                self.assertEqual(verify_instrumented_execution(ROOT, report, output)['canaries'], 2)
                for variant in ('missing', 'duplicate', 'nonfatal', 'environment_failure'):
                    changed = deepcopy(child)
                    if variant == 'missing': changed['canaries'].pop()
                    elif variant == 'duplicate': changed['canaries'].append(changed['canaries'][0])
                    elif variant == 'nonfatal': changed['canaries'][1]['returncode'] = 0
                    else:
                        path = Path(changed['canaries'][1]['log'])
                        path.write_text('FATAL: unexpected memory mapping')
                        changed['canaries'][1]['log_sha256'] = sha256(path)
                    self.save(output, report, changed)
                    with self.subTest(kind=kind, variant=variant), self.assertRaises(ValueError):
                        verify_instrumented_execution(ROOT, report, output)

    def test_saved_proof_rejects_weakened_settings_and_incomplete_executables(self):
        for kind in ('tsan', 'msan'):
            output, report, child = self.proof(kind)
            with patch('instrumented_ci.verify_dependencies', return_value={'synthetic': 'verified'}):
                for variant in ('environment', 'stack', 'missing_binary', 'wrong_binary', 'timeout'):
                    changed, outer = deepcopy(child), deepcopy(report)
                    if variant == 'environment': outer['sanitizer_environment'] = {}
                    elif variant == 'stack': outer['sanitizer_stack_limit'] = 8388608
                    elif variant == 'missing_binary': changed['instrumentation']['binaries'].pop('bitcoin-cli')
                    elif variant == 'wrong_binary': changed['instrumentation']['binaries']['bitcoin-cli']['sha256'] = 'other'
                    else: outer['steps'][1]['command'][-1] = '180'
                    self.save(output, outer, changed)
                    with self.subTest(kind=kind, variant=variant), self.assertRaises(ValueError):
                        verify_instrumented_execution(ROOT, outer, output)

    def test_step_inventory_keeps_full_applicable_frameworks_and_dependency_gates(self):
        expected = ['drift', 'sanitizer-tools', 'sanitizer-dependencies', 'sanitizer', 'unit', 'auxiliary', 'kernel', 'functional']
        for profile in ('bitcoin-tsan', 'pocx-tsan', 'bitcoin-msan', 'pocx-msan'):
            self.assertEqual(required_steps(profile, True), expected)
            self.assertEqual(required_steps(profile, False), expected[:3] + ['configure', 'build'] + expected[3:])


if __name__ == '__main__':
    unittest.main()
