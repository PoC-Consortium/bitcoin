#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin PoCX developers
# Distributed under the MIT software license; see COPYING.
"""Exercise production cross-discovery without claiming Bitcoin/Windows passes."""
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

from common import ROOT, sha256
import record_cross_unit


class CrossUnitTest(unittest.TestCase):
    def fixture(self, directory):
        root = Path(directory); build = root / 'build'; build.mkdir()
        system = build / 'CMakeFiles/probe/CMakeSystem.cmake'; system.parent.mkdir(parents=True)
        system.write_text('set(CMAKE_SYSTEM_NAME "Windows")\nset(CMAKE_SYSTEM_PROCESSOR "x86_64")\nset(CMAKE_CROSSCOMPILING "TRUE")\n')
        cache = build / 'CMakeCache.txt'
        cache.write_text('CMAKE_HOME_DIRECTORY:INTERNAL=' + str(root) + '\nENABLE_POCX:BOOL=ON\nBUILD_TESTS:BOOL=ON\n')
        source = root / 'fixture.cpp'; source.write_text('fixture source\n')
        generated = build / 'generated.h'; generated.write_text('fixture generated input\n')
        binary = build / 'test_pocx.exe'; binary.write_bytes(b'not executed')
        inputs = build / 'unit-inputs.txt'; inputs.write_text(str(source) + '\n' + str(generated) + '\n')
        return root, build, binary, inputs, cache, system

    def test_deferred_record_has_portable_inputs_and_no_discovered_cases(self):
        with tempfile.TemporaryDirectory() as directory:
            root, build, binary, inputs, cache, _ = self.fixture(directory)
            record = record_cross_unit.snapshot(binary, inputs, cache, root)
            self.assertIsNone(record['runtime_inventory'])
            self.assertIn('not executed', record['execution_status'])
            self.assertEqual(record['binary_sha256'], sha256(binary))
            self.assertEqual(record['sources'], {'source/fixture.cpp': sha256(root / 'fixture.cpp'),
                                                'build/generated.h': sha256(build / 'generated.h')})

    def test_wrong_consensus_host_and_empty_or_external_inputs_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root, _, binary, inputs, cache, system = self.fixture(directory)
            original_cache, original_system, original_inputs = cache.read_text(), system.read_text(), inputs.read_text()
            for old, new in (('ENABLE_POCX:BOOL=ON', 'ENABLE_POCX:BOOL=OFF'), ('BUILD_TESTS:BOOL=ON', 'BUILD_TESTS:BOOL=OFF')):
                cache.write_text(original_cache.replace(old, new))
                with self.assertRaises(ValueError): record_cross_unit.snapshot(binary, inputs, cache, root)
            cache.write_text(original_cache)
            for old, new in (('"Windows"', '"Linux"'), ('"TRUE"', '"FALSE"')):
                system.write_text(original_system.replace(old, new))
                with self.assertRaises(ValueError): record_cross_unit.snapshot(binary, inputs, cache, root)
            system.write_text(original_system)
            for value in ('', '/outside-source-and-build/fixture.h\n'):
                inputs.write_text(value)
                with self.assertRaises(ValueError): record_cross_unit.snapshot(binary, inputs, cache, root)
            inputs.write_text(original_inputs)
            (root / 'fixture.cpp').unlink()
            with self.assertRaises(FileNotFoundError): record_cross_unit.snapshot(binary, inputs, cache, root)

    @unittest.skipUnless(shutil.which('x86_64-w64-mingw32-g++'), 'MinGW compiler prerequisite unavailable')
    def test_production_cmake_cross_branch_links_a_pe_without_executing_it(self):
        with tempfile.TemporaryDirectory(prefix='pocx-cross-unit-') as directory:
            root = Path(directory); source = root / 'src/pocx/test'; source.mkdir(parents=True)
            scripts = root / 'test/pocx'; scripts.mkdir(parents=True)
            for name in ('record_cross_unit.py', 'common.py', 'unit_matrix.py', 'unit_parity.py',
                         'unit_build.py', 'build_configuration.py'):
                (scripts / name).write_bytes((ROOT / 'test/pocx' / name).read_bytes())
            (root / 'CMakeLists.txt').write_text('''cmake_minimum_required(VERSION 3.22)
project(cross_unit_probe LANGUAGES CXX)
enable_testing()
option(ENABLE_POCX "PoCX probe" ON)
option(BUILD_TESTS "Unit probe" ON)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin")
add_subdirectory(src/pocx/test)
''')
            (source / 'fixture.cpp').write_text('int main() { return 7; }\n')
            production = (ROOT / 'src/pocx/test/CMakeLists.txt').read_text()
            discovery = production[production.index('set(unit_discovery_dir '):
                                   production.index('install_binary_component(test_pocx')]
            (source / 'CMakeLists.txt').write_text('''find_package(Python3 REQUIRED COMPONENTS Interpreter)
add_executable(test_pocx "${CMAKE_CURRENT_SOURCE_DIR}/fixture.cpp")
set(POCX_UNIT_INPUTS "${CMAKE_CURRENT_SOURCE_DIR}/fixture.cpp")
''' + discovery)
            build = root / 'build'
            def run(command):
                return subprocess.run(command, capture_output=True, text=True, check=True)
            run(['cmake', '-S', str(root), '-B', str(build), '-G', 'Ninja',
                 '-DCMAKE_SYSTEM_NAME=Windows', '-DCMAKE_SYSTEM_PROCESSOR=x86_64',
                 '-DCMAKE_CXX_COMPILER=x86_64-w64-mingw32-g++'])
            result = run(['cmake', '--build', str(build)])
            self.assertIn('runtime discovery remains unverified', result.stdout)
            binary = build / 'bin/test_pocx.exe'
            self.assertEqual(binary.read_bytes()[:2], b'MZ')
            record = build / 'src/pocx/test/cross-build.json'
            self.assertEqual(json.loads(record.read_text()), record_cross_unit.snapshot(binary,
                build / 'src/pocx/test/unit-inputs.txt', build / 'CMakeCache.txt', root))
            self.assertFalse((build / 'src/pocx/test/discovered.cmake').exists())
            rows = json.loads(run(['ctest', '--test-dir', str(build), '--show-only=json-v1']).stdout)['tests']
            self.assertEqual(rows, [])  # No invented runtime registrations.


if __name__ == '__main__':
    unittest.main()
