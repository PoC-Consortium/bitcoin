#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin PoCX developers
# Distributed under the MIT software license; see COPYING.
"""Reject implicit/wrong CMake configurations; exercise actual multi-config CTest selection."""
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import build_configuration as selection

SINGLE = 'CMAKE_BUILD_TYPE:STRING=Release\n'
MULTI = 'CMAKE_CONFIGURATION_TYPES:STRING=Debug;Release;RelWithDebInfo\n'


class ConfigurationTest(unittest.TestCase):
    def test_source_directory_identity_is_normalized_and_required(self):
        root = Path(__file__).resolve().parent
        prefix = 'CMAKE_HOME_DIRECTORY:INTERNAL='
        selection.require_source(prefix + root.as_posix(), root)
        selection.require_source(prefix + (root / 'unused/..').as_posix(), root)
        for cache in ('', prefix, prefix + str(root.parent),
                      prefix + str(root) + '\n' + prefix + str(root)):
            with self.subTest(cache=cache), self.assertRaisesRegex(ValueError, 'different source'):
                selection.require_source(cache, root)

    def test_single_configuration_remains_compatible(self):
        self.assertIsNone(selection.configuration(SINGLE))
        self.assertEqual(selection.configuration(SINGLE, 'Release'), 'Release')
        self.assertEqual(selection.build_arguments(None), [])
        self.assertEqual(selection.ctest_arguments(None), [])

    def test_wrong_single_configuration_is_rejected(self):
        with self.assertRaisesRegex(ValueError, 'CMAKE_BUILD_TYPE'):
            selection.configuration(SINGLE, 'Debug')

    def test_multi_configuration_requires_explicit_selection(self):
        with self.assertRaisesRegex(ValueError, 'require --config'):
            selection.configuration(MULTI)

    def test_unknown_configuration_cannot_fall_back(self):
        for name in ('release', 'Missing', ''):
            with self.subTest(name=name), self.assertRaises(ValueError):
                selection.configuration(MULTI, name)

    def test_path_components_are_rejected_even_when_declared(self):
        for name in ('../Release', '..', '.', 'sub\\Release', '/Release'):
            with self.subTest(name=name), self.assertRaisesRegex(ValueError, 'Invalid'):
                selection.configuration('CMAKE_CONFIGURATION_TYPES:STRING=' + name, name)

    def test_executable_paths_match_platform_and_generator(self):
        build = Path('/build')
        for platform, suffix in (('posix', ''), ('nt', '.exe')):
            with self.subTest(platform=platform), patch.object(selection.os, 'name', platform):
                self.assertEqual(selection.executable(build, 'test_kernel', SINGLE),
                                 build / 'bin' / ('test_kernel' + suffix))
                self.assertEqual(selection.executable(build, 'test_kernel', MULTI, 'Release'),
                                 build / 'bin/Release' / ('test_kernel' + suffix))

    def test_build_and_ctest_select_the_same_configuration(self):
        self.assertEqual(selection.build_arguments('Release'), ['--config', 'Release'])
        self.assertEqual(selection.ctest_arguments('Release'), ['--build-config', 'Release'])

    def test_actual_multi_configuration_execution(self):
        # A real compiled CMake fixture, not Bitcoin/PoCX framework evidence.
        with tempfile.TemporaryDirectory(prefix='cmake-config-') as directory:
            source = Path(directory)
            build = source / 'build'
            (source / 'CMakeLists.txt').write_text('''cmake_minimum_required(VERSION 3.22)
project(configuration_probe LANGUAGES CXX)
enable_testing()
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin")
add_executable(probe probe.cpp)
target_compile_definitions(probe PRIVATE $<$<CONFIG:Debug>:WRONG_CONFIGURATION>)
add_test(NAME configuration_probe COMMAND probe)
''')
            (source / 'probe.cpp').write_text('''int main() {
#ifdef WRONG_CONFIGURATION
return 7;
#else
return 0;
#endif
}
''')
            def run(command, check=True):
                return subprocess.run(command, check=check, capture_output=True, text=True)
            run(['cmake', '-S', str(source), '-B', str(build), '-G', 'Ninja Multi-Config'])
            cache = (build / 'CMakeCache.txt').read_text()
            for name in ('Release', 'Debug'):
                selected = selection.configuration(cache, name)
                run(['cmake', '--build', str(build)] + selection.build_arguments(selected))
                self.assertTrue(selection.executable(build, 'probe', cache, selected).is_file())
                result = run(['ctest', '--test-dir', str(build), '--no-tests=error'] +
                             selection.ctest_arguments(selected), check=False)
                self.assertEqual(result.returncode == 0, name == 'Release', result.stdout + result.stderr)


if __name__ == '__main__':
    unittest.main()
