#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin PoCX developers
# Distributed under the MIT software license; see COPYING.
"""Production kernel build-selection probes; no kernel/Windows domain passes."""
import json
from pathlib import Path
import shutil
import struct
import subprocess
import tempfile
import unittest

from common import ROOT, sha256


class CrossKernelTest(unittest.TestCase):
    def fixture(self, directory):
        source = Path(directory) / 'source'
        kernel = source / 'src/pocx/test/kernel'
        kernel.mkdir(parents=True)
        shutil.copyfile(ROOT / 'src/pocx/test/kernel/CMakeLists.txt', kernel / 'CMakeLists.txt')
        data = source / 'test/pocx/kernel'
        data.mkdir(parents=True)
        for name in ('render_fixtures.py', 'provenance.json', 'fixtures.json'):
            shutil.copyfile(ROOT / 'test/pocx/kernel' / name, data / name)
        (source / 'CMakeLists.txt').write_text('''cmake_minimum_required(VERSION 3.22)
project(KernelBuildSelectionProbe LANGUAGES CXX)
enable_testing()
function(add_windows_application_manifest target)
endfunction()
foreach(target core_interface bitcoin_node bitcoin_consensus bitcoin_common bitcoin_util secp256k1 univalue libevent::extra Boost::headers bitcoinkernel)
  add_library(${target} INTERFACE IMPORTED)
endforeach()
add_subdirectory(src/pocx/test/kernel)
if(TARGET pocx_kernel_fixture_generator)
  target_compile_definitions(pocx_kernel_fixture_generator PRIVATE FIXTURE_SNAPSHOT="${PROJECT_SOURCE_DIR}/test/pocx/kernel/fixtures.json")
endif()
''')
        # Minimal native compiler probe supplies the same input bytes. The cross
        # path must never build/run it; real generator semantics are unchanged
        # and separately checked by kernel provenance and actual native builds.
        (kernel / 'fixture_generator.cpp').write_text('''#include <fstream>
#ifndef FIXTURE_SNAPSHOT
#error Target fixture generator must not be compiled by the cross path
#endif
int main(int argc, char** argv) {
  if (argc != 2) return 7;
  std::ifstream input(FIXTURE_SNAPSHOT, std::ios::binary);
  std::ofstream output(argv[1], std::ios::binary);
  output << input.rdbuf();
  return input.bad() || !output ? 7 : 0;
}
''')
        (kernel / 'test_kernel.cpp').write_text('''#include "pocx_kernel_block_data.h"
int main() { return MAINNET_VERSION == 0x20000000 && REGTEST_BLOCK_DATA.size() == 206 ? 0 : 7; }
''')
        return source

    def configure(self, source, build, *, cross):
        command = ['cmake', '-S', str(source), '-B', str(build), '-G', 'Ninja']
        if cross:
            command += ['-DCMAKE_SYSTEM_NAME=Windows', '-DCMAKE_SYSTEM_PROCESSOR=AMD64',
                        '-DCMAKE_CXX_COMPILER=' + shutil.which('x86_64-w64-mingw32-g++')]
        subprocess.run(command, check=True, capture_output=True, text=True)

    def build(self, build, *, success=True):
        result = subprocess.run(['cmake', '--build', str(build), '--target', 'test_kernel', '--verbose'],
                                capture_output=True, text=True)
        self.assertEqual(result.returncode == 0, success, result.stdout + result.stderr)
        return result.stdout + result.stderr

    @unittest.skipUnless(shutil.which('c++') and shutil.which('x86_64-w64-mingw32-g++'), 'Native and MinGW compiler probes unavailable')
    def test_native_and_cross_paths_render_identical_independently_verified_fixture_bytes(self):
        with tempfile.TemporaryDirectory(prefix='kernel-build-probe-') as directory:
            root = Path(directory)
            source = self.fixture(root)
            native, cross = root / 'native', root / 'cross'
            for build, is_cross in ((native, False), (cross, True)):
                self.configure(source, build, cross=is_cross)
                self.build(build)
            native_data = native / 'src/pocx/test/kernel'
            cross_data = cross / 'src/pocx/test/kernel'
            review = json.loads((ROOT / 'test/pocx/kernel/provenance.json').read_text())
            for build in (native_data, cross_data):
                self.assertEqual(sha256(build / 'kernel-fixtures.json'), review['fixture_sha256'])
            self.assertEqual((native_data / 'pocx_kernel_block_data.h').read_bytes(),
                             (cross_data / 'pocx_kernel_block_data.h').read_bytes())
            subprocess.run([str(native_data / 'test_kernel')], check=True)
            binary = (cross_data / 'test_kernel.exe').read_bytes()
            self.assertEqual(binary[:2], b'MZ')
            coff = struct.unpack_from('<I', binary, 60)[0]
            self.assertEqual(binary[coff:coff + 4], b'PE\0\0')
            self.assertEqual(struct.unpack_from('<H', binary, coff + 4)[0], 0x8664)
            self.assertFalse((cross_data / 'pocx_kernel_fixture_generator.exe').exists())
            self.assertNotIn('pocx_kernel_fixture_generator', (cross / 'build.ninja').read_text())

    @unittest.skipUnless(shutil.which('x86_64-w64-mingw32-g++'), 'MinGW compiler probe unavailable')
    def test_corrupt_cross_snapshot_cannot_generate_a_kernel_header(self):
        with tempfile.TemporaryDirectory(prefix='kernel-build-corrupt-') as directory:
            root = Path(directory)
            source = self.fixture(root)
            build = root / 'build'
            (source / 'test/pocx/kernel/fixtures.json').write_text('{}\n')
            self.configure(source, build, cross=True)
            log = self.build(build, success=False)
            self.assertIn('differ from the independently verified snapshot', log)
            self.assertFalse((build / 'src/pocx/test/kernel/pocx_kernel_block_data.h').exists())

    @unittest.skipUnless(shutil.which('x86_64-w64-mingw32-g++'), 'MinGW compiler probe unavailable')
    def test_snapshot_change_invalidates_incremental_cross_build(self):
        with tempfile.TemporaryDirectory(prefix='kernel-build-incremental-') as directory:
            root = Path(directory)
            source = self.fixture(root)
            build = root / 'build'
            self.configure(source, build, cross=True)
            self.build(build)
            with (source / 'test/pocx/kernel/fixtures.json').open('a') as stream:
                stream.write('\n')
            self.assertIn('differ from the independently verified snapshot', self.build(build, success=False))


if __name__ == '__main__':
    unittest.main()
