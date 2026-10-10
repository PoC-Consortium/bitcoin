#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin PoCX developers
# Distributed under the MIT software license; see COPYING.
"""Compile actual production SIMD gates; configuration probes are not suite passes."""
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import unittest

from common import ROOT


def production_gate(name, target):
    content = (ROOT / name).read_text()
    blocks = re.findall(r'if\([^\n]*CMAKE_SYSTEM_PROCESSOR MATCHES "[^"\n]+"\)\n'
                        r'\s+target_compile_definitions\(' + target + r' PRIVATE ENABLE_SSE2\)\nendif\(\)', content)
    if len(blocks) != 1: raise ValueError('Missing or ambiguous production SSE2 gate: ' + name)
    return blocks[0]


class ProcessorConfigurationTest(unittest.TestCase):
    def compile(self, processor, pocx, expected, *, cross=False):
        with tempfile.TemporaryDirectory(prefix='pocx-processor-') as directory:
            root = Path(directory); build = root / 'build'
            cpp = root / 'probe.cpp'
            cpp.write_text('''#include <pocx/crypto/shabal256_sse2.h>
#if defined(ENABLE_SSE2) != EXPECT_SSE2
#error Production processor gate disagrees with expected configuration
#endif
#ifdef PROBE_MAIN
int main() {
#ifdef ENABLE_SSE2
    const uint8_t* data[4] = {};
    const uint32_t* pre[4] = {};
    uint32_t term[16] = {};
    const uint32_t* terms[4] = {term, term, term, term};
    uint8_t buffers[4][32] = {};
    uint8_t* output[4] = {buffers[0], buffers[1], buffers[2], buffers[3]};
    pocx::crypto::Shabal256_sse2(data, 0, pre, terms, output);
#endif
    return 0;
}
#endif
''')
            consensus_gate = production_gate('src/CMakeLists.txt', 'bitcoin_consensus')
            unit_gate = production_gate('src/pocx/test/CMakeLists.txt', 'test_pocx')
            # The exact production conditional blocks compile both the library
            # and its caller. Linking catches one gate changing without the other.
            (root / 'CMakeLists.txt').write_text('''cmake_minimum_required(VERSION 3.22)
project(processor_probe LANGUAGES CXX)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_SYSTEM_PROCESSOR "''' + processor + '''")
set(ENABLE_POCX ''' + ('ON' if pocx else 'OFF') + ''')
add_library(bitcoin_consensus STATIC "''' + cpp.as_posix() + '" "' +
                (ROOT / 'src/pocx/crypto/shabal256_sse2.cpp').as_posix() + '''")
target_include_directories(bitcoin_consensus PRIVATE "''' + (ROOT / 'src').as_posix() + '''")
target_compile_definitions(bitcoin_consensus PRIVATE EXPECT_SSE2=''' + str(int(expected)) + ''')
''' + consensus_gate + '''
if(ENABLE_POCX)
  add_executable(test_pocx "''' + cpp.as_posix() + '''")
  target_include_directories(test_pocx PRIVATE "''' + (ROOT / 'src').as_posix() + '''")
  target_compile_definitions(test_pocx PRIVATE PROBE_MAIN EXPECT_SSE2=''' + str(int(expected)) + ''')
  target_link_libraries(test_pocx PRIVATE bitcoin_consensus)
''' + unit_gate + '''
endif()
''')
            command = ['cmake', '-S', str(root), '-B', str(build), '-G', 'Ninja']
            if cross:
                command += ['-DCMAKE_SYSTEM_NAME=Windows', '-DCMAKE_SYSTEM_PROCESSOR=' + processor,
                            '-DCMAKE_CXX_COMPILER=x86_64-w64-mingw32-g++']
            def run(command): return subprocess.run(command, capture_output=True, text=True, check=True)
            run(command); run(['cmake', '--build', str(build)])
            if pocx:
                binary = build / ('test_pocx.exe' if cross else 'test_pocx')
                self.assertTrue(binary.is_file())
                if cross: self.assertEqual(binary.read_bytes()[:2], b'MZ')
                else: run([str(binary)])

    def test_x86_spellings_compile_both_production_sse2_paths(self):
        for processor in ('x86_64', 'amd64', 'AMD64', 'X86_64'):
            with self.subTest(processor=processor): self.compile(processor, True, True)

    def test_bitcoin_off_and_non_x86_keep_consensus_simd_disabled(self):
        self.compile('AMD64', False, False)
        for processor in ('aarch64', 'arm64'):
            with self.subTest(processor=processor): self.compile(processor, True, False)

    @unittest.skipUnless(shutil.which('x86_64-w64-mingw32-g++'), 'MinGW prerequisite unavailable')
    def test_windows_amd64_cross_links_the_actual_sse2_implementation(self):
        self.compile('AMD64', True, True, cross=True)


if __name__ == '__main__':
    unittest.main()
