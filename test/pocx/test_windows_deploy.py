#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin PoCX developers
# Distributed under the MIT software license; see COPYING.
"""Exercise the real native installer rule with tiny, unexecuted PE fixtures."""
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

from common import ROOT
from windows_artifacts import pe_machine


@unittest.skipUnless(shutil.which('x86_64-w64-mingw32-g++') and shutil.which('makensis'),
                     'MinGW and NSIS prerequisites unavailable')
class WindowsDeployTest(unittest.TestCase):
    def configure(self, directory, *, native=True, windows=True, gui=True):
        root = Path(directory)
        for name in ('share', 'doc', 'COPYING'):
            (root / name).symlink_to(ROOT / name, target_is_directory=name != 'COPYING')
        (root / 'fixture.cpp').write_text('int main() { return 0; }\n')
        targets = ['bitcoin', 'bitcoind', 'bitcoin-cli', 'bitcoin-tx', 'bitcoin-wallet', 'bitcoin-util']
        if gui:
            targets.append('bitcoin-qt')
        targets.append('test_pocx' if native else 'test_bitcoin')
        project = '''cmake_minimum_required(VERSION 3.22)
project(deploy_probe LANGUAGES CXX HOMEPAGE_URL "https://example.invalid")
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin")
set(CLIENT_NAME "Installer fixture")
set(CLIENT_VERSION_MAJOR 1)
set(CLIENT_VERSION_MINOR 0)
set(CLIENT_VERSION_BUILD 0)
set(CLIENT_VERSION_STRING "1.0.0")
set(COPYRIGHT_YEAR 2026)
set(COPYRIGHT_HOLDERS_FINAL "Fixture")
'''
        project += 'set(ENABLE_POCX ' + ('ON' if native else 'OFF') + ')\n'
        project += f'list(APPEND CMAKE_MODULE_PATH "{ROOT}/cmake/module")\n'
        project += ''.join(f'add_executable({target} fixture.cpp)\n' for target in targets)
        if native:
            project += f'include("{ROOT}/src/pocx/test/windows-deploy.cmake")\n'
        project += 'include(Maintenance)\nadd_windows_deploy_target()\n'
        (root / 'CMakeLists.txt').write_text(project)
        build = root / 'build'
        command = ['cmake', '-S', str(root), '-B', str(build), '-G', 'Ninja']
        if windows:
            command += ['-DCMAKE_SYSTEM_NAME=Windows', '-DCMAKE_SYSTEM_PROCESSOR=x86_64',
                        '-DCMAKE_CXX_COMPILER=x86_64-w64-mingw32-g++']
        subprocess.run(command, capture_output=True, text=True, check=True)
        return build

    def test_native_deploy_builds_installer_with_native_unit_executable(self):
        with tempfile.TemporaryDirectory(prefix='pocx-deploy-') as directory:
            build = self.configure(directory)
            subprocess.run(['cmake', '--build', str(build), '--target', 'deploy', '--parallel', '1'],
                           capture_output=True, text=True, check=True)
            self.assertIn(pe_machine(build / 'bitcoin-pocx-win64-setup.exe'), (0x14c, 0x8664))
            self.assertEqual(pe_machine(build / 'release/test_pocx.exe'), 0x8664)
            self.assertFalse((build / 'release/test_bitcoin.exe').exists())
            nsi = (build / 'bitcoin-pocx-win64-setup.nsi').read_text()
            self.assertIn('/release/test_pocx.exe', nsi)
            self.assertNotIn('/release/test_bitcoin.exe', nsi)

    def test_original_configuration_retains_original_installer_selection(self):
        with tempfile.TemporaryDirectory(prefix='bitcoin-deploy-selection-') as directory:
            build = self.configure(directory, native=False)
            nsi = (build / 'bitcoin-win64-setup.nsi').read_text()
            self.assertIn('/release/test_bitcoin.exe', nsi)
            self.assertNotIn('/release/test_pocx.exe', nsi)
            self.assertFalse((build / 'bitcoin-pocx-win64-setup.nsi').exists())

    def test_partial_windows_and_linux_profiles_do_not_acquire_deploy_target(self):
        for windows, gui in ((True, False), (False, True)):
            with self.subTest(windows=windows, gui=gui), tempfile.TemporaryDirectory() as directory:
                build = self.configure(directory, windows=windows, gui=gui)
                result = subprocess.run(['cmake', '--build', str(build), '--target', 'help'],
                                        capture_output=True, text=True, check=True)
                self.assertNotIn('deploy:', result.stdout)
                self.assertFalse((build / 'bitcoin-pocx-win64-setup.nsi').exists())


if __name__ == '__main__':
    unittest.main()
