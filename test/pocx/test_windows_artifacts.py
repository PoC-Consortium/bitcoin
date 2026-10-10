#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin PoCX developers
# Distributed under the MIT software license; see COPYING.
"""Paired artifact checks using synthetic payloads; no Windows/domain evidence."""
from copy import deepcopy
import json
from pathlib import Path
import struct
import tempfile
import unittest
from unittest.mock import patch

from common import ROOT, sha256
import record_cross_unit
import windows_artifacts as artifacts


class WindowsArtifactsTest(unittest.TestCase):
    def fixture(self, directory):
        root = Path(directory)
        for name in ('CMakeLists.txt', 'CMakePresets.json', '.github/workflows/pocx-tests.yml', 'src/fixture.cpp',
                     *artifacts.FUNCTIONAL_SUPPORT):
            path = root / name; path.parent.mkdir(parents=True, exist_ok=True); path.write_text('synthetic fixture\n')
        builds = []
        for consensus, enabled in (('bitcoin', 'OFF'), ('pocx', 'ON')):
            build = root / ('build-' + consensus); build.mkdir(); builds.append(build)
            (build / 'CMakeCache.txt').write_text('CMAKE_HOME_DIRECTORY:INTERNAL=' + str(root) + '\n' +
                'CMAKE_GENERATOR:INTERNAL=Ninja\nENABLE_POCX:BOOL=' + enabled + '\n' +
                'BUILD_TESTS:BOOL=ON\nENABLE_WALLET:BOOL=ON\nENABLE_IPC:BOOL=OFF\nWITH_USDT:BOOL=OFF\nBUILD_GUI:BOOL=OFF\n')
            for name in ('build.ninja', 'CMakeFiles/rules.ninja', 'test/config.ini', 'src/pocx/test/generated.h'):
                path = build / name; path.parent.mkdir(parents=True, exist_ok=True); path.write_text('fixture build input\n')
            system = build / 'CMakeFiles/probe/CMakeSystem.cmake'; system.parent.mkdir(parents=True)
            system.write_text('set(CMAKE_SYSTEM_NAME "Windows")\nset(CMAKE_SYSTEM_PROCESSOR "x86_64")\nset(CMAKE_CROSSCOMPILING "TRUE")\n')
            names = {'bin/bitcoind.exe', 'bin/test_bitcoin.exe' if consensus == 'bitcoin' else 'bin/test_pocx.exe',
                     *artifacts.AUXILIARY}
            for name in names:
                path = build / name; path.parent.mkdir(parents=True, exist_ok=True)
                header = bytearray(128); header[:2] = b'MZ'; struct.pack_into('<I', header, 60, 64)
                header[64:68] = b'PE\0\0'; struct.pack_into('<H', header, 68, 0x8664); path.write_bytes(header)
            if consensus == 'pocx':
                inputs = build / 'src/pocx/test/unit-inputs.txt'
                inputs.write_text(str(root / 'src/fixture.cpp') + '\n' + str(build / 'src/pocx/test/generated.h') + '\n')
                artifacts.write_json(build / 'src/pocx/test/cross-build.json', record_cross_unit.snapshot(
                    build / 'bin/test_pocx.exe', inputs, build / 'CMakeCache.txt', root))
        return root, builds, root / 'bundle'

    def inventory(self, root, options, *, bitcoin):
        self.assertEqual(options['ENABLE_POCX'], 'OFF' if bitcoin else 'ON')
        return {'original': {'fixture/case'}, 'applicable': {'fixture/case'},
                'additional': set() if bitcoin else {'native/case'}, 'excluded': set(),
                'configuration_disabled': {}, 'expected': {'fixture/case'} | (set() if bitcoin else {'native/case'})}

    def export(self, root, builds, bundle):
        return artifacts.export_pair(*builds, bundle, root=root, revision='a' * 40)

    def verify(self, root, bundle):
        return artifacts.verify_pair(bundle, root=root, revision='a' * 40)

    def setUp(self):
        self.inventory_patch = patch.object(artifacts.unit_matrix, 'inventory', side_effect=self.inventory)
        self.inventory_patch.start(); self.addCleanup(self.inventory_patch.stop)

    def test_exported_pair_is_portable_and_explicitly_unexecuted(self):
        with tempfile.TemporaryDirectory() as directory:
            root, builds, bundle = self.fixture(directory)
            report = self.export(root, builds, bundle)
            self.assertEqual(self.verify(root, bundle), report)
            self.assertEqual(report['execution_status'], 'not executed')
            self.assertEqual([row['consensus'] for row in report['phases']], ['bitcoin', 'pocx'])
            self.assertTrue((bundle / 'pocx/provenance/generated/src/pocx/test/generated.h').is_file())
            with self.assertRaises(ValueError): self.export(root, builds, bundle)
            self.assertIsNone(json.loads((bundle / 'pocx/provenance/cross-unit.json').read_text())['runtime_inventory'])

    def test_missing_enabled_binary_and_wrong_pe_architecture_fail_export(self):
        for change in ('missing auxiliary', 'missing enabled tool', 'wrong architecture'):
            with self.subTest(change=change), tempfile.TemporaryDirectory() as directory:
                root, builds, bundle = self.fixture(directory)
                if change == 'missing auxiliary': (builds[0] / artifacts.AUXILIARY[0]).unlink()
                elif change == 'missing enabled tool':
                    with (builds[0] / 'CMakeCache.txt').open('a') as stream: stream.write('BUILD_CLI:BOOL=ON\n')
                else:
                    path = builds[0] / 'bin/bitcoind.exe'; data = bytearray(path.read_bytes()); struct.pack_into('<H', data, 68, 0x14c); path.write_bytes(data)
                with self.assertRaises(ValueError): self.export(root, builds, bundle)
                self.assertFalse(bundle.exists())

    def test_baseline_must_match_native_feature_target_compiler_and_sanitizer_configuration(self):
        for key, value in (('ENABLE_WALLET', 'OFF'), ('CMAKE_CXX_FLAGS', '-fsanitize=address'),
                           ('CMAKE_CXX_COMPILER', '/different/compiler'), ('BUILD_GUI', 'ON'),
                           ('avx2_compiled', True), ('target_processor', 'AMD64')):
            with self.subTest(key=key):
                phases = [{'build_options': {'ENABLE_POCX': 'OFF', 'ENABLE_WALLET': 'ON'}},
                          {'build_options': {'ENABLE_POCX': 'ON', 'ENABLE_WALLET': 'ON'}}]
                artifacts.matching_configurations(phases)
                phases[1]['build_options'][key] = value
                with self.assertRaisesRegex(ValueError, 'configurations differ'):
                    artifacts.matching_configurations(phases)
        with tempfile.TemporaryDirectory() as directory:
            root, builds, bundle = self.fixture(directory)
            with (builds[0] / 'CMakeCache.txt').open('a') as stream:
                stream.write('CMAKE_CXX_FLAGS:STRING=-fsanitize=address\n')
            with self.assertRaisesRegex(ValueError, 'configurations differ'): self.export(root, builds, bundle)
            self.assertFalse(bundle.exists())

    def test_stale_native_link_inputs_rejected_before_publication(self):
        for name in ('bin/test_pocx.exe', 'src/pocx/test/generated.h', 'src/pocx/test/unit-inputs.txt'):
            with self.subTest(name=name), tempfile.TemporaryDirectory() as directory:
                root, builds, bundle = self.fixture(directory)
                with (builds[1] / name).open('ab') as stream: stream.write(b'changed\n')
                with self.assertRaises((ValueError, FileNotFoundError)): self.export(root, builds, bundle)
                self.assertFalse(bundle.exists())

    def test_binary_configuration_generated_input_and_source_mutations_rejected(self):
        for name in ('pocx/bin/test_pocx.exe', 'bitcoin/provenance/CMakeCache.txt',
                     'pocx/provenance/generated/src/pocx/test/generated.h', 'pocx/provenance/cross-unit.json'):
            with self.subTest(name=name), tempfile.TemporaryDirectory() as directory:
                root, builds, bundle = self.fixture(directory); self.export(root, builds, bundle)
                with (bundle / name).open('ab') as stream: stream.write(b'changed\n')
                with self.assertRaises(ValueError): self.verify(root, bundle)
        with tempfile.TemporaryDirectory() as directory:
            root, builds, bundle = self.fixture(directory); self.export(root, builds, bundle)
            (root / 'src/fixture.cpp').write_text('changed source\n')
            with self.assertRaisesRegex(ValueError, 'source inputs'): self.verify(root, bundle)

    def test_wrong_revision_reordered_phases_and_incomplete_inventory_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root, builds, bundle = self.fixture(directory); report = self.export(root, builds, bundle)
            for mutation in ('revision', 'order', 'inventory', 'unit binary', 'required binary'):
                changed = deepcopy(report)
                if mutation == 'revision': changed['revision'] = 'b' * 40
                elif mutation == 'order': changed['phases'].reverse()
                elif mutation == 'inventory': changed['phases'][0]['expected_unit']['expected'] = []
                elif mutation == 'unit binary': changed['phases'][0]['unit_binary'] = 'bin/bitcoind.exe'
                else: del changed['phases'][0]['files'][artifacts.AUXILIARY[0]]
                artifacts.write_json(bundle / 'pair.json', changed)
                with self.subTest(mutation=mutation), self.assertRaises(ValueError): self.verify(root, bundle)

    def test_extra_and_symlinked_payloads_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root, builds, bundle = self.fixture(directory); self.export(root, builds, bundle)
            extra = bundle / 'pocx/bin/stale.dll'; extra.write_text('stale payload')
            with self.assertRaises(ValueError): self.verify(root, bundle)
            extra.unlink(); extra.symlink_to(root / 'src/fixture.cpp')
            with self.assertRaises(ValueError): self.verify(root, bundle)

    def test_unsafe_and_case_colliding_payload_paths_rejected(self):
        for name in ('', '.', '..', '../outside', '/absolute', 'a//b', 'a/./b', 'C:/outside', 'a\\b'):
            with self.subTest(name=name), self.assertRaises(ValueError): artifacts.relative_name(name)
        with tempfile.TemporaryDirectory() as directory:
            root, builds, bundle = self.fixture(directory)
            source = builds[0] / 'bin/bitcoind.exe'; (builds[0] / 'bin/BITCOIND.exe').write_bytes(source.read_bytes())
            with self.assertRaisesRegex(ValueError, 'Case-colliding'): self.export(root, builds, bundle)

    def test_native_provenance_cannot_claim_discovery_or_omit_generated_inputs(self):
        with tempfile.TemporaryDirectory() as directory:
            root, builds, bundle = self.fixture(directory); report = self.export(root, builds, bundle)
            native = bundle / 'pocx/provenance/cross-unit.json'; original = json.loads(native.read_text())
            for mutation in ('runtime', 'generated'):
                changed = deepcopy(original)
                if mutation == 'runtime': changed['runtime_inventory'] = ['fixture/case']
                else: changed['sources']['build/not-exported.h'] = '0' * 64
                artifacts.write_json(native, changed)
                report['phases'][1]['files']['provenance/cross-unit.json'] = sha256(native)
                artifacts.write_json(bundle / 'pair.json', report)
                with self.subTest(mutation=mutation), self.assertRaises(ValueError): self.verify(root, bundle)

    def test_source_review_pins_the_original_recipe_and_owned_exporter(self):
        review = artifacts.verify_recipe()
        self.assertEqual(review['actual_windows_cases_executed'], 0)
        original = artifacts.sha256
        for name in ('.github/ci-windows-cross.py', 'test/pocx/windows_artifacts.py', 'test/pocx/record_cross_unit.py'):
            with self.subTest(name=name), patch.object(artifacts, 'sha256', side_effect=lambda path:
                    '0' * 64 if path == ROOT / name else original(path)):
                with self.assertRaisesRegex(ValueError, 'changed without review'): artifacts.verify_recipe()


if __name__ == '__main__':
    unittest.main()
