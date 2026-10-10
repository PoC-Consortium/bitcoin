#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin PoCX developers
# Distributed under the MIT software license; see COPYING.
"""Exercise immutable payload relocation, without running Windows binaries."""
from copy import deepcopy
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from common import build_options, sha256
import artifact_functional_view as views
import record_cross_unit
import test_windows_artifacts
import windows_artifacts as artifacts


class FunctionalArtifactViewTest(unittest.TestCase):
    def setUp(self):
        self.helper = test_windows_artifacts.WindowsArtifactsTest()
        mock = patch.object(artifacts.unit_matrix, 'inventory', side_effect=self.helper.inventory)
        mock.start()
        self.addCleanup(mock.stop)

    def fixture(self, directory, *, change=None):
        root, builds, bundle = self.helper.fixture(Path(directory) / 'source')
        for name in ('test_runner.py', 'test_framework/util.py', 'data/vector.json'):
            path = root / 'test/functional' / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text('original fixture: ' + name + '\n')
        tool = root / 'share/rpcauth/rpcauth.py'
        for build in builds:
            cache_path = build / 'CMakeCache.txt'
            options = build_options(cache_path.read_text())
            with cache_path.open('a') as stream:
                stream.write('CMAKE_CACHEFILE_DIR:INTERNAL=' + str(build) + '\n')
                for switch in set(views.COMPONENTS.values()) - set(options):
                    stream.write(switch + ':BOOL=OFF\n')
            options = build_options(cache_path.read_text())
            config = ('[environment]\nCLIENT_NAME=Bitcoin Core\nCLIENT_BUGREPORT=fixture\n'
                f'SRCDIR={root}\nBUILDDIR={build}\nEXEEXT=.exe\nRPCAUTH={tool}\n[components]\n')
            config += ''.join(name + '=true\n' for name, switch in views.COMPONENTS.items() if options[switch] == 'ON')
            (build / 'test/config.ini').write_text(config)
        if change:
            change(root, builds)
        native = builds[1]
        artifacts.write_json(native / 'src/pocx/test/cross-build.json', record_cross_unit.snapshot(
            native / 'bin/test_pocx.exe', native / 'src/pocx/test/unit-inputs.txt', native / 'CMakeCache.txt', root))
        self.helper.export(root, builds, bundle)
        return root, bundle

    def create(self, root, bundle, consensus='bitcoin'):
        destination = root / ('runtime-' + consensus)
        report = views.create_view(bundle, consensus, destination, root=root, revision='a' * 40)
        return destination, report

    def verify(self, root, bundle, destination, consensus='bitcoin'):
        return views.verify_view(bundle, consensus, destination, root=root, revision='a' * 40)

    def test_moved_payload_is_relocated_without_changing_features_sources_or_producer(self):
        with tempfile.TemporaryDirectory() as directory:
            root, bundle = self.fixture(directory)
            moved = Path(directory) / 'consumer-source'
            root.rename(moved)
            root = moved
            bundle = root / 'bundle'
            before = {path.relative_to(bundle).as_posix(): sha256(path) for path in bundle.rglob('*') if path.is_file()}
            for consensus in ('bitcoin', 'pocx'):
                destination, report = self.create(root, bundle, consensus)
                self.assertEqual(self.verify(root, bundle, destination, consensus), report)
                producer = (bundle / consensus / 'provenance/CMakeCache.txt').read_text()
                runtime = (destination / 'CMakeCache.txt').read_text()
                self.assertEqual(build_options(runtime), build_options(producer))
                self.assertIn('CMAKE_HOME_DIRECTORY:INTERNAL=' + root.as_posix(), runtime)
                self.assertNotIn('consumer-source', producer)
                self.assertEqual(len(report['cache_relocations']), 2)
                self.assertEqual(len(report['configuration_relocations']), 3)
                self.assertIn('not a local compiler build', report['scope'])
                for name in ('test_runner.py', 'test_framework/util.py', 'data/vector.json'):
                    self.assertEqual((destination / 'test/functional' / name).read_bytes(),
                                     (root / 'test/functional' / name).read_bytes())
                self.assertFalse(any(path.is_symlink() for path in destination.rglob('*')))
            self.assertEqual(before, {path.relative_to(bundle).as_posix(): sha256(path)
                                     for path in bundle.rglob('*') if path.is_file()})

    def test_changed_or_missing_runtime_inputs_are_rejected(self):
        for name in ('CMakeCache.txt', 'test/config.ini', 'bin/bitcoind.exe', 'test/functional/test_framework/util.py'):
            with self.subTest(name=name), tempfile.TemporaryDirectory() as directory:
                root, bundle = self.fixture(directory)
                destination, _ = self.create(root, bundle)
                path = destination / name
                before = path.read_bytes()
                path.write_bytes(before + b'changed\n')
                with self.assertRaises(ValueError):
                    self.verify(root, bundle, destination)
                path.unlink()
                with self.assertRaises(ValueError):
                    self.verify(root, bundle, destination)

    def test_runtime_provenance_cannot_waive_input_changes(self):
        with tempfile.TemporaryDirectory() as directory:
            root, bundle = self.fixture(directory)
            destination, report = self.create(root, bundle)
            path = destination / 'bin/bitcoind.exe'
            path.write_bytes(b'replacement')
            changed = deepcopy(report)
            changed['files']['bin/bitcoind.exe'] = sha256(path)
            artifacts.write_json(destination / views.MANIFEST, changed)
            with self.assertRaisesRegex(ValueError, 'provenance'):
                self.verify(root, bundle, destination)

    def test_extra_inputs_and_symlinks_fail_but_runtime_outputs_are_allowed(self):
        with tempfile.TemporaryDirectory() as directory:
            root, bundle = self.fixture(directory)
            destination, _ = self.create(root, bundle)
            for name in ('test/cache/state.dat', 'pocx-functional/results.json', 'runtime-reports/results.json'):
                path = destination / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text('runtime output')
            self.verify(root, bundle, destination)
            for name in ('bin/extra.exe', 'test/functional/extra_case.py', 'test/functional/extra.pyc'):
                path = destination / name
                path.write_text('unreviewed input')
                with self.assertRaises(ValueError):
                    self.verify(root, bundle, destination)
                path.unlink()
            original = destination / 'test/functional/test_runner.py'
            original.unlink()
            original.symlink_to(root / 'test/functional/test_runner.py')
            with self.assertRaisesRegex(ValueError, 'symlinked'):
                self.verify(root, bundle, destination)

    def test_source_and_immutable_payload_changes_invalidate_view(self):
        for relative in ('test/functional/test_runner.py', 'bundle/bitcoin/bin/bitcoind.exe',
                         'share/rpcauth/rpcauth.py', 'test/config.ini.in'):
            with self.subTest(relative=relative), tempfile.TemporaryDirectory() as directory:
                root, bundle = self.fixture(directory)
                destination, _ = self.create(root, bundle)
                with (root / relative).open('ab') as stream:
                    stream.write(b'changed')
                with self.assertRaises(ValueError):
                    self.verify(root, bundle, destination)

    def test_feature_mismatch_unknown_component_and_non_windows_suffix_fail(self):
        for suffix in ('ENABLE_WALLET=false\n', 'UNKNOWN_COMPONENT=true\n', 'suffix'):
            def change(root, builds):
                path = builds[0] / 'test/config.ini'
                text = path.read_text()
                if suffix == 'suffix':
                    text = text.replace('EXEEXT=.exe', 'EXEEXT=')
                elif suffix.startswith('ENABLE_WALLET'):
                    text = text.replace('ENABLE_WALLET=true', 'ENABLE_WALLET=false')
                else:
                    text += suffix
                path.write_text(text)
            with self.subTest(change=suffix), tempfile.TemporaryDirectory() as directory:
                root, bundle = self.fixture(directory, change=change)
                with self.assertRaises(ValueError):
                    self.create(root, bundle)
                self.assertFalse((root / 'runtime-bitcoin').exists())

    def test_ambiguous_cache_paths_and_unsafe_destinations_fail(self):
        for key in ('CMAKE_HOME_DIRECTORY', 'CMAKE_CACHEFILE_DIR'):
            with self.subTest(key=key), self.assertRaises(ValueError):
                views.relocate_cache(key + ':INTERNAL=/one\n' + key + ':INTERNAL=/two\n', Path('/root'), Path('/view'))
        with tempfile.TemporaryDirectory() as directory:
            root, bundle = self.fixture(directory)
            for destination in (root, bundle / 'runtime', Path(directory) / 'outside'):
                with self.subTest(destination=destination), self.assertRaises(ValueError):
                    views.create_view(bundle, 'bitcoin', destination, root=root, revision='a' * 40)
            destination, _ = self.create(root, bundle)
            with self.assertRaisesRegex(ValueError, 'already exists'):
                self.create(root, bundle)
            with self.assertRaises(ValueError):
                self.verify(root, bundle, destination, 'pocx')


if __name__ == '__main__':
    unittest.main()
