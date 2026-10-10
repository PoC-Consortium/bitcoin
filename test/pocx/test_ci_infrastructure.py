#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin PoCX developers
# Distributed under the MIT software license; see COPYING.
"""Checks for the separately delivered combined CI entry points."""
import json
import configparser
from pathlib import Path
import sys
import tempfile
import unittest
from common import ROOT
from ci_evidence import artifact_paths, build_snapshot, require_unchanged, source_snapshot, verify_report, verify_steps

BITCOIN = Path(sys.argv.pop(1)).resolve()


class CIInfrastructureTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)

    def test_asan_tracing_wrapper_enables_prerequisites_without_mutating_original_recipe(self):
        import subprocess
        from common import sha256
        original = ROOT / 'ci/test/00_setup_env_native_asan.sh'
        before = sha256(original)
        command = ['bash', '-ec', '''export INSTALL_BCC_TRACING_TOOLS=false
source ./test/pocx/ci/00_setup_env_native_asan_tracing.sh
test "$INSTALL_BCC_TRACING_TOOLS" = true
test "$CONTAINER_NAME" = ci_native_asan
case "$PACKAGES" in *bpfcc-tools*linux-headers-*) ;; *) exit 19 ;; esac
case "$CI_CONTAINER_CAP" in *--privileged*) ;; *) exit 23 ;; esac
''']
        subprocess.run(command, cwd=ROOT, check=True)
        self.assertEqual(sha256(original), before)

    def test_retention_keeps_case_proof_and_prunes_only_node_chain_databases(self):
        import shutil
        root = self.files(['results.json', 'case.py.log', 'v2/case/test_framework.log',
                           'v2/case/node0/bitcoin.conf', 'v2/case/node0/regtest/debug.log',
                           'v2/case/node0/regtest/wallets/wallet.dat',
                           'v2/case/node0/regtest/blocks/blk00000.dat',
                           'v2/case/node0/regtest/blocks/index/000003.log',
                           'v2/case/node0/regtest/chainstate/000003.ldb',
                           'v2/case/node0/regtest/indexes/coinstats/db/000003.log',
                           'fixtures/blocks/expected.json', 'fixtures/chainstate/expected.json'])
        expected = {'results.json', 'case.py.log', 'v2/case/test_framework.log',
                    'v2/case/node0/bitcoin.conf', 'v2/case/node0/regtest/debug.log',
                    'v2/case/node0/regtest/wallets/wallet.dat',
                    'fixtures/blocks/expected.json', 'fixtures/chainstate/expected.json'}
        self.assertEqual({str(path.relative_to(root)) for path in artifact_paths(root)}, expected)
        for name in ('blocks', 'chainstate', 'indexes'):
            shutil.rmtree(root / 'v2/case/node0/regtest' / name)
        self.assertEqual({str(path.relative_to(root)) for path in artifact_paths(root)}, expected)

    def test_headless_cmake_internal_preferences_resolve_to_effective_disabled_options(self):
        from common import build_options
        for cached in ('ON', 'OFF'):
            options = build_options('BUILD_GUI:BOOL=OFF\nBUILD_TESTS:BOOL=ON\n'
                                    f'BUILD_GUI_TESTS:INTERNAL={cached}\nWITH_QRENCODE:INTERNAL={cached}\n'
                                    'CMAKE_HOME_DIRECTORY:INTERNAL=/source\n')
            self.assertEqual(options['BUILD_GUI_TESTS'], 'OFF')
            self.assertEqual(options['WITH_QRENCODE'], 'OFF')
            self.assertNotIn('CMAKE_HOME_DIRECTORY', options)
        self.assertNotIn('BUILD_GUI_TESTS', build_options(
            'BUILD_GUI:BOOL=ON\nBUILD_TESTS:BOOL=ON\nBUILD_GUI_TESTS:INTERNAL=OFF\n'))
        self.assertNotIn('WITH_QRENCODE', build_options(
            'BUILD_GUI:BOOL=OFF\nWITH_QRENCODE:INTERNAL=invalid\n'))

    def test_address_fixture_corrections_are_explicit_and_preserve_framework(self):
        from ci import stage_bitcoin_functional
        runner = stage_bitcoin_functional(BITCOIN, Path(self.temp.name), network_addresses=True)
        record = json.loads((runner.parents[2] / 'provenance.json').read_text())
        self.assertEqual({row['source'] for row in record['replacements']},
                         {'test/functional/feature_bind_port_discover.py',
                          'test/functional/feature_bind_port_externalip.py'})
        for name in ('test_runner.py', 'test_framework/test_node.py', 'rpc_help.py'):
            self.assertEqual((runner.parent / name).read_bytes(), (ROOT / 'test/functional' / name).read_bytes())
        for row in record['replacements']:
            self.assertEqual((runner.parent / Path(row['source']).name).read_bytes(),
                             (ROOT / row['replacement']).read_bytes())

    def test_bitcoin_functional_staging_uses_original_tests(self):
        from ci import stage_bitcoin_functional
        runner = stage_bitcoin_functional(BITCOIN, Path(self.temp.name))
        record = json.loads((runner.parents[2] / 'provenance.json').read_text())
        self.assertEqual(record['replacements'], [])
        for name in ('test_runner.py', 'rpc_help.py'):
            self.assertEqual((runner.parent / name).read_bytes(), (ROOT / 'test/functional' / name).read_bytes())

    def test_upstream_runner_executes_attested_staging_instead_of_build_symlinks(self):
        from ci import stage_bitcoin_functional
        from run_bitcoin_functional import verify_staging
        runner = stage_bitcoin_functional(BITCOIN, Path(self.temp.name), network_addresses=True)
        config = configparser.ConfigParser()
        config.read(runner.parent.parent / 'config.ini')
        view = Path(config['environment']['BUILDDIR'])
        self.assertEqual(view / 'test/functional', runner.parent)
        self.assertEqual((view / 'bin').resolve(), (BITCOIN / 'bin').resolve())
        for name in ('feature_bind_port_discover.py', 'feature_bind_port_externalip.py'):
            actual = view / 'test/functional' / name
            self.assertFalse(actual.is_symlink())
            self.assertEqual(actual.read_bytes(), (ROOT / 'test/pocx/bitcoin_baseline' / name).read_bytes())
        verify_staging(runner)
        (view / 'bin').unlink()
        (view / 'bin').symlink_to(view / 'unexpected-binaries', target_is_directory=True)
        with self.assertRaisesRegex(ValueError, 'different binary build'):
            verify_staging(runner)

    def files(self, paths):
        root = Path(self.temp.name)
        for name in paths:
            path = root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(name)
        return root

    def test_ci_source_proof_rejects_changes_to_helpers_workflow_and_resources(self):
        paths = ['CMakeLists.txt', 'CMakePresets.json', '.github/workflows/pocx-tests.yml',
                 'test/pocx/ci.py', 'test/pocx/common.py', 'test/pocx/unit_matrix.py',
                 'test/pocx/unit-parity.json', 'test/pocx/framework/clock.py',
                 'test/functional/test_framework/messages.py',
                 'test/functional/test_framework/crypto/vectors.csv', 'cmake/flags.cmake',
                 'src/qt/test/wallettests.cpp', 'src/pocx/test/adapted/coins_tests.cpp',
                 'src/validation.cpp', 'src/bench/CMakeLists.txt']
        root = self.files(paths)
        recorded = source_snapshot(root)
        self.assertEqual(set(recorded), set(paths))
        for name in paths:
            with self.subTest(name=name):
                path = root / name
                path.write_text('changed')
                with self.assertRaisesRegex(ValueError, 'changed during CI execution'):
                    require_unchanged('Source inputs', recorded, source_snapshot(root))
                path.write_text(name)
        added = root / 'test/pocx/new_import.py'
        added.write_text('new')
        with self.assertRaises(ValueError):
            require_unchanged('Source inputs', recorded, source_snapshot(root))
        added.unlink()
        (root / paths[-1]).unlink()
        with self.assertRaises(ValueError):
            require_unchanged('Source inputs', recorded, source_snapshot(root))

    def test_fuzz_implementation_is_not_a_dependency_of_delivered_ci(self):
        from ci import PROFILES
        root = self.files(['CMakeLists.txt', 'CMakePresets.json', '.github/workflows/pocx-tests.yml',
                           'test/pocx/ci.py', 'test/pocx/run_fuzz.py', 'test/pocx/fuzz/manifest.json'])
        self.assertNotIn('pocx-fuzz', PROFILES)
        self.assertNotIn('test/pocx/run_fuzz.py', source_snapshot(root))
        self.assertNotIn('test/pocx/fuzz/manifest.json', source_snapshot(root))

    def test_ci_build_proof_rejects_changed_binaries_cache_and_registrations(self):
        paths = ['CMakeCache.txt', 'build.ninja', 'CMakeFiles/rules.ninja', 'test/config.ini',
                 'bin/test_bitcoin', 'lib/libbitcoinkernel.so', 'src/test/CTestTestfile.cmake']
        root = self.files(paths)
        (root / 'CMakeCache.txt').write_text('CMAKE_GENERATOR:INTERNAL=Ninja\n')
        contents = {name:(root / name).read_bytes() for name in paths}
        recorded = build_snapshot(root)
        self.assertEqual(set(recorded), set(paths))
        for name in paths:
            with self.subTest(name=name):
                path = root / name
                path.write_text('changed')
                with self.assertRaises(ValueError):
                    require_unchanged('Build inputs', recorded, build_snapshot(root))
                path.write_bytes(contents[name])
        (root / 'bin/test_bitcoin').unlink()
        with self.assertRaisesRegex(ValueError, 'no built binaries'):
            build_snapshot(root)

    def test_visual_studio_build_snapshot_requires_solution_and_tracks_projects(self):
        paths = ['CMakeCache.txt', 'test/config.ini', 'BitcoinCore.slnx',
                 'src/test/test_bitcoin.vcxproj', 'CMakeFiles/flags.props',
                 'CMakeFiles/custom.targets', 'bin/Release/test_bitcoin.exe',
                 'src/test/CTestTestfile.cmake']
        root = self.files(paths)
        (root / 'CMakeCache.txt').write_text('CMAKE_GENERATOR:INTERNAL=Visual Studio 18 2026\n')
        recorded = build_snapshot(root)
        self.assertEqual(set(recorded), set(paths))
        for name in ('BitcoinCore.slnx','src/test/test_bitcoin.vcxproj','CMakeFiles/flags.props'):
            path = root / name;original = path.read_bytes();path.write_text('changed graph')
            with self.subTest(name=name), self.assertRaises(ValueError):
                require_unchanged('Build inputs', recorded, build_snapshot(root))
            path.write_bytes(original)
        (root / 'BitcoinCore.slnx').unlink()
        with self.assertRaisesRegex(ValueError, 'Missing Visual Studio solution'):
            build_snapshot(root)
        (root / 'BitcoinCore.sln').write_text('legacy solution')
        self.assertIn('BitcoinCore.sln',build_snapshot(root))

    def test_multi_configuration_build_snapshot_includes_selected_ninja_graph(self):
        paths = ['CMakeCache.txt','test/config.ini','build.ninja','build-Release.ninja',
                 'CMakeFiles/rules.ninja','CMakeFiles/impl-Release.ninja','bin/Release/test_bitcoin']
        root = self.files(paths)
        (root / 'CMakeCache.txt').write_text('CMAKE_GENERATOR:INTERNAL=Ninja Multi-Config\n')
        recorded = build_snapshot(root)
        self.assertEqual(set(recorded),set(paths))
        (root / 'CMakeFiles/impl-Release.ninja').write_text('changed selected graph')
        with self.assertRaises(ValueError):require_unchanged('Build inputs',recorded,build_snapshot(root))
        (root / 'CMakeCache.txt').write_text('CMAKE_GENERATOR:INTERNAL=unknown\n')
        with self.assertRaisesRegex(ValueError, 'unsupported CI build generator'):build_snapshot(root)

    def test_ci_proof_rejects_green_summary_with_missing_failed_or_changed_steps(self):
        from common import sha256
        root = self.files(['drift.log', 'unit.log', 'auxiliary.log'])
        steps = [{'name': name, 'status': 'passed', 'returncode': 0, 'command': ['runner', name],
                  'log_sha256': sha256(root / (name + '.log'))}
                 for name in ('drift', 'unit', 'auxiliary')]
        report = {'profile': 'bitcoin-unit', 'skip_build': True, 'status': 'passed', 'steps': steps}
        verify_steps(report, root)
        for replacement in (steps[:-1], steps + [steps[-1]], list(reversed(steps))):
            with self.assertRaisesRegex(ValueError, 'inventory'):
                verify_steps({**report, 'steps': replacement}, root)
        for changed in ({'returncode': 1}, {'status': 'failed'}, {'command': []}, {'log_sha256': 'stale'}):
            with self.subTest(changed=changed), self.assertRaisesRegex(ValueError, 'failed or has missing/changed'):
                verify_steps({**report, 'steps': [steps[0], {**steps[1], **changed}, steps[2]]}, root)
        with self.assertRaisesRegex(ValueError, 'inventory'):
            verify_steps({**report, 'skip_build': False}, root)
        (root / 'unit.log').write_text('different result')
        with self.assertRaisesRegex(ValueError, 'missing/changed'):
            verify_steps(report, root)

    def test_saved_ci_report_rejects_changed_child_evidence_and_failed_status(self):
        from common import sha256
        root = self.files(['CMakeLists.txt', 'CMakePresets.json', '.github/workflows/pocx-tests.yml',
                           'build/ci-results/drift.log', 'build/ci-results/drift.json'])
        output = root / 'build/ci-results'
        artifact = output / 'drift.json'
        report = {'profile': 'drift', 'source': str(root), 'build': str(root / 'build'),
                  'skip_build': True, 'status': 'passed', 'source_snapshot': source_snapshot(root),
                  'steps': [{'name': 'drift', 'status': 'passed', 'returncode': 0,
                             'command': ['runner'], 'log_sha256': sha256(output / 'drift.log')}],
                  'artifacts': {str(artifact): sha256(artifact)}}
        self.assertEqual(verify_report(root, report, output)['retained_artifacts'], 1)
        with self.assertRaisesRegex(ValueError, 'not a passing execution'):
            verify_report(root, {**report, 'status': 'failed'}, output)
        with self.assertRaisesRegex(ValueError, 'no retained artifacts'):
            verify_report(root, {**report, 'artifacts': {}}, output)
        artifact.write_text('different inventory')
        with self.assertRaisesRegex(ValueError, 'artifact missing or changed'):
            verify_report(root, report, output)
        artifact.unlink()
        with self.assertRaisesRegex(ValueError, 'artifact missing or changed'):
            verify_report(root, report, output)


if __name__ == '__main__':
    unittest.main()
