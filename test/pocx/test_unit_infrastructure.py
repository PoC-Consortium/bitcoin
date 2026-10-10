#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin PoCX developers
# Distributed under the MIT software license; see COPYING.
"""Unit-only registration, baseline and stale-build regression checks.

Usage: test_unit_infrastructure.py POCX_BUILD BITCOIN_BUILD [unittest selections]
Run after both unit configurations are built; scratch data stays in POCX_BUILD.
"""
from copy import deepcopy
import json
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
import pocx_bootstrap as pocx_bootstrap
from common import ROOT, OWNED
import unit_build
import unit_parity

BUILD = Path(sys.argv.pop(1)).resolve()
BITCOIN = Path(sys.argv.pop(1)).resolve()


class UnitInfrastructureTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir=BUILD, prefix='unit-infrastructure-')
        self.addCleanup(self.temp.cleanup)

    def test_empty_unit_binary(self):
        fake = Path(self.temp.name) / 'empty'
        fake.write_text('#!/bin/sh\nexit 0\n')
        fake.chmod(0o755)
        result = subprocess.run([sys.executable, str(OWNED / 'register_unit.py'), '--binary', str(fake), '--output', str(fake.with_suffix('.cmake'))], capture_output=True, text=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('empty discovery', result.stderr)

    def test_bitcoin_unit_suites_match_runtime(self):
        # Conditional source expressions can compile a suite while hiding it
        # from upstream's source-based CTest discovery (previously pow_tests).
        binary = BITCOIN / 'bin/test_bitcoin'
        listing = subprocess.run([str(binary), '--list_content'],
                                 capture_output=True, text=True, check=True)
        suites = set(re.findall(r'^([A-Za-z_][A-Za-z_0-9]*)\*$',
                                listing.stdout + listing.stderr, re.M))
        self.assertIn('pow_tests', suites)
        baseline = json.loads((OWNED / 'unit-baseline.json').read_text())
        self.assertEqual(unit_parity.runtime_cases(listing.stdout + listing.stderr),
                         set(baseline['cases']))
        selection = subprocess.run(['ctest', '--test-dir', str(BITCOIN),
                                    '--show-only=json-v1'],
                                   capture_output=True, text=True, check=True)
        tests = json.loads(selection.stdout)['tests']
        registered = {test['name'] for test in tests
                      if Path(test['command'][0]).resolve() == binary.resolve()}
        self.assertEqual(suites, registered)

    def test_unit_baseline_cases_and_exclusions_cannot_be_dropped(self):
        reviewed = json.loads((OWNED / 'unit-parity.json').read_text())
        self.assertEqual(unit_parity.check(ROOT, reviewed), [])
        for mutate in ('applicable', 'excluded'):
            broken = deepcopy(reviewed)
            if mutate == 'applicable':
                broken[mutate].pop()
            else:
                del broken[mutate][next(iter(broken[mutate]))]
            self.assertTrue(unit_parity.check(ROOT, broken))
        broken = deepcopy(reviewed)
        del broken['reviewed_sources']['src/node/blockstorage.cpp']
        self.assertTrue(unit_parity.check(ROOT, broken))

    def test_unit_adaptation_and_storage_reviews_cannot_drift(self):
        reviewed = json.loads((OWNED / 'unit-parity.json').read_text())
        original = unit_parity.digest
        for source in ('src/pocx/test/adapted/pow_tests.cpp',
                       'src/pocx/test/adapted/blockmanager_tests.cpp',
                       'src/node/blockstorage.cpp'):
            with self.subTest(source=source), patch.object(unit_parity, 'digest',
                    side_effect=lambda path: '0' * 64 if path == ROOT / source else original(path)):
                issues = unit_parity.check(ROOT, reviewed)
                self.assertEqual({issue['source'] for issue in issues}, {source})

    def test_unit_case_parser_distinguishes_helpers_and_nested_suites(self):
        listing = 'suite*\n    case*\n    nested*\n        other*\nmock_process \n    helper \n'
        self.assertEqual(unit_parity.runtime_cases(listing), {'suite/case', 'suite/nested/other'})
        with self.assertRaisesRegex(ValueError, 'Duplicate'):
            unit_parity.runtime_cases('suite*\n    case*\n    case*\n')

    def test_missing_explicit_unit_suite(self):
        result = subprocess.run([sys.executable, str(OWNED / 'run_unit.py'),
                                 '--build-dir', str(BUILD), '--suite', 'missing_proof_suite'],
                                capture_output=True, text=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('Missing requested suites', result.stderr)

    def unit_provenance_fixture(self):
        directory = Path(self.temp.name)
        binary, source, inputs, cache, record = [directory / name for name in (
            'test_pocx', 'proof.cpp', 'inputs.txt', 'CMakeCache.txt', 'discovered.build.json')]
        binary.write_bytes(b'compiled proof test')
        source.write_text('required proof checks\n')
        inputs.write_text(str(source) + '\n')
        cache.write_text('ENABLE_WALLET:BOOL=ON\n')
        suites = unit_build.OWNED_SUITES | {'pocx_block_builder_tests'}
        record.write_text(json.dumps(unit_build.snapshot(binary, inputs, cache, suites)))
        return binary, source, inputs, cache, record, suites

    def test_stale_unit_source_rejected(self):
        binary, source, inputs, cache, record, suites = self.unit_provenance_fixture()
        unit_build.verify(binary, inputs, cache, record, suites)
        source.write_text('new required proof checks\n')
        with self.assertRaisesRegex(ValueError, 'Stale unit build provenance'):
            unit_build.verify(binary, inputs, cache, record, suites)

    def test_changed_unit_source_selection_rejected(self):
        binary, source, inputs, cache, record, suites = self.unit_provenance_fixture()
        extra = source.with_name('new_real_proof.cpp')
        extra.write_text('another required suite\n')
        inputs.write_text(str(source) + '\n' + str(extra) + '\n')
        with self.assertRaisesRegex(ValueError, 'Stale unit build provenance'):
            unit_build.verify(binary, inputs, cache, record, suites)

    def test_unit_binary_or_options_change_rejected(self):
        binary, _, inputs, cache, record, suites = self.unit_provenance_fixture()
        binary.write_bytes(b'older executable missing checks')
        with self.assertRaisesRegex(ValueError, 'Stale unit build provenance'):
            unit_build.verify(binary, inputs, cache, record, suites)
        binary.write_bytes(b'compiled proof test')
        cache.write_text('ENABLE_WALLET:BOOL=OFF\n')
        with self.assertRaisesRegex(ValueError, 'Stale unit build provenance'):
            unit_build.verify(binary, inputs, cache, record, suites)

    def test_missing_owned_unit_suite_rejected(self):
        binary, _, inputs, cache, _, suites = self.unit_provenance_fixture()
        for missing in ('pocx_real_proof_tests', 'pocx_block_builder_tests'):
            with self.subTest(missing=missing):
                with self.assertRaisesRegex(ValueError, 'Missing required owned suites'):
                    unit_build.snapshot(binary, inputs, cache, suites - {missing})
        cache.write_text('ENABLE_WALLET:BOOL=OFF\n')
        unit_build.snapshot(binary, inputs, cache, suites - {'pocx_block_builder_tests'})

    def test_missing_unit_build_provenance_rejected(self):
        binary, _, inputs, cache, record, suites = self.unit_provenance_fixture()
        record.unlink()
        with self.assertRaisesRegex(ValueError, 'Missing unit build provenance'):
            unit_build.verify(binary, inputs, cache, record, suites)


if __name__ == '__main__':
    unittest.main()
