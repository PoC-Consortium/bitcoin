#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin PoCX developers
# Distributed under the MIT software license; see COPYING.
"""Kernel inventory, fixture and execution-evidence regression checks.

Usage: test_kernel_infrastructure.py POCX_BUILD RESULTS_JSON [unittest selections]
Results must come from the detailed Boost XML / CTest run of that build.
"""
from copy import deepcopy
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
import xml.etree.ElementTree as ET

sys.dont_write_bytecode = True
import kernel_parity

ROOT = kernel_parity.ROOT
BUILD = Path(sys.argv.pop(1)).resolve()
RESULTS = Path(sys.argv.pop(1)).resolve()


class KernelInfrastructureTest(unittest.TestCase):
    def setUp(self):
        self.review = json.loads((ROOT / 'test/pocx/kernel-parity.json').read_text())
        self.temp = tempfile.TemporaryDirectory(dir=BUILD, prefix='kernel-infrastructure-')
        self.addCleanup(self.temp.cleanup)

    def test_original_cases_and_required_reviews_cannot_be_dropped(self):
        self.assertEqual(kernel_parity.check(ROOT, self.review), [])
        for mutation in ('case', 'exclusion', 'dependency'):
            broken = deepcopy(self.review)
            if mutation == 'case':
                broken['applicable'].pop()
            elif mutation == 'exclusion':
                broken['excluded']['btck_block'] = 'silently dropped'
            else:
                del broken['reviewed_sources']['src/kernel/bitcoinkernel.cpp']
            with self.subTest(mutation=mutation):
                self.assertTrue(kernel_parity.check(ROOT, broken))

    def test_reviewed_sources_cannot_drift(self):
        original = kernel_parity.digest
        for source in self.review['reviewed_sources']:
            with self.subTest(source=source), patch.object(kernel_parity, 'digest',
                    side_effect=lambda path: '0' * 64 if path == ROOT / source else original(path)):
                issues = kernel_parity.check(ROOT, self.review)
                self.assertEqual({issue['source'] for issue in issues}, {source})

    def test_unverified_fixtures_rejected_before_rendering(self):
        source = Path(self.temp.name) / 'unverified.json'
        output = source.with_suffix('.h')
        source.write_text('{}\n')
        result = subprocess.run([sys.executable, str(ROOT / 'test/pocx/kernel/render_fixtures.py'),
                                 str(source), str(output)], capture_output=True, text=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('differ from the independently verified snapshot', result.stderr)
        self.assertFalse(output.exists())

    def test_current_execution_contains_all_original_cases(self):
        result = kernel_parity.verify_execution(ROOT, BUILD, RESULTS, self.review)
        self.assertEqual(result['original_green'], 16)
        self.assertEqual(result['failed'], 0)
        self.assertEqual(result['skipped'], 0)

    def test_missing_or_skipped_case_rejected_despite_green_wrapper(self):
        for mutation in ('missing', 'skipped'):
            report = json.loads(RESULTS.read_text())
            xml = ET.parse(ROOT / report['boost_report'])
            suite = xml.getroot().find('TestSuite')
            case = suite.find('TestCase')
            if mutation == 'missing':
                suite.remove(case)
            else:
                case.set('result', 'skipped')
            altered = Path(self.temp.name) / 'boost.xml'
            xml.write(altered)
            report['boost_report'] = str(altered)
            report['boost_report_sha256'] = kernel_parity.digest(altered)
            record = Path(self.temp.name) / 'results.json'
            record.write_text(json.dumps(report))
            with self.subTest(mutation=mutation), self.assertRaisesRegex(ValueError, 'incomplete kernel cases'):
                kernel_parity.verify_execution(ROOT, BUILD, record, self.review)

    def test_stale_binary_configuration_sources_and_reports_rejected(self):
        for field in ('binary_sha256', 'cache_sha256', 'executed_source_snapshot', 'boost_report_sha256'):
            report = json.loads(RESULTS.read_text())
            if field == 'executed_source_snapshot':
                report[field]['src/pocx/test/kernel/test_kernel.cpp'] = '0' * 64
            else:
                report[field] = '0' * 64
            record = Path(self.temp.name) / 'results.json'
            record.write_text(json.dumps(report))
            with self.subTest(field=field), self.assertRaises(ValueError):
                kernel_parity.verify_execution(ROOT, BUILD, record, self.review)

    def test_commands_cannot_build_and_run_different_configurations(self):
        original = json.loads(RESULTS.read_text())
        selected = original.get('build_configuration') or 'Release'
        for field, flag in (('build_command', '--config'), ('command', '--build-config')):
            report = deepcopy(original)
            report['build_configuration'] = selected
            report['build_command'] = ['cmake', '--config', selected]
            report['command'] = ['ctest', '--build-config', selected]
            report[field] = [arg for arg in report[field] if arg not in (flag, selected)]
            record = Path(self.temp.name) / 'results.json'
            record.write_text(json.dumps(report))
            with self.subTest(field=field), self.assertRaisesRegex(ValueError, 'commands do not select'):
                kernel_parity.verify_execution(ROOT, BUILD, record, self.review)

    def test_failed_rebuild_cannot_leave_old_green_summary(self):
        directory = Path(self.temp.name)
        fake_bin = directory / 'bin'
        fake_bin.mkdir()
        fake_cmake = fake_bin / 'cmake'
        fake_cmake.write_text('#!/bin/sh\nexit 1\n')
        fake_cmake.chmod(0o755)
        output = directory / 'results'
        output.mkdir()
        result_file = output / 'verification.json'
        result_file.write_text('{"status": "passed"}\n')
        env = dict(os.environ, PATH=str(fake_bin) + os.pathsep + os.environ['PATH'])
        result = subprocess.run([sys.executable, str(ROOT / 'test/pocx/run_kernel.py'),
                                 '--build-dir', str(BUILD), '--output-dir', str(output)],
                                env=env, capture_output=True, text=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(json.loads(result_file.read_text())['status'], 'failed')


if __name__ == '__main__':
    unittest.main()
