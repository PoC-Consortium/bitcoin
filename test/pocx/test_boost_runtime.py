#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin PoCX developers
# Distributed under the MIT software license; see COPYING.
"""Check CI randomization and complete reports using real Boost/CTest execution."""
from copy import deepcopy
import os
from pathlib import Path
import re
import subprocess
import tempfile
import unittest
import xml.etree.ElementTree as ET

import boost_runtime


class BoostRuntimeTests(unittest.TestCase):
    def test_only_randomization_survives_inherited_boost_options(self):
        original = {'PATH': '/bin', 'BOOST_TEST_RANDOM': '0007',
                    'BOOST_TEST_RUN_FILTERS': 'missing', 'BOOST_TEST_CATCH_SYSTEM_ERRORS': 'no',
                    'BOOST_TEST_REPORT_LEVEL': 'no', 'BOOST_TEST_LOG_LEVEL': 'nothing'}
        cleaned = boost_runtime.environment(original)
        self.assertEqual(cleaned, {'PATH': '/bin', 'BOOST_TEST_RANDOM': '7',
                                   'BOOST_TEST_LOG_LEVEL': 'message'})
        self.assertEqual(original['BOOST_TEST_RANDOM'], '0007')
        self.assertEqual(boost_runtime.environment({}), {'BOOST_TEST_RANDOM': '0'})

    def test_invalid_seed_fails_closed(self):
        for value in ('', '-1', '+1', '1.0', ' 1', '1 ', '١', str(2**32), None, True):
            with self.subTest(value=value), self.assertRaises(ValueError):
                boost_runtime.environment({'BOOST_TEST_RANDOM': value})

    def test_missing_inconsistent_and_malformed_evidence_rejected(self):
        log = boost_runtime.SEED_MESSAGE + '7\n'
        valid = boost_runtime.record({'BOOST_TEST_RANDOM': '7'}, log)
        self.assertEqual(boost_runtime.verify(log, valid, 1), valid)
        for recorded, text, processes in (
                (None, log, 1), ({}, log, 1),
                ({'random_seed': True, 'observed_seeds': [7]}, log, 1),
                ({'random_seed': 7, 'observed_seeds': [True]}, log, 1),
                ({'random_seed': 7, 'observed_seeds': []}, log, 1),
                ({'random_seed': 0, 'observed_seeds': [7]}, log, 1),
                ({'random_seed': 8, 'observed_seeds': [7]}, log, 1),
                (valid, '', 1), (valid, log, 2),
                (valid, boost_runtime.SEED_MESSAGE + 'invalid', 1),
                (valid, boost_runtime.SEED_MESSAGE + '7invalid', 1),
                (valid, boost_runtime.SEED_MESSAGE + str(2**32), 1)):
            with self.subTest(recorded=recorded, text=text, processes=processes), self.assertRaises(ValueError):
                boost_runtime.verify(text, recorded, processes)
        altered = deepcopy(valid)
        altered['unexpected'] = True
        with self.assertRaises(ValueError):
            boost_runtime.verify(log, altered, 1)

    def test_real_boost_ctest_randomizes_without_losing_cases(self):
        # A small infrastructure executable, not a Bitcoin baseline rebuild.
        with tempfile.TemporaryDirectory(prefix='boost-runtime-') as directory:
            source = Path(directory)
            build = source / 'build'
            cases = '\n'.join(f'BOOST_AUTO_TEST_CASE(case_{number}) {{ '
                              f'BOOST_TEST_MESSAGE("CASE_ORDER:{number}"); BOOST_CHECK(true); }}'
                              for number in range(8))
            (source / 'probe.cpp').write_text('#define BOOST_TEST_MODULE runtime_probe\n'
                '#include <boost/test/included/unit_test.hpp>\n' + cases + '\n')
            (source / 'CMakeLists.txt').write_text('cmake_minimum_required(VERSION 3.22)\n'
                'project(boost_runtime_probe LANGUAGES CXX)\nenable_testing()\n'
                'add_executable(probe probe.cpp)\nadd_test(NAME probe COMMAND probe)\n')
            subprocess.run(['cmake', '-S', str(source), '-B', str(build), '-G', 'Ninja'],
                           capture_output=True, text=True, check=True)
            subprocess.run(['cmake', '--build', str(build), '-j', '1'],
                           capture_output=True, text=True, check=True)
            orders = []
            for index, seed in enumerate(('2', '2', '3', '1', '0')):
                inherited = dict(os.environ, BOOST_TEST_RANDOM=seed, BOOST_TEST_RUN_FILTERS='missing',
                                 BOOST_TEST_REPORT_LEVEL='no', BOOST_TEST_LOG_LEVEL='nothing')
                env = boost_runtime.environment(inherited)
                report = source / f'report-{index}.xml'
                env.update(BOOST_TEST_REPORT_FORMAT='XML', BOOST_TEST_REPORT_LEVEL='detailed',
                           BOOST_TEST_REPORT_SINK=str(report))
                junit = source / f'ctest-{index}.xml'
                subprocess.run(['ctest', '--test-dir', str(build), '--output-junit', str(junit),
                                '--no-tests=error'], env=env, capture_output=True, text=True, check=True)
                log = (build / 'Testing/Temporary/LastTest.log').read_text()
                recorded = boost_runtime.record(env, log)
                boost_runtime.verify(log, recorded, 1)
                self.assertEqual(recorded['random_seed'], int(seed))
                suite = ET.parse(report).getroot().find('TestSuite')
                self.assertEqual({case.get('name') for case in suite},
                                 {f'case_{number}' for number in range(8)})
                self.assertEqual(suite.get('test_cases_passed'), '8')
                self.assertEqual(suite.get('test_cases_skipped'), '0')
                self.assertTrue(all(case.get('result') == 'passed' for case in suite))
                tests = list(ET.parse(junit).iter('testcase'))
                self.assertEqual(len(tests), 1)
                self.assertFalse(any(tests[0].find(tag) is not None for tag in ('failure', 'error', 'skipped')))
                order = re.findall(r'CASE_ORDER:([0-9]+)', log)
                if seed != '0':
                    self.assertEqual(set(order), {str(number) for number in range(8)})
                    self.assertEqual(len(order), 8)
                orders.append(order)
            self.assertEqual(orders[0], orders[1])
            self.assertNotEqual(orders[0], orders[2])


if __name__ == '__main__':
    unittest.main()
