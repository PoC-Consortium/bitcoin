#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin PoCX developers
# Distributed under the MIT software license; see COPYING.
"""Check that successful Qt process exits cannot hide partial or skipped suites."""
import unittest

from run_qt import expected_cases, verify_methods, verify_output

WRAPPER = '<testsuite><testcase name="test_bitcoin-qt"/></testsuite>'


class QtExecutionTest(unittest.TestCase):
    def log(self, native=True, wallet=True):
        return '\n'.join(f'1: PASS : {case}()' for case in sorted(expected_cases(native, wallet)))

    def test_complete_bitcoin_and_native_profiles(self):
        for native, wallet, originals in ((False, True, 9), (True, True, 9),
                                          (False, False, 7), (True, False, 7)):
            with self.subTest(native=native, wallet=wallet):
                result = verify_output(self.log(native, wallet), WRAPPER, native, wallet)
                self.assertEqual(result['original_green'], originals)
                self.assertEqual(result['native_only_green'], int(native))

    def test_direct_artifact_output_uses_same_method_inventory_without_ctest(self):
        for native in (False, True):
            self.assertEqual(verify_methods(self.log(native), native, True),
                             verify_output(self.log(native), WRAPPER, native, True))
        for log in (self.log().replace('1: PASS : URITests::uriTests()', ''),
                    self.log() + '\nSKIP : URITests::uriTests()',
                    self.log() + '\nPASS : URITests::uriTests()'):
            with self.assertRaises(ValueError):
                verify_methods(log, True, True)

    def test_successful_exit_with_missing_case_is_rejected(self):
        with self.assertRaisesRegex(ValueError, 'inventory mismatch'):
            verify_output(self.log().replace('1: PASS : URITests::uriTests()', ''), WRAPPER, True, True)

    def test_skipped_or_expected_failure_is_rejected(self):
        for status in ('SKIP', 'FAIL!', 'XFAIL', 'XPASS'):
            with self.subTest(status=status), self.assertRaisesRegex(ValueError, 'failed, skipped'):
                verify_output(self.log() + f'\n{status} : URITests::uriTests()', WRAPPER, True, True)

    def test_duplicate_and_unknown_cases_are_rejected(self):
        for case in ('URITests::uriTests', 'UnreviewedTests::newCase'):
            with self.subTest(case=case), self.assertRaisesRegex(ValueError, 'inventory mismatch'):
                verify_output(self.log() + f'\nPASS : {case}()', WRAPPER, True, True)

    def test_missing_failed_skipped_or_duplicate_wrapper_is_rejected(self):
        for xml in ('<testsuite/>', WRAPPER.replace('/>', '><failure/></testcase>'),
                    WRAPPER.replace('/>', '><skipped/></testcase>'),
                    WRAPPER.replace('</testsuite>', '<testcase name="test_bitcoin-qt"/></testsuite>')):
            with self.subTest(xml=xml), self.assertRaisesRegex(ValueError, 'CTest wrapper'):
                verify_output(self.log(), xml, True, True)


if __name__ == '__main__':
    unittest.main()
