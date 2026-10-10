#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin PoCX developers
# Distributed under the MIT software license; see COPYING.
"""Keep inherited reference exceptions narrow and new locale violations fatal."""
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import unittest

from common import ROOT

spec = importlib.util.spec_from_file_location('checked_locale_reference', ROOT / 'test/pocx/lint/locale_reference.py')
policy = importlib.util.module_from_spec(spec)
spec.loader.exec_module(policy)


class LocaleReferencePolicyTest(unittest.TestCase):
    def setUp(self):
        scratch = tempfile.TemporaryDirectory(prefix='locale-policy-')
        self.addCleanup(scratch.cleanup)
        self.root = Path(scratch.name)
        for relative in (policy.CHECKER, policy.ADAPTED_CHECKER, policy.ORIGINAL, policy.ADAPTED):
            path = self.root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / relative, path)

    def test_exception_is_only_the_exact_inherited_reference_line(self):
        exception = policy.reviewed_legacy_exception(self.root)
        line = policy.ADAPTED + ':    return strtoll(str.c_str(), nullptr, 10);'
        self.assertIsNotNone(re.fullmatch(exception, line))
        for changed in (line.replace(policy.ADAPTED, 'src/pocx/other.cpp'),
                        line.replace('str.c_str()', 'other.c_str()'),
                        line.replace('strtoll', 'strtol'), line + ' // extra'):
            with self.subTest(changed=changed):
                self.assertIsNone(re.fullmatch(exception, changed))

    def test_changed_or_removed_assertion_fails_even_in_both_copies(self):
        for relative in (policy.ORIGINAL, policy.ADAPTED):
            path = self.root / relative
            path.write_text(path.read_text().replace(
                'BOOST_CHECK_EQUAL(LocaleIndependentAtoi<int32_t>("1234"), 1\'234);',
                'BOOST_CHECK(true);'))
        with self.assertRaisesRegex(ValueError, 'assertions changed'):
            policy.reviewed_legacy_exception(self.root)

    def test_changed_legacy_reference_is_rejected(self):
        path = self.root / policy.ADAPTED
        path.write_text(path.read_text().replace('return strtoll(str.c_str(), nullptr, 10);',
                                                'return LocaleIndependentAtoi<int64_t>(str);'))
        with self.assertRaisesRegex(ValueError, 'reference or original locale assertions changed'):
            policy.reviewed_legacy_exception(self.root)

    def test_duplicate_identical_call_elsewhere_is_rejected(self):
        path = self.root / policy.ADAPTED
        path.write_text(path.read_text() + '\nint64_t extra(const std::string& str) {\n'
                        '    return strtoll(str.c_str(), nullptr, 10);\n}\n')
        with self.assertRaisesRegex(ValueError, 'Additional legacy conversion'):
            policy.reviewed_legacy_exception(self.root)

    def test_changed_original_checker_requires_review(self):
        path = self.root / policy.CHECKER
        path.write_text(path.read_text().replace('src/test/util_tests.cpp:.*strtoll', 'src/.*strtoll'))
        with self.assertRaisesRegex(ValueError, 'Original locale checker changed'):
            policy.reviewed_legacy_exception(self.root)

    def test_owned_copy_cannot_change_scanner_or_add_exceptions(self):
        path = self.root / policy.ADAPTED_CHECKER
        original = path.read_text()
        for changed in (original.replace('--extended-regexp', '--fixed-strings'),
                        original.replace('KNOWN_VIOLATIONS = [', 'KNOWN_VIOLATIONS = ["src/pocx/.*",'),
                        original.replace('reviewed_legacy_exception()])', 'reviewed_legacy_exception(), "src/.*"])')):
            with self.subTest(changed=changed):
                path.write_text(changed)
                with self.assertRaises(ValueError):
                    policy.reviewed_legacy_exception(self.root)

    def test_actual_checker_keeps_new_violations_fatal(self):
        fake_git = self.root / 'git'
        inputs = self.root / 'grep-lines.json'
        fake_git.write_text('#!/usr/bin/env python3\nimport json,pathlib,sys\n'
                            'assert sys.argv[1:3] == ["grep", "--extended-regexp"]\n'
                            'print("\\n".join(json.loads(pathlib.Path(__file__).with_name("grep-lines.json").read_text())))\n')
        fake_git.chmod(0o755)
        reference = ':    return strtoll(str.c_str(), nullptr, 10);'
        inherited = [policy.ORIGINAL + reference, policy.ADAPTED + reference]
        command = [sys.executable, '-B', str(ROOT / policy.ADAPTED_CHECKER)]
        env = {**os.environ, 'PATH': str(self.root) + os.pathsep + os.environ['PATH']}
        for extra in ([], ['src/node/new.cpp:    return strtoll(value, nullptr, 10);'],
                      [policy.ADAPTED + ':    return strtoll(other, nullptr, 10);'],
                      [policy.ADAPTED + ':    return snprintf(output, 5, "%d", value);']):
            with self.subTest(extra=extra):
                inputs.write_text(json.dumps(inherited + extra))
                result = subprocess.run(command, env=env, cwd=ROOT, capture_output=True, text=True)
                self.assertEqual(result.returncode, 1 if extra else 0, result.stdout + result.stderr)
                self.assertEqual(result.stderr, '')
                for line in extra:
                    self.assertIn(line, result.stdout)
                self.assertNotIn(policy.ADAPTED + reference, result.stdout)


if __name__ == '__main__':
    unittest.main()
