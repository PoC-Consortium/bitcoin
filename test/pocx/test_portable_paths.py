#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin PoCX developers
# Distributed under the MIT software license; see COPYING.
"""Repository inventories must retain the same keys on Windows and POSIX."""
import json
from pathlib import Path
import tempfile
import unittest

from common import ROOT
from ci_evidence import source_snapshot, require_unchanged
from stage import framework_sources
from run_bitcoin_functional import read_cases


class PortablePathsTest(unittest.TestCase):
    def test_windows_csv_separators_preserve_failed_cases_and_strict_inventory(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'results.csv'
            path.write_bytes(b'test,status,duration(seconds)\r\r\n'
                             b'a.py,Passed,1\r\r\n'
                             b'b.py,Failed,2\r\r\nALL,Failed,3\r\r\n')
            rows, summary = read_cases(path, ['a.py', 'b.py'])
            self.assertEqual(rows, [['a.py', 'Passed', '1'], ['b.py', 'Failed', '2']])
            self.assertEqual(summary, ['ALL', 'Failed', '3'])
            with self.assertRaises(ValueError):
                read_cases(path, ['a.py'])
            with path.open('ab') as stream:
                stream.write(b'malformed,row\r\r\n')
            with self.assertRaises(ValueError):
                read_cases(path, ['a.py', 'b.py'])

    def test_upstream_framework_keys_match_every_owned_replacement(self):
        sources = framework_sources(ROOT)
        replacements = json.loads((ROOT / 'test/pocx/manifest.json').read_text())['replacements']
        self.assertTrue(replacements)
        self.assertLessEqual(set(replacements), set(sources))
        self.assertTrue(all('\\' not in key for key in sources))
        for key, path in sources.items():
            self.assertEqual(ROOT / 'test/functional' / key, path)

    def test_portable_snapshot_retains_nested_source_drift_detection(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name in ('CMakeLists.txt', 'CMakePresets.json',
                         '.github/workflows/pocx-tests.yml', 'src/nested/example.cpp'):
                path = root / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text('original input\n')
            recorded = source_snapshot(root)
            self.assertIn('src/nested/example.cpp', recorded)
            self.assertTrue(all('\\' not in key for key in recorded))
            require_unchanged('source', recorded, source_snapshot(root))
            (root / 'src/nested/example.cpp').write_text('changed input\n')
            with self.assertRaisesRegex(ValueError, 'src/nested/example.cpp'):
                require_unchanged('source', recorded, source_snapshot(root))


if __name__ == '__main__':
    unittest.main()
