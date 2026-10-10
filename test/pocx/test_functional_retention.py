#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin PoCX developers
# Distributed under the MIT software license; see COPYING.
"""Check the deletion boundary for retained functional-test evidence."""
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import functional_retention as retention


class RetentionTest(unittest.TestCase):
    def populate(self, root):
        for name in ('node0/regtest/blocks/blk00000.dat',
                     'node0/regtest/chainstate/CURRENT', 'node0/regtest/indexes/txindex/CURRENT',
                     'node0/regtest/wallets/default/wallet.dat', 'node0/regtest/debug.log',
                     'node0/bitcoin.conf', 'node0/testnet4/blocks/blk00000.dat',
                     'fixtures/node0/regtest/blocks/blk00000.dat',
                     'node-other/regtest/chainstate/CURRENT', 'blocks/fixture.dat'):
            path = root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(name)

    def prune(self, root, status='passed', complete=True):
        return retention.prune_passed_case(root, status=status,
                                           process_control={'cleanup_complete': complete})

    def test_passed_case_only_removes_direct_regtest_node_databases(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.populate(root)
            before = {path.relative_to(root): path.read_bytes() for path in root.rglob('*') if path.is_file()}
            self.assertEqual(self.prune(root), ['node0/regtest/blocks', 'node0/regtest/chainstate',
                                                'node0/regtest/indexes'])
            for path, contents in before.items():
                if path.parts[:3] in [('node0', 'regtest', name) for name in ('blocks', 'chainstate', 'indexes')]:
                    self.assertFalse((root / path).exists())
                else:
                    self.assertEqual((root / path).read_bytes(), contents)
            self.assertEqual(self.prune(root), [])

    def test_failed_skipped_or_incompletely_stopped_cases_keep_every_file(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.populate(root)
            before = {path.relative_to(root): path.read_bytes() for path in root.rglob('*') if path.is_file()}
            for status in ('failed', 'skipped'):
                self.assertEqual(self.prune(root, status, complete=False), [])
            with self.assertRaisesRegex(ValueError, 'completed process cleanup'):
                self.prune(root, complete=False)
            after = {path.relative_to(root): path.read_bytes() for path in root.rglob('*') if path.is_file()}
            self.assertEqual(after, before)

    def test_directory_links_at_each_boundary_do_not_remove_external_data(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            outside = root / 'outside'
            outside.mkdir()
            sentinel = outside / 'retained'
            sentinel.write_text('external fixture')
            case = root / 'case'
            case.mkdir()
            (root / 'linked-case').symlink_to(case, target_is_directory=True)
            (case / 'node0').symlink_to(outside, target_is_directory=True)
            (case / 'node1').mkdir()
            (case / 'node1/regtest').symlink_to(outside, target_is_directory=True)
            chain = case / 'node2/regtest'
            chain.mkdir(parents=True)
            (chain / 'blocks').symlink_to(outside, target_is_directory=True)
            self.assertEqual(self.prune(root / 'linked-case'), [])
            self.assertEqual(self.prune(case), [])
            self.assertEqual(sentinel.read_text(), 'external fixture')
            self.assertTrue((chain / 'blocks').is_symlink())

    def test_junctions_are_not_ordinary_directories(self):
        with tempfile.TemporaryDirectory() as directory:
            # Exercise the Windows directory-link predicate on older Python too.
            with patch.object(Path, 'is_junction', return_value=True, create=True):
                self.assertFalse(retention.ordinary_directory(Path(directory)))


if __name__ == '__main__':
    unittest.main()
