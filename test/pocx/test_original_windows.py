#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin PoCX developers
# Distributed under the MIT software license; see COPYING.
"""Guard Windows fixture corrections and reject lost assertions or view drift."""
import json
from pathlib import Path
import tempfile
import unittest

from common import ROOT, sha256
import inherited_functional
import original_windows


class OriginalWindowsTest(unittest.TestCase):
    def fixture(self, directory):
        root = Path(directory)
        for name in (original_windows.ORIGINAL, original_windows.REPLACEMENT, original_windows.REVIEW,
                     'test/functional/wallet_multiwallet.py',
                     'test/pocx/bitcoin_baseline/windows/wallet_multiwallet.py'):
            path = root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes((ROOT / name).read_bytes())
        return root

    def test_only_exact_locale_correction_is_permitted(self):
        with tempfile.TemporaryDirectory() as directory:
            root = self.fixture(directory)
            self.assertEqual(set(original_windows.replacements(root)), {'rpc_signer.py', 'wallet_multiwallet.py'})
            path = root / original_windows.REPLACEMENT
            path.write_text(path.read_text().replace("assert_equal({'fingerprint'", "print({'fingerprint'"))
            review = root / original_windows.REVIEW
            record = json.loads(review.read_text())
            record['replacement_sha256'] = sha256(path)
            review.write_text(json.dumps(record))
            with self.assertRaisesRegex(ValueError, 'scenarios or assertions'):
                original_windows.replacements(root)

    def test_multiwallet_guard_rejects_changed_rpc_assertion(self):
        with tempfile.TemporaryDirectory() as directory:
            root = self.fixture(directory)
            path = root / 'test/pocx/bitcoin_baseline/windows/wallet_multiwallet.py'
            path.write_text(path.read_text(encoding='utf8').replace('err_code = -4', 'err_code = -5'), encoding='utf8')
            review = root / original_windows.REVIEW
            record = json.loads(review.read_text())
            record['multiwallet']['replacement_sha256'] = sha256(path)
            review.write_text(json.dumps(record))
            with self.assertRaisesRegex(ValueError, 'scenarios or assertions'):
                original_windows.replacements(root)

    def test_view_preserves_upstream_and_rejects_changed_or_extra_inputs(self):
        with tempfile.TemporaryDirectory() as directory:
            root = self.fixture(directory)
            build = root / 'build'
            for name in ('bin', 'lib', 'test'):
                (build / name).mkdir(parents=True)
            (build / 'test/config.ini').write_text('[environment]\nBUILDDIR=original\n')
            before = (root / original_windows.ORIGINAL).read_bytes()
            view, proof = original_windows.stage(build, root / 'output', root=root)
            self.assertEqual((root / original_windows.ORIGINAL).read_bytes(), before)
            self.assertEqual(original_windows.verify(view, build, root=root), proof)
            extra = view / 'test/functional/unreviewed.py'
            extra.write_text('unreviewed\n')
            with self.assertRaises(ValueError):
                original_windows.verify(view, build, root=root)

    def test_windows_scratch_is_short_unique_and_keeps_original_selection(self):
        profile = inherited_functional.inherited_options({})
        commands = [inherited_functional.original_command(ROOT / 'build',
                    ROOT / ('artifacts/' + label * 100), ('complete', ['rpc_signer.py'], False),
                    mode, 2, 40, profile, windows=True)
                    for label, mode in (('a', 'v1'), ('a', 'v2'), ('b', 'v1'))]
        scratch = [next(a.split('=', 1)[1] for a in command if a.startswith('--tmpdirprefix='))
                   for command in commands]
        self.assertEqual(len(set(scratch)), 3)
        self.assertTrue(all(Path(path).parent == ROOT for path in scratch))
        self.assertTrue(all(Path(path).name.startswith('build-ft-') for path in scratch))
        self.assertTrue(all('--extended' in command and
                            '--exclude=feature_unsupported_utxo_db.py' in command for command in commands))

    def test_existing_platform_guards_do_not_count_as_passes(self):
        profile = inherited_functional.inherited_options({})
        for name in ('feature_posix_fs_permissions.py', 'tool_bitcoin.py'):
            state, reason = inherited_functional.classify(name, 'Skipped', {'target_system': 'Windows'}, profile)
            self.assertEqual(state, 'configuration-disabled')
            self.assertIn('Original platform guard', reason)
            self.assertEqual(inherited_functional.classify(name, 'Failed', {'target_system': 'Windows'}, profile)[0], 'failed')
            self.assertEqual(inherited_functional.classify(name, 'Skipped', {'target_system': 'Linux'}, profile)[0], 'unverified')


if __name__ == '__main__':
    unittest.main()
