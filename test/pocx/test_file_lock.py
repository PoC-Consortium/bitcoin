#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin PoCX developers
# Distributed under the MIT software license; see COPYING.
"""Real host lock checks and Windows adapter fixtures, not Windows suite proof."""
import builtins
import importlib.util
import os
from pathlib import Path
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import common


class FileLockTest(unittest.TestCase):
    def test_lock_preserves_existing_contents_and_releases_on_close(self):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'build.lock';path.write_bytes(b'old lock data')
            with common.exclusive_lock(path):
                with self.assertRaises(OSError):common.exclusive_lock(path)
            with common.exclusive_lock(path):pass
            self.assertEqual(path.read_bytes(),b'old lock data')

    def test_different_builds_can_hold_locks_independently(self):
        with tempfile.TemporaryDirectory() as directory:
            with common.exclusive_lock(Path(directory)/'one.lock'), \
                 common.exclusive_lock(Path(directory)/'two.lock'):pass

    def test_competing_process_is_rejected_then_can_acquire_released_lock(self):
        script=('import sys\nsys.path.insert(0,sys.argv[1])\nfrom common import exclusive_lock\n'
                'from pathlib import Path\ntry:\n lock=exclusive_lock(Path(sys.argv[2]))\n'
                'except OSError:\n sys.exit(17)\nlock.close()\n')
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'build.lock'
            command=[sys.executable,'-c',script,str(common.OWNED),str(path)]
            with common.exclusive_lock(path):
                result=subprocess.run(command,capture_output=True,text=True,timeout=10)
                self.assertEqual(result.returncode,17,result.stdout+result.stderr)
            result=subprocess.run(command,capture_output=True,text=True,timeout=10)
            self.assertEqual(result.returncode,0,result.stdout+result.stderr)

    @unittest.skipUnless(os.name == 'posix','Unix compatibility fixture')
    def test_existing_flock_and_new_helper_exclude_each_other(self):
        import fcntl
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'build.lock'
            with common.exclusive_lock(path),path.open('a+b') as legacy:
                with self.assertRaises(OSError):fcntl.flock(legacy,fcntl.LOCK_EX|fcntl.LOCK_NB)
            with path.open('a+b') as legacy:
                fcntl.flock(legacy,fcntl.LOCK_EX|fcntl.LOCK_NB)
                with self.assertRaises(OSError):common.exclusive_lock(path)

    def test_windows_adapter_locks_byte_zero_without_truncation(self):
        calls=[]
        def locking(fd,mode,count):calls.append((os.lseek(fd,0,os.SEEK_CUR),mode,count))
        adapter=SimpleNamespace(LK_NBLCK=123,locking=locking)
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'build.lock';path.write_bytes(b'existing contents')
            with patch.object(common,'os',SimpleNamespace(name='nt')),patch.dict(sys.modules,msvcrt=adapter):
                with common.exclusive_lock(path):pass
            self.assertEqual(calls,[(0,123,1)])
            self.assertEqual(path.read_bytes(),b'existing contents')

    def test_windows_lock_failure_closes_descriptor_and_propagates(self):
        descriptors=[]
        def locking(fd,*args):
            descriptors.append(fd);raise OSError('contended Windows lock fixture')
        adapter=SimpleNamespace(LK_NBLCK=123,locking=locking)
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'build.lock'
            with patch.object(common,'os',SimpleNamespace(name='nt')),patch.dict(sys.modules,msvcrt=adapter):
                with self.assertRaisesRegex(OSError,'contended'):common.exclusive_lock(path)
            with self.assertRaises(OSError):os.fstat(descriptors[0])

    def test_missing_windows_lock_api_cannot_silently_run_unlocked(self):
        original=builtins.__import__
        def load(name,*args,**kwargs):
            if name=='msvcrt':raise ModuleNotFoundError('Windows fixture missing msvcrt')
            return original(name,*args,**kwargs)
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'build.lock'
            with patch.object(common,'os',SimpleNamespace(name='nt')),patch('builtins.__import__',side_effect=load):
                with self.assertRaises(ModuleNotFoundError):common.exclusive_lock(path)
            with common.exclusive_lock(path):pass

    def test_unknown_platform_fails_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'build.lock'
            with patch.object(common,'os',SimpleNamespace(name='unknown')):
                with self.assertRaisesRegex(ValueError,'Unsupported'):common.exclusive_lock(path)
            with common.exclusive_lock(path):pass

    def test_unit_runners_import_without_unix_fcntl(self):
        original=builtins.__import__
        def load(name,*args,**kwargs):
            if name=='fcntl':raise ModuleNotFoundError('Unix-only module blocked by portability fixture')
            return original(name,*args,**kwargs)
        with patch('builtins.__import__',side_effect=load):
            for name in ('run_unit','run_bitcoin_unit'):
                spec=importlib.util.spec_from_file_location('portable_fixture_'+name,common.OWNED/(name+'.py'))
                module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)


if __name__ == '__main__':
    unittest.main()
