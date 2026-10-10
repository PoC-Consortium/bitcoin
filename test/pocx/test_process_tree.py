#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin PoCX developers
# Distributed under the MIT software license; see COPYING.
"""Real host descendant cleanup, with separate Windows adapter failure probes.

The host lifecycle checks run on Windows too. Mock adapters do not establish
Windows execution evidence when these checks run on a Unix host.
"""
from copy import deepcopy
import ctypes
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

import process_tree as trees


def alive(pid):
    if os.name == 'nt':
        api = ctypes.WinDLL('kernel32', use_last_error=True)
        api.OpenProcess.argtypes = [ctypes.c_uint32, ctypes.c_int, ctypes.c_uint32]
        api.OpenProcess.restype = ctypes.c_void_p
        api.GetExitCodeProcess.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_uint32)]
        api.CloseHandle.argtypes = [ctypes.c_void_p]
        handle = api.OpenProcess(0x1000, False, pid)  # PROCESS_QUERY_LIMITED_INFORMATION
        if not handle:
            if ctypes.get_last_error() == 87:  # ERROR_INVALID_PARAMETER: process is gone.
                return False
            raise ctypes.WinError(ctypes.get_last_error())
        try:
            code = ctypes.c_uint32()
            if not api.GetExitCodeProcess(handle, ctypes.byref(code)):
                raise ctypes.WinError(ctypes.get_last_error())
            return code.value == 259  # STILL_ACTIVE
        finally:
            api.CloseHandle(handle)
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    # A zombie has stopped and released its sockets/files, even if PID1 has not
    # reaped it in a container. Other Unix hosts rely on their normal reaper.
    status = Path('/proc') / str(pid) / 'stat'
    try:
        return not status.is_file() or status.read_text().rsplit(')', 1)[1].split()[0] != 'Z'
    except FileNotFoundError:
        return False


class ProcessTreeTest(unittest.TestCase):
    def fixture(self, mode, code=0):
        with tempfile.TemporaryDirectory(prefix='owned-process-tree-') as directory:
            root = Path(directory);pidfile = root / 'child.pid';script = root / 'fixture.py'
            script.write_text('''import os, pathlib, signal, subprocess, sys, time
mode, target, code = sys.argv[1:]
child = "import os,pathlib,signal,sys,time; pathlib.Path(sys.argv[1]).write_text(str(os.getpid())); time.sleep(120)"
subprocess.Popen([sys.executable, '-c', child, target])
deadline = time.monotonic() + 5
while not pathlib.Path(target).is_file() or not pathlib.Path(target).read_text().strip():
    if time.monotonic() >= deadline: raise RuntimeError('child did not start')
    time.sleep(.01)
if mode == 'ignore-term': signal.signal(signal.SIGTERM, signal.SIG_IGN)
if mode != 'exit': time.sleep(120)
sys.exit(int(code))
''')
            command = [sys.executable, str(script), mode, str(pidfile), str(code)]
            try:
                with (root / 'output.log').open('w') as log:
                    result = trees.execute(command, cwd=root, env=os.environ.copy(), log=log,
                                           timeout=0.8 if mode != 'exit' else 10, grace=0.5)
                self.assertTrue(pidfile.is_file(), (root / 'output.log').read_text())
                pid = int(pidfile.read_text())
                deadline = time.monotonic() + 3
                while alive(pid) and time.monotonic() < deadline:
                    time.sleep(.02)
                self.assertFalse(alive(pid), 'Owned descendant survived cleanup')
                trees.validate_control(trees.description(), result['process_control'], command)
                return result
            finally:
                # Never leave a deliberately leaked fixture process after a
                # regression failure. This PID comes only from our own child.
                if pidfile.is_file() and alive(pid := int(pidfile.read_text())):
                    if os.name == 'nt':
                        subprocess.run(['taskkill', '/F', '/PID', str(pid)], capture_output=True, check=False)
                    else:
                        os.kill(pid, signal.SIGKILL)

    def test_real_host_success_cleans_descendant_after_parent_exit(self):
        result = self.fixture('exit')
        self.assertEqual(result['returncode'], 0)
        self.assertIs(result['timed_out'], False)

    def test_real_host_failure_and_skip_keep_their_exit_codes_and_cleanup(self):
        for code in (7, 77):
            with self.subTest(code=code):
                result = self.fixture('exit', code)
                self.assertEqual(result['returncode'], code)
                self.assertIs(result['timed_out'], False)

    def test_real_host_timeout_terminates_the_whole_tree(self):
        result = self.fixture('timeout')
        self.assertNotEqual(result['returncode'], 0)
        self.assertIs(result['timed_out'], True)

    @unittest.skipUnless(os.name == 'posix', 'SIGTERM escalation is Unix-specific')
    def test_real_unix_timeout_escalates_when_parent_ignores_sigterm(self):
        result = self.fixture('ignore-term')
        self.assertEqual(result['returncode'], -signal.SIGKILL)
        self.assertIs(result['timed_out'], True)

    def test_invalid_command_deadline_or_platform_never_spawns(self):
        with patch.object(trees.subprocess, 'Popen') as spawn:
            for command in ([], '', [''], [True], ['python', None]):
                with self.subTest(command=command), self.assertRaises(ValueError):
                    trees.execute(command, cwd=None, env={}, log=None, timeout=1)
            for timeout in (0, -1, True, None, float('nan'), float('inf')):
                with self.subTest(timeout=timeout), self.assertRaises(ValueError):
                    trees.execute(['python'], cwd=None, env={}, log=None, timeout=timeout)
            with patch.object(trees, 'os', SimpleNamespace(name='unknown')), self.assertRaises(ValueError):
                trees.execute(['python'], cwd=None, env={}, log=None, timeout=1)
            spawn.assert_not_called()

    def test_windows_worker_joins_before_spawn_and_preserves_arguments(self):
        events = []
        api = Mock();api.join.side_effect = lambda name: events.append(('join', name))
        command = ['python', 'test with spaces.py', '']
        name = 'Local\\pocx-functional-' + 'a' * 32
        def run(actual, **kwargs):
            self.assertEqual(actual, command);self.assertEqual(kwargs, {'check': False})
            events.append(('spawn', actual));return SimpleNamespace(returncode=77)
        with patch.object(trees, 'os', SimpleNamespace(name='nt')), \
             patch.object(trees, 'WindowsApi', return_value=api), \
             patch.object(trees.subprocess, 'run', side_effect=run):
            self.assertEqual(trees.windows_worker(name, command), 77)
        self.assertEqual(events, [('join', name), ('spawn', command)])

    def test_windows_worker_cannot_spawn_when_job_assignment_fails(self):
        api = Mock();api.join.side_effect = OSError('cannot join test job')
        with patch.object(trees, 'os', SimpleNamespace(name='nt')), \
             patch.object(trees, 'WindowsApi', return_value=api), \
             patch.object(trees.subprocess, 'run') as spawn, self.assertRaises(OSError):
            trees.windows_worker('Local\\pocx-functional-' + 'b' * 32, ['python'])
        spawn.assert_not_called()

    def windows_parent(self, *, timeout=False, configure_error=False, spawn_error=False, active=False):
        api = Mock();api.create.return_value = 123;api.active.return_value = int(active)
        if configure_error:api.configure.side_effect = OSError('job policy failed')
        process = Mock();process.returncode = 1 if timeout else 77
        process.wait.side_effect = [subprocess.TimeoutExpired('fixture', 1), 1, 1] if timeout else [77, 77, 77]
        command = ['python', 'fixture.py']
        spawn = Mock(side_effect=OSError('spawn failed')) if spawn_error else Mock(return_value=process)
        with patch.object(trees, 'WindowsApi', return_value=api), \
             patch.object(trees.subprocess, 'Popen', spawn):
            try:
                result = trees._windows(command, cwd='cwd', env={'key':'value'}, log=None, timeout=1, grace=.01)
            finally:
                api.terminate.assert_called_once_with(123)
                api.close.assert_called_once_with(123)
                if configure_error:spawn.assert_not_called()
        self.assertEqual(result['returncode'], process.returncode)
        self.assertIs(result['timed_out'], timeout)
        controller = dict(trees.description(), kind='windows-job')
        trees.validate_control(controller, result['process_control'], command)
        self.assertEqual(spawn.call_args.args[0], result['process_control']['invocation'])

    def test_windows_parent_preserves_skip_and_times_out_the_owned_job(self):
        for timeout in (False, True):
            with self.subTest(timeout=timeout):self.windows_parent(timeout=timeout)

    def test_windows_parent_cleans_up_after_policy_or_spawn_failure(self):
        for failure in ('configure_error', 'spawn_error'):
            with self.subTest(failure=failure), self.assertRaises(OSError):
                self.windows_parent(**{failure:True})

    def test_windows_parent_never_accepts_active_descendants_as_cleaned(self):
        with self.assertRaisesRegex(TimeoutError, 'active descendants'):
            self.windows_parent(active=True)

    def test_windows_structures_use_documented_widths_and_alignment(self):
        self.assertEqual(ctypes.sizeof(trees.Accounting), 48)
        self.assertEqual(trees.Accounting.ActiveProcesses.offset, 40)
        self.assertEqual(trees.BasicLimits.LimitFlags.offset, 16)
        self.assertEqual(ctypes.sizeof(trees.IoCounters), 48)
        if ctypes.sizeof(ctypes.c_void_p) == 8:
            self.assertEqual(ctypes.sizeof(trees.BasicLimits), 64)
            self.assertEqual(ctypes.sizeof(trees.ExtendedLimits), 144)

    def windows_api(self):
        dll = Mock()
        for name in ('SetInformationJobObject', 'AssignProcessToJobObject', 'CloseHandle'):
            getattr(dll, name).return_value = 1
        dll.CreateJobObjectW.return_value = 123;dll.OpenJobObjectW.return_value = 123
        dll.GetCurrentProcess.return_value = 456
        with patch.object(trees.ctypes, 'WinDLL', return_value=dll, create=True):
            api = trees.WindowsApi()
        return api, dll

    def test_windows_api_sets_kill_on_close_without_breakaway_flags(self):
        api, dll = self.windows_api();api.configure(123)
        handle, kind, pointer, size = dll.SetInformationJobObject.call_args.args
        self.assertEqual((handle, kind, size), (123, 9, ctypes.sizeof(trees.ExtendedLimits)))
        self.assertEqual(pointer._obj.BasicLimitInformation.LimitFlags, 0x2000)
        self.assertIs(dll.CreateJobObjectW.restype, ctypes.c_void_p)
        self.assertEqual(dll.AssignProcessToJobObject.argtypes, [ctypes.c_void_p, ctypes.c_void_p])

    def test_windows_api_rejects_existing_job_without_modifying_it(self):
        api, dll = self.windows_api()
        with patch.object(trees.ctypes, 'get_last_error', return_value=183, create=True), \
             self.assertRaisesRegex(OSError, 'already exists'):
            api.create('collision fixture')
        dll.CloseHandle.assert_called_once_with(123)
        dll.SetInformationJobObject.assert_not_called();dll.TerminateJobObject.assert_not_called()

    def test_windows_api_closes_worker_handle_before_spawn_even_on_assignment_failure(self):
        for assigned in (0, 1):
            api, dll = self.windows_api();dll.AssignProcessToJobObject.return_value = assigned
            with patch.object(trees.ctypes, 'get_last_error', return_value=5, create=True), \
                 patch.object(trees.ctypes, 'WinError', side_effect=lambda code: OSError(code, 'assignment failed'), create=True):
                if assigned:
                    api.join('job fixture')
                else:
                    with self.assertRaises(OSError):api.join('job fixture')
            dll.OpenJobObjectW.assert_called_once_with(1, False, 'job fixture')
            dll.AssignProcessToJobObject.assert_called_once_with(123, 456)
            dll.CloseHandle.assert_called_once_with(123)

    def test_controller_proof_rejects_missing_cleanup_and_changed_commands(self):
        command = ['python', 'case.py']
        controller = dict(trees.description(), kind='posix-session')
        control = {'kind':'posix-session','cleanup_complete':True,'invocation':command}
        trees.validate_control(controller, control, command)
        for field, value in [('cleanup_complete',False),('cleanup_complete',1),
                             ('kind','windows-job'),('invocation',['different'])]:
            broken = deepcopy(control);broken[field] = value
            with self.subTest(field=field, value=value), self.assertRaises(ValueError):
                trees.validate_control(controller, broken, command)
        with self.assertRaises(ValueError):trees.validate_control(None, control, command)
        with self.assertRaises(ValueError):trees.validate_control(controller, None, command)


if __name__ == '__main__':
    unittest.main()
