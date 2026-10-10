#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin PoCX developers
# Distributed under the MIT software license; see COPYING.
"""Run one test in an owned Unix session or Windows job, including its children.

The Windows worker joins its parent's job before it can launch the test. The
parent keeps the only job handle while the test runs, so cleanup still covers
descendants after the test or worker exits. There is no uncontained fallback.
"""
import ctypes
import hashlib
import math
import os
from pathlib import Path
import re
import signal
import subprocess
import sys
import time
import uuid

SOURCE = 'test/pocx/process_tree.py'
FILE = Path(__file__).resolve()
JOB_PATTERN = r'Local\\pocx-functional-[0-9a-f]{32}'


class BasicLimits(ctypes.Structure):
    _fields_ = [('PerProcessUserTimeLimit', ctypes.c_int64),
                ('PerJobUserTimeLimit', ctypes.c_int64), ('LimitFlags', ctypes.c_uint32),
                ('MinimumWorkingSetSize', ctypes.c_size_t), ('MaximumWorkingSetSize', ctypes.c_size_t),
                ('ActiveProcessLimit', ctypes.c_uint32), ('Affinity', ctypes.c_size_t),
                ('PriorityClass', ctypes.c_uint32), ('SchedulingClass', ctypes.c_uint32)]


class IoCounters(ctypes.Structure):
    _fields_ = [(name, ctypes.c_uint64) for name in (
        'ReadOperationCount', 'WriteOperationCount', 'OtherOperationCount',
        'ReadTransferCount', 'WriteTransferCount', 'OtherTransferCount')]


class ExtendedLimits(ctypes.Structure):
    _fields_ = [('BasicLimitInformation', BasicLimits), ('IoInfo', IoCounters),
                *[(name, ctypes.c_size_t) for name in (
                    'ProcessMemoryLimit', 'JobMemoryLimit', 'PeakProcessMemoryUsed', 'PeakJobMemoryUsed')]]


class Accounting(ctypes.Structure):
    _fields_ = [*[(name, ctypes.c_int64) for name in (
        'TotalUserTime', 'TotalKernelTime', 'ThisPeriodTotalUserTime', 'ThisPeriodTotalKernelTime')],
        *[(name, ctypes.c_uint32) for name in (
            'TotalPageFaultCount', 'TotalProcesses', 'ActiveProcesses', 'TotalTerminatedProcesses')]]


class WindowsApi:
    def __init__(self):
        self.dll = ctypes.WinDLL('kernel32', use_last_error=True)
        handle = ctypes.c_void_p
        signatures = {
            'CreateJobObjectW': ([handle, ctypes.c_wchar_p], handle),
            'OpenJobObjectW': ([ctypes.c_uint32, ctypes.c_int, ctypes.c_wchar_p], handle),
            'SetInformationJobObject': ([handle, ctypes.c_int, handle, ctypes.c_uint32], ctypes.c_int),
            'QueryInformationJobObject': ([handle, ctypes.c_int, handle, ctypes.c_uint32, handle], ctypes.c_int),
            'AssignProcessToJobObject': ([handle, handle], ctypes.c_int),
            'GetCurrentProcess': ([], handle),
            'TerminateJobObject': ([handle, ctypes.c_uint32], ctypes.c_int),
            'CloseHandle': ([handle], ctypes.c_int),
        }
        for name, (arguments, result) in signatures.items():
            function = getattr(self.dll, name)
            function.argtypes, function.restype = arguments, result

    @staticmethod
    def checked(result):
        if not result:
            raise ctypes.WinError(ctypes.get_last_error())
        return result

    def create(self, name):
        handle = self.checked(self.dll.CreateJobObjectW(None, name))
        if ctypes.get_last_error() == 183:  # ERROR_ALREADY_EXISTS: never modify another job.
            self.close(handle)
            raise OSError('Windows test job already exists')
        return handle

    def configure(self, handle):
        limits = ExtendedLimits()
        limits.BasicLimitInformation.LimitFlags = 0x2000  # JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
        # No breakaway flags: test children must remain in the owned job.
        self.checked(self.dll.SetInformationJobObject(handle, 9, ctypes.byref(limits), ctypes.sizeof(limits)))

    def join(self, name):
        # JOB_OBJECT_ASSIGN_PROCESS; the worker closes its handle before spawn.
        handle = self.checked(self.dll.OpenJobObjectW(1, False, name))
        try:
            self.checked(self.dll.AssignProcessToJobObject(handle, self.dll.GetCurrentProcess()))
        finally:
            self.close(handle)

    def terminate(self, handle):
        self.checked(self.dll.TerminateJobObject(handle, 1))

    def active(self, handle):
        accounting = Accounting()
        self.checked(self.dll.QueryInformationJobObject(handle, 1, ctypes.byref(accounting),
                                                        ctypes.sizeof(accounting), None))
        return accounting.ActiveProcesses

    def close(self, handle):
        self.checked(self.dll.CloseHandle(handle))


def description():
    if os.name not in ('posix', 'nt'):
        raise ValueError('Unsupported test process platform: ' + os.name)
    return {'source': SOURCE, 'path': str(FILE), 'sha256': hashlib.sha256(FILE.read_bytes()).hexdigest(),
            'interpreter': sys.executable,
            'kind': 'windows-job' if os.name == 'nt' else 'posix-session'}


def validate_control(controller, control, command):
    if (not isinstance(controller, dict) or set(controller) != {'source', 'path', 'sha256', 'kind', 'interpreter'} or
            controller['source'] != SOURCE or not isinstance(controller['path'], str) or
            not isinstance(controller['interpreter'], str) or not controller['interpreter'] or
            not controller['path'] or not isinstance(controller['sha256'], str) or
            not re.fullmatch('[0-9a-f]{64}', controller['sha256']) or
            controller['kind'] not in ('posix-session', 'windows-job')):
        raise ValueError('Missing or invalid test process controller provenance')
    if not isinstance(control, dict) or control.get('cleanup_complete') is not True:
        raise ValueError('Test process tree cleanup was not completed')
    expected_keys = {'kind', 'cleanup_complete', 'invocation'}
    invocation = command
    if controller['kind'] == 'windows-job':
        expected_keys.add('job')
        if not isinstance(control.get('job'), str) or not re.fullmatch(JOB_PATTERN, control['job']):
            raise ValueError('Missing or invalid owned Windows test job')
        invocation = [controller['interpreter'], controller['path'], '--windows-worker', control['job'], '--', *command]
    if set(control) != expected_keys or control['kind'] != controller['kind'] or control['invocation'] != invocation:
        raise ValueError('Test process controller differs from the executed command')


def _signal_group(process, sig):
    try:
        os.killpg(process.pid, sig)
    except ProcessLookupError:
        pass


def _posix(command, *, cwd, env, log, timeout, grace):
    process = subprocess.Popen(command, cwd=cwd, env=env, stdout=log, stderr=subprocess.STDOUT,
                               start_new_session=True)
    timed_out = False
    try:
        try:
            code = process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            timed_out = True
            _signal_group(process, signal.SIGTERM)
            try:
                code = process.wait(timeout=grace)
            except subprocess.TimeoutExpired:
                _signal_group(process, signal.SIGKILL)
                code = process.wait(timeout=grace)
    finally:
        # Cleanup is needed even when the parent exits successfully or raises.
        _signal_group(process, signal.SIGKILL)
        process.wait(timeout=grace)
    return {'returncode': code, 'timed_out': timed_out,
            'process_control': {'kind': 'posix-session', 'cleanup_complete': True, 'invocation': command}}


def _windows(command, *, cwd, env, log, timeout, grace):
    api = WindowsApi()
    name = 'Local\\pocx-functional-' + uuid.uuid4().hex
    handle = api.create(name)
    process = None
    timed_out = False
    invocation = [sys.executable, str(FILE), '--windows-worker', name, '--', *command]
    try:
        api.configure(handle)
        process = subprocess.Popen(invocation, cwd=cwd, env=env, stdout=log, stderr=subprocess.STDOUT)
        try:
            code = process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            timed_out = True
            # Cleanup in finally terminates the whole job, including its worker.
    finally:
        try:
            api.terminate(handle)
            if process is not None:
                process.wait(timeout=grace)
            deadline = time.monotonic() + grace
            while api.active(handle):
                if time.monotonic() >= deadline:
                    raise TimeoutError('Windows test job still has active descendants')
                time.sleep(0.02)
        finally:
            # Closing the last handle is a second cleanup path if termination
            # failed. Any such failure still propagates instead of reporting pass.
            try:
                api.close(handle)
            finally:
                if process is not None:
                    try:
                        process.wait(timeout=grace)
                    except subprocess.TimeoutExpired:
                        # A worker not yet joined cannot have launched a test.
                        process.kill()
                        process.wait(timeout=grace)
    if timed_out:
        code = process.returncode
    return {'returncode': code, 'timed_out': timed_out,
            'process_control': {'kind': 'windows-job', 'cleanup_complete': True,
                                'invocation': invocation, 'job': name}}


def execute(command, *, cwd, env, log, timeout, grace=15):
    if (not isinstance(command, list) or not command or not command[0] or
            not all(isinstance(argument, str) for argument in command)):
        raise ValueError('Expected a nonempty test command')
    for value in (timeout, grace):
        if type(value) not in (int, float) or not math.isfinite(value) or value <= 0:
            raise ValueError('Test timeout and cleanup grace must be finite and positive')
    kind = description()['kind']
    operation = _windows if kind == 'windows-job' else _posix
    return operation(command, cwd=cwd, env=env, log=log, timeout=timeout, grace=grace)


def windows_worker(name, command):
    if os.name != 'nt' or not re.fullmatch(JOB_PATTERN, name) or not command:
        raise ValueError('Expected an owned Windows job and test command')
    WindowsApi().join(name)
    # Joining and closing the temporary job handle must both succeed first.
    # The test and every child it creates then inherit job membership.
    return subprocess.run(command, check=False).returncode


if __name__ == '__main__':
    if len(sys.argv) < 5 or sys.argv[1] != '--windows-worker' or sys.argv[3] != '--':
        raise SystemExit('Internal Windows process worker requires a job and command')
    sys.exit(windows_worker(sys.argv[2], sys.argv[4:]))
