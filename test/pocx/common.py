#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin PoCX developers
# Distributed under the MIT software license; see COPYING.
"""Paths, configuration and scratch directories shared by PoCX test runners."""
import hashlib
import os
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
OWNED = ROOT / "test/pocx"


def exclusive_lock(path):
    """Hold a nonblocking build lock until the returned file is closed.

    Windows CRT locks start at the current position and can extend beyond EOF.
    Use byte zero of the same non-truncated file for every invocation. Unix
    keeps flock compatibility with existing runners.
    """
    stream = path.open('a+b')
    try:
        if os.name == 'nt':
            import msvcrt
            stream.seek(0)
            msvcrt.locking(stream.fileno(), msvcrt.LK_NBLCK, 1)
        elif os.name == 'posix':
            import fcntl
            fcntl.flock(stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
        else:
            raise ValueError('Unsupported build-lock platform: ' + os.name)
    except BaseException:
        stream.close()
        raise
    return stream


def sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def short_tmpdir(build):
    """Keep IPC socket names short without putting test state outside the worktree."""
    temp = build / 't'
    if len(os.fsencode(temp)) > 80:
        # Default CI profile names can push Unix sockets over sockaddr_un's
        # limit. Separate builds retain distinct scratch directories.
        name = hashlib.sha256(str(build).encode()).hexdigest()[:8]
        temp = ROOT / 'build-tmp' / name
        if len(os.fsencode(temp)) > 80:
            # A slightly longer checkout can still fit a root-level scratch
            # directory. Keep the same build identity and ignored build prefix.
            temp = ROOT / ('build' + name)
    if len(os.fsencode(temp)) > 80:
        raise ValueError('Source path is too long for IPC tests; use a shorter isolated worktree path')
    temp.mkdir(parents=True, exist_ok=True)
    return temp


def build_options(cache):
    options = {}
    internal = {}
    for line in cache.splitlines():
        if line.startswith(('//', '#')) or ':' not in line or '=' not in line:
            continue
        key, rest = line.split(':', 1)
        kind, value = rest.split('=', 1)
        if kind != 'INTERNAL':
            options[key] = value
        else:
            internal[key] = value
    # CMake hides dependent GUI options in INTERNAL cache entries when their
    # parent is disabled. The cached value is a preference for a later enabled
    # configuration; the effective value is OFF while the condition is false.
    for key, parents in {'BUILD_GUI_TESTS': ('BUILD_GUI', 'BUILD_TESTS'),
                         'WITH_QRENCODE': ('BUILD_GUI',)}.items():
        if (key not in options and internal.get(key) in ('ON', 'OFF') and
                any(options.get(parent) == 'OFF' for parent in parents)):
            options[key] = 'OFF'
    return options
