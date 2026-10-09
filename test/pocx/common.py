#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin PoCX developers
# Distributed under the MIT software license; see COPYING.
"""Paths, configuration and scratch directories shared by PoCX test runners."""
import hashlib
import os
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
OWNED = ROOT / "test/pocx"


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
        raise ValueError('Source path is too long for IPC tests; use a shorter isolated worktree path')
    temp.mkdir(parents=True, exist_ok=True)
    return temp


def build_options(cache):
    options = {}
    for line in cache.splitlines():
        if line.startswith(('//', '#')) or ':' not in line or '=' not in line:
            continue
        key, rest = line.split(':', 1)
        kind, value = rest.split('=', 1)
        if kind != 'INTERNAL':
            options[key] = value
    return options
