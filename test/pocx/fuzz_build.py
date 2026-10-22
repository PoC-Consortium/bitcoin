#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin PoCX developers
# Distributed under the MIT software license; see COPYING.
"""Bind a fuzz executable to its evaluated inputs and configured build."""
import json
from pathlib import Path

from common import sha256


def snapshot(binary, inputs, cache):
    paths = {Path(line).resolve() for line in inputs.read_text().splitlines() if line}
    if not paths:
        raise ValueError('Empty evaluated fuzz source selection')
    return {'scope': 'Fuzz build inputs and binary; not runtime or semantic parity proof',
            'binary_sha256': sha256(binary), 'input_manifest_sha256': sha256(inputs),
            'cache_sha256': sha256(cache),
            'sources': {str(path): sha256(path) for path in sorted(paths)}}


def verify(binary, inputs, cache, record):
    if not record.is_file():
        raise ValueError('Missing fuzz build provenance; rebuild fuzz')
    evidence = json.loads(record.read_text())
    if evidence != snapshot(binary, inputs, cache):
        raise ValueError('Stale fuzz build provenance; rebuild fuzz')
    return evidence
