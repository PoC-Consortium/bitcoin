#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin PoCX developers
# Distributed under the MIT software license; see COPYING.
"""Bind unit discovery to the evaluated test sources, selected inputs and binary.

This detects stale builds and missing required owned suites. It is not a full
compiler dependency graph or evidence of assertion-level upstream parity.
"""
import hashlib
import json
from pathlib import Path

OWNED_SUITES = {'pocx_tests', 'pocx_simd_tests', 'pocx_wire_tests', 'pocx_real_proof_tests'}


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def required_suites(cache):
    return OWNED_SUITES | ({'pocx_block_builder_tests'} if 'ENABLE_WALLET:BOOL=ON\n' in cache else set())


def snapshot(binary, inputs, cache, suites):
    missing = required_suites(cache.read_text()) - set(suites)
    if missing:
        raise ValueError(f'Missing required owned suites: {sorted(missing)}')
    paths = {Path(line).resolve() for line in inputs.read_text().splitlines() if line}
    if not paths:
        raise ValueError('Empty evaluated unit source selection')
    return {'scope': __doc__, 'binary_sha256': digest(binary),
            'input_manifest_sha256': digest(inputs), 'cache_sha256': digest(cache),
            'sources': {str(path): digest(path) for path in sorted(paths)},
            'suites': sorted(suites)}


def verify(binary, inputs, cache, record, suites):
    if not record.is_file():
        raise ValueError('Missing unit build provenance; rebuild test_pocx')
    evidence = json.loads(record.read_text())
    current = snapshot(binary, inputs, cache, suites)
    differences = [field for field in ('binary_sha256', 'input_manifest_sha256', 'cache_sha256', 'suites')
                   if evidence.get(field) != current[field]]
    differences += [path for path in sorted(evidence.get('sources', {}).keys() | current['sources'].keys())
                    if evidence.get('sources', {}).get(path) != current['sources'].get(path)]
    if differences:
        raise ValueError(f'Stale unit build provenance; rebuild test_pocx: {differences}')
    return evidence
