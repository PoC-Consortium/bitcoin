#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin PoCX developers
# Distributed under the MIT software license; see COPYING.
"""Expand inherited product matrices before GitHub creates the platform jobs."""
import hashlib
import json
import os

from common import ROOT

JOBS = {'linux': 'ci-matrix', 'macos': 'macos-native-arm64', 'windows': 'windows-native-dll'}
FUZZ_ENVIRONMENTS = {'./ci/test/00_setup_env_native_fuzz.sh',
                     './ci/test/00_setup_env_native_fuzz_with_msan.sh'}
UPSTREAM_RECIPE_MAP_SHA256 = '09821d2f932a29ae5f3002e35fbadf4a9fe286df1ac02ddbcc64ae14cbce26df'
UPSTREAM_REVISION = '9be056a8a72b624dae9623b2f7bded92c2a21c91'
UPSTREAM_MATRIX_SHA256 = '5281faede86e2a69eb775c39c48dc28e9542d247458149af94e405231df126ff'


def matrices(product, root=ROOT):
    if product not in ('bitcoin', 'pocx'):
        raise ValueError('Matrix selection requires CI_PRODUCT=bitcoin or pocx')
    reference = json.loads((root / 'test/pocx/upstream-ci-matrix.json').read_text())
    original = reference['matrices']
    encoded = json.dumps(original, sort_keys=True, separators=(',', ':')).encode()
    if (reference['upstream_revision'] != UPSTREAM_REVISION or
            hashlib.sha256(encoded).hexdigest() != UPSTREAM_MATRIX_SHA256):
        raise ValueError('Inherited matrix changed without upstream scope review')
    recipes = reference.get('recipe_sha256', {})
    encoded_recipes = json.dumps(recipes, sort_keys=True, separators=(',', ':')).encode()
    if hashlib.sha256(encoded_recipes).hexdigest() != UPSTREAM_RECIPE_MAP_SHA256:
        raise ValueError('Original CI recipe inventory changed without upstream scope review')
    for name, expected in recipes.items():
        if hashlib.sha256((root / name).read_bytes()).hexdigest() != expected:
            raise ValueError('Original CI recipe changed: ' + name)
    result = {}
    for output, job in JOBS.items():
        rows = original[job]['include']
        if product == 'pocx':
            rows = [row for row in rows if row.get('job-type') != 'fuzz' and
                    row.get('file-env') not in FUZZ_ENVIRONMENTS]
        # An include-only matrix avoids exclude/include interactions which can
        # otherwise reintroduce explicitly deferred fuzz configurations.
        result[output] = {'include': rows}
    return result


if __name__ == '__main__':
    for name, matrix in matrices(os.environ.get('CI_PRODUCT')).items():
        print(name + '=' + json.dumps(matrix, separators=(',', ':')))
