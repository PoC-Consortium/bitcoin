#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin PoCX developers
# Distributed under the MIT software license; see COPYING.
"""Provision the pinned external script vectors required by complete unit runs."""
import argparse
import hashlib
import json
from pathlib import Path
import tempfile
import urllib.request

COMMIT = '0739b29cfb99e8de42298f550e9cdbf1a7659dcf'
SHA256 = 'cd789a58ec45916e1721cdd14e82ca4c93100959f1cef4e229b22e3bf539f095'
VECTORS = 2244
URL = f'https://raw.githubusercontent.com/bitcoin-core/qa-assets/{COMMIT}/unit_test_data/script_assets_test.json'


def validate(payload):
    if hashlib.sha256(payload).hexdigest() != SHA256:
        raise ValueError('External unit script assets checksum mismatch')
    vectors = json.loads(payload)
    if not isinstance(vectors, list) or len(vectors) != VECTORS:
        raise ValueError('External unit script vector inventory mismatch')


def provision(directory):
    directory = Path(directory).resolve()
    directory.mkdir(parents=True, exist_ok=True)
    target = directory / 'script_assets_test.json'
    if target.exists():
        validate(target.read_bytes())
    else:
        with urllib.request.urlopen(URL, timeout=120) as response:
            payload = response.read()
        validate(payload)
        temporary = None
        try:
            with tempfile.NamedTemporaryFile(dir=directory, prefix='.script-assets-', delete=False) as stream:
                temporary = Path(stream.name)
                stream.write(payload)
            temporary.replace(target)
        finally:
            if temporary is not None:
                temporary.unlink(missing_ok=True)
    return {'directory': str(directory), 'repository': 'bitcoin-core/qa-assets',
            'commit': COMMIT, 'sha256': SHA256, 'vectors': VECTORS, 'url': URL}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--directory', type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(provision(args.directory), indent=2))
