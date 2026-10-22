#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin PoCX developers
# Distributed under the MIT software license; see COPYING.
"""Generate reviewed PoCX address-fixture replacements without calling the node.

Only checksum-valid addresses are translated. Payloads and witness versions are
preserved. Malformed inputs remain malformed; valid descriptor checksums are
recomputed only when the original descriptor checksum verified.
"""
import hashlib
import json
from pathlib import Path
import re
import sys
import pocx_bootstrap as pocx_bootstrap
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'test/functional'))
from test_framework.address import base58_to_byte, byte_to_base58
from test_framework.segwit_addr import decode_segwit_address, encode_segwit_address
from test_framework.descriptors import descsum_check, descsum_create

ROOT = Path(__file__).resolve().parents[2]

MAPPING = {}


def translate(token, chain=None):
    replacement = token
    lower = token.lower()
    for prefix, new in [('bcrt', 'rpocx'), ('bc', 'pocx'), ('tb', 'tpocx')]:
        if lower.startswith(prefix + '1'):
            version, payload = decode_segwit_address(prefix, token)
            if version is not None:
                replacement = encode_segwit_address(new, version, payload)
                if token.isupper():
                    replacement = replacement.upper()
            break
    else:
        try:
            payload, version = base58_to_byte(token)
            versions = {0: 85, 5: 90}
            if chain in ['testnet', 'testnet4']:
                versions.update({111: 127, 196: 132})
            if len(payload) == 20 and version in versions:
                replacement = byte_to_base58(payload, versions[version])
        except (AssertionError, ValueError, IndexError):
            pass
    if replacement != token:
        MAPPING[token] = replacement
    return replacement


def adapt(text):
    def string(match):
        literal = match[0]
        contents = literal[1:-1]
        changed = re.sub(r'[A-Za-z0-9]{14,90}', lambda m: translate(m[0]), contents)
        if changed != contents and '#' in contents:
            try:
                if descsum_check(contents):
                    changed = descsum_create(changed.split('#')[0])
            except (ValueError, AssertionError):
                pass
        return '"' + changed + '"'
    return re.sub(r'"(?:[^"\\]|\\.)*"', string, text)


def main():
    files = ['key_tests.cpp', 'script_standard_tests.cpp', 'util_tests.cpp', 'rpc_tests.cpp', 'descriptor_tests.cpp']
    provenance = {}
    for name in files:
        source = ROOT / 'src/test' / name
        target = ROOT / 'src/pocx/test/adapted' / name
        target.write_text(adapt(source.read_text()))
        provenance[name] = {'source': str(source.relative_to(ROOT)), 'source_sha256': hashlib.sha256(source.read_bytes()).hexdigest(),
                            'reason': 'PoCX network address constants; scripts, keys and assertions preserved'}
    source = ROOT / 'src/test/amount_tests.cpp'
    (ROOT / 'src/pocx/test/adapted/amount_tests.cpp').write_text(source.read_text().replace(' BTC/kvB', ' BTCX/kvB'))
    provenance['amount_tests.cpp'] = {'source': 'src/test/amount_tests.cpp', 'source_sha256': hashlib.sha256(source.read_bytes()).hexdigest(), 'reason': 'PoCX currency display is BTCX'}
    source = ROOT / 'src/test/data/key_io_valid.json'
    values = json.loads(source.read_text())
    for row in values:
        row[0] = translate(row[0], row[2]['chain'])
    (ROOT / 'src/pocx/test/data/key_io_valid.json').write_text(json.dumps(values, indent=4) + '\n')
    source = ROOT / 'src/test/data/bip341_wallet_vectors.json'
    (ROOT / 'src/pocx/test/data/bip341_wallet_vectors.json').write_text(adapt(source.read_text()))
    for name in ['key_io_valid.json', 'bip341_wallet_vectors.json']:
        source = ROOT / 'src/test/data' / name
        provenance['data/' + name] = {'source': str(source.relative_to(ROOT)),
            'source_sha256': hashlib.sha256(source.read_bytes()).hexdigest(),
            'reason': 'Network address envelopes only; scripts and cryptographic vectors unchanged'}
    (ROOT / 'test/pocx/address-vector-provenance.json').write_text(json.dumps({'sources': provenance, 'addresses': MAPPING}, indent=2) + '\n')
    print(f'Adapted {len(files)+1} suites and valid key/address vectors; {len(MAPPING)} address mappings')


if __name__ == '__main__':
    main()
