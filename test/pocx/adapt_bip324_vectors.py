#!/usr/bin/env python3
"""Regenerate only network-dependent BIP324 outputs using Python reference crypto.

Every original Bitcoin output is verified before its PoCX replacement is emitted.
Inputs, packet indices, payload sizes and all C++ rejection assertions are retained.
"""
import hashlib
import json
from pathlib import Path
import re
import sys

import pocx_bootstrap as pocx_bootstrap
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'test/functional'))
from test_framework.crypto.chacha20 import FSChaCha20
from test_framework.crypto.bip324_cipher import FSChaCha20Poly1305
from test_framework.crypto.hkdf import hkdf_sha256
from test_framework.v2_p2p import EncryptedP2PState

ROOT = Path(__file__).resolve().parents[2]


def outputs(row, magic):
    idx, priv, ours, theirs, initiating, content, multiply, aad, ignore = row[:9]
    secret = EncryptedP2PState.v2_ecdh(bytes.fromhex(priv), bytes.fromhex(theirs), bytes.fromhex(ours), initiating)
    def key(info):
        return hkdf_sha256(salt=b'bitcoin_v2_shared_secret' + magic, ikm=secret, info=info.encode(), length=32)
    side = 'initiator' if initiating else 'responder'
    length_cipher = FSChaCha20(key(side + '_L'))
    payload_cipher = FSChaCha20Poly1305(key(side + '_P'))
    def encrypt(content, aad, ignore):
        return length_cipher.crypt(len(content).to_bytes(3, 'little')) + payload_cipher.encrypt(aad, bytes([128 if ignore else 0]) + content)
    for _ in range(idx):
        encrypt(b'', b'', True)
    ciphertext = encrypt(bytes.fromhex(content) * multiply, bytes.fromhex(aad), ignore)
    garbage = key('garbage_terminators')
    send, recv = (garbage[:16], garbage[16:]) if initiating else (garbage[16:], garbage[:16])
    return [send.hex(), recv.hex(), key('session_id').hex(), ciphertext.hex() if row[12] else '', ciphertext[-len(bytes.fromhex(row[13])):].hex() if row[13] else '']


def main():
    source = ROOT / 'src/test/bip324_tests.cpp'
    original = source.read_text()
    count = 0
    def replace(match):
        nonlocal count
        row = json.loads('[' + match[1] + ']')
        assert len(row) == 14
        assert outputs(row, bytes.fromhex('f9beb4d9')) == row[9:], f'Bitcoin reference mismatch, vector {count}'
        row[9:] = outputs(row, bytes.fromhex('a73c915e'))
        count += 1
        print(f'Verified and converted vector {count}', flush=True)
        return '    TestBIP324PacketVector(\n        ' + ',\n        '.join(json.dumps(x) for x in row) + ');'
    adapted = re.sub(r'^    TestBIP324PacketVector\(\s*(.*?)\);', replace, original, flags=re.M | re.S)
    assert count == 7, count
    adapted = adapted.replace('// as that is what the test vectors are written for.', '// with independently regenerated PoCX outputs (test/pocx/adapt_bip324_vectors.py).')
    dest = ROOT / 'src/pocx/test/adapted/bip324_tests.cpp'
    dest.write_text(adapted)
    deps = [source, Path(__file__), ROOT / 'test/pocx/pocx_bootstrap.py', *sorted((ROOT / 'test/functional/test_framework/crypto').glob('*.py')), ROOT / 'test/functional/test_framework/v2_p2p.py']
    provenance = {'vectors': count, 'bitcoin_magic': 'f9beb4d9', 'pocx_magic': 'a73c915e', 'original_outputs_verified': True, 'sha256': {str(p.relative_to(ROOT)): hashlib.sha256(p.read_bytes()).hexdigest() for p in deps}}
    (ROOT / 'test/pocx/bip324-vector-provenance.json').write_text(json.dumps(provenance, indent=2) + '\n')


if __name__ == '__main__':
    main()
