#!/usr/bin/env python3
"""Preserve BIP158 transaction/script inputs and independently rekey for PoCX headers."""
import hashlib
from io import BytesIO
import json
from pathlib import Path
import struct
import sys
import pocx_bootstrap as pocx_bootstrap
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'test/functional'))
from test_framework.messages import CBlock, hash256, ser_compact_size
from test_framework.blockfilter import bip158_basic_element_hash

ROOT = Path(__file__).resolve().parents[2]


def encode_filter(elements, block_hash):
    values = sorted(bip158_basic_element_hash(s, len(elements), block_hash) for s in elements)
    bits = []
    previous = 0
    for value in values:
        delta = value - previous
        previous = value
        quotient, remainder = divmod(delta, 1 << 19)
        bits.extend([1] * quotient + [0])
        bits.extend((remainder >> bit) & 1 for bit in range(18, -1, -1))
    bits.extend([0] * (-len(bits) % 8))
    return ser_compact_size(len(elements)) + bytes(sum(bits[i + j] << (7 - j) for j in range(8)) for i in range(0, len(bits), 8))


def main():
    source = ROOT / 'src/test/data/blockfilters.json'
    rows = json.loads(source.read_text())
    count = 0
    for row in rows:
        if len(row) == 1:
            continue
        raw = bytes.fromhex(row[2])
        stream = BytesIO(raw)
        block = CBlock()
        block.deserialize(stream)
        assert not stream.read(), 'Trailing Bitcoin fixture bytes'
        assert hash256(raw[:80])[::-1].hex() == row[1]
        elements = {bytes(out.scriptPubKey) for tx in block.vtx for out in tx.vout if out.scriptPubKey and out.scriptPubKey[0] != 0x6a}
        elements |= {bytes.fromhex(s) for s in row[3] if s}
        original_filter = encode_filter(elements, row[1])
        previous_header = bytes.fromhex(row[4])[::-1]
        assert original_filter.hex() == row[5], f'Original filter mismatch at height {row[0]}'
        assert hash256(hash256(original_filter) + previous_header)[::-1].hex() == row[6]
        # Fixed header-only fixture: same version, prevhash, merkle root and time;
        # explicit height/base target, zero proof/key/signature. Not a valid proof.
        header = raw[:72] + struct.pack('<i', row[0]) + bytes(32) + struct.pack('<Q', 1) + bytes(72 + 33 + 65)
        assert len(header) == 286
        row[1] = hash256(header)[::-1].hex()
        row[2] = (header + raw[80:]).hex()
        encoded = encode_filter(elements, row[1])
        row[5] = encoded.hex()
        row[6] = hash256(hash256(encoded) + previous_header)[::-1].hex()
        count += 1
    assert count > 0
    (ROOT / 'src/pocx/test/data/blockfilters.json').write_text(json.dumps(rows, indent=2) + '\n')
    deps = [source, Path(__file__), ROOT / 'test/pocx/pocx_bootstrap.py', ROOT / 'test/functional/test_framework/messages.py', ROOT / 'test/functional/test_framework/blockfilter.py', ROOT / 'test/functional/test_framework/crypto/siphash.py']
    provenance = {'vectors': count, 'original_hash_filter_header_verified': True, 'sha256': {str(p.relative_to(ROOT)): hashlib.sha256(p.read_bytes()).hexdigest() for p in deps}}
    (ROOT / 'test/pocx/blockfilter-vector-provenance.json').write_text(json.dumps(provenance, indent=2) + '\n')
    print(f'Verified and converted {count} blockfilter vectors')


if __name__ == '__main__':
    main()
