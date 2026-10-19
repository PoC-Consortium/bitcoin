#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin PoCX developers
# Distributed under the MIT software license; see COPYING.
"""Reproduce native serialization and transport seeds without starting nodes.

The accepted block is frozen from a verified functional run. Other structures
are parser/merkle fixtures, not claims of consensus-valid blocks or real proofs.
FuzzedDataProvider escapes backslashes in strings and consumes integers from
the end of its input. Controls below follow the unchanged upstream call order.
"""
import hashlib
import argparse
import json
import random
import struct
from pathlib import Path

SOURCE = Path(__file__).resolve().parent
OWNED = SOURCE


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def hash256(data):
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()


def fdp_string(data):
    return data.replace(b'\\', b'\\\\') + b'\\\x00'


def varint(value):
    result = bytearray([value & 127])
    while value > 127:
        value = (value >> 7) - 1
        result.insert(0, (value & 127) | 128)
    return bytes(result)


def main():
    fixture = SOURCE / 'fixtures/native-regtest-block.json'
    metadata = json.loads(fixture.read_text())
    raw = bytes.fromhex(metadata['block_hex'])
    assert sha256(raw) == metadata['block_sha256']
    header = raw[:286]
    assert hash256(header[:221] + bytes(65))[::-1].hex() == metadata['expected_block_hash']
    block_hash = bytes.fromhex(metadata['expected_block_hash'])[::-1]
    seeds = {}

    def save(target, name, data):
        path = OWNED / 'corpus' / target / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        seeds[str(path.relative_to(OWNED))] = {'bytes': len(data), 'sha256': sha256(data)}

    for target in ['block', 'block_deserialize', 'blockmerkleroot']:
        save(target, 'accepted-native-witness-block', raw)
    for target in ['block_header', 'blockheader_deserialize']:
        save(target, 'accepted-native-header', header)
    damaged = bytearray(raw)
    damaged[36] ^= 1
    save('block', 'wrong-merkle-root', damaged)

    # One, two, and duplicate-leaf trees. Only the frozen block above is an
    # accepted block: these bodies deliberately vary independently of signatures.
    tx = struct.pack('<i', 2) + b'\x01' + bytes(32) + bytes.fromhex('ffffffff')
    tx += b'\x04\x02\xce\x00\x00' + bytes.fromhex('feffffff')
    tx += b'\x01' + struct.pack('<q', 1_000_000_000) + b'\x01\x51' + bytes(4)
    tx2 = tx[:-4] + struct.pack('<I', 1)
    for name, txs in [('empty', []), ('one', [tx]), ('two', [tx, tx2]), ('duplicate', [tx, tx])]:
        block = header + bytes([len(txs)]) + b''.join(txs)
        # ConsumeBool(with_witness), then string, then merkle controls.
        save('merkle', name, fdp_string(block) + bytes(16) + b'\x00')
    save('merkle', 'accepted-witness', fdp_string(raw) + bytes(16) + b'\x01')
    save('tx_in_deserialize', 'coinbase-input', tx[5:50])
    save('prefilled_transaction_deserialize', 'coinbase', b'\x00' + tx)
    save('block_header_and_short_txids_deserialize', 'native-prefilled', header + bytes(8) + b'\x00\x01\x00' + tx)
    save('blocktransactions_deserialize', 'coinbase', block_hash + b'\x01' + tx)
    save('blocktransactionsrequest_deserialize', 'request-index-zero', block_hash + b'\x01\x00')
    save('merkle_block_deserialize', 'one-leaf', header + struct.pack('<I', 1) + b'\x01' + hash256(tx) + b'\x01\x01')
    save('partial_merkle_tree_deserialize', 'one-leaf', struct.pack('<I', 1) + b'\x01' + hash256(tx) + b'\x01\x01')

    # Disk index has VARINT metadata, no wire height, and adds nNextBaseTarget.
    for status in [3, 3 | 8 | 16]:
        prefix = varint(259900) + varint(metadata['height']) + varint(status) + varint(1)
        if status & 24:
            prefix += varint(2) + varint(100) + varint(200)
        disk = prefix + header[:72] + header[76:116] + header[108:116] + header[116:]
        save('diskblockindex_deserialize', f'native-status-{status}', disk)
        # Loop controls exercise multiple RaiseValidity choices before stopping.
        save('chain', f'native-status-{status}', fdp_string(disk) + bytes([0, 5, 1, 4, 1, 2, 1]))

    empty_filter = b'\x00' + block_hash + b'\x01\x00'
    save('block_filter_deserialize', 'empty-basic', empty_filter)
    save('blockfilter', 'empty-basic', fdp_string(empty_filter) + bytes(32) + fdp_string(b'element'))
    # A one-element GCS stream with quotient/remainder zero is a valid encoding.
    one_filter = b'\x00' + block_hash + b'\x04\x01\x00\x00\x00'
    save('block_filter_deserialize', 'one-basic', one_filter)
    save('blockfilter', 'one-basic', fdp_string(one_filter) + bytes(32) + fdp_string(b'element'))

    primitives = {
        'block_file_info_deserialize': bytes(7),
        'fee_rate_deserialize': struct.pack('<q', 1000),
        'out_point_deserialize': block_hash + struct.pack('<I', 7),
        'pub_key_deserialize': b'\x21' + header[188:221],
        'script_deserialize': b'\x01\x51',
        'flat_file_pos_deserialize': varint(2) + varint(100),
        'key_origin_info_deserialize': b'ABCD\x02' + struct.pack('<II', 7, 0x80000001),
        'psbt_input_deserialize': b'\x00', 'psbt_output_deserialize': b'\x00',
        'blocklocator_deserialize': struct.pack('<i', 70016) + b'\x01' + block_hash,
        'txundo_deserialize': b'\x00', 'blockundo_deserialize': b'\x00',
        'coins_deserialize': b'\x00\x00\x07\x51',
        'txoutcompressor_deserialize': b'\x00\x07\x51',
        'inv_deserialize': struct.pack('<I', 2) + block_hash,
        'bloomfilter_deserialize': b'\x01\x00' + struct.pack('<II', 1, 0) + b'\x00',
        'uint160_deserialize': bytes(range(20)), 'uint256_deserialize': bytes(range(32)),
    }
    # An unsigned non-witness transaction plus one empty input/output map.
    unsigned_tx = tx[:5] + tx[5:41] + b'\x00' + tx[46:]
    primitives['partially_signed_transaction_deserialize'] = b'psbt\xff\x01\x00' + bytes([len(unsigned_tx)]) + unsigned_tx + b'\x00\x00\x00'
    # MakeNoLogFileContext defaults to regtest; preserve a wrong-network input
    # as well as the positive seed. Both magics come from native chainparams.
    snapshot = b'utxo\xff\x02\x00' + bytes.fromhex('fabfb5da') + block_hash + struct.pack('<Q', 1)
    primitives['snapshotmetadata_deserialize'] = snapshot
    save('snapshotmetadata_deserialize', 'wrong-network-mainnet', snapshot[:7] + bytes.fromhex('a73c915e') + snapshot[11:])
    for target, data in primitives.items():
        save(target, 'structured', data)

    # Address V1/V2 and network/disk variants use controls at the input end.
    addr_v1 = bytes(10) + b'\xff\xff' + bytes([127, 0, 0, 1])
    addr_v2 = b'\x01\x04' + bytes([127, 0, 0, 1])
    for enc, address in [(0, addr_v1), (1, addr_v2)]:
        save('netaddr_deserialize', f'v{enc+1}-ipv4', fdp_string(address) + bytes([enc]))
        save('service_deserialize', f'v{enc+1}-ipv4', fdp_string(address + b'\x20\x8d') + bytes([enc]))
    for enc, address in [(0, addr_v1), (1, addr_v2)]:
        for disk in [True, False]:
            # V2 encodes services with CompactSize, V1 with uint64.
            services = b'\x01' if enc else struct.pack('<Q', 1)
            serialized = struct.pack('<I', 1_700_000_000) + services + address + b'\x20\x8d'
            if disk:
                serialized = struct.pack('<I', 220000 | (1 << 29 if enc else 0)) + serialized
            controls = bytes([0 if disk else 1, enc])
            save('address_deserialize', f'v{enc+1}-' + ('disk' if disk else 'network'), fdp_string(serialized) + controls)
            source = address
            save('addr_info_deserialize', f'v{enc+1}-' + ('disk' if disk else 'network'), fdp_string(serialized + source + bytes(12)) + controls)

    key1, key2 = bytes(31) + b'\x01', bytes(31) + b'\x02'
    for compressed in [0, 1]:
        save('message', f'valid-key-{compressed}', fdp_string(b'PoCX signed message') + key1 + fdp_string(b'bad-address') + fdp_string(b'bad-signature') + bytes([compressed]))
    for mode in [0, 1, 2, 3, 4, 6, 0xFA, 0xFE]:
        # Eight-byte RNG seed is consumed before mode; remaining controls drive
        # lengths and corruption location. 0xFA exercises nonempty AAD/content.
        controls = bytes(range(16)) + bytes([mode]) + bytes(8)
        save('bip324_cipher_roundtrip', f'mode-{mode:02x}', key1 + bytes(32) + key2 + bytes([1])*32 + controls)

    for target, prefix in [('p2p_transport_bidirectional', b''),
                           ('p2p_transport_bidirectional_v2', key1 + bytes(32) + key2 + bytes(32)),
                           ('p2p_transport_bidirectional_v1v2', key1 + bytes(32))]:
        rng = random.Random(324)
        for index in range(6):
            operations = rng.randbytes(300)
            # Consume RNG seed, key compression and garbage lengths from end.
            setup = (b'\x00\x00\x01' * (2 if target.endswith('_v2') else 1)) if prefix else b''
            save(target, f'simulation-{index}', prefix + operations + setup + bytes(8))

    payload = struct.pack('<Q', 12345)
    command = b'ping' + bytes(8)
    size = struct.pack('<I', len(payload))
    checksum = hash256(payload)[:4]
    native_magic = bytes.fromhex('fabfb5da')
    save('messageheader_deserialize', 'native-ping', native_magic + command + size + checksum)
    save('p2p_transport_serialization', 'assisted-valid-ping', command + size + payload + b'\x01\x01')
    save('p2p_transport_serialization', 'unassisted-valid-ping', native_magic + command + size + checksum + payload + bytes(2))
    save('p2p_transport_serialization', 'wrong-checksum', native_magic + command + size + bytes(4) + payload + bytes(2))
    save('p2p_transport_serialization', 'wrong-magic', bytes(4) + command + size + checksum + payload + bytes(2))
    save('p2p_transport_serialization', 'oversized', native_magic + command + struct.pack('<I', 0xffffffff) + bytes(4) + bytes(2))

    manifest = {'scope': 'Reproducible structured parser, merkle, signing and transport seeds; original target assertions retained',
                'generator_sha256': sha256(Path(__file__).read_bytes()), 'native_fixture': metadata, 'seeds': seeds}
    (OWNED / 'corpus-provenance.json').write_text(json.dumps(manifest, indent=2) + '\n')
    print(f'Generated {len(seeds)} structured seeds')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    OWNED = args.output.resolve()
    OWNED.mkdir(parents=True, exist_ok=True)
    main()
