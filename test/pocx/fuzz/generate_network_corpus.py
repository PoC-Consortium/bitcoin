#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin PoCX developers
# Distributed under the MIT software license; see COPYING.
"""Reproduce upstream networking fuzz seeds without real sockets or nodes.

Whole upstream targets remain unchanged. Controls follow their front-byte and
end-integer reads. Saved long state sequences are intentionally not truncated.
These fixtures exercise networking state, not native capacity-proof acceptance.
"""
import ipaddress
import argparse
import json
import random
import struct
from pathlib import Path

from generate_corpus import SOURCE, OWNED, fdp_string, hash256, sha256
from generate_index_corpus import Controls

NOW = 1_800_000_000
U32 = (1 << 32) - 1
U64 = (1 << 64) - 1
I64_MIN = -(1 << 63)
I64_MAX = (1 << 63) - 1
TARGETS = ['data_stream_addr_man', 'addrman', 'addrman_serdeser', 'banman',
           'connman', 'net', 'local_address', 'netaddress', 'net_permissions',
           'protocol', 'bloom_filter', 'rolling_bloom_filter', 'node_eviction',
           'asmap', 'asmap_direct', 'p2p_handshake']
SOURCES = ['addrman', 'banman', 'connman', 'net', 'netaddress', 'net_permissions',
           'protocol', 'bloom_filter', 'rolling_bloom_filter', 'node_eviction',
           'asmap', 'asmap_direct', 'p2p_handshake']


class Input:
    def __init__(self):
        self.front = bytearray()
        self.controls = Controls()

    def integer(self, value, minimum=0, maximum=U64):
        self.controls.integral(value, minimum, maximum)

    def boolean(self, value):
        self.controls.boolean(value)

    def time(self, value=NOW):
        self.integer(value, 946684801, 4133980799)

    def raw(self, data):
        self.front.extend(data)

    def string(self, data=b''):
        self.raw(fdp_string(data))

    def addr(self, network=0, data=b'\x08\x08\x08\x08'):
        self.integer(network, 0, 5)
        sizes = [4, 16, 32, 32, 16, 32]
        assert len(data) == sizes[network]
        self.raw(data)

    def service(self, network=0, data=b'\x08\x08\x08\x08', port=18333):
        self.addr(network, data)
        self.integer(port, 0, 65535)

    def weak(self, index, maximum):
        self.boolean(True)
        self.integer(index, 0, maximum)

    def address(self):
        self.service()
        self.weak(1, 6)  # NODE_NETWORK
        self.integer(NOW, 0, U32)

    def node(self, connection=0):
        # value_or evaluates ConsumeIntegral even when the caller supplies id.
        self.integer(0, 0, I64_MAX)
        self.integer(-1, -2, -1)  # INVALID_SOCKET; FuzzedSock owns no real fd
        self.boolean(True)  # selectable
        self.address()
        self.integer(0)  # keyed network group
        self.integer(2)  # local nonce differs from version message nonce1
        self.address()
        self.string()
        self.integer(connection, 0, 6)
        if connection == 0:
            self.boolean(False)  # not inbound onion
        self.integer(0)  # network id
        self.weak(0, 9)  # no permissions

    def operation(self, op, maximum):
        self.boolean(True)
        self.integer(op, 0, maximum)

    def finish(self):
        return bytes(self.front) + self.controls.encode()


def encode_number(value, minimum, sizes):
    bits = []
    for index, width in enumerate(sizes):
        if value - minimum < 1 << width:
            if index + 1 < len(sizes):
                bits.append(0)
            bits.extend((value - minimum >> bit) & 1 for bit in reversed(range(width)))
            return bits
        assert index + 1 < len(sizes)
        bits.append(1)
        minimum += 1 << width
    raise AssertionError('unencodable asmap number')


def asn(value):
    return encode_number(value, 1, range(15, 25))


def bit_bytes(bits):
    return bytes(sum(bit << j for j, bit in enumerate(bits[i:i+8]))
                 for i in range(0, len(bits), 8))


def main():
    seeds = {}

    def save(target, name, data):
        path = OWNED / 'corpus' / target / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        seeds[str(path.relative_to(OWNED))] = {'bytes': len(data), 'sha256': sha256(data)}

    addresses = {
        'ipv4-public': (0, ipaddress.ip_address('8.8.8.8').packed),
        'ipv4-private': (0, ipaddress.ip_address('10.1.2.3').packed),
        'ipv4-rfc2544': (0, ipaddress.ip_address('198.18.0.1').packed),
        'ipv4-cgnat': (0, ipaddress.ip_address('100.64.0.1').packed),
        'ipv4-testnet': (0, ipaddress.ip_address('192.0.2.1').packed),
        'ipv4-linklocal': (0, ipaddress.ip_address('169.254.1.1').packed),
        'ipv6-public': (1, ipaddress.ip_address('2001:4860:4860::8888').packed),
        'ipv6-documentation': (1, ipaddress.ip_address('2001:db8::1').packed),
        'ipv6-unique-local': (1, ipaddress.ip_address('fd00::1').packed),
        'ipv6-teredo': (1, ipaddress.ip_address('2001:0:1:2:3:4:5:6').packed),
        'tor-v3': (2, sha256(b'tor-network-seed').encode()[:32]),
        'i2p': (3, sha256(b'i2p-network-seed').encode()[:32]),
        'cjdns': (4, bytes.fromhex('fc000000000000000000000000000001')),
        'internal': (5, b'pocx-independent-internal-address'[:32]),
    }
    for name, (network, address) in addresses.items():
        seed = Input()
        seed.addr(network, address)
        seed.integer(24 if network == 0 else 64, 0, 255)
        seed.integer(18333, 0, 65535)
        seed.addr(network, address)
        seed.boolean(True)
        seed.integer(18333, 0, 65535)
        save('netaddress', name + '-same-service', seed.finish())

    for index, text in enumerate([
        'noban,relay@127.0.0.1:18333', 'all@[::1]:18333', '127.0.0.1:18333',
        'relay@8.8.8.8/32', 'in,out,download@2001:4860::/32', '10.0.0.0/8',
        'invalid@127.0.0.1:18333', 'out@127.0.0.1:18333', 'noban@bad-address',
    ]):
        seed = Input()
        seed.string(text.encode())
        seed.weak(4, 9)
        save('net_permissions', f'permission-{index}', seed.finish())

    tx = (struct.pack('<i', 2) + b'\x01' + bytes(32) + b'\xff'*4
          + b'\x02\x01\x01' + b'\xff'*4 + b'\x01'
          + struct.pack('<q', 1_000_000_000) + b'\x01\x51' + bytes(4))
    for index, kind in enumerate([1, 2, 3, 4, 5, 0x40000001, 0xffffffff]):
        first = struct.pack('<I', kind) + bytes([index])*32
        second = struct.pack('<I', 2) + bytes([index+1])*32
        save('protocol', f'inventory-{kind}', fdp_string(first) + fdp_string(second))

    for op, payload in enumerate([b'bloom-network-key', bytes(32) + struct.pack('<I', 1), bytes(range(32)), tx]):
        seed = Input()
        seed.integer(128, 1, 10_000_000)
        seed.integer(1000, 1, U32)
        seed.integer(42, 0, U32)
        seed.integer(1, 0, 3)
        seed.integer(op, 0, 3)
        seed.string(payload)
        save('bloom_filter', f'insert-type-{op}', seed.finish())
    seed = Input()
    seed.integer(128, 1, 1000)
    seed.integer(1000, 1, U32)
    seed.integer(0, 0, 2)
    seed.string(b'rolling-network-key')
    seed.integer(1, 0, 2)
    seed.raw(bytes(range(32)))
    seed.integer(2, 0, 2)
    save('rolling_bloom_filter', 'insert-bytes-hash-reset', seed.finish())

    for count in [1, 48, 96]:
        seed = Input()
        for index in range(count):
            seed.boolean(True)
            for value in [index, NOW-index, index*1000, NOW-index*20, NOW-index*10]:
                seed.integer(value, I64_MIN, I64_MAX)
            for value in [True, True, False]:
                seed.boolean(value)
            seed.integer(index % 8)
            seed.boolean(index % 9 == 0)
            seed.boolean(False)
            seed.integer(1, 0, 6)  # IPv4
            seed.boolean(False)  # no noban protection
            seed.integer(0, 0, 6)  # inbound, eligible for eviction
        seed.boolean(False)
        save('node_eviction', f'{count}-inbound-candidates', seed.finish())

    programs = {
        'return': [0] + asn(64512),
        'jump': [1, 0] + encode_number(1 + len(asn(64512)), 17, range(5, 31))
                + [0] + asn(64512) + [0] + asn(64513),
        'default-match': [1, 1, 1] + asn(64512) + [1, 1, 0]
                         + encode_number(256, 2, range(1, 9)) + [0] + asn(64513),
    }
    for name, bits in programs.items():
        packed = bit_bytes(bits)
        assert 3 <= len(packed) <= 130
        for high in [False, True]:
            address = bytes([128 if high else 0]) + bytes(15)
            # Direct format stores one bit per byte, with exactly one separator.
            address_bits = bytes((byte >> bit) & 1 for byte in address for bit in reversed(range(8)))
            save('asmap_direct', f'{name}-{int(high)}', bytes(bits) + b'\xff' + address_bits)
            save('asmap', f'{name}-ipv6-{int(high)}', bytes([128 + len(packed)-3]) + packed + address)
            save('asmap', f'{name}-ipv4-{int(high)}', bytes([len(packed)-3]) + packed + address[:4])

    # AddrMan v4 with zero entries, 1024 empty new buckets and null AS-map hash.
    empty_addrman = b'\x04\x24' + bytes(32) + struct.pack('<iii', 0, 0, 1024 ^ (1 << 30)) + bytes(1024*4 + 32)
    save('data_stream_addr_man', 'valid-empty-regtest-db', fdp_string(b'\xfa\xbf\xb5\xda' + empty_addrman) + fdp_string(b''))
    for tried in range(4):
        seed = Input()
        seed.time()
        seed.string()  # no AS-map
        seed.raw(bytes(range(32)) + bytes(reversed(range(32))))
        seed.integer(tried, 0, 3)
        seed.integer(3, 1, 50)
        seed.raw(bytes([tried+1])*32)  # FillAddrman RNG seed
        save('addrman_serdeser', f'tried-fraction-{tried}', seed.finish())
    seed = Input()
    seed.time()
    seed.string()
    seed.raw(bytes(range(32)))
    seed.boolean(False)  # no initial deserialization
    seed.operation(2, 6)
    seed.boolean(True)
    seed.address()
    seed.boolean(False)
    seed.addr()
    seed.integer(0, 0, 100_000_000)
    for op in [3, 4, 5, 6, 0, 1]:
        seed.operation(op, 6)
        if op in [3, 4, 5, 6]:
            seed.service()
            if op == 4:
                seed.boolean(True)
            if op == 6:
                seed.weak(3, 6)
            else:
                seed.time()
    seed.boolean(False)
    seed.boolean(False)  # no network filter
    seed.integer(4096, 0, 4096)
    seed.integer(100, 0, 100)
    seed.boolean(False)  # unfiltered
    for _ in range(7):
        seed.boolean(True)
    seed.boolean(False)  # tried/new selection
    seed.boolean(False)  # size without new filter
    save('addrman', 'add-good-attempt-connected-services-select', seed.finish())
    seed = Input()
    seed.time()
    seed.string()
    seed.raw(bytes(range(32)))
    seed.boolean(True)
    seed.string(empty_addrman)
    seed.boolean(False)
    save('addrman', 'deserialize-valid-empty', seed.finish())

    for corrupt in [False, True]:
        seed = Input()
        seed.time()
        seed.boolean(corrupt)
        if corrupt:
            seed.string(b'{"invalid":')
        else:
            seed.boolean(False)  # accessible banlist
        seed.integer(86400, I64_MIN, (1 << 31)-1)
        for op in [0, 3, 7, 8, 9, 10, 5, 2]:
            seed.operation(op, 10)
            if op in [0, 3, 9, 10, 5]:
                seed.addr()
            if op == 0:
                seed.integer(86400, I64_MIN, (1 << 31)-1)
                seed.boolean(False)  # relative expiry
        seed.boolean(False)
        seed.time()
        save('banman', f'ban-persist-unban-corrupt-{int(corrupt)}', seed.finish())

    for target in ['net', 'local_address']:
        seed = Input()
        seed.time()
        if target == 'local_address':
            seed.service()
        seed.node()
        if target == 'net':
            seed.integer(70016, -(1 << 31), (1 << 31)-1)
            seed.integer(0, 0, 1)  # V1 address encoding
            seed.string(bytes(10) + b'\xff\xff\x08\x08\x08\x08' + struct.pack('>H', 18333))
            for op in [2, 1, 3, 4, 0]:
                seed.operation(op, 4)
                if op == 4:
                    body = struct.pack('<Q', 1234)
                    packet = bytes.fromhex('a73c915e') + b'ping'.ljust(12, b'\0') + struct.pack('<I', len(body)) + hash256(body)[:4] + body
                    seed.string(packet)
        else:
            for op in [1, 3, 4, 5, 2]:
                seed.operation(op, 5)
                if op == 1:
                    seed.integer(2, 0, 4)  # LOCAL_BIND, LOCAL_MAX=5
        seed.boolean(False)
        save(target, 'valid-service-state-operations', seed.finish())

    # Connman calls into FuzzedSock/FuzzedNetEvents. Randomized callback draws
    # are covered by raw seeds too; no operating-system socket is requested.
    def connman_input():
        seed = Input()
        seed.time()
        seed.string()
        seed.raw(bytes(range(32)))
        seed.boolean(False)
        seed.integer(0)
        seed.integer(0)
        seed.boolean(True)
        seed.integer(1024)
        seed.node()
        seed.boolean(False)  # no added test nodes
        return seed

    for op in range(25):
        seed = connman_input()
        seed.operation(op, 24)
        seed.raw(bytes(256))  # callback payload/default controls
        save('connman', f'operation-{op:02d}', seed.finish())
    seed = connman_input()
    seed.operation(3, 24)
    seed.string(b'fuzz-peer.invalid:18333')
    seed.operation(21, 24)
    seed.integer(1, 0, 6)  # full outbound relay
    seed.boolean(False)  # no proxy override
    for _ in range(4):  # three false arguments, then uninterrupted connection
        seed.boolean(False)
    seed.addr()  # mocked DNS lookup returns a routable IPv4 address
    seed.raw(bytes(512))  # mocked socket callbacks finish when input exhausts
    save('connman', 'mock-dns-outbound-connection', seed.finish())

    # Native version body uses unchanged Bitcoin P2P handshake serialization.
    addr = bytes(26)
    version = (struct.pack('<iQq', 70016, 9, NOW) + addr + addr
               + struct.pack('<Q', 1) + b'\x00' + struct.pack('<i', 0) + b'\x01')
    for connection in [0, 1, 4]:
        for name, messages in [
            ('version-verack', [(0, version), (1, b'')]),
            ('version-wtxid-verack', [(0, version), (33, b''), (1, b'')]),
            ('verack-before-version', [(1, b'')]),
            ('duplicate-version', [(0, version), (0, version)]),
        ]:
            seed = Input()
            seed.integer(1, 1, 3)
            seed.node(connection)
            seed.integer(9)  # local NODE_NETWORK | NODE_WITNESS
            for message, body in messages:
                seed.boolean(True)
                seed.integer(0, 0, 0)  # one peer needs no consumed index byte
                seed.integer(0, -600, 1200)
                seed.integer(message, 0, 34)
                seed.string(body)
            seed.boolean(False)
            save('p2p_handshake', f'{name}-connection-{connection}', seed.finish())

    rng = random.Random(31800)
    for target in TARGETS:
        for index in range(4):
            save(target, f'network-operations-{index}', rng.randbytes(512))

    root = SOURCE.parents[2]
    manifest = {'scope': __doc__, 'generator_sha256': sha256(Path(__file__).read_bytes()),
                'sources': {f'src/test/fuzz/{name}.cpp': sha256((root/f'src/test/fuzz/{name}.cpp').read_bytes()) for name in SOURCES},
                'dependencies': {name: sha256((SOURCE/name).read_bytes()) for name in ['generate_corpus.py', 'generate_index_corpus.py']},
                'seeds': seeds}
    (OWNED/'network-corpus-provenance.json').write_text(json.dumps(manifest, indent=2)+'\n')
    print(f'Generated {len(seeds)} networking seeds')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    OWNED = args.output.resolve()
    OWNED.mkdir(parents=True, exist_ok=True)
    main()
