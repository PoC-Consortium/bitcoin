#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin PoCX developers
# Distributed under the MIT software license; see COPYING.
"""Reproduce metadata, mocked tree, and native headers-sync fuzz sequences.

These targets preserve upstream metadata/state-machine checks. Derived tree and
sync headers do not claim valid capacity proofs or full consensus acceptance.
"""
import argparse
import json
import random
import struct
from pathlib import Path

from generate_corpus import SOURCE, OWNED, fdp_string, hash256, sha256, varint


class Controls:
    """Serialize the order of integers read from FuzzedDataProvider's end."""
    def __init__(self):
        self.reads = bytearray()

    def integral(self, value, minimum, maximum):
        assert minimum <= value <= maximum
        width = ((maximum - minimum).bit_length() + 7) // 8
        self.reads.extend((value - minimum).to_bytes(width, 'big'))

    def boolean(self, value):
        self.integral(int(value), 0, 255)

    def encode(self):
        return bytes(reversed(self.reads))


def tree(operations):
    controls = Controls()
    controls.integral(1_800_000_000, 946684801, 4133980799)
    block_count = 1
    heights = [0]
    chain_height = 0
    pruned_count = 0
    for op in operations:
        controls.boolean(True)
        kind, *args = op
        controls.integral({'header': 0, 'block': 1, 'activate': 2, 'prune': 3, 'download': 4}[kind], 0, 4)
        if kind == 'header':
            parent = args[0]
            controls.integral(parent, 0, block_count - 1)
            controls.integral(0x20000000, -(1 << 31), (1 << 31) - 1)
            controls.integral(1_800_000_000, 0, (1 << 32) - 1)
            block_count += 1
            heights.append(heights[parent] + 1)
        elif kind == 'block':
            index, invalid = args
            controls.integral(index, 0, block_count - 1)
            controls.boolean(invalid)
            if not invalid:
                controls.integral(1, 1, 1000)
                controls.integral(1, 1, 1000)
        elif kind == 'activate':
            # Explicit per-connect controls, and the expected resulting height,
            # follow the unchanged simplified activation loop's draw order.
            connection_controls, chain_height = args
            for value in connection_controls:
                controls.boolean(value)
        elif kind == 'prune':
            controls.integral(args[0], 0, chain_height)
            pruned_count += 1
        elif kind == 'download':
            controls.integral(args[0], 0, pruned_count - 1)
            controls.integral(1, 1, 1000)
            pruned_count -= 1
    controls.boolean(False)
    return controls.encode()


def main():
    seeds = {}

    def save(target, name, data):
        path = OWNED / 'corpus' / target / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        seeds[str(path.relative_to(OWNED))] = {'bytes': len(data), 'sha256': sha256(data)}

    # Consume block-file information from the front; read counts and header
    # integers from the end. The fixed DB key matches the upstream fixture.
    for files in [1, 2, 4]:
        blocks = files * 10
        info = [b''.join(varint(v) for v in [1, 100+i, 20, i, i+1, 1000, 1001]) for i in range(files)]
        front = b''.join(fdp_string(data) for data in info) + fdp_string(b'pocx-fuzz-flag')
        controls = Controls()
        controls.integral(files, 1, 100)
        controls.integral(blocks, files * 10, files * 100)
        for index in range(blocks):
            controls.integral(0x20000000, -(1 << 31), (1 << 31)-1)
            controls.integral(1_800_000_000 + index, 0, (1 << 32)-1)
            controls.integral(index, 0, (1 << 32)-1)
        save('block_index', f'{files}-files-{blocks}-headers', front + controls.encode())

    base = [('header', 0), ('header', 1), ('block', 1, False), ('block', 2, False),
            ('activate', [False, False, False, False], 2)]
    scenarios = {
        'connect-two': base,
        'prune-and-download': base + [('prune', 1), ('download', 0)],
        'invalid-body': [('header', 0), ('block', 1, True), ('activate', [], 0)],
        'invalid-during-connect': [('header', 0), ('block', 1, False), ('activate', [True], 0)],
        'pruned-reorg-abort': base + [('prune', 1), ('header', 0), ('header', 3), ('header', 4),
                                    ('block', 3, False), ('block', 4, False), ('block', 5, False),
                                    ('activate', [], 2)],
        'valid-fork': base + [('header', 0), ('header', 3), ('header', 4),
                              ('block', 3, False), ('block', 4, False), ('block', 5, False),
                              ('activate', [False]*6, 3)],
    }
    for name, operations in scenarios.items():
        save('block_index_tree', name, tree(operations))
    rng = random.Random(31512)
    for index in range(8):
        save('block_index_tree', f'operations-{index}', rng.randbytes(256))

    context_path = SOURCE / 'fixtures/mainnet-header-context.json'
    context = json.loads(context_path.read_text())
    genesis = bytes.fromhex(context['genesis_header'])
    first = bytes.fromhex(context['first_header'])
    assert len(genesis) == len(first) == 286
    assert first[4:36] == hash256(genesis[:221] + bytes(65))
    assert first[76:108] == hash256(genesis[76:108] + genesis[148:168])
    target = int.from_bytes(genesis[108:116], 'little')
    assert target == (1 << 42) // 120
    headers = [first]
    for height in [2, 3]:
        previous = headers[-1]
        header = bytearray(previous)
        header[4:36] = hash256(previous[:221] + bytes(65))
        header[68:72] = struct.pack('<I', int.from_bytes(previous[68:72], 'little') + 120)
        header[72:76] = struct.pack('<I', height)
        header[76:108] = hash256(previous[76:108] + previous[148:168])
        header[172:180] = struct.pack('<Q', height)
        header[180:188] = bytes(8)  # claimed quality zero gives zero deadline
        header[221:286] = bytes(65)
        headers.append(bytes(header))
    work = (1 << 64) // target

    def sync(name, batch, threshold, continuous=True, replay=False, full=False):
        controls = Controls()
        # ConsumeTime's minimum is the mainnet genesis timestamp here.
        controls.integral(1_800_000_000, int.from_bytes(genesis[68:72], 'little'), 4133980799)
        controls.integral(1, 1, 1282)  # twice mainnet commitment period641
        controls.integral(0, 0, 30436)  # twice redownload buffer15218
        controls.boolean(continuous)
        controls.boolean(full)
        if replay:
            controls.boolean(False)  # replay stored headers
            controls.integral(len(batch), 1, len(batch))
            controls.boolean(False)
        front = threshold.to_bytes(32, 'little') + fdp_string(bytes([len(batch)]) + b''.join(batch))
        save('headers_sync_state', name, front + controls.encode())

    sync('presync-to-redownload', headers, work*3, replay=True)
    sync('presync-incomplete', headers, 1 << 255, full=False)
    sync('presync-request-more', headers, 1 << 255, full=True)
    sync('single-real-header', [first], work, replay=True)
    for name, offset in [('wrong-parent', 4), ('wrong-target', 108), ('wrong-gensig', 76), ('wrong-time', 68)]:
        bad = bytearray(first)
        if name == 'wrong-time':
            bad[68:72] = genesis[68:72]
        else:
            bad[offset] ^= 1
        sync(name, [bytes(bad)], work, continuous=name != 'wrong-parent')
    save('pocx_headers_sync_configuration', 'zero-period', b'\x00')
    manifest = {'scope': 'Metadata and mocked block-tree sequences; native claimed-work presync/redownload, not full proof validation',
                'generator_sha256': sha256(Path(__file__).read_bytes()),
                'native_context_sha256': sha256(context_path.read_bytes()),
                'guided_tree_operations': scenarios, 'seeds': seeds}
    (OWNED / 'index-corpus-provenance.json').write_text(json.dumps(manifest, indent=2) + '\n')
    print(f'Generated {len(seeds)} index/sync seeds')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    OWNED = args.output.resolve()
    OWNED.mkdir(parents=True, exist_ok=True)
    main()
