#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin PoCX developers
# Distributed under the MIT software license; see COPYING.
"""Render kernel fixture bytes with independent header hashes and field expectations."""
from hashlib import sha256
import json
from pathlib import Path
import struct
import sys


def hash256(data):
    return sha256(sha256(data).digest()).digest()[::-1].hex()


def render(source, output):
    provenance = json.loads(Path(__file__).with_name('provenance.json').read_text())
    if sha256(source.read_bytes()).hexdigest() != provenance['fixture_sha256']:
        raise ValueError('Kernel fixtures differ from the independently verified snapshot; regenerate and review reference evidence')
    fixtures = json.loads(source.read_text())
    main = bytes.fromhex(fixtures['mainnet'])
    chain = fixtures['regtest']
    if len(chain) != 206 or len(main) < 287 or main[286] != 1:
        raise ValueError('Require one mainnet coinbase block and 206 regtest blocks')
    version = struct.unpack_from('<i', main)[0]
    timestamp, height = struct.unpack_from('<Ii', main, 68)
    if version != 0x20000000 or height != 1:
        raise ValueError('Unexpected fixture version/height')
    for index, encoded in enumerate(chain, 1):
        raw = bytes.fromhex(encoded)
        if len(raw) < 287 or struct.unpack_from('<i', raw, 72)[0] != index:
            raise ValueError(f'Invalid regtest fixture height {index}')
        if index > 1 and raw[4:36][::-1].hex() != hash256(previous[:221] + bytes(65)):
            raise ValueError(f'Broken fixture chain at {index}')
        previous = raw
    # Expectations do not call the kernel's hash/accessor implementations.
    main_hash = hash256(main[:221] + bytes(65))
    txid = hash256(main[287:])  # Single non-witness mainnet coinbase transaction.
    rendered = ('// Generated test data; do not edit.\n#pragma once\n'
                '#include <array>\n#include <cstdint>\n#include <string_view>\n'
                f'inline constexpr std::string_view MAINNET_BLOCK_DATA = "{main.hex()}";\n'
                f'inline constexpr std::string_view MAINNET_BLOCK_HASH = "{main_hash}";\n'
                f'inline constexpr std::string_view MAINNET_TXID = "{txid}";\n'
                f'inline constexpr std::string_view MAINNET_PREV_HASH = "{main[4:36][::-1].hex()}";\n'
                f'inline constexpr int32_t MAINNET_VERSION = {version};\n'
                f'inline constexpr uint32_t MAINNET_TIMESTAMP = {timestamp};\n'
                'inline constexpr std::array<std::string_view, 206> REGTEST_BLOCK_DATA {\n' +
                ''.join(f'"{encoded}",\n' for encoded in chain) + '};\n')
    output.write_text(rendered)


if __name__ == '__main__':
    render(Path(sys.argv[1]), Path(sys.argv[2]))
