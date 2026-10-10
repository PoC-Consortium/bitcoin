# Copyright (c) 2026 The Bitcoin PoCX developers
# Distributed under the MIT software license; see COPYING.
"""Rebase explicitly copied wallet fixtures onto transaction-identical chains.

This is test fixture construction, not a wallet migration implementation. Only
encoded address-book destinations, block locators and transaction confirmation
block hashes may change. Keys, descriptors, raw transactions, labels, amounts,
conflicts, abandonment and all other records remain byte for byte unchanged.
"""
from io import BytesIO
import hashlib
import os
from pathlib import Path
import shutil
import sqlite3
import subprocess
import tempfile

from .address import base58_to_byte
from .bitcoin_messages import CTransaction, deser_compact_size, deser_string, ser_string
from .segwit_addr import decode_segwit_address, encode_segwit_address

BITCOIN_GENESIS = '0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206'
POCX_GENESIS = '2a98a52253aeff06093948b00568d380b7634621bc606403127973c9acbbfde0'


def reencode_regtest_address(address, destination_hrp):
    """Change only a validated regtest witness address's network encoding."""
    if destination_hrp not in ('bcrt', 'rpocx'):
        raise ValueError('Expected an explicit Bitcoin or PoCX regtest HRP')
    for source_hrp in ('bcrt', 'rpocx'):
        if address.lower().startswith(source_hrp + '1'):
            version, program = decode_segwit_address(source_hrp, address)
            if version is None:
                raise ValueError('Invalid regtest witness address')
            return encode_segwit_address(destination_hrp, version, program)
    _, version = base58_to_byte(address)
    if version not in (111, 196):
        raise ValueError('Expected a regtest Base58 address')
    return address


class WalletChainContext:
    def __init__(self, block_hashes, *, source_hrp, destination_hrp):
        if (source_hrp, destination_hrp) not in (('bcrt', 'rpocx'), ('rpocx', 'bcrt')):
            raise ValueError('Expected distinct, explicit regtest chain contexts')
        self.source_hrp = source_hrp
        self.destination_hrp = destination_hrp
        self.block_hashes = {}
        for source, destination in block_hashes.items():
            if len(source) != 64 or len(destination) != 64:
                raise ValueError('Block hashes must contain exactly 32 bytes')
            source_bytes = bytes.fromhex(source)[::-1]
            destination_bytes = bytes.fromhex(destination)[::-1]
            if len(source_bytes) != 32 or len(destination_bytes) != 32:
                raise ValueError('Invalid block hash encoding')
            self.block_hashes[source_bytes] = destination_bytes
        genesis = {('bcrt', 'rpocx'): (BITCOIN_GENESIS, POCX_GENESIS),
                   ('rpocx', 'bcrt'): (POCX_GENESIS, BITCOIN_GENESIS)}[source_hrp, destination_hrp]
        if self.block_hashes.get(bytes.fromhex(genesis[0])[::-1]) != bytes.fromhex(genesis[1])[::-1]:
            raise ValueError('Missing or incorrect regtest genesis mapping')
        if len(set(self.block_hashes.values())) != len(self.block_hashes):
            raise ValueError('Block mapping must be bijective')

    def reverse(self):
        return WalletChainContext({destination[::-1].hex(): source[::-1].hex()
                                   for source, destination in self.block_hashes.items()},
                                  source_hrp=self.destination_hrp, destination_hrp=self.source_hrp)

    def block_hash(self, value, *, transaction_state=False):
        # CWalletTx uses zero and one for inactive and abandoned states. These
        # are status markers, never block identities to be rewritten.
        if transaction_state and value in (bytes(32), b'\x01' + bytes(31)):
            return value
        if value not in self.block_hashes:
            raise ValueError('Wallet references an unmapped block; fixture correspondence is incomplete')
        return self.block_hashes[value]

    def record(self, key, value):
        stream = BytesIO(key)
        kind = deser_string(stream)
        key_suffix = stream.read()
        if kind in (b'name', b'purpose', b'destdata'):
            stream = BytesIO(key_suffix)
            address = deser_string(stream).decode('ascii')
            # Labels and destination data values are opaque user data.
            replacement = reencode_regtest_address(address, self.destination_hrp)
            key = ser_string(kind) + ser_string(replacement.encode()) + stream.read()
        elif kind in (b'bestblock', b'bestblock_nomerkle'):
            if key_suffix:
                raise ValueError('Unexpected block locator key suffix')
            stream = BytesIO(value)
            version = stream.read(4)
            if len(version) != 4:
                raise ValueError('Truncated block locator version')
            count = deser_compact_size(stream)
            prefix = value[:stream.tell()]
            hashes = [stream.read(32) for _ in range(count)]
            if any(len(h) != 32 for h in hashes) or stream.read():
                raise ValueError('Invalid block locator length')
            value = prefix + b''.join(self.block_hash(h) for h in hashes)
        elif kind == b'tx':
            if len(key_suffix) != 32:
                raise ValueError('Unexpected wallet transaction key')
            stream = BytesIO(value)
            transaction = CTransaction()
            transaction.deserialize(stream)
            if transaction.txid_int.to_bytes(32, 'little') != key_suffix:
                raise ValueError('Wallet transaction key does not match its serialized transaction')
            offset = stream.tell()
            block_hash = stream.read(32)
            if len(block_hash) != 32:
                raise ValueError('Truncated wallet transaction block hash')
            # Everything following the hash (position, metadata, ordering and
            # conflict/abandonment status) remains unchanged.
            value = value[:offset] + self.block_hash(block_hash, transaction_state=True) + value[offset + 32:]
        return key, value

    def records(self, records):
        records = list(records)
        result = [self.record(key, value) for key, value in records]
        if len({key for key, _ in result}) != len(result):
            raise ValueError('Rebased wallet records collide')
        if self.reverse()._records_without_roundtrip(result) != list(records):
            raise ValueError('Wallet fixture conversion is not reversible')
        return result

    def _records_without_roundtrip(self, records):
        return [self.record(key, value) for key, value in records]


def read_wallet_dump(path):
    lines = Path(path).read_bytes().splitlines(keepends=True)
    if len(lines) < 3 or lines[:2] != [b'BITCOIN_CORE_WALLET_DUMP,1\n', b'format,bdb\n']:
        raise ValueError('Expected a version 1 Berkeley DB wallet dump')
    checksum = hashlib.sha256(hashlib.sha256(b''.join(lines[:-1])).digest()).hexdigest()
    if lines[-1] != b'checksum,' + checksum.encode() + b'\n':
        raise ValueError('Wallet dump checksum mismatch')
    records = []
    for line in lines[2:-1]:
        key, value = line.rstrip(b'\n').split(b',')
        records.append((bytes.fromhex(key.decode()), bytes.fromhex(value.decode())))
    if len({key for key, _ in records}) != len(records):
        raise ValueError('Duplicate wallet dump record')
    return records


def write_wallet_dump(path, records):
    payload = b'BITCOIN_CORE_WALLET_DUMP,1\nformat,bdb\n'
    payload += b''.join(key.hex().encode() + b',' + value.hex().encode() + b'\n' for key, value in records)
    checksum = hashlib.sha256(hashlib.sha256(payload).digest()).hexdigest().encode()
    Path(path).write_bytes(payload + b'checksum,' + checksum + b'\n')


def rebase_wallet_file(path, context, *, bitcoin_wallet=None):
    """Rebase a detached fixture copy, retaining every unmodified record."""
    path = Path(path)
    with path.open('rb') as stream:
        magic = stream.read(16)
    if magic == b'SQLite format 3\x00':
        with sqlite3.connect(path) as database:
            database.execute('BEGIN IMMEDIATE')
            original = database.execute('SELECT key, value FROM main ORDER BY key').fetchall()
            updated = context.records(original)
            changed = [(before, after) for before, after in zip(original, updated) if before != after]
            database.executemany('DELETE FROM main WHERE key=?', [(before[0],) for before, _ in changed])
            database.executemany('INSERT INTO main(key,value) VALUES(?,?)', [after for _, after in changed])
            assert sorted(database.execute('SELECT key,value FROM main').fetchall()) == sorted(updated)
        return {'format': 'sqlite', 'records': len(original), 'context_records_changed': len(changed)}
    if len(magic) != 16 or int.from_bytes(magic[12:16], 'little') != 0x053162:
        raise ValueError('Expected a SQLite or Berkeley DB wallet fixture')
    if bitcoin_wallet is None:
        raise ValueError('Berkeley DB fixture rebasing requires the genuine previous-release wallet tool')
    with tempfile.TemporaryDirectory(prefix='pocx-wallet-context-', dir='/tmp') as directory:
        directory = Path(directory)
        source = directory / 'source'
        source_wallet = source / 'regtest/wallets/fixture'
        source_wallet.mkdir(parents=True)
        shutil.copyfile(path, source_wallet / 'wallet.dat')
        destination = directory / 'destination'
        (destination / 'regtest/wallets').mkdir(parents=True)

        def invoke(datadir, command, dumpfile, *flags):
            result = subprocess.run([str(bitcoin_wallet), '-regtest', f'-datadir={datadir}', '-wallet=fixture',
                                     f'-dumpfile={dumpfile}', *flags, command],
                                    capture_output=True, text=True, timeout=60)
            if result.returncode:
                raise RuntimeError(f'Previous-release wallet tool failed: {command}, exit {result.returncode}')

        original_dump = directory / 'original.dump'
        invoke(source, 'dump', original_dump)
        original = read_wallet_dump(original_dump)
        updated = context.records(original)
        updated_dump = directory / 'updated.dump'
        write_wallet_dump(updated_dump, updated)
        invoke(destination, 'createfromdump', updated_dump, '-format=bdb')
        verified_dump = directory / 'verified.dump'
        invoke(destination, 'dump', verified_dump)
        if sorted(read_wallet_dump(verified_dump)) != sorted(updated):
            raise ValueError('Previous-release tool changed non-context wallet records')
        # Install only after complete logical verification. The caller must
        # supply a detached fixture copy, never a wallet loaded by a node.
        with tempfile.NamedTemporaryFile(prefix=path.name + '.', dir=path.parent, delete=False) as temporary:
            replacement = Path(temporary.name)
        try:
            shutil.copyfile(destination / 'regtest/wallets/fixture/wallet.dat', replacement)
            shutil.copystat(path, replacement)
            os.replace(replacement, path)
        finally:
            replacement.unlink(missing_ok=True)
        return {'format': 'bdb', 'records': len(original),
                'context_records_changed': sum(before != after for before, after in zip(original, updated))}
