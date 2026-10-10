# Copyright (c) 2026 The Bitcoin PoCX developers
# Distributed under the MIT software license; see COPYING.
"""Explicit fixture support for migrating genuine old Bitcoin wallets to PoCX.

Only schema-defined address/descriptor/block fields cross chain contexts. User
labels, comments, transaction bytes, amounts, keys and unknown fields are opaque.
Both nodes validate real blocks and transactions using their own consensus.
"""
from copy import deepcopy
from io import BytesIO
from pathlib import Path
import re

from .bitcoin_test_node import TestNode as BitcoinTestNode
from .blocktools import bitcoin_block_with_shared_transactions, resign_pocx_block
from .descriptors import descsum_check, descsum_create
from .messages import CBlock, COIN
from .test_node import TestNode
from .util import assert_equal
from .wallet_compatibility import (
    BITCOIN_GENESIS, POCX_GENESIS, WalletChainContext, rebase_wallet_file,
    reencode_regtest_address,
)


def shared_regtest_subsidy(height):
    if type(height) is not int or height < 1:
        raise ValueError('Expected a positive regtest block height')
    return min((10 * COIN) >> (height // 500), (50 * COIN) >> (height // 150))


def cap_shared_coinbase(block):
    """Underclaim only subsidy, retaining every other transaction byte."""
    native_subsidy = (10 * COIN) >> (block.nHeight // 500)
    # generateblock builds its coinbase before adding explicit transactions, so
    # fees are unclaimed. Require that exact fixture shape rather than silently
    # rewriting an arbitrary transaction or dropping outputs.
    assert_equal(sum(output.nValue for output in block.vtx[0].vout), native_subsidy)
    reduction = native_subsidy - shared_regtest_subsidy(block.nHeight)
    assert block.vtx[0].vout[0].nValue >= reduction
    block.vtx[0].vout[0].nValue -= reduction
    block.hashMerkleRoot = block.calc_merkle_root()
    resign_pocx_block(block)


def rpc_address(value, hrp):
    # Base58 regtest addresses and raw scripts need no encoding change. Only
    # explicit witness prefixes are decoded; this function is never used on
    # labels, arbitrary dictionary keys or other opaque user strings.
    if isinstance(value, str) and value.lower().startswith(('bcrt1', 'rpocx1')):
        return reencode_regtest_address(value, hrp)
    return value


def rpc_descriptor(value, hrp):
    body = value.split('#', 1)[0]
    if not re.search(r'addr\((?:bcrt1|rpocx1)', body):
        return value
    if '#' in value and not descsum_check(value):
        raise ValueError('Invalid address descriptor checksum')
    body = re.sub(r'addr\(([^()]*)\)', lambda match: 'addr(' + rpc_address(match[1], hrp) + ')', body)
    return descsum_create(body) if '#' in value else body


def wallet_rpc_parameters(method, args, kwargs):
    """Encode only known v28.2 wallet RPC parameter positions/keys for Bitcoin."""
    args, kwargs = deepcopy(list(args)), deepcopy(kwargs)

    def parameter(position, name, transform):
        if len(args) > position:
            args[position] = transform(args[position])
        if name in kwargs:
            kwargs[name] = transform(kwargs[name])

    address = lambda value: rpc_address(value, 'bcrt')

    def outputs(value):
        if isinstance(value, list):
            return [outputs(item) for item in value]
        return {address(key): amount for key, amount in value.items()}

    if method in ('getaddressinfo', 'validateaddress', 'setlabel', 'sendtoaddress', 'importaddress'):
        parameter(0, 'address', address)
    if method == 'addmultisigaddress':
        parameter(1, 'keys', lambda values: [address(value) for value in values])
    if method == 'send':
        parameter(0, 'outputs', outputs)

        def options(value):
            if 'change_address' in value:
                value['change_address'] = address(value['change_address'])
            return value

        parameter(4, 'options', options)
        if 'change_address' in kwargs:
            kwargs['change_address'] = address(kwargs['change_address'])
    if method == 'sendall':
        parameter(0, 'recipients', lambda values: [outputs(value) if isinstance(value, dict)
                                                  else address(value) for value in values])
    if method == 'listunspent':
        parameter(2, 'addresses', lambda values: [address(value) for value in values])
    if method in ('importmulti', 'importdescriptors'):
        def requests(values):
            for item in values:
                if isinstance(item.get('scriptPubKey'), dict) and 'address' in item['scriptPubKey']:
                    item['scriptPubKey']['address'] = address(item['scriptPubKey']['address'])
                if 'desc' in item:
                    item['desc'] = rpc_descriptor(item['desc'], 'bcrt')
            return values
        parameter(0, 'requests', requests)
    return args, kwargs


def wallet_rpc_result(method, value, context):
    """Return full RPC data in the native fixture context, without losing fields."""
    value = deepcopy(value)

    def address_fields(row):
        if 'address' in row:
            row['address'] = rpc_address(row['address'], 'rpocx')
        for field in ('desc', 'descriptor'):
            if field in row:
                row[field] = rpc_descriptor(row[field], 'rpocx')
        if 'parent_descs' in row:
            row['parent_descs'] = [rpc_descriptor(desc, 'rpocx') for desc in row['parent_descs']]
        return row

    def block_hash(value):
        return context.block_hash(bytes.fromhex(value)[::-1])[::-1].hex()

    def transaction(row):
        address_fields(row)
        if 'blockhash' in row:
            row['blockhash'] = block_hash(row['blockhash'])
        for detail in row.get('details', []):
            address_fields(detail)
        if 'decoded' in row:
            for output in row['decoded']['vout']:
                address_fields(output['scriptPubKey'])
        return row

    if method in ('getnewaddress', 'getrawchangeaddress'):
        return rpc_address(value, 'rpocx')
    if method in ('getaddressinfo', 'validateaddress', 'addmultisigaddress'):
        address_fields(value)
        if 'embedded' in value:
            address_fields(value['embedded'])
    if method == 'gettransaction':
        transaction(value)
    if method in ('listtransactions', 'listunspent'):
        for row in value:
            transaction(row)
    if method == 'getwalletinfo' and 'lastprocessedblock' in value:
        value['lastprocessedblock']['hash'] = block_hash(value['lastprocessedblock']['hash'])
    if method == 'listaddressgroupings':
        for group in value:
            for row in group:
                row[0] = rpc_address(row[0], 'rpocx')
    if method == 'getaddressesbylabel':
        value = {rpc_address(address, 'rpocx'): detail for address, detail in value.items()}
    if method == 'listdescriptors':
        for row in value['descriptors']:
            address_fields(row)
    return value


class MigrationWalletRPC:
    def __init__(self, rpc, node, *, context=None):
        self._rpc, self._node, self._context = rpc, node, context

    def __getattr__(self, method):
        operation = getattr(self._rpc, method)

        def invoke(*args, **kwargs):
            if self._context is not None:
                args, kwargs = wallet_rpc_parameters(method, args, kwargs)
            result = operation(*args, **kwargs)
            if method in ('send', 'sendall', 'sendtoaddress', 'sendrawtransaction', 'bumpfee'):
                self._node.wallet_fixture_producer(self._node.index)
            return wallet_rpc_result(method, result, self._context()) if self._context else result
        return invoke


class MigrationBitcoinNode(BitcoinTestNode):
    def get_wallet_rpc(self, wallet_name):
        rpc = super().get_wallet_rpc(wallet_name)
        # The deliberate signet fixture must retain its actual chain context.
        if self.chain != 'regtest':
            return rpc
        return MigrationWalletRPC(rpc, self, context=self.wallet_fixture_context)


class MigrationPoCXNode(TestNode):
    def get_wallet_rpc(self, wallet_name):
        return MigrationWalletRPC(super().get_wallet_rpc(wallet_name), self)

    def sendrawtransaction(self, *args, **kwargs):
        result = self.__getattr__('sendrawtransaction')(*args, **kwargs)
        self.wallet_fixture_producer(self.index)
        return result


class PairedMigrationWallets:
    """Mine shared bodies on independently validated Bitcoin and PoCX chains."""
    def setup_network(self):
        self.setup_nodes()
        self.wallet_block_map = {BITCOIN_GENESIS: POCX_GENESIS}
        self.wallet_relay_source = 0
        for node in self.nodes:
            node.wallet_fixture_producer = self.record_wallet_producer
        self.nodes[1].wallet_fixture_context = self.wallet_context
        self.sync_all()

    def record_wallet_producer(self, index):
        self.wallet_relay_source = index

    def wallet_context(self):
        return WalletChainContext(self.wallet_block_map, source_hrp='bcrt', destination_hrp='rpocx')

    def connect_nodes(self, a, b, **kwargs):
        # Upstream reconnects after restart to resume fixture propagation. These
        # header formats cannot be P2P-connected; retain that fixture boundary
        # explicitly, with real RPC acceptance and checked block correspondence.
        assert_equal({a, b}, {0, 1})
        assert all(node.running and node.rpc_connected and node.chain == 'regtest' for node in self.nodes)
        self.sync_all()

    def sync_blocks(self, nodes=None, **kwargs):
        native, bitcoin = self.nodes
        assert_equal(native.getblockcount(), bitcoin.getblockcount())
        assert_equal(self.wallet_block_map[bitcoin.getbestblockhash()], native.getbestblockhash())

    @staticmethod
    def ordered_mempool(node):
        pending = node.getrawmempool(True)
        result = []
        while pending:
            ready = sorted(txid for txid, row in pending.items() if not set(row['depends']) & pending.keys())
            assert ready, 'Cyclic or incomplete mempool fixture'
            result.extend(ready)
            for txid in ready:
                del pending[txid]
        return result

    def sync_mempools(self, nodes=None, **kwargs):
        first, second = self.nodes[self.wallet_relay_source], self.nodes[1 - self.wallet_relay_source]
        # Relay from the last successful producer first, so a real replacement
        # removes stale conflicts before the reverse pass. Never union competing
        # mempool snapshots or suppress policy/consensus rejection errors.
        for source, destination in [(first, second), (second, first)]:
            for txid in self.ordered_mempool(source):
                if txid not in destination.getrawmempool():
                    assert_equal(destination.sendrawtransaction(source.getrawtransaction(txid)), txid)
        assert_equal(set(first.getrawmempool()), set(second.getrawmempool()))

    def rebase_migration_fixture(self, wallet_name):
        if self.nodes[1].chain != 'regtest':
            return  # Retain original wrong-chain migration failure and rollback.
        path = self.nodes[0].wallets_path / wallet_name
        if not path.is_file():
            path /= self.wallet_data_filename
        self.rebase_wallet_fixture(path)

    def rebase_wallet_fixture(self, path, *, to_bitcoin=False):
        context = self.wallet_context()
        proof = rebase_wallet_file(path, context.reverse() if to_bitcoin else context,
            bitcoin_wallet=Path(self.options.previous_releases_path) / 'v28.2/bin' /
                ('bitcoin-wallet' + self.config['environment']['EXEEXT']))
        self.log.debug('Unloaded wallet context fixture: %s', proof)

    def bitcoin_backup(self, path):
        import shutil
        import tempfile
        directory = Path(tempfile.mkdtemp(prefix='bitcoin-wallet-backup-', dir=self.options.tmpdir))
        copy = directory / Path(path).name
        shutil.copyfile(path, copy)
        self.rebase_wallet_fixture(copy, to_bitcoin=True)
        return str(copy)

    def generate(self, generator, nblocks, *, sync_fun=None, **kwargs):
        assert any(generator is node for node in self.nodes)
        address = reencode_regtest_address(generator.get_deterministic_priv_key().address, 'rpocx')
        return self.generate_shared_wallet_blocks(nblocks, address, sync_fun=sync_fun)

    def generatetodescriptor(self, generator, nblocks, descriptor, *, sync_fun=None, **kwargs):
        assert generator is self.nodes[0]
        return self.generate_shared_wallet_blocks(nblocks, descriptor, sync_fun=sync_fun)

    def generate_shared_wallet_blocks(self, nblocks, output, *, sync_fun=None):
        assert type(nblocks) is int and nblocks > 0
        native, bitcoin = self.nodes
        hashes = []
        for _ in range(nblocks):
            self.sync_mempools()
            parent = native.getblockheader(native.getbestblockhash())
            clock = native.mocktime
            try:
                native.setmocktime(parent['time'] + 1)
                raw = native.generateblock(output, self.ordered_mempool(native), False, called_by_framework=True)
                block = CBlock()
                block.deserialize(BytesIO(bytes.fromhex(raw['hex'])))
            finally:
                native.setmocktime(clock or 0)
            assert_equal(block.nHeight, native.getblockcount() + 1)
            assert_equal(block.hashPrevBlock, int(parent['hash'], 16))
            cap_shared_coinbase(block)
            timestamp = max(block.nTime, native.mocktime or 0, bitcoin.mocktime or 0)
            native.setmocktime(timestamp)
            bitcoin.setmocktime(timestamp)
            template = bitcoin.getblocktemplate({'rules': ['segwit']})
            template['curtime'] = block.nTime
            shared = bitcoin_block_with_shared_transactions(block.vtx, template)
            assert_equal(shared.nTime, block.nTime)
            assert_equal([tx.serialize() for tx in shared.vtx], [tx.serialize() for tx in block.vtx])
            assert_equal(native.submitblock(block.serialize().hex()), None)
            assert_equal(bitcoin.submitblock(shared.serialize().hex()), None)
            self.wallet_block_map[shared.hash_hex] = block.hash_hex
            hashes.append(block.hash_hex)
            self.sync_blocks()
        sync_fun() if sync_fun else self.sync_all()
        return hashes
