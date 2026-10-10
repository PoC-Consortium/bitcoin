# Copyright (c) 2026 The Bitcoin PoCX developers
# Distributed under the MIT software license; see COPYING.
"""Reuse transaction helpers and construct native competing forks explicitly.

The staged bitcoin_blocktools module is an ordinary copy of reviewed upstream
sources. Its PoW block constructors remain unsupported for PoCX. Only the fork
fixture below replaces a mining-dependent entrypoint; no globals are patched.
"""
from .bitcoin_blocktools import *  # noqa: F403
from io import BytesIO
from pathlib import Path
import json
import subprocess
import tempfile

from .messages import CBlock
from .bitcoin_messages import CBlock as BitcoinBlock, CTransaction as BitcoinTransaction
from .test_node import TestNode
from .util import MAX_NODES, assert_equal, initialize_datadir


def bitcoin_block_with_shared_coinbase(coinbase, template):
    """Mine a Bitcoin header around an unchanged native coinbase transaction.

    Independent test chains can share the same funding outpoint. Bitcoin allows
    the smaller native reward as an underclaimed subsidy; neither consensus
    validator is replaced and the chains retain their distinct headers/genesis.
    """
    return bitcoin_block_with_shared_transactions([coinbase], template)


def bitcoin_block_with_shared_transactions(transactions, template):
    """Mine an independent Bitcoin header around byte-identical transactions."""
    if not transactions:
        raise ValueError('A shared block requires a coinbase transaction')
    bitcoin_transactions = []
    for transaction in transactions:
        copied = BitcoinTransaction()
        copied.deserialize(BytesIO(transaction.serialize()))
        assert_equal(copied.serialize(), transaction.serialize())
        bitcoin_transactions.append(copied)
    bitcoin_coinbase = bitcoin_transactions[0]
    assert sum(output.nValue for output in bitcoin_coinbase.vout) <= template['coinbasevalue']
    block = BitcoinBlock()
    block.nVersion = template['version']
    block.hashPrevBlock = int(template['previousblockhash'], 16)
    block.nBits = int(template['bits'], 16)
    block.nTime = max(template['curtime'], template['mintime'])
    block.vtx = bitcoin_transactions
    block.hashMerkleRoot = block.calc_merkle_root()
    block.solve()
    return block


def create_empty_fork(node, fork_length=FORK_LENGTH):
    """Return signed empty blocks extending the current tip without altering it.

    A disconnected, wallet-disabled node replays the active chain through normal
    submitblock validation, then forges the native branch. Reserve the last node
    index in this test's port range, with all data and logs under its own tmpdir.
    """
    if type(fork_length) is not int or fork_length < 1:
        raise ValueError('PoCX fork length must be a positive integer')
    index = MAX_NODES - 1
    parent_dir = Path(node.datadir_path).parent
    if (parent_dir / f'node{index}').exists():
        raise ValueError('PoCX fork fixture requires the last test node index to be reserved')
    assert_equal(node.getblockchaininfo()['chain'], 'regtest')
    parent = node.getbestblockhash()
    height = node.getblockcount()
    mempool = set(node.getrawmempool())
    parent_time = node.getblockheader(parent)['time']
    directory = Path(tempfile.mkdtemp(prefix='pocx-fork-', dir=parent_dir))
    datadir = initialize_datadir(directory, index, 'regtest')
    scratch = TestNode(index, datadir, chain='regtest', rpchost=None,
                       timewait=node.rpc_timeout, timeout_factor=node.timeout_factor,
                       binaries=node.binaries, coverage_dir=node.coverage_dir,
                       cwd=node.cwd, uses_wallet=False,
                       extra_args=['-listen=0', f'-mocktime={parent_time}'])
    blocks = []
    process = None
    verified = False
    try:
        scratch.start()
        process = scratch.process
        scratch.wait_for_rpc_connection()
        scratch.help('get_assignment')
        assert_equal(scratch.getblockhash(0), node.getblockhash(0))
        for h in range(1, height + 1):
            blockhash = node.getblockhash(h)
            assert_equal(scratch.submitblock(node.getblock(blockhash, 0)), None)
        assert_equal(scratch.getbestblockhash(), parent)
        previous = parent
        for offset in range(1, fork_length + 1):
            candidate = scratch.generateblock('raw(51)', [], called_by_framework=True)
            block = CBlock()
            block.deserialize(BytesIO(bytes.fromhex(scratch.getblock(candidate['hash'], 0))))
            assert_equal(block.hash_hex, candidate['hash'])
            assert_equal(block.hashPrevBlock, int(previous, 16))
            assert_equal(block.nHeight, height + offset)
            assert_equal(len(block.vtx), 1)
            assert block.vchSignature != bytes(65)
            blocks.append(block)
            previous = block.hash_hex
        assert scratch.verifychain(4, 0)
        verified = True
    finally:
        # Only this fixture's child. Even a failed startup/replay must be reaped.
        try:
            if scratch.running and scratch.rpc_connected:
                scratch.stop_node()
        finally:
            process = process or scratch.process
            if process is not None and process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=10)
            (directory / 'fixture.json').write_text(json.dumps({
                'source_tip': parent, 'source_height': height,
                'fork_length': fork_length, 'built_and_verified': verified,
                'block_hashes': [block.hash_hex for block in blocks],
                'node_index': index, 'pid': process.pid if process is not None else None,
                'returncode': process.poll() if process is not None else None,
            }, indent=2) + '\n')
    assert_equal(node.getbestblockhash(), parent)
    assert_equal(node.getblockcount(), height)
    assert_equal(set(node.getrawmempool()), mempool)
    return blocks


POCX_MAX_FUTURE_BLOCK_TIME = 15
_REGTEST_ACCOUNT = bytes.fromhex('1e50bcc17e3c6ab42d39a6a5d79b0d7a6983a765')
_REGTEST_SIGNING_KEY = bytes.fromhex('0a1590dc8867ab2a1fc28432dcc1c614fc0e5e0b169b9cc9f4dd7263232c8ff8')


class PoCXAddressGenerator:
    """Explicit TestNode producer for historical generatetoaddress calls."""
    def __init__(self, node, address):
        self._test_node = node
        self.address = address

    def generate(self, nblocks, *, called_by_framework, **kwargs):
        return self._test_node.generatetoaddress(nblocks, self.address,
                                                called_by_framework=called_by_framework, **kwargs)


def create_pocx_coinbase(height, pubkey=None, *, script_pubkey=None,
                         extra_output_script=None, fees=0, nValue=None):
    """Keep upstream scripts/BIP34 padding with the regtest10coin/500block subsidy."""
    coinbase = create_coinbase(height, pubkey, script_pubkey=script_pubkey,
                               extra_output_script=extra_output_script,
                               nValue=0 if nValue is None else nValue)
    if nValue is None:
        coinbase.vout[0].nValue = ((10 * COIN) >> (height // 500)) + fees
    return coinbase


def resign_pocx_block(block):
    """Sign a mutated synthetic regtest header without replacing its proof/body.

    Explicitly restricted to the reserved regtest actor and seed. Tests construct
    malformed bodies here so rejection reaches the intended consensus check,
    rather than failing first on an obsolete header signature.
    """
    from .crypto import secp256k1
    from .key import ECKey, ECPubKey, ORDER, rfc6979_nonce
    from .messages import hash256, ser_string
    from .script import hash160

    assert_equal(block.pocxProof.account_id, _REGTEST_ACCOUNT)
    assert_equal(block.pocxProof.seed, bytes(32))
    assert 0 <= block.pocxProof.nonce < 64
    key = ECKey()
    key.set(_REGTEST_SIGNING_KEY, compressed=True)
    public_key = key.get_pubkey().get_bytes()
    assert_equal(hash160(public_key), _REGTEST_ACCOUNT)
    assert_equal(block.vchPubKey, public_key)
    digest = hash256(ser_string(b'POCX Signed Block:\n') + ser_string(block.hash_hex.encode()))
    nonce = int.from_bytes(rfc6979_nonce(key.get_bytes() + digest), 'big')
    point = nonce * secp256k1.G
    r = int(point.x) % ORDER
    s = pow(nonce, -1, ORDER) * (int.from_bytes(digest, 'big') + key.secret * r) % ORDER
    recid = (int(point.y) & 1) | (2 if int(point.x) >= ORDER else 0)
    if s > ORDER // 2:
        s = ORDER - s
        recid ^= 1
    block.vchSignature = bytes([31 + recid]) + r.to_bytes(32, 'big') + s.to_bytes(32, 'big')
    rb, sb = r.to_bytes((r.bit_length() + 8) // 8, 'big'), s.to_bytes((s.bit_length() + 8) // 8, 'big')
    der = b'\x30' + bytes([4 + len(rb) + len(sb), 2, len(rb)]) + rb + bytes([2, len(sb)]) + sb
    pubkey = ECPubKey()
    pubkey.set(public_key)
    assert pubkey.verify_ecdsa(der, digest)


def create_pocx_block(node, hashprev=None, coinbase=None, ntime=None, *, version=None, tmpl=None, txlist=None, check_mempool=True):
    """Build on the active tip, then permit explicit transaction/header mutations.

    Obtain a native empty proof/signature without submission. Transaction bodies
    are assembled in Python so intentionally invalid txs never go through an RPC
    prevalidation filter. Preserve producer tip, height and clock. Check mempool
    preservation for quiescent fixtures by default; connected generation callers
    allow independently arriving transactions during the unsubmitted preview. Only
    callers decide when receiving clocks should advance. Requested time is raised
    to the actual proof's minimum deadline; future-time tests can set it exactly
    after construction and re-sign. Arbitrary-parent forging is not supported.
    """
    import copy
    from .messages import tx_from_hex

    assert_equal(node.getblockchaininfo()['chain'], 'regtest')
    parent = node.getbestblockhash()
    height = node.getblockcount()
    mempool = set(node.getrawmempool()) if check_mempool else None
    clock = node.mocktime
    if hashprev is not None:
        assert_equal(hashprev, int(parent, 16))
    if tmpl is not None:
        assert_equal(tmpl['previousblockhash'], parent)
        assert_equal(tmpl['height'], height + 1)
    parent_time = node.getblockheader(parent)['time']
    try:
        node.setmocktime(parent_time + 1)
        result = node.generateblock('raw(51)', [], False, called_by_framework=True)
        block = CBlock()
        block.deserialize(BytesIO(bytes.fromhex(result['hex'])))
        assert_equal(block.hash_hex, result['hash'])
        assert_equal(block.hashPrevBlock, int(parent, 16))
        assert_equal(block.nHeight, height + 1)
        assert_equal(len(block.vtx), 1)
        assert block.nTime > parent_time
    finally:
        node.setmocktime(clock or 0)
    assert_equal(node.getbestblockhash(), parent)
    assert_equal(node.getblockcount(), height)
    if check_mempool:
        assert_equal(set(node.getrawmempool()), mempool)
    assert_equal(node.mocktime, clock)
    if coinbase is not None:
        block.vtx[0] = copy.deepcopy(coinbase)
    if txlist:
        block.vtx.extend(tx_from_hex(tx) if isinstance(tx, str) else copy.deepcopy(tx) for tx in txlist)
    if version is not None:
        block.nVersion = version
    elif tmpl is not None:
        block.nVersion = tmpl['version']
    if ntime is None:
        ntime = tmpl.get('curtime') if tmpl is not None else clock
    if ntime is not None:
        block.nTime = max(block.nTime, ntime)
    block.hashMerkleRoot = block.calc_merkle_root()
    resign_pocx_block(block)
    return block


def create_pocx_block_on_ancestor(node, parent_hash):
    """Build and independently accept a native child of a stored active ancestor.

    A wallet-disabled child replays the original chain through normal validation.
    Source tip, mempool and clock remain unchanged; only the returned block can
    subsequently be mutated by the caller. This does not forge on unknown parents.
    """
    if not isinstance(parent_hash, int):
        raise ValueError('PoCX ancestor hash must be an integer')
    parent = f'{parent_hash:064x}'
    assert_equal(node.getblockchaininfo()['chain'], 'regtest')
    ancestor = node.getblockheader(parent)
    ancestor_height = ancestor['height']
    assert_equal(node.getblockhash(ancestor_height), parent)
    source_tip, source_height = node.getbestblockhash(), node.getblockcount()
    source_mempool, source_clock = set(node.getrawmempool()), node.mocktime
    index = MAX_NODES - 1
    parent_dir = Path(node.datadir_path).parent
    if (parent_dir / f'node{index}').exists():
        raise ValueError('PoCX ancestor fixture requires the last test node index to be reserved')
    directory = Path(tempfile.mkdtemp(prefix='pocx-ancestor-', dir=parent_dir))
    datadir = initialize_datadir(directory, index, 'regtest')
    scratch = TestNode(index, datadir, chain='regtest', rpchost=None,
                       timewait=node.rpc_timeout, timeout_factor=node.timeout_factor,
                       binaries=node.binaries, coverage_dir=node.coverage_dir,
                       cwd=node.cwd, uses_wallet=False,
                       extra_args=['-listen=0', f"-mocktime={ancestor['time']}"])
    process, block, verified = None, None, False
    try:
        scratch.start()
        process = scratch.process
        scratch.wait_for_rpc_connection()
        scratch.help('get_assignment')
        assert_equal(scratch.getblockhash(0), node.getblockhash(0))
        for height in range(1, ancestor_height + 1):
            assert_equal(scratch.submitblock(node.getblock(node.getblockhash(height), 0)), None)
        assert_equal(scratch.getbestblockhash(), parent)
        block = create_pocx_block(scratch, coinbase=create_pocx_coinbase(ancestor_height + 1))
        assert_equal(block.hashPrevBlock, parent_hash)
        assert_equal(block.nHeight, ancestor_height + 1)
        assert_equal(len(block.vtx), 1)
        scratch.setmocktime(block.nTime)
        assert_equal(scratch.submitblock(block.serialize().hex()), None)
        assert_equal(scratch.getbestblockhash(), block.hash_hex)
        assert scratch.verifychain(4, 0)
        verified = True
    finally:
        try:
            if scratch.running and scratch.rpc_connected:
                scratch.stop_node()
        finally:
            process = process or scratch.process
            if process is not None and process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=10)
            (directory / 'ancestor.json').write_text(json.dumps({
                'source_tip': source_tip, 'source_height': source_height,
                'parent': parent, 'parent_height': ancestor_height,
                'built_and_verified': verified,
                'block_hash': block.hash_hex if block is not None else None,
                'block_height': block.nHeight if block is not None else None,
                'node_index': index, 'pid': process.pid if process is not None else None,
                'returncode': process.poll() if process is not None else None,
            }, indent=2) + '\n')
    assert_equal(node.getbestblockhash(), source_tip)
    assert_equal(node.getblockcount(), source_height)
    assert_equal(set(node.getrawmempool()), source_mempool)
    assert_equal(node.mocktime, source_clock)
    return block


class _PoCXAncestorSource:
    """Explicit read-only source view for the existing validated fork builder."""
    def __init__(self, node, parent, height):
        self._node = node
        self._parent = parent
        self._height = height

    def __getattr__(self, name):
        return getattr(self._node, name)

    def getbestblockhash(self):
        return self._parent

    def getblockcount(self):
        return self._height


def create_pocx_branch(node, parent_hash, nblocks):
    """Return a validated native branch on a stored active parent, without submission.

    Replay and child ownership use the existing offline fork builder. The view
    selects the replay endpoint; RPC data and block bytes still come from the real
    node. Also check the actual source state, not just the selected parent view.
    Receiving clocks and eventual P2P submission remain the caller's responsibility.
    """
    if type(parent_hash) is not int:
        raise ValueError('PoCX branch parent hash must be an integer')
    if type(nblocks) is not int or nblocks < 1:
        raise ValueError('PoCX branch length must be a positive integer')
    parent = f'{parent_hash:064x}'
    assert_equal(node.getblockchaininfo()['chain'], 'regtest')
    height = node.getblockheader(parent)['height']
    assert_equal(node.getblockhash(height), parent)
    source_tip, source_height = node.getbestblockhash(), node.getblockcount()
    source_mempool, source_clock = set(node.getrawmempool()), node.mocktime
    directory = Path(node.datadir_path).parent
    before = set(directory.glob('pocx-fork-*/fixture.json'))
    blocks = []
    try:
        blocks = create_empty_fork(_PoCXAncestorSource(node, parent, height), nblocks)
        assert_equal(len(blocks), nblocks)
        previous = parent
        for offset, block in enumerate(blocks, 1):
            assert_equal(block.hashPrevBlock, int(previous, 16))
            assert_equal(block.nHeight, height + offset)
            previous = block.hash_hex
        return blocks
    finally:
        journals = set(directory.glob('pocx-fork-*/fixture.json')) - before
        assert len(journals) <= 1
        for journal in journals:
            record = json.loads(journal.read_text())
            (journal.parent / 'branch.json').write_text(json.dumps({
                **record, 'actual_source_tip': source_tip, 'actual_source_height': source_height,
                'actual_source_clock': source_clock,
                'parent_header': node.getblockheader(parent, False),
                'blocks': [block.serialize().hex() for block in blocks],
            }, indent=2) + '\n')
        assert_equal(node.getbestblockhash(), source_tip)
        assert_equal(node.getblockcount(), source_height)
        assert_equal(set(node.getrawmempool()), source_mempool)
        assert_equal(node.mocktime, source_clock)
