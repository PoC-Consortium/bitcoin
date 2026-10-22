#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin PoCX developers
# Distributed under the MIT software license; see COPYING.
"""A native offline fork preserves the source and reorgs mined spends normally."""
import json
from pathlib import Path
from test_framework.blocktools import create_empty_fork, create_pocx_block_on_ancestor, create_pocx_branch
from test_framework.messages import hash256
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_raises_message, assert_raises_rpc_error
from test_framework.wallet import MiniWallet


class InvalidHeaderSource:
    """Read-only source view with one deliberately invalid replay header."""
    def __init__(self, node):
        self.node = node
        self.first_hash = node.getblockhash(1)

    def __getattr__(self, name):
        return getattr(self.node, name)

    def getblock(self, blockhash, verbosity):
        raw = self.node.getblock(blockhash, verbosity)
        if blockhash == self.first_hash and verbosity == 0:
            data = bytes.fromhex(raw)
            # Zero ECDSA r is invalid. Keep the recovery prefix and s nonzero
            # so submitblock cannot treat this as a request for auto-signing.
            return (data[:222] + bytes(32) + data[254:]).hex()
        return raw


class NativeForkFixtureTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 2
        self.uses_wallet = False

    def run_test(self):
        node, peer = self.nodes
        wallet = MiniWallet(node)
        txid = wallet.send_self_transfer(from_node=node)['txid']
        self.sync_mempools()
        parent = node.getbestblockhash()
        old_clock = node.mocktime
        directory = Path(node.datadir_path).parent
        previous = set(directory.glob('pocx-fork-*/fixture.json'))
        assert_raises_message(AssertionError, 'bad-pocx-sig', create_empty_fork, InvalidHeaderSource(node), 1)
        failed, = set(directory.glob('pocx-fork-*/fixture.json')) - previous
        failure = json.loads(failed.read_text())
        assert_equal(failure['built_and_verified'], False)
        assert_equal(failure['returncode'], 0)
        assert failure['pid'] > 0
        assert_equal(node.getbestblockhash(), parent)
        assert_equal(node.getrawmempool(), [txid])
        fork = create_empty_fork(node, fork_length=6)
        successful, = set(directory.glob('pocx-fork-*/fixture.json')) - previous - {failed}
        result = json.loads(successful.read_text())
        assert_equal(result['built_and_verified'], True)
        assert_equal(result['returncode'], 0)
        assert_equal(result['block_hashes'], [block.hash_hex for block in fork])
        assert_equal(node.mocktime, old_clock)
        assert_equal(node.getbestblockhash(), parent)
        assert_equal(peer.getbestblockhash(), parent)
        assert_equal(node.getrawmempool(), [txid])
        assert_raises_rpc_error(-5, 'Block not found', node.getblockheader, fork[0].hash_hex)
        assert_equal(len(fork), 6)
        assert_equal(fork[-1].nHeight, 206)
        live = self.generate(node, 2)
        assert txid in node.getblock(live[0])['tx']
        assert_equal(node.getrawmempool(), [])
        for observer in self.nodes:
            observer.setmocktime(max(observer.mocktime, fork[-1].nTime))
        for block in fork:
            assert node.submitblock(block.serialize().hex()) in (None, 'inconclusive')
        self.sync_blocks()
        assert_equal(node.getbestblockhash(), fork[-1].hash_hex)
        assert_equal(peer.getbestblockhash(), fork[-1].hash_hex)
        assert_equal(set(node.getrawmempool()), {txid})
        for block in fork:
            assert_equal(node.getblock(block.hash_hex, 0), block.serialize().hex())
        mined, = self.generate(node, 1)
        assert txid in node.getblock(mined)['tx']
        assert all(n.verifychain(4, 0) for n in self.nodes)

        self.log.info('Native ancestor construction preserves source state and validates its child')
        ancestor_hash = node.getblockhash(200)
        parent_raw = bytes.fromhex(node.getblockheader(ancestor_hash, False))
        source_tip, source_clock = node.getbestblockhash(), node.mocktime
        source_mempool = node.getrawmempool()
        previous = set(directory.glob('pocx-ancestor-*/ancestor.json'))
        assert_raises_message(ValueError, 'hash must be an integer',
                              create_pocx_block_on_ancestor, node, ancestor_hash)
        assert_raises_rpc_error(-5, 'Block not found', create_pocx_block_on_ancestor, node, 123)
        assert_raises_message(AssertionError, 'bad-pocx-sig', create_pocx_block_on_ancestor,
                              InvalidHeaderSource(node), int(ancestor_hash, 16))
        failed, = set(directory.glob('pocx-ancestor-*/ancestor.json')) - previous
        failure = json.loads(failed.read_text())
        assert_equal(failure['built_and_verified'], False)
        assert_equal(failure['returncode'], 0)
        block = create_pocx_block_on_ancestor(node, int(ancestor_hash, 16))
        successful, = set(directory.glob('pocx-ancestor-*/ancestor.json')) - previous - {failed}
        result = json.loads(successful.read_text())
        assert_equal(result['built_and_verified'], True)
        assert_equal(result['returncode'], 0)
        assert_equal(result['block_hash'], block.hash_hex)
        assert_equal(result['block_height'], 201)
        assert_equal(block.hashPrevBlock, int(ancestor_hash, 16))
        assert_equal(block.nHeight, 201)
        assert_equal(block.generationSignature.to_bytes(32, 'little'),
                     hash256(parent_raw[76:108] + parent_raw[148:168]))
        assert_equal(block.vtx[0].vout[0].nValue, 10 * 100_000_000)
        assert block.vtx[0].wit.is_null()
        assert_raises_rpc_error(-5, 'Block not found', node.getblockheader, block.hash_hex)
        assert_equal(node.getbestblockhash(), source_tip)
        assert_equal(node.mocktime, source_clock)
        assert_equal(node.getrawmempool(), source_mempool)
        assert_equal(peer.getbestblockhash(), source_tip)

        self.log.info('Native multi-block ancestor branch preserves a pending transaction')
        pending = wallet.send_self_transfer(from_node=node)['txid']
        self.sync_mempools()
        source_clock = node.mocktime
        parent_hash = node.getblockhash(205)
        parent_raw = bytes.fromhex(node.getblockheader(parent_hash, False))
        previous = set(directory.glob('pocx-fork-*/branch.json'))
        assert_raises_message(ValueError, 'parent hash must be an integer',
                              create_pocx_branch, node, parent_hash, 3)
        for count in [0, -1, True, 1.5]:
            assert_raises_message(ValueError, 'length must be a positive integer',
                                  create_pocx_branch, node, int(parent_hash, 16), count)
        assert_raises_rpc_error(-5, 'Block not found', create_pocx_branch, node, 123, 3)
        assert_raises_message(AssertionError, 'bad-pocx-sig', create_pocx_branch,
                              InvalidHeaderSource(node), int(parent_hash, 16), 3)
        failed, = set(directory.glob('pocx-fork-*/branch.json')) - previous
        failure = json.loads(failed.read_text())
        assert_equal(failure['built_and_verified'], False)
        assert_equal(failure['returncode'], 0)
        branch = create_pocx_branch(node, int(parent_hash, 16), 3)
        successful, = set(directory.glob('pocx-fork-*/branch.json')) - previous - {failed}
        result = json.loads(successful.read_text())
        assert_equal(result['built_and_verified'], True)
        assert_equal(result['returncode'], 0)
        assert_equal(result['actual_source_tip'], source_tip)
        assert_equal(result['actual_source_clock'], source_clock)
        assert_equal(result['blocks'], [block.serialize().hex() for block in branch])
        assert_equal([block.nHeight for block in branch], [206, 207, 208])
        previous_hash, previous_time = int(parent_hash, 16), int.from_bytes(parent_raw[68:72], 'little')
        for block in branch:
            assert_equal(block.hashPrevBlock, previous_hash)
            assert_equal(block.generationSignature.to_bytes(32, 'little'),
                         hash256(parent_raw[76:108] + parent_raw[148:168]))
            assert block.nTime > previous_time
            assert_equal(len(block.vtx), 1)
            assert_equal(block.vtx[0].vout[0].nValue, 10 * 100_000_000)
            previous_hash, previous_time, parent_raw = block.hash_int, block.nTime, block.serialize()[:286]
        assert_raises_rpc_error(-5, 'Block not found', node.getblockheader, branch[-1].hash_hex)
        assert_equal(node.getbestblockhash(), source_tip)
        assert_equal(node.mocktime, source_clock)
        assert_equal(node.getrawmempool(), [pending])
        assert_equal(peer.getbestblockhash(), source_tip)
        assert_equal(peer.getrawmempool(), [pending])


if __name__ == '__main__':
    NativeForkFixtureTest(__file__).main()
