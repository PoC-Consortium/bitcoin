#!/usr/bin/env python3
# Copyright (c) 2014-present The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test logic for skipping signature validation on old blocks.

Test logic for skipping signature validation on blocks which we've assumed
valid (https://github.com/bitcoin/bitcoin/pull/9484)

We build a chain that includes an invalid signature for one of the transactions:

    0:        genesis block
    1:        block 1 with coinbase transaction output.
    2-101:    bury that block with 100 blocks so the coinbase transaction
              output can be spent
    102:      a block containing a transaction spending the coinbase
              transaction output. The transaction has an invalid signature.
    103-2202: bury the bad block with just over two weeks' worth of blocks
              (2100 blocks)

Start a few nodes:

    - node0 has no -assumevalid parameter. Try to sync to block 2202. It will
      reject block 102 and only sync as far as block 101
    - node1 has -assumevalid set to the hash of block 102. Try to sync to
      block 2202. node1 will sync all the way to block 2202.
    - node2 has -assumevalid set to the hash of block 102. Try to sync to
      block 200. node2 will reject block 102 since it's assumed valid, but it
      isn't buried by at least two weeks' work.
    - node3 has -assumevalid set to the hash of block 102. Feed a longer
      competing headers-only branch so block #1 is not on the best header chain.
    - node4 has -assumevalid set to the hash of block 102. Submit an alternative
      block #1 that is not part of the assumevalid chain.
    - node5 starts with no -assumevalid parameter. Reindex to hit
      "assumevalid hash not in headers" and "below minimum chainwork".
"""

from test_framework.blocktools import (
    COINBASE_MATURITY,
    add_witness_commitment,
    create_pocx_coinbase,
    create_pocx_branch,
    resign_pocx_block,
)
from test_framework.messages import (
    CBlockHeader,
    COutPoint,
    CTransaction,
    CTxIn,
    CTxOut,
    msg_block,
    msg_headers,
)
from test_framework.p2p import P2PInterface
from test_framework.script import (
    CScript,
    OP_TRUE,
)
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal
from test_framework.wallet_util import generate_keypair


class BaseNode(P2PInterface):
    def send_header_for_blocks(self, new_blocks):
        headers_message = msg_headers()
        headers_message.headers = [CBlockHeader(b) for b in new_blocks]
        for offset in range(0, len(headers_message.headers), 2000):
            chunk = msg_headers()
            chunk.headers = headers_message.headers[offset:offset + 2000]
            self.send_without_ping(chunk)


class AssumeValidTest(BitcoinTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 6
        self.rpc_timeout = 120

    def setup_network(self):
        self.add_nodes(self.num_nodes)
        # Start node0. We don't start the other nodes yet since
        # we need to pre-mine a block with an invalid transaction
        # signature so we can pass in the block hash as assumevalid.
        self.start_node(0)

    def prepare_native_chain(self, blocks, parent, parent_time):
        # Same native mining account means generation signatures and actual
        # proof qualities survive body/parent/time mutations.600second spacing
        # keeps the rolling target at the independently known genesis cap.
        for offset, block in enumerate(blocks, 1):
            block.hashPrevBlock = parent
            block.nTime = parent_time + 600 * offset
            block.nVersion = 4
            block.nBaseTarget = (1 << 58) // 120
            block.hashMerkleRoot = block.calc_merkle_root()
            resign_pocx_block(block)
            parent = block.hash_int

    def run_test(self):
        # Native chainwork represents120seconds per genesis-cap block, so
        # five times the Bitcoin burial depth preserves the two-week WORK gate.
        burial_depth = 2100 * 5
        chain_height = COINBASE_MATURITY + 2 + burial_depth
        genesis = int(self.nodes[0].getbestblockhash(), 16)
        genesis_time = self.nodes[0].getblockheader(f'{genesis:064x}')['time']
        _, coinbase_pubkey = generate_keypair()
        self.blocks = create_pocx_branch(self.nodes[0], genesis, chain_height)
        self.blocks[0].vtx[0] = create_pocx_coinbase(1, coinbase_pubkey)
        self.block1 = self.blocks[0]
        tx = CTransaction()
        tx.vin.append(CTxIn(COutPoint(self.block1.vtx[0].txid_int, 0), scriptSig=b""))
        tx.vout.append(CTxOut(9 * 100000000, CScript([OP_TRUE])))
        self.blocks[101].vtx.append(tx)
        add_witness_commitment(self.blocks[101])
        self.prepare_native_chain(self.blocks, genesis, genesis_time)
        block102 = self.blocks[101]
        assert_equal(block102.nHeight, 102)
        assert burial_depth * 120 > 14 * 24 * 60 * 60
        assert 98 * 120 < 14 * 24 * 60 * 60
        block_1_hash = self.blocks[0].hash_hex

        self.start_node(1, extra_args=[f"-assumevalid={block102.hash_hex}"])
        self.start_node(2, extra_args=[f"-assumevalid={block102.hash_hex}"])
        self.start_node(3, extra_args=[f"-assumevalid={block102.hash_hex}"])
        self.start_node(4, extra_args=[f"-assumevalid={block102.hash_hex}"])
        self.start_node(5)

        # nodes[0]
        self.log.info("Send blocks to node0. Block 102 will be rejected.")
        p2p0 = self.nodes[0].add_p2p_connection(BaseNode())
        p2p0.send_header_for_blocks(self.blocks[0:2000])
        p2p0.send_header_for_blocks(self.blocks[2000:])
        with self.nodes[0].assert_debug_log(expected_msgs=[
            f"Enabling script verification at block #1 ({block_1_hash}): assumevalid=0 (always verify).",
        ]):
            p2p0.send_and_ping(msg_block(self.blocks[0]))
        with self.nodes[0].assert_debug_log(expected_msgs=[
            "Block validation error: block-script-verify-flag-failed",
        ]):
            for i in range(1, 103):
                p2p0.send_without_ping(msg_block(self.blocks[i]))
            p2p0.wait_for_disconnect()
            assert_equal(self.nodes[0].getblockcount(), COINBASE_MATURITY + 1)
            assert_equal(next(filter(lambda x: x["hash"] == self.blocks[-1].hash_hex, self.nodes[0].getchaintips()))["status"], "invalid")

        # nodes[1]
        self.log.info("Send all blocks to node1. All blocks will be accepted.")
        p2p1 = self.nodes[1].add_p2p_connection(BaseNode())
        p2p1.send_header_for_blocks(self.blocks[0:2000])
        p2p1.send_header_for_blocks(self.blocks[2000:])
        with self.nodes[1].assert_debug_log(expected_msgs=[
            f"Disabling script verification at block #1 ({self.blocks[0].hash_hex}).",
        ]):
            p2p1.send_and_ping(msg_block(self.blocks[0]))
        with self.nodes[1].assert_debug_log(expected_msgs=[
            f"Enabling script verification at block #103 ({self.blocks[102].hash_hex}): block height above assumevalid height.",
        ]):
            for i in range(1, chain_height):
                p2p1.send_without_ping(msg_block(self.blocks[i]))
            # Syncing 2200 blocks can take a while on slow systems. Give it plenty of time to sync.
            p2p1.sync_with_ping(timeout=960)
            assert_equal(self.nodes[1].getblockcount(), chain_height)

        # nodes[2]
        self.log.info("Send blocks to node2. Block 102 will be rejected.")
        p2p2 = self.nodes[2].add_p2p_connection(BaseNode())
        p2p2.send_header_for_blocks(self.blocks[0:200])
        with self.nodes[2].assert_debug_log(expected_msgs=[
            f"Enabling script verification at block #1 ({block_1_hash}): block too recent relative to best header.",
        ]):
            p2p2.send_and_ping(msg_block(self.blocks[0]))
        with self.nodes[2].assert_debug_log(expected_msgs=[
            "Block validation error: block-script-verify-flag-failed",
        ]):
            for i in range(1, 103):
                p2p2.send_without_ping(msg_block(self.blocks[i]))
            p2p2.wait_for_disconnect()
            assert_equal(self.nodes[2].getblockcount(), COINBASE_MATURITY + 1)
            assert_equal(next(filter(lambda x: x["hash"] == self.blocks[199].hash_hex, self.nodes[2].getchaintips()))["status"], "invalid")

        # nodes[3]
        self.log.info("Send two header chains, and a block not in the best header chain to node3.")
        best_hash = self.nodes[3].getbestblockhash()
        tip_block = self.nodes[3].getblock(best_hash)
        _second_chain_tip, _second_chain_time, _second_chain_height = int(best_hash, 16), tip_block["time"] + 1, tip_block["height"] + 1
        second_chain = create_pocx_branch(self.nodes[3], int(best_hash, 16), 150)
        # A distinct first coinbase makes this an independent competing branch.
        second_chain[0].vtx[0].vin[0].scriptSig += b'\x00'
        self.prepare_native_chain(second_chain, int(best_hash, 16), tip_block['time'])
        p2p3 = self.nodes[3].add_p2p_connection(BaseNode())
        p2p3.send_header_for_blocks(second_chain)
        p2p3.send_header_for_blocks(self.blocks[0:103])
        with self.nodes[3].assert_debug_log(expected_msgs=[
            f"Enabling script verification at block #1 ({block_1_hash}): block not in best header chain.",
        ]):
            p2p3.send_and_ping(msg_block(self.blocks[0]))
            assert_equal(self.nodes[3].getblockcount(), 1)

        # nodes[4]
        self.log.info("Send a block not in the assumevalid header chain to node4.")
        genesis_hash = self.nodes[4].getbestblockhash()
        genesis_time = self.nodes[4].getblock(genesis_hash)['time']
        alt1 = create_pocx_branch(self.nodes[4], int(genesis_hash, 16), 1)[0]
        alt1.vtx[0].vin[0].scriptSig += b'\x00\x00'
        self.prepare_native_chain([alt1], int(genesis_hash, 16), genesis_time)
        p2p4 = self.nodes[4].add_p2p_connection(BaseNode())
        p2p4.send_header_for_blocks(self.blocks[0:103])
        with self.nodes[4].assert_debug_log(expected_msgs=[
            f"Enabling script verification at block #1 ({alt1.hash_hex}): block not in assumevalid chain.",
        ]):
            p2p4.send_and_ping(msg_block(alt1))
            assert_equal(self.nodes[4].getblockcount(), 1)

        # nodes[5]
        self.log.info("Reindex to hit specific assumevalid gates (no races with header downloads/chainwork during startup).")
        p2p5 = self.nodes[5].add_p2p_connection(BaseNode())
        p2p5.send_header_for_blocks(self.blocks[0:200])
        p2p5.send_without_ping(msg_block(self.blocks[0]))
        self.wait_until(lambda: self.nodes[5].getblockcount() == 1)
        with self.nodes[5].assert_debug_log(expected_msgs=[
            f"Enabling script verification at block #1 ({block_1_hash}): assumevalid hash not in headers.",
        ]):
            self.restart_node(5, extra_args=["-reindex-chainstate", "-assumevalid=1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"])
            assert_equal(self.nodes[5].getblockcount(), 1)
        with self.nodes[5].assert_debug_log(expected_msgs=[
            f"Enabling script verification at block #1 ({block_1_hash}): best header chainwork below minimumchainwork.",
        ]):
            self.restart_node(5, extra_args=["-reindex-chainstate", f"-assumevalid={block102.hash_hex}", f"-minimumchainwork={hex(201 * ((1 << 64) // ((1 << 58) // 120)) + 1)}"])
            assert_equal(self.nodes[5].getblockcount(), 1)


if __name__ == '__main__':
    AssumeValidTest(__file__).main()
