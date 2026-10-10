#!/usr/bin/env python3
# Copyright (c) The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test that the correct active block is chosen in complex reorgs."""

from copy import deepcopy

from test_framework.blocktools import create_pocx_block, resign_pocx_block
from test_framework.messages import CBlock, CBlockHeader, from_hex
from test_framework.script import CScript
from test_framework.p2p import P2PDataStore
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal

class ChainTiebreaksTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 2
        self.setup_clean_chain = True
        self.pocx_synchronized_generation = True

    def setup_network(self):
        self.setup_nodes()

    @staticmethod
    def send_headers(node, blocks):
        """Submit headers for blocks to node."""
        for block in blocks:
            # Use RPC rather than P2P, to prevent the message from being interpreted as a block
            # announcement.
            assert_equal(node.submitheader(hexdata=CBlockHeader(block).serialize().hex()), None)
        for height in {block.nHeight for block in blocks}:
            assert_equal(len({node.getblockheader(block.hash_hex)['chainwork'] for block in blocks if block.nHeight == height}), 1)

    def test_chain_split_in_memory(self):
        node = self.nodes[0]
        # Add P2P connection to bitcoind
        peer = node.add_p2p_connection(P2PDataStore())

        self.log.info('Precomputing blocks')
        #
        #          /- B3 -- B7
        #        B1      \- B8
        #       /  \
        #      /    \ B4 -- B9
        #   B0           \- B10
        #      \
        #       \  /- B5
        #        B2
        #          \- B6
        #
        blocks = []

        # Independently accept one native proof per depth on the disconnected
        # second node. Keep all timestamp/difficulty/proof histories by depth,
        # varying only coinbase tags and linked parent hashes for the binary tree.
        source_tip = node.getbestblockhash()
        producer = self.nodes[1]
        hashes = self.generate(producer, 4, sync_fun=self.no_op)
        templates = [from_hex(CBlock(), producer.getblock(blockhash, 0)) for blockhash in hashes]
        assert producer.verifychain(4, 0)
        producer.invalidateblock(hashes[0])
        assert_equal(producer.getblockcount(), 0)
        assert_equal(node.getbestblockhash(), source_tip)
        for i in range(11):
            depth = (i + 1).bit_length() - 1
            block = deepcopy(templates[depth])
            block.hashPrevBlock = int(source_tip, 16) if i == 0 else blocks[(i - 1) >> 1].hash_int
            block.vtx[0].vin[0].scriptSig += CScript([i])
            block.hashMerkleRoot = block.calc_merkle_root()
            resign_pocx_block(block)
            blocks.append(block)
        assert_equal(len({block.hash_hex for block in blocks}), 11)
        node.setmocktime(max(node.mocktime, blocks[-1].nTime))

        self.log.info('Make sure B0 is accepted normally')
        peer.send_blocks_and_test([blocks[0]], node, success=True)
        # B0 must be active chain now.
        assert_equal(node.getbestblockhash(), blocks[0].hash_hex)

        self.log.info('Send B1 and B2 headers, and then blocks in opposite order')
        self.send_headers(node, blocks[1:3])
        peer.send_blocks_and_test([blocks[2]], node, success=True)
        peer.send_blocks_and_test([blocks[1]], node, success=False)
        # B2 must be active chain now, as full data for B2 was received first.
        assert_equal(node.getbestblockhash(), blocks[2].hash_hex)

        self.log.info('Send all further headers in order')
        self.send_headers(node, blocks[3:])
        # B2 is still the active chain, headers don't change this.
        assert_equal(node.getbestblockhash(), blocks[2].hash_hex)

        self.log.info('Send blocks B7-B10')
        peer.send_blocks_and_test([blocks[7]], node, success=False)
        peer.send_blocks_and_test([blocks[8]], node, success=False)
        peer.send_blocks_and_test([blocks[9]], node, success=False)
        peer.send_blocks_and_test([blocks[10]], node, success=False)
        # B2 is still the active chain, as B7-B10 have missing parents.
        assert_equal(node.getbestblockhash(), blocks[2].hash_hex)

        self.log.info('Send parents B3-B4 of B8-B10 in reverse order')
        peer.send_blocks_and_test([blocks[4]], node, success=False, force_send=True)
        peer.send_blocks_and_test([blocks[3]], node, success=False, force_send=True)
        # B9 is now active. Despite B7 being received earlier, the missing parent.
        assert_equal(node.getbestblockhash(), blocks[9].hash_hex)

        self.log.info('Invalidate B9-B10')
        node.invalidateblock(blocks[9].hash_hex)
        node.invalidateblock(blocks[10].hash_hex)
        # B7 is now active.
        assert_equal(node.getbestblockhash(), blocks[7].hash_hex)

        # Invalidate blocks to start fresh on the next test
        node.invalidateblock(blocks[0].hash_hex)

    def test_chain_split_from_disk(self):
        node = self.nodes[1]
        peer = node.add_p2p_connection(P2PDataStore())

        self.generate(node, 1, sync_fun=self.no_op)

        self.log.info('Precomputing blocks')
        #
        #            /- A1
        #           /
        #   G -- B1 --- A2
        #           \
        #            \- A3
        #
        blocks = []

        # Construct three equal-work blocks building from the tip.
        start_height = node.getblockcount()
        tip_block = node.getblock(node.getbestblockhash())
        _prev_time = tip_block["time"]

        template = create_pocx_block(node)
        for i in range(0, 3):
            block = deepcopy(template)
            block.vtx[0].vin[0].scriptSig += CScript([i])
            block.hashMerkleRoot = block.calc_merkle_root()
            resign_pocx_block(block)
            blocks.append(block)
        node.setmocktime(max(node.mocktime, template.nTime))
        assert_equal(len({block.hash_hex for block in blocks}), 3)

        # Send blocks and test that only the first one connects
        self.log.info('Send A1, A2, and A3. Make sure that only the former connects')
        peer.send_blocks_and_test([blocks[0]], node, success=True)
        peer.send_blocks_and_test([blocks[1]], node, success=False)
        peer.send_blocks_and_test([blocks[2]], node, success=False)
        assert_equal(len({node.getblockheader(block.hash_hex)['chainwork'] for block in blocks}), 1)

        # Restart and send a new block
        self.restart_node(1)
        assert_equal(blocks[0].hash_hex, node.getbestblockhash())
        peer = node.add_p2p_connection(P2PDataStore())
        next_block = create_pocx_block(node)
        assert_equal(next_block.hashPrevBlock, blocks[0].hash_int)
        assert_equal(next_block.nHeight, start_height + 2)
        node.setmocktime(max(node.mocktime, next_block.nTime))
        peer.send_blocks_and_test([next_block], node, success=True)

    def run_test(self):
        self.test_chain_split_in_memory()
        self.test_chain_split_from_disk()


if __name__ == '__main__':
    ChainTiebreaksTest(__file__).main()
