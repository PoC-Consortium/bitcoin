#!/usr/bin/env python3
# Copyright (c) 2019-present The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test that we reject low difficulty headers to prevent our block tree from filling up with useless bloat"""

from test_framework.test_framework import BitcoinTestFramework

from test_framework.p2p import (
    P2PInterface,
)

from test_framework.messages import (
    msg_headers,
)

from test_framework.blocktools import (
    create_pocx_branch,
    resign_pocx_block,
)

from test_framework.util import assert_equal

import time

NATIVE_BASE_TARGET = (1 << 58) // 120
NATIVE_BLOCK_WORK = (1 << 64) // NATIVE_BASE_TARGET

NODE1_BLOCKS_REQUIRED = 15
NODE2_BLOCKS_REQUIRED = 2047


class RejectLowDifficultyHeadersTest(BitcoinTestFramework):
    def set_test_params(self):
        self.rpc_timeout *= 4  # To avoid timeout when generating BLOCKS_TO_MINE
        self.setup_clean_chain = True
        self.pocx_synchronized_generation = False
        self.num_nodes = 4
        # Node0 has no required chainwork; node1 requires 15 blocks on top of the genesis block; node2 requires 2047
        self.extra_args = [["-minimumchainwork=0x0", "-checkblockindex=0"], [f"-minimumchainwork={hex(16 * NATIVE_BLOCK_WORK - 1)}", "-checkblockindex=0"], [f"-minimumchainwork={hex(2048 * NATIVE_BLOCK_WORK)}", "-checkblockindex=0"], [f"-minimumchainwork={hex(2048 * NATIVE_BLOCK_WORK)}", "-checkblockindex=0", "-whitelist=noban@127.0.0.1"]]

    def setup_network(self):
        self.setup_nodes()
        self.reconnect_all()
        self.sync_all()

    def disconnect_all(self):
        self.disconnect_nodes(0, 1)
        self.disconnect_nodes(0, 2)
        self.disconnect_nodes(0, 3)

    def reconnect_all(self):
        self.connect_nodes(0, 1)
        self.connect_nodes(0, 2)
        self.connect_nodes(0, 3)

    def mocktime_all(self, time):
        for n in self.nodes:
            n.setmocktime(time)

    def generate(self, node, count, sync_fun=None):
        # Historical600second intervals retain fixed native per-height work.
        # Restore the receiver's clock after each batch, so connected peers
        # don't experience multi-week timeout jumps during fixture production.
        clock = node.mocktime
        blocks = []
        try:
            for _ in range(count):
                parent = node.getblockheader(node.getbestblockhash())
                timestamp = parent['time'] + 600
                node.setmocktime(timestamp)
                block_hash = node.generate(1, called_by_framework=True)[0]
                header = node.getblockheader(block_hash)
                assert_equal(header['time'], timestamp)
                assert_equal(header['base_target'], NATIVE_BASE_TARGET)
                assert_equal(int(header['chainwork'], 16), (header['height'] + 1) * NATIVE_BLOCK_WORK)
                blocks.append(block_hash)
        finally:
            node.setmocktime(clock or 0)
        sync_fun() if sync_fun else self.sync_all()
        return blocks

    def test_chains_sync_when_long_enough(self):
        self.log.info("Generate blocks on the node with no required chainwork, and verify nodes 1 and 2 have no new headers in their headers tree")
        with (
                self.nodes[1].assert_debug_log(expected_msgs=["[net] Ignoring low-work chain (height=14)"], timeout=2),
                self.nodes[2].assert_debug_log(expected_msgs=["[net] Ignoring low-work chain (height=14)"], timeout=2),
                self.nodes[3].assert_debug_log(expected_msgs=["Synchronizing blockheaders, height: 14"], timeout=2),
        ):
            self.generate(self.nodes[0], NODE1_BLOCKS_REQUIRED-1, sync_fun=self.no_op)

        # Node3 should always allow headers due to noban permissions
        self.log.info("Check that node3 will sync headers (due to noban permissions)")

        def check_node3_chaintips(num_tips, tip_hash, height):
            node3_chaintips = self.nodes[3].getchaintips()
            assert len(node3_chaintips) == num_tips
            assert {
                'height': height,
                'hash': tip_hash,
                'branchlen': height,
                'status': 'headers-only',
            } in node3_chaintips

        check_node3_chaintips(2, self.nodes[0].getbestblockhash(), NODE1_BLOCKS_REQUIRED-1)

        for node in self.nodes[1:3]:
            chaintips = node.getchaintips()
            assert len(chaintips) == 1
            assert {
                'height': 0,
                'hash': self.nodes[0].getblockhash(0),
                'branchlen': 0,
                'status': 'active',
            } in chaintips

        self.log.info("Generate more blocks to satisfy node1's minchainwork requirement, and verify node2 still has no new headers in headers tree")
        with (
                self.nodes[2].assert_debug_log(expected_msgs=["[net] Ignoring low-work chain (height=15)"], timeout=2),
                self.nodes[3].assert_debug_log(expected_msgs=["Synchronizing blockheaders, height: 15"], timeout=2),
        ):
            self.generate(self.nodes[0], NODE1_BLOCKS_REQUIRED - self.nodes[0].getblockcount(), sync_fun=self.no_op)
        self.sync_blocks(self.nodes[0:2]) # node3 will sync headers (noban permissions) but not blocks (due to minchainwork)

        assert {
            'height': 0,
            'hash': self.nodes[0].getblockhash(0),
            'branchlen': 0,
            'status': 'active',
        } in self.nodes[2].getchaintips()

        assert len(self.nodes[2].getchaintips()) == 1

        self.log.info("Check that node3 accepted these headers as well")
        check_node3_chaintips(2, self.nodes[0].getbestblockhash(), NODE1_BLOCKS_REQUIRED)

        self.log.info("Generate long chain for node0/node1/node3")
        self.generate(self.nodes[0], NODE2_BLOCKS_REQUIRED-self.nodes[0].getblockcount(), sync_fun=self.no_op)

        self.log.info("Verify that node2 and node3 will sync the chain when it gets long enough")
        self.sync_blocks()

    def test_peerinfo_includes_headers_presync_height(self):
        self.log.info("Test that getpeerinfo() includes headers presync height")

        # Disconnect network, so that we can find our own peer connection more
        # easily
        self.disconnect_all()

        p2p = self.nodes[0].add_p2p_connection(P2PInterface())
        node = self.nodes[0]

        # Ensure we have a long chain already
        current_height = self.nodes[0].getblockcount()
        if (current_height < 3000):
            self.generate(node, 3000-current_height, sync_fun=self.no_op)

        # Send a group of 2000 headers, forking from genesis.
        parent = int(node.getblockhash(0), 16)
        genesis_time = node.getblockheader(node.getblockhash(0))['time']
        new_blocks = create_pocx_branch(node, parent, 2000)
        for offset, block in enumerate(new_blocks, 1):
            block.hashPrevBlock = parent
            block.nTime = genesis_time + 600 * offset
            block.nBaseTarget = NATIVE_BASE_TARGET
            resign_pocx_block(block)
            parent = block.hash_int
        assert_equal(len(new_blocks), 2000)
        assert_equal(node.getblockcount(), current_height)

        headers_message = msg_headers(headers=new_blocks)
        p2p.send_and_ping(headers_message)

        # getpeerinfo should show a sync in progress
        assert_equal(node.getpeerinfo()[0]['presynced_headers'], 2000)

    def test_large_reorgs_can_succeed(self):
        self.log.info("Test that a 2000+ block reorg, starting from a point that is more than 2000 blocks before a locator entry, can succeed")

        self.sync_all() # Ensure all nodes are synced.
        self.disconnect_all()

        # locator(block at height T) will have heights:
        # [T, T-1, ..., T-10, T-12, T-16, T-24, T-40, T-72, T-136, T-264,
        #  T-520, T-1032, T-2056, T-4104, ...]
        # So mine a number of blocks > 4104 to ensure that the first window of
        # received headers during a sync are fully between locator entries.
        BLOCKS_TO_MINE = 4110

        self.generate(self.nodes[0], BLOCKS_TO_MINE, sync_fun=self.no_op)
        self.generate(self.nodes[1], BLOCKS_TO_MINE+2, sync_fun=self.no_op)

        self.reconnect_all()

        self.mocktime_all(int(time.time()))  # Temporarily hold time to avoid internal timeouts
        self.sync_blocks(timeout=300) # Ensure tips eventually agree
        self.mocktime_all(0)


    def run_test(self):
        self.test_chains_sync_when_long_enough()

        self.test_large_reorgs_can_succeed()

        self.test_peerinfo_includes_headers_presync_height()



if __name__ == '__main__':
    RejectLowDifficultyHeadersTest(__file__).main()
