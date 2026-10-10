#!/usr/bin/env python3
# Copyright (c) 2019-present The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test bitcoind aborts if can't disconnect a block.

- Start a single node and generate 3 blocks.
- Delete the undo data.
- Mine a fork that requires disconnecting the tip.
- Verify that bitcoind AbortNode's.
"""
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, p2p_port


class AbortNodeTest(BitcoinTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 2

    def setup_network(self):
        self.setup_nodes()
        # We'll connect the nodes later

    def run_test(self):
        self.generate(self.nodes[0], 3, sync_fun=self.no_op)

        # Deleting the undo file will result in reorg failure
        (self.nodes[0].blocks_path / "rev00000.dat").unlink()

        # Connecting to a node with a more work chain will trigger a reorg
        # attempt.
        self.generate(self.nodes[1], 3, sync_fun=self.no_op)
        assert_equal(self.nodes[0].getblockcount(), 3)
        assert_equal(self.nodes[1].getblockcount(), 3)
        assert self.nodes[0].getbestblockhash() != self.nodes[1].getbestblockhash()
        # PoCX generation advances the miner's clock to its capacity deadline.
        # Finish the longer competing branch while disconnected, then align the
        # receiving fixture clock before delivering it. Otherwise the 15-second
        # future-header rule rejects it before reaching missing-undo recovery.
        self.generate(self.nodes[1], 1, sync_fun=self.no_op)
        assert_equal(self.nodes[1].getblockcount(), 4)
        fork_time = self.nodes[1].getblockheader(self.nodes[1].getbestblockhash())["time"]
        self.nodes[0].setmocktime(fork_time)
        with self.nodes[0].assert_debug_log(["Failed to disconnect block"]):
            # The expected abort may precede connect_nodes' RPC handshake wait.
            # Request the ordinary P2P connection and check the actual fatal
            # error/exit below instead of polling an RPC server that must die.
            self.nodes[0].addnode(f"127.0.0.1:{p2p_port(1)}", "onetry")

            # Check that node0 aborted
            self.log.info("Waiting for crash")
            self.nodes[0].wait_until_stopped(timeout=5, expect_error=True, expected_stderr="Error: A fatal internal error occurred, see debug.log for details: Failed to disconnect block.")
        self.log.info("Node crashed - now verifying restart fails")
        self.nodes[0].assert_start_raises_init_error()


if __name__ == '__main__':
    AbortNodeTest(__file__).main()
