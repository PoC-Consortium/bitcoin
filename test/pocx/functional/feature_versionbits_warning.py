#!/usr/bin/env python3
# Copyright (c) 2016-present The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test version bits warning system.

Generate chains with block versions that appear to be signalling unknown
soft-forks, and test that warning alerts are generated.
"""
import os
import re

from test_framework.blocktools import create_empty_fork, resign_pocx_block
from test_framework.messages import NODE_NONE, msg_block
from test_framework.p2p import P2PInterface
from test_framework.test_framework import BitcoinTestFramework

# Unknown-warning periods on test chains use DifficultyAdjustmentInterval(),
# independently of the144-block known-deployment period. Native regtest uses
# one day /120seconds =720blocks and the same75% warning threshold.
VB_PERIOD = 24 * 60 * 60 // 120
VB_THRESHOLD = VB_PERIOD * 3 // 4
VB_TOP_BITS = 0x20000000
VB_UNKNOWN_BIT = 27       # Choose a bit unassigned to any deployment
VB_UNKNOWN_VERSION = VB_TOP_BITS | (1 << VB_UNKNOWN_BIT)

WARN_UNKNOWN_RULES_ACTIVE = f"Unknown new rules activated (versionbit {VB_UNKNOWN_BIT})"
VB_PATTERN = re.compile("Unknown new rules activated.*versionbit")

class VersionBitsWarningTest(BitcoinTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.pocx_synchronized_generation = True
        self.num_nodes = 1

    def setup_network(self):
        self.alert_filename = os.path.join(self.options.tmpdir, "alert.txt")
        # Open and close to create zero-length file
        with open(self.alert_filename, 'w'):
            pass
        self.extra_args = [[f"-alertnotify=echo %s >> \"{self.alert_filename}\""]]
        self.setup_nodes()

    def send_blocks_with_version(self, peer, numblocks, version):
        """Send numblocks blocks to peer with version set"""
        tip = self.nodes[0].getbestblockhash()
        height = self.nodes[0].getblockcount()
        _block_time = self.nodes[0].getblockheader(tip)["time"] + 1
        tip = int(tip, 16)

        native_blocks = create_empty_fork(self.nodes[0], fork_length=numblocks)
        self.nodes[0].setmocktime(max(self.nodes[0].mocktime or 0, native_blocks[-1].nTime))
        for block in native_blocks:
            block.hashPrevBlock = tip
            block.nVersion = version
            resign_pocx_block(block)
            peer.send_without_ping(msg_block(block))
            height += 1
            tip = block.hash_int
        peer.sync_with_ping()

    def versionbits_in_alert_file(self):
        """Test that the versionbits warning has been written to the alert file."""
        with open(self.alert_filename, 'r') as f:
            alert_text = f.read()
        return VB_PATTERN.search(alert_text) is not None

    def run_test(self):
        node = self.nodes[0]
        peer = node.add_p2p_connection(P2PInterface(), services=NODE_NONE)

        node_deterministic_address = node.get_deterministic_priv_key().address
        # Mine one period worth of blocks
        self.generatetoaddress(node, VB_PERIOD, node_deterministic_address)

        self.log.info("Check that there is no warning if previous VB_BLOCKS have <VB_THRESHOLD blocks with unknown versionbits version.")
        # Build one period of blocks with < VB_THRESHOLD blocks signaling some unknown bit
        self.send_blocks_with_version(peer, VB_THRESHOLD - 1, VB_UNKNOWN_VERSION)
        self.generatetoaddress(node, VB_PERIOD - VB_THRESHOLD + 1, node_deterministic_address)

        # Check that we're not getting any versionbit-related errors in get*info()
        assert not VB_PATTERN.match(",".join(node.get_mining_info()["warnings"]))
        assert not VB_PATTERN.match(",".join(node.getnetworkinfo()["warnings"]))

        # Build one period of blocks with VB_THRESHOLD blocks signaling some unknown bit
        self.send_blocks_with_version(peer, VB_THRESHOLD, VB_UNKNOWN_VERSION)
        self.generatetoaddress(node, VB_PERIOD - VB_THRESHOLD, node_deterministic_address)

        self.log.info("Check that there is a warning if previous VB_BLOCKS have >=VB_THRESHOLD blocks with unknown versionbits version.")
        # Mine a period worth of expected blocks so the generic block-version warning
        # is cleared. This will move the versionbit state to ACTIVE.
        self.generatetoaddress(node, VB_PERIOD, node_deterministic_address)

        # Stop-start the node. This is required because bitcoind will only warn once about unknown versions or unknown rules activating.
        self.restart_node(0)

        # Generating one block guarantees that we'll get out of IBD
        self.generatetoaddress(node, 1, node_deterministic_address)
        self.wait_until(lambda: not node.getblockchaininfo()['initialblockdownload'])
        # Generating one more block will be enough to generate an error.
        self.generatetoaddress(node, 1, node_deterministic_address)
        # Check that get*info() shows the versionbits unknown rules warning
        assert WARN_UNKNOWN_RULES_ACTIVE in ",".join(node.get_mining_info()["warnings"])
        assert WARN_UNKNOWN_RULES_ACTIVE in ",".join(node.getnetworkinfo()["warnings"])
        # Check that the alert file shows the versionbits unknown rules warning
        self.wait_until(lambda: self.versionbits_in_alert_file())

        # The native mining RPC must retain the shared deprecated warning format.
        self.restart_node(0, extra_args=[*self.extra_args[0], '-deprecatedrpc=warnings'])
        self.generatetoaddress(node, 2, node_deterministic_address)
        mining_warning = node.get_mining_info()['warnings']
        assert isinstance(mining_warning, str)
        assert WARN_UNKNOWN_RULES_ACTIVE in mining_warning
        assert mining_warning == node.getnetworkinfo()['warnings']

if __name__ == '__main__':
    VersionBitsWarningTest(__file__).main()
