#!/usr/bin/env python3
# Copyright (c) 2025-present The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test coinstatsindex across node versions.

This test may be removed some time after v29 has reached end of life.
"""

from copy import deepcopy
from decimal import Decimal
from io import BytesIO
import shutil

from test_framework.bitcoin_test_node import TestNode as BitcoinTestNode
from test_framework.blocktools import bitcoin_block_with_shared_coinbase
from test_framework.messages import CBlock, COIN
from test_framework.test_framework import BitcoinTestFramework
from test_framework.test_node import TestNode
from test_framework.util import assert_equal


def expected_bitcoin_stats(native_stats, bitcoin_bestblock):
    """Keep every field, accounting explicitly for both subsidy schedules."""
    result = deepcopy(native_stats)
    result['bestblock'] = bitcoin_bestblock
    height = native_stats['height']
    def subsidy_difference(h):
        return Decimal((50 * COIN >> (h // 150)) - (10 * COIN >> (h // 500))) / COIN
    result['total_unspendable_amount'] += sum(subsidy_difference(h) for h in range(height + 1))
    result['block_info']['unspendable'] += subsidy_difference(height)
    category = 'genesis_block' if height == 0 else 'unclaimed_rewards'
    result['block_info']['unspendables'][category] += subsidy_difference(height)
    return result


class CoinStatsIndexTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 2
        self.setup_clean_chain = True
        self.pocx_synchronized_generation = True
        self.supports_cli = False
        self.extra_args = [["-coinstatsindex"],["-coinstatsindex"]]

    def skip_test_if_missing_module(self):
        self.skip_if_no_previous_releases()

    def setup_nodes(self):
        self.add_nodes(
            self.num_nodes,
            extra_args=self.extra_args,
            versions=[
                None,
                280200,
            ],
            node_classes=[TestNode, BitcoinTestNode],
        )
        self.start_nodes()

    def setup_network(self):
        self.setup_nodes()
        node, legacy_node = self.nodes
        # Reproduce the original 199-block inventory with identical coinbase
        # transactions on independent chains. Old Bitcoin cannot read native
        # cached headers. Shared outpoints retain the full MuHash comparison.
        for _ in range(199):
            blockhash = self.generate(node, 1, sync_fun=self.no_op)[0]
            block = CBlock()
            block.deserialize(BytesIO(bytes.fromhex(node.getblock(blockhash, 0))))
            assert_equal(len(block.vtx), 1)
            legacy_node.setmocktime(node.mocktime)
            bitcoin_block = bitcoin_block_with_shared_coinbase(
                block.vtx[0], legacy_node.getblocktemplate({'rules': ['segwit']}))
            assert_equal(legacy_node.submitblock(bitcoin_block.serialize().hex()), None)
        assert_equal(node.getblockcount(), 199)
        assert_equal(legacy_node.getblockcount(), 199)
        assert node.getblockhash(0) != legacy_node.getblockhash(0)

    def run_test(self):
        self._test_coin_stats_index_compatibility()

    def _test_coin_stats_index_compatibility(self):
        node = self.nodes[0]
        legacy_node = self.nodes[1]
        for n in self.nodes:
            self.wait_until(lambda: n.getindexinfo()['coinstatsindex']['synced'] is True)

        self.log.info("Test that gettxoutsetinfo() output is consistent between the different index versions")
        res0 = node.gettxoutsetinfo('muhash')
        res1 = legacy_node.gettxoutsetinfo('muhash')
        # Compare every field. Only block identity and independently calculated
        # subsidy underclaims differ: old Bitcoin allows 50 coins, PoCX 10.
        # Bitcoin regtest halves at height150, native regtest at500. Genesis is
        # unspendable too. Keep both independently specified subsidy schedules.
        assert_equal(res0['bestblock'], node.getbestblockhash())
        expected_legacy = expected_bitcoin_stats(res0, legacy_node.getbestblockhash())
        assert_equal(res1, expected_legacy)

        self.log.info("Test that gettxoutsetinfo() output is consistent for the new index running on a datadir with the old version")
        self.stop_nodes()
        shutil.rmtree(node.chain_path / "indexes" / "coinstatsindex")
        shutil.copytree(legacy_node.chain_path / "indexes" / "coinstats", node.chain_path / "indexes" / "coinstats")
        old_version_path = node.chain_path / "indexes" / "coinstats"
        msg = f'[warning] Old version of coinstatsindex found at {old_version_path}. This folder can be safely deleted unless you plan to downgrade your node to version 29 or lower.'
        with node.assert_debug_log(expected_msgs=[msg]):
            self.start_node(0, ['-coinstatsindex'])
        self.wait_until(lambda: node.getindexinfo()['coinstatsindex']['synced'] is True)
        res2 = node.gettxoutsetinfo('muhash')
        assert_equal(res2, res0)


if __name__ == '__main__':
    CoinStatsIndexTest(__file__).main()
