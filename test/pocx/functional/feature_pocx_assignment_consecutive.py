#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin PoCX developers
# Distributed under the MIT software license; see COPYING.
"""Five consecutive cached assignments to one forging address (segfault regression)."""
from decimal import Decimal
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal


class ConsecutiveAssignmentTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.uses_wallet = True
        self.extra_args = [['-fallbackfee=0.00001']]

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def run_test(self):
        node = self.nodes[0]
        mining, forge = [node.getnewaddress('', 'bech32') for _ in range(2)]
        self.generatetoaddress(node, 101, mining)
        plots = [node.getnewaddress('', 'bech32') for _ in range(5)]
        node.sendmany('', {plot: Decimal('1') for plot in plots})
        self.generatetoaddress(node, 1, mining)
        assert_equal(len(node.listunspent(1, 9999999, plots)), 5)
        txids = []
        # No intervening block, flush or restart: all five creations hit cache.
        for plot in plots:
            txid = node.create_assignment(plot, forge, Decimal('0.0001'))['txid']
            txids.append(txid)
            node.getmempoolentry(txid)
        assert_equal(len(set(txids)), 5)
        block_hash = self.generatetoaddress(node, 1, mining)[0]
        block_txids = node.getblock(block_hash)['tx']
        for plot, txid in zip(plots, txids):
            assert txid in block_txids
            assert txid not in node.getrawmempool()
            assert_equal(node.gettransaction(txid)['confirmations'], 1)
            state = node.get_assignment(plot)
            assert_equal(state['state'], 'ASSIGNING')
            assert_equal(state['forging_address'], forge)
            assert_equal(state['assignment_txid'], txid)
        self.generatetoaddress(node, 4, mining)
        for plot in plots:
            assert_equal(node.get_assignment(plot)['state'], 'ASSIGNED')
            assert_equal(node.get_assignment(plot)['forging_address'], forge)


if __name__ == '__main__':
    ConsecutiveAssignmentTest(__file__).main()
