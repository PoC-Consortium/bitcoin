#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin PoCX developers
# Distributed under the MIT software license; see COPYING.
"""Two cycles, distinct forging addresses, and every historical state."""
from decimal import Decimal
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal


class AssignmentDoubleCycleTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.uses_wallet = True
        self.extra_args = [['-fallbackfee=0.00001']]

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def run_test(self):
        node = self.nodes[0]
        mining = node.getnewaddress('', 'bech32')
        history = []

        def mine(count):
            self.generatetoaddress(node, count, mining)

        def state(expected, forge=None, height=None):
            result = node.get_assignment(plot, *([] if height is None else [height]))
            assert_equal(result['state'], expected)
            if forge is not None:
                assert_equal(result['forging_address'], forge)

        def checkpoint(expected, forge=None):
            state(expected, forge)
            history.append((node.getblockcount(), expected, forge))

        mine(101)
        plot, forge1, forge2 = [node.getnewaddress('', 'bech32') for _ in range(3)]
        assert forge1 != forge2
        node.sendtoaddress(plot, Decimal('1'))
        mine(1)
        checkpoint('UNASSIGNED')
        for cycle, forge in enumerate([forge1, forge2], 1):
            self.log.info(f'Cycle {cycle}: assignment, activation, revocation and final state')
            if cycle == 2:
                node.sendtoaddress(plot, Decimal('1'))
                mine(2)
            assignment = node.create_assignment(plot, forge, Decimal('0.0001'))['txid']
            assert assignment in node.getrawmempool()
            mine(1)
            checkpoint('ASSIGNING', forge)
            mine(4)
            checkpoint('ASSIGNED', forge)
            node.sendtoaddress(plot, Decimal('1'))
            mine(2)
            revoke = node.revoke_assignment(plot, Decimal('0.0001'))['txid']
            assert revoke in node.getrawmempool()
            mine(1)
            checkpoint('REVOKING', forge)
            mine(8)
            checkpoint('REVOKED', forge)
        self.log.info('Historical verification of all nine recorded states and both signers')
        assert_equal(len(history), 9)
        for height, expected, forge in history:
            state(expected, forge, height)


if __name__ == '__main__':
    AssignmentDoubleCycleTest(__file__).main()
