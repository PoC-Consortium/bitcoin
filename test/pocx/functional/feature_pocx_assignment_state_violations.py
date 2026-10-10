#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin PoCX developers
# Distributed under the MIT software license; see COPYING.
"""All seven wrapper state violations, checked at mempool and block construction."""
from decimal import Decimal
import re
from test_framework.authproxy import JSONRPCException
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_raises_rpc_error


class AssignmentStateViolationsTest(BitcoinTestFramework):
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

        def mine(count):
            self.generatetoaddress(node, count, mining)

        def fund(plot):
            existing = node.listunspent(1, 9999999, [plot])
            reserved = [{'txid': u['txid'], 'vout': u['vout']} for u in existing]
            if reserved:
                node.lockunspent(False, reserved)
            try:
                node.sendtoaddress(plot, Decimal('1'))
                mine(1)
            finally:
                if reserved:
                    node.lockunspent(True, reserved)
            assert_equal(len(node.listunspent(1, 9999999, [plot])), len(existing) + 1)

        mine(101)
        cases = [('assign', s) for s in ('ASSIGNING', 'ASSIGNED', 'REVOKING')]
        cases += [('revoke', s) for s in ('UNASSIGNED', 'ASSIGNING', 'REVOKING', 'REVOKED')]
        for action, state in cases:
            self.log.info(f'{action} in {state}: preserve setup, reject in mempool and block construction')
            plot, forge, other_forge = [node.getnewaddress('', 'bech32') for _ in range(3)]
            fund(plot)
            if action == 'assign' and state == 'ASSIGNING':
                fund(plot)  # Two confirmed inputs before entering ASSIGNING.
            if state != 'UNASSIGNED':
                first = node.create_assignment(plot, forge, Decimal('0.0001'))['txid']
                assert first in node.getrawmempool()
                mine(1 if state == 'ASSIGNING' else 5)
            if state in ('REVOKING', 'REVOKED'):
                fund(plot)
                revoke = node.revoke_assignment(plot, Decimal('0.0001'))['txid']
                assert revoke in node.getrawmempool()
                mine(1 if state == 'REVOKING' else 10)
            assert_equal(node.get_assignment(plot)['state'], state)
            if not (action == 'assign' and state == 'ASSIGNING') and state != 'UNASSIGNED':
                fund(plot)
            assert_equal(node.get_assignment(plot)['state'], state)
            reason = 'plot-not-available-for-assignment' if action == 'assign' else 'cannot-revoke-inactive'
            try:
                if action == 'assign':
                    node.create_assignment(plot, other_forge, Decimal('0.0001'))
                else:
                    node.revoke_assignment(plot, Decimal('0.0001'))
            except JSONRPCException as error:
                # Current wallet RPC records the candidate, then reports failed
                # broadcast. Recover that signed candidate for both lower layers.
                assert_equal(error.error['code'], -26)
                assert reason in error.error['message'], error.error
                match = re.search(r'Transaction ([0-9a-f]{64}) was recorded', error.error['message'])
                assert match, error.error
                raw = node.gettransaction(match[1])['hex']
            else:
                raise AssertionError('Wallet RPC accepted invalid state transition')
            txid = node.decoderawtransaction(raw)['txid']
            accepted = node.testmempoolaccept([raw])[0]
            assert_equal(accepted['allowed'], False)
            assert reason in accepted['reject-reason'], accepted
            assert_raises_rpc_error(-26, reason, node.sendrawtransaction, raw)
            assert txid not in node.getrawmempool()
            old_tip = node.getbestblockhash()
            try:
                result = self.generateblock(node, mining, [raw])
            except JSONRPCException as error:
                assert reason in error.error['message'], error.error
                assert_equal(node.getbestblockhash(), old_tip)
            else:
                # Preserve the legacy alternative: exclusion is acceptable only
                # if the generated block contains precisely its coinbase.
                block = node.getblock(result['hash'], 2)
                assert_equal(len(block['tx']), 1)
                assert txid not in [tx['txid'] for tx in block['tx']]
            assert_equal(node.get_assignment(plot)['state'], state)


if __name__ == '__main__':
    AssignmentStateViolationsTest(__file__).main()
