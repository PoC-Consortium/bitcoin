#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin PoCX developers
# Distributed under the MIT software license; see COPYING.
"""Both operation orders and duplicate assignment/revocation block rejection."""
from decimal import Decimal
import re
from test_framework.authproxy import JSONRPCException
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_raises_rpc_error


class AssignmentBlockConflictsTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.uses_wallet = True
        self.extra_args = [['-fallbackfee=0.00001']]

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def run_test(self):
        node = self.nodes[0]
        address = lambda: node.getnewaddress('', 'bech32')
        mining = address()

        def mine(count):
            return self.generatetoaddress(node, count, mining)

        def fund(plot, count):
            # Preserve every existing plot output during subsequent funding.
            locked = [{'txid': u['txid'], 'vout': u['vout']} for u in node.listunspent(1, 9999999, [plot])]
            if locked:
                node.lockunspent(False, locked)
            for _ in range(count):
                txid = node.sendtoaddress(plot, Decimal('1'))
                mine(1)
                coins = [u for u in node.listunspent(1, 9999999, [plot]) if u['txid'] == txid]
                assert_equal(len(coins), 1)
                outpoint = {'txid': txid, 'vout': coins[0]['vout']}
                node.lockunspent(False, [outpoint])
                locked.append(outpoint)
            node.lockunspent(True, locked)
            assert_equal(len(node.listunspent(1, 9999999, [plot])), len(locked))

        def rejected_candidate(rpc, reason, *args):
            try:
                rpc(*args)
            except JSONRPCException as exc:
                error = exc.error
                assert_equal(error['code'], -26)
                assert reason in error['message'], error
            else:
                raise AssertionError('Wallet accepted conflicting operation')
            match = re.search(r'Transaction ([0-9a-f]{64}) was recorded', error['message'])
            assert match, error
            txid = match[1]
            raw = node.gettransaction(txid)['hex']
            assert txid not in node.getrawmempool()
            assert_raises_rpc_error(-26, reason, node.sendrawtransaction, raw)
            return raw

        def reject_block(raws, reasons):
            # Distinct confirmed inputs: failure must be the assignment rule,
            # never a double-spend or missing-input fixture error.
            inputs = [(v['txid'], v['vout']) for raw in raws for v in node.decoderawtransaction(raw)['vin']]
            assert_equal(len(set(inputs)), len(inputs))
            before = node.getbestblockhash()
            try:
                self.generateblock(node, mining, raws)
            except JSONRPCException as error:
                assert_equal(error.error['code'], -25)
                assert any('TestBlockValidity failed: ' + reason in error.error['message'] for reason in reasons), error.error
            else:
                raise AssertionError('Invalid conflicting operations accepted in block')
            assert_equal(node.getbestblockhash(), before)

        mine(101)
        for reverse in (False, True):
            self.log.info(f'Unconfirmed assignment and revocation, reverse order={reverse}')
            plot, forge = address(), address()
            fund(plot, 2)
            assignment = node.create_assignment(plot, forge, Decimal('0.0001'))
            node.getmempoolentry(assignment['txid'])
            revoke = rejected_candidate(node.revoke_assignment, 'cannot-revoke-inactive', plot, Decimal('0.0001'))
            raws = [assignment['hex'], revoke]
            reject_block(list(reversed(raws)) if reverse else raws,
                         ['cannot-revoke-inactive', 'revoke-after-assign-in-block'])
            assert_equal(node.get_assignment(plot)['state'], 'UNASSIGNED')
            mine(6)
            assert_equal(node.get_assignment(plot)['state'], 'ASSIGNED')

        self.log.info('Duplicate assignment to distinct forging addresses')
        plot, forge1, forge2 = address(), address(), address()
        fund(plot, 2)
        first = node.create_assignment(plot, forge1, Decimal('0.0001'))
        node.getmempoolentry(first['txid'])
        second = rejected_candidate(node.create_assignment, 'assignment-conflict', plot, forge2, Decimal('0.0001'))
        reject_block([first['hex'], second], ['plot-not-available-for-assignment', 'duplicate-assignment-in-block'])
        mine(6)
        assert_equal(node.get_assignment(plot)['forging_address'], forge1)

        self.log.info('Duplicate revocation of an active assignment')
        plot, forge = address(), address()
        fund(plot, 3)
        node.create_assignment(plot, forge, Decimal('0.0001'))
        mine(5)
        assert_equal(node.get_assignment(plot)['state'], 'ASSIGNED')
        fund(plot, 2)
        first = node.revoke_assignment(plot, Decimal('0.0001'))
        node.getmempoolentry(first['txid'])
        second = rejected_candidate(node.revoke_assignment, 'revocation-conflict', plot, Decimal('0.0001'))
        reject_block([first['hex'], second], ['cannot-revoke-inactive', 'duplicate-revocation-in-block'])
        assert_equal(node.get_assignment(plot)['state'], 'ASSIGNED')
        mine(1)
        assert_equal(node.get_assignment(plot)['state'], 'REVOKING')


if __name__ == '__main__':
    AssignmentBlockConflictsTest(__file__).main()
