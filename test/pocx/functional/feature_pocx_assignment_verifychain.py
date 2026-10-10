#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin PoCX developers
# Distributed under the MIT software license; see COPYING.
"""Level-4 reconnect-cache regression plus genuine same-block conflicts."""
from decimal import Decimal
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_raises_rpc_error


class AssignmentVerifychainTest(BitcoinTestFramework):
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
            self.generatetoaddress(node, count, mining)

        def fund(plot, lock=False):
            txid = node.sendtoaddress(plot, Decimal('1'))
            mine(1)
            outputs = node.gettransaction(txid, True, True)['decoded']['vout']
            matches = [out['n'] for out in outputs if out['scriptPubKey'].get('address') == plot]
            assert_equal(len(matches), 1)
            outpoint = {'txid': txid, 'vout': matches[0]}
            if lock:
                node.lockunspent(False, [outpoint])
            return outpoint

        def verify(depth):
            tip = node.getbestblockhash()
            with node.assert_debug_log([f'Verifying last {depth} blocks at level 4',
                                        f'No coin database inconsistencies in last {depth} blocks']):
                assert_equal(node.verifychain(4, depth), True)
            assert_equal(node.getbestblockhash(), tip)

        def raw_marker(plot, outpoint, marker):
            raw = node.createrawtransaction([outpoint], [{'data': marker}, {plot: Decimal('0.999')}])
            signed = node.signrawtransactionwithwallet(raw)
            assert_equal(signed['complete'], True)
            return signed['hex']

        def reject(raws):
            tip = node.getbestblockhash()
            assert_raises_rpc_error(-25, 'TestBlockValidity failed:', self.generateblock, node, mining, raws)
            assert_equal(node.getbestblockhash(), tip)

        mine(101)
        forge, plot = address(), address()
        fund(plot)
        node.create_assignment(plot, forge, Decimal('0.0001'))
        mine(1)
        assignment_height = node.getblockcount()
        mine(4)
        assert_equal(node.get_assignment(plot)['state'], 'ASSIGNED')
        fund(plot)
        node.revoke_assignment(plot, Decimal('0.0001'))
        mine(1)
        assert_equal(node.get_assignment(plot)['state'], 'REVOKING')
        self.log.info('Level-4 reconnection of revocation alone and full assignment span')
        verify(1)
        verify(node.getblockcount() - assignment_height + 1)

        plot2, plot3 = address(), address()
        u2a, u2b = fund(plot2, True), fund(plot2, True)
        u3a, u3b, u3c = fund(plot3, True), fund(plot3, True), fund(plot3, True)
        node.lockunspent(True, [u3c])
        node.create_assignment(plot3, forge, Decimal('0.0001'))
        mine(5)
        assert_equal(node.get_assignment(plot3)['state'], 'ASSIGNED')
        w2, w3, wf = [node.validateaddress(a)['witness_program'] for a in (plot2, plot3, forge)]
        a2a = raw_marker(plot2, u2a, '504f4358' + w2 + wf)
        a2b = raw_marker(plot2, u2b, '504f4358' + w2 + wf)
        self.log.info('Genuine same-block conflicts remain rejected')
        reject([a2a, a2b])
        r3 = raw_marker(plot3, u3a, '58434f50' + w3)
        a3 = raw_marker(plot3, u3b, '504f4358' + w3 + wf)
        reject([r3, a3])
        node.lockunspent(True)
        result = self.generateblock(node, mining, [a2a])
        assert node.decoderawtransaction(a2a)['txid'] in node.getblock(result['hash'])['tx']
        assert_equal(node.get_assignment(plot2)['state'], 'ASSIGNING')
        verify(3)


if __name__ == '__main__':
    AssignmentVerifychainTest(__file__).main()
