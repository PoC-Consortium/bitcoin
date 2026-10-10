#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin PoCX developers
# Distributed under the MIT software license; see COPYING.
"""Shared wallet, assignment conflicts and partitions from the multinode attack script."""
from decimal import Decimal
from feature_pocx_assignment_multinode import AssignmentMultinodeTest
from test_framework.util import assert_equal, assert_raises_rpc_error


class MultinodeAttacksTest(AssignmentMultinodeTest):
    def set_test_params(self):
        super().set_test_params()
        self.wallet_names = [self.default_wallet_name, self.default_wallet_name]
        self.extra_args[1] = ['-mocktime=2031536000', '-maxtipage=34560000', '-fallbackfee=0.00001']

    def run_test(self):
        first, second = self.nodes
        funding = first.get_wallet_rpc(self.default_wallet_name)
        wallet2 = second.get_wallet_rpc(self.default_wallet_name)
        mining = funding.getnewaddress('', 'bech32')
        def mine(count=1, connected=True):
            return self.generatetoaddress(first, count, mining, sync_fun=None if connected else self.no_op)
        mine(111)
        first.createwallet('wallet1')
        wallet = first.get_wallet_rpc('wallet1')
        funded1 = funding.sendtoaddress(wallet.getnewaddress('', 'bech32'), 10)
        mine()
        change = [{'txid': u['txid'], 'vout': u['vout']} for u in funding.listunspent() if u['txid'] == funded1]
        if change:
            funding.lockunspent(False, change)
        funded2 = funding.sendtoaddress(wallet2.getnewaddress('', 'bech32'), 10)
        mine()
        funding.lockunspent(True)
        inputs2 = first.decoderawtransaction(funding.gettransaction(funded2)['hex'])['vin']
        assert all(v['txid'] != funded1 for v in inputs2)
        assert_equal(wallet.getbalance(), 10)
        assert_equal(wallet2.getbalance(), 10)

        self.log.info('1: restore the same private descriptors on the second node')
        second.createwallet('imported', blank=True, descriptors=True)
        backup = second.get_wallet_rpc('imported')
        descriptors = wallet.listdescriptors(True)['descriptors']
        imports = [{**d, 'timestamp': 0, 'range': [0, 1000]} for d in descriptors]
        results = backup.importdescriptors(imports)
        assert all(item['success'] for item in results), results
        assert_equal(backup.getbalance(), 10)
        forge1 = wallet.getnewaddress('', 'bech32')
        forge2 = wallet2.getnewaddress('', 'bech32')

        def funded_plot():
            plot = wallet.getnewaddress('', 'bech32')
            wallet.sendtoaddress(plot, 1)
            mine()
            assert backup.getaddressinfo(plot)['ismine']
            assert any(u['address'] == plot for u in backup.listunspent())
            return plot

        def parity(plot, signer, state):
            a, b = [n.get_assignment(plot) for n in self.nodes]
            assert_equal(a, b)
            assert_equal(a['state'], state)
            assert_equal(a['forging_address'], signer)

        self.log.info('2: conflicting assignments from the same restored wallet')
        plot = funded_plot()
        # A partition ensures both submissions exist before either receives the
        # other: this preserves the wrapper's both-created conflict branch.
        self.disconnect_nodes(0, 1)
        tx1 = wallet.create_assignment(plot, forge1, Decimal('0.0001'))['txid']
        tx2 = backup.create_assignment(plot, forge2, Decimal('0.0001'))['txid']
        assert tx1 != tx2
        assert tx1 in first.getrawmempool() and tx2 in second.getrawmempool()
        raw1 = first.decoderawtransaction(wallet.gettransaction(tx1)['hex'])
        raw2 = second.decoderawtransaction(backup.gettransaction(tx2)['hex'])
        assert {(v['txid'], v['vout']) for v in raw1['vin']} & {(v['txid'], v['vout']) for v in raw2['vin']}
        mine(connected=False)
        self.connect_nodes(0, 1)
        self.sync_blocks()
        assert tx2 not in second.getrawmempool()
        parity(plot, forge1, 'ASSIGNING')
        mine(4)
        parity(plot, forge1, 'ASSIGNED')

        self.log.info('3: active assignment revocation versus reassignment')
        plot2 = funded_plot()
        wallet.create_assignment(plot2, forge1, Decimal('0.0001'))
        mine(5)
        parity(plot2, forge1, 'ASSIGNED')
        wallet.sendtoaddress(plot2, 1)
        mine()
        self.disconnect_nodes(0, 1)
        revoke = wallet.revoke_assignment(plot2, Decimal('0.0001'))['txid']
        assert revoke in first.getrawmempool()
        assert_raises_rpc_error(-26, 'plot-not-available-for-assignment', backup.create_assignment,
                                plot2, forge2, Decimal('0.0001'))
        self.connect_nodes(0, 1)
        mine()
        parity(plot2, forge1, 'REVOKING')

        self.log.info('4: partitioned node cannot spend funding it has not received')
        self.disconnect_nodes(0, 1)
        plot3 = wallet.getnewaddress('', 'bech32')
        wallet.sendtoaddress(plot3, 1)
        mine(connected=False)
        assignment3 = wallet.create_assignment(plot3, forge1, Decimal('0.0001'))['txid']
        mine(connected=False)
        assert assignment3 in first.getblock(first.getbestblockhash())['tx']
        assert_equal(second.get_assignment(plot3)['state'], 'UNASSIGNED')
        assert not any(u['address'] == plot3 for u in backup.listunspent())
        assert_raises_rpc_error(-4, 'No coins available at the plot address', backup.create_assignment, plot3, forge2, Decimal('0.0001'))
        self.connect_nodes(0, 1)
        self.sync_blocks()
        parity(plot3, forge1, 'ASSIGNING')

        self.log.info('5: disconnected mempool assignment relays and confirms after reconnect')
        plot4 = funded_plot()
        self.disconnect_nodes(0, 1)
        tx4 = wallet.create_assignment(plot4, forge1, Decimal('0.0001'))['txid']
        assert tx4 in first.getrawmempool()
        assert tx4 not in second.getrawmempool()
        self.connect_nodes(0, 1)
        # Normal unbroadcast retry runs every 10-15 minutes on CScheduler.
        first.mockscheduler(901)
        self.sync_mempools()
        assert tx4 in second.getrawmempool()
        mine()
        parity(plot4, forge1, 'ASSIGNING')
        assert all(n.verifychain(4, 0) for n in self.nodes)


if __name__ == '__main__':
    MultinodeAttacksTest(__file__).main()
