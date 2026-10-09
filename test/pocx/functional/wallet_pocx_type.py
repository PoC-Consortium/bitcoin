#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin PoCX developers
# Distributed under the MIT software license; see COPYING.
"""All five phases of wrapper assignments/test-wallet-rpc-pocx-type-v2.sh."""
from decimal import Decimal
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal


class WalletPoCXTypeTest(BitcoinTestFramework):
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

        def check(txid, expected):
            groups = [[node.gettransaction(txid)],
                      [row for row in node.listtransactions('*', 1000) if row['txid'] == txid],
                      [row for row in node.listsinceblock()['transactions'] if row['txid'] == txid]]
            for rows in groups:
                assert rows, f'Missing wallet RPC rows for {txid}'
                for row in rows:
                    if expected is None:
                        assert 'pocx_type' not in row
                    else:
                        assert_equal(row['pocx_type'], expected)

        self.log.info('Phase 1: bootstrap mature wallet and distinct addresses')
        mine(101)
        plot, forge, other = [node.getnewaddress('', 'bech32') for _ in range(3)]
        self.log.info('Phase 2: ordinary send before plot funding preserves plot UTXO')
        ordinary = node.sendtoaddress(other, Decimal('0.5'))
        mine(1)
        check(ordinary, None)
        self.log.info('Phase 3: funded plot and assignment classification in all RPC rows')
        node.sendtoaddress(plot, Decimal('1'))
        mine(1)
        assignment = node.create_assignment(plot, forge, Decimal('0.0001'))['txid']
        mine(1)
        check(assignment, 'assignment')
        self.log.info('Phase 4: refund plot, activate assignment and revoke')
        node.sendtoaddress(plot, Decimal('1'))
        mine(1)
        mine(4)
        revocation = node.revoke_assignment(plot, Decimal('0.0001'))['txid']
        mine(1)
        check(revocation, 'revocation')
        self.log.info('Phase 5: classification must not leak into ordinary transactions')
        check(ordinary, None)


if __name__ == '__main__':
    WalletPoCXTypeTest(__file__).main()
