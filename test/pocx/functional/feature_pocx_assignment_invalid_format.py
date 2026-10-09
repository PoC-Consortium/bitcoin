#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin PoCX developers
# Distributed under the MIT software license; see COPYING.
"""Legacy malformed marker cases plus current-format length boundaries and control."""
from decimal import Decimal
from test_framework.authproxy import JSONRPCException
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal


class AssignmentInvalidFormatTest(BitcoinTestFramework):
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
        mining, forge = address(), address()
        forge_bytes = bytes.fromhex(node.validateaddress(forge)['witness_program'])

        def mine(count):
            return self.generatetoaddress(node, count, mining)

        mine(101)
        old_plot = bytes.fromhex('c081d70a692c2e8bdb5e57f2b8310a8fe421ad8bdb7c052401f28f5c44eaf5f0')
        reserved = bytes.fromhex('a30d89499f8000ca')
        old_payload = b'\x00' + old_plot + reserved
        cases = [
            ('legacy-wrong-magic', lambda p: b'DEAD' + old_payload),
            ('legacy-truncated', lambda p: b'POCX\x00' + old_plot),
            ('legacy-wrong-assignment-magic', lambda p: b'XCOP' + old_payload),
            ('legacy-oversized', lambda p: b'POCX' + old_payload + bytes.fromhex('deadbeef' * 4)),
            ('assignment-one-short', lambda p: (b'POCX' + p + forge_bytes)[:-1]),
            ('assignment-one-long', lambda p: b'POCX' + p + forge_bytes + b'\x00'),
            ('revocation-one-short', lambda p: (b'XCOP' + p)[:-1]),
            ('revocation-one-long', lambda p: b'XCOP' + p + b'\x00'),
            ('valid-assignment-control', lambda p: b'POCX' + p + forge_bytes),
        ]
        for label, marker in cases:
            self.log.info(label)
            plot = address()
            node.sendtoaddress(plot, Decimal('1'))
            mine(1)
            coins = node.listunspent(1, 9999999, [plot])
            assert_equal(len(coins), 1)
            coin = coins[0]
            plot_bytes = bytes.fromhex(node.validateaddress(plot)['witness_program'])
            raw = node.createrawtransaction([{'txid': coin['txid'], 'vout': coin['vout']}],
                                           [{'data': marker(plot_bytes).hex()},
                                            {forge: Decimal('0.0001')},
                                            {node.getrawchangeaddress(): Decimal('0.9998')}])
            signed = node.signrawtransactionwithwallet(raw)
            assert_equal(signed['complete'], True)
            valid_control = label == 'valid-assignment-control'
            try:
                txid = node.sendrawtransaction(signed['hex'])
            except JSONRPCException as error:
                assert not valid_control, error.error
                assert_equal(error.error['code'], -26)
                assert 'opreturn' in error.error['message'], error.error
            else:
                hashes = mine(5)
                assert any(txid in node.getblock(h)['tx'] for h in hashes)
            assert_equal(node.get_assignment(plot)['state'], 'ASSIGNED' if valid_control else 'UNASSIGNED')
            if valid_control:
                assert_equal(node.get_assignment(plot)['forging_address'], forge)


if __name__ == '__main__':
    AssignmentInvalidFormatTest(__file__).main()
