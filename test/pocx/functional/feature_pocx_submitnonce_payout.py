#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin PoCX developers
# Distributed under the MIT software license; see COPYING.
"""All six payout RPC cases from test-regtest-submitnonce-payout-v2.sh.

This verifies parsing and acknowledgement, not eventual scheduler forging.
"""
from test_framework.descriptors import descsum_create
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_raises_rpc_error

WIF = 'cMvJbCxo3qCee5EFHSYVuK7UP69ijvHtXmrikzKtjbtEvzUYU5T5'


class SubmitNoncePayoutTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.uses_wallet = True

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def arguments(self):
        ctx = self.nodes[0].get_mining_info()
        return [ctx['block_hash'], ctx['height'], ctx['generation_signature'], ctx['base_target'],
                self.account, '00' * 32, 1, ctx['minimum_compression_level'], 0]

    def run_test(self):
        node = self.nodes[0]
        descriptor = f'wpkh({WIF})'
        imported = node.importdescriptors([{'desc': descsum_create(descriptor), 'timestamp': 'now'}])
        assert_equal(len(imported), 1)
        assert imported[0]['success']
        address, = node.deriveaddresses(node.getdescriptorinfo(descriptor)['descriptor'])
        self.account = node.getaddressinfo(address)['witness_program']
        recipient = node.getnewaddress()
        assert recipient != address
        before = node.getbestblockhash()
        cases = [
            ([{'address': 'notanaddress', 'amount_sat': 100000000}], -5, 'invalid address'),
            ([{'address': address, 'amount_sat': -1}], -3, 'out of range'),
            ([{'address': address, 'amount_sat': 2100000000000001}], -3, 'out of range'),
            ([{'address': address}], -8, "integer 'amount_sat'"),
            ([{'amount_sat': 1}], -8, "string 'address'"),
            ([{'address': address, 'amount_sat': '1'}], -8, "integer 'amount_sat'"),
        ]
        for outputs, code, message in cases:
            args = self.arguments()
            assert_raises_rpc_error(code, message, node.submit_nonce, *args, outputs)
            # Parsing must precede context validation, even with an invalid height.
            args[1] = -1
            assert_raises_rpc_error(code, message, node.submit_nonce, *args, outputs)
            assert_equal(node.getbestblockhash(), before)
        legacy = node.submit_nonce(*self.arguments())
        assert 'raw_quality' in legacy, legacy
        split = node.submit_nonce(*self.arguments(), [
            {'address': address, 'amount_sat': 100000000},
            {'address': recipient, 'amount_sat': 50000000},
        ])
        assert 'raw_quality' in split, split


if __name__ == '__main__':
    SubmitNoncePayoutTest(__file__).main()
