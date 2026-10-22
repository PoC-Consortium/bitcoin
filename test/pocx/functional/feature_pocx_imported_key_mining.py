#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin PoCX developers
# Distributed under the MIT software license; see COPYING.
"""Port of mining/test-regtest-mining-legacy-v2.sh, with a blank descriptor wallet."""
from test_framework.descriptors import descsum_create
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal


class ImportedKeyMiningTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.uses_wallet = True
        self.wallet_names = [False]

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def run_test(self):
        node = self.nodes[0]
        node.createwallet('imported', disable_private_keys=False, blank=True, descriptors=True)
        wallet = node.get_wallet_rpc('imported')
        wif = 'cNgs3AUH8xu2faRgLBR5kT7mAB6tUJZDDRH5YeKtZw4LqhbapNWd'
        descriptor = f'wpkh({wif})'
        result = wallet.importdescriptors([{'desc': descsum_create(descriptor), 'timestamp': 'now'}])
        assert_equal(len(result), 1)
        assert result[0]['success']
        public_descriptor = node.getdescriptorinfo(descriptor)['descriptor']
        addresses = node.deriveaddresses(public_descriptor)
        assert_equal(len(addresses), 1)
        address = addresses[0]
        assert address.startswith('rpocx1')
        info = wallet.getaddressinfo(address)
        assert info['ismine'] and info['solvable']
        assert_equal(node.getblockcount(), 0)
        blocks = self.generatetoaddress(node, 100, address)
        assert_equal(node.getblockcount(), 100)
        assert_equal(len(blocks), 100)
        assert_equal(wallet.getbalances()['mine']['immature'], 1000)


if __name__ == '__main__':
    ImportedKeyMiningTest(__file__).main()
