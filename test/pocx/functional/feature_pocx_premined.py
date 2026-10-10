#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin PoCX developers
# Distributed under the MIT software license; see COPYING.
"""Verify the shared pre-funded fixture before migrating its upstream consumers."""
from decimal import Decimal
from pathlib import Path
from test_framework.address import address_to_scriptpubkey, create_deterministic_address_bcrt1_p2tr_op_true
from test_framework.test_framework import BitcoinTestFramework
from test_framework.test_node import TestNode
from test_framework.util import assert_equal


class PoCXPreminedTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 3
        self.uses_wallet = True
        # Exercise the default upstream pre-funded fixture, not clean-chain setup.

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def run_test(self):
        tips = [node.getbestblockhash() for node in self.nodes]
        assert_equal(len(set(tips)), 1)
        taproot = create_deterministic_address_bcrt1_p2tr_op_true()[0]
        addresses = [key.address for key in TestNode.PRIV_KEYS[:3]] + [taproot]
        first = self.nodes[0]
        genesis = first.getblockhash(0)
        previous = genesis
        allocations = [0] * 4
        for height in range(1, 201):
            blockhash = first.getblockhash(height)
            block = first.getblock(blockhash, 2)
            assert_equal(block['height'], height)
            assert_equal(block['previousblockhash'], previous)
            assert_equal(block['confirmations'], 201 - height)
            owner = ((height - 1) // 25) % 4 if height < 200 else 0
            output = block['tx'][0]['vout'][0]
            assert_equal(output['value'], Decimal('10'))
            assert_equal(output['scriptPubKey']['hex'], address_to_scriptpubkey(addresses[owner]).hex())
            allocations[owner] += 1
            previous = blockhash
        assert_equal(allocations, [51, 50, 50, 49])
        for index, node in enumerate(self.nodes):
            assert_equal(node.getblockcount(), 200)
            assert_equal(node.getblockchaininfo()['initialblockdownload'], False)
            assert_equal(node.getbalance(), Decimal('250'))
            balances = node.getbalances()['mine']
            assert_equal(balances['trusted'], Decimal('250'))
            assert_equal(balances['immature'], Decimal('260' if index == 0 else '250'))
            destination = node.get_deterministic_priv_key().address
            assert destination.startswith('rpocx1')
            assert_equal(node.getaddressinfo(destination)['ismine'], True)
            assert_equal(node.validateaddress(destination)['scriptPubKey'], address_to_scriptpubkey(destination).hex())
            assert node.verifychain(4, 0)
        # Demonstrate that deterministic generate() uses the owned destination
        # and that funded wallets can spend, relay and confirm through real nodes.
        recipient = self.nodes[1].getnewaddress()
        transaction = first.sendtoaddress(recipient, Decimal('1'))
        self.sync_mempools()
        assert transaction in self.nodes[2].getrawmempool()
        blocks = self.generate(first, 1)
        assert_equal(first.getblockcount(), 201)
        assert_equal(first.gettransaction(transaction)['confirmations'], 1)
        assert_equal(first.getblock(blocks[0], 2)['tx'][0]['vout'][0]['scriptPubKey']['hex'],
                     address_to_scriptpubkey(first.get_deterministic_priv_key().address).hex())
        assert_equal(list(Path(self.options.cachedir).glob('**/blocks')), [])


if __name__ == '__main__':
    PoCXPreminedTest(__file__).main()
