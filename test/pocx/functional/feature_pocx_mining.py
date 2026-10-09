#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin PoCX developers
# Distributed under the MIT software license, see the accompanying file COPYING.
"""Port of wrapper scripts/mining/test-regtest-mining-v2.sh (100 blocks)."""
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal
from test_framework.blocktools import create_pocx_block
from unittest.mock import patch


class PoCXMiningTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.uses_wallet = True

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def run_test(self):
        node = self.nodes[0]
        address = node.getnewaddress("", "bech32")
        assert address.startswith("rpocx1")
        assert_equal(node.getblockcount(), 0)
        previous = node.getbestblockhash()
        blocks = self.generatetoaddress(node, 100, address)
        assert_equal(len(blocks), 100)
        assert_equal(len(set(blocks)), 100)
        assert_equal(node.getblockcount(), 100)
        assert_equal(node.getbestblockhash(), blocks[-1])
        for height, blockhash in enumerate(blocks, 1):
            block = node.getblock(blockhash, 2)
            assert_equal(block["height"], height)
            assert_equal(block["previousblockhash"], previous)
            assert_equal(block["confirmations"], 101 - height)
            assert address in [v["scriptPubKey"].get("address") for v in block["tx"][0]["vout"]]
            previous = blockhash
        assert node.verifychain(4, 0)

        # A valid transaction arriving during an unsubmitted proof preview must
        # remain available to the actual mining RPC. Inject its arrival at that
        # exact boundary instead of relying on nondeterministic peer timing.
        self.log.info('Test transaction arrival during synchronized proof preview')
        self.generate(node, 1)
        parent = node.getbestblockhash()
        height = node.getblockcount()
        clock = node.mocktime
        assert_equal(node.getrawmempool(), [])
        create_pocx_block(node)  # Keep strict preservation checks for a quiet fixture.
        original_preview = node.generateblock
        arrived = []

        def preview_with_arrival(*args, **kwargs):
            assert_equal(args, ('raw(51)', [], False))
            result = original_preview(*args, **kwargs)
            assert_equal(node.getbestblockhash(), parent)
            assert_equal(node.getblockcount(), height)
            assert_equal(node.getrawmempool(), [])
            arrived.append(node.sendtoaddress(node.getnewaddress(), 1))
            assert_equal(node.getrawmempool(), arrived)
            return result

        self.pocx_synchronized_generation = True
        with patch.object(node, 'generateblock', side_effect=preview_with_arrival):
            mined = self.generate(node, 1)
        assert_equal(len(arrived), 1)
        assert_equal(len(mined), 1)
        assert_equal(node.getblockcount(), height + 1)
        assert_equal(node.getblock(mined[0])['tx'][1:], arrived)
        assert_equal(node.getrawmempool(), [])
        assert node.mocktime >= clock
        assert node.verifychain(4, 0)


if __name__ == '__main__':
    PoCXMiningTest(__file__).main()
