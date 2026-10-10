#!/usr/bin/env python3
# Copyright (c) 2017-present The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test that mempool.dat is both backward and forward compatible between versions

NOTE: The test is designed to prevent cases when compatibility is broken accidentally.
In case we need to break mempool compatibility we can continue to use the test by just bumping the version number.

Previous releases are required by this test, see test/README.md.
"""

from io import BytesIO

from test_framework.blocktools import COINBASE_MATURITY, bitcoin_block_with_shared_coinbase
from test_framework.bitcoin_test_node import TestNode as BitcoinTestNode
from test_framework.messages import CBlock
from test_framework.test_framework import BitcoinTestFramework
from test_framework.test_node import TestNode
from test_framework.util import assert_equal
from test_framework.wallet import (
    MiniWallet,
    MiniWalletMode,
)


class MempoolCompatibilityTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 2
        self.setup_clean_chain = True
        self.pocx_synchronized_generation = True

    def skip_test_if_missing_module(self):
        self.skip_if_no_previous_releases()

    def setup_network(self):
        self.add_nodes(self.num_nodes, versions=[
            200100,  # Last release without unbroadcast serialization and without XOR
            None,
        ], node_classes=[BitcoinTestNode, TestNode])
        self.start_nodes()

    def run_test(self):
        self.log.info("Test that mempool.dat is compatible between versions")

        old_node, new_node = self.nodes
        assert "unbroadcastcount" not in old_node.getmempoolinfo()
        new_wallet = MiniWallet(new_node, mode=MiniWalletMode.RAW_P2PK)
        native_funding_hash = self.generate(new_wallet, 1, sync_fun=self.no_op)[0]
        native_funding_block = CBlock()
        native_funding_block.deserialize(BytesIO(bytes.fromhex(new_node.getblock(native_funding_hash, 0))))
        old_node.setmocktime(new_node.mocktime)
        bitcoin_funding_block = bitcoin_block_with_shared_coinbase(
            native_funding_block.vtx[0], old_node.getblocktemplate({'rules': ['segwit']}))
        assert_equal(old_node.submitblock(bitcoin_funding_block.serialize().hex()), None)
        self.generate(new_node, COINBASE_MATURITY, sync_fun=self.no_op)
        old_node.generate(COINBASE_MATURITY, called_by_framework=True)
        # Independent chains have identical funding UTXOs. Preserve the original
        # precondition needed for mempool acceptance without synchronizing PoW
        # and PoCX headers, which deliberately have different formats/genesis.
        assert_equal(old_node.getblockcount(), COINBASE_MATURITY + 1)
        assert_equal(new_node.getblockcount(), COINBASE_MATURITY + 1)
        assert old_node.getblockhash(0) != new_node.getblockhash(0)
        funding_txid = native_funding_block.vtx[0].txid_hex
        old_coin = old_node.gettxout(funding_txid, 0)
        new_coin = new_node.gettxout(funding_txid, 0)
        for field in ['value', 'confirmations', 'coinbase']:
            assert_equal(old_coin[field], new_coin[field])
        assert_equal(old_coin['scriptPubKey']['hex'], new_coin['scriptPubKey']['hex'])
        assert_equal(old_coin['coinbase'], True)

        self.log.info("Add a transaction to mempool on old node and shutdown")
        old_tx_hash = new_wallet.send_self_transfer(from_node=old_node)["txid"]
        assert old_tx_hash in old_node.getrawmempool()
        self.stop_node(0)
        self.stop_node(1)

        self.log.info("Move mempool.dat from old to new node")
        old_node_mempool = old_node.chain_path / "mempool.dat"
        new_node_mempool = new_node.chain_path / "mempool.dat"
        new_node_mempool.unlink()
        old_node_mempool.rename(new_node_mempool)

        self.log.info("Start new node and verify mempool contains the tx")
        self.start_node(1, extra_args=["-persistmempoolv1=1"])
        assert old_tx_hash in new_node.getrawmempool()

        self.log.info("Add unbroadcasted tx to mempool on new node and shutdown")
        unbroadcasted_tx_hash = new_wallet.send_self_transfer(from_node=new_node)['txid']
        assert unbroadcasted_tx_hash in new_node.getrawmempool()
        assert new_node.getmempoolentry(unbroadcasted_tx_hash)['unbroadcast']
        self.stop_node(1)

        self.log.info("Move mempool.dat from new to old node")
        new_node_mempool.rename(old_node_mempool)

        self.log.info("Start old node again and verify mempool contains both txs")
        self.start_node(0, ['-nowallet'])
        assert old_tx_hash in old_node.getrawmempool()
        assert unbroadcasted_tx_hash in old_node.getrawmempool()


if __name__ == "__main__":
    MempoolCompatibilityTest(__file__).main()
