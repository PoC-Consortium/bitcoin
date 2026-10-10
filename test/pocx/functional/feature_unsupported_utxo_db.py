#!/usr/bin/env python3
# Copyright (c) 2022-present The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test that unsupported utxo db causes an init error.

Previous releases are required by this test, see test/README.md.
"""

import shutil

from test_framework.test_framework import BitcoinTestFramework
from test_framework.bitcoin_test_node import TestNode as BitcoinTestNode
from test_framework.test_node import TestNode
from test_framework.util import assert_equal


class UnsupportedUtxoDbTest(BitcoinTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 2
        self.pocx_synchronized_generation = True

    def skip_test_if_missing_module(self):
        self.skip_if_no_previous_releases()

    def setup_network(self):
        self.add_nodes(
            self.num_nodes,
            versions=[
                140300,  # Last release with previous utxo db format
                None,  # For MiniWallet, without migration code
            ],
            node_classes=[BitcoinTestNode, TestNode],
        )

    def run_test(self):
        self.log.info("Create previous version (v0.14.3) utxo db")
        self.start_node(0)
        block = self.nodes[0].generate(1, called_by_framework=True)[-1]
        assert_equal(self.nodes[0].getbestblockhash(), block)
        assert_equal(self.nodes[0].gettxoutsetinfo()["total_amount"], 50)

        # Reindexing must recover this node's own valid PoCX blocks. Old Bitcoin
        # headers describe a different chain and are not a recovery fixture.
        self.start_node(1)
        native_block = self.generate(self.nodes[1], 1, sync_fun=self.no_op)[-1]
        native_utxos = self.nodes[1].gettxoutsetinfo('muhash')
        assert_equal(native_utxos['total_amount'], 10)
        assert_equal(native_utxos['bestblock'], native_block)
        self.stop_nodes()

        self.log.info("Check init error")
        legacy_utxos_dir = self.nodes[0].chain_path / "chainstate"
        recent_utxos_dir = self.nodes[1].chain_path / "chainstate"
        shutil.rmtree(recent_utxos_dir)
        shutil.copytree(legacy_utxos_dir, recent_utxos_dir)
        self.nodes[1].assert_start_raises_init_error(
            expected_msg="Error: Unsupported chainstate database format found. "
            "Please restart with -reindex-chainstate. "
            "This will rebuild the chainstate database.",
        )

        self.log.info("Drop legacy utxo db")
        self.start_node(1, extra_args=["-reindex-chainstate"])
        assert_equal(self.nodes[1].getbestblockhash(), native_block)
        recovered_utxos = self.nodes[1].gettxoutsetinfo('muhash')
        assert_equal(recovered_utxos['total_amount'], 10)
        assert_equal(recovered_utxos['muhash'], native_utxos['muhash'])
        assert_equal(recovered_utxos['txouts'], native_utxos['txouts'])


if __name__ == "__main__":
    UnsupportedUtxoDbTest(__file__).main()
