#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin PoCX developers
# Distributed under the MIT software license, see the accompanying file COPYING.
"""All six phases of wrapper assignments/test-assignment-lifecycle-v2.sh."""
from decimal import Decimal
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal


class AssignmentLifecycleTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.uses_wallet = True
        self.extra_args = [["-fallbackfee=0.00001"]]

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def run_test(self):
        node = self.nodes[0]
        mining = node.getnewaddress("", "bech32")

        def mine(count):
            return self.generatetoaddress(node, count, mining)

        def state(expected, height=None):
            results = [peer.get_assignment(plot, *([] if height is None else [height])) for peer in self.nodes]
            for result in results:
                assert_equal(result["state"], expected)
                if expected != "UNASSIGNED":
                    assert_equal(result["forging_address"], forge)
                assert_equal(result, results[0])

        def invalidate(block_hash):
            for peer in self.nodes:
                peer.invalidateblock(block_hash)
            self.sync_blocks()

        def reconsider(block_hash):
            for peer in self.nodes:
                peer.reconsiderblock(block_hash)
            self.sync_blocks()

        hashes, heights = {}, {}

        def checkpoint(name):
            hashes[name] = node.getbestblockhash()
            heights[name] = node.getblockcount()
            state(name)

        def opcode(txid, prefix):
            tx = node.decoderawtransaction(node.gettransaction(txid)["hex"])
            assert tx["vout"][0]["scriptPubKey"]["hex"].startswith(prefix)

        self.log.info("Phase 1: mature funds, funded plot, unassigned state")
        mine(101)
        plot = node.getnewaddress("", "bech32")
        forge = node.getnewaddress("", "bech32")
        node.sendtoaddress(plot, Decimal("1"))
        mine(1)
        checkpoint("UNASSIGNED")
        assert_equal(node.getrawmempool(), [])

        self.log.info("Phase 2: assignment and exact four-block activation delay")
        assignment = node.create_assignment(plot, forge, Decimal("0.0001"))["txid"]
        self.sync_mempools()
        assert all(assignment in peer.getrawmempool() for peer in self.nodes)
        mine(1)
        checkpoint("ASSIGNING")
        assert_equal(node.getrawmempool(), [])
        for _ in range(3):
            mine(1)
            state("ASSIGNING")
        mine(1)
        checkpoint("ASSIGNED")
        opcode(assignment, "6a2c504f4358")

        self.log.info("Phase 3: refund plot and exact eight-block revocation delay")
        node.sendtoaddress(plot, Decimal("1"))
        mine(2)
        revocation = node.revoke_assignment(plot, Decimal("0.0001"))["txid"]
        self.sync_mempools()
        assert all(revocation in peer.getrawmempool() for peer in self.nodes)
        mine(1)
        checkpoint("REVOKING")
        assert_equal(node.getrawmempool(), [])
        for _ in range(7):
            mine(1)
            state("REVOKING")
        mine(1)
        checkpoint("REVOKED")
        opcode(revocation, "6a1858434f50")

        self.log.info("Phase 4: single-state rollbacks and reconsideration")
        for invalid, expected, txid in [
            ("REVOKED", "REVOKING", None),
            ("REVOKING", "ASSIGNED", revocation),
            ("ASSIGNED", "ASSIGNING", None),
            ("ASSIGNING", "UNASSIGNED", assignment),
        ]:
            invalidate(hashes[invalid])
            state(expected)
            if txid:
                assert txid in node.getrawmempool()
        for name in ["ASSIGNING", "ASSIGNED", "REVOKING", "REVOKED"]:
            reconsider(hashes[name])
        state("REVOKED")
        assert_equal(node.getbestblockhash(), hashes["REVOKED"])

        self.log.info("Phase 5: multi-state rollback and reconsider descendants")
        invalidate(hashes["REVOKING"])
        state("ASSIGNED")
        invalidate(hashes["ASSIGNING"])
        state("UNASSIGNED")
        for name in ["ASSIGNING", "ASSIGNED"]:
            reconsider(hashes[name])
        state("REVOKED")
        assert_equal(node.getbestblockhash(), hashes["REVOKED"])

        self.log.info("Phase 6: historical queries for all five states")
        for name, height in heights.items():
            state(name, height)
        assert node.verifychain(4, 0)


if __name__ == '__main__':
    AssignmentLifecycleTest(__file__).main()
