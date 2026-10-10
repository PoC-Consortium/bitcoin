#!/usr/bin/env python3
# Copyright (c) 2020-present The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test indices in conjunction with prune."""
import concurrent.futures
import os
from test_framework.authproxy import JSONRPCException
from test_framework.messages import CBlock, from_hex
from test_framework.script import CScript
from test_framework.test_framework import BitcoinTestFramework
from test_framework.test_node import TestNode
from test_framework.util import (
    assert_equal,
    assert_greater_than,
    assert_raises_rpc_error,
)

from typing import List, Any

def send_batch_request(node: TestNode, method: str, params: List[Any]) -> List[Any]:
    """Send batch request and parse all results"""
    data = [getattr(node, method).get_request(*p) for p in params]
    response = node.batch(data)
    result = []
    for item in response:
        assert "error" not in item, item["error"]
        result.append(item["result"])

    return result


class FeatureIndexPruneTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 4
        self.extra_args = [
            ["-fastprune", "-prune=1", "-blockfilterindex=1"],
            ["-fastprune", "-prune=1", "-coinstatsindex=1"],
            ["-fastprune", "-prune=1", "-blockfilterindex=1", "-coinstatsindex=1"],
            [],
        ]

    def setup_network(self):
        self.setup_nodes()  # No P2P connection, so that linear_sync works

    def linear_sync(self, node_from, *, height_from=None):
        # Linear sync over RPC, because P2P sync may not be linear
        to_height = node_from.getblockcount()
        if height_from is None:
            height_from = min([n.getblockcount() for n in self.nodes]) + 1
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.num_nodes) as rpc_threads:
            for i in range(height_from, to_height + 1):
                b = node_from.getblock(blockhash=node_from.getblockhash(i), verbosity=0)
                list(rpc_threads.map(lambda n: n.submitblock(b), self.nodes))

    def generate(self, node, num_blocks, sync_fun=None):
        return super().generate(node, num_blocks, sync_fun=sync_fun or (lambda: self.linear_sync(node)))

    def sync_index(self, height):
        expected_filter = {
            'basic block filter index': {'synced': True, 'best_block_height': height},
        }
        self.wait_until(lambda: self.nodes[0].getindexinfo() == expected_filter)

        expected_stats = {
            'coinstatsindex': {'synced': True, 'best_block_height': height}
        }
        self.wait_until(lambda: self.nodes[1].getindexinfo() == expected_stats, timeout=150)

        expected = {**expected_filter, **expected_stats}
        self.wait_until(lambda: self.nodes[2].getindexinfo() == expected)

    def restart_without_indices(self):
        for i in range(3):
            self.restart_node(i, extra_args=["-fastprune", "-prune=1"])

    def check_for_block(self, node, hash):
        try:
            self.nodes[node].getblock(hash)
            return True
        except JSONRPCException:
            return False

    def storage_layout(self, through=None):
        source = self.nodes[3]  # Original unpruned reference node.
        tip_height = source.getblockcount()
        through = tip_height if through is None else through
        ranges = [[]]
        size = 0
        reference = from_hex(CBlock(), source.getblock(source.getblockhash(tip_height), 0))
        if through > tip_height:
            # Coinbase-only native blocks have fixed-width reward/header fields.
            # Predict only the BIP34 script length, then verify the resulting
            # boundary against actual mined bytes before using it for pruning.
            assert_equal(len(reference.vtx), 1)
            assert_equal(reference.vtx[0].vin[0].scriptSig, CScript([tip_height, 0]))
        for height in range(through + 1):
            if height <= tip_height:
                record_size = 8 + len(bytes.fromhex(source.getblock(source.getblockhash(height), 0)))
            else:
                reference.vtx[0].vin[0].scriptSig = CScript([height, 0])
                record_size = 8 + len(reference.serialize())
            normal = self.copied_funding_layout and height < 200
            limit = 128 * 1024 * 1024 if normal else max(65536, record_size + 1)
            if size + record_size >= limit:
                ranges.append([])
                size = 0
            ranges[-1].append(height)
            size += record_size
        assert all(ranges)
        return ranges

    def expected_prune_height(self, requested):
        limit = min(requested, self.nodes[3].getblockcount() - 288)
        return max(heights[-1] for heights in self.storage_layout()[:-1] if heights[-1] <= limit)

    def run_test(self):
        self.copied_funding_layout = True
        filter_nodes = [self.nodes[0], self.nodes[2]]
        stats_nodes = [self.nodes[1], self.nodes[2]]

        self.log.info("check if we can access blockfilters and coinstats when pruning is enabled but no blocks are actually pruned")
        self.sync_index(height=200)
        tip = self.nodes[0].getbestblockhash()
        for node in filter_nodes:
            assert_greater_than(len(node.getblockfilter(tip)['filter']), 0)
        for node in stats_nodes:
            assert node.gettxoutsetinfo(hash_type="muhash", hash_or_height=tip)['muhash']

        self.generate(self.nodes[0], 500)
        self.sync_index(height=700)

        self.log.info("prune some blocks")
        for node in self.nodes[:2]:
            with node.assert_debug_log(['limited pruning to height 689']):
                pruneheight_new = node.pruneblockchain(400)
                # the prune heights used here and below are magic numbers that are determined by the
                # thresholds at which block files wrap, so they depend on disk serialization and default block file size.
                assert_equal(pruneheight_new, self.expected_prune_height(400))

        self.log.info("check if we can access the tips blockfilter and coinstats when we have pruned some blocks")
        tip = self.nodes[0].getbestblockhash()
        for node in filter_nodes:
            assert_greater_than(len(node.getblockfilter(tip)['filter']), 0)
        for node in stats_nodes:
            assert node.gettxoutsetinfo(hash_type="muhash", hash_or_height=tip)['muhash']

        self.log.info("check if we can access the blockfilter and coinstats of a pruned block")
        height_hash = self.nodes[0].getblockhash(2)
        for node in filter_nodes:
            assert_greater_than(len(node.getblockfilter(height_hash)['filter']), 0)
        for node in stats_nodes:
            assert node.gettxoutsetinfo(hash_type="muhash", hash_or_height=height_hash)['muhash']

        # mine and sync index up to a height that will later be the pruneheight
        projected = self.storage_layout(through=1000)
        index_checkpoint = max(heights[-1] for heights in projected[:-1] if heights[-1] <= 1000) + 1
        self.generate(self.nodes[0], index_checkpoint - 700)
        # The indexed block is exactly the first retained block, preserving
        # the original safe-pruning boundary at index height minus one.
        assert_equal(self.storage_layout()[-1][0], index_checkpoint)
        self.sync_index(height=index_checkpoint)

        self.restart_without_indices()

        self.log.info("make sure trying to access the indices throws errors")
        for node in filter_nodes:
            msg = "Index is not enabled for filtertype basic"
            assert_raises_rpc_error(-1, msg, node.getblockfilter, height_hash)
        for node in stats_nodes:
            msg = "Querying specific block heights requires coinstatsindex"
            assert_raises_rpc_error(-8, msg, node.gettxoutsetinfo, "muhash", height_hash)

        self.generate(self.nodes[0], 1500 - index_checkpoint)

        self.log.info("prune exactly up to the indices best blocks while the indices are disabled")
        for i in range(3):
            pruneheight_2 = self.nodes[i].pruneblockchain(1000)
            assert_equal(pruneheight_2, self.expected_prune_height(1000))
            assert_equal(pruneheight_2, index_checkpoint - 1)
            # Restart the nodes again with the indices activated
            self.restart_node(i, extra_args=self.extra_args[i])

        self.log.info("make sure that we can continue with the partially synced indices after having pruned up to the index height")
        self.sync_index(height=1500)

        self.log.info("prune further than the indices best blocks while the indices are disabled")
        self.restart_without_indices()
        self.generate(self.nodes[0], 1000)

        for i in range(3):
            pruneheight_3 = self.nodes[i].pruneblockchain(2000)
            assert_greater_than(pruneheight_3, pruneheight_2)
            self.stop_node(i)

        self.log.info("make sure we get an init error when starting the nodes again with the indices")
        filter_msg = "Error: basic block filter index best block of the index goes beyond pruned data (including undo data). Please disable the index or reindex (which will download the whole blockchain again)"
        stats_msg = "Error: coinstatsindex best block of the index goes beyond pruned data (including undo data). Please disable the index or reindex (which will download the whole blockchain again)"
        end_msg = f"{os.linesep}Error: A fatal internal error occurred, see debug.log for details: Failed to start indexes, shutting down…"
        for i, msg in enumerate([filter_msg, stats_msg, filter_msg]):
            self.nodes[i].assert_start_raises_init_error(extra_args=self.extra_args[i], expected_msg=msg+end_msg)

        self.log.info("fetching the missing blocks with getblockfrompeer doesn't work for block filter index and coinstatsindex")
        # Only checking the first two nodes since this test takes a long time
        # and the third node is kind of redundant in this context
        for i, msg in enumerate([filter_msg, stats_msg]):
            self.restart_node(i, extra_args=["-prune=1", "-fastprune"])
            node = self.nodes[i]
            prune_height = node.getblockchaininfo()["pruneheight"]
            self.connect_nodes(i, 3)
            peers = node.getpeerinfo()
            assert_equal(len(peers), 1)
            peer_id = peers[0]["id"]

            # 1500 is the height to where the indices were able to sync previously
            hashes = send_batch_request(node, "getblockhash", [[a] for a in range(1500, prune_height)])
            send_batch_request(node, "getblockfrompeer", [[bh, peer_id] for bh in hashes])
            # Ensure all necessary blocks have been fetched before proceeding
            for bh in hashes:
                self.wait_until(lambda: self.check_for_block(i, bh), timeout=10)

            # Upon restart we expect the same errors as previously although all
            # necessary blocks have been fetched. Both indices need the undo
            # data of the blocks to be available as well and getblockfrompeer
            # can not provide that.
            self.stop_node(i)
            node.assert_start_raises_init_error(extra_args=self.extra_args[i], expected_msg=msg+end_msg)

        self.log.info("make sure the nodes start again with the indices and an additional -reindex arg")
        for i in range(3):
            restart_args = self.extra_args[i] + ["-reindex"]
            self.restart_node(i, extra_args=restart_args)

        self.copied_funding_layout = False  # Reindex rebuilt all files in fastprune mode.
        self.linear_sync(self.nodes[3])
        self.sync_index(height=2500)

        for node in self.nodes[:2]:
            with node.assert_debug_log(['limited pruning to height 2489']):
                pruneheight_new = node.pruneblockchain(2500)
                assert_equal(pruneheight_new, self.expected_prune_height(2500))

        self.log.info("ensure that prune locks don't prevent indices from failing in a reorg scenario")
        with self.nodes[0].assert_debug_log(['basic block filter index prune lock moved back to 2480']):
            self.nodes[3].invalidateblock(self.nodes[0].getblockhash(2480))
            self.generate(self.nodes[3], 30, sync_fun=lambda: self.linear_sync(self.nodes[3], height_from=2480))


if __name__ == '__main__':
    FeatureIndexPruneTest(__file__).main()
