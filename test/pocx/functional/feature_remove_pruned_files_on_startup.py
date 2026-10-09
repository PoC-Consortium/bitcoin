#!/usr/bin/env python3
# Copyright (c) 2022-present The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Tests around pruning rev and blk files on startup."""

import platform
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal


class FeatureRemovePrunedFilesOnStartupTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.extra_args = [["-fastprune", "-prune=1"]]

    def mine_batches(self, blocks):
        n = blocks // 250
        for _ in range(n):
            self.generate(self.nodes[0], 250)
        self.generate(self.nodes[0], blocks % 250)

    def run_test(self):
        blk0 = self.nodes[0].blocks_path / "blk00000.dat"
        rev0 = self.nodes[0].blocks_path / "rev00000.dat"
        blk1 = self.nodes[0].blocks_path / "blk00001.dat"
        rev1 = self.nodes[0].blocks_path / "rev00001.dat"
        self.mine_batches(800)

        # Predict the blockfile layout from serialized record lengths, rather
        # than assuming Bitcoin's smaller headers leave exactly two file pairs.
        # The funding fixture copied heights0..199 from the normal128MiB
        # producer; this node writes height200 onward with64KiB fastprune.
        file_ranges = [[]]
        file_size = 0
        for height in range(self.nodes[0].getblockcount() + 1):
            block_hash = self.nodes[0].getblockhash(height)
            record_size = 8 + len(bytes.fromhex(self.nodes[0].getblock(block_hash, 0)))
            limit = 128 * 1024 * 1024 if height < 200 else max(65536, record_size + 1)
            if file_size + record_size >= limit:
                file_ranges.append([])
                file_size = 0
            file_ranges[-1].append(height)
            file_size += record_size
        assert all(file_ranges)
        assert file_ranges[0][-1] <= 600
        assert file_ranges[1][-1] <= 600
        expected_remaining = sorted(
            f"{prefix}{index:05d}.dat"
            for index, heights in enumerate(file_ranges)
            if heights[-1] > 600 or index == len(file_ranges) - 1
            for prefix in ('blk', 'rev')
        )

        self.log.info("Open some files to check that this may delay deletion")
        fd1 = open(blk0, "rb")
        fd2 = open(rev1, "rb")
        self.nodes[0].pruneblockchain(600)

        # Windows systems will not remove files with an open fd
        if platform.system() != 'Windows':
            assert not blk0.exists()
            assert not rev0.exists()
            assert not blk1.exists()
            assert not rev1.exists()
        else:
            assert blk0.exists()
            assert not rev0.exists()
            assert not blk1.exists()
            assert rev1.exists()

        self.log.info("Check that the files are removed on restart once the fds are closed")
        fd1.close()
        fd2.close()
        self.restart_node(0)
        assert not blk0.exists()
        assert not rev1.exists()

        self.log.info("Check that a reindex will wipe all files")

        def ls_files():
            ls = [
                entry.name
                for entry in self.nodes[0].blocks_path.iterdir()
                if entry.is_file() and any(map(entry.name.startswith, ["rev", "blk"]))
            ]
            return sorted(ls)

        assert_equal(ls_files(), expected_remaining)
        self.restart_node(0, extra_args=self.extra_args[0] + ["-reindex"])
        assert_equal(self.nodes[0].getblockcount(), 0)
        self.stop_node(0)  # Stop node to flush the two newly created files
        assert_equal(ls_files(), ["blk00000.dat", "rev00000.dat"])


if __name__ == '__main__':
    FeatureRemovePrunedFilesOnStartupTest(__file__).main()
