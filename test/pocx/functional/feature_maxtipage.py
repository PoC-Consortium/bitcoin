#!/usr/bin/env python3
# Copyright (c) 2022-present The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test logic for setting -maxtipage on command line.

Nodes don't consider themselves out of "initial block download" as long as
their best known block header time is more than -maxtipage in the past.
"""

import time

from test_framework.blocktools import create_pocx_block
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal


DEFAULT_MAX_TIP_AGE = 24 * 60 * 60


class MaxTipAgeTest(BitcoinTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.pocx_synchronized_generation = False
        self.num_nodes = 2

    def setup_nodes(self):
        super().setup_nodes()
        for node in self.nodes:
            node.setmocktime(0)

    def generate_at_age(self, miner, observer, earliest, age):
        # Native deadlines prevent mining consecutive blocks one second apart.
        # Place the observer precisely at the original tip-age boundary instead.
        preview = create_pocx_block(miner, ntime=earliest)
        miner.setmocktime(preview.nTime)
        if age is not None:
            observer.setmocktime(preview.nTime + age)
        self.generate(miner, 1)
        assert_equal(miner.getblockheader(miner.getbestblockhash())['time'], preview.nTime)
        if age is not None:
            assert_equal(observer.mocktime - preview.nTime, age)

    def test_maxtipage(self, maxtipage, set_parameter=True, test_deltas=True):
        node_miner = self.nodes[0]
        node_ibd = self.nodes[1]

        self.restart_node(1, [f'-maxtipage={maxtipage}'] if set_parameter else None)
        self.connect_nodes(0, 1)
        cur_time = int(time.time())

        if test_deltas:
            # tips older than maximum age -> stay in IBD
            node_ibd.setmocktime(cur_time)
            for delta in [5, 4, 3, 2, 1]:
                self.generate_at_age(node_miner, node_ibd, cur_time - maxtipage - delta, maxtipage + delta)
                assert_equal(node_ibd.getblockchaininfo()['initialblockdownload'], True)

        # tip within maximum age -> leave IBD
        self.generate_at_age(node_miner, node_ibd, max(cur_time - maxtipage, 0), maxtipage if test_deltas else None)
        assert_equal(node_ibd.getblockchaininfo()['initialblockdownload'], False)

        # reset time to system time so we don't have a time offset with the ibd node the next
        # time we connect to it, ensuring TimeOffsets::WarnIfOutOfSync() doesn't output to stderr
        node_miner.setmocktime(0)

    def run_test(self):
        self.log.info("Test IBD with maximum tip age of 24 hours (default).")
        self.test_maxtipage(DEFAULT_MAX_TIP_AGE, set_parameter=False)

        for hours in [20, 10, 5, 2, 1]:
            maxtipage = hours * 60 * 60
            self.log.info(f"Test IBD with maximum tip age of {hours} hours (-maxtipage={maxtipage}).")
            self.test_maxtipage(maxtipage)

        max_long_val = 9223372036854775807
        self.log.info(f"Test IBD with highest allowable maximum tip age ({max_long_val}).")
        self.test_maxtipage(max_long_val, test_deltas=False)


if __name__ == '__main__':
    MaxTipAgeTest(__file__).main()
