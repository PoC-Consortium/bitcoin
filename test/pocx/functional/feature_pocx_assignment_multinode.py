#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin PoCX developers
# Distributed under the MIT software license; see COPYING.
"""Reuse every lifecycle assertion with a wallet-less peer observing P2P relay."""
from feature_pocx_assignment_lifecycle import AssignmentLifecycleTest


class AssignmentMultinodeTest(AssignmentLifecycleTest):
    def set_test_params(self):
        super().set_test_params()
        self.num_nodes = 2
        self.wallet_names = [self.default_wallet_name, False]
        # The parked future clock must not leave the observer in IBD, which
        # suppresses transaction relay. Allow a 400-day tip age in this fixture.
        self.extra_args += [['-disablewallet', '-mocktime=2031536000', '-maxtipage=34560000']]

    def sync_mempools(self, nodes=None, **kwargs):
        # Transaction inventory uses NodeClock timers. Advance the fixed clocks
        # while waiting so this exercises ordinary relay without whitelisting.
        peers = nodes or self.nodes
        if not hasattr(self, '_relay_times'):
            self._relay_times = [2000000000, 2031536000]
        def synced():
            pools = [set(peer.getrawmempool()) for peer in peers]
            if all(pool == pools[0] for pool in pools):
                return True
            for index, peer in enumerate(self.nodes):
                self._relay_times[index] = max(self._relay_times[index], peer.getblockchaininfo()['time']) + 5
                peer.setmocktime(self._relay_times[index])
            return False
        self.wait_until(synced, timeout=60)
        for peer in peers:
            peer.syncwithvalidationinterfacequeue()

    def run_test(self):
        super().run_test()

    def setup_network(self):
        self.setup_nodes()
        # PoCX generation advances mocktime by deadlines; receiving node must
        # remain ahead of those timestamps throughout this observer scenario.
        self.nodes[1].setmocktime(2031536000)
        self.connect_nodes(0, 1)
        self.sync_all()


if __name__ == '__main__':
    AssignmentMultinodeTest(__file__).main()
