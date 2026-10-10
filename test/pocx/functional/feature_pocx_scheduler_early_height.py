#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin PoCX developers
# Distributed under the MIT software license; see COPYING.
"""Required early-height forging regression; currently exposes POCX-SCHEDULER-001."""
from feature_pocx_scheduler_payout import SchedulerPayoutTest


class EarlyHeightSchedulerTest(SchedulerPayoutTest):
    def set_test_params(self):
        super().set_test_params()
        self.seed_blocks = 1

    def check_fees_and_budget(self, node, account, signer, recipient):
        # This fixture has no mature funds; fee/budget cases belong to the
        # mature-chain test. Its required assertion is accepted height-2 forging.
        pass

    def run_test(self):
        super().run_test()


if __name__ == '__main__':
    EarlyHeightSchedulerTest(__file__).main()
