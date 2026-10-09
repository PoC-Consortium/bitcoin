#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin PoCX developers
# Distributed under the MIT software license; see COPYING.
"""Unflushed SIGKILL recovery, catch-up and assignment state parity.

Preserves the wrapper's crash timing. This does not inject a crash at an exact
internal database write boundary; that stronger fault-injection check is separate.
"""
from decimal import Decimal
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal


class AssignmentCrashReviveTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 2
        self.setup_clean_chain = True
        self.uses_wallet = True
        self.receiver_time = 2031536000
        self.extra_args = [['-fallbackfee=0.00001'],
                           ['-fallbackfee=0.00001', f'-mocktime={self.receiver_time}']]

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def setup_network(self):
        # Explicit submitblock catch-up, matching the original regression.
        self.setup_nodes()

    def run_test(self):
        source, receiver = self.nodes
        receiver.setmocktime(self.receiver_time)
        mining = source.getnewaddress('', 'bech32')

        def mine(count):
            return self.generatetoaddress(source, count, mining, sync_fun=self.no_op)

        def catch_up():
            for height in range(receiver.getblockcount() + 1, source.getblockcount() + 1):
                block_hash = source.getblockhash(height)
                assert_equal(receiver.submitblock(source.getblock(block_hash, 0)), None)
                assert_equal(receiver.getbestblockhash(), block_hash)
            assert_equal(receiver.getblockcount(), source.getblockcount())
            assert_equal(receiver.getbestblockhash(), source.getbestblockhash())

        def parity(plot, history):
            assert_equal(receiver.get_assignment(plot), source.get_assignment(plot))
            for height in history:
                assert_equal(receiver.get_assignment(plot, height), source.get_assignment(plot, height))

        mine(110)
        scenarios = []
        for revoke_while_down in (False, True):
            plot, forge = [source.getnewaddress('', 'bech32') for _ in range(2)]
            source.sendtoaddress(plot, Decimal('1'))
            mine(1)
            catch_up()
            source.create_assignment(plot, forge)
            mine(1)
            assignment_height = source.getblockcount()
            catch_up()
            mine(5)
            catch_up()
            history = [assignment_height, assignment_height + 3, assignment_height + 4]
            assert_equal(source.get_assignment(plot)['state'], 'ASSIGNED')
            source.gettxoutsetinfo()  # Flush only the surviving source.
            parity(plot, history)
            self.log.info(f'SIGKILL receiver without forced flush; revoke during downtime={revoke_while_down}')
            receiver.kill_process()  # Own process handle, verified SIGKILL exit.
            if revoke_while_down:
                source.sendtoaddress(plot, Decimal('1'))
                mine(1)
                source.revoke_assignment(plot)
                mine(1)
                revocation_height = source.getblockcount()
                mine(8)
                history += [revocation_height, revocation_height + 7, revocation_height + 8]
                assert_equal(source.get_assignment(plot)['state'], 'REVOKED')
            else:
                mine(10)  # Exact original wrapper downtime scenario.
            source.gettxoutsetinfo()
            self.start_node(1)
            catch_up()
            receiver.gettxoutsetinfo()
            parity(plot, history)
            scenarios.append((plot, history))

        self.log.info('Clean restart and chainstate reindex preserve recovered current and historical states')
        self.restart_node(1)
        catch_up()
        for plot, history in scenarios:
            parity(plot, history)
        self.restart_node(1, extra_args=self.extra_args[1] + ['-reindex-chainstate'])
        catch_up()
        for plot, history in scenarios:
            parity(plot, history)


if __name__ == '__main__':
    AssignmentCrashReviveTest(__file__).main()
