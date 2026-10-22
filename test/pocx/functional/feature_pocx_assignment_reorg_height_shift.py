#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin PoCX developers
# Distributed under the MIT software license; see COPYING.
"""Same assignment txid re-mined earlier/later, flushed rows and reindex parity."""
from decimal import Decimal
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal


class AssignmentHeightShiftTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 4
        self.setup_clean_chain = True
        self.uses_wallet = True
        self.extra_args = [['-fallbackfee=0.00001'] for _ in range(4)]

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def setup_network(self):
        self.setup_nodes()  # Four independent fresh chains, one per variant.

    def run_test(self):
        for index, (direction, restart_between) in enumerate(
                [('later', False), ('later', True), ('earlier', False), ('earlier', True)]):
            self.log.info(f'{direction}: restart between flush and reorg={restart_between}')
            node = self.nodes[index]
            mining, plot, forge = [node.getnewaddress('', 'bech32') for _ in range(3)]

            def mine(count):
                return self.generatetoaddress(node, count, mining, sync_fun=self.no_op)

            def block(txs=()):
                return self.generateblock(node, mining, list(txs), sync_fun=self.no_op)['hash']

            def empty(count):
                for _ in range(count):
                    block()

            def field(key, expected, height=None):
                result = node.get_assignment(plot, *([] if height is None else [height]))
                assert_equal(result[key], expected)

            def flush():
                node.gettxoutsetinfo()

            def restart(reindex=False):
                now = node.getblockchaininfo()['time'] + 1
                args = self.extra_args[index] + [f'-mocktime={now}']
                if reindex:
                    args += ['-reindex-chainstate']
                self.restart_node(index, extra_args=args)
                if self.default_wallet_name not in node.listwallets():
                    node.loadwallet(self.default_wallet_name)

            def included(txid, height):
                assert txid in node.getblock(node.getblockhash(height))['tx']

            def orphan(block_hash, txid):
                node.invalidateblock(block_hash)
                assert txid in node.getrawmempool()
                field('has_assignment', False)

            mine(101)
            node.sendtoaddress(plot, Decimal('1'))
            mine(1)
            field('has_assignment', False)
            if direction == 'earlier':
                old_hash = block()
                n = node.getblockcount()
            txid = node.create_assignment(plot, forge, Decimal('0.0001'))['txid']
            assert txid in node.getrawmempool()
            mine(1)
            old_height = node.getblockcount()
            included(txid, old_height)
            field('assignment_height', old_height)
            if direction == 'later':
                n = old_height
                old_hash = node.getblockhash(n)
            flush()  # Essential on-disk stale-row precondition, not optional.
            if restart_between:
                restart()
            orphan(old_hash, txid)
            if direction == 'later':
                empty(2)
                block([txid])
                new_height = n + 2
            else:
                block([txid])
                empty(2)
                new_height = n
            included(txid, new_height)
            flush()
            for cold in (False, True):
                if cold:
                    restart()
                self.log.info(f'{direction}: check stale-row absence with cold cache={cold}')
                if direction == 'later':
                    field('has_assignment', False, n)
                    field('has_assignment', False, n + 1)
                else:
                    field('has_assignment', False, n - 1)
                field('assignment_txid', txid)
                field('assignment_height', new_height)
                field('activation_height', new_height + 4)
                field('forging_address', forge)
            if direction == 'later':
                orphan(node.getblockhash(n + 2), txid)
                empty(3)
                flush()
                field('has_assignment', False)
                empty(6)
                field('has_assignment', False)
                field('state', 'UNASSIGNED')
            else:
                empty(n + 4 - node.getblockcount())
                assert_equal(node.getblockcount(), n + 4)
                field('state', 'ASSIGNED')
                field('state', 'ASSIGNING', n + 3)
            tip = node.getbestblockhash()
            height = node.getblockcount()
            live = [node.get_assignment(plot, h) for h in range(n - 1, height + 1)]
            restart(reindex=True)
            self.wait_until(lambda: node.getblockcount() == height and not node.getblockchaininfo()['initialblockdownload'])
            assert_equal(node.getbestblockhash(), tip)
            flush()
            rebuilt = [node.get_assignment(plot, h) for h in range(n - 1, height + 1)]
            assert_equal(rebuilt, live)


if __name__ == '__main__':
    AssignmentHeightShiftTest(__file__).main()
