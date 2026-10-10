#!/usr/bin/env python3
# Copyright (c) 2017-present The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

#
# Test getblockstats rpc call
#

from decimal import Decimal

from test_framework.blocktools import COINBASE_MATURITY
from test_framework.messages import CBlock, COIN, from_hex
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
    assert_raises_rpc_error,
    wallet_importprivkey,
)
import json
import os

TESTSDIR = os.path.dirname(os.path.realpath(__file__))


def independent_stats(raw_blocks):
    """Calculate every expected field from wire transactions and prior outputs.

    This oracle reads no getblockstats, verbose block or undo RPC results.
    Serialized output bytes plus the documented outpoint/height/coinbase
    overhead determine sizes; real input values determine fees independently.
    """
    utxos, times, result = {}, [], []
    def median(values):
        values = sorted(values)
        n = len(values)
        return (values[(n - 1) // 2] + values[n // 2]) // 2 if n else 0
    def unspendable(out):
        return len(out.scriptPubKey) > 10000 or out.scriptPubKey[:1] == b'\x6a'
    def size(out):
        return len(out.serialize()) + 36 + 4 + 1
    for height, raw in enumerate(raw_blocks):
        block = from_hex(CBlock(), raw)
        times.append(block.nTime)
        inputs = outputs = actual = size_inc = size_actual = total_out = 0
        fees, sizes, rates, weights, witness = [], [], [], [], []
        for tx_index, tx in enumerate(block.vtx):
            outputs += len(tx.vout)
            for n, out in enumerate(tx.vout):
                size_inc += size(out)
                if height and not unspendable(out):
                    actual += 1
                    size_actual += size(out)
                    utxos[(tx.txid_int, n)] = out
            if tx_index == 0:
                continue
            inputs += len(tx.vin)
            value_in = 0
            for txin in tx.vin:
                previous = utxos.pop((txin.prevout.hash, txin.prevout.n))
                value_in += previous.nValue
                size_inc -= size(previous)
                size_actual -= size(previous)
            value_out = sum(out.nValue for out in tx.vout)
            total_out += value_out
            fee = value_in - value_out
            assert fee >= 0
            fees.append(fee)
            sizes.append(len(tx.serialize_with_witness()))
            weights.append(tx.get_weight())
            rates.append(fee * 4 // tx.get_weight())
            witness.append(not tx.wit.is_null())
        total_weight = sum(weights)
        percentiles = []
        for numerator, denominator in [(1, 10), (1, 4), (1, 2), (3, 4), (9, 10)]:
            cumulative = 0
            for rate, weight in sorted(zip(rates, weights)):
                cumulative += weight
                if cumulative * denominator >= total_weight * numerator:
                    percentiles.append(rate)
                    break
            else:
                percentiles.append(0)
        count = len(fees)
        result.append(dict(
            avgfee=sum(fees) // count if count else 0,
            avgfeerate=sum(fees) * 4 // total_weight if total_weight else 0,
            avgtxsize=sum(sizes) // count if count else 0,
            blockhash=block.hash_hex, feerate_percentiles=percentiles, height=height,
            ins=inputs, maxfee=max(fees, default=0), maxfeerate=max(rates, default=0),
            maxtxsize=max(sizes, default=0), medianfee=median(fees),
            mediantime=sorted(times[-11:])[len(times[-11:]) // 2],
            mediantxsize=median(sizes), minfee=min(fees, default=0),
            minfeerate=min(rates, default=0), mintxsize=min(sizes, default=0), outs=outputs,
            subsidy=(10 * COIN) >> (height // 500),
            swtotal_size=sum(n for n, sw in zip(sizes, witness) if sw),
            swtotal_weight=sum(n for n, sw in zip(weights, witness) if sw),
            swtxs=sum(witness), time=block.nTime, total_out=total_out,
            total_size=sum(sizes), total_weight=total_weight, totalfee=sum(fees),
            txs=len(block.vtx), utxo_increase=outputs-inputs, utxo_size_inc=size_inc,
            utxo_increase_actual=actual-inputs, utxo_size_inc_actual=size_actual))
    return result

class GetblockstatsTest(BitcoinTestFramework):

    start_height = 101
    max_stat_pos = 2

    def add_options(self, parser):
        parser.add_argument('--gen-test-data', dest='gen_test_data',
                            default=False, action='store_true',
                            help='Generate test data')
        parser.add_argument('--test-data', dest='test_data',
                            default='data/rpc_getblockstats.json',
                            action='store', metavar='FILE',
                            help='Test data file')

    def set_test_params(self):
        self.num_nodes = 1
        self.wallet_names = []
        self.setup_clean_chain = True
        self.pocx_synchronized_generation = True

    def skip_test_if_missing_module(self):
        if self.options.gen_test_data:
            self.skip_if_no_wallet()

    def get_stats(self):
        return [self.nodes[0].getblockstats(hash_or_height=self.start_height + i) for i in range(self.max_stat_pos+1)]

    def generate_test_data(self, filename):
        mocktime = 1525107225
        self.nodes[0].setmocktime(mocktime)
        self.nodes[0].createwallet(wallet_name='test')
        privkey = self.nodes[0].get_deterministic_priv_key().key
        wallet_importprivkey(self.nodes[0], privkey, 0)

        self.generate(self.nodes[0], COINBASE_MATURITY + 1)

        address = self.nodes[0].get_deterministic_priv_key().address
        self.nodes[0].sendtoaddress(address=address, amount=2, subtractfeefromamount=True)
        self.generate(self.nodes[0], 1)

        self.nodes[0].sendtoaddress(address=address, amount=2, subtractfeefromamount=True)
        self.nodes[0].sendtoaddress(address=address, amount=2, subtractfeefromamount=False)
        self.fee_rate=300
        self.nodes[0].sendtoaddress(address=address, amount=Decimal('0.2'), subtractfeefromamount=True, fee_rate=self.fee_rate)
        # Send to OP_RETURN output to test its exclusion from statistics
        self.nodes[0].send(outputs={"data": "21"}, fee_rate=self.fee_rate)
        self.sync_all()
        self.generate(self.nodes[0], 1)


        blocks = []
        tip = self.nodes[0].getbestblockhash()
        blockhash = None
        height = 0
        while tip != blockhash:
            blockhash = self.nodes[0].getblockhash(height)
            blocks.append(self.nodes[0].getblock(blockhash, 0))
            height += 1

        self.expected_stats = independent_stats(blocks)[self.start_height:]
        to_dump = {
            'blocks': blocks,
            'mocktime': int(self.nodes[0].mocktime),
            'stats': self.expected_stats,
        }
        with open(filename, 'w') as f:
            json.dump(to_dump, f, sort_keys=True, indent=2)

    def load_test_data(self, filename):
        with open(filename, 'r') as f:
            d = json.load(f)
            blocks = d['blocks']
            mocktime = d['mocktime']
            self.expected_stats = d['stats']

        # Treat fixture statistics as assertions against independently decoded
        # blocks, never as values learned from the RPC under test.
        assert_equal(d['stats'], independent_stats(blocks)[self.start_height:])
        # Set the timestamps from the file so that the nodes can get out of Initial Block Download
        self.nodes[0].setmocktime(mocktime)
        self.sync_all()

        # Native genesis has an intentionally empty forging signature and is
        # already installed at startup. Verify the exact bytes before replay.
        assert_equal(blocks[0], self.nodes[0].getblock(self.nodes[0].getblockhash(0), 0))
        for b in blocks[1:]:
            assert_equal(self.nodes[0].submitblock(b), None)


    def run_test(self):
        test_data = os.path.join(TESTSDIR, self.options.test_data)
        if self.options.gen_test_data:
            self.generate_test_data(test_data)
        else:
            self.load_test_data(test_data)

        self.sync_all()
        stats = self.get_stats()

        # Make sure all valid statistics are included but nothing else is
        expected_keys = self.expected_stats[0].keys()
        assert_equal(set(stats[0].keys()), set(expected_keys))

        assert_equal(stats[0]['height'], self.start_height)
        assert_equal(stats[self.max_stat_pos]['height'], self.start_height + self.max_stat_pos)

        for i in range(self.max_stat_pos+1):
            self.log.info('Checking block %d' % (i))
            assert_equal(stats[i], self.expected_stats[i])

            # Check selecting block by hash too
            blockhash = self.expected_stats[i]['blockhash']
            stats_by_hash = self.nodes[0].getblockstats(hash_or_height=blockhash)
            assert_equal(stats_by_hash, self.expected_stats[i])

        # Make sure each stat can be queried on its own
        for stat in expected_keys:
            for i in range(self.max_stat_pos+1):
                result = self.nodes[0].getblockstats(hash_or_height=self.start_height + i, stats=[stat])
                assert_equal(list(result.keys()), [stat])
                if result[stat] != self.expected_stats[i][stat]:
                    self.log.info('result[%s] (%d) failed, %r != %r' % (
                        stat, i, result[stat], self.expected_stats[i][stat]))
                assert_equal(result[stat], self.expected_stats[i][stat])

        # Make sure only the selected statistics are included (more than one)
        some_stats = {'minfee', 'maxfee'}
        stats = self.nodes[0].getblockstats(hash_or_height=1, stats=list(some_stats))
        assert_equal(set(stats.keys()), some_stats)

        # Test invalid parameters raise the proper json exceptions
        tip = self.start_height + self.max_stat_pos
        assert_raises_rpc_error(-8, 'Target block height %d after current tip %d' % (tip+1, tip),
                                self.nodes[0].getblockstats, hash_or_height=tip+1)
        assert_raises_rpc_error(-8, 'Target block height %d is negative' % (-1),
                                self.nodes[0].getblockstats, hash_or_height=-1)

        # Make sure not valid stats aren't allowed
        inv_sel_stat = 'asdfghjkl'
        inv_stats = [
            [inv_sel_stat],
            ['minfee', inv_sel_stat],
            [inv_sel_stat, 'minfee'],
            ['minfee', inv_sel_stat, 'maxfee'],
        ]
        for inv_stat in inv_stats:
            assert_raises_rpc_error(-8, f"Invalid selected statistic '{inv_sel_stat}'",
                                    self.nodes[0].getblockstats, hash_or_height=1, stats=inv_stat)

        # Make sure we aren't always returning inv_sel_stat as the culprit stat
        assert_raises_rpc_error(-8, f"Invalid selected statistic 'aaa{inv_sel_stat}'",
                                self.nodes[0].getblockstats, hash_or_height=1, stats=['minfee', f'aaa{inv_sel_stat}'])
        # Mainchain's genesis block shouldn't be found on regtest
        assert_raises_rpc_error(-5, 'Block not found', self.nodes[0].getblockstats,
                                hash_or_height='000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f')

        # Invalid number of args
        assert_raises_rpc_error(-1, 'getblockstats hash_or_height ( stats )', self.nodes[0].getblockstats, '00', 1, 2)
        assert_raises_rpc_error(-1, 'getblockstats hash_or_height ( stats )', self.nodes[0].getblockstats)

        self.log.info('Test block height 0')
        genesis_stats = self.nodes[0].getblockstats(0)
        assert_equal(genesis_stats["blockhash"], "2a98a52253aeff06093948b00568d380b7634621bc606403127973c9acbbfde0")
        assert_equal(genesis_stats["utxo_increase"], 1)
        assert_equal(genesis_stats["utxo_size_inc"], 117)
        assert_equal(genesis_stats["utxo_increase_actual"], 0)
        assert_equal(genesis_stats["utxo_size_inc_actual"], 0)

        self.log.info('Test tip including OP_RETURN')
        tip_stats = self.nodes[0].getblockstats(tip)
        assert_equal(tip_stats["utxo_increase"], 6)
        assert_equal(tip_stats["utxo_size_inc"], 441)
        assert_equal(tip_stats["utxo_increase_actual"], 4)
        assert_equal(tip_stats["utxo_size_inc_actual"], 300)

        self.log.info("Test when only header is known")
        block = self.generateblock(self.nodes[0], output="raw(55)", transactions=[], submit=False)
        header = from_hex(CBlock(), block['hex'])
        self.nodes[0].setmocktime(max(self.nodes[0].mocktime, header.nTime))
        self.nodes[0].submitheader(block["hex"])
        assert_raises_rpc_error(-1, "Block not available (not fully downloaded)", lambda: self.nodes[0].getblockstats(block['hash']))

        self.log.info('Test when block is missing')
        (self.nodes[0].blocks_path / 'blk00000.dat').rename(self.nodes[0].blocks_path / 'blk00000.dat.backup')
        assert_raises_rpc_error(-1, 'Block not found on disk', self.nodes[0].getblockstats, hash_or_height=1)
        (self.nodes[0].blocks_path / 'blk00000.dat.backup').rename(self.nodes[0].blocks_path / 'blk00000.dat')


if __name__ == '__main__':
    GetblockstatsTest(__file__).main()
