#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin PoCX developers
# Distributed under the MIT software license; see COPYING.
"""Submit a non-synthetic proof through the scheduler to an accepted payout block."""
from decimal import Decimal

from test_framework.descriptors import descsum_create
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal

# Deliberately differs from the reserved synthetic-regtest forging key.
WIF = 'cNgs3AUH8xu2faRgLBR5kT7mAB6tUJZDDRH5YeKtZw4LqhbapNWd'


class SchedulerPayoutTest(BitcoinTestFramework):
    def set_test_params(self):
        self.seed_blocks = 110
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.uses_wallet = True

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def run_test(self):
        node = self.nodes[0]
        node.setmocktime(1700000000)
        descriptor = f'wpkh({WIF})'
        result = node.importdescriptors([{'desc': descsum_create(descriptor), 'timestamp': 'now'}])
        assert result[0]['success']
        signer, = node.deriveaddresses(node.getdescriptorinfo(descriptor)['descriptor'])
        account = node.getaddressinfo(signer)['witness_program']
        assert account != '1e50bcc17e3c6ab42d39a6a5d79b0d7a6983a765'
        recipient = node.getnewaddress('', 'bech32')
        self.generatetoaddress(node, self.seed_blocks, recipient)
        assert_equal(node.getblockchaininfo()['initialblockdownload'], False)
        parent = node.getbestblockhash()
        parent_time = node.getblockheader(parent)['time']
        # Scheduler uses system_clock deadlines; use a historical parent so its
        # deadline is already past. Mock consensus time permits the proof delay.
        # This exercises forging without pretending mocktime drives its wait.
        node.setmocktime(parent_time + 100000)
        ctx = node.get_mining_info()
        payouts = [{'address': recipient, 'amount_sat': 150000000}]
        with node.assert_debug_log(['[Scheduler] Block forged and accepted!']):
            response = node.submit_nonce(ctx['block_hash'], ctx['height'], ctx['generation_signature'],
                                         ctx['base_target'], account, '00' * 32, 1,
                                         ctx['minimum_compression_level'], 0, payouts)
            assert response['poc_time'] <= 100000, response
            self.wait_until(lambda: node.getblockcount() == self.seed_blocks + 1, timeout=30)
        block = node.getblock(node.getbestblockhash(), 2)
        assert_equal(block['previousblockhash'], parent)
        proof = node.getblockheader(block['hash'])['pocx_proof']
        assert_equal(proof['account_id'], signer)
        assert_equal(proof['nonce'], 1)
        assert_equal(proof['seed'], '00' * 32)
        assert_equal(proof['quality'], response['raw_quality'])
        outputs = block['tx'][0]['vout']
        paid = {v['scriptPubKey'].get('address'): v['value'] for v in outputs if 'address' in v['scriptPubKey']}
        assert_equal(paid, {recipient: 1.5, signer: 8.5})
        assert node.verifychain(4, 0)
        self.check_fees_and_budget(node, account, signer, recipient)

    def check_fees_and_budget(self, node, account, signer, recipient):
        self.log.info('Check fee remainder and forge-time over-budget rejection')
        txid = node.sendtoaddress(node.getnewaddress('', 'bech32'), 1)
        fee = node.getmempoolentry(txid)['fees']['base']
        assert fee > 0
        fee_sat = int(fee * 100000000)
        before = node.getbestblockhash()
        height = node.getblockcount()
        node.setmocktime(node.getblockheader(before)['time'] + 100000)
        ctx = node.get_mining_info()
        args = [ctx['block_hash'], ctx['height'], ctx['generation_signature'], ctx['base_target'],
                account, '00' * 32, 1, ctx['minimum_compression_level'], 0]
        # MoneyRange permits this amount, but it exceeds this template's actual
        # subsidy+fees by one satoshi. Only forge-time budget validation catches it.
        excessive = [{'address': recipient, 'amount_sat': 10 * 100000000 + fee_sat + 1}]
        with node.assert_debug_log(['Payout split rejected: outputs sum > coinbase value',
                                    '[Scheduler] Block building failed']):
            response = node.submit_nonce(*args, excessive)
            assert response['poc_time'] <= 100000, response
        assert_equal(node.getbestblockhash(), before)
        assert txid in node.getrawmempool()
        # The failed attempt must leave the scheduler usable for a valid retry.
        with node.assert_debug_log(['[Scheduler] Block forged and accepted!']):
            node.submit_nonce(*args, [{'address': recipient, 'amount_sat': 150000000}])
            self.wait_until(lambda: node.getblockcount() == height + 1, timeout=30)
        block = node.getblock(node.getbestblockhash(), 2)
        assert_equal(block['previousblockhash'], before)
        assert_equal([tx['txid'] for tx in block['tx'][1:]], [txid])
        outputs = block['tx'][0]['vout']
        paid = {v['scriptPubKey']['address']: v['value'] for v in outputs if 'address' in v['scriptPubKey']}
        assert_equal(paid, {recipient: Decimal('1.5'), signer: Decimal('8.5') + fee})
        assert_equal(sum(v['value'] for v in outputs), Decimal(10) + fee)
        assert_equal(node.getrawmempool(), [])
        assert node.verifychain(4, 0)


if __name__ == '__main__':
    SchedulerPayoutTest(__file__).main()
