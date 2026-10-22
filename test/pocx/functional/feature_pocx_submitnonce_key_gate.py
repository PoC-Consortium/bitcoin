#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin PoCX developers
# Distributed under the MIT software license; see COPYING.
"""Port all five receive-path cases from test-regtest-submitnonce-key-gate-v2.sh.

RPC acknowledgement is not evidence of eventual scheduler forging.
"""
from test_framework.authproxy import JSONRPCException
from test_framework.descriptors import descsum_create
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal

WIF = 'cNgs3AUH8xu2faRgLBR5kT7mAB6tUJZDDRH5YeKtZw4LqhbapNWd'


class SubmitNonceKeyGateTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.uses_wallet = True
        self.wallet_names = [False]

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def make_wallet(self, name, *, watch=False, locked=False):
        node = self.nodes[0]
        node.createwallet(name, disable_private_keys=watch, blank=True, descriptors=True)
        wallet = node.get_wallet_rpc(name)
        desc = self.public_desc if watch else descsum_create(f'wpkh({WIF})')
        result = wallet.importdescriptors([{'desc': desc, 'timestamp': 'now'}])
        assert_equal(len(result), 1)
        assert result[0]['success']
        info = wallet.getaddressinfo(self.address)
        assert info['ismine'] and info['solvable']
        assert_equal(wallet.getwalletinfo()['private_keys_enabled'], not watch)
        if locked:
            wallet.encryptwallet('hodor')
            assert_equal(wallet.getwalletinfo()['unlocked_until'], 0)
        return wallet

    def submit(self):
        node = self.nodes[0]
        ctx = node.get_mining_info()
        return node.submit_nonce(ctx['block_hash'], ctx['height'], ctx['generation_signature'],
                                 ctx['base_target'], self.account, '00' * 32, 1,
                                 ctx['minimum_compression_level'], 0)

    def rejected(self, code, *, locked=False):
        node = self.nodes[0]
        before = node.getbestblockhash()
        try:
            self.submit()
        except JSONRPCException as error:
            assert_equal(error.error['code'], code)
            message = error.error['message']
            assert self.address in message, message
            assert self.account not in message, message
            if locked:
                assert 'walletpassphrase' in message, message
        else:
            raise AssertionError('submit_nonce accepted without an available private key')
        assert_equal(node.getbestblockhash(), before)

    def accepted(self):
        result = self.submit()
        assert 'raw_quality' in result and 'poc_time' in result, result
        assert int(result['raw_quality']) >= 0
        assert result['poc_time'] >= 0

    def run_test(self):
        node = self.nodes[0]
        self.public_desc = node.getdescriptorinfo(f'wpkh({WIF})')['descriptor']
        self.address, = node.deriveaddresses(self.public_desc)
        self.account = node.validateaddress(self.address)['witness_program']
        assert_equal(len(self.account), 40)
        self.log.info('A: registered, solvable watch-only script still lacks the signing key')
        self.make_wallet('wo', watch=True)
        self.rejected(-5)
        node.unloadwallet('wo')
        self.log.info('B: encrypted locked private key requires unlocking')
        self.make_wallet('locked', locked=True)
        self.rejected(-13, locked=True)
        node.unloadwallet('locked')
        self.log.info('C: available key passes the receive-path gate')
        self.make_wallet('keyed')
        self.accepted()
        node.unloadwallet('keyed')
        for names, locks in ((('locked_first', 'keyed_second'), (True, False)),
                             (('keyed_first', 'locked_second'), (False, True))):
            self.log.info('Multi-wallet load order: %s', names)
            for name, locked in zip(names, locks):
                self.make_wallet(name, locked=locked)
            assert_equal(set(node.listwallets()), set(names))
            self.accepted()
            for name in names:
                node.unloadwallet(name)


if __name__ == '__main__':
    SubmitNonceKeyGateTest(__file__).main()
