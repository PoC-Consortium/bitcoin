#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin PoCX developers
# Distributed under the MIT software license; see COPYING.
"""Preserve all five cases from test-regtest-submitblock-sign-v2.sh."""
from io import BytesIO

from test_framework.authproxy import JSONRPCException
from test_framework.descriptors import descsum_create
from test_framework.messages import CBlock, CTxOut
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal

FORGING_WIF = 'cMvJbCxo3qCee5EFHSYVuK7UP69ijvHtXmrikzKtjbtEvzUYU5T5'


class SubmitBlockSigningTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.uses_wallet = True
        self.wallet_names = [False]

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def import_key(self, name):
        node = self.nodes[0]
        node.createwallet(name, blank=True, descriptors=True)
        wallet = node.get_wallet_rpc(name)
        result = wallet.importdescriptors([{'desc': descsum_create(f'wpkh({FORGING_WIF})'), 'timestamp': 'now'}])
        assert_equal(len(result), 1)
        assert result[0]['success']
        assert wallet.getaddressinfo(self.address)['ismine']
        return wallet

    def candidate(self):
        node = self.nodes[0]
        self.clock = max(self.clock, node.getblockheader(node.getbestblockhash())['time']) + 600
        node.setmocktime(self.clock)
        before = node.getbestblockhash()
        result = self.generateblock(node, self.address, [], False, sync_fun=self.no_op)
        assert_equal(node.getbestblockhash(), before)
        block = CBlock()
        block.deserialize(BytesIO(bytes.fromhex(result['hex'])))
        assert_equal(block.hash_hex, result['hash'])
        assert block.vchSignature != bytes(65)
        return block

    def accept(self, block, *, signed_as_is=False):
        node = self.nodes[0]
        height = node.getblockcount()
        original = block.serialize()
        assert_equal(node.submitblock(original.hex()), None)
        assert_equal(node.getblockcount(), height + 1)
        assert_equal(node.getbestblockhash(), block.hash_hex)
        stored = CBlock()
        stored.deserialize(BytesIO(bytes.fromhex(node.getblock(block.hash_hex, 0))))
        assert stored.vchSignature != bytes(65)
        if signed_as_is:
            assert_equal(stored.serialize(), original)
        else:
            # Auto-signing must preserve all bytes except the compact signature.
            stored.vchSignature = bytes(65)
            assert_equal(stored.serialize(), original)

    def reject_unsigned(self, block, *, locked=False):
        node = self.nodes[0]
        block.vchSignature = bytes(65)
        before = (node.getblockcount(), node.getbestblockhash())
        try:
            node.submitblock(block.serialize().hex())
        except JSONRPCException as error:
            assert_equal(error.error['code'], -5)
            assert self.address in error.error['message'], error.error
            if locked:
                assert 'walletpassphrase' in error.error['message'], error.error
        else:
            raise AssertionError('Unsigned block accepted without an available signing key')
        assert_equal((node.getblockcount(), node.getbestblockhash()), before)

    def run_test(self):
        node = self.nodes[0]
        self.clock = 2000000000
        descriptor = node.getdescriptorinfo(f'wpkh({FORGING_WIF})')['descriptor']
        self.address, = node.deriveaddresses(descriptor)
        self.log.info('A: unlocked signer auto-signs an unsigned block')
        self.import_key('keyed')
        block = self.candidate()
        expected_hash = block.hash_hex
        block.vchSignature = bytes(65)
        assert_equal(block.hash_hex, expected_hash)
        self.accept(block)
        node.unloadwallet('keyed')

        self.log.info('B: signed block is accepted byte-for-byte without loaded wallets')
        assert_equal(node.listwallets(), [])
        self.accept(self.candidate(), signed_as_is=True)

        self.log.info('C: loaded wallet without the key cannot sign')
        node.createwallet('other', blank=True, descriptors=True)
        self.reject_unsigned(self.candidate())
        node.unloadwallet('other')

        self.log.info('D: encrypted locked signer is rejected with an unlock hint')
        wallet = self.import_key('keyed_locked')
        wallet.encryptwallet('hodor')
        assert_equal(wallet.getwalletinfo()['unlocked_until'], 0)
        self.reject_unsigned(self.candidate(), locked=True)
        node.unloadwallet('keyed_locked')

        self.log.info('E: split coinbase preserves proof and receives a new signature')
        self.import_key('keyed2')
        block = self.candidate()
        assert_equal(len(block.vtx), 1)
        before = block.serialize()
        coinbase = block.vtx[0]
        old_total = sum(output.nValue for output in coinbase.vout)
        scripts = [bytes.fromhex('0014' + value * 20) for value in ('11', '22')]
        for index, output in enumerate(coinbase.vout):
            if output.scriptPubKey and output.scriptPubKey[0] != 0x6a:
                values = [output.nValue // 2, output.nValue - output.nValue // 2]
                coinbase.vout[index:index + 1] = [CTxOut(value, script) for value, script in zip(values, scripts)]
                break
        else:
            raise AssertionError('No coinbase reward output')
        assert_equal(sum(output.nValue for output in coinbase.vout), old_total)
        block.hashMerkleRoot = block.calc_merkle_root()
        block.vchSignature = bytes(65)
        after = block.serialize()
        assert_equal(after[:36], before[:36])
        assert_equal(after[68:221], before[68:221])
        self.accept(block)
        accepted = node.getblock(block.hash_hex, 2)['tx'][0]['vout']
        for script, value in zip(scripts, values):
            matches = [v for v in accepted if v['scriptPubKey']['hex'] == script.hex()]
            assert_equal(len(matches), 1)
            assert_equal(matches[0]['value'] * 100000000, value)
        node.unloadwallet('keyed2')
        assert node.verifychain(4, 0)


if __name__ == '__main__':
    SubmitBlockSigningTest(__file__).main()
