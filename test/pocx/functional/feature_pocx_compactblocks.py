#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin PoCX developers
# Distributed under the MIT software license; see COPYING.
"""Exchange signed PoCX compact blocks and reconstruct missing witness transactions."""
from hashlib import sha256
from io import BytesIO
import struct

from test_framework.crypto.siphash import siphash256
from test_framework.messages import (
    BlockTransactions, CBlock, CInv, HeaderAndShortIDs, MSG_CMPCT_BLOCK,
    msg_blocktxn, msg_cmpctblock, msg_getdata, msg_sendcmpct, msg_tx,
)
from test_framework.p2p import P2PInterface, p2p_lock
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal


class PoCXCompactBlocksTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 2
        self.setup_clean_chain = True
        self.uses_wallet = True
        self.extra_args = [[], ['-maxtipage=34560000']]

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def run_test(self):
        source, target = self.nodes
        # An observer clock ahead of forging deadlines avoids future-header
        # rejection while ordinary P2P establishes the shared funding chain.
        source.setmocktime(2000000000)
        target.setmocktime(2031536000)
        address = source.getnewaddress('', 'bech32')
        self.generatetoaddress(source, 110, address)
        parent = source.getbestblockhash()
        assert_equal(target.getbestblockhash(), parent)
        assert_equal(target.getblockchaininfo()['initialblockdownload'], False)
        self.disconnect_nodes(0, 1)
        txids = [source.sendtoaddress(source.getnewaddress('', 'bech32'), 1) for _ in range(2)]
        assert_equal(target.getrawmempool(), [])
        blockhash, = self.generatetoaddress(source, 1, address, sync_fun=self.no_op)
        raw = bytes.fromhex(source.getblock(blockhash, 0))
        block = CBlock()
        block.deserialize(BytesIO(raw))
        assert_equal(block.hash_hex, blockhash)
        assert_equal(block.nHeight, 111)
        assert_equal({tx.txid_hex for tx in block.vtx[1:]}, set(txids))
        assert all(not tx.wit.is_null() for tx in block.vtx[1:])
        assert block.vchSignature != bytes(65)
        # Compact reconstruction uses CanDirectFetch's recent-tip condition.
        # Leave the parked observer clock once the shared chain is established.
        target.setmocktime(block.nTime)

        # Download a compact block from a real node and independently derive its
        # BIP152 keys from the native wire header, including the signature.
        outgoing = source.add_p2p_connection(P2PInterface())
        outgoing.send_and_ping(msg_sendcmpct(announce=False, version=2))
        outgoing.send_without_ping(msg_getdata([CInv(MSG_CMPCT_BLOCK, int(blockhash, 16))]))
        outgoing.wait_until(lambda: 'cmpctblock' in outgoing.last_message)
        with p2p_lock:
            compact = outgoing.last_message['cmpctblock'].header_and_shortids
        native_header = bytes.fromhex(source.getblockheader(blockhash, False))
        assert_equal(compact.header.serialize(), native_header)
        assert_equal(len(native_header), 286)
        assert_equal(compact.header.hash_hex, blockhash)
        assert_equal([tx.index for tx in compact.prefilled_txn], [0])
        keys = struct.unpack('<QQ', sha256(native_header + struct.pack('<Q', compact.nonce)).digest()[:16])
        expected = [siphash256(*keys, tx.wtxid_int) & 0xffffffffffff for tx in block.vtx[1:]]
        assert_equal(compact.shortids, expected)
        assert_equal(compact.prefilled_txn[0].tx.serialize_with_witness(), block.vtx[0].serialize_with_witness())

        # The target has the parent but none of these transactions. Its request
        # must identify every missing non-coinbase slot before block acceptance.
        incoming = target.add_p2p_connection(P2PInterface())
        incoming.send_and_ping(msg_sendcmpct(announce=False, version=2))
        encoded = HeaderAndShortIDs()
        encoded.initialize_from_block(block, nonce=0x123456789abcdef0, use_witness=True)
        incoming.send_without_ping(msg_cmpctblock(encoded.to_p2p()))
        incoming.wait_until(lambda: 'getblocktxn' in incoming.last_message)
        with p2p_lock:
            request = incoming.last_message['getblocktxn'].block_txn_request
        assert_equal(request.blockhash, int(blockhash, 16))
        assert_equal(request.to_absolute(), list(range(1, len(block.vtx))))
        assert_equal(target.getbestblockhash(), parent)
        response = msg_blocktxn()
        response.block_transactions = BlockTransactions(request.blockhash, [block.vtx[i] for i in request.to_absolute()])
        incoming.send_and_ping(response)
        self.wait_until(lambda: target.getbestblockhash() == blockhash)
        assert_equal(target.getblock(blockhash, 0), raw.hex())
        self.check_mempool_reconstruction(source, target, incoming, address)
        assert target.verifychain(4, 0)
        source.disconnect_p2ps()
        target.disconnect_p2ps()

    def check_mempool_reconstruction(self, source, target, peer, address):
        self.log.info('Reconstruct a compact block directly from witness transactions in the mempool')
        txids = [source.sendtoaddress(source.getnewaddress('', 'bech32'), 1) for _ in range(2)]
        parent = target.getbestblockhash()
        blockhash, = self.generatetoaddress(source, 1, address, sync_fun=self.no_op)
        block = CBlock()
        block.deserialize(BytesIO(bytes.fromhex(source.getblock(blockhash, 0))))
        assert_equal(block.nHeight, 112)
        assert_equal({tx.txid_hex for tx in block.vtx[1:]}, set(txids))
        target.setmocktime(block.nTime)
        for tx in block.vtx[1:]:
            assert not tx.wit.is_null()
            peer.send_and_ping(msg_tx(tx))
        assert_equal(set(target.getrawmempool()), set(txids))
        assert_equal(target.getbestblockhash(), parent)
        with p2p_lock:
            peer.last_message.pop('getblocktxn', None)
        encoded = HeaderAndShortIDs()
        encoded.initialize_from_block(block, nonce=0xfedcba9876543210, use_witness=True)
        peer.send_and_ping(msg_cmpctblock(encoded.to_p2p()))
        self.wait_until(lambda: target.getbestblockhash() == blockhash)
        with p2p_lock:
            assert 'getblocktxn' not in peer.last_message
        assert_equal(target.getblock(blockhash, 0), source.getblock(blockhash, 0))
        assert_equal(target.getrawmempool(), [])


if __name__ == '__main__':
    PoCXCompactBlocksTest(__file__).main()
