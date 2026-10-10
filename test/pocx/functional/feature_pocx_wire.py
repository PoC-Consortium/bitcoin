#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin PoCX developers
# Distributed under the MIT software license, see the accompanying file COPYING.
"""Cross-check PoCX header/block wire bytes and signature-zeroed hashes with a node."""
from hashlib import sha256
from io import BytesIO
import struct

from test_framework.messages import CBlock, CBlockHeader, CInv, MSG_BLOCK, msg_getdata, msg_getheaders
from test_framework.p2p import P2PInterface, p2p_lock
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_raises


def check_vector():
    # Independently packed layout, including signed int32 and full-width uint64 fields.
    raw = (struct.pack('<i', -2147483648) + bytes(range(32)) + bytes(range(32, 64))
           + struct.pack('<Ii', 0xffffffff, 2147483647) + bytes(range(64, 96))
           + struct.pack('<Q', 0xfedcba9876543210) + bytes(range(96, 128))
           + bytes(range(128, 148)) + struct.pack('<IQQ', 0xffffffff, 0xffffffffffffffff, 0x876543210fedcba9)
           + bytes(range(148, 181)) + bytes(range(181, 246)))
    assert_equal(len(raw), 286)
    header = CBlockHeader()
    header.deserialize(BytesIO(raw))
    assert_equal(header.serialize(), raw)
    assert_equal(header.nVersion, -2147483648)
    assert_equal(header.nHeight, 2147483647)
    assert_equal(header.pocxProof.nonce, 0xffffffffffffffff)
    assert_equal(header.pocxProof.quality, 0x876543210fedcba9)
    expected = sha256(sha256(raw[:221] + bytes(65)).digest()).digest()[::-1].hex()
    assert_equal(header.hash_hex, expected)
    for size in range(286):
        assert_raises(EOFError, CBlockHeader().deserialize, BytesIO(raw[:size]))
    for offset in range(286):
        changed = bytearray(raw)
        changed[offset] ^= 1
        mutation = CBlockHeader()
        mutation.deserialize(BytesIO(changed))
        assert_equal(mutation.hash_hex == expected, offset >= 221)
    clone = CBlockHeader(header)
    clone.pocxProof.nonce = 0
    assert_equal(header.pocxProof.nonce, 0xffffffffffffffff)


class PoCXWireTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.uses_wallet = True

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def run_test(self):
        check_vector()
        node = self.nodes[0]
        hashes = self.generatetoaddress(node, 3, node.getnewaddress('', 'bech32'))
        raw_blocks = {}
        raw_headers = {}
        for height, blockhash in enumerate(hashes, 1):
            raw_blocks[blockhash] = bytes.fromhex(node.getblock(blockhash, 0))
            raw_headers[blockhash] = bytes.fromhex(node.getblockheader(blockhash, False))
            block = CBlock()
            block.deserialize(BytesIO(raw_blocks[blockhash]))
            header = CBlockHeader(block)
            assert_equal(block.serialize(), raw_blocks[blockhash])
            assert_equal(header.serialize(), raw_headers[blockhash])
            assert_equal(len(header.serialize()), 286)
            assert_equal(block.hash_hex, header.hash_hex, blockhash)
            assert_equal(block.calc_merkle_root(), block.hashMerkleRoot)
            info = node.getblockheader(blockhash)
            assert_equal(block.nHeight, info['height'], height)
            assert_equal(block.nBaseTarget, info['base_target'])
            assert_equal(f'{block.generationSignature:064x}', info['generation_signature'])
            proof = info['pocx_proof']
            assert_equal(block.pocxProof.seed.hex(), proof['seed'])
            for field in ('compression', 'nonce', 'quality'):
                assert_equal(getattr(block.pocxProof, field), proof[field])
            assert_equal(block.pocxProof.account_id.hex(), node.validateaddress(proof['account_id'])['witness_program'])
            assert block.vchSignature != bytes(65)

        peer = node.add_p2p_connection(P2PInterface())
        request = msg_getheaders()
        request.locator.vHave = [int(node.getblockhash(0), 16)]
        peer.send_without_ping(request)
        peer.wait_for_header(hashes[0])
        with p2p_lock:
            headers = peer.last_message['headers'].headers
            assert_equal([h.hash_hex for h in headers], hashes)
            assert_equal([h.serialize() for h in headers], [raw_headers[h] for h in hashes])
        for blockhash in hashes:
            peer.send_without_ping(msg_getdata([CInv(MSG_BLOCK, int(blockhash, 16))]))
            peer.wait_for_block(int(blockhash, 16))
            with p2p_lock:
                received = peer.last_message['block'].block
                # MSG_BLOCK excludes witness, while RPC returns witness serialization.
                reference = CBlock()
                reference.deserialize(BytesIO(raw_blocks[blockhash]))
                assert_equal(received.serialize(with_witness=False), reference.serialize(with_witness=False))
        node.disconnect_p2ps()


if __name__ == '__main__':
    PoCXWireTest(__file__).main()
