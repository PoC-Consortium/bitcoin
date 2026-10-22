#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin PoCX developers
# Distributed under the MIT software license; see COPYING.
"""Reject malformed PoCX transitions and accept exact deadline boundaries."""
from copy import deepcopy
from hashlib import sha256
import json
from pathlib import Path

from test_framework.blocktools import create_pocx_block, pocx_deadline, resign_pocx_block, sign_pocx_block_with_key
from test_framework.messages import CBlockHeader
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_greater_than, assert_raises_rpc_error


class PoCXConsensusTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True

    def reject_header(self, block, reason):
        node = self.nodes[0]
        before = node.getbestblockhash()
        assert_raises_rpc_error(-25, reason, node.submitheader, CBlockHeader(block).serialize().hex())
        assert_equal(node.getbestblockhash(), before)

    def run_test(self):
        node = self.nodes[0]
        self.log.info('Use independent Rust proof vectors to reach contextual rejection')
        vectors = json.loads((Path(self.config['environment']['SRCDIR']) /
            'src/pocx/test/data/real_proof_vectors.json').read_text())
        candidate = create_pocx_block(node)
        for vector, reason in zip(vectors[:2], ('bad-gensig', 'bad-height')):
            block = deepcopy(candidate)
            block.nHeight = vector['height']
            block.generationSignature = int(vector['generation_signature'], 16)
            block.pocxProof.account_id = bytes.fromhex(vector['account'])
            block.pocxProof.seed = bytes.fromhex(vector['seed'])
            for field in ('nonce', 'compression', 'quality'):
                setattr(block.pocxProof, field, vector[field])
            # A known key makes the header signature valid. Signer authorization
            # belongs to ConnectBlock, after the contextual rejection under test.
            sign_pocx_block_with_key(block, (1).to_bytes(32, 'big'))
            self.reject_header(block, reason)
        # No wallet dependency: these use the explicitly reserved regtest actor.
        # Proof correctness also has independent Rust vectors in the unit suite;
        # this test isolates contextual rejection and node integration.
        self.generate(node, 12)
        for _ in range(3):
            parent_hash = node.getbestblockhash()
            parent = node.getblockheader(parent_hash)
            block = create_pocx_block(node)
            # Use wire bytes for the predecessor's 20-byte account identifier,
            # independent of display address encodings and node hashing code.
            raw_parent = bytes.fromhex(node.getblockheader(parent_hash, False))
            expected = sha256(sha256(raw_parent[76:108] + raw_parent[148:168]).digest()).digest()
            assert_equal(block.generationSignature, int.from_bytes(expected, 'little'))
            deadline = pocx_deadline(block.pocxProof.quality, block.nBaseTarget)
            assert_greater_than(deadline, 0)
            block.nTime = parent['time'] + deadline
            resign_pocx_block(block)
            node.setmocktime(max(node.mocktime or 0, block.nTime))

            self.log.info('Reject targets that differ from the exact contextual retarget')
            for value in (0, block.nBaseTarget + 1):
                invalid = deepcopy(block)
                invalid.nBaseTarget = value
                resign_pocx_block(invalid)
                self.reject_header(invalid, 'bad-diff')

            self.log.info('Reject the second before the deadline, including backwards time')
            for timestamp in (parent['time'] - 1, parent['time'] + deadline - 1):
                invalid = deepcopy(block)
                invalid.nTime = timestamp
                resign_pocx_block(invalid)
                self.reject_header(invalid, 'time-too-old' if timestamp < parent['time'] else 'bad-pocx-timing')

            self.log.info('Reject a corrupt compact signature without accepting a block')
            invalid = deepcopy(block)
            invalid.vchSignature = bytes([invalid.vchSignature[0] ^ 1]) + invalid.vchSignature[1:]
            self.reject_header(invalid, 'bad-pocx-sig')

            self.log.info('Accept the exact deadline with the valid signature and proof')
            assert_equal(node.submitheader(CBlockHeader(block).serialize().hex()), None)
            assert_equal(node.submitblock(block.serialize().hex()), None)
            assert_equal(node.getbestblockhash(), block.hash_hex)
        assert node.verifychain(4, 0)


if __name__ == '__main__':
    PoCXConsensusTest(__file__).main()
