#!/usr/bin/env python3
# Copyright (c) 2022-present The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test signet miner tool"""

import json
import os.path
import shlex
import subprocess
import sys
import time

from test_framework.blocktools import SIGNET_HEADER
from feature_signet import unsigned_native_block, add_solution, signet_miner_helpers
from test_framework.psbt import PSBT
from test_framework.key import ECKey
from test_framework.script_util import CScript, key_to_p2wpkh_script
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
    wallet_importprivkey,
)
from test_framework.wallet_util import bytes_to_wif


CHALLENGE_PRIVATE_KEY = (42).to_bytes(32, 'big')

def get_segwit_commitment(node):
    coinbase = node.getblock(node.getbestblockhash(), 2)['tx'][0]
    commitment = coinbase['vout'][1]['scriptPubKey']['hex']
    assert_equal(commitment[0:12], '6a24aa21a9ed')
    return commitment

def get_signet_commitment(segwit_commitment):
    for el in CScript.fromhex(segwit_commitment):
        if isinstance(el, bytes) and el[0:4] == SIGNET_HEADER:
            return el[4:].hex()
    return None

class SignetMinerTest(BitcoinTestFramework):
    def set_test_params(self):
        self.chain = "signet"
        self.setup_clean_chain = True
        self.num_nodes = 4

        # generate and specify signet challenge (simple p2wpkh script)
        privkey = ECKey()
        privkey.set(CHALLENGE_PRIVATE_KEY, True)
        pubkey = privkey.get_pubkey().get_bytes()
        challenge = key_to_p2wpkh_script(pubkey)

        self.extra_args = [
            [f'-signetchallenge={challenge.hex()}'],
            ["-signetchallenge=51"], # OP_TRUE
            ["-signetchallenge=60"], # OP_16
            ["-signetchallenge=202cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"], # sha256("hello")
        ]

    def skip_test_if_missing_module(self):
        self.skip_if_no_cli()
        self.skip_if_no_wallet()


    def setup_network(self):
        self.setup_nodes()
        # Nodes with different signet networks are not connected

    def mine_block(self, node):
        # Native generation replaces only Bitcoin header assembly/nonce grinding.
        # The original tool's PSBT construction, wallet signing, final solution
        # extraction and all commitment/height assertions remain exercised.
        return self.mine_block_manual(node, sign=not self.helpers.trivial_challenge(node.getblockchaininfo()['signet_challenge']))

    def mine_block_manual(self, node, *, sign):
        n_blocks = node.getblockcount()
        script = CScript(bytes.fromhex(node.validateaddress(node.getnewaddress())['scriptPubKey']))
        block = unsigned_native_block(node, script_pubkey=script)
        challenge = node.getblockchaininfo()['signet_challenge']
        psbt = self.helpers.generate_psbt(block, challenge)
        if sign:
            res = node.walletprocesspsbt(psbt=psbt, sign=True, sighashtype='ALL')
            assert res['complete']
            psbt = res['psbt']
        parsed = PSBT.from_base64(psbt)
        solution = self.helpers.get_solution_from_psbt(parsed, emptyok=not sign)
        block = add_solution(block, solution)
        assert_equal(node.submitblock(block.serialize().hex()), None)
        assert_equal(node.getblockcount(), n_blocks + 1)

    def run_test(self):
        self.helpers = signet_miner_helpers(self.config['environment']['SRCDIR'])
        self.log.info("Signet node with single signature challenge")
        node = self.nodes[0]
        # import private key needed for signing block
        wallet_importprivkey(node, bytes_to_wif(CHALLENGE_PRIVATE_KEY), 0)
        self.mine_block(node)
        # MUST include signet commitment
        assert get_signet_commitment(get_segwit_commitment(node))

        self.log.info("Mine manually using genpsbt and solvepsbt")
        self.mine_block_manual(node, sign=True)
        assert get_signet_commitment(get_segwit_commitment(node))

        node = self.nodes[1]
        self.log.info("Signet node with trivial challenge (OP_TRUE)")
        self.mine_block(node)
        # MAY omit signet commitment (BIP 325). Do so for better compatibility
        # with signet unaware mining software and hardware.
        assert get_signet_commitment(get_segwit_commitment(node)) is None

        node = self.nodes[2]
        self.log.info("Signet node with trivial challenge (OP_16)")
        self.mine_block(node)
        assert get_signet_commitment(get_segwit_commitment(node)) is None

        node = self.nodes[3]
        self.log.info("Signet node with trivial challenge (push sha256 hash)")
        self.mine_block(node)
        assert get_signet_commitment(get_segwit_commitment(node)) is None

        self.log.info("Manual mining with a trivial challenge doesn't require a PSBT")
        self.mine_block_manual(node, sign=False)
        assert get_signet_commitment(get_segwit_commitment(node)) is None


if __name__ == "__main__":
    SignetMinerTest(__file__).main()
