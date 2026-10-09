#!/usr/bin/env python3
# Copyright (c) 2019-present The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test basic signet functionality"""

from decimal import Decimal

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal

SIGNET_DEFAULT_CHALLENGE = '512103ad5e0edad18cb1f0fc0d28a3d4f1f3e445640337489abb10404f2d1e086be430210359ef5021964fe22d6f8e05b2463c9540ce96883fe3b278760f048f5189f2e6c452ae'

# These real storage proofs were independently checked against the pinned Rust
# scalar and optimized implementations by test/pocx/kernel/verify_fixtures.py.
# Regtest and Signet share the genesis generation signature/account. Different
# base targets and timestamps below are calculated independently in Python.
REAL_PROOF_HEADERS = ['00000020e0fdbbacc9737912036460bc214663b780d36805b048390906ffae5322a5982ae2fd6c9973e988158ed9d2bc86f1c3b3abb741490009ba0e13d8f0225776c7aa4ee7494d01000000a2f101e6f06c41def4c20fdb0735415fc2f5fee9bed0b76787c2823a10ace19588888888888808000707070707070707070707070707070707070707070707070707070707070707751e76e8199196d454941c45d1b3a323f1433bd60100000001000000000000008a5996222f6a8c540279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f817981fd2345d0b9dd82c898af1362ffe15837125b66bbfeab4de46dee78decd03c467b6d154dfa407c65fba2306d33a57f6af7556ebfe5dc376732fc1d033909c742d500', '00000020991854fe8e40921f3a04a0cc2bfc37d50924ab0f4763ad66262e758f6e7f23b211a82aa4279469756f5f92c978c4bf4af17c4fa763d4ddf725af8da21598cee315e9494d0200000083d94578250e95c3c70b94408a43e6026b28eae875a841180dc6280f55be112d88888888888808000707070707070707070707070707070707070707070707070707070707070707751e76e8199196d454941c45d1b3a323f1433bd6010000000100000000000000ed04fb8a671a379b0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f817981fc7fc018e6e4deecc36209e0003fecab6cef4ddb67f7623ce38b6ca16551f8b8f618b549d664fac0f930715e9a4c66f2253c9062a8b7c67a7a8dd3d6d310b539700', '00000020af54fac4c7d2ffa16f0606dfbd69ce4fd482751dd58248517d3a75e5dd6335f4674730ac1230973afe8f9f16a032370a385304e3e346f9e1c7ea1341fa878ddef7ea494d03000000f842427fa5150ce61e0599724baba2cfeb8ef4d3957e3dde13d680c7be79f67d88888888888808000707070707070707070707070707070707070707070707070707070707070707751e76e8199196d454941c45d1b3a323f1433bd6010000000100000000000000c2b5112d2c101cb80279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f817981fea68cd9b237853f61621349c6c6f9edf4fe2ebd3604db67da8a374a59affe43d3d93608d1d89660787914b56540daf78db0f08f2a19ae7e633416d5cac0a24da00', '000000209458dcb327d8fab8264272b6aeea408f6d721f1a1147e02a6e845b778dbb67df921bb345fee83f789c669151956672b7ec4787b0ad396b123570e24bd714d3a107ed494d04000000696625d75d48dab1368e70239cd0db2f0639b5bb808fa82718840a548c336d5188888888888808000707070707070707070707070707070707070707070707070707070707070707751e76e8199196d454941c45d1b3a323f1433bd601000000010000000000000040fe414382d82ef20279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f8179820bb89e8146dfc500782ad55d61117518ad3d4baa0c6dfe50307c8b5ed62e813420fd32315e9a9eb45c008b7dcc2bdab21222fda12806bb7ea6910634cbd24ad4300', '000000205bb8297c5262a6957f42fb2127b42b5e9a8c90a6665344728c749bb0a841d11647f4967ece4bff0ca4bf673e803d13f7c111a63bd43c9f4cca7cddca9ce3fefc85ee494d050000003f8691da33d997c4ed3363e8c50f44300ac50fbe8621028c78d4ff12e638aeab88888888888808000707070707070707070707070707070707070707070707070707070707070707751e76e8199196d454941c45d1b3a323f1433bd60100000001000000000000003c9f72e503e5cb5b0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f817982042db54415fcb775c9ac61b6360c62b1dac81901167f5291c019ad6298081897010e1cf167ccd88c41a7c6ff1e1d21cdbf18f99a38eabef775370b5eb7e6b72cd00', '00000020654c050ddd1085f01eb332eb3477679798502af40268be626f73fae1fa4d5a60b0a51a39472f22dc7a189f03aa4025ee2c034d94ef8c7d7991e70cc240d734e4a3ef494d06000000600f1833824a9f3e42e0e0f2365bf895550f567a6a8f4c0593a3509c51f0c45288888888888808000707070707070707070707070707070707070707070707070707070707070707751e76e8199196d454941c45d1b3a323f1433bd6010000000100000000000000459c1817dca47f260279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f8179820324847e88667830678c03fc951ff678c97a7b9de614dc7e5bbac7500400492794a92b05bcde11713a314378d9a69eede8755a8ff123191ec5947ee678790e4b800', '00000020efd610f08285292fe640ebce492e77e5bfd569fb75d088dd3e6cb8ad9ac188fefe5efd50711ba558559cd5067173ce0fc0a2e40293e98b0dbf668e6954f90f0265f1494d0700000042cec651c35ee7b1529788bea7d6785385bdc68a525c1fbd082bb20e1e63179588888888888808000707070707070707070707070707070707070707070707070707070707070707751e76e8199196d454941c45d1b3a323f1433bd6010000000100000000000000655710a649ff94960279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f8179820d49f177bfc3806366d6e8ce2d2cd3b54ee89752cc1b9f51181d5d0ea07b258c83384d8108642cef462f0f7aae5f3b3100ba55fe00098b6c6455f2105bb2d27d200', '000000206d11f116db699b7e5a5dac26a9f8feeb177fde0e542516cca44436927dffd8552d080bd0ed4d85fdee69b81d5e1111643606a1e2ced2b7a0bfaf5baff2ad5ada75f3494d0800000068cc25c084363051e309543ee81beab1f4365c6fe1ef0bc4dd2ba93ded93c71c88888888888808000707070707070707070707070707070707070707070707070707070707070707751e76e8199196d454941c45d1b3a323f1433bd6010000000100000000000000f9ca09cfeb7818f30279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798202949ad823f2637db600919af2647f3aa91ade2564f1758049fe7e88f607fe8a8516705598ad46aac1800dae320a873ca4e2e9e745effb4136fd178901f985be800', '0000002095e14f2a598fd9b078805081b849415d8cfc12f339bfb1dee277bf01a061db995174a0a129b20f2bef5439906e161cc18b28f732b09b43f35cd7155d648a720b89f5494d090000008e64a9933d85e8739e81efca2ba01429837689346b429fae7d253b04ca32edfd88888888888808000707070707070707070707070707070707070707070707070707070707070707751e76e8199196d454941c45d1b3a323f1433bd6010000000100000000000000390b7ae19b294bf80279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f8179820d56d3cf643b747d8dc455fa6ae12f299b5f36ecd701a6e96cf9bea568355e90518400fefa2e220d0c962bfc2fc33317d16880b066cfeec7b99a4e0202a3e898f00', '00000020e34f590fb45136a71525717a5567669fc01d62dc605f920918a09516b3fcabb626e7e77b5e188c31a570b8637627c20f0eb2a8b01306eede6ee1f7f67b9d39f552f6494d0a00000002ec460685e723d9ce789a0d9504d817681cf849fc294b287c0e0c49c1561e5288888888888808000707070707070707070707070707070707070707070707070707070707070707751e76e8199196d454941c45d1b3a323f1433bd601000000010000000000000027e9b6f9422e510d0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798208bb6eae5a05c3c85639bb9df2275e92f80f6fb27d5f77102ed05bb5aacb5eb2937095e1912dca7fb616f78f76cfd5bda3f9cb587727c1af49f96fca34e086d1e00']

from io import BytesIO
from pathlib import Path
import copy
import importlib.machinery
import importlib.util

from test_framework.blocktools import add_witness_commitment, create_coinbase, SIGNET_HEADER
from test_framework.crypto import secp256k1
from test_framework.key import ECKey, ORDER, rfc6979_nonce
from test_framework.messages import CBlock, CTransaction, hash256, from_hex, ser_string
from test_framework.psbt import PSBT
from test_framework.script import CScript, OP_0, OP_1, OP_2, OP_CHECKMULTISIG, sign_input_legacy


def challenge_key(number):
    key = ECKey()
    key.set(number.to_bytes(32, 'big'), compressed=True)
    return key


CONTROLLED_CHALLENGE = CScript([OP_1, challenge_key(42).get_pubkey().get_bytes(),
                               challenge_key(43).get_pubkey().get_bytes(), OP_2, OP_CHECKMULTISIG]).hex()
CONTROLLED_TWO_SIGNATURES = CScript([OP_2, challenge_key(42).get_pubkey().get_bytes(),
                                    challenge_key(43).get_pubkey().get_bytes(), OP_2, OP_CHECKMULTISIG]).hex()


def cube_root(value):
    low, high = 0, 1 << ((value.bit_length() + 2) // 3)
    while low + 1 < high:
        mid = (low + high) // 2
        if mid ** 3 <= value:
            low = mid
        else:
            high = mid
    return high if high ** 3 == value else low


def native_deadline(quality, target):
    divisor = (cube_root(120 << 126) * 3927365422841) >> 42
    scale = ((120 << 84) + divisor // 2) // divisor
    return (scale * cube_root((quality << 63) // target) + (1 << 62)) >> 63


def native_target(history):
    cap = (1 << 42) // 120
    if len(history) == 1:
        return cap
    last = history[-1]
    window = min(24, last.nHeight)
    weighted = last.nBaseTarget
    raw_sum, bended_sum = 0, 0
    for index, block in enumerate(reversed(history[-window:])):
        raw_sum += block.pocxProof.quality // block.nBaseTarget
        bended_sum += native_deadline(block.pocxProof.quality, block.nBaseTarget)
        if index:
            weighted = (weighted * (index + 1) + block.nBaseTarget) // (index + 2)
    target_span = window * 120
    actual_span = last.nTime - history[-window - 1].nTime - bended_sum + raw_sum
    actual_span = max(target_span // 2, min(2 * target_span, actual_span))
    adjusted = weighted * actual_span // target_span
    adjusted = max(last.nBaseTarget - last.nBaseTarget // 5,
                   min(last.nBaseTarget + last.nBaseTarget // 5, adjusted))
    return max(1, min(cap, adjusted))


def unsigned_native_block(node, script_pubkey=None):
    height = node.getblockcount() + 1
    assert 1 <= height <= len(REAL_PROOF_HEADERS)
    history = [from_hex(CBlock(), node.getblock(node.getblockhash(h), 0)) for h in range(height)]
    previous = history[-1]
    assert_equal(history[0].hash_hex, '879af7781ec732bef50d912796cc7f0bd44232d4e0d17a4271b96a557f2c7359')
    block = from_hex(CBlock(), REAL_PROOF_HEADERS[height - 1])
    assert_equal(block.generationSignature,
                 int.from_bytes(hash256(previous.generationSignature.to_bytes(32, 'little') + previous.pocxProof.account_id), 'little'))
    assert_equal(block.pocxProof.account_id.hex(), '751e76e8199196d454941c45d1b3a323f1433bd6')
    block.hashPrevBlock = previous.hash_int
    block.nBaseTarget = native_target(history)
    block.nTime = previous.nTime + max(1, native_deadline(block.pocxProof.quality, block.nBaseTarget))
    block.vtx = [create_coinbase(height, script_pubkey=script_pubkey, nValue=10)]
    add_witness_commitment(block)
    block.vtx[0].vout[-1].scriptPubKey = bytes(block.vtx[0].vout[-1].scriptPubKey)
    return block


def native_sign(block):
    key = challenge_key(1)
    assert_equal(block.vchPubKey, key.get_pubkey().get_bytes())
    block.hashMerkleRoot = block.calc_merkle_root()
    digest = hash256(ser_string(b'POCX Signed Block:\n') + ser_string(block.hash_hex.encode()))
    nonce = int.from_bytes(rfc6979_nonce(key.get_bytes() + digest), 'big')
    point = nonce * secp256k1.G
    r = int(point.x) % ORDER
    sig_s = pow(nonce, -1, ORDER) * (int.from_bytes(digest, 'big') + key.secret * r) % ORDER
    recid = (int(point.y) & 1) | (2 if int(point.x) >= ORDER else 0)
    if sig_s > ORDER // 2:
        sig_s = ORDER - sig_s
        recid ^= 1
    block.vchSignature = bytes([31 + recid]) + r.to_bytes(32, 'big') + sig_s.to_bytes(32, 'big')
    return block


def signet_miner_helpers(source_root):
    # Reuse the original tool's BIP325 transaction/PSBT implementation directly.
    # Only its Bitcoin nonce grinding and80byte-header CLI assembly are replaced.
    path = str(Path(source_root) / 'contrib/signet/miner')
    loader = importlib.machinery.SourceFileLoader('upstream_signet_helpers', path)
    spec = importlib.util.spec_from_loader(loader.name, loader)
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    return module


def add_solution(block, solution):
    if solution is not None:
        script = block.vtx[0].vout[-1].scriptPubKey
        block.vtx[0].vout[-1].scriptPubKey = CScript(bytes(script) + bytes(CScript([SIGNET_HEADER + solution])))
    return native_sign(block)


def controlled_signet_block(node, helpers):
    block = unsigned_native_block(node)
    to_sign, _ = helpers.signet_txs(block, bytes.fromhex(CONTROLLED_CHALLENGE))
    to_sign.vin[0].scriptSig = bytes(CScript([OP_0]))
    # CHECKMULTISIG takes dummy first, followed by the one required signature.
    sign_input_legacy(to_sign, 0, CScript(bytes.fromhex(CONTROLLED_CHALLENGE)), challenge_key(42))
    elements = list(CScript(to_sign.vin[0].scriptSig))
    to_sign.vin[0].scriptSig = CScript([OP_0, elements[0]])
    solution = ser_string(to_sign.vin[0].scriptSig) + b'\x00'
    return add_solution(block, solution)


class SignetParams:
    def __init__(self, challenge=None):
        # Prune to prevent disk space warning on CI systems with limited space,
        # when using networks other than regtest.
        if challenge is None:
            self.challenge = SIGNET_DEFAULT_CHALLENGE
            self.shared_args = ["-prune=550"]
        else:
            self.challenge = challenge
            self.shared_args = ["-prune=550", f"-signetchallenge={challenge}"]

class SignetBasicTest(BitcoinTestFramework):
    def set_test_params(self):
        self.chain = "signet"
        self.num_nodes = 8
        self.setup_clean_chain = True
        self.signets = [
            SignetParams(challenge='51'), # OP_TRUE
            SignetParams(challenge=CONTROLLED_CHALLENGE), # controlled1of2 signing keys
            # default challenge as a 2-of-2, which means it should fail
            SignetParams(challenge=CONTROLLED_TWO_SIGNATURES),
            SignetParams(), # exact default challenge still checked on its own pair
        ]

        self.extra_args = [
            self.signets[0].shared_args, self.signets[0].shared_args,
            self.signets[1].shared_args, self.signets[1].shared_args,
            self.signets[2].shared_args, self.signets[2].shared_args,
            self.signets[3].shared_args, self.signets[3].shared_args,
        ]

    def setup_network(self):
        self.setup_nodes()

        # Setup the three signets, which are incompatible with each other
        self.connect_nodes(0, 1)
        self.connect_nodes(2, 3)
        self.connect_nodes(4, 5)
        self.connect_nodes(6, 7)

    def run_test(self):
        self.log.info("basic tests using OP_TRUE challenge")

        self.log.info('getblockchaininfo')
        def check_getblockchaininfo(node_idx, signet_idx):
            blockchain_info = self.nodes[node_idx].getblockchaininfo()
            assert_equal(blockchain_info['chain'], 'signet')
            assert_equal(blockchain_info['signet_challenge'], self.signets[signet_idx].challenge)
        check_getblockchaininfo(node_idx=1, signet_idx=0)
        check_getblockchaininfo(node_idx=2, signet_idx=1)
        check_getblockchaininfo(node_idx=5, signet_idx=2)

        self.log.info('getmininginfo')
        def check_getmininginfo(node_idx, signet_idx):
            mining_info = self.nodes[node_idx].get_mining_info()
            assert_equal(mining_info['blocks'], 0)
            assert_equal(mining_info['base_target'], (1 << 42) // 120)
            assert_equal(mining_info['chain'], 'signet')
            assert 'currentblocktx' not in mining_info
            assert 'currentblockweight' not in mining_info
            assert 'networkhashps' not in mining_info
            assert_equal(mining_info['pooledtx'], 0)
            assert_equal(mining_info['signet_challenge'], self.signets[signet_idx].challenge)
        check_getmininginfo(node_idx=0, signet_idx=0)
        check_getmininginfo(node_idx=3, signet_idx=1)
        check_getmininginfo(node_idx=4, signet_idx=2)

        check_getblockchaininfo(node_idx=6, signet_idx=3)
        check_getmininginfo(node_idx=7, signet_idx=3)
        helpers = signet_miner_helpers(self.config['environment']['SRCDIR'])
        trivial = add_solution(unsigned_native_block(self.nodes[0]), None)
        assert_equal(self.nodes[0].submitblock(trivial.serialize().hex()), None)
        assert_equal(self.nodes[0].getblockcount(), 1)
        signet_blocks = []

        self.log.info("pregenerated signet blocks check")

        height = 0
        for _ in range(10):
            block = controlled_signet_block(self.nodes[2], helpers).serialize().hex()
            signet_blocks.append(block)
            assert_equal(self.nodes[2].submitblock(block), None)
            height += 1
            assert_equal(self.nodes[2].getblockcount(), height)

        self.log.info("pregenerated signet blocks check (incompatible solution)")

        assert_equal(self.nodes[4].submitblock(signet_blocks[0]), 'bad-signet-blksig')

        self.log.info("test that signet logs the network magic on node start")
        with self.nodes[0].assert_debug_log(["Signet derived magic (message start)"]):
            self.restart_node(0)
        self.stop_node(0)
        self.nodes[0].assert_start_raises_init_error(extra_args=["-signetchallenge=abc"], expected_msg="Error: -signetchallenge must be hex, not 'abc'.")
        self.nodes[0].assert_start_raises_init_error(extra_args=["-signetchallenge=abc"] * 2, expected_msg="Error: -signetchallenge cannot be multiple values.")


if __name__ == '__main__':
    SignetBasicTest(__file__).main()
