#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin PoCX developers
# Distributed under the MIT software license; see COPYING.
"""Actual plot signing at assignment boundaries, competing forks and cold state.

The plot is HASH160(pubkey(secret=1)), deliberately outside the synthetic regtest
selector. Every tested block comes from submit_nonce through the scheduler. A
walletless peer checks crypto-valid but unauthorized signatures in ConnectBlock.
Expectations use fixed regtest delays (4/8), never get_assignment as an oracle.
"""
import copy
from decimal import Decimal
from io import BytesIO
import json
from pathlib import Path

from test_framework.address import byte_to_base58, key_to_p2wpkh
from test_framework.crypto import secp256k1
from test_framework.descriptors import descsum_create
from test_framework.key import ECKey, ECPubKey, ORDER, rfc6979_nonce
from test_framework.messages import CBlock, hash256, ser_string
from test_framework.script import hash160
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_raises_rpc_error


MAGIC = b'POCX Signed Block:\n'
SYNTHETIC_ACCOUNT = bytes.fromhex('1e50bcc17e3c6ab42d39a6a5d79b0d7a6983a765')


def proof_deadline(quality, target):
    def cube_root(value):
        lo, hi = 0, 1 << ((value.bit_length() + 2) // 3)
        while lo + 1 < hi:
            mid = (lo + hi) // 2
            if mid ** 3 <= value:
                lo = mid
            else:
                hi = mid
        return hi if hi ** 3 == value else lo

    divisor = (cube_root(120 << 126) * 3927365422841) >> 42
    scale = ((120 << 84) + divisor // 2) // divisor
    return (scale * cube_root((quality << 63) // target) + (1 << 62)) >> 63


def signature_hash(block):
    # Independently slice native wire offsets: signature is excluded from the
    # block hash, but the stored public key is included. Both domain operands
    # are serialized strings; the second contains displayed hexadecimal.
    raw = block.serialize()[:286]
    displayed = hash256(raw[:221] + bytes(65))[::-1].hex()
    assert_equal(displayed, block.hash_hex)
    return hash256(ser_string(MAGIC) + ser_string(displayed.encode()))


def verify_compact(block):
    signature = block.vchSignature
    assert len(signature) == 65 and 31 <= signature[0] <= 34
    recid = signature[0] - 31
    r = int.from_bytes(signature[1:33], 'big')
    s = int.from_bytes(signature[33:], 'big')
    assert 0 < r < ORDER and 0 < s <= ORDER // 2
    digest = signature_hash(block)
    # Independent recovery checks the compact recovery bit as well as ECDSA.
    x = r + (recid >> 1) * ORDER
    assert x < secp256k1.FE.SIZE
    point = secp256k1.GE.from_bytes(bytes([2 + (recid & 1)]) + x.to_bytes(32, 'big'))
    assert point is not None
    inverse = pow(r, -1, ORDER)
    recovered = secp256k1.GE.mul((s * inverse, point),
                               (-int.from_bytes(digest, 'big') * inverse, secp256k1.G))
    assert not recovered.infinity
    assert_equal(recovered.to_bytes_compressed(), block.vchPubKey)
    rb = r.to_bytes((r.bit_length() + 8) // 8, 'big')
    sb = s.to_bytes((s.bit_length() + 8) // 8, 'big')
    der = b'\x30' + bytes([4 + len(rb) + len(sb), 2, len(rb)]) + rb + bytes([2, len(sb)]) + sb
    pubkey = ECPubKey()
    pubkey.set(block.vchPubKey)
    assert pubkey.verify_ecdsa(der, digest)


def resign(block, key):
    block.vchPubKey = key.get_pubkey().get_bytes()
    digest = signature_hash(block)
    nonce = int.from_bytes(rfc6979_nonce(key.get_bytes() + digest), 'big')
    point = nonce * secp256k1.G
    r = int(point.x) % ORDER
    s = (pow(nonce, -1, ORDER) * (int.from_bytes(digest, 'big') + key.secret * r)) % ORDER
    recid = (int(point.y) & 1) | (2 if int(point.x) >= ORDER else 0)
    if s > ORDER // 2:
        s = ORDER - s
        recid ^= 1
    block.vchSignature = bytes([31 + recid]) + r.to_bytes(32, 'big') + s.to_bytes(32, 'big')
    verify_compact(block)


class AssignmentSignersTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 2
        self.setup_clean_chain = True
        self.pocx_synchronized_generation = True
        self.uses_wallet = True
        self.wallet_names = [self.default_wallet_name, False]
        # Historical deadlines let the real-clock scheduler forge immediately.
        # Cold rollback tips must stay outside IBD while peers are disconnected.
        self.extra_args = [['-fallbackfee=0.00001', '-maxtipage=34560000'],
                           ['-disablewallet', '-maxtipage=34560000']]

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def import_signer(self, name, scalar):
        key = ECKey()
        key.set(scalar.to_bytes(32, 'big'), compressed=True)
        address = key_to_p2wpkh(key.get_pubkey().get_bytes())
        wif = byte_to_base58(key.get_bytes() + b'\x01', 239)
        node = self.nodes[0]
        node.createwallet(name, blank=False, descriptors=True)
        wallet = node.get_wallet_rpc(name)
        result = wallet.importdescriptors([{'desc': descsum_create(f'wpkh({wif})'), 'timestamp': 'now'}])
        assert_equal([item['success'] for item in result], [True])
        assert_equal(wallet.getaddressinfo(address)['witness_program'], hash160(key.get_pubkey().get_bytes()).hex())
        return key, address

    def state(self, expected, nodes=None):
        for node in nodes or self.nodes:
            assert_equal(node.get_assignment(self.plot)['state'], expected)

    def clock_for_proof(self):
        parent_time = self.nodes[0].getblockheader(self.nodes[0].getbestblockhash())['time']
        clock = max(parent_time + 100000, *(node.mocktime for node in self.nodes))
        for node in self.nodes:
            node.setmocktime(clock)

    def nonce_args(self):
        node = self.nodes[0]
        ctx = node.get_mining_info()
        assert_equal(ctx['height'], node.getblockcount() + 1)
        assert_equal(ctx['minimum_compression_level'], 1)
        return [ctx['block_hash'], ctx['height'], ctx['generation_signature'], ctx['base_target'],
                self.account.hex(), '00' * 32, 1, 1, 0]

    def missing_signer(self, address, code=-5):
        self.clock_for_proof()
        node = self.nodes[0]
        before = node.getbestblockhash()
        assert_raises_rpc_error(code, address, node.submit_nonce, *self.nonce_args())
        assert_equal(node.getbestblockhash(), before)

    def reject_wrong_signers(self, block, validator):
        correct_hash = block.hash_hex
        validator.invalidateblock(correct_hash)
        assert_equal(validator.getblockcount(), block.nHeight - 1)
        parent = validator.getbestblockhash()
        assert_equal(int(parent, 16), block.hashPrevBlock)
        for key in (self.owner_key, self.farmer_key):
            if key.get_pubkey().get_bytes() == block.vchPubKey:
                continue
            wrong = copy.deepcopy(block)
            resign(wrong, key)
            # Everything outside the signer fields is the same valid real proof,
            # parent, timestamp and transactions. Rejection must reach the
            # contextual assignment check, not fail generic signature recovery.
            assert_equal(wrong.serialize()[:188], block.serialize()[:188])
            assert_equal(wrong.serialize()[286:], block.serialize()[286:])
            assert wrong.hash_hex != correct_hash
            with validator.assert_debug_log(['bad-pocx-assignment-sig']):
                assert_equal(validator.submitblock(wrong.serialize().hex()), 'bad-pocx-assignment-sig')
            assert_equal(validator.getbestblockhash(), parent)
            self.rejections.append({'height': block.nHeight, 'hash': wrong.hash_hex,
                                    'signer': hash160(wrong.vchPubKey).hex(),
                                    'reason': 'bad-pocx-assignment-sig', 'validator': validator.index})
        validator.reconsiderblock(correct_hash)
        assert_equal(validator.getbestblockhash(), correct_hash)

    def forge(self, expected_key, label, *, connected=True, split_sat=0):
        node, peer = self.nodes
        self.clock_for_proof()
        args = self.nonce_args()
        parent, height = node.getbestblockhash(), node.getblockcount()
        if split_sat:
            args.append([{'address': self.mining, 'amount_sat': split_sat}])
        with node.assert_debug_log(['[Scheduler] Block forged and accepted!']):
            response = node.submit_nonce(*args)
            assert response['poc_time'] <= 100000, response
            self.wait_until(lambda: node.getblockcount() == height + 1, timeout=30)
        if connected:
            self.sync_blocks()
        raw = bytes.fromhex(node.getblock(node.getbestblockhash(), 0))
        block = CBlock()
        block.deserialize(BytesIO(raw))
        assert_equal(block.serialize(), raw)
        assert_equal(block.hash_hex, node.getbestblockhash())
        assert_equal(block.nHeight, height + 1)
        assert_equal(block.hashPrevBlock, int(parent, 16))
        assert_equal(block.pocxProof.account_id, self.account)
        assert block.pocxProof.account_id != SYNTHETIC_ACCOUNT
        assert_equal(block.pocxProof.seed, bytes(32))
        assert_equal(block.pocxProof.nonce, 1)
        assert_equal(block.pocxProof.compression, 1)
        assert_equal(block.pocxProof.quality, int(response['raw_quality']))
        assert_equal(response['poc_time'], proof_deadline(block.pocxProof.quality, block.nBaseTarget))
        parent_raw = bytes.fromhex(node.getblockheader(parent, False))
        assert_equal(block.generationSignature.to_bytes(32, 'little'),
                     hash256(parent_raw[76:108] + parent_raw[148:168]))
        assert block.nTime >= int.from_bytes(parent_raw[68:72], 'little') + response['poc_time']
        assert_equal(block.vchPubKey, expected_key.get_pubkey().get_bytes())
        verify_compact(block)
        if connected:
            assert_equal(bytes.fromhex(peer.getblock(block.hash_hex, 0)), raw)
        self.reject_wrong_signers(block, peer if connected else node)
        self.records.append({'label': label, 'height': block.nHeight, 'hash': block.hash_hex,
                             'parent': parent, 'signer': hash160(block.vchPubKey).hex()})
        (self.output / f'{block.hash_hex}.bin').write_bytes(raw)
        self.proofs.append(','.join([f'{block.generationSignature:064x}', self.account.hex(),
                                     block.pocxProof.seed.hex(), str(block.pocxProof.nonce),
                                     str(block.nHeight), str(block.pocxProof.compression),
                                     str(block.pocxProof.quality)]))
        return block.hash_hex

    def cold_state(self, expected, *, producer=False, reindex=False):
        indices = (0,) if producer else (1,)
        for index in indices:
            node = self.nodes[index]
            tip = node.getbestblockhash()
            wallets = node.listwallets() if index == 0 else []
            was_connected = bool(node.getpeerinfo())
            node.gettxoutsetinfo()  # Flush the assignment row; exercise DB reads.
            args = self.extra_args[index] + (['-reindex-chainstate'] if reindex else [])
            self.restart_node(index, extra_args=args)
            for name in wallets:
                if name not in node.listwallets():
                    node.loadwallet(name)
            assert_equal(node.getbestblockhash(), tip)
            assert not node.getblockchaininfo()['initialblockdownload']
            assert node.verifychain(4, 0)
            self.state(expected, [node])
            if was_connected:
                self.connect_nodes(0, 1)
                self.sync_blocks()

    def competing_boundary_fork(self, first_hash, expected_state, signer, label, split_sat):
        node, peer = self.nodes
        old_tip = peer.getbestblockhash()
        old_work = int(peer.getblockheader(old_tip)['chainwork'], 16)
        first_height = node.getblockheader(first_hash)['height']
        self.disconnect_nodes(0, 1)
        node.gettxoutsetinfo()
        node.invalidateblock(first_hash)
        assert_equal(node.getblockcount(), first_height - 1)
        self.state(expected_state, [node])
        self.cold_state(expected_state, producer=True)
        if signer is self.farmer_key:
            farmer_wallet = node.get_wallet_rpc('farmer')
            assert_equal(farmer_wallet.getwalletinfo()['unlocked_until'], 0)
            self.missing_signer(self.farmer, -13)
            farmer_wallet.walletpassphrase('signer-test', 100000000)
        replacement = self.forge(signer, label + '-boundary', connected=False, split_sat=split_sat)
        assert replacement != first_hash
        self.forge(signer, label + '-after', connected=False, split_sat=split_sat)
        self.forge(signer, label + '-greater-work', connected=False, split_sat=split_sat)
        new_tip = node.getbestblockhash()
        assert int(node.getblockheader(new_tip)['chainwork'], 16) > old_work
        assert_equal(peer.getbestblockhash(), old_tip)
        self.connect_nodes(0, 1)
        self.sync_blocks()
        assert_equal(peer.getbestblockhash(), new_tip)
        assert_equal(peer.getblockhash(first_height), replacement)
        assert peer.verifychain(4, 0)
        self.forks.append({'label': label, 'fork_height': first_height, 'old_tip': old_tip,
                           'new_tip': new_tip, 'old_work': old_work,
                           'new_work': int(node.getblockheader(new_tip)['chainwork'], 16)})

    def run_test(self):
        node, peer = self.nodes
        self.output = Path(self.options.tmpdir) / 'actual-signers'
        self.output.mkdir()
        self.records, self.proofs, self.rejections, self.forks = [], [], [], []
        self.owner_key, self.plot = self.import_signer('plot', 1)
        self.farmer_key, self.farmer = self.import_signer('farmer', 2)
        self.account = hash160(self.owner_key.get_pubkey().get_bytes())
        assert_equal(self.account.hex(), '751e76e8199196d454941c45d1b3a323f1433bd6')
        self.mining = node.get_wallet_rpc(self.default_wallet_name).getnewaddress('', 'bech32')
        for observer in self.nodes:
            observer.setmocktime(1700000000)
        self.generatetoaddress(node, 110, self.mining)
        assert not node.getblockchaininfo()['initialblockdownload']
        assert not peer.getblockchaininfo()['initialblockdownload']
        node.get_wallet_rpc(self.default_wallet_name).sendtoaddress(self.plot, Decimal('1'))
        self.generatetoaddress(node, 1, self.mining)
        self.state('UNASSIGNED')
        self.forge(self.owner_key, 'unassigned')

        self.log.info('A real plot uses its owner through H+3, then its farmer at H+4')
        wallet = node.get_wallet_rpc('plot')
        assignment = wallet.create_assignment(self.plot, self.farmer, Decimal('0.0001'))['txid']
        self.generatetoaddress(node, 1, self.mining)
        assignment_height = node.getblockcount()
        assert assignment in node.getblock(node.getbestblockhash())['tx']
        self.state('ASSIGNING')
        node.unloadwallet('plot')  # A farmer key alone is insufficient before activation.
        self.missing_signer(self.plot)
        node.loadwallet('plot')
        for offset in range(1, 4):
            self.forge(self.owner_key, f'assignment-plus-{offset}')
            assert_equal(node.getblockcount(), assignment_height + offset)
            self.state('ASSIGNING')
        node.unloadwallet('farmer')  # Parent is ASSIGNING, next block requires farmer.
        self.missing_signer(self.farmer)
        node.loadwallet('farmer')
        farmer_wallet = node.get_wallet_rpc('farmer')
        farmer_wallet.encryptwallet('signer-test')
        self.missing_signer(self.farmer, -13)
        farmer_wallet.walletpassphrase('signer-test', 100000000)
        activation_hash = self.forge(self.farmer_key, 'assignment-plus-4')
        assert_equal(node.getblockcount(), assignment_height + 4)
        self.state('ASSIGNED')
        self.forge(self.farmer_key, 'assignment-plus-5')
        self.cold_state('ASSIGNED')
        # The walletless peer keeps its old tip until greater-work P2P reorg.
        self.competing_boundary_fork(activation_hash, 'ASSIGNING', self.farmer_key,
                                     'activation-fork', 1)

        self.log.info('Farmer remains effective through R+7; owner returns at R+8')
        node.get_wallet_rpc(self.default_wallet_name).sendtoaddress(self.plot, Decimal('1'))
        self.generatetoaddress(node, 1, self.mining)
        revocation = node.get_wallet_rpc('plot').revoke_assignment(self.plot, Decimal('0.0001'))['txid']
        self.generatetoaddress(node, 1, self.mining)
        revocation_height = node.getblockcount()
        assert revocation in node.getblock(node.getbestblockhash())['tx']
        self.state('REVOKING')
        for offset in range(1, 8):
            self.forge(self.farmer_key, f'revocation-plus-{offset}')
            assert_equal(node.getblockcount(), revocation_height + offset)
            self.state('REVOKING')
        self.cold_state('REVOKING')
        node.unloadwallet('plot')  # Parent is REVOKING, next block requires owner.
        self.missing_signer(self.plot)
        node.loadwallet('plot')
        revoked_hash = self.forge(self.owner_key, 'revocation-plus-8')
        assert_equal(node.getblockcount(), revocation_height + 8)
        self.state('REVOKED')
        self.forge(self.owner_key, 'revocation-plus-9')
        self.competing_boundary_fork(revoked_hash, 'REVOKING', self.owner_key,
                                     'revocation-fork', 2)
        self.state('REVOKED')
        self.cold_state('REVOKED', reindex=True)
        self.sync_blocks()
        self.forge(self.owner_key, 'post-reindex')
        for observer in self.nodes:
            assert observer.verifychain(4, 0)
            for height, state in ((assignment_height + 3, 'ASSIGNING'),
                                  (assignment_height + 4, 'ASSIGNED'),
                                  (revocation_height + 7, 'REVOKING'),
                                  (revocation_height + 8, 'REVOKED')):
                assert_equal(observer.get_assignment(self.plot, height)['state'], state)
        (self.output / 'proofs.csv').write_text('\n'.join(self.proofs) + '\n')
        (self.output / 'results.json').write_text(json.dumps({
            'assignment_height': assignment_height, 'revocation_height': revocation_height,
            'blocks': self.records, 'rejections': self.rejections, 'competing_forks': self.forks,
        }, indent=2) + '\n')


if __name__ == '__main__':
    AssignmentSignersTest(__file__).main()
