#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin PoCX developers
# Distributed under the MIT software license; see COPYING.
"""Check mixed-chain fixture boundaries without starting network services.

These infrastructure checks do not establish functional previous-release passes.
"""
import argparse
import atexit
import ast
from collections import Counter
from copy import deepcopy
from decimal import Decimal
from pathlib import Path
import json
import sys
import sqlite3
import tempfile
import unittest
from unittest.mock import patch

from common import ROOT
from stage import stage

parser=argparse.ArgumentParser(description=__doc__)
parser.add_argument('--build-dir',type=Path,
                    help='Optional real build; otherwise use an isolated source-only fixture')
args=parser.parse_args()
if args.build_dir:
    staged,_,_=stage(args.build_dir)
else:
    # Exercise this source tree's real staging and node constructors. No binary
    # is started, and the synthetic build metadata is never runtime evidence.
    scratch_build=tempfile.TemporaryDirectory(prefix='build-compat-fixture-',dir=ROOT)
    atexit.register(scratch_build.cleanup)
    build=Path(scratch_build.name)
    (build/'CMakeCache.txt').write_text(
        f'ENABLE_POCX:BOOL=ON\nCMAKE_HOME_DIRECTORY:INTERNAL={ROOT}\n')
    (build/'test').mkdir()
    (build/'test/config.ini').write_text('[environment]\nEXEEXT=\n[components]\n')
    # A clean source archive has no git metadata. Revision lookup is irrelevant
    # to these fixture checks; source copying and hashing remain real.
    with patch('stage.subprocess.check_output',return_value='source-only-infrastructure-fixture'):
        staged,_,_=stage(build)
sys.path.insert(0,str(staged))
from test_framework.bitcoin_messages import COutPoint, CTransaction, CTxIn, CTxOut
from test_framework.bitcoin_test_node import TestNode as BitcoinTestNode
from test_framework.blocktools import bitcoin_block_with_shared_coinbase, bitcoin_block_with_shared_transactions
from test_framework.messages import uint256_from_compact
from test_framework.test_framework import BitcoinTestFramework
from test_framework.test_node import TestNode
from test_framework.util import initialize_datadir
from feature_coinstatsindex_compatibility import expected_bitcoin_stats
from test_framework.bitcoin_messages import ser_compact_size, ser_string
from test_framework.segwit_addr import encode_segwit_address
from test_framework.wallet_compatibility import (
    BITCOIN_GENESIS, POCX_GENESIS, WalletChainContext,
    read_wallet_dump, rebase_wallet_file, reencode_regtest_address, write_wallet_dump,
)
from test_framework.wallet_migration_fixtures import (
    MigrationWalletRPC, PairedMigrationWallets, cap_shared_coinbase,
    rpc_descriptor, shared_regtest_subsidy, wallet_rpc_parameters, wallet_rpc_result,
)


class FixtureFramework(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes=2
        self.setup_clean_chain=True

    def run_test(self):
        raise AssertionError('Infrastructure checks must never start a functional run')


class PreviousReleaseFixturesTest(unittest.TestCase):
    def framework(self,directory):
        with patch.object(sys,'argv',['fixture','--configfile='+str(staged/'config.ini')]):
            framework=FixtureFramework(str(staged/'mempool_compatibility.py'))
        framework.options.tmpdir=directory
        framework.options.previous_releases_path=str(ROOT/'releases')
        for i in range(2):
            initialize_datadir(directory,i,'regtest')
        return framework

    def test_default_nodes_keep_native_address_fixtures(self):
        with tempfile.TemporaryDirectory(prefix='pocx-node-factory-',dir='/tmp') as d:
            framework=self.framework(d)
            framework.add_nodes(2)
            self.assertTrue(all(type(node) is TestNode for node in framework.nodes))
            self.assertEqual(framework.nodes[0].PRIV_KEYS,TestNode.PRIV_KEYS)

    def test_explicit_old_release_keeps_original_bitcoin_keys_and_binary(self):
        with tempfile.TemporaryDirectory(prefix='pocx-node-factory-',dir='/tmp') as d:
            framework=self.framework(d)
            framework.add_nodes(2,versions=[200100,None],node_classes=[BitcoinTestNode,TestNode])
            self.assertIs(type(framework.nodes[0]),BitcoinTestNode)
            self.assertIs(type(framework.nodes[1]),TestNode)
            self.assertEqual(framework.nodes[0].PRIV_KEYS,BitcoinTestNode.PRIV_KEYS)
            self.assertNotEqual(framework.nodes[0].PRIV_KEYS[0].address,framework.nodes[1].PRIV_KEYS[0].address)
            self.assertEqual(Path(framework.nodes[0].args[0]),ROOT/'releases/v0.20.1/bin/bitcoind')

    def test_invalid_node_factory_inventory_is_rejected(self):
        for classes in [[BitcoinTestNode],[BitcoinTestNode,object]]:
            with self.subTest(classes=classes),tempfile.TemporaryDirectory(prefix='pocx-node-factory-',dir='/tmp') as d:
                framework=self.framework(d)
                with self.assertRaises((AssertionError,ValueError)):
                    framework.add_nodes(2,node_classes=classes)
                self.assertEqual(framework.nodes,[])

    def coinbase(self,value):
        tx=CTransaction()
        tx.vin=[CTxIn(COutPoint(0,0xffffffff),b'\x01\x01')]
        tx.vout=[CTxOut(value,b'\x51')]
        return tx

    def template(self):
        return {'version':4,'previousblockhash':'01'*32,'bits':'207fffff',
                'curtime':2000000000,'mintime':1999999999,'coinbasevalue':5000000000}

    def test_bitcoin_proof_preserves_coinbase_bytes_and_uses_80_byte_header(self):
        tx=self.coinbase(1000000000)
        block=bitcoin_block_with_shared_coinbase(tx,self.template())
        self.assertEqual(block.vtx[0].serialize(),tx.serialize())
        self.assertEqual(block.vtx[0].txid_hex,tx.txid_hex)
        self.assertEqual(len(block.serialize())-len(tx.serialize())-1,80)
        self.assertLessEqual(int(block.hash_hex,16),uint256_from_compact(block.nBits))

    def test_subsidy_overclaim_cannot_create_a_shared_funding_fixture(self):
        with self.assertRaises(AssertionError):
            bitcoin_block_with_shared_coinbase(self.coinbase(5000000001),self.template())

    def test_shared_block_keeps_every_transaction_and_its_position(self):
        coinbase=self.coinbase(1000000000)
        spend=CTransaction()
        spend.vin=[CTxIn(COutPoint(coinbase.txid_int,0),b'')]
        spend.vout=[CTxOut(999990000,b'\x51')]
        child=CTransaction()
        child.vin=[CTxIn(COutPoint(spend.txid_int,0),b'')]
        child.vout=[CTxOut(999980000,b'\x51')]
        transactions=[coinbase,spend,child]
        block=bitcoin_block_with_shared_transactions(transactions,self.template())
        self.assertEqual([tx.serialize() for tx in block.vtx],[tx.serialize() for tx in transactions])
        self.assertEqual(block.hashMerkleRoot,block.calc_merkle_root())
        self.assertEqual(block.vtx[1].txid_hex,spend.txid_hex)
        self.assertEqual(len(block.serialize())-sum(len(tx.serialize()) for tx in transactions)-1,80)

    def test_stats_keep_all_fields_and_account_for_genesis_and_old_halving(self):
        for height,total_delta,block_delta,category in [(0,40,40,'genesis_block'),
                (149,6000,40,'unclaimed_rewards'),(150,6015,15,'unclaimed_rewards'),
                (199,6750,15,'unclaimed_rewards')]:
            with self.subTest(height=height):
                native={'height':height,'bestblock':'native','muhash':'unchanged','txouts':199,
                        'future_field':{'must':'remain'},'total_unspendable_amount':Decimal(10),
                        'block_info':{'unspendable':Decimal(0),'coinbase':Decimal(10),
                                      'unspendables':{'genesis_block':Decimal(0),'unclaimed_rewards':Decimal(0)}}}
                before=deepcopy(native)
                expected=deepcopy(native)
                expected['bestblock']='bitcoin'
                expected['total_unspendable_amount']+=total_delta
                expected['block_info']['unspendable']+=block_delta
                expected['block_info']['unspendables'][category]+=block_delta
                self.assertEqual(expected_bitcoin_stats(native,'bitcoin'),expected)
                self.assertEqual(native,before)


class WalletContextFixturesTest(unittest.TestCase):
    def context(self):
        return WalletChainContext({BITCOIN_GENESIS: POCX_GENESIS, '11'*32: '22'*32},
                                  source_hrp='bcrt', destination_hrp='rpocx')

    def test_address_encoding_preserves_witness_programs_and_base58_keys(self):
        for version, program in [(0,bytes(range(20))),(0,bytes(range(32))),(1,bytes(range(32)))]:
            bitcoin=encode_segwit_address('bcrt',version,program)
            native=encode_segwit_address('rpocx',version,program)
            self.assertEqual(reencode_regtest_address(bitcoin,'rpocx'),native)
            self.assertEqual(reencode_regtest_address(native,'bcrt'),bitcoin)
            with self.assertRaises(ValueError):
                reencode_regtest_address(bitcoin[:-1]+'!', 'rpocx')
        address=BitcoinTestNode.PRIV_KEYS[0].address
        self.assertEqual(reencode_regtest_address(address,'rpocx'),address)

    def test_context_mapping_requires_correct_genesis_and_a_bijection(self):
        for mapping in [{}, {BITCOIN_GENESIS:'11'*32},
                        {BITCOIN_GENESIS:POCX_GENESIS,'11'*32:POCX_GENESIS}]:
            with self.subTest(mapping=mapping),self.assertRaises(ValueError):
                WalletChainContext(mapping,source_hrp='bcrt',destination_hrp='rpocx')
        with self.assertRaises(ValueError):
            self.context().record(ser_string(b'bestblock_nomerkle'),bytes(4)+b'\x01'+bytes.fromhex('33'*32))

    def test_rebasing_changes_only_address_keys_and_locator_hashes(self):
        bitcoin=encode_segwit_address('bcrt',0,bytes(range(20)))
        native=encode_segwit_address('rpocx',0,bytes(range(20)))
        opaque=b'user label bcrt1must-not-change and private key bytes\x00\xff'
        locator=bytes(4)+ser_compact_size(2)+bytes.fromhex('11'*32)+bytes.fromhex(BITCOIN_GENESIS)[::-1]
        records=[(ser_string(b'name')+ser_string(bitcoin.encode()),opaque),
                 (ser_string(b'destdata')+ser_string(bitcoin.encode())+ser_string(b'used'),b'\x011'),
                 (ser_string(b'bestblock_nomerkle'),locator),
                 (ser_string(b'future_record'),opaque)]
        expected=[(ser_string(b'name')+ser_string(native.encode()),opaque),
                  (ser_string(b'destdata')+ser_string(native.encode())+ser_string(b'used'),b'\x011'),
                  (ser_string(b'bestblock_nomerkle'),bytes(4)+b'\x02'+bytes.fromhex('22'*32)+bytes.fromhex(POCX_GENESIS)[::-1]),
                  records[3]]
        self.assertEqual(self.context().records(records),expected)
        self.assertEqual(self.context().reverse().records(expected),records)

    def test_transaction_bytes_and_confirmed_conflicted_abandoned_states_survive(self):
        tx=PreviousReleaseFixturesTest().coinbase(1000000000)
        raw=tx.serialize()
        key=ser_string(b'tx')+tx.txid_int.to_bytes(32,'little')
        for old_hash,new_hash in [(bytes.fromhex('11'*32),bytes.fromhex('22'*32)),
                                  (bytes(32),bytes(32)),(b'\x01'+bytes(31),b'\x01'+bytes(31))]:
            for position in [1,-1]:
                # The tail includes the Merkle-branch length and serialized
                # position. All later metadata is opaque and must survive.
                tail=b'\x00'+position.to_bytes(4,'little',signed=True)+b'walletconflicts/comment/orderpos'
                original=(key,raw+old_hash+tail)
                expected=(key,raw+new_hash+tail)
                self.assertEqual(self.context().record(*original),expected)
                self.assertEqual(self.context().reverse().record(*expected),original)

    def test_sqlite_failure_rolls_back_and_success_retains_every_record(self):
        with tempfile.TemporaryDirectory(prefix='pocx-wallet-sqlite-',dir='/tmp') as d:
            path=Path(d)/'wallet.dat'
            key=ser_string(b'bestblock_nomerkle')
            invalid=bytes(4)+b'\x01'+bytes.fromhex('33'*32)
            opaque=(ser_string(b'keymeta')+b'private-key-identifier',b'untouched HD path and creation time')
            with sqlite3.connect(path) as db:
                db.execute('CREATE TABLE main(key BLOB PRIMARY KEY NOT NULL,value BLOB NOT NULL)')
                db.executemany('INSERT INTO main VALUES(?,?)',[(key,invalid),opaque])
            with self.assertRaises(ValueError):
                rebase_wallet_file(path,self.context())
            with sqlite3.connect(path) as db:
                self.assertEqual(sorted(db.execute('SELECT key,value FROM main').fetchall()),sorted([(key,invalid),opaque]))
                valid=bytes(4)+b'\x01'+bytes.fromhex(BITCOIN_GENESIS)[::-1]
                db.execute('UPDATE main SET value=? WHERE key=?',(valid,key))
            proof=rebase_wallet_file(path,self.context())
            self.assertEqual(proof,{'format':'sqlite','records':2,'context_records_changed':1})
            with sqlite3.connect(path) as db:
                self.assertEqual(db.execute('SELECT value FROM main WHERE key=?',(opaque[0],)).fetchone()[0],opaque[1])
            rebase_wallet_file(path,self.context().reverse())
            with sqlite3.connect(path) as db:
                self.assertEqual(db.execute('SELECT value FROM main WHERE key=?',(key,)).fetchone()[0],valid)

    def test_wallet_dump_checksum_and_duplicate_records_are_enforced(self):
        with tempfile.TemporaryDirectory(prefix='pocx-wallet-dump-',dir='/tmp') as d:
            path=Path(d)/'wallet.dump'
            records=[(ser_string(b'key'),b'opaque-secret-material')]
            write_wallet_dump(path,records)
            self.assertEqual(read_wallet_dump(path),records)
            path.write_bytes(path.read_bytes().replace(b'format,bdb',b'format,xyz'))
            with self.assertRaises(ValueError):
                read_wallet_dump(path)
            write_wallet_dump(path,records+records)
            with self.assertRaises(ValueError):
                read_wallet_dump(path)

    def test_backward_adapter_retains_every_original_assertion_and_method(self):
        original=ast.parse((ROOT/'test/functional/wallet_backwards_compatibility.py').read_text())
        adapted=ast.parse((ROOT/'test/pocx/functional/wallet_backwards_compatibility.py').read_text())
        def assertions(tree):
            return Counter(ast.dump(node,include_attributes=False) for node in ast.walk(tree)
                if isinstance(node,ast.Assert) or (isinstance(node,ast.Call) and
                    (getattr(node.func,'id','') or getattr(node.func,'attr','')).startswith('assert')))
        def methods(tree):
            return Counter(node.name for node in ast.walk(tree) if isinstance(node,ast.FunctionDef))
        self.assertEqual(sum(assertions(original).values()),47)
        # Review only the explicit funding-height and witness-HRP changes.
        # Every other original assertion must remain structurally identical.
        for before, after in [
            ('assert_equal(node_v20.getblockchaininfo()["blocks"], COINBASE_MATURITY + 1)',
             'assert_equal(node_v20.getblockchaininfo()["blocks"], funding_blocks)'),
            ('assert_equal(bad_deriv_wallet_master.getaddressinfo(bad_path_addr)["hdkeypath"], good_deriv_path)',
             'assert_equal(bad_deriv_wallet_master.getaddressinfo(reencode_regtest_address(bad_path_addr, "rpocx"))["hdkeypath"], good_deriv_path)'),
        ]:
            old = ast.dump(ast.parse(before).body[0].value)
            new = ast.dump(ast.parse(after).body[0].value)
            self.assertEqual(assertions(original)[old], 1)
            self.assertEqual(assertions(adapted)[new], 1)
            for node in ast.walk(original):
                if isinstance(node, ast.Call) and ast.dump(node) == old:
                    replacement = ast.parse(after).body[0].value
                    node.func, node.args, node.keywords = replacement.func, replacement.args, replacement.keywords
        self.assertFalse(assertions(original)-assertions(adapted))
        self.assertFalse(methods(original)-methods(adapted))

    def test_owned_framework_additions_cannot_escape_or_replace_upstream_modules(self):
        for destination,source in [('test_framework/messages.py','framework/wallet_compatibility.py'),
                                   ('other/wallet.py','framework/wallet_compatibility.py'),
                                   ('test_framework/wallet.py','../../outside.py')]:
            with self.subTest(destination=destination),tempfile.TemporaryDirectory(dir='/tmp') as d:
                manifest=json.loads((ROOT/'test/pocx/manifest.json').read_text())
                manifest['framework_additions']={destination:source}
                path=Path(d)/'manifest.json'
                path.write_text(json.dumps(manifest))
                with self.assertRaisesRegex(ValueError,'framework addition'):
                    stage(staged.parent,manifest_path=path)


class MigrationFixturesTest(unittest.TestCase):
    def test_wallet_fixture_tools_follow_configured_executable_suffix(self):
        from types import SimpleNamespace
        from wallet_backwards_compatibility import BackwardsCompatibilityTest
        for suffix in ('', '.exe'):
            for fixture_type, method in ((PairedMigrationWallets, 'rebase_wallet_fixture'),
                                         (BackwardsCompatibilityTest, 'rebase_fixture')):
                fixture = SimpleNamespace(
                    options=SimpleNamespace(previous_releases_path=str(ROOT / 'releases')),
                    config={'environment': {'EXEEXT': suffix}},
                    wallet_context=lambda: WalletChainContext({BITCOIN_GENESIS: POCX_GENESIS}, source_hrp='bcrt', destination_hrp='rpocx'),
                    log=SimpleNamespace(debug=lambda *args: None))
                module = sys.modules[fixture_type.__module__]
                with self.subTest(suffix=suffix, fixture=fixture_type.__name__), patch.object(module, 'rebase_wallet_file') as rebase:
                    getattr(fixture_type, method)(fixture, Path('fixture-wallet.dat'))
                    self.assertEqual(Path(rebase.call_args.kwargs['bitcoin_wallet']),
                                     ROOT / 'releases/v28.2/bin' / ('bitcoin-wallet' + suffix))

    def context(self):
        return WalletContextFixturesTest().context()

    def addresses(self):
        return (encode_segwit_address('bcrt',0,bytes(range(20))),
                encode_segwit_address('rpocx',0,bytes(range(20))))

    def test_rpc_parameters_preserve_labels_comments_amounts_and_caller_objects(self):
        bitcoin,native=self.addresses()
        opaque=native+' is a user label, not an address parameter'
        args=[native,2,opaque,opaque]
        self.assertEqual(wallet_rpc_parameters('sendtoaddress',args,{}),([bitcoin,2,opaque,opaque],{}))
        self.assertEqual(args,[native,2,opaque,opaque])
        self.assertEqual(wallet_rpc_parameters('setlabel',[native,opaque],{}),([bitcoin,opaque],{}))
        self.assertEqual(wallet_rpc_parameters('getnewaddress',[opaque],{}),([opaque],{}))
        self.assertEqual(wallet_rpc_parameters('unreviewed_method',[{'address':native}],{}),([{'address':native}],{}))

    def test_rpc_outputs_change_only_destination_keys_and_explicit_change_options(self):
        bitcoin,native=self.addresses()
        kwargs={'outputs':[{native:Decimal('1.25')}],
                'options':{'change_address':native,'comment':native},'comment':native}
        before=deepcopy(kwargs)
        _,result=wallet_rpc_parameters('send',[],kwargs)
        self.assertEqual(result,{'outputs':[{bitcoin:Decimal('1.25')}],
                                 'options':{'change_address':bitcoin,'comment':native},'comment':native})
        self.assertEqual(kwargs,before)
        self.assertEqual(wallet_rpc_parameters('sendall',[[native,{native:2}]],{}),([[bitcoin,{bitcoin:2}]],{}))
        self.assertEqual(wallet_rpc_parameters('importaddress',['001122','opaque'],{}),(['001122','opaque'],{}))

    def test_descriptor_conversion_validates_checksum_and_does_not_touch_labels(self):
        from test_framework.descriptors import descsum_create
        bitcoin,native=self.addresses()
        old=descsum_create('addr('+bitcoin+')')
        new=descsum_create('addr('+native+')')
        self.assertEqual(rpc_descriptor(old,'rpocx'),new)
        self.assertEqual(rpc_descriptor(new,'bcrt'),old)
        with self.assertRaises(ValueError):
            rpc_descriptor(old[:-1]+'!','rpocx')
        requests=[{'desc':new,'label':native,'scriptPubKey':{'address':native},'timestamp':'now'}]
        self.assertEqual(wallet_rpc_parameters('importmulti',[requests],{}),
                         ([[{'desc':old,'label':native,'scriptPubKey':{'address':bitcoin},'timestamp':'now'}]],{}))
        self.assertEqual(requests[0]['desc'],new)

    def test_rpc_results_keep_all_metadata_and_map_only_schema_fields(self):
        bitcoin,native=self.addresses()
        row={'address':bitcoin,'blockhash':'11'*32,'comment':bitcoin,'label':bitcoin,
             'txid':'aa'*32,'hex':'unchanged raw transaction','amount':Decimal('2.5'),
             'confirmations':-1,'walletconflicts':['bb'*32],
             'details':[{'address':bitcoin,'label':bitcoin}],
             'future_field':{'address':bitcoin,'blockhash':'11'*32}}
        expected=deepcopy(row)
        expected['address']=native
        expected['blockhash']='22'*32
        expected['details'][0]['address']=native
        self.assertEqual(wallet_rpc_result('gettransaction',row,self.context()),expected)
        self.assertEqual(row['address'],bitcoin)
        self.assertEqual(wallet_rpc_result('listlabels',[bitcoin],self.context()),[bitcoin])
        groups=[[[bitcoin,Decimal('2.5'),bitcoin]]]
        self.assertEqual(wallet_rpc_result('listaddressgroupings',groups,self.context()),[[[native,Decimal('2.5'),bitcoin]]])
        row['blockhash']='33'*32
        with self.assertRaises(ValueError):
            wallet_rpc_result('gettransaction',row,self.context())

    def test_balance_context_preserves_amounts_and_requires_known_tip(self):
        row = {'mine': {'trusted': Decimal('1.25'), 'untrusted_pending': Decimal('0.5'),
                        'immature': Decimal('10')},
               'lastprocessedblock': {'hash': '11' * 32, 'height': 115},
               'future_field': {'hash': '11' * 32}}
        expected = deepcopy(row)
        expected['lastprocessedblock']['hash'] = '22' * 32
        for method in ('getwalletinfo', 'getbalances'):
            with self.subTest(method=method):
                self.assertEqual(wallet_rpc_result(method, row, self.context()), expected)
                self.assertEqual(row['lastprocessedblock']['hash'], '11' * 32)
                unknown = deepcopy(row)
                unknown['lastprocessedblock']['hash'] = '33' * 32
                with self.assertRaises(ValueError):
                    wallet_rpc_result(method, unknown, self.context())

    def test_rpc_proxy_tracks_successful_producers_and_preserves_exceptions(self):
        from types import SimpleNamespace
        bitcoin,native=self.addresses()
        calls=[]
        producers=[]
        class RPC:
            def sendtoaddress(self,*args,**kwargs):
                calls.append((args,kwargs))
                return 'txid'
            def bumpfee(self,*args,**kwargs):raise failure
        failure=RuntimeError('actual RPC failure')
        proxy=MigrationWalletRPC(RPC(),SimpleNamespace(index=1,wallet_fixture_producer=producers.append),context=self.context)
        self.assertEqual(proxy.sendtoaddress(native,2,comment=native),'txid')
        self.assertEqual(calls,[((bitcoin,2),{'comment':native})])
        self.assertEqual(producers,[1])
        with self.assertRaises(RuntimeError) as caught:
            proxy.bumpfee('txid')
        self.assertIs(caught.exception,failure)
        self.assertEqual(producers,[1])

    def test_shared_subsidy_covers_both_different_halving_schedules(self):
        for height,amount in [(1,1000000000),(149,1000000000),(150,1000000000),
                              (449,1000000000),(450,625000000),(499,625000000),
                              (500,500000000),(599,500000000),(600,312500000),
                              (750,156250000),(1000,78125000)]:
            with self.subTest(height=height):
                self.assertEqual(shared_regtest_subsidy(height),amount)
        for invalid in [0,-1,True,1.5]:
            with self.assertRaises(ValueError):
                shared_regtest_subsidy(invalid)

    def test_subsidy_cap_preserves_all_other_outputs_and_non_coinbase_transactions(self):
        from test_framework.blocktools import _REGTEST_ACCOUNT, _REGTEST_SIGNING_KEY
        from test_framework.key import ECKey
        from test_framework.messages import CBlock
        block=CBlock()
        block.nHeight=450
        block.pocxProof.account_id=_REGTEST_ACCOUNT
        key=ECKey()
        key.set(_REGTEST_SIGNING_KEY,compressed=True)
        block.vchPubKey=key.get_pubkey().get_bytes()
        coinbase=PreviousReleaseFixturesTest().coinbase(1000000000)
        coinbase.vout.append(CTxOut(0,b'\x6a'+bytes(36)))
        block.vtx=[coinbase,PreviousReleaseFixturesTest().coinbase(12345)]
        protected=deepcopy((block.vtx[0].vin,block.vtx[0].vout[0].scriptPubKey))
        second_output=block.vtx[0].vout[1].serialize()
        transaction=block.vtx[1].serialize()
        cap_shared_coinbase(block)
        self.assertEqual(block.vtx[0].vout[0].nValue,625000000)
        self.assertEqual(block.vtx[0].vout[1].serialize(),second_output)
        self.assertEqual(block.vtx[1].serialize(),transaction)
        self.assertEqual([vin.serialize() for vin in block.vtx[0].vin],[vin.serialize() for vin in protected[0]])
        self.assertEqual(block.vtx[0].vout[0].scriptPubKey,protected[1])
        self.assertEqual(block.hashMerkleRoot,block.calc_merkle_root())
        self.assertEqual(len(block.vchSignature),65)
        with self.assertRaises(AssertionError):
            cap_shared_coinbase(block)

    def test_relay_prioritizes_a_real_replacement_over_stale_conflicts(self):
        calls=[]
        class Node:
            def __init__(self,name,pool):
                self.name=name
                self.pool=pool
            def syncwithvalidationinterfacequeue(self):calls.append((self.name,'flush'))
            def getrawmempool(self,verbose=False):return {tx:{'depends':[]} for tx in self.pool} if verbose else list(self.pool)
            def getrawtransaction(self,txid):return txid
            def sendrawtransaction(self,txid):
                calls.append((self.name,txid))
                if txid=='stale':
                    raise AssertionError('Must not relay stale conflict after replacement')
                self.pool={'replacement'}
                return txid
        class Fixture(PairedMigrationWallets):
            pass
        fixture=Fixture()
        fixture.nodes=[Node('native',{'stale'}),Node('bitcoin',{'replacement'})]
        fixture.wallet_relay_source=1
        fixture.sync_mempools()
        self.assertEqual(calls,[('native','replacement'),('native','flush'),('bitcoin','flush')])
        self.assertEqual(fixture.nodes[0].pool,fixture.nodes[1].pool)

    def test_mempool_dependency_cycles_and_relay_rejections_are_not_suppressed(self):
        from types import SimpleNamespace
        node=SimpleNamespace(getrawmempool=lambda verbose:{'a':{'depends':['b']},'b':{'depends':['a']}})
        with self.assertRaises(AssertionError):
            PairedMigrationWallets.ordered_mempool(node)
        calls=[]
        class Fixture(PairedMigrationWallets):
            pass
        failure=RuntimeError('genuine policy rejection')
        def reject(raw):
            calls.append(raw)
            raise failure
        source=SimpleNamespace(getrawmempool=lambda verbose=False:{'a':{'depends':[]}} if verbose else ['a'],getrawtransaction=lambda txid:'raw')
        destination=SimpleNamespace(getrawmempool=lambda:[],sendrawtransaction=reject)
        fixture=Fixture()
        fixture.nodes=[source,destination]
        fixture.wallet_relay_source=0
        with self.assertRaises(RuntimeError) as caught:
            fixture.sync_mempools()
        self.assertIs(caught.exception,failure)
        self.assertEqual(calls,['raw'])

    def test_backward_fixture_relays_native_replacement_before_old_conflicts(self):
        from wallet_backwards_compatibility import BackwardsCompatibilityTest
        calls=[]
        class Node:
            def __init__(self,index,pool):
                self.index=index
                self.pool=pool
            def getrawmempool(self):return sorted(self.pool)
            def getrawtransaction(self,txid):return txid
            def sendrawtransaction(self,txid):
                calls.append((self.index,txid))
                if txid=='stale':
                    raise AssertionError('Old conflict must not be resent')
                self.pool={'replacement'}
                return txid
        from types import SimpleNamespace
        fixture=SimpleNamespace(nodes=[Node(0,{'replacement'}),Node(1,{'replacement'}),Node(2,{'stale'})])
        fixture.relay_wallet_transactions=lambda sources,destinations:BackwardsCompatibilityTest.relay_wallet_transactions(fixture,sources,destinations)
        with patch.object(BitcoinTestFramework,'sync_mempools'):
            BackwardsCompatibilityTest.sync_mempools(fixture)
        self.assertEqual(calls,[(2,'replacement')])
        self.assertTrue(all(node.pool=={'replacement'} for node in fixture.nodes))

    def test_wrong_chain_fixture_is_never_rebased(self):
        from types import SimpleNamespace
        def forbidden(*args,**kwargs):raise AssertionError('Wrong-chain fixture must retain its real context')
        fixture=SimpleNamespace(nodes=[None,SimpleNamespace(chain='signet')],rebase_wallet_fixture=forbidden)
        self.assertIsNone(PairedMigrationWallets.rebase_migration_fixture(fixture,'failed_load_after_migrate'))

    def test_migration_adapter_retains_every_assertion_method_and_scenario_invocation(self):
        original=ast.parse((ROOT/'test/functional/wallet_migration.py').read_text())
        adapted=ast.parse((ROOT/'test/pocx/functional/wallet_migration.py').read_text())
        def assertions(tree):return Counter(ast.dump(n,include_attributes=False) for n in ast.walk(tree)
            if isinstance(n,ast.Assert) or isinstance(n,ast.Call) and
            (getattr(n.func,'id','') or getattr(n.func,'attr','')).startswith('assert'))
        self.assertEqual(sum(assertions(original).values()),289)
        self.assertFalse(assertions(original)-assertions(adapted))
        methods=lambda tree:Counter(n.name for n in ast.walk(tree) if isinstance(n,ast.FunctionDef))
        self.assertFalse(methods(original)-methods(adapted))
        run=lambda tree:next(n for n in ast.walk(tree) if isinstance(n,ast.FunctionDef) and n.name=='run_test')
        old_run, new_run = run(original), run(adapted)
        self.assertEqual(ast.dump(old_run.body[2]), ast.dump(ast.parse('self.generate(self.master_node, 101)').body[0]))
        self.assertEqual(ast.dump(new_run.body[2]), ast.dump(ast.parse('self.generate(self.master_node, 105)').body[0]))
        self.assertEqual(ast.dump(new_run.body[3]), ast.dump(ast.parse('assert_equal(self.master_node.getbalance(), 50)').body[0]))
        # Only initial funding differs; preserve the complete scenario sequence.
        new_run.body[2:4] = [old_run.body[2]]
        self.assertEqual(ast.dump(old_run), ast.dump(new_run))


if __name__=='__main__':
    unittest.main(argv=[sys.argv[0]])
