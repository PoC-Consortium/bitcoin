# Copyright (c) 2026 The Bitcoin PoCX developers
# Distributed under the MIT software license; see COPYING.
"""Reuse upstream utilities with the native default data-directory name."""
from .bitcoin_util import *  # noqa: F403
from . import bitcoin_util


def get_temp_default_datadir(temp_dir):
    env, original = bitcoin_util.get_temp_default_datadir(temp_dir)
    name = '.bitcoin-pocx' if original.name == '.bitcoin' else 'Bitcoin-PocX'
    return env, original.with_name(name)


def chain_folder(chain):
    return 'testnet' if chain == 'testnet3' else chain


def get_auth_cookie(datadir, chain):
    return bitcoin_util.get_auth_cookie(datadir, chain_folder(chain))


def delete_cookie_file(datadir, chain):
    return bitcoin_util.delete_cookie_file(datadir, chain_folder(chain))


def rpc_url(datadir, i, chain, rpchost):
    return bitcoin_util.rpc_url(datadir, i, chain_folder(chain), rpchost)
