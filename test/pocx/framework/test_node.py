#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin PoCX developers
# Distributed under the MIT software license; see COPYING.
"""Reuse upstream node mechanics with PoCX deterministic funding destinations.

Staging copies the reviewed upstream module to bitcoin_test_node.py. No runtime
patches or changes to the upstream class are used.
"""
from .bitcoin_test_node import (
    BITCOIN_PID_FILENAME_DEFAULT,
    ErrorMatch,
    FailedToStartError,
    NULL_BLK_XOR_KEY,
    TestNode as BitcoinTestNode,
    TestNodeCLI,
    TestNodeCLIAttr,
)
from .address import base58_to_byte, program_to_witness
from .util import chain_folder


class TestNode(BitcoinTestNode):
    # Preserve every upstream WIF/key and its public-key hash. Fund wpkh outputs,
    # which the existing combo descriptor import controls, with the PoCX HRP.
    PRIV_KEYS = [key._replace(address=program_to_witness(0, base58_to_byte(key.address)[0]))
                 for key in BitcoinTestNode.PRIV_KEYS]
    pocx_fixture_time = None
    pocx_preserve_mocktime = False

    @property
    def chain_path(self):
        return self.datadir_path / chain_folder(self.chain)

    def start(self, extra_args=None, *args, **kwargs):
        selected = list(self.extra_args or []) if extra_args is None else list(extra_args)
        preserve_clock = self.pocx_fixture_time is not None or (
            self.pocx_preserve_mocktime and self.mocktime is not None)
        if preserve_clock and not any(
                argument.startswith('-mocktime=') for argument in self.args + selected):
            # VerifyDB runs before RPC. A chain created at deterministic future
            # mocktime needs a suitable clock already during startup.
            selected.append(f'-mocktime={max(self.pocx_fixture_time or 0, self.mocktime or 0)}')
        return super().start(selected, *args, **kwargs)
