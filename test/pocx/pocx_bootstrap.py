#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin PoCX developers
# Distributed under the MIT software license; see COPYING.
"""Disable bytecode writes before importing owned runners or original test code.

Entry points import this module explicitly for its startup side effect. Keeping
startup here leaves their imports together and avoids writing Python caches into
original test directories. It does not change test selection or execution flags.
"""
import sys

sys.dont_write_bytecode = True
