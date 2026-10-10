#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin PoCX developers
# Distributed under the MIT software license; see COPYING.
"""Backport BCC compiler flags for the verified old-BCC/new-kernel pairing.

BCC 0.18 predefines byte-swap feature macros now defined by kernel headers,
and omits control-flow protection required by x86 nocf_check declarations.
Modern BCC removes those definitions and enables -fcf-protection on x86:
https://github.com/iovisor/bcc/blob/v0.31.0/src/cc/frontends/clang/kbuild_helper.cc
https://github.com/iovisor/bcc/blob/v0.31.0/src/cc/frontends/clang/loader.cc

Keep diagnostics enabled. Limit this backport to the actually verified Linux
6.12/x86_64/BCC 0.18 combination; other environments retain their own flags.
"""
import platform
import re


def kernel_header_flags(bcc_version, *, system=None, machine=None, release=None):
    system = platform.system() if system is None else system
    machine = platform.machine() if machine is None else machine
    release = platform.release() if release is None else release
    if (bcc_version != '0.18.0' or system != 'Linux' or machine != 'x86_64' or
            re.match(r'^6\.12(?:\.|$)', release) is None):
        return []
    return ['-U__HAVE_BUILTIN_BSWAP16__', '-U__HAVE_BUILTIN_BSWAP32__',
            '-U__HAVE_BUILTIN_BSWAP64__', '-fcf-protection']
