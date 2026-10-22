#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin PoCX developers
# Distributed under the MIT software license; see COPYING.
"""Read i686 USDT arguments at their declared widths before widening event fields.

The BPF compiler uses the host ABI. A 32-bit target can supply four-byte pointers
or size_t values to an eight-byte host field. BCC rejects mismatched destination
sizes. Its generated readers identify the actual argument types. Keep those
readers, every original event field and every assertion; introduce a correctly
typed temporary only for i686 targets. Native 64-bit BPF text passes through intact.
The separately reviewed old-BCC/kernel header backport adjusts compiler flags
only for its verified environment, without disabling diagnostics.
"""
from pathlib import Path
import re

import bcc
from bcc import BPF as BitcoinBPF

from test_framework.bcc_headers import kernel_header_flags


def _code(text):
    """Mask comments and literals while preserving source offsets and newlines."""
    pattern = r'//[^\n]*|/\*.*?\*/|"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\''
    return re.sub(pattern, lambda match: ''.join('\n' if c == '\n' else ' ' for c in match[0]),
                  text, flags=re.DOTALL)


def argument_reads(text, contexts):
    active = [probe for context in contexts for probe in context.enumerate_active_probes()]
    if not active:
        return text, []
    architectures = set()
    for binary, _, _, _ in active:
        with Path(binary.decode() if isinstance(binary, bytes) else binary).open('rb') as stream:
            header = stream.read(20)
        if len(header) != 20 or header[:4] != b'\x7fELF' or header[5] not in (1, 2):
            raise ValueError('USDT target must have an identifiable ELF ABI')
        architectures.add((header[4], int.from_bytes(header[18:20], 'little' if header[5] == 1 else 'big')))
    if len(architectures) != 1:
        raise ValueError('Mixed USDT target ABIs are not supported')
    elf_class, machine = next(iter(architectures))
    if elf_class == 2:
        return text, []
    if (elf_class, machine) != (1, 3):
        raise ValueError('Only the reviewed i686 argument-width bridge is supported')

    readers = {}
    pattern = (r'static __always_inline int _bpf_readarg_(\w+)_(\d+)'
               r'\(struct pt_regs \*ctx, void \*dest, size_t len\) \{\s*'
               r'if \(len != sizeof\(((?:u?int)(?:8|16|32|64)_t)\)\) return -1;')
    for context in contexts:
        generated = context.get_text()
        matches = re.findall(pattern, generated)
        expected = re.findall(r'static __always_inline int _bpf_readarg_(\w+)_(\d+)\(', generated)
        if not matches or len(matches) != len(expected):
            raise ValueError('Unrecognized BCC USDT reader declarations')
        for function, index, ctype in matches:
            key = (function, int(index))
            if key in readers and readers[key] != ctype:
                raise ValueError('Conflicting USDT argument declarations')
            readers[key] = ctype

    masked = _code(text)
    changes = []
    review = []
    for function in sorted({name for name, _ in readers}):
        declaration = re.compile(r'\bint\s+' + re.escape(function) +
                                 r'\s*\(\s*struct\s+pt_regs\s*\*\s*(\w+)\s*\)\s*\{')
        matches = list(declaration.finditer(masked))
        if len(matches) != 1:
            raise ValueError('Missing or ambiguous USDT callback: ' + function)
        start = matches[0].end()
        depth = 1
        end = start
        while end < len(masked) and depth:
            depth += (masked[end] == '{') - (masked[end] == '}')
            end += 1
        if depth:
            raise ValueError('Unterminated USDT callback: ' + function)
        body = masked[start:end - 1]
        call_pattern = (r'\bbpf_usdt_readarg\s*\(\s*(\d+)\s*,\s*(\w+)\s*,\s*&\s*'
                        r'([A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*)\s*\)')
        calls = list(re.finditer(call_pattern, body))
        if not calls or len(calls) != len(re.findall(r'\bbpf_usdt_readarg\s*\(', body)):
            raise ValueError('Unrecognized USDT argument destination: ' + function)
        for call in calls:
            index, context_name, destination = call.groups()
            key = (function, int(index))
            if key not in readers or context_name != matches[0][1]:
                raise ValueError('USDT call differs from the declared reader')
            ctype = readers[key]
            # Keep the reader's return value and leave the original destination
            # untouched on failure. Pointer widening must be unsigned; the final
            # cast preserves the original signed/unsigned scalar field type.
            replacement = ('({ ' + ctype + ' pocx_usdt_argument = 0; '
                           'int pocx_usdt_result = bpf_usdt_readarg(' + index + ', ' + context_name +
                           ', &pocx_usdt_argument); if (pocx_usdt_result == 0) ' + destination +
                           ' = (__typeof__(' + destination + '))(unsigned long long)pocx_usdt_argument; '
                           'pocx_usdt_result; })')
            changes.append((start + call.start(), start + call.end(), replacement))
            review.append({'function': function, 'argument': int(index),
                           'ctype': ctype, 'destination': destination})
    for start, end, replacement in sorted(changes, reverse=True):
        text = text[:start] + replacement + text[end:]
    return text, review


class BPF(BitcoinBPF):
    def __init__(self, text=None, **kwargs):
        text, self.pocx_usdt_argument_reads = argument_reads(text, kwargs.get('usdt_contexts', []))
        self.pocx_kernel_header_flags = kernel_header_flags(getattr(bcc, '__version__', None))
        if self.pocx_kernel_header_flags:
            kwargs['cflags'] = [*kwargs.get('cflags', []), *self.pocx_kernel_header_flags]
        super().__init__(text=text, **kwargs)
