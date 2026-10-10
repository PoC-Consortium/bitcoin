#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin PoCX developers
# Distributed under the MIT software license; see COPYING.
"""Reject width-bridge ambiguity and stale original views; no domain case proof."""
import importlib.util
import json
from pathlib import Path
import shutil
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from common import ROOT
from framework.bcc_headers import kernel_header_flags
import original_usdt


class Backend:
    def __init__(self, **kwargs):
        self.kwargs = kwargs


spec = importlib.util.spec_from_file_location('pocx_bpf_abi_fixture', ROOT / original_usdt.HELPER)
abi = importlib.util.module_from_spec(spec)
headers_spec = importlib.util.spec_from_file_location('pocx_bcc_headers_fixture', ROOT / original_usdt.HEADERS)
headers = importlib.util.module_from_spec(headers_spec)
headers_spec.loader.exec_module(headers)
with patch.dict('sys.modules', {'bcc': SimpleNamespace(BPF=Backend),
                               'test_framework.bcc_headers': headers}):
    spec.loader.exec_module(abi)


class Context:
    def __init__(self, binary, declarations):
        self.binary = binary
        self.declarations = declarations

    def enumerate_active_probes(self):
        return [(str(self.binary).encode(), b'trace_event', 0, 0)]

    def get_text(self):
        return '\n'.join(
            f'static __always_inline int _bpf_readarg_{function}_{index}'
            '(struct pt_regs *ctx, void *dest, size_t len) {\n'
            f'  if (len != sizeof({ctype})) return -1;\n'
            '  return 0;\n}' for function, index, ctype in self.declarations)


PROGRAM = '''int trace_event(struct pt_regs *ctx) {
    void *pointer = 0;
    bpf_usdt_readarg(1, ctx, &pointer);
    bpf_probe_read_user(&event.data, sizeof(event.data), pointer);
    return 0;
}
'''


class BCCHeaderCompatibilityTest(unittest.TestCase):
    def test_only_verified_old_bcc_kernel_pair_selects_flags(self):
        environment = {'system': 'Linux', 'machine': 'x86_64', 'release': '6.12.107+deb13-amd64'}
        expected = ['-U__HAVE_BUILTIN_BSWAP16__', '-U__HAVE_BUILTIN_BSWAP32__',
                    '-U__HAVE_BUILTIN_BSWAP64__', '-fcf-protection']
        self.assertEqual(kernel_header_flags('0.18.0', **environment), expected)
        for version in (None, '0.17.0', '0.18.1', '0.29.1', '0.31.0'):
            with self.subTest(version=version):
                self.assertEqual(kernel_header_flags(version, **environment), [])
        for changes in ({'system': 'Darwin'}, {'machine': 'aarch64'}, {'machine': 'i686'},
                        {'release': '6.11.9'}, {'release': '6.120.1'}, {'release': '6.13.0'}):
            with self.subTest(changes=changes):
                self.assertEqual(kernel_header_flags('0.18.0', **{**environment, **changes}), [])

    def test_backend_preserves_caller_flags_and_diagnostics(self):
        caller_flags = ['-DVALUE=1', '-Werror']
        backport = ['-U__HAVE_BUILTIN_BSWAP16__', '-fcf-protection']
        with patch.object(abi, 'kernel_header_flags', return_value=backport):
            backend = abi.BPF(text=PROGRAM, cflags=caller_flags, debug=7)
        self.assertEqual(caller_flags, ['-DVALUE=1', '-Werror'])
        self.assertEqual(backend.kwargs, {'text': PROGRAM, 'cflags': [*caller_flags, *backport], 'debug': 7})
        self.assertEqual(backend.pocx_kernel_header_flags, backport)


class BPFArgumentWidthTest(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        self.binary = self.root / 'probe'
        self.elf(1, 3)
        self.context = Context(self.binary, [('trace_event', 1, 'uint32_t')])

    def elf(self, elf_class, machine):
        self.binary.write_bytes(b'\x7fELF' + bytes((elf_class, 1)) + bytes(12) + machine.to_bytes(2, 'little'))

    def test_native64_is_byte_exact_and_keeps_backend_arguments(self):
        self.elf(2, 62)
        self.context.get_text = lambda: self.fail('ELF64 must not inspect or rewrite BCC readers')
        backend = abi.BPF(text=PROGRAM, usdt_contexts=[self.context], debug=7, cflags=['-DVALUE=1'])
        self.assertEqual(backend.kwargs, {'text': PROGRAM, 'usdt_contexts': [self.context],
                                         'debug': 7, 'cflags': ['-DVALUE=1']})
        self.assertEqual(backend.pocx_usdt_argument_reads, [])

    def test_no_active_contexts_preserves_program(self):
        self.assertEqual(abi.argument_reads(PROGRAM, []), (PROGRAM, []))

    def test_original_adapter_requires_enabled_linux_i686(self):
        enabled = {'target_system': 'Linux', 'WITH_USDT': 'ON'}
        self.assertTrue(original_usdt.required(self.binary, enabled))
        self.assertFalse(original_usdt.required(self.binary, {**enabled, 'WITH_USDT': 'OFF'}))
        self.assertFalse(original_usdt.required(self.binary, {**enabled, 'target_system': 'Windows'}))
        self.elf(2, 62)
        with patch.dict('sys.modules', {'bcc': SimpleNamespace(__version__='0.31.0')}):
            self.assertFalse(original_usdt.required(self.binary, enabled))
        with patch.dict('sys.modules', {'bcc': SimpleNamespace(__version__='0.18.0')}), \
                patch.object(original_usdt, 'kernel_header_flags', return_value=['-fcf-protection']):
            self.assertTrue(original_usdt.required(self.binary, enabled))
        self.elf(1, 40)
        with self.assertRaises(ValueError):
            original_usdt.required(self.binary, enabled)

    def test_i686_preserves_read_user_and_original_event_destination(self):
        changed, records = abi.argument_reads(PROGRAM, [self.context])
        self.assertIn('bpf_probe_read_user(&event.data, sizeof(event.data), pointer);', changed)
        self.assertEqual(records, [{'function': 'trace_event', 'argument': 1,
                                   'ctype': 'uint32_t', 'destination': 'pointer'}])
        self.assertIn('if (pocx_usdt_result == 0) pointer =', changed)
        self.assertIn('pocx_usdt_result; })', changed)

    def test_signed_scalar_and_pointer_types_stay_distinct(self):
        self.context.declarations.append(('trace_event', 2, 'int64_t'))
        text = PROGRAM.replace('    return 0;', '    bpf_usdt_readarg (2, ctx, &event.amount);\n    return 0;')
        changed, rows = abi.argument_reads(text, [self.context])
        self.assertEqual([row['ctype'] for row in rows], ['uint32_t', 'int64_t'])
        self.assertIn('__typeof__(event.amount)', changed)

    def test_comments_and_literals_cannot_forge_functions_or_reads(self):
        prefix = '// int trace_event(struct pt_regs *ctx) { bpf_usdt_readarg(8, ctx, &fake); }\n'
        text = prefix + PROGRAM.replace('void *pointer = 0;', 'void *pointer = 0; /* } */')
        changed, rows = abi.argument_reads(text, [self.context])
        self.assertTrue(changed.startswith(prefix))
        self.assertEqual(len(rows), 1)

    def test_unknown_target_abi_rejected(self):
        self.elf(1, 40)
        with self.assertRaisesRegex(ValueError, 'i686'):
            abi.argument_reads(PROGRAM, [self.context])

    def test_mixed_target_abis_rejected(self):
        other = self.root / 'other'
        other.write_bytes(b'\x7fELF\x02\x01' + bytes(12) + (62).to_bytes(2, 'little'))
        with self.assertRaisesRegex(ValueError, 'Mixed'):
            abi.argument_reads(PROGRAM, [self.context, Context(other, [])])

    def test_ambiguous_or_unrecognized_reader_rejected(self):
        for declarations in [[('trace_event', 1, 'uint32_t'), ('trace_event', 1, 'uint64_t')],
                             [('trace_event', 1, 'long')]]:
            with self.subTest(declarations=declarations):
                self.context.declarations = declarations
                with self.assertRaises(ValueError):
                    abi.argument_reads(PROGRAM, [self.context])

    def test_unknown_index_context_or_destination_rejected(self):
        for old, new in [('(1, ctx, &pointer)', '(2, ctx, &pointer)'),
                         ('(1, ctx, &pointer)', '(1, wrong, &pointer)'),
                         ('(1, ctx, &pointer)', '(1, ctx, output())')]:
            with self.subTest(replacement=new), self.assertRaises(ValueError):
                abi.argument_reads(PROGRAM.replace(old, new), [self.context])

    def test_ambiguous_or_unterminated_callback_rejected(self):
        for text in [PROGRAM + PROGRAM, PROGRAM[:-2]]:
            with self.subTest(text=text), self.assertRaises(ValueError):
                abi.argument_reads(text, [self.context])


class OriginalUSDTViewTest(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        self.source = self.root / 'original'
        tests = self.source / 'test/functional'
        tests.mkdir(parents=True)
        for name in original_usdt.TESTS:
            shutil.copyfile(ROOT / 'test/functional' / name, tests / name)
        (tests / 'test_framework').mkdir()
        (tests / 'test_framework/__init__.py').write_text('')
        self.owned = self.root / 'owned'
        review = json.loads((ROOT / original_usdt.REVIEW).read_text())
        for name in [original_usdt.REVIEW, *review['helpers'],
                     *(row['replacement'] for row in review['tests'].values())]:
            target = self.owned / name
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / name, target)
        self.build = self.root / 'build'
        (self.build / 'test').mkdir(parents=True)
        (self.build / 'bin').mkdir()
        (self.build / 'lib').mkdir()
        (self.build / 'test/config.ini').write_text('[environment]\nBUILDDIR=' + str(self.build) +
                                                   '\nSRCDIR=' + str(self.source) + '\n[components]\nENABLE_WALLET=1\n')

    def stage(self):
        return original_usdt.stage(self.build, self.root / 'output', root=self.source, owned_root=self.owned)

    def verify(self, view):
        return original_usdt.verify(view, self.build, root=self.source, owned_root=self.owned)

    def test_exact_original_sources_and_binary_build_are_preserved(self):
        before = original_usdt.original_sources(self.source)
        view, proof = self.stage()
        self.assertEqual(original_usdt.original_sources(self.source), before)
        self.assertEqual(self.verify(view), proof)
        self.assertEqual((view / 'bin').resolve(), (self.build / 'bin').resolve())
        with self.assertRaisesRegex(ValueError, 'overwrite'):
            self.stage()

    def test_changed_original_owned_helper_staging_or_config_rejected(self):
        view, _ = self.stage()
        paths = [self.source / 'test/functional/interface_usdt_validation.py',
                 self.owned / original_usdt.HELPER,
                 view / 'test/functional/interface_usdt_validation.py',
                 view / 'test/config.ini', self.build / 'test/config.ini']
        for path in paths:
            with self.subTest(path=path):
                before = path.read_bytes()
                path.write_bytes(before + b'\n# changed\n')
                with self.assertRaises(ValueError):
                    self.verify(view)
                path.write_bytes(before)

    def test_unexpected_file_symlink_or_binary_relocation_rejected(self):
        view, _ = self.stage()
        extra = view / 'test/functional/extra.py'
        extra.write_text('unexpected')
        with self.assertRaises(ValueError):
            self.verify(view)
        extra.unlink()
        extra.symlink_to(view / 'test/functional/interface_usdt_validation.py')
        with self.assertRaisesRegex(ValueError, 'real files'):
            self.verify(view)
        extra.unlink()
        (view / 'bin').unlink()
        (view / 'bin').symlink_to(self.root)
        with self.assertRaisesRegex(ValueError, 'different binary'):
            self.verify(view)


if __name__ == '__main__':
    unittest.main()
