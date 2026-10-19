#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin PoCX developers
# Distributed under the MIT software license; see COPYING.
"""Exercise fuzz inventory, drift and runtime-evidence rejection gates."""
import json
from pathlib import Path
import shutil
import tempfile
import unittest

from common import ROOT, sha256
import ci_fuzz_run
import fuzz_build
import fuzz_parity
import run_fuzz


class FuzzParityTest(unittest.TestCase):
    def test_inherited_worker_count_and_manual_option_are_explicit(self):
        self.assertEqual(ci_fuzz_run.jobs_from_makejobs('-j4'), 4)
        self.assertEqual(ci_fuzz_run.jobs_from_makejobs('-j 4'), 4)
        with self.assertRaisesRegex(ValueError, 'Unsupported inherited MAKEJOBS'):
            ci_fuzz_run.jobs_from_makejobs('--keep-going')

    def fixture(self, destination):
        baseline, parity = fuzz_parity.records()
        files = set(baseline['sources']) | set(parity['reviewed_sources']) | {
            'test/pocx/fuzz-baseline.json', 'test/pocx/fuzz-parity.json'}
        for name in files:
            target = destination / name
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / name, target)
        return baseline, parity

    def test_original_and_adapted_source_drift_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            baseline, parity = self.fixture(root)
            self.assertEqual(fuzz_parity.check(root), [])
            original = root / baseline['targets']['block_header']['source']
            original.write_text(original.read_text() + '\n// unintended inline edit\n')
            self.assertIn('Original fuzz source changed', ' '.join(fuzz_parity.check(root)))
            shutil.copyfile(ROOT / baseline['targets']['block_header']['source'], original)
            adapted = root / parity['targets']['block_header']['replacement']
            adapted.write_text(adapted.read_text() + '\n// unreviewed adaptation\n')
            self.assertIn('Reviewed fuzz dependency changed', ' '.join(fuzz_parity.check(root)))

    def test_omitted_target_and_replacement_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            _, parity = self.fixture(root)
            del parity['targets']['block_header']
            (root / 'test/pocx/fuzz-parity.json').write_text(json.dumps(parity))
            self.assertIn('classification is incomplete', ' '.join(fuzz_parity.check(root)))
            parity['targets']['block_header'] = fuzz_parity.records()[1]['targets']['block_header']
            (root / 'test/pocx/fuzz-parity.json').write_text(json.dumps(parity))
            selected = root / 'src/pocx/test/fuzz/sources.cmake'
            selected.write_text(selected.read_text().replace('adapted/block_header.cpp', 'adapted/removed_header.cpp'))
            self.assertIn('Missing fuzz source selection', ' '.join(fuzz_parity.check(root)))

    def test_stale_build_or_report_marker_cannot_pass(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / 'source.cpp'
            binary = root / 'fuzz'
            cache = root / 'CMakeCache.txt'
            selection = root / 'selection.txt'
            record = root / 'build.json'
            source.write_text('int x;\n')
            binary.write_bytes(b'linked binary')
            cache.write_text('ENABLE_POCX:BOOL=ON\n')
            selection.write_text(str(source) + '\n')
            record.write_text(json.dumps(fuzz_build.snapshot(binary, selection, cache)))
            fuzz_build.verify(binary, selection, cache, record)
            source.write_text('int y;\n')
            with self.assertRaisesRegex(ValueError, 'Stale fuzz build provenance'):
                fuzz_build.verify(binary, selection, cache, record)
        with self.assertRaisesRegex(ValueError, 'completion'):
            run_fuzz.completed('#1 INITED\n', 'case', 1, libfuzzer=True)
        with self.assertRaisesRegex(ValueError, 'incomplete'):
            run_fuzz.completed('case: succeeded against 0 files in 0s.\n',
                               'case', 0, libfuzzer=False)

    def test_saved_result_rejects_changed_corpus_or_log(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            build = root / 'build'
            build.mkdir()
            source = root / 'source.cpp'
            source.write_text('int x;\n')
            binary = build / 'fuzz'
            binary.write_bytes(b'linked binary')
            cache = build / 'CMakeCache.txt'
            cache.write_text('ENABLE_POCX:BOOL=ON\n')
            provenance = build / 'pocx-fuzz-build'
            provenance.mkdir()
            inputs = provenance / 'build-inputs.txt'
            inputs.write_text(str(source) + '\n')
            record = provenance / 'build.json'
            record.write_text(json.dumps(fuzz_build.snapshot(binary, inputs, cache)))
            corpus = root / 'corpus'
            (corpus / 'case').mkdir(parents=True)
            seed = corpus / 'case/seed'
            seed.write_bytes(b'input')
            output = build / 'fuzz-results-fixture'
            (output / 'case').mkdir(parents=True)
            log = output / 'case/fuzz.log'
            log.write_text('case: succeeded against 1 files in 0s.\n')
            report = {
                'registered': ['case'], 'selected': ['case'], 'results': [{
                    'target': 'case', 'status': 'passed', 'returncode': 0,
                    'executions': 1, 'saved_inputs': 1, 'corpus': {'seed': sha256(seed)},
                    'log': str(log), 'log_sha256': sha256(log)}],
                'configuration_disabled': {}, 'excluded': {},
                'build_provenance_sha256': sha256(record), 'binary_sha256': sha256(binary),
                'cache_sha256': sha256(cache), 'runner_sha256': sha256(ROOT / 'test/pocx/run_fuzz.py'),
                'baseline_sha256': sha256(ROOT / 'test/pocx/fuzz-baseline.json'),
                'parity_sha256': sha256(ROOT / 'test/pocx/fuzz-parity.json'),
                'corpus_provenance_sha256': None, 'engine': 'standalone', 'empty_min_time': 60,
            }
            report_path = output / 'results.json'
            report_path.write_text(json.dumps(report))
            contract = {'expected': ['case'], 'configuration_disabled': {}, 'excluded': {}}
            verify = lambda: run_fuzz.verify_report(report_path, build=build, corpus=corpus,
                                                     contract=contract, binary=binary, provenance=provenance)
            verify()
            seed.write_bytes(b'changed input')
            with self.assertRaisesRegex(ValueError, 'corpus inputs changed'):
                verify()
            seed.write_bytes(b'input')
            log.write_text('case: succeeded against 0 files in 0s.\n')
            with self.assertRaisesRegex(ValueError, 'log is missing or changed'):
                verify()


if __name__ == '__main__':
    unittest.main()
