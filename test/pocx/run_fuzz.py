#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin PoCX developers
# Distributed under the MIT software license; see COPYING.
"""Run reviewed fuzz targets with upstream replay flags and strict accounting."""
import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import time

import build_configuration
from common import ROOT, build_options, exclusive_lock, sha256
import fuzz_build
import fuzz_parity


def load_upstream():
    spec = importlib.util.spec_from_file_location('upstream_fuzz_runner', ROOT / 'test/fuzz/test_runner.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def fuzz_environment(upstream, target):
    env = upstream.get_fuzz_env(target=target, source_dir=str(ROOT))
    return {key: value for key, value in env.items() if key not in (
        'FUZZ_NONDETERMINISM', 'PRINT_ALL_FUZZ_TARGETS_AND_ABORT',
        'WRITE_ALL_FUZZ_TARGETS_AND_ABORT', 'LIMIT_TO_MESSAGE_TYPE',
        'LIMIT_TO_RPC_COMMAND')}


def corpus_record(directory):
    files = sorted(path for path in directory.iterdir() if path.is_file()) if directory.is_dir() else []
    if directory.is_dir() and any(path.is_symlink() or not path.is_file() for path in directory.iterdir()):
        raise ValueError('Unexpected non-file fuzz corpus entry: ' + str(directory))
    return {path.name: sha256(path) for path in files}


def completed(log, target, count, *, libfuzzer, empty_min_time=None):
    if libfuzzer:
        done = re.findall(r'^#(\d+)\s+DONE\b', log, re.M)
        if len(done) != 1 or int(done[0]) < 1:
            raise ValueError('Missing or ambiguous libFuzzer completion')
        if not count and not empty_min_time:
            raise ValueError('Empty corpus without a bounded fuzz campaign')
        return int(done[0])
    matches = re.findall(r'^' + re.escape(target) + r': succeeded against (\d+) files in ', log, re.M)
    if matches != [str(count)] or count < 1:
        raise ValueError('Missing, empty or incomplete standalone corpus execution')
    return count


def build_record(build, cache, selected_config):
    directory = build / 'pocx-fuzz-build'
    if selected_config is not None and build_options(cache).get('CMAKE_CONFIGURATION_TYPES'):
        directory /= selected_config
    return directory


def verify_report(path, *, build, corpus, contract, binary, provenance):
    """Reject missing, duplicated or stale execution and corpus evidence."""
    report = json.loads(path.read_text())
    registered = report['registered']
    selected = report['selected']
    expected = set(contract['expected'])
    if set(registered) != expected or len(registered) != len(expected):
        raise ValueError('Saved fuzz registration differs from selected configuration')
    if not selected or set(selected) - expected or len(selected) != len(set(selected)):
        raise ValueError('Saved fuzz target selection is incomplete or duplicated')
    rows = report['results']
    if len(rows) != len(selected) or {row['target'] for row in rows} != set(selected):
        raise ValueError('Saved fuzz target results are missing or duplicated')
    if (report['configuration_disabled'] != contract['configuration_disabled'] or
            report['excluded'] != contract['excluded']):
        raise ValueError('Saved fuzz exclusions or disabled cases changed')
    build_inputs = provenance / 'build-inputs.txt'
    current = fuzz_build.verify(binary, build_inputs, build / 'CMakeCache.txt', provenance / 'build.json')
    if (report['build_provenance_sha256'] != sha256(provenance / 'build.json') or
            report['binary_sha256'] != current['binary_sha256'] or
            report['cache_sha256'] != sha256(build / 'CMakeCache.txt') or
            report['runner_sha256'] != sha256(Path(__file__)) or
            report['baseline_sha256'] != sha256(ROOT / 'test/pocx/fuzz-baseline.json') or
            report['parity_sha256'] != sha256(ROOT / 'test/pocx/fuzz-parity.json')):
        raise ValueError('Saved fuzz source, binary or runner provenance changed')
    stage = corpus.parent / 'provenance.json'
    if report['corpus_provenance_sha256'] != (sha256(stage) if stage.is_file() else None):
        raise ValueError('Saved fuzz corpus provenance changed')
    manifest = json.loads(stage.read_text()) if stage.is_file() else None
    if manifest is not None:
        if manifest['stage_sha256'] != sha256(ROOT / 'test/pocx/stage_fuzz_corpus.py'):
            raise ValueError('Fuzz corpus staging code changed')
        for name, expected_hash in manifest['generator_sha256'].items():
            if sha256(ROOT / 'test/pocx/fuzz' / name) != expected_hash:
                raise ValueError('Fuzz corpus generator changed: ' + name)
    for row in rows:
        target = row['target']
        log = path.parent / target / 'fuzz.log'
        if Path(row['log']).resolve() != log.resolve() or row['log_sha256'] != sha256(log):
            raise ValueError('Saved fuzz log is missing or changed: ' + target)
        inputs = corpus_record(corpus / target)
        if inputs != row['corpus'] or len(inputs) != row['saved_inputs']:
            raise ValueError('Saved fuzz corpus inputs changed: ' + target)
        if manifest is not None:
            if manifest['targets'][target]['inputs'] != inputs:
                raise ValueError('Staged fuzz corpus manifest differs: ' + target)
        if row['status'] == 'passed':
            if row.get('returncode') != 0 or row.get('executions') != completed(
                    log.read_text(errors='surrogateescape'), target, len(inputs),
                    libfuzzer=report['engine'] == 'libFuzzer',
                    empty_min_time=report['empty_min_time']):
                raise ValueError('Saved fuzz completion is invalid: ' + target)
        elif row['status'] == 'inactive':
            if (target != 'pocx_shabal_avx2' or row.get('returncode') != 77 or
                    'POCX_FUZZ_INACTIVE: AVX2 runtime unavailable' not in log.read_text(errors='replace')):
                raise ValueError('Invalid hardware-inactive fuzz result: ' + target)
        elif row['status'] not in ('failed', 'incomplete'):
            raise ValueError('Unknown saved fuzz execution status: ' + target)
    return report


def run(args):
    build = args.build_dir.resolve()
    cache = (build / 'CMakeCache.txt').read_text()
    build_configuration.require_source(cache, ROOT)
    selected_config = build_configuration.configuration(cache, args.config)
    contract = fuzz_parity.inventory(build, bitcoin=args.bitcoin, selected_config=selected_config)
    issues = fuzz_parity.check()
    if issues:
        raise ValueError('Fuzz source review failed: ' + str(issues))
    expected = set(contract['expected'])
    selected = set(args.target) if args.target else expected
    if not selected or selected - expected or len(args.target) != len(set(args.target)):
        raise ValueError('Empty, duplicate or unknown fuzz target selection')
    binary = build_configuration.executable(build, 'fuzz', cache, selected_config)
    provenance = build_record(build, cache, selected_config)
    with exclusive_lock(build / 'pocx-fuzz.lock'):
        evidence = fuzz_build.verify(binary, provenance / 'build-inputs.txt', build / 'CMakeCache.txt',
                                     provenance / 'build.json')
        upstream = load_upstream()
        environment = {key: value for key, value in os.environ.items() if key not in (
            'FUZZ', 'FUZZ_NONDETERMINISM', 'PRINT_ALL_FUZZ_TARGETS_AND_ABORT',
            'WRITE_ALL_FUZZ_TARGETS_AND_ABORT', 'LIMIT_TO_MESSAGE_TYPE',
            'LIMIT_TO_RPC_COMMAND')}
        listing = subprocess.run([str(binary)], env=environment | {'PRINT_ALL_FUZZ_TARGETS_AND_ABORT': '1'},
                                 capture_output=True, text=True, check=True, timeout=60).stdout.splitlines()
        if set(listing) != expected or len(listing) != len(expected):
            raise ValueError(f'Fuzz registration mismatch: missing={sorted(expected-set(listing))}, '
                             f'extra={sorted(set(listing)-expected)}')
        first = sorted(selected)[0]
        help_result = subprocess.run([str(binary), '-help=1'],
                                    env=fuzz_environment(upstream, first),
                                    capture_output=True, text=True, timeout=60)
        libfuzzer = 'libFuzzer' in help_result.stderr
        output = Path(tempfile.mkdtemp(prefix='fuzz-results-', dir=build))
        corpus = args.corpus.resolve()
        staged = corpus.parent / 'provenance.json'
        report = {'scope': 'full selected configuration' if selected == expected else 'focused target selection',
                  'product': 'bitcoin' if args.bitcoin else 'pocx', 'binary': str(binary),
                  'build_configuration': selected_config, 'build_provenance_sha256': sha256(provenance / 'build.json'),
                  'binary_sha256': evidence['binary_sha256'], 'cache_sha256': sha256(build / 'CMakeCache.txt'),
                  'runner_sha256': sha256(Path(__file__)), 'baseline_sha256': sha256(ROOT / 'test/pocx/fuzz-baseline.json'),
                  'parity_sha256': sha256(ROOT / 'test/pocx/fuzz-parity.json'),
                  'registered': sorted(listing), 'selected': sorted(selected),
                  'configuration_disabled': contract['configuration_disabled'], 'excluded': contract['excluded'],
                  'engine': 'libFuzzer' if libfuzzer else 'standalone',
                  'valgrind': args.valgrind,
                  'empty_min_time': args.empty_min_time,
                  'corpus_provenance_sha256': sha256(staged) if staged.is_file() else None,
                  'sanitizers': re.findall(r'^SANITIZERS:[^=]+=(.*)$', cache, re.M), 'results': []}
        def job(target):
            directory = corpus / target
            directory.mkdir(parents=True, exist_ok=True)
            seeds = corpus_record(directory)
            target_output = output / target
            target_output.mkdir()
            env = fuzz_environment(upstream, target)
            command = [str(binary)]
            if libfuzzer:
                command += [f'-max_total_time={args.empty_min_time}'] if not seeds else ['-runs=1', str(directory)]
            else:
                command += [str(directory)]
            if args.valgrind:
                command = ['valgrind', '--quiet', '--error-exitcode=1'] + command
            started = time.monotonic()
            row = {'target': target, 'status': 'failed', 'command': command, 'corpus': seeds,
                   'saved_inputs': len(seeds), 'sanitizer_options': {key: env.get(key, '') for key in
                   ('ASAN_OPTIONS', 'UBSAN_OPTIONS', 'LSAN_OPTIONS', 'MSAN_OPTIONS')}}
            raw = b''
            try:
                result = subprocess.run(command, env=env, cwd=target_output, capture_output=True,
                                        timeout=args.timeout)
                raw = result.stdout + result.stderr
                row['returncode'] = result.returncode
                if (target == 'pocx_shabal_avx2' and result.returncode == 77 and
                        b'POCX_FUZZ_INACTIVE: AVX2 runtime unavailable' in raw):
                    row.update(status='inactive', reason='AVX2 runtime unavailable')
                elif result.returncode:
                    row['reason'] = 'Nonzero fuzz exit'
                else:
                    row['executions'] = completed(raw.decode('utf-8', errors='surrogateescape'), target,
                        len(seeds), libfuzzer=libfuzzer, empty_min_time=args.empty_min_time)
                    row['status'] = 'passed'
            except subprocess.TimeoutExpired as error:
                raw = (error.stdout or b'') + (error.stderr or b'')
                row.update(status='incomplete', reason='Execution timeout', returncode=None)
            except (ValueError, OSError) as error:
                row['reason'] = str(error)
            row['duration_seconds'] = time.monotonic() - started
            log = target_output / 'fuzz.log'
            log.write_bytes(raw)
            row['log'] = str(log)
            row['log_sha256'] = sha256(log)
            return row
        report_path = output / 'results.json'
        report_path.write_text(json.dumps(report, indent=2) + '\n')
        with ThreadPoolExecutor(max_workers=args.jobs) as pool:
            for future in as_completed([pool.submit(job, target) for target in sorted(selected)]):
                row = future.result()
                report['results'].append(row)
                report_path.write_text(json.dumps(report, indent=2) + '\n')
                print(f"{row['target']}: {row['status']} ({row['saved_inputs']} corpus inputs)", flush=True)
        verify_report(report_path, build=build, corpus=corpus, contract=contract,
                      binary=binary, provenance=provenance)
        print('Results: ' + str(output), flush=True)
        return any(row['status'] != 'passed' for row in report['results'])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--build-dir', type=Path, required=True)
    parser.add_argument('--corpus', type=Path, required=True)
    parser.add_argument('--bitcoin', action='store_true')
    parser.add_argument('--valgrind', action='store_true', help='Preserve the inherited manual Valgrind fuzz option')
    parser.add_argument('--config')
    parser.add_argument('--jobs', type=int, default=4)
    parser.add_argument('--empty-min-time', type=int, default=60)
    parser.add_argument('--timeout', type=int, help='Optional local per-target deadline; inherited CI has no added deadline')
    parser.add_argument('target', nargs='*')
    args = parser.parse_args()
    if args.jobs < 1 or args.empty_min_time < 1 or (args.timeout is not None and args.timeout < 1):
        parser.error('Jobs and runtime budgets must be positive')
    return run(args)


if __name__ == '__main__':
    raise SystemExit(main())
