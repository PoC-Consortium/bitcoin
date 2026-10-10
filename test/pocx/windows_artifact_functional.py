#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin PoCX developers
# Distributed under the MIT software license; see COPYING.
"""Run and verify both functional transports from an immutable Windows pair.

The parent owns the complete process tree and independently checks the retained
case inventory, commands and raw results. This is a functional profile, not proof
of a full producer/manifest/hosted CI pipeline.
"""
import argparse
import rpc_coverage
from collections import Counter
import csv
import json
import math
import os
from pathlib import Path
import shlex
import sys
import time

from common import ROOT, sha256
import artifact_functional_view as views
import functional_environment
from functional_cases import selected_cases, upstream_cases
from functional_results import transport_results
import inherited_functional as functional
import process_tree
from verify_functional import dependency_hashes, verify_current_inputs
import windows_artifacts


def execution_profile(environment, factor):
    profile = functional.inherited_options(environment)
    factor = profile['timeout_factor'] if profile['timeout_factor'] is not None else factor
    if type(factor) not in (int, float) or not math.isfinite(factor) or factor <= 0 or not math.isfinite(2400 * factor):
        raise ValueError('Functional timeout factor must be finite and positive')
    profile['effective_timeout_factor'] = factor
    return profile


def verify_child(report, directory, view, options, jobs, factor, environment, *, root=ROOT):
    profile = execution_profile(environment, factor)
    factor = profile['effective_timeout_factor']
    native = options['ENABLE_POCX'] == 'ON'
    if (report.get('status') != 'passed' or report.get('profile') != profile or
            report.get('build_options') != options or report.get('build_configuration') is not None or
            report.get('native') is not native or report.get('external_dependencies') != dependency_hashes()):
        raise ValueError('Functional child configuration/profile/dependencies are incomplete or changed')
    raw = []
    expected_runs = []
    if native:
        proof_record = report.get('native_proof', {})
        proof_path = Path(proof_record.get('path', ''))
        if (proof_path.is_symlink() or not proof_path.resolve().is_relative_to(view.resolve()) or
                not proof_path.is_file() or sha256(proof_path) != proof_record.get('sha256')):
            raise ValueError('Missing or changed native functional proof')
        proof = json.loads(proof_path.read_text())
        if proof.get('provenance', {}).get('format_version') not in (9, 10):
            raise ValueError('Artifact native execution requires the current process-controlled proof format')
        manifest = verify_current_inputs(proof, view)
        expected = selected_cases(manifest, upstream_cases(root / 'test/functional/test_runner.py'))
        if (proof['provenance']['selected_cases'] != expected or proof['provenance']['transport_modes'] != ['v1', 'v2'] or
                proof['provenance'].get('build_configuration') is not None or
                proof['provenance'].get('timeout_factor') != factor or
                proof['provenance'].get('environment_profile') !=
                    {'previous_releases': profile['previous_releases'], 'network_addresses': False} or
                proof['provenance'].get('execution_options') !=
                    {'use_cli': profile['use_cli'], 'multiprocess': profile['multiprocess']}):
            raise ValueError('Native proof does not match the required full matrix and profile')
        pairs = transport_results(proof)
        if profile.get('coverage', False) != (proof['provenance'].get('rpc_coverage') is True) or not rpc_coverage.verify(proof):
            raise ValueError('Missing or failed requested RPC coverage')
        expected_exit = 0 if all(row['status'] == 'passed' for _, row in pairs) else 1
        expected_runs.append(('native', functional.native_command(view, jobs, factor, profile, environment), expected_exit))
        for mode, row in pairs:
            raw.append((row['case'], mode, mode, row['status'], row['seconds']))
        expected = [spec['id'] for spec in expected]
    else:
        enabled = options.get('BUILD_BENCH') == 'ON'
        if options.get('BUILD_BENCH') not in ('ON', 'OFF'): raise ValueError('Missing explicit benchmark feature')
        benchmarks = []
        if enabled:
            log = directory / 'benchmarks.log'
            discovery = {'command': [str(view / 'bin/bench_bitcoin.exe'), '-list'], 'log_sha256': sha256(log)}
            if report.get('benchmark_discovery') != discovery:
                raise ValueError('Benchmark discovery command or raw log changed')
            benchmarks = log.read_text().splitlines()
        elif 'benchmark_discovery' in report:
            raise ValueError('Disabled benchmarks have unexpected discovery evidence')
        if report.get('benchmarks') != benchmarks: raise ValueError('Benchmark inventory differs from executed listing')
        expected = functional.original_inventory(root / 'test/functional/test_runner.py', benchmarks, enabled)
        for mode in ('v1', 'v2'):
            for group in functional.original_groups(expected, options):
                command = functional.original_command(view, directory, group, mode, jobs, factor, profile, windows=True)
                if group[2]:
                    runs = [run for run in report['runs'] if run['name'] == mode + '-legacy-utxo']
                    if len(runs) != 1: raise ValueError('Missing or duplicate old-release UTXO execution')
                    code = runs[0]['returncode']
                    if type(code) is not int or code not in (0, 77): raise ValueError('Old-release UTXO execution failed')
                    status = 'Passed' if code == 0 else 'Skipped'
                    raw.append((functional.LEGACY_UTXO, mode, mode, status, runs[0]['seconds']))
                    expected_runs.append((mode + '-legacy-utxo', command, code))
                else:
                    rows, summary = functional.read_cases(directory / (mode + '.csv'), group[1])
                    if summary[1] != 'Passed': raise ValueError('Original functional aggregate failed')
                    for case, status, duration in rows:
                        raw.append((case, mode, functional.effective_transport(case, mode), status, float(duration)))
                    expected_runs.append((mode, command, 0))
    if report.get('expected_cases') != expected: raise ValueError('Functional expected inventory changed')
    if len(report.get('runs', [])) != len(expected_runs): raise ValueError('Missing or additional functional runner execution')
    for run, (name, command, code) in zip(report['runs'], expected_runs):
        if (run['name'] != name or run['command'] != command or run['returncode'] != code or
                type(run.get('seconds')) not in (int, float) or not math.isfinite(run['seconds']) or run['seconds'] < 0 or
                run['log_sha256'] != sha256(directory / (name + '.log'))):
            raise ValueError('Functional runner command, terminal result or retained log changed')
    wanted = Counter((case, mode) for case in expected for mode in ('v1', 'v2'))
    if Counter((case, mode) for case, mode, _, _, _ in raw) != wanted:
        raise ValueError('Incomplete raw functional matrix')
    checked = []
    for case, mode, effective, status, seconds in raw:
        state, reason = functional.classify(case, status, options, profile, native=native, root=root)
        if state not in ('passed', 'configuration-disabled'):
            raise ValueError('Required functional case failed or skipped without a source guard: ' + case)
        checked.append({'case': case, 'transport': mode, 'effective_transport': effective, 'status': state,
                        'reason': reason, 'execution_status': status, 'seconds': seconds})
    if report.get('cases') != checked or report.get('counts') != dict(Counter(row['status'] for row in checked)):
        raise ValueError('Functional reported cases differ from raw terminal results')
    if not any(row['status'] == 'passed' for row in checked): raise ValueError('No applicable functional passes')
    return checked


def run_phase(bundle, row, output, jobs, factor, *, environment=None, timeout=86400,
              execute=process_tree.execute, root=ROOT, revision=None):
    if type(jobs) is not int or jobs < 1 or type(timeout) is not int or timeout < 1:
        raise ValueError('Expected positive functional jobs and process timeout')
    output = output.resolve()
    if output.is_relative_to(bundle.resolve()): raise ValueError('Reports must be outside immutable artifact payload')
    options = row['build_options']
    if options.get('target_system') != 'Windows': raise ValueError('Functional artifacts require a Windows target')
    env = {key: value for key, value in (os.environ if environment is None else environment).items() if key != 'PYTHONPATH'}
    env['PYTHONDONTWRITEBYTECODE'] = '1'
    profile = execution_profile(env, factor)
    factor = profile['effective_timeout_factor']
    releases = functional_environment.release_binaries(env['PREVIOUS_RELEASES_DIR']) if profile['previous_releases'] else {}
    release_inputs = {name: {'path': str(path), 'sha256': sha256(path)} for name, path in releases.items()}
    pair = windows_artifacts.verify_pair(bundle, root=root, revision=revision)
    if row not in pair['phases']: raise ValueError('Functional phase differs from immutable artifact manifest')
    output.mkdir(parents=True, exist_ok=False)
    view = output / 'runtime'
    report = {'status': 'running', 'scope': 'Complete applicable artifact functional selection in both transports; full hosted pipeline incomplete',
        'full_windows_ci_pass': False, 'consensus': row['consensus'], 'cases': [],
        'pair_sha256': sha256(bundle / 'pair.json'), 'process_controller': process_tree.description(),
        'profile': profile, 'timeout': timeout, 'previous_release_binaries': release_inputs}
    def save(): (output / 'results.json').write_text(json.dumps(report, indent=2) + '\n')
    save()
    try:
        report['runtime_view'] = views.create_view(bundle, row['consensus'], view, root=root, revision=revision)
        if profile['previous_releases'] and not str(view).isascii():
            raise ValueError('Windows old-release functional execution requires an ASCII-only runtime root')
        child = output / 'execution'
        command = [sys.executable, '-B', str(root / 'test/pocx/inherited_functional.py'),
            '--build-dir', str(view), '--output', str(child), '--jobs', str(jobs), '--timeout-factor', str(factor)]
        report['command'] = command; save()
        log = output / 'functional.log'
        start = time.monotonic()
        with log.open('w') as stream:
            execution = execute(command, cwd=root, env=env, log=stream, timeout=timeout)
        report.update(**execution, seconds=time.monotonic() - start, log_sha256=sha256(log)); save()
        process_tree.validate_control(report['process_controller'], execution['process_control'], command)
        if execution['returncode'] or execution['timed_out']: raise ValueError('Artifact functional process failed or timed out')
        proof_path = child / 'results.json'
        proof = json.loads(proof_path.read_text())
        report['child_report_sha256'] = sha256(proof_path)
        report['cases'] = verify_child(proof, child, view, options, jobs, factor, env, root=root)
        views.verify_view(bundle, row['consensus'], view, root=root, revision=revision)
        if (sha256(bundle / 'pair.json') != report['pair_sha256'] or
                any(sha256(path) != release_inputs[name]['sha256'] for name, path in releases.items())):
            raise ValueError('Artifact or previous-release input changed during functional execution')
        report['counts'] = dict(Counter(row['status'] for row in report['cases']))
        with (output / 'cases.csv').open('w', newline='') as stream:
            writer = csv.DictWriter(stream, fieldnames=list(report['cases'][0])); writer.writeheader(); writer.writerows(report['cases'])
        report['status'] = 'passed'
    except BaseException as error:
        proof_path = output / 'execution/results.json'
        if proof_path.is_file():
            report['child_report_sha256'] = sha256(proof_path)
            report['failed_child_report'] = str(proof_path)
        report.update(status='failed', error=str(error)); save(); raise
    save()
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--artifacts', type=Path, required=True)
    parser.add_argument('--consensus', choices=('bitcoin', 'pocx'), required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--jobs', type=int, default=4)
    parser.add_argument('--timeout-factor', type=float, default=40)
    parser.add_argument('--timeout', type=int, default=86400)
    args = parser.parse_args()
    if os.name != 'nt': parser.error('Actual artifact functional execution requires Windows')
    windows_artifacts.verify_recipe()
    pair = windows_artifacts.verify_pair(args.artifacts)
    row = next(row for row in pair['phases'] if row['consensus'] == args.consensus)
    run_phase(args.artifacts, row, args.output, args.jobs, args.timeout_factor, timeout=args.timeout)


if __name__ == '__main__':
    main()
