#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin PoCX developers
# Distributed under the MIT software license; see COPYING.
"""Consume an immutable Windows pair: complete Bitcoin runtime before PoCX.

Plans and callback checks do not establish Windows execution. Actual hosted
producer/workflow verification is a separate requirement from this runtime.
"""
import argparse
import csv
import json
import os
from pathlib import Path
import shlex
import sys

from common import ROOT, sha256
from functional_cases import upstream_cases
import process_tree
import unit_assets
import windows_artifacts
import windows_artifact_functional as functional
import windows_artifact_tests as frameworks

MANIFEST_SKIPS = {'fuzz.exe', 'bench_bitcoin.exe'}  # Exact unchanged cross-driver exemptions.


def functional_rows(cases, native, *, root=ROOT):
    upstream = upstream_cases(root / 'test/functional/test_runner.py')
    original_names = {case['test'] for case in upstream}
    manifest = json.loads((root / 'test/pocx/manifest.json').read_text())
    rows = []
    for case in cases:
        name = shlex.split(case['case'])[0]
        only = native and name not in original_names
        rows.append({**case, 'framework': 'functional', 'counting_unit': 'Argument case per transport',
            'origin': 'pocx-only' if only else 'original',
            'adaptation': 'original' if not native else 'pocx-only' if only else
                'adapted' if name in manifest['tests'] else 'unchanged'})
    if native:
        seen = set()
        for case in upstream:
            name = case['test']
            if name not in manifest.get('excluded_tests', {}):
                continue
            for mode in ('v1', 'v2'):
                key = (case['id'], mode)
                if key in seen:
                    continue
                seen.add(key)
                rows.append({'framework': 'functional', 'counting_unit': 'Argument case per transport',
                    'case': case['id'], 'transport': mode, 'effective_transport': mode,
                    'origin': 'original', 'adaptation': 'excluded', 'status': 'reviewed-exclusion',
                    'reason': manifest['excluded_tests'][name], 'seconds': '', 'execution_status': 'not executed'})
    return rows


def run_pair(bundle, output, assets, jobs, factor, *, environment=None, timeout=86400,
             execute=process_tree.execute, root=ROOT, revision=None):
    if type(jobs) is not int or jobs < 1 or type(timeout) is not int or timeout < 1:
        raise ValueError('Expected positive runtime jobs and timeout')
    output = output.resolve()
    if output.is_relative_to(bundle.resolve()):
        raise ValueError('Reports must be outside immutable artifact bundle')
    pair = windows_artifacts.verify_pair(bundle, root=root, revision=revision)
    env = dict(os.environ if environment is None else environment)
    env['PYTHONDONTWRITEBYTECODE'] = '1'
    env['DOWNLOAD_PREVIOUS_RELEASES'] = 'true'
    profile = functional.execution_profile(env, factor)
    if not env.get('PREVIOUS_RELEASES_DIR'):
        raise ValueError('Full Windows runtime requires PREVIOUS_RELEASES_DIR')
    output.mkdir(parents=True, exist_ok=False)
    report = {'status': 'running', 'scope': 'Complete applicable paired artifact runtime; hosted producer/workflow evidence remains separate',
        'full_windows_runtime_pass': False, 'full_windows_ci_pass': False, 'host_platform': sys.platform,
        'pair_sha256': sha256(bundle / 'pair.json'), 'phases': [], 'cases': [], 'native_execution': 'deferred',
        'process_controller': process_tree.description(), 'profile': profile, 'timeout': timeout}
    def save():
        (output / 'results.json').write_text(json.dumps(report, indent=2) + '\n')
        columns = ['consensus', 'framework', 'counting_unit', 'case', 'transport', 'effective_transport',
                   'origin', 'adaptation', 'status', 'reason', 'execution_status', 'assertions_passed', 'seconds']
        with (output / 'cases.csv').open('w', newline='') as stream:
            writer = csv.DictWriter(stream, fieldnames=columns, extrasaction='ignore')
            writer.writeheader()
            writer.writerows(report['cases'])
    def unchanged():
        windows_artifacts.verify_pair(bundle, root=root, revision=revision)
        if sha256(bundle / 'pair.json') != report['pair_sha256']:
            raise ValueError('Immutable artifact manifest changed')
    save()
    try:
        for row in pair['phases']:
            consensus = row['consensus']
            payload = bundle / consensus
            if consensus == 'pocx':
                report['native_execution'] = 'started after complete original framework/functional runtime passed'
            directory = output / consensus
            directory.mkdir()
            phase = {'consensus': consensus, 'status': 'running', 'steps': []}
            report['phases'].append(phase)
            save()
            def invoke(name, command):
                unchanged()
                step = {'name': name, 'command': command, 'status': 'running'}
                phase['steps'].append(step)
                save()
                log = directory / (name + '.log')
                with log.open('w') as stream:
                    result = execute(command, cwd=root, env=env, log=stream, timeout=2400)
                step.update(**result, log_sha256=sha256(log))
                save()
                process_tree.validate_control(report['process_controller'], result['process_control'], command)
                if result['returncode'] or result['timed_out']:
                    raise ValueError('Windows artifact prerequisite failed: ' + name)
                unchanged()
                step['status'] = 'passed'
                save()
            if consensus == 'bitcoin':
                invoke('host-process-lifecycle', [sys.executable, '-B', str(root / 'test/pocx/test_process_tree.py')])
            invoke('version', [str(payload / 'bin/bitcoind.exe'), '-version'])
            manifest = directory / 'bitcoind.manifest'
            invoke('extract-manifest', ['mt.exe', '-nologo', '-inputresource:' + str(payload / 'bin/bitcoind.exe'), '-out:' + str(manifest)])
            if not manifest.is_file() or not manifest.stat().st_size:
                raise ValueError('Extracted Windows manifest missing or empty')
            phase['extracted_manifest_sha256'] = sha256(manifest)
            phase['manifest_exemptions'] = []
            for name in sorted(row['files']):
                if not name.startswith('bin/') or not name.endswith('.exe'):
                    continue
                if Path(name).name in MANIFEST_SKIPS:
                    phase['manifest_exemptions'].append({'binary': name, 'reason': 'Unchanged original cross-driver manifest exemption'})
                    continue
                invoke('validate-' + Path(name).stem, ['mt.exe', '-nologo', '-inputresource:' + str(payload / name), '-validate_manifest'])
            child = frameworks.run_phase(payload, row, directory / 'frameworks', assets,
                environment=env, timeout=2400, execute=execute)
            if child['status'] != 'passed':
                raise ValueError('Original/native artifact framework profile failed')
            phase['framework_report_sha256'] = sha256(directory / 'frameworks/results.json')
            report['cases'].extend(dict(case, consensus=consensus) for case in child['cases'])
            save()
            unchanged()
            child = functional.run_phase(bundle, row, directory / 'functional', jobs, factor,
                environment=env, timeout=timeout, execute=execute, root=root, revision=revision)
            if child['status'] != 'passed':
                raise ValueError('Original/native artifact functional profile failed')
            phase['functional_report_sha256'] = sha256(directory / 'functional/results.json')
            report['cases'].extend(dict(case, consensus=consensus) for case in functional_rows(child['cases'], consensus == 'pocx', root=root))
            unchanged()
            phase['status'] = 'passed'
            save()
        report.update(status='passed', full_windows_runtime_pass=True)
    except BaseException as error:
        if report['phases']:
            phase = report['phases'][-1]
            if phase['status'] == 'running':
                phase['status'] = 'failed'
            for step in phase['steps']:
                if step['status'] == 'running':
                    step['status'] = 'failed'
            phase['retained_reports'] = {}
            for name in ('frameworks', 'functional'):
                path = output / phase['consensus'] / name / 'results.json'
                if path.is_file():
                    phase['retained_reports'][name] = {'path': str(path), 'sha256': sha256(path)}
        report.update(status='failed', error=str(error))
        save()
        raise
    save()
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--artifacts', type=Path, required=True)
    parser.add_argument('--output', type=Path)
    parser.add_argument('--jobs', type=int, default=getattr(os, 'process_cpu_count', os.cpu_count)() or 1)
    parser.add_argument('--timeout-factor', type=float, default=40)
    parser.add_argument('--timeout', type=int, default=86400)
    parser.add_argument('--plan', action='store_true')
    args = parser.parse_args()
    if not args.plan and os.name != 'nt':
        parser.error('Actual complete artifact runtime requires Windows')
    windows_artifacts.verify_recipe()
    pair = windows_artifacts.verify_pair(args.artifacts)
    if args.plan:
        print(json.dumps({'status': 'configured only; not executed', 'full_windows_ci_pass': False,
            'phases': [{'consensus': row['consensus'], 'steps': ['manifest', 'qt/unit/libraries/kernel', 'functional v1/v2 including previous releases']}
                       for row in pair['phases']]}, indent=2))
        return
    if args.output is None:
        parser.error('Execution requires a new --output directory')
    assets = unit_assets.provision(ROOT / 'unit_test_data')
    run_pair(args.artifacts, args.output, assets, args.jobs, args.timeout_factor, timeout=args.timeout)


if __name__ == '__main__':
    main()
