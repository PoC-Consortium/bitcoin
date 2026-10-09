#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin PoCX developers
# Distributed under the MIT software license; see COPYING.
"""Verify a complete functional matrix, retaining explicit reviewed profile skips.

The low-level runner stays strict: any skip has a nonzero exit status. This
profile verifier accepts only exact, reviewed optional-feature skip reasons;
skips remain skips in every result and never count as passes.
"""
from collections import Counter
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys

sys.dont_write_bytecode = True
from common import ROOT, OWNED
from functional_cases import selected_cases, upstream_cases
from functional_results import transport_results
from stage import framework_sources


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def dependency_hashes():
    review = json.loads((OWNED / 'upstream-functional-parity.json').read_text())
    paths = {path for row in review['results'].values() for path in row.get('dependencies', {})}
    return {path: digest(ROOT / path) for path in sorted(paths)}


def verify(report, expected_cases, modes, policy, build_options):
    """Reject partial matrices, unexpected skips and failures without relabeling."""
    pairs = transport_results(report)
    if report['provenance']['selected_cases'] != expected_cases or report['provenance']['transport_modes'] != modes:
        raise ValueError('Complete declared case/transport selection required')
    counts = {mode: Counter() for mode in modes}
    skips = []
    for mode, row in pairs:
        counts[mode][row['status']] += 1
        if row['status'] == 'failed':
            raise ValueError('Functional failure: ' + row['case'] + ' (' + mode + ')')
        if row['status'] == 'skipped':
            allowance = policy['cases'].get(row['case'])
            if not allowance or row['skip_reason'] not in allowance['reasons']:
                raise ValueError('Unreviewed functional skip: ' + row['case'] + ': ' + row['skip_reason'])
            if any(build_options.get(key) != value for key, value in allowance.get('build_options', {}).items()):
                raise ValueError('Skip does not match build profile: ' + row['case'])
            skips.append({'case': row['case'], 'transport': mode, 'reason': row['skip_reason'],
                          'limitation': allowance['limitation']})
    if any(not count['passed'] for count in counts.values()):
        raise ValueError('No passing functional cases in a required transport')
    return {'status': 'passed', 'scope': 'Complete current-input functional selection for the declared build/environment profile; reviewed skips are unverified feature combinations and are never counted as passes.',
            'counts_by_transport': {mode: dict(count) for mode, count in counts.items()}, 'skips': skips}


def verify_current_inputs(report, build):
    provenance = report['provenance']
    if Path(provenance['build']).resolve() != build or provenance['cache_sha256'] != digest(build / 'CMakeCache.txt'):
        raise ValueError('Functional build configuration changed')
    manifest = json.loads((OWNED / 'manifest.json').read_text())
    sources = framework_sources(ROOT)
    for dest, source in manifest['replacements'].items():
        sources[dest] = OWNED / source
    for section in ('framework_copies', 'support_copies'):
        for dest, source in manifest.get(section, {}).items():
            sources[dest] = ROOT / 'test/functional' / source
    for dest, source in manifest.get('support_replacements', {}).items():
        sources[dest] = OWNED / source
    for dest, source in manifest['tests'].items():
        sources[dest] = OWNED / source
    for name in manifest['reused_tests']:
        sources[name] = ROOT / 'test/functional' / name
    current = {name: {'source': str(path.relative_to(ROOT)), 'sha256': digest(path)} for name, path in sources.items()}
    if current != provenance['files']:
        raise ValueError('Selected functional source/resource snapshot changed')
    for name, record in provenance['binaries'].items():
        if Path(record['path']).resolve() != build / 'bin' / name or digest(record['path']) != record['sha256']:
            raise ValueError('Functional binary changed: ' + name)
    runner = provenance['runner']
    if runner['source'] != 'test/pocx/test_runner.py' or digest(ROOT / runner['source']) != runner['sha256']:
        raise ValueError('Functional runner changed')
    return manifest


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--build-dir', type=Path, required=True)
    parser.add_argument('--jobs', type=int, default=4)
    parser.add_argument('--timeout', type=int, default=2400)
    parser.add_argument('--transport', choices=['v1', 'v2', 'matrix'], default='matrix')
    parser.add_argument('--report', type=Path, help='Verify an already complete owned report')
    parser.add_argument('--dependency-snapshot', type=Path, help='Required with --report: terminal run wrapper attesting external dependencies')
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    build = args.build_dir.resolve()
    if args.jobs < 1 or args.timeout < 1 or not build.is_relative_to(ROOT) or build == ROOT:
        parser.error('Invalid build/jobs/timeout')
    modes = ['v1', 'v2'] if args.transport == 'matrix' else [args.transport]
    output = args.output or (args.report.with_name('profile-verification.json') if args.report else None)
    if output:
        output.unlink(missing_ok=True)
    if args.report:
        if not args.dependency_snapshot:
            parser.error('--report requires --dependency-snapshot')
        snapshot = json.loads(args.dependency_snapshot.read_text())
        if snapshot.get('status') != 'terminal' or not snapshot.get('dependencies_unchanged'):
            raise ValueError('Missing terminal external-dependency attestation')
        report_path = args.report.resolve()
        if (ROOT / snapshot['report'] / 'results.json').resolve() != report_path:
            raise ValueError('External-dependency attestation belongs to another report')
        before = snapshot['dependencies_before']
    else:
        if args.dependency_snapshot:
            parser.error('--dependency-snapshot requires --report')
        before = dependency_hashes()
        command = [sys.executable, str(OWNED / 'test_runner.py'), '--build-dir', str(build),
                   '--jobs', str(args.jobs), '--timeout', str(args.timeout), '--transport', args.transport]
        reports = []
        execution = subprocess.Popen(command, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        for line in execution.stdout:
            print(line, end='', flush=True)
            if line.startswith('Results: '):
                reports.append(line.strip().removeprefix('Results: '))
        execution.wait()
        if len(reports) != 1:
            raise ValueError('Runner did not produce exactly one complete report')
        if execution.returncode not in (0, 1):
            raise ValueError('Abnormal functional runner exit')
        report_path = Path(reports[0]) / 'results.json'
    if before != dependency_hashes():
        raise ValueError('External functional source dependencies changed or were not fully recorded')
    report = json.loads(report_path.read_text())
    manifest = verify_current_inputs(report, build)
    expected = selected_cases(manifest, upstream_cases(ROOT / 'test/functional/test_runner.py'))
    policy_path = OWNED / 'functional-profile-skips.json'
    result = verify(report, expected, modes, json.loads(policy_path.read_text()), report['provenance']['build_options'])
    result.update(execution_report=str(report_path.relative_to(ROOT)),
                  execution_report_sha256=digest(report_path), policy_sha256=digest(policy_path),
                  external_dependencies=before)
    output = output or report_path.with_name('profile-verification.json')
    output.write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps({key: value for key, value in result.items() if key not in ('skips', 'external_dependencies')}, indent=2))
    return 0


if __name__ == '__main__':
    try:
        sys.exit(main())
    except (OSError, ValueError, KeyError, subprocess.SubprocessError) as error:
        print('Functional verification failed: ' + str(error), file=sys.stderr)
        sys.exit(1)
