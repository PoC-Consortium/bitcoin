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

import pocx_bootstrap as pocx_bootstrap
from common import ROOT, OWNED, build_options
from functional_cases import selected_cases, upstream_cases
from functional_results import transport_results
from stage import framework_sources
import functional_environment
import functional_execution
import build_configuration
import process_tree
import rpc_coverage


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def dependency_hashes():
    review = json.loads((OWNED / 'upstream-functional-parity.json').read_text())
    paths = {path for row in review['results'].values() for path in row.get('dependencies', {})}
    paths.update(review['execution_infrastructure']['sources'])
    return {path: digest(ROOT / path) for path in sorted(paths)}


def verify(report, expected_cases, modes, policy, build_options, require_no_skips=False):
    """Reject partial matrices, unexpected skips and failures without relabeling."""
    pairs = transport_results(report)
    if not rpc_coverage.verify(report):
        raise ValueError('RPC interface has uncovered commands')
    if report['provenance']['selected_cases'] != expected_cases or report['provenance']['transport_modes'] != modes:
        raise ValueError('Complete declared case/transport selection required')
    counts = {mode: Counter() for mode in modes}
    skips = []
    for mode, row in pairs:
        if 'retention_error' in row:
            raise ValueError('Functional database retention failed: ' + row['case'] + ' (' + mode + ')')
        counts[mode][row['status']] += 1
        if row['status'] == 'failed':
            raise ValueError('Functional failure: ' + row['case'] + ' (' + mode + ')')
        if row['status'] == 'skipped':
            if require_no_skips:
                raise ValueError('Required functional feature was skipped: ' + row['case'])
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
    cache = (build / 'CMakeCache.txt').read_text()
    build_configuration.require_source(cache, ROOT)
    selected_config = build_configuration.configuration(cache, provenance.get('build_configuration'))
    if Path(provenance['build']).resolve() != build or provenance['cache_sha256'] != digest(build / 'CMakeCache.txt'):
        raise ValueError('Functional build configuration changed')
    if provenance['build_options'] != build_options(cache):
        raise ValueError('Functional recorded features differ from the build configuration')
    manifest = json.loads((OWNED / 'manifest.json').read_text())
    sources = framework_sources(ROOT)
    for dest, source in manifest['replacements'].items():
        sources[dest] = OWNED / source
    for section in ('framework_copies', 'support_copies'):
        for dest, source in manifest.get(section, {}).items():
            sources[dest] = ROOT / 'test/functional' / source
    for section in ('framework_additions', 'support_replacements'):
        for dest, source in manifest.get(section, {}).items():
            sources[dest] = OWNED / source
    for dest, source in manifest['tests'].items():
        sources[dest] = OWNED / source
    for name in manifest['reused_tests']:
        sources[name] = ROOT / 'test/functional' / name
    current = {name: {'source': str(path.relative_to(ROOT)), 'sha256': digest(path)} for name, path in sources.items()}
    if current != provenance['files']:
        raise ValueError('Selected functional source/resource snapshot changed')
    paths = functional_execution.binary_paths(build, cache, selected_config)
    if provenance.get('format_version', 1) >= 8:
        if 'build_configuration' not in provenance:
            raise ValueError('Missing functional build configuration')
        required_helpers = ('test/pocx/stage.py', 'test/pocx/build_configuration.py',
                            'test/pocx/functional_execution.py', 'test/pocx/functional_environment.py',
                            'test/pocx/process_tree.py')
        if provenance.get('staging_helpers') != {name: digest(ROOT / name) for name in required_helpers}:
            raise ValueError('Missing or stale functional staging helper provenance')
        if not {'bitcoind', 'bitcoin-cli'}.issubset(provenance['binaries']):
            raise ValueError('Missing required functional binaries')
        if set(provenance['binaries']) != {name for name, path in paths.items() if path.is_file()}:
            raise ValueError('Functional executable inventory changed since execution')
    if provenance.get('format_version', 1) >= 9 and provenance.get('process_controller') != process_tree.description():
        raise ValueError('Missing or stale functional process controller provenance')
    for name, record in provenance['binaries'].items():
        if (name not in paths or Path(record['path']).resolve() != paths[name].resolve() or
                digest(record['path']) != record['sha256']):
            raise ValueError('Functional binary changed: ' + name)
    functional_execution.environment(provenance,
        {name: record['path'] for name, record in provenance['binaries'].items()}, provenance['build_options'])
    if provenance.get('format_version', 1) >= 5:
        profile = provenance['environment_profile']
        functional_environment.arguments('', profile)
        directory = provenance['previous_releases_directory']
        expected = functional_environment.release_binaries(directory) if profile['previous_releases'] else {}
        recorded = provenance['previous_release_binaries']
        if set(recorded) != set(expected) or any(
                Path(recorded[name]['path']).resolve() != path or digest(path) != recorded[name]['sha256']
                for name, path in expected.items()):
            raise ValueError('Previous-release binary inventory changed since functional execution')
        if not profile['previous_releases'] and directory is not None:
            raise ValueError('Disabled previous-release profile has an unexpected directory')
    runner = provenance['runner']
    if runner['source'] != 'test/pocx/test_runner.py' or digest(ROOT / runner['source']) != runner['sha256']:
        raise ValueError('Functional runner changed')
    return manifest


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--build-dir', type=Path, required=True)
    parser.add_argument('--config', help='Explicit CMake configuration, required for multi-config generators')
    parser.add_argument('--jobs', type=int, default=4)
    parser.add_argument('--timeout', type=int, default=2400)
    parser.add_argument('--timeout-factor', type=float)
    parser.add_argument('--transport', choices=['v1', 'v2', 'matrix'], default='matrix')
    parser.add_argument('--previous-releases', action='store_true')
    parser.add_argument('--usecli', action='store_true')
    parser.add_argument('--multiprocess', action='store_true')
    parser.add_argument('--previous-releases-dir', type=Path)
    parser.add_argument('--network-addresses', action='store_true')
    parser.add_argument('--require-no-skips', action='store_true',
                        help='Require every selected case to run, including optional feature cases')
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
        if (args.previous_releases or args.previous_releases_dir or args.network_addresses or
                args.timeout_factor is not None or args.usecli or args.multiprocess):
            parser.error('Existing reports retain their recorded prerequisite profile; omit prerequisite flags')
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
        if args.config is not None:
            command += ['--config', args.config]
        if args.previous_releases:
            command.append('--previous-releases')
        if args.usecli:
            command.append('--usecli')
        if args.multiprocess:
            command.append('--multiprocess')
        if args.previous_releases_dir:
            command += ['--previous-releases-dir', str(args.previous_releases_dir)]
        if args.network_addresses:
            command.append('--network-addresses')
        if args.timeout_factor is not None:
            command += ['--timeout-factor', str(args.timeout_factor)]
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
    if args.config is not None and report['provenance'].get('build_configuration') != args.config:
        raise ValueError('Requested functional configuration differs from recorded execution')
    manifest = verify_current_inputs(report, build)
    expected = selected_cases(manifest, upstream_cases(ROOT / 'test/functional/test_runner.py'))
    policy_path = OWNED / 'functional-profile-skips.json'
    result = verify(report, expected, modes, json.loads(policy_path.read_text()), report['provenance']['build_options'],
                    require_no_skips=args.require_no_skips)
    result['required_no_skips'] = args.require_no_skips
    result['timeout_factor'] = report['provenance'].get('timeout_factor', 1)
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
