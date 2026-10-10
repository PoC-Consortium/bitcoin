#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin PoCX developers
# Distributed under the MIT software license; see COPYING.
"""Strict original/native functional dispatch for inherited feature configurations.

Explicitly disabled features are recorded separately. Missing modules, binaries
or permissions for enabled features fail; an upstream green ALL row is not enough.
Both transports and all extended cases run on each side of the baseline pair.
"""
import ast
import argparse
from collections import Counter
import csv
import json
import math
import os
from pathlib import Path
import shlex
import subprocess
import sys
import time

from common import ROOT, sha256
from functional_cases import selected_cases, upstream_cases
from functional_results import transport_results
from run_bitcoin_functional import expected_cases, read_cases, effective_transport
import functional_execution
import build_configuration
import rpc_coverage
from verify_functional import verify_current_inputs, dependency_hashes

GUARDS = {
    'skip_if_no_wallet': 'ENABLE_WALLET', 'skip_if_no_wallet_tool': 'BUILD_WALLET_TOOL',
    'skip_if_no_bitcoin_tx': 'BUILD_TX', 'skip_if_no_bitcoin_util': 'BUILD_UTIL',
    'skip_if_no_bitcoin_chainstate': 'BUILD_UTIL_CHAINSTATE', 'skip_if_no_bitcoin_bench': 'BUILD_BENCH',
    'skip_if_no_cli': 'BUILD_CLI', 'skip_if_no_ipc': 'ENABLE_IPC',
    'skip_if_no_bitcoind_tracepoints': 'WITH_USDT', 'skip_if_no_bitcoind_zmq': 'WITH_ZMQ',
    'skip_if_no_external_signer': 'ENABLE_EXTERNAL_SIGNER',
}
PREVIOUS = {'feature_coinstatsindex_compatibility.py', 'feature_unsupported_utxo_db.py',
            'mempool_compatibility.py', 'wallet_backwards_compatibility.py', 'wallet_migration.py'}
ADDRESS = {'feature_bind_port_discover.py', 'feature_bind_port_externalip.py'}
LEGACY_UTXO = 'feature_unsupported_utxo_db.py'


def original_inventory(source, benchmarks, bench_enabled):
    if type(bench_enabled) is not bool: raise ValueError('Missing explicit benchmark feature')
    if bench_enabled: return expected_cases(source, benchmarks)
    if benchmarks: raise ValueError('Disabled benchmark feature has an executed benchmark inventory')
    # Upstream expands the dynamic script only when benchmarks are compiled.
    # Keep its unexpanded, source-guarded skip in an explicitly disabled build.
    return [row['upstream_case'] for row in upstream_cases(source)]


def original_groups(expected, options):
    if options.get('target_system') != 'Windows': return [('complete', expected, False)]
    if expected.count(LEGACY_UTXO) != 1:
        raise ValueError('Windows selection must retain the original old-release UTXO case exactly once')
    return [('complete', [case for case in expected if case != LEGACY_UTXO], False),
            ('legacy-utxo', [LEGACY_UTXO], True)]


def original_command(build, output, group, mode, jobs, factor, profile, *, windows=False):
    name, _, direct = group
    common = ['--timeout-factor=' + str(factor), '--' + mode + 'transport']
    if profile['use_cli']: common.append('--usecli')
    if profile['previous_releases']: common.append('--previous-releases')
    if direct:
        directory = (output / ('legacy-utxo-' + mode)).resolve()
        if not str(directory).isascii():
            raise ValueError('Ancient Windows release requires an ASCII-only data directory')
        return [sys.executable, str(build / 'test/functional' / LEGACY_UTXO),
            '--configfile=' + str(build / 'test/config.ini'), '--tmpdir=' + str(directory),
            '--cachedir=' + str(build / 'test/cache'), '--portseed=0', '--randomseed=0', *common]
    command = [sys.executable, str(build / 'test/functional/test_runner.py'), '--jobs=' + str(jobs),
        '--extended', '--resultsfile=' + str(output / (mode + '.csv')),
        '--tmpdirprefix=' + str(output / mode), '--combinedlogslen=100', *common]
    if name != 'complete': raise ValueError('Unknown original functional group')
    if profile.get('coverage'): command.append('--coverage')
    if windows: command.append('--exclude=' + LEGACY_UTXO)
    return command


def native_command(build, jobs, factor, profile, environment, selected_config=None):
    command = [sys.executable, str(ROOT / 'test/pocx/test_runner.py'), '--build-dir', str(build),
               '--jobs', str(jobs), '--transport', 'matrix', '--timeout-factor', str(factor),
               '--timeout', str(math.ceil(2400 * factor))]
    if selected_config is not None: command += ['--config', selected_config]
    if profile.get('coverage'): command.append('--coverage')
    for key, flag in (('use_cli', '--usecli'), ('multiprocess', '--multiprocess'),
                      ('previous_releases', '--previous-releases')):
        if profile[key]: command.append(flag)
    if profile['previous_releases']:
        command += ['--previous-releases-dir', environment['PREVIOUS_RELEASES_DIR']]
    return command


def inherited_options(environment):
    extra = shlex.split(environment.get('TEST_RUNNER_EXTRA', ''))
    allowed = {'--v1transport', '--v2transport', '--usecli', '--extended', '--previous-releases', '--coverage'}
    factors = []
    extended_selection = []
    index = 0
    while index < len(extra):
        argument = extra[index]
        if argument == '--timeout-factor':
            index += 1
            if index == len(extra):raise ValueError('Missing inherited functional timeout factor')
            factors.append(extra[index])
        elif argument.startswith('--timeout-factor='):
            factors.append(argument.split('=', 1)[1])
        elif argument == '--exclude':
            index += 1
            if index == len(extra) or extra[index] != 'feature_dbcrash':
                raise ValueError('Unreviewed inherited functional exclusion')
            extended_selection.append('feature_dbcrash.py')
        elif argument == '--exclude=feature_dbcrash':
            extended_selection.append('feature_dbcrash.py')
        elif argument not in allowed:
            raise ValueError('Unreviewed inherited functional argument: ' + argument)
        index += 1
    if len(factors) > 1:
        raise ValueError('Duplicate inherited functional timeout factors')
    factor = None
    if factors:
        try:factor = float(factors[0])
        except ValueError as error:raise ValueError('Invalid inherited functional timeout factor') from error
        if not math.isfinite(factor) or factor <= 0:raise ValueError('Invalid inherited functional timeout factor')
    wrapper = shlex.split(environment.get('BITCOIN_CMD', ''))
    if wrapper not in ([], ['bitcoin', '-m']):
        raise ValueError('Unreviewed inherited BITCOIN_CMD; expected bitcoin -m')
    return {'use_cli': '--usecli' in extra, 'multiprocess': bool(wrapper),
            'previous_releases': '--previous-releases' in extra or
                                 environment.get('DOWNLOAD_PREVIOUS_RELEASES') == 'true',
            'network_addresses': False, 'transports': ['v1', 'v2'], 'extended': True,
            'inherited_arguments': extra, 'timeout_factor': factor,
            'coverage': '--coverage' in extra,
            'selection_extensions': extended_selection}


def disabled_reason(name, options, profile, *, native=False, root=ROOT):
    if name in PREVIOUS and not profile['previous_releases']:
        return 'Previous-release execution explicitly disabled by this profile; required in the optional profile'
    if name in ADDRESS and not profile['network_addresses']:
        return 'Special-address execution explicitly disabled by this profile; required in the optional profile'
    path = root / ('test/pocx/functional' if native else 'test/functional') / name
    if not path.is_file() and native:
        path = root / 'test/functional' / name
    if not path.is_file():
        raise ValueError('Missing reviewed functional source: ' + name)
    guards = set()
    for cls in ast.parse(path.read_text()).body:
        if not isinstance(cls, ast.ClassDef):
            continue
        for method in cls.body:
            if not isinstance(method, ast.FunctionDef) or method.name != 'skip_test_if_missing_module':
                continue
            # Only unconditional direct guards justify a build-feature omission.
            for node in method.body:
                call = node.value if isinstance(node, ast.Expr) else None
                if (isinstance(call, ast.Call) and isinstance(call.func, ast.Attribute) and
                        isinstance(call.func.value, ast.Name) and call.func.value.id == 'self' and
                        not call.args and not call.keywords):
                    guards.add(call.func.attr)
    reasons = [f'{GUARDS[guard]}=OFF' for guard in sorted(guards & GUARDS.keys())
               if options.get(GUARDS[guard]) == 'OFF']
    if reasons:
        return ', '.join(reasons) + '; unconditional guard in ' + str(path.relative_to(root))
    if 'skip_if_platform_not_linux' in guards and options.get('target_system') != 'Linux':
        return 'Original tracing guard requires Linux; target is ' + options['target_system']
    return None


def classify(case, status, options, profile, *, native=False, root=ROOT):
    if status in ('passed', 'Passed'):
        return 'passed', ''
    if status in ('skipped', 'Skipped'):
        reason = disabled_reason(shlex.split(case)[0], options, profile, native=native, root=root)
        return ('configuration-disabled', reason) if reason else ('unverified', 'Unexpected skip or missing enabled prerequisite')
    return 'failed', 'Functional process failed or timed out'


def run(build, output, options, jobs, factor, *, environment=None, selected_config=None):
    if type(jobs) is not int or jobs < 1: raise ValueError('Expected positive functional job count')
    env = dict(os.environ if environment is None else environment)
    profile = inherited_options(env)
    factor = profile['timeout_factor'] if profile['timeout_factor'] is not None else factor
    if type(factor) not in (int, float) or not math.isfinite(factor) or factor <= 0 or not math.isfinite(2400 * factor):
        raise ValueError('Inherited functional timeout factor must be finite and positive')
    profile['effective_timeout_factor'] = factor
    cache = (build / 'CMakeCache.txt').read_text()
    selected_config = build_configuration.configuration(cache, selected_config)
    paths = functional_execution.binary_paths(build, cache, selected_config)
    env = {key: value for key, value in env.items() if key not in {*functional_execution.BINARY_ENVIRONMENT.values(), 'BITCOIN_CMD', 'PYTHONPATH'}}
    env['PYTHONDONTWRITEBYTECODE'] = '1'
    if not profile['previous_releases']:
        env['PREVIOUS_RELEASES_DIR'] = str(build / 'previous-releases-disabled')
        if Path(env['PREVIOUS_RELEASES_DIR']).exists():
            raise ValueError('Disabled previous-release profile directory must not exist')
    env.update(functional_execution.binary_environment(paths, env.get('PATH', os.defpath)))
    env.update(functional_execution.environment(
        {'format_version':7,'execution_options':functional_execution.settings(profile['use_cli'], profile['multiprocess'])},
        {name:path for name,path in paths.items() if path.is_file()}, options))
    native = options['ENABLE_POCX'] == 'ON'
    output.mkdir(parents=True, exist_ok=False)
    dependencies = dependency_hashes()
    report = {'status': 'running', 'scope': 'Inherited applicable functional selection; disabled profile features remain required in their enabled configurations',
              'profile': profile, 'build_options': options, 'build_configuration': selected_config,
              'cases': [], 'runs': [], 'native': native}
    def save():
        report['counts'] = dict(Counter(row['status'] for row in report['cases']))
        (output / 'results.json').write_text(json.dumps(report, indent=2) + '\n')
        with (output / 'cases.csv').open('w', newline='') as stream:
            writer = csv.DictWriter(stream, fieldnames=['case', 'transport', 'effective_transport', 'status',
                                                        'reason', 'execution_status', 'seconds'])
            writer.writeheader(); writer.writerows(report['cases'])
    def execute(name, command, child_env):
        log = output / (name + '.log')
        start = time.monotonic()
        with log.open('w') as stream:
            result = subprocess.run(command, env=child_env, cwd=ROOT, stdout=stream, stderr=subprocess.STDOUT)
        report['runs'].append({'name': name, 'command': command, 'returncode': result.returncode,
                               'seconds': time.monotonic() - start, 'log_sha256': sha256(log)})
        save()
        return result, log
    save()
    try:
        if native:
            command = native_command(build, jobs, factor, profile, env, selected_config)
            result, log = execute('native', command, env)
            import re
            paths = re.findall(r'^Results: (.+)$', log.read_text(), re.MULTILINE)
            if len(paths) != 1:
                raise ValueError('Native runner did not retain exactly one complete report')
            proof_path = Path(paths[0]) / 'results.json'
            proof = json.loads(proof_path.read_text())
            manifest = verify_current_inputs(proof, build)
            expected = selected_cases(manifest, upstream_cases(ROOT / 'test/functional/test_runner.py'))
            if (proof['provenance']['selected_cases'] != expected or
                    proof['provenance']['transport_modes'] != ['v1', 'v2']):
                raise ValueError('Incomplete native functional matrix')
            if (proof['provenance'].get('build_configuration') != selected_config or
                    proof['provenance'].get('timeout_factor', 1) != factor):
                raise ValueError('Native functional configuration or timing differs from inherited invocation')
            if (functional_execution.recorded(proof['provenance']) !=
                    functional_execution.settings(profile['use_cli'], profile['multiprocess']) or
                    proof['provenance']['environment_profile'] !=
                    {'previous_releases': profile['previous_releases'], 'network_addresses': profile['network_addresses']}):
                raise ValueError('Native functional execution differs from inherited profile')
            report['expected_cases'] = [case['id'] for case in expected]
            executed = transport_results(proof)
            coverage_passed = rpc_coverage.verify(proof)
            if profile['coverage'] != (proof['provenance'].get('rpc_coverage') is True):
                raise ValueError('Native RPC coverage request differs from inherited profile')
            for mode, row in executed:
                state, reason = classify(row['case'], row['status'], options, profile, native=True)
                report['cases'].append({'case': row['case'], 'transport': mode, 'effective_transport': mode,
                                        'status': state, 'reason': reason, 'execution_status': row['status'],
                                        'seconds': row['seconds']})
            report['native_proof'] = {'path': str(proof_path), 'sha256': sha256(proof_path)}
            expected_exit = 0 if all(row['status'] == 'passed' for _, row in executed) and coverage_passed else 1
            if result.returncode != expected_exit:
                raise ValueError('Native functional exit status differs from its case results')
            if not coverage_passed:
                raise ValueError('Native RPC interface has uncovered commands')
            # The owned runner is intentionally strict: even a reviewed feature
            # skip returns1. The inherited profile keeps those rows explicitly
            # configuration-disabled. Failures and missing enabled prerequisites
            # are rejected by the case counts below, never waived by this exit.
        else:
            if options.get('BUILD_BENCH') not in ('ON', 'OFF'):
                raise ValueError('Missing explicit inherited benchmark feature')
            benchmarks = []
            if options['BUILD_BENCH'] == 'ON':
                command = [str(paths['bench_bitcoin']), '-list']
                listing = subprocess.check_output(command, env=env, cwd=ROOT, text=True)
                benchmarks = listing.splitlines()
                log = output / 'benchmarks.log'; log.write_text(listing)
                report['benchmark_discovery'] = {'command': command, 'log_sha256': sha256(log)}
            report['benchmarks'] = benchmarks
            expected = original_inventory(ROOT / 'test/functional/test_runner.py', benchmarks, options['BUILD_BENCH'] == 'ON')
            report['expected_cases'] = expected
            for mode in profile['transports']:
                for group in original_groups(expected, options):
                    command = original_command(build, output, group, mode, jobs, factor, profile,
                                               windows=options.get('target_system') == 'Windows')
                    result, _ = execute(mode if not group[2] else mode + '-legacy-utxo', command, env)
                    if group[2]:
                        status = 'Passed' if result.returncode == 0 else 'Skipped' if result.returncode == 77 else 'Failed'
                        rows = [(LEGACY_UTXO, status, report['runs'][-1]['seconds'])]
                    else:
                        rows, summary = read_cases(output / (mode + '.csv'), group[1])
                    for case, status, duration in rows:
                        state, reason = classify(case, status, options, profile)
                        report['cases'].append({'case': case, 'transport': mode,
                                                'effective_transport': effective_transport(case, mode), 'status': state,
                                                'reason': reason, 'execution_status': status, 'seconds': float(duration)})
                    # Preserve actual case results before rejecting a failed
                    # aggregate/exit. A red first transport must not erase its
                    # passes, failures or explicitly disabled feature rows.
                    save()
                    if not group[2] and (result.returncode != 0 or summary[1] != 'Passed'):
                        raise ValueError('Original functional runner failed')
        counts = Counter(row['status'] for row in report['cases'])
        report['counts'] = dict(counts)
        if not counts['passed'] or counts['failed'] or counts['unverified']:
            raise ValueError('Required applicable functional cases failed or remain unverified')
        if dependencies != dependency_hashes():
            raise ValueError('External functional dependencies changed during inherited execution')
        report['external_dependencies'] = dependencies
        report['status'] = 'passed'
    except Exception as error:
        if not native:
            recorded = {(row['case'], row['transport']) for row in report['cases']}
            for mode in profile['transports']:
                for case in report.get('expected_cases', []):
                    if (case, mode) not in recorded:
                        report['cases'].append({'case': case, 'transport': mode,
                            'effective_transport': effective_transport(case, mode), 'status': 'unverified',
                            'reason': 'No valid execution evidence retained after original runner failure',
                            'execution_status': 'unverified', 'seconds': 0.0})
        report.update(status='failed', error=str(error))
        save()
        raise
    save()
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--build-dir', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--jobs', type=int, default=4)
    parser.add_argument('--timeout-factor', type=float, default=40)
    parser.add_argument('--config')
    args = parser.parse_args()
    build = args.build_dir.resolve()
    if build == ROOT or not build.is_relative_to(ROOT): parser.error('Use a separate runtime directory inside this worktree')
    cache = (build / 'CMakeCache.txt').read_text()
    build_configuration.require_source(cache, ROOT)
    import unit_matrix
    from check_drift import check
    if check(ROOT): raise ValueError('Inherited functional source review failed')
    options, _ = unit_matrix.configuration(build)
    run(build, args.output.resolve(), options, args.jobs, args.timeout_factor, selected_config=args.config)


if __name__ == '__main__':
    main()
