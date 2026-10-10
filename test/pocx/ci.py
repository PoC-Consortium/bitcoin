#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin PoCX developers
# Distributed under the MIT software license; see COPYING.
"""Reproducible Linux CI profiles; required failures always propagate.

Profiles run complete selections, not the seven-suite M1 demonstration. Each
invocation owns an isolated build directory. --skip-build uses an existing build
only after checking its source and configuration. No command updates provenance.
"""
import argparse
import configparser
import fcntl
import json
import os
from pathlib import Path
import re
import resource
import shutil
import subprocess
import sys
import tempfile
import time

sys.dont_write_bytecode = True
from stage import ROOT, build_options, sha256, short_tmpdir
from ci_evidence import artifact_paths, build_snapshot, require_unchanged, source_snapshot, verify_report

PROFILES = ('drift', 'bitcoin-unit', 'bitcoin-functional', 'bitcoin-qt', 'bitcoin-kernel',
            'bitcoin-functional-optional', 'pocx-functional-optional',
            'bitcoin-asan', 'pocx-asan',
            'bitcoin-tsan', 'pocx-tsan', 'bitcoin-msan', 'pocx-msan',
            'bitcoin-wallet-disabled', 'bitcoin-ipc-disabled',
            'pocx-unit', 'pocx-functional', 'pocx-qt', 'pocx-wallet-disabled',
            'pocx-ipc-disabled', 'pocx-kernel', 'pocx-real-proof')


def stage_bitcoin_functional(build, output, *, network_addresses=False):
    """Snapshot original Bitcoin tests; explicitly attest optional shared fixture fixes."""
    tree = output / 'bitcoin-functional'
    tests = tree / 'test/functional'
    shutil.copytree(ROOT / 'test/functional', tests,
                    ignore=shutil.ignore_patterns('__pycache__', '*.pyc'))
    # The unchanged upstream runner launches scripts from BUILDDIR/test/functional,
    # not its own directory. A private build view makes the attested copies
    # (including the two reviewed address corrections) the executed scripts.
    # Only executable/library directories point back to the actual build.
    for name in ('bin', 'lib'):
        (tree / name).symlink_to(build / name, target_is_directory=True)
    config = configparser.ConfigParser()
    config.read(build / 'test/config.ini')
    config['environment']['BUILDDIR'] = str(tree)
    with (tree / 'test/config.ini').open('w') as stream:
        config.write(stream)
    replacements = []
    if network_addresses:
        review = json.loads((ROOT / 'test/pocx/bitcoin_baseline/review.json').read_text())
        parity = json.loads((ROOT / 'test/pocx/upstream-functional-parity.json').read_text())
        expected = {'feature_bind_port_discover.py', 'feature_bind_port_externalip.py'}
        if set(review['cases']) != expected:
            raise ValueError('Incomplete shared Bitcoin address fixture review')
        for name, row in review['cases'].items():
            original = ROOT / row['source']
            corrected = ROOT / row['replacement']
            canonical = parity['results'][name]
            if (row['source'] != f'test/functional/{name}' or
                    row['replacement'] != f'test/pocx/bitcoin_baseline/{name}' or
                    row['source_sha256'] != sha256(original) or
                    row['replacement_sha256'] != sha256(corrected) or
                    canonical['replacement_sha256'] != sha256(corrected)):
                raise ValueError('Unreviewed shared Bitcoin address fixture: ' + name)
            shutil.copyfile(corrected, tests / name)
            replacements.append(row)
    files = {str(path.relative_to(tree)): sha256(path) for path in sorted((tree / 'test').rglob('*')) if path.is_file()}
    (tree / 'provenance.json').write_text(json.dumps({
        'scope': 'Bitcoin original functional tree/runner with individually attested shared fixture corrections only when requested; raw upstream failures remain separately reported',
        'replacements': replacements, 'files': files,
        'build_view': str(tree), 'binary_build': str(build),
    }, indent=2) + '\n')
    return tests / 'test_runner.py'


def options(profile, instrumented_directory=None):
    qt = profile.endswith('-qt')
    result = {
        'ENABLE_POCX': 'OFF' if profile.startswith('bitcoin-') else 'ON',
        'CMAKE_BUILD_TYPE': 'Release',
        'BUILD_TESTS': 'ON',
        'BUILD_GUI': 'ON' if qt else 'OFF',
        'BUILD_BENCH': 'OFF',
        'BUILD_FUZZ_BINARY': 'OFF',
        'BUILD_FOR_FUZZING': 'OFF',
        'ENABLE_WALLET': 'OFF' if profile.endswith('-wallet-disabled') else 'ON',
        'ENABLE_IPC': 'OFF' if profile.endswith('-ipc-disabled') else 'ON',
        'BUILD_KERNEL_LIB': 'ON' if profile.endswith('-kernel') else 'OFF',
        'WITH_ZMQ': 'OFF', 'WITH_USDT': 'OFF',
        'SANITIZERS': '',
    }
    if profile.endswith('-functional-optional'):
        result.update(BUILD_BENCH='ON', BUILD_UTIL_CHAINSTATE='ON', BUILD_KERNEL_LIB='ON',
                      WITH_ZMQ='ON', WITH_USDT='ON', BUILD_DAEMON='ON', BUILD_CLI='ON',
                      BUILD_BITCOIN_BIN='ON', BUILD_TX='ON', BUILD_UTIL='ON', BUILD_WALLET_TOOL='ON')
    if profile.endswith('-asan'):
        from sanitizer_ci import required_options
        result.update(required_options())
    if profile.endswith(('-tsan', '-msan')):
        from instrumented_ci import required_options
        if instrumented_directory is None:
            raise ValueError('Instrumented dependency preparation directory is required')
        result.update(required_options(profile.rsplit('-', 1)[1], instrumented_directory))
    return result


def validate_build(build, profile, instrumented_directory=None):
    cache = (build / 'CMakeCache.txt').read_text()
    if f'CMAKE_HOME_DIRECTORY:INTERNAL={ROOT}\n' not in cache:
        raise ValueError('Build belongs to a different source worktree')
    actual = build_options(cache)
    # Extra optional libraries do not invalidate existing profiles. The required
    # consensus, wallet, test and sanitizer settings must still match exactly.
    required = ['ENABLE_POCX', 'ENABLE_WALLET', 'BUILD_TESTS', 'ENABLE_IPC',
                'BUILD_FOR_FUZZING', 'BUILD_FUZZ_BINARY', 'CMAKE_BUILD_TYPE', 'SANITIZERS']
    if profile.endswith('-qt'):
        required += ['BUILD_GUI', 'BUILD_GUI_TESTS']
    if profile.endswith('-kernel'):
        required += ['BUILD_KERNEL_LIB', 'BUILD_KERNEL_TEST']
    if profile.endswith('-functional-optional'):
        required += ['BUILD_BENCH', 'BUILD_UTIL_CHAINSTATE', 'BUILD_KERNEL_LIB',
                     'WITH_ZMQ', 'WITH_USDT', 'BUILD_DAEMON', 'BUILD_CLI',
                     'BUILD_BITCOIN_BIN', 'BUILD_TX', 'BUILD_UTIL', 'BUILD_WALLET_TOOL']
    if profile.endswith('-asan'):
        from sanitizer_ci import required_options
        required += [key for key in required_options() if key not in ('CMAKE_C_COMPILER', 'CMAKE_CXX_COMPILER')]
    if profile.endswith(('-tsan', '-msan')):
        from instrumented_ci import required_options
        required += [key for key in required_options(profile.rsplit('-', 1)[1], instrumented_directory)
                     if key not in ('CMAKE_C_COMPILER', 'CMAKE_CXX_COMPILER')]
    expected = {**options(profile, instrumented_directory), 'BUILD_KERNEL_TEST': 'ON'}
    expected.setdefault('BUILD_GUI_TESTS', 'ON')
    mismatch = {key: {'expected': expected[key], 'actual': actual.get(key)}
                for key in required if actual.get(key, '' if key == 'SANITIZERS' else None) != expected[key]}
    if mismatch:
        raise ValueError(f'Wrong CI build profile: {mismatch}')
    if profile.endswith('-asan'):
        from sanitizer_ci import tools
        toolchain = tools()
        for key in ('CMAKE_C_COMPILER', 'CMAKE_CXX_COMPILER'):
            if not actual.get(key) or Path(actual[key]).resolve() != Path(toolchain[expected[key]]['path']).resolve():
                raise ValueError('Wrong CI sanitizer compiler: ' + key)
    if profile.endswith(('-tsan', '-msan')):
        from instrumented_ci import tools
        toolchain = tools(profile.rsplit('-', 1)[1])
        for key in ('CMAKE_C_COMPILER', 'CMAKE_CXX_COMPILER'):
            if not actual.get(key) or Path(actual[key]).resolve() != Path(toolchain[expected[key]]['path']).resolve():
                raise ValueError('Wrong CI instrumented compiler: ' + key)
    return cache


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--profile', choices=PROFILES, required=True)
    parser.add_argument('--build-dir', type=Path, help='default: build-ci-PROFILE inside this worktree')
    parser.add_argument('--jobs', type=int, default=4)
    parser.add_argument('--skip-build', action='store_true', help='validate and test an existing build')
    parser.add_argument('--transport', choices=['v1', 'v2', 'matrix'],
                        help='PoCX functional transport selection (default: matrix)')
    parser.add_argument('--previous-releases-dir', type=Path,
                        help='Verified historical binaries; required for optional functional profiles')
    parser.add_argument('--instrumented-dependencies-dir', type=Path,
                        help='Verified prepared libc++/depends; required only for TSAN/MSAN profiles')
    args = parser.parse_args()
    if args.jobs < 1:
        parser.error('jobs must be positive')
    asan = args.profile.endswith('-asan')
    instrumented = args.profile.endswith(('-tsan', '-msan'))
    sanitizer = asan or instrumented
    kind = args.profile.rsplit('-', 1)[1] if sanitizer else None
    optional = args.profile.endswith('-functional-optional') or sanitizer
    if args.transport and args.profile not in ('pocx-functional', 'pocx-functional-optional', 'pocx-asan', 'pocx-tsan', 'pocx-msan'):
        parser.error('--transport requires the pocx-functional profile')
    if optional and args.transport not in (None, 'matrix'):
        parser.error('Required optional functional profiles must execute both transports')
    if optional != bool(args.previous_releases_dir):
        parser.error('--previous-releases-dir is required only for optional functional profiles')
    if instrumented != bool(args.instrumented_dependencies_dir):
        parser.error('--instrumented-dependencies-dir is required only for TSAN/MSAN profiles')
    dependency_directory = args.instrumented_dependencies_dir.resolve() if instrumented else None
    if instrumented and (not dependency_directory.is_relative_to(ROOT) or dependency_directory == ROOT):
        parser.error('Instrumented dependencies must belong to this worktree')
    build = (args.build_dir or ROOT / f'build-ci-{args.profile}').resolve()
    if build == ROOT or not build.is_relative_to(ROOT):
        parser.error('Use a separate build directory inside this source worktree')
    build.mkdir(parents=True, exist_ok=True)
    lock = (build / 'pocx-ci.lock').open('w')
    fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    output = Path(tempfile.mkdtemp(prefix='ci-results-', dir=build))
    report = {'format': 1, 'profile': args.profile, 'source': str(ROOT), 'build': str(build),
              'revision': subprocess.check_output(['git', '-C', str(ROOT), 'rev-parse', 'HEAD'], text=True).strip(),
              'skip_build': args.skip_build, 'status': 'running', 'steps': [], 'artifacts': {}}
    env = {key: value for key, value in os.environ.items() if not key.startswith('BOOST_TEST_') and key not in {
        'PYTHONPATH', 'BITCOIN_CMD', 'BITCOIND', 'BITCOINCLI', 'BITCOIN_BIN',
        'BITCOIN_BENCH', 'BITCOINUTIL', 'BITCOINTX', 'BITCOINCHAINSTATE', 'BITCOINWALLET',
        'FUZZ', 'PRINT_ALL_FUZZ_TARGETS_AND_ABORT', 'WRITE_ALL_FUZZ_TARGETS_AND_ABORT'}}
    # Short paths also preserve Unix-domain IPC socket length limits.
    temp = short_tmpdir(build)
    config_home = output / 'qt-config'
    config_home.mkdir()
    report['tmpdir'] = str(temp)
    env.update(TMPDIR=str(temp), PYTHONDONTWRITEBYTECODE='1',
               QT_QPA_PLATFORM='minimal', XDG_CONFIG_HOME=str(config_home))

    def save():
        (output / 'results.json').write_text(json.dumps(report, indent=2) + '\n')

    def run(name, command):
        print(f'{name}: running; log: {output / (name + ".log")}', flush=True)
        start = time.monotonic()
        step = {'name': name, 'command': list(map(str, command)), 'status': 'running'}
        report['steps'].append(step)
        result_prefixes = ('pocx-unit-', 'bitcoin-unit-', 'pocx-results-')
        old_results = {path for path in build.iterdir() if path.is_dir() and path.name.startswith(result_prefixes)}
        save()
        with (output / f'{name}.log').open('w') as log:
            result = subprocess.run(step['command'], cwd=ROOT, env=env, stdout=log, stderr=subprocess.STDOUT)
        step.update(returncode=result.returncode, seconds=time.monotonic() - start,
                    status='passed' if result.returncode == 0 else 'failed',
                    log_sha256=sha256(output / f'{name}.log'))
        new_results = {path for path in build.iterdir() if path.is_dir() and path.name.startswith(result_prefixes)} - old_results
        # Freeze child proof and framework outputs immediately after each step.
        # Do not include the outer report itself, which is still being written.
        for directory in [output, *sorted(new_results)]:
            for path in artifact_paths(directory):
                if path != output / 'results.json':
                    report['artifacts'].setdefault(str(path), sha256(path))
        save()
        print(f'{name}: {step["status"]} ({result.returncode})', flush=True)
        return result.returncode == 0

    try:
        report['source_snapshot'] = source_snapshot(ROOT)
        save()
        # Gate reviewed inputs before spending build time. Keep drift in every
        # profile; a passing runtime test cannot approve an upstream change.
        if not run('drift', [sys.executable, ROOT / 'test/pocx/check_drift.py', '--output', output / 'drift.json']):
            report['status'] = 'failed'
            return 1
        if args.profile == 'drift':
            report['status'] = 'passed'
            report['execution_verification'] = verify_report(ROOT, report, output)
            return 0
        if asan:
            from sanitizer_ci import runtime_environment
            report['sanitizer_environment'] = runtime_environment()
            env.update(report['sanitizer_environment'])
            if not run('sanitizer-tools', [sys.executable, ROOT / 'test/pocx/sanitizer_ci.py',
                                         '--check-tools', '--output', output / 'sanitizer-tools.json']):
                report['status'] = 'failed'
                return 1
        if instrumented:
            helper = ROOT / 'test/pocx/instrumented_ci.py'
            report['instrumented_dependencies_directory'] = str(dependency_directory)
            if not run('sanitizer-tools', [sys.executable, helper, '--sanitizer', kind,
                                          '--check-tools', '--output', output / 'sanitizer-tools.json']):
                report['status'] = 'failed'
                return 1
            if not run('sanitizer-dependencies', [sys.executable, helper, '--sanitizer', kind,
                       '--verify-dependencies', '--directory', dependency_directory,
                       '--output', output / 'sanitizer-dependencies.json']):
                report['status'] = 'failed'
                return 1
            from instrumented_ci import runtime_environment
            report['sanitizer_environment'] = runtime_environment(kind, dependency_directory)
            env.update(report['sanitizer_environment'])
        if (args.profile.endswith(('-unit', '-wallet-disabled', '-ipc-disabled')) or
                args.profile == 'pocx-real-proof' or sanitizer):
            from unit_assets import provision
            report['external_script_assets'] = provision(build / 'unit_test_data')
            env['DIR_UNIT_TEST_DATA'] = report['external_script_assets']['directory']
            save()
        if not args.skip_build:
            configure = ['cmake', '-S', str(ROOT), '-B', str(build), '-G', 'Ninja']
            configure += [f'-D{key}={value}' for key, value in options(args.profile, dependency_directory).items()]
            if sanitizer:
                configure.append('-Werror=dev')
            if not run('configure', configure):
                report['status'] = 'failed'
                return 1
            command = ['cmake', '--build', str(build), '-j', str(args.jobs)]
            if args.profile.endswith('-qt'):
                command += ['--target', 'test_bitcoin-qt']
            if not run('build', command):
                report['status'] = 'failed'
                return 1
        cache = validate_build(build, args.profile, dependency_directory)
        report.update(cache_sha256=sha256(build / 'CMakeCache.txt'), build_options=build_options(cache))
        report['binaries'] = {str(path.relative_to(build)): sha256(path) for path in sorted((build / 'bin').glob('*')) if path.is_file()}
        require_unchanged('Source inputs', report['source_snapshot'], source_snapshot(ROOT))
        report['execution_build_snapshot'] = build_snapshot(build)
        save()
        # Real-proof kernel API cases revalidate blocks on every disk read.
        kernel_enabled = all(report['build_options'].get(key) == 'ON'
                             for key in ('BUILD_KERNEL_LIB', 'BUILD_KERNEL_TEST'))
        ctest_timeout = '2400' if sanitizer else '900' if kernel_enabled else '180'
        ctest = ['ctest', '--test-dir', str(build), '-j', str(args.jobs), '--output-on-failure',
                 '--timeout', ctest_timeout, '--no-tests=error']
        commands = []
        if sanitizer:
            # Match upstream CI_LIMIT_STACK_SIZE for every sanitizer runtime.
            stack_limit = 512 * 1024
            _, hard = resource.getrlimit(resource.RLIMIT_STACK)
            resource.setrlimit(resource.RLIMIT_STACK, (stack_limit, hard))
            report['sanitizer_stack_limit'] = resource.getrlimit(resource.RLIMIT_STACK)[0]
            if instrumented:
                gate = [sys.executable, ROOT / 'test/pocx/instrumented_ci.py', '--sanitizer', kind,
                        '--directory', dependency_directory, '--build-dir', build,
                        '--output', output / 'sanitizer/verification.json']
            else:
                gate = [sys.executable, ROOT / 'test/pocx/sanitizer_ci.py',
                        '--build-dir', build, '--output', output / 'sanitizer/verification.json']
            if not run('sanitizer', gate):
                report['status'] = 'failed'
                return 1
            bitcoin = args.profile.startswith('bitcoin-')
            unit_script = 'run_bitcoin_unit.py' if bitcoin else 'run_unit.py'
            unit = [sys.executable, ROOT / 'test/pocx' / unit_script,
                    '--build-dir', build, '--jobs', str(args.jobs), '--timeout', '2400']
            if not bitcoin:
                unit.append('--all')
            commands.append(('unit', unit))
            registered = json.loads(subprocess.check_output(['ctest', '--test-dir', str(build), '--show-only=json-v1'], text=True))['tests']
            unit_binary = str(build / 'bin' / ('test_bitcoin' if bitcoin else 'test_pocx'))
            other = sorted(test['name'] for test in registered
                           if test.get('command', [''])[0] != unit_binary and
                           test['name'] not in ('test_kernel', 'test_bitcoin-qt'))
            if not other:
                raise ValueError('Missing sanitizer auxiliary library CTest registrations')
            report['auxiliary_tests'] = other
            commands.append(('auxiliary', ctest + ['-R', '^(' + '|'.join(map(re.escape, other)) + ')$',
                             '--output-junit', str(output / 'auxiliary-junit.xml')]))
            if asan:
                commands.append(('qt', [sys.executable, ROOT / 'test/pocx/run_qt.py',
                             '--build-dir', build, '--output-dir', output / 'qt', '--jobs', str(args.jobs),
                             '--timeout', '2400']))
            else:
                report['configuration_disabled'] = {'qt': 'Inherited native_tsan/native_msan BUILD_GUI=OFF and depends NO_QT=1'}
            kernel = [sys.executable, ROOT / 'test/pocx/run_kernel.py', '--build-dir', build,
                      '--output-dir', output / 'kernel', '--jobs', str(args.jobs), '--timeout', '2400']
            if bitcoin:
                kernel.append('--bitcoin')
            commands.append(('kernel', kernel))
            report['functional_transports'] = ['v1', 'v2']
            if bitcoin:
                runner = stage_bitcoin_functional(build, output, network_addresses=True)
                report['bitcoin_functional_staging'] = str(runner.parent)
                functional = [sys.executable, ROOT / 'test/pocx/run_bitcoin_functional.py',
                              '--runner', runner, '--jobs', str(args.jobs),
                              '--previous-releases-dir', args.previous_releases_dir.resolve()]
            else:
                functional = [sys.executable, ROOT / 'test/pocx/verify_functional.py',
                              '--build-dir', build, '--jobs', str(args.jobs), '--transport', 'matrix',
                              '--require-no-skips', '--previous-releases', '--network-addresses',
                              '--previous-releases-dir', args.previous_releases_dir.resolve()]
            functional += ['--timeout-factor', '40', '--output', output / 'functional-verification.json']
            if not bitcoin:
                # Upstream has no outer per-script hard cap. Keep scaled waits
                # reachable while preserving owned process-group cleanup.
                functional += ['--timeout', '96000']
            commands.append(('functional', functional))
        elif args.profile in ('bitcoin-unit', 'bitcoin-wallet-disabled', 'bitcoin-ipc-disabled'):
            commands.append(('unit', [sys.executable, ROOT / 'test/pocx/run_bitcoin_unit.py',
                             '--build-dir', build, '--jobs', str(args.jobs)]))
            registered = json.loads(subprocess.check_output(['ctest', '--test-dir', str(build), '--show-only=json-v1'], text=True))['tests']
            other = sorted(test['name'] for test in registered if test.get('command', [''])[0] != str(build / 'bin/test_bitcoin'))
            if not other:
                raise ValueError('Missing auxiliary library CTest registrations')
            report['auxiliary_tests'] = other
            commands.append(('auxiliary', ctest + ['-R', '^(' + '|'.join(map(re.escape, other)) + ')$',
                             '--output-junit', str(output / 'auxiliary-junit.xml')]))
        elif args.profile == 'bitcoin-functional-optional':
            runner = stage_bitcoin_functional(build, output, network_addresses=True)
            report['bitcoin_functional_staging'] = str(runner.parent)
            report['functional_transports'] = ['v1', 'v2']
            commands.append(('functional', [sys.executable, ROOT / 'test/pocx/run_bitcoin_functional.py',
                             '--runner', runner, '--jobs', str(args.jobs),
                             '--previous-releases-dir', args.previous_releases_dir.resolve(),
                             '--output', output / 'functional-verification.json']))
        elif args.profile == 'bitcoin-functional':
            # Run the full upstream base inventory through its build-tree entry
            # point, which reads this build's config.ini. Extended tests remain
            # accounted for separately in the upstream inventory.
            runner = stage_bitcoin_functional(build, output)
            report['bitcoin_functional_staging'] = str(runner.parent)
            commands.append(('functional', [sys.executable, runner,
                             f'--jobs={args.jobs}', f'--tmpdirprefix={output}',
                             f'--resultsfile={output / "functional.csv"}', '--combinedlogslen=100', '--randomseed=0']))
        elif args.profile.endswith('-qt'):
            commands.append(('qt', [sys.executable, ROOT / 'test/pocx/run_qt.py',
                             '--build-dir', build, '--output-dir', output / 'qt',
                             '--jobs', str(args.jobs)]))
        elif args.profile.endswith('-kernel'):
            kernel = [sys.executable, ROOT / 'test/pocx/run_kernel.py',
                      '--build-dir', build, '--output-dir', output / 'kernel',
                      '--jobs', str(args.jobs)]
            if args.profile.startswith('bitcoin-'):
                kernel.append('--bitcoin')
            commands.append(('kernel', kernel))
        elif args.profile in ('pocx-functional', 'pocx-functional-optional'):
            transport = args.transport or 'matrix'
            report['functional_transports'] = ['v1', 'v2'] if transport == 'matrix' else [transport]
            commands.append(('functional', [sys.executable, ROOT / 'test/pocx/verify_functional.py',
                             '--build-dir', build, '--jobs', str(args.jobs), '--transport', transport]))
            if optional:
                commands[-1][1].extend(['--require-no-skips', '--previous-releases',
                                       '--previous-releases-dir', args.previous_releases_dir.resolve(),
                                       '--network-addresses', '--output', output / 'functional-verification.json'])
        elif args.profile == 'pocx-real-proof':
            commands.append(('real-proof', [sys.executable, ROOT / 'test/pocx/run_unit.py',
                             '--build-dir', build, '--suite', 'pocx_real_proof_tests',
                             '--suite', 'pocx_simd_tests', '--suite', 'pocx_wire_tests',
                             '--jobs', str(args.jobs)]))
        else:
            commands.append(('unit', [sys.executable, ROOT / 'test/pocx/run_unit.py', '--build-dir', build, '--all', '--jobs', str(args.jobs)]))
            registered = json.loads(subprocess.check_output(['ctest', '--test-dir', str(build), '--show-only=json-v1'], text=True))['tests']
            other = sorted(test['name'] for test in registered if test.get('command', [''])[0] != str(build / 'bin/test_pocx'))
            if not other:
                raise ValueError('Missing auxiliary library CTest registrations')
            report['auxiliary_tests'] = other
            commands.append(('auxiliary', ctest + ['-R', '^(' + '|'.join(map(re.escape, other)) + ')$',
                             '--output-junit', str(output / 'auxiliary-junit.xml')]))
        # Continue independent checks after a test failure to preserve evidence.
        # Any failed step still makes the profile fail.
        passed = True
        for name, command in commands:
            passed = run(name, command) and passed
        require_unchanged('Source inputs', report['source_snapshot'], source_snapshot(ROOT))
        require_unchanged('Build inputs', report['execution_build_snapshot'], build_snapshot(build))
        report['status'] = 'passed' if passed else 'failed'
        if passed:
            report['execution_verification'] = verify_report(ROOT, report, output)
        return 0 if passed else 1
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        report.update(status='failed', error=str(error))
        print(str(error), file=sys.stderr)
        return 1
    finally:
        save()
        print(f'CI profile {args.profile}: {report["status"]}; results: {output}', flush=True)


if __name__ == '__main__':
    sys.exit(main())
