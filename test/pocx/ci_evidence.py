#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin PoCX developers
# Distributed under the MIT software license; see COPYING.
"""Bind a local CI invocation to its inputs and complete, successful step logs.

This supplements framework-specific case verification. It is neither a full
compiler dependency graph nor proof that a hosted workflow has executed.
"""
from common import sha256


def source_snapshot(root):
    import json
    paths = {root / '.github/workflows/pocx-tests.yml', root / 'CMakeLists.txt',
             root / 'CMakePresets.json'}
    # Include runner imports, reviews, fixtures, original test/production sources
    # and build selection files. Fuzz belongs to a separate package. Recording
    # C++ sources too lets the saved-report verifier detect later source changes,
    # rather than merely checking that the old child JSON itself is unchanged.
    for directory in ('test/pocx', 'test/functional', 'test/sanitizer_suppressions', 'cmake', 'src', 'ci/test'):
        for path in (root / directory).rglob('*'):
            relative = path.relative_to(root / directory)
            if ('__pycache__' in relative.parts or 'fuzz' in relative.parts or
                    (directory == 'test/pocx' and (path.name == 'run_fuzz.py' or
                     path.name.startswith(('fuzz', 'test_fuzz'))))):
                continue
            if path.is_file() and path.suffix not in ('.md', '.pyc'):
                paths.add(path)
    for name in ('.github/workflows/ci.yml', '.github/ci-windows.py', '.github/ci-windows-cross.py',
                 '.github/ci-test-each-commit-exec.py', 'ci/test_run_all.sh'):
        if (root / name).is_file():
            paths.add(root / name)
    for name in ('ci/test/00_setup_env_native_asan.sh', 'ci/test/03_test_script.sh'):
        if (root / name).is_file():
            paths.add(root / name)
    instrumented = root / 'test/pocx/instrumented-ci.json'
    if instrumented.is_file():
        paths.update(root / name for name in json.loads(instrumented.read_text())['source_sha256'])
    return {str(path.relative_to(root)): sha256(path) for path in sorted(paths)}


def build_snapshot(build):
    paths = {build / 'CMakeCache.txt', build / 'test/config.ini'}
    prefix = 'CMAKE_GENERATOR:INTERNAL='
    generators = [line[len(prefix):] for line in (build / 'CMakeCache.txt').read_text().splitlines()
                  if line.startswith(prefix)]
    if len(generators) != 1:
        raise ValueError('Missing or ambiguous CI build generator')
    generator = generators[0]
    if generator in ('Ninja', 'Ninja Multi-Config'):
        paths.update((build / 'build.ninja', build / 'CMakeFiles/rules.ninja'))
        paths.update(build.glob('*.ninja'))
        paths.update((build / 'CMakeFiles').rglob('*.ninja'))
    elif generator and generator.startswith('Visual Studio '):
        projects = set(build.rglob('*.vcxproj'))
        solutions = set(build.glob('*.sln')) | set(build.glob('*.slnx'))
        if not projects or not solutions:
            raise ValueError('Missing Visual Studio solution or project build inputs')
        paths.update(projects | solutions)
        for suffix in ('*.props', '*.targets'):
            paths.update(build.rglob(suffix))
    else:
        raise ValueError('Missing or unsupported CI build generator: ' + str(generator))
    paths.update(build.rglob('CTestTestfile.cmake'))
    for directory in ('bin', 'lib'):
        paths.update(path for path in (build / directory).rglob('*') if path.is_file())
    binaries = [path for path in paths if path.is_relative_to(build / 'bin')]
    if not binaries:
        raise ValueError('CI execution has no built binaries')
    return {str(path.relative_to(build)): sha256(path) for path in sorted(paths)}


def require_unchanged(label, recorded, current):
    changed = sorted(name for name in recorded.keys() | current.keys()
                     if recorded.get(name) != current.get(name))
    if changed:
        raise ValueError(f'{label} changed during CI execution: {changed}')


def required_steps(profile, skip_build):
    steps = ['drift']
    if profile == 'drift':
        return steps
    if profile.endswith(('-asan', '-tsan', '-msan')):
        steps.append('sanitizer-tools')
    if profile.endswith(('-tsan', '-msan')):
        steps.append('sanitizer-dependencies')
    if not skip_build:
        steps += ['configure', 'build']
    if profile.endswith(('-unit', '-wallet-disabled', '-ipc-disabled')):
        return steps + ['unit', 'auxiliary']
    if profile.endswith('-asan'):
        return steps + ['sanitizer', 'unit', 'auxiliary', 'qt', 'kernel', 'functional']
    if profile.endswith(('-tsan', '-msan')):
        return steps + ['sanitizer', 'unit', 'auxiliary', 'kernel', 'functional']
    selection = {'bitcoin-functional': 'functional', 'pocx-functional': 'functional',
                 'bitcoin-functional-optional': 'functional', 'pocx-functional-optional': 'functional',
                 'bitcoin-qt': 'qt', 'pocx-qt': 'qt',
                 'bitcoin-kernel': 'kernel', 'pocx-kernel': 'kernel',
                 'pocx-real-proof': 'real-proof'}
    return steps + [selection[profile]]


def verify_steps(report, output):
    expected = required_steps(report['profile'], report['skip_build'])
    steps = report['steps']
    if [step['name'] for step in steps] != expected:
        raise ValueError('CI step inventory is incomplete, duplicated or out of order')
    for step in steps:
        log = output / (step['name'] + '.log')
        if (step.get('status') != 'passed' or step.get('returncode') != 0 or
                not step.get('command') or not log.is_file() or
                step.get('log_sha256') != sha256(log)):
            raise ValueError('CI step failed or has missing/changed evidence: ' + step['name'])
    return {'steps': expected, 'scope': 'local CI entrypoint; framework case proof remains in child reports'}


def verify_report(root, report, output):
    """Reject stale local evidence without rerunning or updating its snapshots."""
    from pathlib import Path
    if report.get('status') != 'passed' or report.get('source') != str(root):
        raise ValueError('CI report is not a passing execution of this worktree')
    build = Path(report['build'])
    if build == root or not build.is_relative_to(root):
        raise ValueError('CI report has a build outside this worktree')
    require_unchanged('Source inputs', report['source_snapshot'], source_snapshot(root))
    if report['profile'] != 'drift':
        require_unchanged('Build inputs', report['execution_build_snapshot'], build_snapshot(build))
    proof = verify_steps(report, output)
    artifacts = report.get('artifacts', {})
    if not artifacts:
        raise ValueError('CI execution has no retained artifacts')
    for name, expected in artifacts.items():
        path = Path(name)
        if not path.is_relative_to(build) or not path.is_file() or sha256(path) != expected:
            raise ValueError('CI artifact missing or changed: ' + name)
    proof['retained_artifacts'] = len(artifacts)
    if report['profile'].endswith(('-functional-optional', '-asan', '-tsan', '-msan')):
        proof['required_functional'] = verify_required_functional(root, report, output)
    if report['profile'].endswith('-asan'):
        proof['sanitizer'] = verify_sanitizer_execution(root, report, output)
    if report['profile'].endswith(('-tsan', '-msan')):
        proof['sanitizer'] = verify_instrumented_execution(root, report, output)
    return proof


def verify_required_functional(root, report, output):
    """Do not let a normal skip-tolerant invocation stand in for this profile."""
    import json
    from collections import Counter
    path = output / 'functional-verification.json'
    if report.get('functional_transports') != ['v1', 'v2']:
        raise ValueError('Required functional profile must retain both transports')
    if report.get('artifacts', {}).get(str(path)) != sha256(path):
        raise ValueError('Required functional verification artifact is missing or changed')
    child = json.loads(path.read_text())
    if child.get('status') != 'passed' or child.get('required_no_skips') is not True:
        raise ValueError('Required functional proof must reject every skip')
    command = next(step['command'] for step in report['steps'] if step['name'] == 'functional')
    native = report['profile'].startswith('pocx-')
    script = 'verify_functional.py' if native else 'run_bitcoin_functional.py'
    if len(command) < 2 or command[1] != str(root / 'test/pocx' / script):
        raise ValueError('Wrong required functional entrypoint')
    if '--output' not in command or command[command.index('--output') + 1] != str(path):
        raise ValueError('Required functional proof belongs to a different command')
    if native:
        from functional_cases import selected_cases, upstream_cases
        manifest = json.loads((root / 'test/pocx/manifest.json').read_text())
        expected = len(selected_cases(manifest, upstream_cases(root / 'test/functional/test_runner.py')))
        counts = child.get('counts_by_transport')
        if (any(flag not in command for flag in ('--require-no-skips', '--previous-releases',
                                                 '--previous-releases-dir', '--network-addresses')) or
                '--transport' not in command or command[command.index('--transport') + 1] != 'matrix' or
                child.get('skips') != [] or counts != {mode: {'passed': expected} for mode in ('v1', 'v2')}):
            raise ValueError('Required PoCX functional selection or prerequisite gate is incomplete')
        return {'cases_per_transport': expected, 'transports': ['v1', 'v2'], 'skipped': 0}
    from run_bitcoin_functional import effective_transport, expected_cases, normalized_case
    expected = expected_cases(root / 'test/functional/test_runner.py', child['benchmarks'])
    pairs = Counter((row['case'], row['requested_transport']) for row in child['cases'])
    actual = {(normalized_case(row['case']), row['transport']) for row in child['cases']}
    if (child.get('transport_modes') != ['v1', 'v2'] or child.get('expected_cases') != expected or
            pairs != Counter((case, mode) for case in expected for mode in ('v1', 'v2')) or
            actual != {(normalized_case(case), mode) for case in expected for mode in ('v1', 'v2')} or
            any(row['status'] != 'passed' or row['transport'] != effective_transport(row['case'], row['requested_transport'])
                for row in child['cases'])):
        raise ValueError('Required original functional inventory is incomplete or not passing')
    return {'cases_per_transport': len(expected), 'transports': ['v1', 'v2'], 'skipped': 0}


def verify_sanitizer_execution(root, report, output):
    import json
    from pathlib import Path
    from sanitizer_ci import CANARIES, required_binaries, runtime_environment, verify_compile_commands
    if report.get('sanitizer_environment') != runtime_environment(root):
        raise ValueError('Sanitizer runtime environment was missing or weakened')
    path = output / 'sanitizer/verification.json'
    if report.get('artifacts', {}).get(str(path)) != sha256(path):
        raise ValueError('Sanitizer verification artifact missing or changed')
    child = json.loads(path.read_text())
    if (child.get('status') != 'passed' or child.get('environment') != runtime_environment(root) or
            not child.get('instrumentation', {}).get('compile_commands') or
            not child.get('instrumentation', {}).get('binaries')):
        raise ValueError('Missing passing sanitizer instrumentation/runtime proof')
    instrumentation = child['instrumentation']
    commands = instrumentation['compile_commands']
    if (any(not isinstance(rows, list) or not rows for rows in commands.values()) or
            verify_compile_commands('\n'.join(line for rows in commands.values() for line in rows),
                                    root=root, build=Path(report['build'])) != commands):
        raise ValueError('Sanitizer compile evidence is incomplete or inconsistent')
    binaries = instrumentation['binaries']
    if set(binaries) != set(required_binaries(report['profile'].startswith('pocx-'))):
        raise ValueError('Sanitizer executable inventory is incomplete or unexpected')
    for name, record in binaries.items():
        path = output / 'sanitizer/symbols' / (name + '-symbols.log')
        if (record.get('sha256') != report['execution_build_snapshot'].get('bin/' + name) or
                record.get('symbols_log') != str(path) or not path.is_file() or
                record.get('symbols_sha256') != sha256(path)):
            raise ValueError('Sanitizer executable or symbol evidence changed: ' + name)
        symbols = path.read_text()
        if '__asan_init' not in symbols or '__ubsan_handle_' not in symbols:
            raise ValueError('Sanitizer executable lacks required runtime symbols: ' + name)
    canaries = child.get('canaries', [])
    if (len(canaries) != len(CANARIES) or {row['canary'] for row in canaries} != set(CANARIES) or
            any(row.get('status') != 'passed' for row in canaries)):
        raise ValueError('Missing, duplicated or failed sanitizer canary')
    for row in canaries:
        diagnostic = CANARIES[row['canary']][1]
        if row.get('expected_diagnostic') != diagnostic or (row['returncode'] == 0) != (diagnostic is None):
            raise ValueError('Sanitizer error did not fail as required')
        path = output / 'sanitizer/canaries' / (row['canary'] + '.log')
        if (row.get('log') != str(path) or not path.is_file() or row.get('log_sha256') != sha256(path)):
            raise ValueError('Sanitizer canary diagnostic evidence missing or changed')
        text = path.read_text()
        if ((diagnostic is not None and diagnostic not in text) or
                (diagnostic is None and ('runtime error:' in text or 'Sanitizer' in text))):
            raise ValueError('Sanitizer canary diagnostic did not match the required result')
    steps = {row['name']: row['command'] for row in report['steps']}
    for name in ('unit', 'auxiliary', 'qt', 'kernel'):
        command = steps[name]
        if '--timeout' not in command or command[command.index('--timeout') + 1] != '2400':
            raise ValueError('Required sanitizer framework timeout missing: ' + name)
    command = steps['functional']
    if '--timeout-factor' not in command or command[command.index('--timeout-factor') + 1] != '40':
        raise ValueError('Required sanitizer functional timeout scaling missing')
    functional = json.loads((output / 'functional-verification.json').read_text())
    if functional.get('timeout_factor') != 40:
        raise ValueError('Sanitizer functional proof belongs to an unscaled execution')
    return {'canaries': len(canaries), 'scope': 'Required C++ sanitizer configuration; framework cases separately verified; Rust instrumentation not inferred.'}


def verify_instrumented_execution(root, report, output):
    import json
    from pathlib import Path
    from instrumented_ci import CANARIES, compile_commands, runtime_environment, verify_dependencies
    from sanitizer_ci import required_binaries
    kind = report['profile'].rsplit('-', 1)[1]
    directory = Path(report['instrumented_dependencies_directory'])
    if directory == root or not directory.is_relative_to(root):
        raise ValueError('Instrumented dependency proof belongs to another worktree')
    expected_environment = runtime_environment(kind, directory, root)
    if report.get('sanitizer_environment') != expected_environment or report.get('sanitizer_stack_limit') != 524288:
        raise ValueError('Required instrumented runtime environment/stack limit missing or weakened')
    path = output / 'sanitizer/verification.json'
    if report.get('artifacts', {}).get(str(path)) != sha256(path):
        raise ValueError('Instrumented sanitizer proof missing or changed')
    child = json.loads(path.read_text())
    if (child.get('status') != 'passed' or child.get('sanitizer') != kind or
            child.get('environment') != expected_environment or
            child.get('stack_limit') != 524288 or
            child.get('dependency_proof') != verify_dependencies(kind, directory, root)):
        raise ValueError('Missing passing instrumented sanitizer/dependency proof')
    commands = child.get('instrumentation', {}).get('compile_commands', {})
    if (not commands or any(not isinstance(rows, list) or not rows for rows in commands.values()) or
            compile_commands('\n'.join(line for rows in commands.values() for line in rows), kind,
                             directory, Path(report['build']), root) != commands):
        raise ValueError('Incomplete or inconsistent instrumented compile proof')
    binaries = child.get('instrumentation', {}).get('binaries', {})
    expected = set(required_binaries(report['profile'].startswith('pocx-'))) - {'test_bitcoin-qt'}
    if set(binaries) != expected:
        raise ValueError('Incomplete instrumented executable inventory')
    for name, row in binaries.items():
        path = output / 'sanitizer/symbols' / (name + '-symbols.log')
        if (row.get('sha256') != report['execution_build_snapshot'].get('bin/' + name) or
                row.get('symbols_log') != str(path) or not path.is_file() or row.get('symbols_sha256') != sha256(path) or
                ('__tsan_init' if kind == 'tsan' else '__msan_init') not in path.read_text()):
            raise ValueError('Missing or changed instrumented executable evidence: ' + name)
    canaries = child.get('canaries', [])
    if (len(canaries) != len(CANARIES[kind]) or {row['canary'] for row in canaries} != set(CANARIES[kind])):
        raise ValueError('Missing or duplicate instrumented runtime canary')
    for row in canaries:
        diagnostics = CANARIES[kind][row['canary']][1]
        path = output / 'sanitizer/canaries' / (row['canary'] + '.log')
        if (row.get('status') != 'passed' or row.get('expected_diagnostics') != diagnostics or
                (row.get('returncode') == 0) != (not diagnostics) or row.get('log') != str(path) or
                not path.is_file() or row.get('log_sha256') != sha256(path)):
            raise ValueError('Failed or missing instrumented runtime canary evidence')
        text = path.read_text()
        if (any(diagnostic not in text for diagnostic in diagnostics) or
                (not diagnostics and ('Sanitizer' in text or 'runtime error:' in text))):
            raise ValueError('Wrong instrumented runtime canary diagnostic')
    steps = {row['name']: row['command'] for row in report['steps']}
    for name in ('unit', 'auxiliary', 'kernel'):
        command = steps[name]
        if '--timeout' not in command or command[command.index('--timeout') + 1] != '2400':
            raise ValueError('Required instrumented framework timeout missing: ' + name)
    command = steps['functional']
    if '--timeout-factor' not in command or command[command.index('--timeout-factor') + 1] != '40':
        raise ValueError('Required instrumented functional timeout missing')
    functional = json.loads((output / 'functional-verification.json').read_text())
    if functional.get('timeout_factor') != 40:
        raise ValueError('Instrumented functional proof belongs to an unscaled execution')
    return {'canaries': len(canaries), 'scope': 'Required inherited C++ sanitizer and dependency preparation; framework cases verified separately. Qt disabled by the upstream profile; Rust instrumentation not inferred.'}


if __name__ == '__main__':
    import argparse
    import json
    from pathlib import Path
    from common import ROOT
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--report', type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(verify_report(ROOT, json.loads(args.report.read_text()), args.report.parent), indent=2))
