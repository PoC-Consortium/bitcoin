#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin PoCX developers
# Distributed under the MIT software license; see COPYING.
"""Run the unchanged full upstream functional runner with no optional skips.

The two special-address fixtures run separately so their prerequisite flags
never leak into unrelated scripts. Every upstream argument variant and dynamic
benchmark case is required in each transport, including extended tests.
"""
import argparse
from collections import Counter
import configparser
import csv
import json
import math
from pathlib import Path
import os
import shlex
import subprocess
import sys

sys.dont_write_bytecode = True
from common import ROOT, sha256
from functional_cases import TRANSPORT_FLAGS, upstream_cases
from functional_environment import arguments, release_binaries, verify_network_addresses

ADDRESS_TESTS = ('feature_bind_port_discover.py', 'feature_bind_port_externalip.py')


def effective_transport(case, requested):
    # Upstream explicitly gives --v1transport precedence over --v2transport.
    if requested not in ('v1', 'v2'):
        raise ValueError('Unknown functional transport')
    return 'v1' if requested == 'v1' or '--v1transport' in shlex.split(case) else 'v2'


def normalized_case(case):
    return shlex.join([arg for arg in shlex.split(case) if arg not in TRANSPORT_FLAGS])


def expected_cases(source, benchmarks):
    rows = upstream_cases(source)
    if (not benchmarks or len(set(benchmarks)) != len(benchmarks) or
            any(not name or any(char.isspace() for char in name) for name in benchmarks)):
        raise ValueError('Missing, duplicate or invalid benchmark inventory')
    result = []
    for row in rows:
        if row['dynamic']:
            result.extend(f'{row["upstream_case"]} --bench={name}' for name in benchmarks)
        else:
            result.append(row['upstream_case'])
    if len(result) != len(set(result)) or not set(ADDRESS_TESTS).issubset(result):
        raise ValueError('Incomplete or duplicate upstream functional inventory')
    return result


def case_groups(cases):
    return [('complete', [case for case in cases if case not in ADDRESS_TESTS], None),
            *[(name.removesuffix('.py'), [name], name) for name in ADDRESS_TESTS]]


def runner_arguments(runner, group, jobs, directory, csv_path, mode, timeout_factor=1):
    if mode not in ('v1', 'v2'):
        raise ValueError('Unknown functional transport')
    command = [sys.executable, str(runner), f'--jobs={jobs}',
               f'--tmpdirprefix={directory}', f'--resultsfile={csv_path}',
               '--combinedlogslen=100', '--randomseed=0', f'--{mode}transport']
    command += arguments(group or '', {'previous_releases': True, 'network_addresses': True})
    if type(timeout_factor) not in (int, float) or not math.isfinite(timeout_factor) or timeout_factor <= 0:
        raise ValueError('Functional timeout factor must be finite and positive')
    if timeout_factor != 1:
        command.append('--timeout-factor=' + str(timeout_factor))
    if group is None:
        command += ['--extended', *[f'--exclude={name}' for name in ADDRESS_TESTS]]
    else:
        command.append(group)
    return command


def read_cases(path, expected):
    with Path(path).open(newline='') as stream:
        reader = csv.reader(stream)
        if next(reader, None) != ['test', 'status', 'duration(seconds)']:
            raise ValueError('Unexpected upstream results CSV schema')
        rows = list(reader)
    if any(len(row) != 3 for row in rows):
        raise ValueError('Malformed upstream result row')
    summaries = [row for row in rows if row[0] == 'ALL']
    tests = [row for row in rows if row[0] != 'ALL']
    if (len(summaries) != 1 or not rows or rows[-1] != summaries[0] or
            Counter(row[0] for row in tests) != Counter(expected)):
        raise ValueError('Missing, duplicate or unexpected upstream functional case')
    for _, status, duration in rows:
        if (status not in ('Passed', 'Failed', 'Skipped') or
                not math.isfinite(float(duration)) or float(duration) < 0):
            raise ValueError('Invalid upstream functional result')
    return tests, summaries[0]


def verify_cases(rows, summary, returncode):
    # Upstream ALL/exit status can be green when individual cases skipped.
    if returncode != 0 or summary[1] != 'Passed' or any(row[1] != 'Passed' for row in rows):
        raise ValueError('Required original functional case failed or skipped')


def release_snapshot(directory):
    return {name: {'path': str(path), 'sha256': sha256(path)}
            for name, path in release_binaries(directory).items()}


def verify_staging(runner):
    tree = runner.parents[2]
    record = json.loads((tree / 'provenance.json').read_text())
    config = configparser.ConfigParser()
    config.read(tree / 'test/config.ini')
    if (Path(config['environment']['BUILDDIR']).resolve() != tree or
            record['build_view'] != str(tree) or
            runner != tree / 'test/functional/test_runner.py' or
            runner.read_bytes() != (ROOT / 'test/functional/test_runner.py').read_bytes() or
            {Path(row['source']).name for row in record['replacements']} != set(ADDRESS_TESTS)):
        raise ValueError('Original functional runner must execute the reviewed staged test tree')
    build = Path(record['binary_build'])
    if any((tree / name).resolve() != (build / name).resolve() for name in ('bin', 'lib')):
        raise ValueError('Original functional staging points to a different binary build')
    for relative, expected in record['files'].items():
        if sha256(tree / relative) != expected:
            raise ValueError('Staged original functional input changed: ' + relative)
    return record


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--runner', type=Path, required=True)
    parser.add_argument('--previous-releases-dir', type=Path, required=True)
    parser.add_argument('--jobs', type=int, default=4)
    parser.add_argument('--timeout-factor', type=float, default=1)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if args.jobs < 1 or not math.isfinite(args.timeout_factor) or args.timeout_factor <= 0:
        parser.error('jobs must be positive')
    runner = args.runner.resolve()
    output = args.output.resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    report = {'status': 'running', 'required_no_skips': True,
              'timeout_factor': args.timeout_factor,
              'transport_modes': ['v1', 'v2'], 'runs': [], 'cases': [],
              'transport_scope': 'Both global configurations; inherited upstream transport variants retain their flags. Individual rows record the effective transport, and every normalized case requires both transports.'}
    try:
        staged = verify_staging(runner)
        report['staging'] = staged
        report['network_interfaces'] = verify_network_addresses()
        releases = args.previous_releases_dir.resolve()
        before = release_snapshot(releases)
        report['previous_release_binaries'] = before
        # The private bin directory resolves to the actual, separately attested build.
        bench = runner.parents[2] / 'bin/bench_bitcoin'
        benchmarks = subprocess.check_output([str(bench), '-list'], text=True).splitlines()
        cases = expected_cases(runner, benchmarks)
        report.update(expected_cases=cases, benchmarks=benchmarks)
        env = {**os.environ, 'PREVIOUS_RELEASES_DIR': str(releases), 'PYTHONDONTWRITEBYTECODE': '1'}
        passed = True
        for mode in report['transport_modes']:
            for group_name, selection, test in case_groups(cases):
                directory = output.parent / f'bitcoin-functional-{mode}-{group_name}'
                directory.mkdir()
                csv_path, log_path = directory / 'results.csv', directory / 'runner.log'
                command = runner_arguments(runner, test, args.jobs, directory, csv_path, mode, args.timeout_factor)
                with log_path.open('w') as log:
                    execution = subprocess.run(command, cwd=ROOT, env=env, stdout=log, stderr=subprocess.STDOUT)
                run = {'transport': mode, 'selection': selection, 'command': command,
                       'returncode': execution.returncode, 'log': str(log_path),
                       'log_sha256': sha256(log_path), 'status': 'failed'}
                report['runs'].append(run)
                try:
                    rows, summary = read_cases(csv_path, selection)
                    run.update(csv=str(csv_path), csv_sha256=sha256(csv_path))
                    report['cases'] += [{'case': name, 'requested_transport': mode,
                                         'transport': effective_transport(name, mode),
                                         'status': status.lower(), 'seconds': float(seconds)}
                                        for name, status, seconds in rows]
                    verify_cases(rows, summary, execution.returncode)
                    run['status'] = 'passed'
                except (OSError, ValueError) as error:
                    run['error'] = str(error)
                    passed = False
                print(f'Original functional {mode}/{group_name}: {run["status"]}', flush=True)
                output.write_text(json.dumps(report, indent=2) + '\n')
        if before != release_snapshot(releases):
            raise ValueError('Previous-release binaries changed during execution')
        if staged != verify_staging(runner):
            raise ValueError('Staged original functional inputs changed during execution')
        report['status'] = 'passed' if passed else 'failed'
        return 0 if passed else 1
    except (OSError, ValueError, KeyError, subprocess.SubprocessError) as error:
        report.update(status='failed', error=str(error))
        print(str(error), file=sys.stderr)
        return 1
    finally:
        output.write_text(json.dumps(report, indent=2) + '\n')


if __name__ == '__main__':
    sys.exit(main())
