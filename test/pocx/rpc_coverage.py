# Copyright (c) 2026 The Bitcoin PoCX developers
# Distributed under the MIT software license; see COPYING.
"""Retain and verify RPC coverage using the unchanged upstream evaluator."""
from pathlib import Path
import subprocess
import sys

from common import ROOT, sha256

EVALUATOR = (
    'import sys; sys.path.insert(0, sys.argv[1]); import test_runner; '
    'coverage = test_runner.RPCCoverage.__new__(test_runner.RPCCoverage); '
    'coverage.dir = sys.argv[2]; '
    'sys.exit(0 if coverage.report_rpc_coverage() else 1)'
)


def inputs(directory):
    directory = Path(directory)
    if directory.is_symlink() or not directory.is_dir():
        raise ValueError('Missing RPC coverage directory')
    reference = directory / 'rpc_interface.txt'
    files = {}
    covered = {'generate'}  # Exact upstream allowance for the framework wrapper.
    for path in sorted(directory.rglob('*')):
        if path.is_symlink():
            raise ValueError('RPC coverage inputs must not be symlinks')
        if path.is_file() and (path == reference or path.name.startswith('coverage.')):
            files[str(path.relative_to(directory))] = sha256(path)
            if path != reference:
                covered.update(line.strip() for line in path.read_text().splitlines())
    if 'rpc_interface.txt' not in files:
        raise ValueError('Missing RPC coverage reference')
    commands = {line.strip() for line in reference.read_text().splitlines()}
    if not commands:
        raise ValueError('Empty RPC coverage reference')
    return files, sorted(commands - covered)


def command(directory):
    return [sys.executable, '-c', EVALUATOR, str(ROOT / 'test/functional'), str(directory)]


def evaluate(directory, environment):
    directory = Path(directory).resolve()
    before, uncovered = inputs(directory)
    log = directory.parent / 'rpc-coverage.log'
    env = {key: value for key, value in environment.items() if key != 'PYTHONPATH'}
    env['PYTHONDONTWRITEBYTECODE'] = '1'
    with log.open('w') as stream:
        result = subprocess.run(command(directory), cwd=ROOT, env=env,
                                stdout=stream, stderr=subprocess.STDOUT, timeout=60)
    if inputs(directory) != (before, uncovered) or result.returncode != int(bool(uncovered)):
        raise ValueError('Upstream RPC coverage evaluation failed or inputs changed')
    return {'directory': str(directory), 'files': before, 'uncovered': uncovered,
            'source_sha256': sha256(ROOT / 'test/functional/test_runner.py'),
            'helper_sha256': sha256(Path(__file__)), 'command': command(directory),
            'returncode': result.returncode, 'log': str(log), 'log_sha256': sha256(log)}


def verify(report):
    provenance = report['provenance']
    enabled = provenance.get('format_version', 1) >= 10
    if not enabled:
        if 'rpc_coverage' in provenance or 'rpc_coverage' in report:
            raise ValueError('Historical report has unrecorded RPC coverage')
        return True
    if provenance.get('rpc_coverage') is not True:
        raise ValueError('Missing explicit RPC coverage request')
    if provenance.get('rpc_coverage_helper_sha256') != sha256(Path(__file__)):
        raise ValueError('RPC coverage helper changed since invocation')
    modes = provenance['transport_modes']
    records = report.get('rpc_coverage', {})
    if set(records) != set(modes):
        raise ValueError('Missing transport RPC coverage results')
    all_passed = True
    for mode in modes:
        rows = [row for row in report['results'] if row.get('transport') == mode]
        parents = {Path(row['log']).resolve().parent for row in rows}
        if len(parents) != 1:
            raise ValueError('RPC coverage must match the executed transport directory')
        directory = next(iter(parents)) / 'rpc-coverage'
        files, uncovered = inputs(directory)
        log = directory.parent / 'rpc-coverage.log'
        expected = {'directory': str(directory), 'files': files, 'uncovered': uncovered,
                    'source_sha256': sha256(ROOT / 'test/functional/test_runner.py'),
                    'helper_sha256': sha256(Path(__file__)), 'command': command(directory),
                    'returncode': int(bool(uncovered)), 'log': str(log), 'log_sha256': sha256(log)}
        if records[mode] != expected:
            raise ValueError('RPC coverage result or retained inputs changed')
        all_passed = all_passed and not uncovered
    return all_passed


def arguments(report, mode):
    if report['provenance'].get('format_version', 1) < 10:
        return []
    return ['--coveragedir=' + report['rpc_coverage'][mode]['directory']]
