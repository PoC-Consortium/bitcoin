#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin PoCX developers
# Distributed under the MIT software license; see COPYING.
"""Run inherited POSIX recipes with an explicit Bitcoin baseline before PoCX.

Invoke after the existing container/dependency setup. --plan is read-only and
does not establish execution coverage. Fuzz jobs retain their original driver.
"""
import argparse
import difflib
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time
import windows_cross

from common import ROOT, sha256
from ci_evidence import source_snapshot

SETTINGS = ('HOST', 'MAKEJOBS', 'GOAL', 'BITCOIN_CONFIG', 'DEP_OPTS', 'NO_DEPENDS',
            'RUN_UNIT_TESTS', 'RUN_FUNCTIONAL_TESTS', 'RUN_TIDY', 'RUN_IWYU',
            'TEST_RUNNER_EXTRA', 'TEST_RUNNER_TIMEOUT_FACTOR', 'BITCOIN_CMD',
            'CI_OS_NAME', 'CI_LIMIT_STACK_SIZE', 'DOWNLOAD_PREVIOUS_RELEASES', 'TEST_RUNNER_PORT_MIN',
            'VCPKG_ROOT', 'VCToolsVersion', 'VSCMD_ARG_TGT_ARCH')
RECIPE_SOURCES = {'ci/test/03_test_script.sh', 'ci/test/02_run_container.py',
                  'test/pocx/ci/00_setup_env_native_asan_tracing.sh',
                  'test/pocx/ci/test_imagefile', 'ci/test_imagefile',
                  'test/pocx/ci/inherited_runtime_env.sh',
                  'test/pocx/ci/inherited_test_script.sh', 'test/pocx/inherited_ci.py',
                  'test/pocx/inherited_tests.py', 'test/pocx/inherited_functional.py',
                  '.github/ci-test-each-commit-exec.py', 'test/pocx/revision_ci.py',
                  'test/pocx/windows_cross.py', 'test/pocx/test_windows_cross.py'}
RECIPE_SOURCES.update({'test/pocx/pocx_bootstrap.py', 'test/pocx/original_usdt.py', 'test/pocx/framework/bpf_abi.py',
                       'test/pocx/test_bpf_abi.py', 'test/pocx/bitcoin_baseline/usdt/review.json'})
RECIPE_SOURCES.update('test/pocx/bitcoin_baseline/usdt/interface_usdt_' + name + '.py' for name in
                      ('coinselection', 'mempool', 'net', 'utxocache', 'validation'))
UPSTREAM_RECIPE_SHA256 = 'cfd9e9583398dee9527a2fb7ea099104a8cab53f7bf5ccdceb3f4e84425ebb8b'
UPSTREAM_REVISION_RECIPE_SHA256 = '7d6c921986188b726f82bb08a782be738f6dfc2460d1f64272ae8bd8715d040b'
EVIDENCE_PREFIXES = ('pocx-inherited-', 'bitcoin-unit-', 'pocx-unit-', 'pocx-results-')
EVIDENCE_SUFFIXES = {'.json', '.xml', '.csv', '.log', '.txt'}


def iwyu_inputs(root, snapshot):
    """Keep exact inputs before the upstream include tool applies suggestions."""
    result = {}
    for name in snapshot:
        path = root / name
        if (Path(name).parts[:1] == ('src',) and
                path.suffix in ('.c', '.cc', '.cpp', '.h', '.hpp')):
            if path.is_symlink():
                raise ValueError('IWYU source input must be a regular file: ' + name)
            result[name] = (path.read_bytes(), path.stat().st_mode & 0o777)
    return result


def restore_iwyu_inputs(root, inputs, patch_path):
    """Retain suggestions, then restore inputs for the next consensus phase.

    The unchanged recipe rejects edits in its enforced phase. Its later warning
    phase intentionally applies suggestions and allows a diff. Never carry
    either phase's edits into the other consensus build or mask its exit code.
    All other source changes remain subject to the ordinary source guard.
    """
    changes = []
    differences = []
    for name, (before, mode) in inputs.items():
        path = root / name
        if path.is_symlink():
            raise ValueError('IWYU replaced a source input with a symlink: ' + name)
        after = path.read_bytes() if path.is_file() else b''
        if path.is_file() and before == after and path.stat().st_mode & 0o777 == mode:
            continue
        changes.append({'path': name, 'before_sha256': hashlib.sha256(before).hexdigest(),
                        'analysis_sha256': sha256(path) if path.is_file() else None,
                        'original_mode': mode})
        differences.extend(difflib.unified_diff(
            before.decode('utf-8').splitlines(keepends=True),
            after.decode('utf-8').splitlines(keepends=True),
            fromfile='a/' + name, tofile='b/' + name))
    patch_path.write_text(''.join(differences))
    for change in changes:
        path = root / change['path']
        before, mode = inputs[change['path']]
        path.write_bytes(before)
        path.chmod(mode)
        if sha256(path) != change['before_sha256'] or path.stat().st_mode & 0o777 != mode:
            raise ValueError('IWYU input restoration failed: ' + change['path'])
    return {'scope': 'Upstream IWYU suggestions retained separately; exact source bytes/modes restored after analysis. Recipe exit status and enforced-phase failure remain authoritative.',
            'changes': changes, 'patch': str(patch_path), 'patch_sha256': sha256(patch_path),
            'inputs_restored': True}


def evidence_directories(build):
    if not build.is_dir():
        return set()
    return {path for path in build.iterdir() if path.is_dir() and not path.is_symlink()
            and path.name.startswith(EVIDENCE_PREFIXES)}


def retain_evidence(build, before, destination):
    """Copy bounded report trees, never functional node data or build products."""
    retained = {}
    for child in sorted(evidence_directories(build) - before):
        # Keep the raw RPC coverage inputs from both transports. These files
        # have numeric suffixes and sit one level deeper than ordinary logs.
        for directory in (child / 'rpc-coverage', child / 'v2/rpc-coverage'):
            if directory.is_symlink() or directory.parent.is_symlink() or not directory.is_dir():
                continue
            for path in sorted(directory.rglob('*')):
                if (path.is_symlink() or not path.is_file() or
                        not (path.name == 'rpc_interface.txt' or path.name.startswith('coverage.')) or
                        any(parent.is_symlink() for parent in path.parents if parent != directory)):
                    continue
                relative = path.relative_to(build)
                target = destination / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(path, target)
                retained[str(relative)] = sha256(target)
        for entry in sorted(child.iterdir()):
            candidates = sorted(entry.iterdir()) if entry.is_dir() and not entry.is_symlink() else [entry]
            for path in candidates:
                if path.is_symlink() or not path.is_file() or path.suffix not in EVIDENCE_SUFFIXES:
                    continue
                relative = path.relative_to(build)
                target = destination / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(path, target)
                retained[str(relative)] = sha256(target)
    return retained


def publish(output, root=ROOT):
    """Retain success and failure reports outside scratch before guest cleanup."""
    destination = root / 'artifacts/pocx-inherited' / output.parent.name
    destination.parent.mkdir(parents=True, exist_ok=True)
    bundle = output / windows_cross.BUNDLE_DIRECTORY
    shutil.copytree(output, destination, ignore=lambda directory, names:
        [windows_cross.BUNDLE_DIRECTORY] if Path(directory) == output and bundle.is_dir() else [])
    published_pair = None
    if bundle.is_dir():
        published_pair = windows_cross.publish(bundle, destination.parent / windows_cross.PUBLISHED_DIRECTORY, root=root)
    # Root is required by original BPF tests. Let the ordinary hosted artifact
    # uploader read the published reports after that elevated CI step finishes.
    paths = [root / 'artifacts', destination.parent, destination, *destination.rglob('*')]
    if published_pair is not None:
        paths.extend([published_pair, *published_pair.rglob('*')])
    for path in paths:
        path.chmod(0o755 if path.is_dir() else 0o644)
    print('Published inherited CI results:', destination, flush=True)
    return destination


def verify_recipe(root=ROOT):
    review = json.loads((root / 'test/pocx/inherited-ci.json').read_text())
    if (set(review['source_sha256']) != RECIPE_SOURCES or
            review['source_sha256']['ci/test/03_test_script.sh'] != UPSTREAM_RECIPE_SHA256 or
            review['source_sha256']['.github/ci-test-each-commit-exec.py'] != UPSTREAM_REVISION_RECIPE_SHA256):
        raise ValueError('Incomplete inherited CI source review or changed original recipe')
    for name, expected in review['source_sha256'].items():
        if sha256(root / name) != expected:
            raise ValueError('Inherited CI recipe changed without review: ' + name)
    from check_drift import check
    issues = check(root)
    if issues:
        raise ValueError('Inherited CI parity source review failed: ' + str(issues))
    return review


def plan(environment, root=ROOT):
    if environment.get('RUN_FUZZ_TESTS') == 'true':
        raise ValueError('Fuzz jobs must retain the original driver; this package does not approve fuzz')
    if Path(environment['BASE_ROOT_DIR']).resolve() != root.resolve():
        raise ValueError('Inherited CI source tree does not match this worktree')
    host = environment.get('HOST') or subprocess.check_output(
        [str(root / 'depends/config.guess')], text=True).strip()
    scratch = Path(environment['BASE_SCRATCH_DIR']).resolve()
    build = Path(environment.get('BASE_BUILD_DIR', str(scratch / ('build-' + host)))).resolve()
    output = Path(environment['BASE_OUTDIR']).resolve()
    for path in (scratch, build, output):
        if path == root or not path.is_relative_to(root):
            raise ValueError('Use isolated inherited CI directories inside this source worktree')
    pairs = []
    for name, enabled in (('bitcoin', 'OFF'), ('pocx', 'ON')):
        child = dict(environment, HOST=host)
        child['BASE_BUILD_DIR'] = str(build) + ('-bitcoin-baseline' if name == 'bitcoin' else '')
        child['BASE_OUTDIR'] = str(output) + ('-bitcoin-baseline' if name == 'bitcoin' else '')
        # Last command-line definitions win over inherited presets/flags.
        # Fuzz builds remain a separate package on both sides of this pair.
        child['BITCOIN_CONFIG'] = (environment.get('BITCOIN_CONFIG', '') +
            f' -DENABLE_POCX={enabled} -DBUILD_FUZZ_BINARY=OFF -DBUILD_FOR_FUZZING=OFF')
        pairs.append({'consensus': name, 'command': ['bash', str(root / 'test/pocx/ci/inherited_test_script.sh')],
                      'environment': child})
    windows_cross.is_cross_pair(pairs)
    return pairs


def execute(pairs, output, *, root=ROOT, run=subprocess.run):
    if [item['consensus'] for item in pairs] != ['bitcoin', 'pocx']:
        raise ValueError('Inherited CI requires exactly one original baseline followed by one native build')
    cross = windows_cross.is_cross_pair(pairs)
    output.mkdir(parents=True, exist_ok=False)
    report = {'status': 'running', 'scope': 'Original-first CI controller; actual framework and hosted execution require their own evidence.',
              'source_snapshot': source_snapshot(root), 'steps': [], 'native_execution': 'deferred',
              'runtime_scope': 'Cross-build only; target-host execution deferred' if cross else 'Native inherited runtime recipe'}
    def save():
        (output / 'results.json').write_text(json.dumps(report, indent=2) + '\n')
    save()
    try:
        for item in pairs:
            env = item['environment']
            step = {'consensus': item['consensus'], 'command': item['command'], 'status': 'running',
                    'settings': {key: env[key] for key in (*SETTINGS, 'BASE_BUILD_DIR', 'BASE_OUTDIR') if key in env}}
            report['steps'].append(step)
            if item['consensus'] == 'pocx':
                report['native_execution'] = ('Cross-build started after original build; target-host baseline still required'
                    if cross else 'started after successful original baseline')
            save()
            log = output / (item['consensus'] + '.log')
            build = Path(env['BASE_BUILD_DIR'])
            before = evidence_directories(build)
            include_inputs = (iwyu_inputs(root, report['source_snapshot'])
                              if env.get('RUN_IWYU') == 'true' else None)
            start = time.monotonic()
            try:
                with log.open('w') as stream:
                    result = run(item['command'], cwd=root, env=env, stdout=stream, stderr=subprocess.STDOUT)
            finally:
                if include_inputs is not None:
                    step['iwyu_source_restoration'] = restore_iwyu_inputs(
                        root, include_inputs, output / (item['consensus'] + '-iwyu-suggestions.patch'))
                step['retained_evidence'] = retain_evidence(build, before, output / (item['consensus'] + '-evidence'))
                if log.is_file():
                    step['log_sha256'] = sha256(log)
                save()
            step.update(status='passed' if result.returncode == 0 else 'failed',
                        returncode=result.returncode, seconds=time.monotonic() - start, log_sha256=sha256(log))
            save()
            if result.returncode:
                raise ValueError(item['consensus'] + ' inherited CI recipe failed')
            if source_snapshot(root) != report['source_snapshot']:
                raise ValueError('Source inputs changed during inherited CI execution')
        if cross:
            report['windows_artifacts'] = windows_cross.export(pairs, output, root=root)
            if source_snapshot(root) != report['source_snapshot']:
                raise ValueError('Source inputs changed during Windows artifact export')
        report['status'] = 'passed'
    except Exception as error:
        if report['steps'] and report['steps'][-1]['status'] == 'running':
            report['steps'][-1].update(status='failed', error=str(error))
        report.update(status='failed', error=str(error))
        save()
        raise
    save()
    return report


def execute_and_publish(pairs, output, *, root=ROOT, run=subprocess.run):
    try:
        return execute(pairs, output, root=root, run=run)
    finally:
        if output.is_dir():
            failed = sys.exc_info()[0] is not None
            try:
                publish(output, root)
            except Exception as error:
                if not failed:
                    raise
                print('Evidence publication also failed: ' + str(error), file=sys.stderr, flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--plan', action='store_true')
    args = parser.parse_args()
    verify_recipe()
    pairs = plan(os.environ)
    if args.plan:
        print(json.dumps({'status': 'configured only; not executed', 'phases': [
            {**{key: row[key] for key in ('consensus', 'command')},
             'settings': {key: row['environment'][key] for key in (*SETTINGS, 'BASE_BUILD_DIR', 'BASE_OUTDIR')
                          if key in row['environment']}} for row in pairs]}, indent=2))
        return 0
    scratch = Path(os.environ['BASE_SCRATCH_DIR'])
    scratch.mkdir(parents=True, exist_ok=True)
    output = Path(tempfile.mkdtemp(prefix='pocx-inherited-', dir=scratch)) / 'execution'
    print('Inherited CI results:', output, flush=True)
    execute_and_publish(pairs, output)
    return 0


if __name__ == '__main__':
    sys.exit(main())
