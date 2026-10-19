#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin PoCX developers
# Distributed under the MIT software license; see COPYING.
"""Review fuzz membership independently of build and runtime success."""
import json
import re

from common import ROOT, sha256
import unit_matrix


BASELINE_SHA256 = '26931d13b1b61638a0cc7c7d0683281d3689d9341013244624d5d1d621dc3671'

def records(root=ROOT):
    baseline_path = root / 'test/pocx/fuzz-baseline.json'
    baseline = json.loads(baseline_path.read_text())
    parity = json.loads((root / 'test/pocx/fuzz-parity.json').read_text())
    if sha256(baseline_path) != BASELINE_SHA256 or parity['baseline_sha256'] != BASELINE_SHA256:
        raise ValueError('Fuzz baseline changed without parity review')
    return baseline, parity


def declared_targets(source):
    return re.findall(r'^FUZZ_TARGET(?:_DESERIALIZE)?\(\s*(\w+)', source, re.M)


def check(root=ROOT):
    baseline, parity = records(root)
    issues = []
    if set(parity['targets']) != set(baseline['targets']):
        issues.append('Original fuzz target classification is incomplete')
    originals = {str(path.relative_to(root)) for directory in
                 ('src/test/fuzz', 'src/wallet/test/fuzz', 'test/fuzz')
                 for path in (root / directory).rglob('*')
                 if path.is_file() and '__pycache__' not in path.parts and path.suffix != '.pyc'}
    if originals != set(baseline['sources']):
        issues.append('Original fuzz source inventory changed')
    for name, expected in baseline['sources'].items():
        if not (root / name).is_file() or sha256(root / name) != expected:
            issues.append('Original fuzz source changed: ' + name)
    selected = (root / 'src/pocx/test/fuzz/sources.cmake').read_text()
    for target, row in parity['targets'].items():
        if row['classification'] == 'excluded':
            if not row.get('reason', '').strip():
                issues.append('Unjustified fuzz exclusion: ' + target)
            continue
        if row['classification'] not in ('reused', 'adapted'):
            issues.append('Unknown fuzz classification: ' + target)
            continue
        source = row['replacement']
        original = baseline['targets'][target]['source']
        if (row['classification'] == 'reused') != (source == original):
            issues.append('Incorrect reuse/adaptation classification: ' + target)
        if row['classification'] == 'adapted' and not row.get('review', '').strip():
            issues.append('Unreviewed fuzz adaptation: ' + target)
        if not (root / source).is_file() or target not in declared_targets((root / source).read_text()):
            issues.append('Missing reviewed fuzz target: ' + target)
        if not source.startswith('src/wallet/'):
            expression = source.replace('src/pocx/test/fuzz', '${CMAKE_CURRENT_SOURCE_DIR}', 1)
            if expression == source:
                expression = '${PROJECT_SOURCE_DIR}/' + source
            if expression not in selected:
                issues.append('Missing fuzz source selection: ' + source)
    native_sources = {str(path.relative_to(root)) for path in
                      (root / 'src/pocx/test/fuzz').rglob('*.cpp')}
    declarations = [target for source in native_sources for target in
                    declared_targets((root / source).read_text())]
    declared = set(declarations)
    if len(declarations) != len(declared):
        issues.append('Duplicate native fuzz target declarations')
    reviewed = {target for target, row in parity['targets'].items() if row['classification'] == 'adapted'}
    reviewed |= parity['native_targets'].keys()
    if declared != reviewed:
        issues.append('Native fuzz declarations differ from reviewed membership')
    for target, row in parity['native_targets'].items():
        source = row['source']
        if source not in native_sources or target not in declared_targets((root / source).read_text()):
            issues.append('Incorrect native fuzz source mapping: ' + target)
        expression = source.replace('src/pocx/test/fuzz', '${CMAKE_CURRENT_SOURCE_DIR}', 1)
        if expression not in selected:
            issues.append('Missing native fuzz source selection: ' + target)
        if row['condition'] not in ('always', 'HAVE_AVX2', 'x86_64'):
            issues.append('Unknown native feature condition: ' + target)
    required = native_sources | {
        'src/CMakeLists.txt', 'src/kernel/chainparams.cpp',
        'src/pocx/test/util/mining.cpp', 'src/pocx/test/fuzz/CMakeLists.txt',
        'src/pocx/test/fuzz/sources.cmake',
        'src/pocx/test/fuzz/provenance.cmake',
        'test/pocx/bitcoin_fuzz_ci.py', 'test/pocx/check_drift.py',
        'test/pocx/ci_fuzz_run.py',
        'test/pocx/ci_matrix.py', 'test/pocx/fuzz_build.py', 'test/pocx/fuzz_parity.py',
        'test/pocx/record_fuzz.py', 'test/pocx/run_fuzz.py',
        'test/pocx/test_fuzz_parity.py',
        'test/pocx/stage_fuzz_corpus.py',
    }
    required |= {str(path.relative_to(root)) for path in (root / 'test/pocx/fuzz').rglob('*')
                 if path.is_file() and path.suffix in ('.py', '.json')}
    if not required.issubset(parity['reviewed_sources']):
        issues.append('Missing native fuzz source review')
    for source, expected in parity['reviewed_sources'].items():
        if not (root / source).is_file() or sha256(root / source) != expected:
            issues.append('Reviewed fuzz dependency changed: ' + source)
    return issues


def inventory(build, *, bitcoin=False, selected_config=None, root=ROOT):
    baseline, parity = records(root)
    options, _ = unit_matrix.configuration(build, selected_config)
    if options.get('ENABLE_POCX') != ('OFF' if bitcoin else 'ON'):
        raise ValueError('Wrong fuzz product configuration')
    if options.get('ENABLE_WALLET') not in ('ON', 'OFF'):
        raise ValueError('Missing fuzz wallet configuration')
    if options.get('BUILD_FOR_FUZZING') != 'ON' and options.get('CMAKE_BUILD_TYPE') != 'Debug':
        raise ValueError('Fuzz execution requires BUILD_FOR_FUZZING or Debug')
    disabled = {}
    exclusions = {}
    expected = set()
    for target, row in baseline['targets'].items():
        if row['hidden']:
            disabled[target] = 'Inherited hidden target: explicit specialized corpus/minimizer use only'
        elif row['requires_wallet'] and options['ENABLE_WALLET'] == 'OFF':
            disabled[target] = 'ENABLE_WALLET=OFF'
        elif not bitcoin and parity['targets'][target]['classification'] == 'excluded':
            exclusions[target] = parity['targets'][target]['reason']
        else:
            expected.add(target)
    if not bitcoin:
        for target, row in parity['native_targets'].items():
            condition = row['condition']
            if condition == 'HAVE_AVX2' and not options['avx2_compiled']:
                disabled[target] = 'HAVE_AVX2 is false'
            elif condition == 'x86_64' and not re.search(r'x86_64|amd64', options['target_processor'], re.I):
                disabled[target] = 'SSE2 target requires native x86-64'
            elif condition not in ('always', 'HAVE_AVX2', 'x86_64'):
                raise ValueError('Unreviewed native fuzz feature condition: ' + condition)
            else:
                expected.add(target)
    return {'expected': sorted(expected), 'configuration_disabled': disabled, 'excluded': exclusions}


if __name__ == '__main__':
    problems = check()
    print(json.dumps({'status': 'failed' if problems else 'passed', 'issues': problems}, indent=2))
    raise SystemExit(bool(problems))
