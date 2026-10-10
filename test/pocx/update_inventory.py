#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin PoCX developers
# Distributed under the MIT software license; see COPYING.
"""Report current selections and supplied execution evidence against the fixed M0 baseline.

Does not approve provenance changes or replace the separate upstream drift gate.
"""
import argparse
import csv
import hashlib
import json
from pathlib import Path
import re
import subprocess
import xml.etree.ElementTree as ET
from functional_results import transport_results
from functional_cases import upstream_cases
from stage import framework_sources

ROOT = Path(__file__).resolve().parents[2]
BASE = '5de2720ca47b3a753081e5ce545113cd3b616018'
UPSTREAM = '9be056a8a72b624dae9623b2f7bded92c2a21c91'


def git_content(revision, path):
    p = subprocess.run(['git', '-C', str(ROOT), 'show', f'{revision}:{path}'], capture_output=True)
    return p.stdout if p.returncode == 0 else None


def digest(content):
    return hashlib.sha256(content).hexdigest() if content is not None else None


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--wrapper', required=True, type=Path, help='Explicit read-only wrapper checkout')
    parser.add_argument('--pocx-unit-results', type=Path, action='append', default=[])
    parser.add_argument('--bitcoin-unit-results', type=Path, action='append', default=[])
    parser.add_argument('--bitcoin-functional-results', type=Path, action='append', default=[],
                        help='CI results.json for the complete Bitcoin functional profile')
    parser.add_argument('--pocx-wallet-disabled-results', type=Path, action='append', default=[])
    parser.add_argument('--pocx-kernel-results', type=Path, action='append', default=[])
    parser.add_argument('--functional-results', type=Path, action='append', default=[])
    parser.add_argument('--fuzz-results', type=Path, action='append', default=[])
    parser.add_argument('--output', type=Path, default=ROOT / 'test/pocx/coverage.json',
                        help='Inventory snapshot destination; defaults to coverage.json')
    args = parser.parse_args()
    wrapper = args.wrapper.resolve()
    inventory = json.loads((ROOT / 'artifacts/baseline-inventory.json').read_text())
    restorations = json.loads((ROOT / 'test/pocx/restorations.json').read_text())['files']
    seen = {e['source'] for e in inventory}
    for pattern in ['test/functional/test_framework/**/*.py', 'test/functional/data/**/*.py', 'src/test/util/*', 'src/test/kernel/*']:
        for path in sorted(ROOT.glob(pattern)):
            if path.is_file() and str(path.relative_to(ROOT)) not in seen:
                inventory.append({'source': str(path.relative_to(ROOT)), 'execution': 'not run'})
    manifest = json.loads((ROOT / 'test/pocx/manifest.json').read_text())
    parity = json.loads((ROOT / 'test/pocx/scenario-parity.json').read_text())
    scenarios = {'wrapper/' + item['source']: item for item in parity['scenarios']}
    replacements = {'test/functional/' + source: 'test/pocx/' + target
                    for source, target in manifest['replacements'].items()}
    for source, target in manifest['tests'].items():
        if (ROOT / 'test/functional' / source).is_file():
            replacements['test/functional/' + source] = 'test/pocx/' + target
    for name in ('rpcnestedtests.cpp', 'wallettests.cpp', 'test_main.cpp'):
        replacements['src/qt/test/' + name] = 'src/pocx/test/qt/' + name
    for source in (ROOT / 'src/pocx/test/qt').glob('*.cpp'):
        inventory.append({'source': str(source.relative_to(ROOT))})
    replacements['src/test/kernel/test_kernel.cpp'] = 'src/pocx/test/kernel/test_kernel.cpp'
    replacements['src/test/kernel/block_data.h'] = 'src/pocx/test/kernel/fixture_generator.cpp'
    for source in (ROOT / 'src/pocx/test/kernel').glob('*.cpp'):
        inventory.append({'source': str(source.relative_to(ROOT))})
    for source in (ROOT / 'src/pocx/test/fuzz').glob('*.cpp'):
        inventory.append({'source': str(source.relative_to(ROOT))})
        upstream_source = 'src/test/fuzz/' + source.name
        if (ROOT / upstream_source).is_file():
            replacements[upstream_source] = str(source.relative_to(ROOT))
    cmake = (ROOT / 'src/pocx/test/sources.cmake').read_text()
    selected = re.findall(r'\$\{(?:PROJECT_SOURCE_DIR|CMAKE_CURRENT_SOURCE_DIR)\}/([^\s)]+)', cmake)
    owned_sources = ['src/pocx/test/' + item for item in selected if not item.startswith('src/')]
    # The functional package also inventories upstream fuzz sources, but the
    # separately delivered native fuzz selection need not be installed.
    fuzz_cmake_path = ROOT / 'src/pocx/test/fuzz/CMakeLists.txt'
    selected_fuzz = set()
    if fuzz_cmake_path.is_file():
        fuzz_cmake = fuzz_cmake_path.read_text()
        reused_fuzz = re.search(r'set\(POCX_REUSED_FUZZ_SOURCES\s+(.*?)\)', fuzz_cmake, re.S)[1]
        selected_fuzz = {'src/test/fuzz/' + name for name in re.findall(r'[\w]+\.cpp', reused_fuzz)}
        selected_fuzz.update(str(path.relative_to(ROOT)) for path in (ROOT / 'src/pocx/test/fuzz').glob('*.cpp')
                             if path.name in fuzz_cmake)
    for source in list(manifest['tests'].values()) + [str(Path(item).relative_to('src/pocx/test')) for item in owned_sources]:
        path = ('test/pocx/' + source) if source in manifest['tests'].values() else 'src/pocx/test/' + source
        if path not in seen:
            inventory.append({'source': path})
            seen.add(path)
    # Match owned adaptations to their actual baseline source; reject ambiguity.
    baseline_paths = [item['source'] for item in inventory if not item['source'].startswith('src/pocx/test/')]
    for replacement in owned_sources:
        if '/adapted/' not in replacement:
            continue
        candidates = [source for source in baseline_paths if Path(source).name == Path(replacement).name]
        if len(candidates) != 1:
            raise ValueError(f'Ambiguous adaptation source: {replacement}: {candidates}')
        replacements[candidates[0]] = replacement
    entries = []
    for entry in inventory:
        source = entry['source']
        entry['upstream'] = UPSTREAM
        entry['baseline_revision'] = BASE
        entry['follow_up'] = 'M2: scenario/case parity; M3: consensus gaps; M4: drift/CI'
        entry['execution'] = 'not run'
        if source.startswith('/'):
            path = wrapper / 'scripts' / source.split('/scripts/', 1)[1]
            entry['source'] = 'wrapper/' + str(path.relative_to(wrapper))
            content = path.read_bytes()
            entry['baseline_revision'] = '4ee7296187e3c4e864457bb5402202c8d1625ce2'
            entry['upstream'] = None
            entry['sha256'] = digest(content)
            mapping = scenarios.get(entry['source'])
            if mapping:
                entry.update(classification='adapted', replacement='test/pocx/' + mapping['destination'],
                             reason='Reviewed scenario/precondition mapping in scenario-parity.json')
                entry['parity_mapping'] = mapping['assertions_and_preconditions']
                entry['source_review_current'] = entry['sha256'] == mapping['source_sha256']
            else:
                entry.update(classification='deferred', reason='Required wrapper migration lacks reviewed parity mapping')
            entry['covered_behavior'] = path.stem
        else:
            baseline = git_content(BASE, source)
            upstream = git_content(UPSTREAM, source)
            entry['baseline_sha256'] = digest(baseline)
            entry['upstream_sha256'] = digest(upstream)
            if source in restorations:
                record = restorations[source]
                entry['upstream_restoration'] = {
                    **record,
                    'current_source_matches_restored_upstream': digest((ROOT / source).read_bytes()) == record['restored_sha256'],
                    'current_replacement_matches_review': digest((ROOT / record['replacement']).read_bytes()) == record['replacement_sha256']}
            entry['classification'] = 'PoCX-specific' if upstream is None else ('reused' if baseline == upstream else 'adapted')
            entry['reason'] = 'Byte comparison against upstream v31.1; reused does not imply PoCX-compatible'
            entry['replacement'] = None
            origins = [original for original, replacement in replacements.items() if replacement == source]
            if origins:
                entry['classification'] = 'adapted'
                entry['reason'] = 'Owned replacement for inventoried upstream behavior'
                entry['adaptation_origins'] = [
                    {'source': original, 'upstream_sha256': digest(git_content(UPSTREAM, original)),
                     'baseline_sha256': digest(git_content(BASE, original))}
                    for original in origins]
            if source in ['src/test/pocx_tests.cpp', 'src/test/pocx_simd_tests.cpp']:
                entry['replacement'] = source.replace('src/test/', 'src/pocx/test/')
            if source in ['src/test/util/mining.cpp', 'src/test/util/setup_common.cpp']:
                entry['replacement'] = source.replace('src/test/util/', 'src/pocx/test/util/')
            if source == 'test/functional/test_framework/test_framework.py':
                entry['replacement'] = 'test/pocx/framework/test_framework.py'
            if source in replacements:
                entry['replacement'] = replacements[source]
                entry['classification'] = 'adapted'
                entry['reason'] = 'PoCX-owned replacement selected by build or staging manifest'
            effective = ROOT / (entry.get('replacement') or source)
            entry['current_sha256'] = digest(effective.read_bytes()) if effective.is_file() else None
            text = (effective.read_bytes() if effective.is_file() else baseline or b'').decode(errors='replace')
            entry['covered_behavior'] = re.findall(r'BOOST_(?:FIXTURE_TEST_SUITE|AUTO_TEST_SUITE)\((\w+)', text) or [Path(source).stem]
            cases = []
            guards = []
            for num, line in enumerate(text.splitlines(), 1):
                if re.match(r'\s*#\s*(if|ifdef|ifndef)\b', line):
                    guards.append({'line': num, 'condition': line.strip()})
                elif re.match(r'\s*#\s*endif\b', line):
                    if guards:
                        guards.pop()
                elif re.match(r'\s*#\s*(else|elif)\b', line) and guards:
                    guards[-1] = {'line': num, 'condition': line.strip(), 'previous': guards[-1]}
                match = re.search(r'BOOST_(?:AUTO|FIXTURE)_TEST_CASE\((\w+)', line)
                if match and guards:
                    cases.append({'case': match[1], 'line': num, 'guards': list(guards)})
            entry['guarded_case_source'] = str(effective.relative_to(ROOT))
            entry['guarded_cases'] = cases
            entry['pocx_conditional_lines'] = [{'line': num, 'text': line.strip()}
                for num, line in enumerate(text.splitlines(), 1)
                if re.match(r'\s*#', line) and 'ENABLE_POCX' in line]
            if '/fuzz/' in source:
                # Include the upstream deserializer registration wrapper. Anchor
                # declarations so its macro body cannot invent a target "name".
                entry['fuzz_targets'] = re.findall(r'^FUZZ_TARGET(?:_DESERIALIZE)?\(\s*(\w+)', text, re.M)
                entry['profile_status'] = ('Selected real target source; corpus/sanitizer execution evidence below'
                    if str(effective.relative_to(ROOT)) in selected_fuzz else
                    'Not selected; applicable upstream fuzz migration remains outstanding')
            elif source in {'test/functional/' + path for path in manifest.get('support_copies', {}).values()}:
                entry['profile_status'] = 'Selected unchanged support module; imported by functional consumers'
            elif source.startswith(('test/functional/', 'test/pocx/functional/')):
                entry['profile_status'] = ('Selected' if Path(source).name in manifest['tests'] or
                    Path(source).name in manifest['reused_tests'] or source in replacements else
                    'Not selected; functional migration remains outstanding')
            elif '/qt/' in source:
                entry['profile_status'] = 'Qt selection: src/qt/test/CMakeLists.txt and src/pocx/test/qt/sources.cmake; execution evidence below'
            elif '/kernel/' in source:
                entry['profile_status'] = ('Optional pocx-kernel CI; all 16 upstream cases retained with independently verified PoCX real-proof fixtures; '
                                           'see test/pocx/kernel/parity.json and provenance.json')
            else:
                entry['profile_status'] = 'Selection: src/pocx/test/sources.cmake; runtime registration/results authoritative'
        entries.append(entry)
    # Execution is independent of source reuse/adaptation classification.
    unit_results = {}
    for profile, paths in [('bitcoin', args.bitcoin_unit_results), ('pocx', args.pocx_unit_results),
                           ('pocx-wallet-disabled', args.pocx_wallet_disabled_results),
                           ('pocx-kernel', args.pocx_kernel_results)]:
        unit_results[profile] = {}
        for path in paths:
            evidence = str(path.resolve().relative_to(ROOT))
            source_record = path.parent / 'results.json'
            source_evidence = {'source_freshness': 'not recorded by this JUnit artifact'}
            if source_record.is_file():
                metadata = json.loads(source_record.read_text())
                if 'test_sources' in metadata:
                    changed = []
                    for name, expected in metadata['test_sources'].items():
                        current = Path(name).resolve()
                        current.relative_to(ROOT)
                        if not current.is_file() or digest(current.read_bytes()) != expected:
                            changed.append(str(current.relative_to(ROOT)))
                    source_evidence = {
                        'source_record': str(source_record.resolve().relative_to(ROOT)),
                        'scope': 'Evaluated unit test sources and selected support/data/build inputs; not full compiler dependency graph',
                        'recorded_sources_match_current': not changed,
                        'changed_since_execution': changed}
            for case in ET.parse(path).getroot().iter('testcase'):
                unit_results[profile][case.attrib['name']] = {
                    'status': 'failed' if case.find('failure') is not None or case.find('error') is not None else
                              'skipped' if case.find('skipped') is not None else 'passed',
                    'evidence': evidence, **source_evidence}
    functional = {'pocx': {}, 'pocx-v2': {}}
    bitcoin_functional = {}
    for path in args.bitcoin_functional_results:
        report = json.loads(path.read_text())
        if report['profile'] != 'bitcoin-functional' or report['build_options']['ENABLE_POCX'] != 'OFF':
            raise ValueError(f'Wrong Bitcoin functional evidence profile: {path}')
        stage = Path(report['bitcoin_functional_staging'])
        stage.resolve().relative_to(ROOT)
        staging = json.loads((stage.parent / 'provenance.json').read_text())
        changed = []
        selected_sources = {}
        legacy_overrides = {'rpc_help.py': 'test/pocx/functional/rpc_help.py',
                            'test_runner.py': 'test/pocx/bitcoin_test_runner.py'}
        replacements = staging['replacements']
        if set(replacements) - set(legacy_overrides.values()):
            raise ValueError(f'Unreviewed Bitcoin functional staging replacements: {replacements}')
        overrides = {name: source for name, source in legacy_overrides.items() if source in replacements}
        for name, recorded in staging['files'].items():
            if not name.startswith('functional/'):
                continue
            filename = name.removeprefix('functional/')
            source = overrides.get(filename, 'test/functional/' + filename)
            selected_sources[filename] = source
            if not (ROOT / source).is_file() or digest((ROOT / source).read_bytes()) != recorded:
                changed.append(source)
        step = next(item for item in report['steps'] if item['name'] == 'functional')
        if step.get('status') == 'running' or step['command'][1] != str(stage / 'test_runner.py'):
            raise ValueError(f'Incomplete or incorrect staged runner evidence: {path}')
        for row in csv.DictReader((path.parent / 'functional.csv').open()):
            if row['test'] == 'ALL':
                continue
            filename = row['test'].split()[0]
            if filename not in selected_sources or row['status'] not in ('Passed', 'Failed', 'Skipped'):
                raise ValueError(f'Unrecognized Bitcoin functional result: {row}')
            bitcoin_functional.setdefault(filename, {})[row['test']] = {
                'status': row['status'].lower(), 'evidence': str(path.resolve().relative_to(ROOT)),
                'executed_source': selected_sources[filename],
                'recorded_tree_matches_current_sources': not changed,
                'changed_since_execution': changed,
            }
    current_tree_sources = {name: str(path.relative_to(ROOT))
                           for name, path in framework_sources(ROOT).items()}
    current_tree_sources.update({name: 'test/pocx/' + path for name, path in manifest['replacements'].items()})
    current_tree_sources.update({name: 'test/functional/' + path for name, path in manifest.get('framework_copies', {}).items()})
    current_tree_sources.update({name: 'test/functional/' + path for name, path in manifest.get('support_copies', {}).items()})
    current_tree_sources.update({name: 'test/pocx/' + path for name, path in manifest.get('support_replacements', {}).items()})
    current_tree_sources.update({name: 'test/pocx/' + path for name, path in manifest['tests'].items()})
    current_tree_sources.update({name: 'test/functional/' + name for name in manifest['reused_tests']})
    for path in args.functional_results:
        report = json.loads(path.read_text())
        recorded_files = report['provenance']['files']
        mismatches = [name for name, record in recorded_files.items()
                      if current_tree_sources.get(name) != record['source'] or
                      not (ROOT / record['source']).is_file() or
                      digest((ROOT / record['source']).read_bytes()) != record['sha256']]
        runner = report['provenance'].get('runner')
        if report['provenance'].get('format_version', 1) >= 2 and (
                not runner or runner.get('source') != 'test/pocx/test_runner.py'):
            raise ValueError('Missing functional runner source attestation')
        if runner and (not (ROOT / runner['source']).is_file() or
                       digest((ROOT / runner['source']).read_bytes()) != runner['sha256']):
            mismatches.append(runner['source'])
        if report['provenance'].get('format_version', 1) >= 3:
            for field, source in [('case_selection', 'test/pocx/functional_cases.py'),
                                  ('upstream_runner', 'test/functional/test_runner.py')]:
                record = report['provenance'].get(field)
                if not record or record.get('source') != source:
                    raise ValueError(f'Missing functional case source attestation: {source}')
                if digest((ROOT / source).read_bytes()) != record['sha256']:
                    mismatches.append(source)
        for mode, result in transport_results(report):
            if result['test'] not in recorded_files:
                raise ValueError(f'Unrecorded functional case source: {result["test"]}')
            functional['pocx' if mode == 'v1' else 'pocx-v2'][result.get('case', result['test'])] = {'status': result['status'],
                'evidence': str(path.resolve().relative_to(ROOT)),
                'test': result['test'],
                'case_arguments': result.get('case_arguments', []),
                'global_transport': mode,
                'test_arguments': result.get('test_arguments', []),
                'skip_reason': result.get('skip_reason'),
                'recorded_tree_matches_current_sources': not mismatches,
                'changed_since_execution': mismatches}
    fuzz_results = {}
    expected_fuzz = (set(json.loads((ROOT / 'test/pocx/fuzz/targets.json').read_text())['targets'])
                     if args.fuzz_results else set())
    for path in args.fuzz_results:
        report = json.loads(path.read_text())
        results = report['results']
        if {result['target'] for result in results} != expected_fuzz or len(results) != len(expected_fuzz):
            raise ValueError(f'Incomplete or mismatched fuzz registration evidence: {path}')
        for result in results:
            if result['total_inputs'] < 1 or result['saved_inputs'] < 1:
                raise ValueError(f'Empty fuzz execution evidence: {path}')
            fuzz_results[result['target']] = {
                'status': result['status'], 'evidence': str(path.resolve().relative_to(ROOT)),
                'scope': report['scope'], 'sanitizers': report['sanitizers'],
                'sanitizer_options': report.get('sanitizer_options', {}),
                'gcov_instrumented': report.get('gcov_instrumented', False),
                'saved_inputs': result['saved_inputs'], 'total_inputs': result['total_inputs'],
                'mutations_per_target': report['mutations_per_target'],
            }
    upstream_selection = upstream_cases(ROOT / 'test/functional/test_runner.py')
    for entry in entries:
        execution = {}
        for profile, results in unit_results.items():
            selected = {suite: results[suite] for suite in entry.get('covered_behavior', []) if suite in results}
            if '/qt/' in entry['source'] and 'test_bitcoin-qt' in results:
                selected['test_bitcoin-qt'] = results['test_bitcoin-qt']
            if '/kernel/' in entry['source'] and 'test_kernel' in results:
                selected['test_kernel'] = {**results['test_kernel'], 'scope': 'Kernel CTest target; inspect retained log for case-level outcomes'}
            if selected:
                execution[profile] = selected
        replacement = Path(entry.get('replacement') or entry['source']).name
        bitcoin_cases = bitcoin_functional.get(Path(entry['source']).name, {})
        if entry['source'].startswith('test/functional/') or any(
                case['executed_source'] == entry['source'] for case in bitcoin_cases.values()):
            if bitcoin_cases:
                execution.setdefault('bitcoin', {}).update(bitcoin_cases)
        for profile, results in functional.items():
            for case, result in results.items():
                if replacement == result['test']:
                    execution.setdefault(profile, {})[case] = result
        if Path(entry['source']).parent in (Path('test/functional'), Path('test/pocx/functional')):
            entry['upstream_functional_cases'] = [
                {**case, 'execution_by_profile': {
                    profile: results[case['id']] for profile, results in functional.items() if case['id'] in results and
                    (not case['upstream_transport'] or
                     f'--{results[case["id"]]["global_transport"]}transport' in case['upstream_transport'])}}
                for case in upstream_selection if case['test'] == replacement]
        if (entry.get('replacement') or entry['source']) in selected_fuzz:
            for target in entry.get('fuzz_targets', []):
                if target in fuzz_results:
                    execution.setdefault('pocx-fuzz', {})[target] = fuzz_results[target]
        entry['execution_by_profile'] = execution
        statuses = {result['status'] for profile in execution.values() for result in profile.values()}
        entry['execution'] = ('failed' if 'failed' in statuses else 'skipped' if 'skipped' in statuses
                              else 'passed' if statuses else 'not run')
    args.output.write_text(json.dumps(entries, indent=2) + '\n')
    print(f'Inventoried {len(entries)} sources; provenance approvals unchanged')


if __name__ == '__main__':
    main()
