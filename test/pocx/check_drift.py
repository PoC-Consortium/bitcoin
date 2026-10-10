#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin PoCX developers
# Distributed under the MIT software license; see COPYING.
"""Fail for unclassified tests or changes to reviewed upstream source dependencies.

This checks reviewed source inputs, not whether required test execution is green.
Never updates reviewed hashes; inventory generation cannot approve source drift.
"""
import argparse
import hashlib
import json
from pathlib import Path
from functional_cases import selected_cases, selection_digest, upstream_cases

ROOT = Path(__file__).resolve().parents[2]


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def check(root):
    entries = json.loads((root / 'test/pocx/coverage.json').read_text())
    known = {entry['source']: entry for entry in entries}
    restorations = json.loads((root / 'test/pocx/restorations.json').read_text())['files']
    import unit_parity
    import qt_parity
    import kernel_parity
    issues = unit_parity.check(root) + qt_parity.check(root) + kernel_parity.check(root)
    directories = [('src/test', '*.cpp'), ('src/wallet/test', '*.cpp'),
                   ('src/qt/test', '*.cpp'), ('src/test/fuzz', '*.cpp'),
                   ('test/functional', '*.py'), ('test/functional/test_framework', '**/*.py'),
                   ('test/functional/data', '**/*.py'),
                   ('src/test/util', '*'), ('src/test/kernel', '*'),
                   ('src/pocx/test', '**/*.cpp'), ('test/pocx/functional', '*.py')]
    current = {str(path.relative_to(root)) for directory, pattern in directories
               for path in (root / directory).glob(pattern) if path.is_file()}
    known_paths = known.keys() | {entry['replacement'] for entry in entries if entry.get('replacement')}
    for source in sorted(current - known_paths):
        issues.append({'source': source, 'reason': 'new source requires classification'})
    for replacement in sorted(known_paths - known.keys()):
        if not (root / replacement).is_file():
            issues.append({'source': replacement, 'reason': 'inventoried replacement removed'})
    for source, entry in known.items():
        if not any(source.startswith(directory + '/') for directory, _ in directories):
            continue
        path = root / source
        if not path.exists():
            # The two original PoCX-only suites were intentionally moved, not
            # removed. Their replacement must still exist. No general removal waiver.
            if source in ('src/test/pocx_tests.cpp', 'src/test/pocx_simd_tests.cpp') and (root / entry['replacement']).is_file():
                continue
            issues.append({'source': source, 'reason': 'reviewed source removed'})
        elif source in restorations:
            reviewed = restorations[source]
            if (reviewed['upstream_revision'] != entry['upstream'] or
                    reviewed['restored_sha256'] != entry['upstream_sha256']):
                issues.append({'source': source, 'reason': 'restoration record does not match the pinned upstream inventory'})
            if digest(path) != reviewed['restored_sha256']:
                issues.append({'source': source, 'reason': 'restored upstream source changed since replacement parity review'})
            replacement = root / reviewed['replacement']
            if not replacement.is_file() or digest(replacement) != reviewed['replacement_sha256']:
                issues.append({'source': reviewed['replacement'], 'reason': 'replacement changed since upstream restoration parity review'})
        elif entry.get('baseline_sha256') and digest(path) != entry['baseline_sha256']:
            issues.append({'source': source, 'reason': 'source changed since reviewed fork baseline',
                           'replacement': entry.get('replacement')})
    provenance = json.loads((root / 'test/pocx/framework-provenance.json').read_text())
    resources = {str(path.relative_to(root)) for path in
                 (root / 'test/functional/test_framework').rglob('*.csv')}
    reviewed_resources = {source for source in provenance if source.endswith('.csv')}
    for source in sorted(resources ^ reviewed_resources):
        issues.append({'source': source, 'reason': 'framework resource requires review'})
    for source, record in provenance.items():
        path = root / source
        if not path.is_file() or digest(path) != record['reviewed_fork_sha256']:
            issues.append({'source': source, 'reason': 'framework dependency changed since review'})
    vectors = json.loads((root / 'test/pocx/vectors/provenance.json').read_text())
    for source, field in {
        'src/pocx/test/data/real_proof_vectors.json': 'fixture_sha256',
        'test/pocx/vectors/reference.rs': 'generator_sha256',
        'test/pocx/vectors/generate.py': 'driver_sha256',
        'test/pocx/vectors/Cargo.lock': 'cargo_lock_sha256',
    }.items():
        path = root / source
        if not path.is_file() or digest(path) != vectors[field]:
            issues.append({'source': source, 'reason': 'real-proof fixture or generator differs from verified reference provenance'})
    kernel = json.loads((root / 'test/pocx/kernel/provenance.json').read_text())
    for source, expected in {**kernel['sources'], **kernel['reviewed_dependencies']}.items():
        path = root / source
        if not path.is_file() or digest(path) != expected:
            issues.append({'source': source, 'reason': 'kernel adaptation or fixture dependency differs from independently verified provenance'})
    functional = json.loads((root / 'test/pocx/upstream-functional-parity.json').read_text())
    manifest = json.loads((root / 'test/pocx/manifest.json').read_text())
    additions = manifest.get('framework_additions', {})
    reviewed_additions = functional.get('owned_framework_additions', {})
    if set(additions) != set(reviewed_additions):
        issues.append({'source': 'test/pocx/manifest.json', 'reason': 'owned framework additions require review'})
    for destination, record in reviewed_additions.items():
        source = record['source']
        if additions.get(destination) != source.removeprefix('test/pocx/'):
            issues.append({'source': source, 'reason': 'owned framework addition selection changed since review'})
        for dependency, expected in {source: record['sha256'], **record['dependencies']}.items():
            if not (root / dependency).is_file() or digest(root / dependency) != expected:
                issues.append({'source': dependency, 'reason': 'owned framework addition changed since review'})
    clock_sources = {'test/pocx/framework/test_framework.py', 'test/pocx/framework/blocktools.py'}
    reviewed_clocks = functional.get('native_forging_clock', {}).get('sources', {})
    if set(reviewed_clocks) != clock_sources:
        issues.append({'source': 'test/pocx/upstream-functional-parity.json',
                       'reason': 'native forging clock dependency inventory requires review'})
    for source, expected in reviewed_clocks.items():
        path = root / source
        if not path.is_file() or digest(path) != expected:
            issues.append({'source': source, 'reason': 'native forging clock changed since review'})
    execution_sources = {'test/pocx/test_runner.py', 'test/pocx/functional_results.py',
                         'test/pocx/update_inventory.py', 'test/pocx/functional_cases.py',
                         'test/pocx/functional_environment.py',
                         'test/pocx/functional_execution.py',
                         'test/pocx/functional_retention.py',
                         'test/pocx/build_configuration.py',
                         'test/pocx/process_tree.py',
                         'test/pocx/rpc_coverage.py',
                         'test/pocx/stage.py', 'test/pocx/verify_functional.py',
                         'test/pocx/functional-profile-skips.json'}
    reviewed_execution = functional.get('execution_infrastructure', {}).get('sources', {})
    for source in sorted(execution_sources ^ reviewed_execution.keys()):
        issues.append({'source': source, 'reason': 'functional execution infrastructure requires review'})
    for source, expected in reviewed_execution.items():
        path = root / source
        if not path.is_file() or digest(path) != expected:
            issues.append({'source': source, 'reason': 'functional execution infrastructure changed since review'})
    selection = functional.get('case_selection', {})
    source = 'test/functional/test_runner.py'
    if selection.get('upstream_runner_sha256') != digest(root / source):
        issues.append({'source': source, 'reason': 'upstream functional argument selections changed since review'})
    cases = selected_cases(manifest, upstream_cases(root / source))
    if (selection.get('selected_cases') != cases or
            selection.get('selected_cases_sha256') != selection_digest(cases)):
        issues.append({'source': 'test/pocx/manifest.json',
                       'reason': 'functional case selection changed since review'})
    exclusions = functional.get('exclusions', {})
    if exclusions != manifest.get('excluded_tests', {}):
        issues.append({'source': 'test/pocx/manifest.json', 'reason': 'functional exclusions changed since specific review'})
    for name, record in functional['results'].items():
        source = record['source']
        entry = known.get(source, {})
        if (functional['upstream_revision'] != entry.get('upstream') or
                record['source_sha256'] != entry.get('upstream_sha256')):
            issues.append({'source': source, 'reason': 'functional parity record does not match the pinned upstream inventory'})
        replacement = record['replacement']
        selected = ('test/pocx/' + manifest['tests'][name] if name in manifest['tests']
                    else source if name in manifest['reused_tests'] else None)
        expected_selection = None if name in exclusions else (replacement or source)
        if selected != expected_selection:
            issues.append({'source': source, 'reason': 'reviewed functional consumer removed or replaced without parity review'})
        path = root / (replacement or source)
        if not path.is_file() or digest(path) != record['replacement_sha256']:
            issues.append({'source': replacement or source, 'reason': 'functional consumer changed since assertion and precondition parity review'})
        required_dependencies = {
            **{test: {'test/pocx/framework/bpf_abi.py'} for test in (
                'interface_usdt_coinselection.py', 'interface_usdt_mempool.py',
                'interface_usdt_net.py', 'interface_usdt_utxocache.py',
                'interface_usdt_validation.py')},
            'rpc_help.py': {'src/rpc/client.cpp', 'src/pocx/rpc/client_conversion_params.inc'},
            'feature_loadblock.py': {'contrib/linearize/linearize-data.py', 'contrib/linearize/linearize-hashes.py'},
            'feature_versionbits_warning.py': {'src/pocx/rpc/mining.cpp'},
            'mining_basic.py': {'src/pocx/rpc/mining.cpp'},
            'feature_signet.py': {'contrib/signet/miner', 'test/pocx/kernel/provenance.json', 'src/pocx/rpc/mining.cpp', 'src/kernel/chainparams.cpp'},
            'tool_signet_miner.py': {'contrib/signet/miner', 'test/pocx/kernel/provenance.json', 'test/pocx/functional/feature_signet.py'},
            'feature_assumeutxo.py': {'src/kernel/chainparams.cpp', 'src/pocx/consensus/regtest_functional_assumeutxo.inc'},
            'wallet_assumeutxo.py': {'src/kernel/chainparams.cpp', 'src/pocx/consensus/regtest_functional_assumeutxo.inc'},
            'interface_ipc_mining.py': {'src/interfaces/mining.h', 'src/ipc/capnp/mining.capnp',
                                      'src/node/interfaces.cpp'},
            'tool_bitcoin_chainstate.py': {'src/bitcoin-chainstate.cpp',
                'src/pocx/test/tools/chainstate_test_clock.cpp', 'src/pocx/test/tools/CMakeLists.txt',
                'src/pocx/consensus/regtest_functional_assumeutxo.inc'},
            'feature_unsupported_utxo_db.py': {'test/pocx/framework/test_framework.py',
                                             'test/functional/test_framework/test_node.py'},
            'mempool_compatibility.py': {'test/pocx/framework/test_framework.py',
                'test/functional/test_framework/test_node.py', 'test/pocx/framework/blocktools.py',
                'test/functional/test_framework/messages.py'},
            'feature_coinstatsindex_compatibility.py': {'test/pocx/framework/test_framework.py',
                'test/functional/test_framework/test_node.py', 'test/pocx/framework/blocktools.py',
                'test/functional/test_framework/messages.py'},
            'wallet_backwards_compatibility.py': {'test/pocx/framework/test_framework.py',
                'test/functional/test_framework/test_node.py', 'test/pocx/framework/blocktools.py',
                'test/pocx/framework/wallet_compatibility.py', 'test/functional/test_framework/messages.py'},
            'wallet_migration.py': {'test/pocx/framework/test_framework.py',
                'test/functional/test_framework/test_node.py', 'test/pocx/framework/test_node.py',
                'test/pocx/framework/blocktools.py', 'test/pocx/framework/wallet_compatibility.py',
                'test/pocx/framework/wallet_migration_fixtures.py',
                'test/functional/test_framework/messages.py', 'src/rpc/mining.cpp',
                'src/pocx/regtest/forging.cpp'},
        }.get(name, set())
        dependencies = record.get('dependencies', {})
        if set(dependencies) != required_dependencies:
            issues.append({'source': source, 'reason': 'functional consumer dependency inventory requires review'})
        for dependency, expected in dependencies.items():
            path = root / dependency
            if not path.is_file() or digest(path) != expected:
                issues.append({'source': dependency, 'reason': 'functional consumer dependency changed since review'})
    reviewed_support = functional.get('support_copies', {})
    for destination in sorted((manifest.get('support_copies', {}).keys() |
                               manifest.get('support_replacements', {}).keys()) - reviewed_support.keys()):
        issues.append({'source': destination, 'reason': 'functional support resource requires review'})
    for destination, record in reviewed_support.items():
        if manifest.get('support_copies', {}).get(destination) != record['source'].removeprefix('test/functional/'):
            issues.append({'source': record['source'], 'reason': 'reviewed support module removed or replaced without parity review'})
        if not (root / record['source']).is_file() or digest(root / record['source']) != record['source_sha256']:
            issues.append({'source': record['source'], 'reason': 'support module changed since parity review'})
        consumers = record.get('consumers')
        if consumers is not None:
            expected_consumers = {'data/rpc_getblockstats.json': ['rpc_getblockstats.py']}.get(destination)
            if consumers != expected_consumers:
                issues.append({'source': destination, 'reason': 'case-local support dependency requires review'})
        replacement = record.get('replacement')
        selected = manifest.get('support_replacements', {}).get(destination)
        if ('test/pocx/' + selected if selected else None) != replacement:
            issues.append({'source': record['source'], 'reason': 'native support replacement changed since parity review'})
        if replacement and (not (root / replacement).is_file() or digest(root / replacement) != record['replacement_sha256']):
            issues.append({'source': replacement, 'reason': 'native support resource changed since parity review'})
    for source, record in functional.get('framework_replacements', {}).items():
        entry = known.get(source, {})
        if (functional['upstream_revision'] != entry.get('upstream') or
                record['source_sha256'] != entry.get('upstream_sha256')):
            issues.append({'source': source, 'reason': 'framework parity record does not match the pinned upstream inventory'})
        destination = source.removeprefix('test/functional/')
        if (manifest['replacements'].get(destination) != record['replacement'].removeprefix('test/pocx/') or
                manifest.get('framework_copies', {}).get(record['copied_upstream_alias']) != destination):
            issues.append({'source': source, 'reason': 'reviewed framework replacement or upstream alias changed without parity review'})
        for replacement, expected in {record['replacement']: record['replacement_sha256'],
                                      **record['dependencies']}.items():
            path = root / replacement
            if not path.is_file() or digest(path) != expected:
                issues.append({'source': replacement, 'reason': 'native fork fixture or dependency changed since parity review'})
    return issues


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    issues = check(ROOT)
    result = {'scope': 'upstream test inventory, reviewed dependencies and real-proof/kernel fixture provenance; not execution coverage',
              'status': 'review required' if issues else 'passed', 'issues': issues}
    rendered = json.dumps(result, indent=2) + '\n'
    if args.output:
        args.output.write_text(rendered)
    print(rendered, end='')
    return bool(issues)


if __name__ == '__main__':
    raise SystemExit(main())
