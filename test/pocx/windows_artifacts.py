#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin PoCX developers
# Distributed under the MIT software license; see COPYING.
"""Export and verify paired Windows cross-build payloads without running PE files.

Checksums bind the CI-produced payload to its source/configuration; they are not
a signature or evidence that any test was executed. Consumers keep payloads
unchanged and place runtime reports and relocated functional views elsewhere.
"""
import argparse
import json
from pathlib import Path, PurePosixPath
import shutil
import struct
import subprocess
import tempfile

from common import ROOT, sha256
import build_configuration
from ci_evidence import source_snapshot, build_snapshot, require_unchanged
import record_cross_unit
import unit_matrix

AUXILIARY = ('src/secp256k1/bin/exhaustive_tests.exe', 'src/secp256k1/bin/noverify_tests.exe',
             'src/secp256k1/bin/tests.exe', 'src/univalue/object.exe', 'src/univalue/unitester.exe')
FUNCTIONAL_SUPPORT = ('test/config.ini.in', 'share/rpcauth/rpcauth.py',
                      'test/get_previous_releases.py', 'test/download_utils.py')
UPSTREAM_RECIPE_SHA256 = '3d67e51113cb3edd9c24a6714d8393510c7b5d8d6a7bb8fed43a6911efd3fcc3'
REVIEW_SOURCES = {'.github/ci-windows-cross.py', 'src/pocx/test/CMakeLists.txt',
    'test/pocx/rpc_coverage.py', 'test/pocx/test_rpc_coverage.py',
    'test/pocx/windows_artifacts.py', 'test/pocx/test_windows_artifacts.py',
    'test/pocx/record_cross_unit.py', 'test/pocx/test_cross_unit.py',
    'test/pocx/unit_matrix.py', 'test/pocx/unit_parity.py', 'test/pocx/unit_build.py',
    'test/pocx/build_configuration.py', 'test/pocx/ci_evidence.py', 'src/CMakeLists.txt',
    'test/pocx/test_processor_configuration.py', 'test/pocx/windows_artifact_unit.py',
    'test/pocx/test_windows_artifact_unit.py', 'test/pocx/process_tree.py', 'test/pocx/unit_assets.py',
    'test/pocx/windows_artifact_tests.py', 'test/pocx/test_windows_artifact_tests.py',
    'test/pocx/run_qt.py', 'test/pocx/test_qt_infrastructure.py', 'test/pocx/qt_parity.py',
    'test/pocx/kernel_parity.py', 'test/pocx/test_cross_kernel.py', 'src/pocx/test/kernel/CMakeLists.txt',
    'test/pocx/kernel/provenance.json', 'test/pocx/kernel-parity.json', 'test/pocx/kernel/fixtures.json',
    'test/pocx/artifact_functional_view.py', 'test/pocx/test_artifact_functional_view.py',
    'test/pocx/windows_artifact_functional.py', 'test/pocx/test_windows_artifact_functional.py',
    'test/pocx/windows_artifact_ci.py', 'test/pocx/test_windows_artifact_ci.py',
    'test/pocx/inherited_functional.py', 'test/pocx/test_inherited_ci.py',
    'test/pocx/functional_environment.py', 'test/pocx/functional_cases.py',
    'test/pocx/functional_results.py', 'test/pocx/run_bitcoin_functional.py',
    'test/pocx/verify_functional.py', 'test/pocx/stage.py', 'test/pocx/manifest.json',
    'test/pocx/upstream-functional-parity.json', 'test/pocx/windows_cross.py', 'test/pocx/test_windows_cross.py',
    'test/pocx/inherited_ci.py', 'test/pocx/inherited-ci.json', '.github/workflows/ci.yml',
    'ci/test/02_run_container.py', 'ci/test/00_setup_env_win64.sh', 'ci/test/00_setup_env_win64_msvcrt.sh',
    'test/get_previous_releases.py', 'test/download_utils.py'}


def verify_recipe(root=ROOT):
    review = json.loads((root / 'test/pocx/windows-artifacts.json').read_text())
    if (set(review['source_sha256']) != REVIEW_SOURCES or
            review['source_sha256']['.github/ci-windows-cross.py'] != UPSTREAM_RECIPE_SHA256):
        raise ValueError('Incomplete cross-artifact review or changed original Windows recipe')
    for name, digest in review['source_sha256'].items():
        if sha256(root / name) != digest:
            raise ValueError('Windows cross-artifact source changed without review: ' + name)
    return review


def relative_name(name):
    if not isinstance(name, str) or not name or '\\' in name or ':' in name:
        raise ValueError('Invalid Windows artifact relative path')
    path = PurePosixPath(name)
    if path.is_absolute() or name == '.' or '..' in path.parts or str(path) != name:
        raise ValueError('Non-canonical Windows artifact relative path')
    return path


def pe_machine(path):
    with path.open('rb') as stream:
        header = stream.read(64)
        if len(header) != 64 or header[:2] != b'MZ':
            raise ValueError('Not a Windows PE artifact: ' + str(path))
        stream.seek(struct.unpack_from('<I', header, 60)[0])
        coff = stream.read(6)
    if len(coff) != 6 or coff[:4] != b'PE\0\0':
        raise ValueError('Invalid Windows PE artifact: ' + str(path))
    return struct.unpack_from('<H', coff, 4)[0]


def portable_inventory(inventory):
    return {key: sorted(value) if isinstance(value, set) else value for key, value in inventory.items()}


def revision_id(root):
    return subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=root, text=True).strip()


def functional_support(root):
    result = {}
    for name in FUNCTIONAL_SUPPORT:
        path = root / name
        if path.is_symlink() or not path.is_file():
            raise ValueError('Missing or symlinked functional support input: ' + name)
        result[name] = sha256(path)
    return result


def write_json(path, value):
    path.write_text(json.dumps(value, indent=2) + '\n')


def validate_configuration(options, system):
    if (options.get('target_system') != 'Windows' or
            str(options.get('target_processor', '')).lower() not in ('x86_64', 'amd64') or
            'set(CMAKE_CROSSCOMPILING "TRUE")' not in system.read_text() or options.get('BUILD_TESTS') != 'ON'):
        raise ValueError('Artifact profile requires an x86_64 Windows cross-build with unit tests')


def required_files(options, consensus):
    if consensus not in ('bitcoin', 'pocx'): raise ValueError('Unknown Windows artifact consensus')
    unit = 'test_bitcoin.exe' if consensus == 'bitcoin' else 'test_pocx.exe'
    required = {'bin/bitcoind.exe', 'bin/' + unit, *AUXILIARY}
    switches = {'BUILD_CLI': 'bitcoin-cli.exe', 'BUILD_TX': 'bitcoin-tx.exe', 'BUILD_UTIL': 'bitcoin-util.exe',
                'BUILD_WALLET_TOOL': 'bitcoin-wallet.exe', 'BUILD_UTIL_CHAINSTATE': 'bitcoin-chainstate.exe',
                'BUILD_BENCH': 'bench_bitcoin.exe', 'BUILD_KERNEL_TEST': 'test_kernel.exe'}
    for switch, binary in switches.items():
        if options.get(switch) == 'ON': required.add('bin/' + binary)
    if options.get('BUILD_GUI') == 'ON' and options.get('BUILD_GUI_TESTS') == 'ON':
        required.add('bin/test_bitcoin-qt.exe')
    return required, 'bin/' + unit


def matching_configurations(phases):
    """A baseline must use the native phase's feature, target and compiler profile."""
    original, native = (row['build_options'] for row in phases)
    keys = {key for key in original.keys() | native.keys() if
        key.startswith(('BUILD_', 'ENABLE_', 'WITH_', 'SECP256K1_')) or
        key.startswith(('CMAKE_C_FLAGS', 'CMAKE_CXX_FLAGS', 'CMAKE_EXE_LINKER_FLAGS',
                        'CMAKE_SHARED_LINKER_FLAGS', 'CMAKE_MODULE_LINKER_FLAGS')) or
        key in ('CMAKE_BUILD_TYPE', 'CMAKE_C_COMPILER', 'CMAKE_CXX_COMPILER',
                'CMAKE_CONFIGURATION_TYPES', 'target_system', 'target_processor', 'avx2_compiled')}
    keys.discard('ENABLE_POCX')
    differences = sorted(key for key in keys if original.get(key) != native.get(key))
    if differences: raise ValueError('Original/native artifact configurations differ: ' + ', '.join(differences))


def export_phase(build, destination, consensus, root):
    cache = build / 'CMakeCache.txt'
    build_configuration.require_source(cache.read_text(), root)
    build_configuration.configuration(cache.read_text())  # Current MinGW profiles are single-config.
    options, system = unit_matrix.configuration(build)
    validate_configuration(options, system)
    expected = portable_inventory(unit_matrix.inventory(root, options, bitcoin=consensus == 'bitcoin'))
    required, unit = required_files(options, consensus)
    for name in required:
        if not (build / name).is_file(): raise ValueError('Missing required Windows artifact: ' + name)
    selected = {path for path in (build / 'bin').iterdir() if path.suffix.lower() in ('.exe', '.dll')}
    selected.update(build / name for name in AUXILIARY)
    files = {}
    def copy(path, name):
        relative_name(name)
        if path.is_symlink() or not path.is_file():
            raise ValueError('Missing or symlinked Windows artifact input: ' + str(path))
        target = destination / name
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(path, target)
        files[name] = sha256(target)
        if files[name] != sha256(path): raise ValueError('Windows artifact changed during export')
    for path in sorted(selected):
        if pe_machine(path) != 0x8664: raise ValueError('Windows artifact machine differs from x86_64 target')
        copy(path, path.relative_to(build).as_posix())
    copy(cache, 'provenance/CMakeCache.txt')
    copy(system, 'provenance/' + system.relative_to(build).as_posix())
    copy(build / 'test/config.ini', 'test/config.ini')
    unit_sources = {}
    if consensus == 'pocx':
        inputs = build / 'src/pocx/test/unit-inputs.txt'
        record = build / 'src/pocx/test/cross-build.json'
        current = record_cross_unit.snapshot(build / unit, inputs, cache, root)
        if json.loads(record.read_text()) != current:
            raise ValueError('Stale Windows cross-unit build provenance')
        copy(record, 'provenance/cross-unit.json')
        copy(inputs, 'provenance/unit-inputs.txt')
        for name, digest in current['sources'].items():
            if name.startswith('source/'):
                unit_sources[name[len('source/'):]] = digest
            elif name.startswith('build/'):
                copy(build / name[len('build/'):], 'provenance/generated/' + name[len('build/'):])
            else: raise ValueError('Unknown cross-unit input namespace')
    if len({name.casefold() for name in files}) != len(files):
        raise ValueError('Case-colliding Windows artifact paths')
    return {'consensus': consensus, 'build_options': options, 'unit_binary': unit,
            'expected_unit': expected, 'unit_source_sha256': unit_sources, 'files': files,
            'execution_status': 'not executed; target-host unit discovery and assertions required'}


def export_pair(bitcoin_build, pocx_build, output, *, root=ROOT, revision=None):
    root = root.resolve()
    builds = [bitcoin_build.resolve(), pocx_build.resolve()]
    if builds[0] == builds[1] or output.exists():
        raise ValueError('Use distinct original/native builds and a new artifact destination')
    for build in builds:
        if build == root or not build.is_relative_to(root):
            raise ValueError('Cross-build source and binary trees must share this worktree')
    sources = source_snapshot(root)
    support = functional_support(root)
    before = [build_snapshot(build) for build in builds]
    revision = revision_id(root) if revision is None else revision
    if not isinstance(revision, str) or len(revision) != 40 or any(c not in '0123456789abcdef' for c in revision):
        raise ValueError('Missing immutable source revision')
    output.parent.mkdir(parents=True, exist_ok=True)
    temporary = Path(tempfile.mkdtemp(prefix='pocx-windows-export-', dir=output.parent))
    try:
        report = {'format': 1, 'kind': 'pocx-windows-cross-pair', 'revision': revision,
                  'source_snapshot': sources, 'functional_support_sha256': support,
                  'phases': [], 'execution_status': 'not executed'}
        for consensus, build in zip(('bitcoin', 'pocx'), builds):
            report['phases'].append(export_phase(build, temporary / consensus, consensus, root))
        for build, snapshot in zip(builds, before):
            require_unchanged('Cross-build inputs', snapshot, build_snapshot(build))
        require_unchanged('Cross-build source inputs', sources, source_snapshot(root))
        require_unchanged('Cross-build functional support inputs', support, functional_support(root))
        write_json(temporary / 'pair.json', report)
        verify_pair(temporary, root=root, revision=revision)
        temporary.rename(output)
    except BaseException:
        shutil.rmtree(temporary)
        raise
    return report


def verify_pair(bundle, *, root=ROOT, revision=None):
    if bundle.is_symlink(): raise ValueError('Symlinked Windows artifact bundle')
    report = json.loads((bundle / 'pair.json').read_text())
    revision = revision_id(root) if revision is None else revision
    if (report.get('format') != 1 or report.get('kind') != 'pocx-windows-cross-pair' or
            report.get('revision') != revision or report.get('execution_status') != 'not executed' or
            [row['consensus'] for row in report['phases']] != ['bitcoin', 'pocx']):
        raise ValueError('Missing, reordered or wrong-revision Windows artifact pair')
    require_unchanged('Artifact source inputs', report['source_snapshot'], source_snapshot(root))
    require_unchanged('Artifact functional support inputs', report.get('functional_support_sha256'), functional_support(root))
    matching_configurations(report['phases'])
    all_files = {'pair.json'}
    for row in report['phases']:
        phase = bundle / row['consensus']
        for name, digest in row['files'].items():
            relative_name(name)
            path = phase / name
            if path.is_symlink() or not path.is_file() or sha256(path) != digest:
                raise ValueError('Missing, changed or symlinked Windows artifact: ' + name)
            all_files.add(row['consensus'] + '/' + name)
            if path.suffix.lower() in ('.exe', '.dll') and pe_machine(path) != 0x8664:
                raise ValueError('Wrong Windows artifact architecture')
        options, system = unit_matrix.configuration(phase / 'provenance')
        validate_configuration(options, system)
        build_configuration.configuration((phase / 'provenance/CMakeCache.txt').read_text())
        if row['build_options'] != options:
            raise ValueError('Artifact metadata differs from recorded compiler configuration')
        required, unit = required_files(options, row['consensus'])
        if row['unit_binary'] != unit or not required.issubset(row['files']):
            raise ValueError('Incomplete required Windows artifact binary selection')
        expected = portable_inventory(unit_matrix.inventory(root, options, bitcoin=row['consensus'] == 'bitcoin'))
        if row['expected_unit'] != expected:
            raise ValueError('Windows artifact unit inventory differs from current reviewed configuration')
        for name, digest in row['unit_source_sha256'].items():
            relative_name(name)
            if sha256(root / name) != digest: raise ValueError('Stale cross-unit source: ' + name)
        if row['consensus'] == 'pocx':
            native = json.loads((phase / 'provenance/cross-unit.json').read_text())
            if (native.get('format') != 1 or native.get('kind') != 'windows-cross-unit-inputs' or
                    'runtime_inventory' not in native or native['runtime_inventory'] is not None or not native['sources'] or
                    native.get('execution_status') != 'not executed; runtime discovery required on target host' or
                    native['binary_sha256'] != row['files'][row['unit_binary']] or
                    native['cache_sha256'] != row['files']['provenance/CMakeCache.txt'] or
                    native['input_manifest_sha256'] != row['files']['provenance/unit-inputs.txt'] or
                    native['target_system_sha256'] != sha256(system) or native['build_options'] != options):
                raise ValueError('Incomplete native cross-unit input provenance')
            for name, digest in native['sources'].items():
                relative_name(name)
                if name.startswith('source/'):
                    if row['unit_source_sha256'].get(name[len('source/'):]) != digest:
                        raise ValueError('Missing cross-unit source input proof')
                elif name.startswith('build/'):
                    if row['files'].get('provenance/generated/' + name[len('build/'):]) != digest:
                        raise ValueError('Missing cross-unit generated input proof')
                else: raise ValueError('Unknown cross-unit input namespace')
    paths = list(bundle.rglob('*'))
    if (len({name.casefold() for name in all_files}) != len(all_files) or any(path.is_symlink() for path in paths) or
            {path.relative_to(bundle).as_posix() for path in paths if path.is_file()} != all_files):
        raise ValueError('Unexpected, missing or symlinked Windows artifact payload files')
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--bitcoin-build', type=Path)
    parser.add_argument('--pocx-build', type=Path)
    parser.add_argument('--output', type=Path)
    parser.add_argument('--verify', type=Path)
    args = parser.parse_args()
    verify_recipe()
    if args.verify:
        if any((args.bitcoin_build, args.pocx_build, args.output)): parser.error('Choose export or verification')
        report = verify_pair(args.verify)
    else:
        if not all((args.bitcoin_build, args.pocx_build, args.output)): parser.error('Export requires both builds and output')
        report = export_pair(args.bitcoin_build, args.pocx_build, args.output)
    print(json.dumps({'status': 'artifact inputs verified; tests not executed', 'revision': report['revision']}))


if __name__ == '__main__':
    main()
