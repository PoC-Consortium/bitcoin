#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin PoCX developers
# Distributed under the MIT software license; see COPYING.
"""Build pinned LLVM libc++ and inherited depends in a fresh owned directory."""
import argparse
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile
import urllib.request

sys.dont_write_bytecode = True
from common import ROOT, sha256
from instrumented_ci import dependency_options, installed_inputs, required_archives, specification, tools, verify_dependencies


def prepare(kind, directory, jobs):
    if not directory.is_relative_to(ROOT) or directory == ROOT:
        raise ValueError('Use a separate dependency directory inside this worktree')
    directory.mkdir(exist_ok=False)
    path = directory / 'preparation.json'
    report = {'status': 'failed', 'sanitizer': kind, 'steps': {}, 'scope': __doc__,
              'builder_sha256': sha256(Path(__file__))}
    def save():
        path.write_text(json.dumps(report, indent=2) + '\n')
    def run(name, command):
        log = directory / (name + '.log')
        with log.open('w') as stream:
            execution = subprocess.run(command, cwd=ROOT, stdout=stream, stderr=subprocess.STDOUT)
        report['steps'][name] = {'command': command, 'returncode': execution.returncode, 'log_sha256': sha256(log)}
        save()
        execution.check_returncode()
    try:
        spec = specification(kind)
        report.update(tools=tools(kind), source_sha256=spec['source_sha256'])
        save()
        archive = directory / 'llvm.src.tar.xz'
        with urllib.request.urlopen(spec['llvm']['url'], timeout=60) as response, archive.open('wb') as stream:
            shutil.copyfileobj(response, stream)
        if sha256(archive) != spec['llvm']['sha256']:
            raise ValueError('LLVM source archive SHA256 mismatch')
        report['llvm_archive_sha256'] = sha256(archive)
        extracted = directory / 'llvm-source'
        extracted.mkdir()
        with tarfile.open(archive) as source:
            source.extractall(extracted, filter='data')
        roots = list(extracted.glob('*/runtimes'))
        if len(roots) != 1:
            raise ValueError('Missing or ambiguous LLVM runtime source')
        runtime = directory / 'libcxx'
        options = {**spec['libcxx_options'], 'LLVM_USE_SANITIZER': spec['profiles'][kind]['libcxx_sanitizer'],
                   'CMAKE_C_COMPILER': report['tools']['clang-22']['path'],
                   'CMAKE_CXX_COMPILER': report['tools']['clang++-22']['path']}
        run('libcxx-configure', ['cmake', '-S', str(roots[0]), '-B', str(runtime), '-G', 'Ninja',
                                 *[f'-D{key}={value}' for key, value in options.items()]])
        run('libcxx-build', ['cmake', '--build', str(runtime), '-j', str(jobs)])
        depends = directory / 'depends'
        for name in spec['source_sha256']:
            if not name.startswith('depends/'):
                continue
            destination = directory / name
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(ROOT / name, destination)
        # The inherited native_libmultiprocess recipe uses ../src/ipc relative
        # to depends. This host generator remains the reviewed original source.
        local = directory / 'src/ipc'
        local.mkdir(parents=True)
        (local / 'libmultiprocess').symlink_to(ROOT / 'src/ipc/libmultiprocess', target_is_directory=True)
        host = subprocess.check_output([str(depends / 'config.guess')], text=True).strip()
        if host != 'x86_64-pc-linux-gnu':
            raise ValueError('Required instrumented profile expects Linux x86_64, got ' + host)
        report.update(host=host, prefix=str(depends / host), depends_options=dependency_options(kind, directory))
        run('depends-build', ['make', '-C', str(depends), '-j' + str(jobs), 'HOST=' + host,
                              *report['depends_options']])
        prefix = Path(report['prefix'])
        report['installed_inputs'] = installed_inputs(directory, prefix)
        libraries = required_archives(kind)
        report['archive_instrumentation'] = {}
        for name in libraries:
            library = prefix / 'lib' / name
            symbols = subprocess.check_output([report['tools']['llvm-nm-22']['path'], str(library)], text=True)
            marker = '__tsan_' if kind == 'tsan' else '__msan_'
            if marker not in symbols:
                raise ValueError('Dependency archive lacks required instrumentation: ' + name)
            log = directory / (name + '-symbols.log')
            log.write_text(symbols)
            report['archive_instrumentation'][name] = {'sha256': sha256(library), 'symbols_sha256': sha256(log)}
        report['libcxx_instrumentation'] = {}
        for name in ('libc++.so.1', 'libc++abi.so.1'):
            library = runtime / 'lib' / name
            symbols = subprocess.check_output([report['tools']['llvm-nm-22']['path'], str(library)], text=True)
            if ('__tsan_' if kind == 'tsan' else '__msan_') not in symbols:
                raise ValueError('libc++ runtime lacks required instrumentation: ' + name)
            log = directory / (name + '-symbols.log')
            log.write_text(symbols)
            report['libcxx_instrumentation'][name] = {'sha256': sha256(library), 'symbols_sha256': sha256(log)}
        report['status'] = 'passed'
        save()
        verify_dependencies(kind, directory)
    except (OSError, ValueError, KeyError, subprocess.SubprocessError) as error:
        report.update(status='failed', error=str(error))
        raise
    finally:
        save()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--sanitizer', choices=['tsan', 'msan'], required=True)
    parser.add_argument('--directory', type=Path, required=True)
    parser.add_argument('--jobs', type=int, default=4)
    args = parser.parse_args()
    if args.jobs < 1:
        parser.error('jobs must be positive')
    try:
        prepare(args.sanitizer, args.directory.resolve(), args.jobs)
        return 0
    except (OSError, ValueError, KeyError, subprocess.SubprocessError) as error:
        print(str(error), file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())
