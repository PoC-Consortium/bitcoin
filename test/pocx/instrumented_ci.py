#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin PoCX developers
# Distributed under the MIT software license; see COPYING.
"""Required TSAN/MSAN configuration and evidence; never use system libc++ as a fallback."""
import argparse
import json
import os
from pathlib import Path
import re
import resource
import shlex
import shutil
import subprocess
import sys

sys.dont_write_bytecode = True
from common import ROOT, build_options, sha256
from sanitizer_ci import required_binaries, VENDORED

CANARIES = {
    'tsan': {
        'clean': ('#include <thread>\n#include <mutex>\nint value; std::mutex lock;\n'
                  'void write() { std::lock_guard<std::mutex> guard(lock); ++value; }\n'
                  'int main() { std::thread t(write); write(); t.join(); return value != 2; }\n', []),
        'race': ('#include <thread>\nvolatile int value;\n'
                 'void CanaryRaceWrite() { for (int i = 0; i < 1000; ++i) value = i; }\n'
                 'int main() { std::thread t(CanaryRaceWrite); CanaryRaceWrite(); t.join(); return 0; }\n',
                 ['ThreadSanitizer: data race']),
    },
    'msan': {
        'clean': ('#include <vector>\nint main() { std::vector<int> v(2, 7); return v[1] != 7; }\n', []),
        'uninitialized': ('#include <cstdlib>\n__attribute__((noinline)) int read(volatile int* p) { return *p; }\n'
                          'int main() { volatile int* p = static_cast<int*>(std::malloc(sizeof(int))); '
                          'int n = read(p); std::free(const_cast<int*>(p)); return n == 123; }\n',
                          ['MemorySanitizer: use-of-uninitialized-value',
                           'Uninitialized value was created by a heap allocation']),
    },
}


def specification(kind, root=ROOT):
    if kind not in CANARIES:
        raise ValueError('Unknown instrumented sanitizer')
    spec = json.loads((root / 'test/pocx/instrumented-ci.json').read_text())
    for name, digest in spec['source_sha256'].items():
        if sha256(root / name) != digest:
            raise ValueError('Instrumented dependency recipe changed since review: ' + name)
    return spec


def tools(kind, root=ROOT):
    specification(kind, root)
    result = {}
    for name in ('clang-22', 'clang++-22', 'llvm-symbolizer-22', 'llvm-nm-22'):
        path = shutil.which(name)
        if path is None:
            raise ValueError('Missing required sanitizer tool: ' + name)
        version = subprocess.check_output([path, '--version'], text=True)
        if not re.search(r'\bversion\s+22\.', version):
            raise ValueError('Wrong required sanitizer tool version: ' + name)
        result[name] = {'path': path, 'sha256': sha256(Path(path)), 'version': version}
    return result


def dependency_flags(kind, directory):
    flags = ['-nostdinc++', '-nostdlib++', '-isystem', str(directory / 'libcxx/include/c++/v1'),
             '-L' + str(directory / 'libcxx/lib'), '-Wl,-rpath,' + str(directory / 'libcxx/lib'),
             '-lc++', '-lc++abi', '-lpthread', '-Wno-unused-command-line-argument']
    memory = ['-fsanitize=memory', '-fsanitize-memory-track-origins=2', '-fno-omit-frame-pointer',
              '-g', '-O1', '-fno-optimize-sibling-calls']
    return (' '.join(memory) if kind == 'msan' else '',
            shlex.join((memory if kind == 'msan' else ['-fsanitize=thread']) + flags))


def dependency_options(kind, directory):
    cflags, cxxflags = dependency_flags(kind, directory)
    result = ['NO_QT=1', 'CC=clang-22', 'CXX=clang++-22', 'CXXFLAGS=' + cxxflags, 'LOG=1']
    if kind == 'msan':
        result += ['DEBUG=1', 'CFLAGS=' + cflags]
    return result


def required_options(kind, directory, root=ROOT):
    spec = specification(kind, root)
    cflags, cxxflags = dependency_flags(kind, directory)
    manifest = json.loads((directory / 'preparation.json').read_text())
    prefix = Path(manifest['prefix'])
    return {**spec['build_options'], **spec['profiles'][kind]['build_options'],
            'CMAKE_C_COMPILER': 'clang-22', 'CMAKE_CXX_COMPILER': 'clang++-22',
            'CMAKE_C_FLAGS': cflags, 'CMAKE_CXX_FLAGS': cxxflags,
            'CMAKE_TOOLCHAIN_FILE': str(prefix / 'toolchain.cmake'),
            'SANITIZERS': 'thread' if kind == 'tsan' else 'memory'}


def runtime_environment(kind, directory, root=ROOT):
    spec = specification(kind, root)
    manifest = json.loads((directory / 'preparation.json').read_text())
    return {**{key: value.format(root=root) for key, value in spec['profiles'][kind]['runtime_environment'].items()},
            'LD_LIBRARY_PATH': str(Path(manifest['prefix']) / 'lib') + ':' + str(directory / 'libcxx/lib')}


def installed_inputs(directory, prefix):
    paths = {prefix / 'toolchain.cmake', directory / 'libcxx/CMakeCache.txt',
             directory / 'libcxx/build.ninja', directory / 'libcxx/CMakeFiles/rules.ninja'}
    for tree in (prefix, directory / 'libcxx/include', directory / 'libcxx/lib'):
        paths.update(path for path in tree.rglob('*') if path.is_file())
    if any(not path.is_file() for path in paths):
        raise ValueError('Missing instrumented dependency inputs')
    return {str(path): sha256(path) for path in sorted(paths)}


def verify_dependencies(kind, directory, root=ROOT):
    spec = specification(kind, root)
    path = directory / 'preparation.json'
    report = json.loads(path.read_text())
    if (report.get('status') != 'passed' or report.get('sanitizer') != kind or
            report.get('source_sha256') != spec['source_sha256'] or
            report.get('llvm_archive_sha256') != spec['llvm']['sha256'] or
            report.get('depends_options') != dependency_options(kind, directory)):
        raise ValueError('Missing, stale or wrong instrumented dependency preparation')
    if (report.get('builder_sha256') != sha256(root / 'test/pocx/prepare_instrumented_dependencies.py') or
            sha256(directory / 'llvm.src.tar.xz') != spec['llvm']['sha256']):
        raise ValueError('Instrumented dependency builder or LLVM archive changed')
    prefix = Path(report['prefix'])
    if not prefix.is_relative_to(directory / 'depends') or prefix.name != report['host']:
        raise ValueError('Instrumented dependency prefix belongs to a different preparation')
    if report.get('installed_inputs') != installed_inputs(directory, prefix):
        raise ValueError('Instrumented dependency inputs changed after preparation')
    for name, row in report['steps'].items():
        log = directory / (name + '.log')
        if row.get('returncode') != 0 or row.get('log_sha256') != sha256(log):
            raise ValueError('Instrumented dependency build did not pass: ' + name)
    if set(report['steps']) != {'libcxx-configure', 'libcxx-build', 'depends-build'}:
        raise ValueError('Incomplete instrumented dependency build steps')
    cache = build_options((directory / 'libcxx/CMakeCache.txt').read_text())
    for name, expected in spec['libcxx_options'].items():
        if cache.get(name) != expected:
            raise ValueError('Wrong instrumented libc++ setting: ' + name)
    if cache.get('LLVM_USE_SANITIZER') != spec['profiles'][kind]['libcxx_sanitizer']:
        raise ValueError('Wrong libc++ sanitizer')
    current_tools = tools(kind, root)
    if report.get('tools') != current_tools:
        raise ValueError('Instrumented dependency compiler changed')
    # These archives are built by the inherited depends recipes. Native code
    # generators are host tools, not libraries linked into the tested programs.
    expected = ['libcapnp.a', 'libkj.a', 'libzmq.a']
    if kind == 'msan':
        expected += ['libevent.a', 'libsqlite3.a']
    archives = report.get('archive_instrumentation', {})
    if set(archives) != set(expected):
        raise ValueError('Incomplete instrumented dependency archive inventory')
    for name, row in archives.items():
        path = prefix / 'lib' / name
        log = directory / (name + '-symbols.log')
        marker = '__tsan_' if kind == 'tsan' else '__msan_'
        if row.get('sha256') != sha256(path) or row.get('symbols_sha256') != sha256(log) or marker not in log.read_text():
            raise ValueError('Missing dependency sanitizer instrumentation: ' + name)
    libraries = report.get('libcxx_instrumentation', {})
    if set(libraries) != {'libc++.so.1', 'libc++abi.so.1'}:
        raise ValueError('Missing instrumented libc++ runtime inventory')
    for name, row in libraries.items():
        log = directory / (name + '-symbols.log')
        library = directory / 'libcxx/lib' / name
        if (row.get('sha256') != sha256(library) or row.get('symbols_sha256') != sha256(log) or
                ('__tsan_' if kind == 'tsan' else '__msan_') not in log.read_text()):
            raise ValueError('libc++ runtime instrumentation missing or changed: ' + name)
    return {'status': 'passed', 'report': str(directory / 'preparation.json'), 'report_sha256': sha256(directory / 'preparation.json'),
            'scope': 'Instrumented libc++ and inherited depends preparation; native generators and Rust sanitizer coverage not inferred.'}


def compile_commands(text, kind, directory, build, root=ROOT):
    records = {}
    required = shlex.split(dependency_flags(kind, directory)[1])
    sanitizer = 'thread' if kind == 'tsan' else 'memory'
    for line in text.splitlines():
        tokens = shlex.split(line)
        if '-c' not in tokens or '-o' not in tokens:
            continue
        source = (build / tokens[tokens.index('-c') + 1]).resolve()
        if source.suffix not in ('.cpp', '.cc') or not source.is_relative_to(root / 'src'):
            continue
        if source.relative_to(root / 'src').parts[0] in VENDORED:
            continue
        if (not any(Path(token).name == 'clang++-22' for token in tokens[:tokens.index('-c')]) or
                any(token not in tokens for token in required) or
                any(token.startswith(('-fno-sanitize', '-fsanitize-recover=')) for token in tokens) or
                any(token != '-fsanitize=' + sanitizer for token in tokens if token.startswith('-fsanitize='))):
            raise ValueError('Missing or weakened instrumented compile flags: ' + str(source))
        if kind == 'msan' and ('-U_FORTIFY_SOURCE' not in tokens or
                [token for token in tokens if token.startswith('-fsanitize-memory-track-origins=')][-1:] != ['-fsanitize-memory-track-origins=2']):
            raise ValueError('Missing MSAN origins/fortify controls')
        if kind == 'tsan' and any(token not in tokens for token in ('-DARENA_DEBUG', '-DDEBUG_LOCKCONTENTION', '-D_LIBCPP_REMOVE_TRANSITIVE_INCLUDES')):
            raise ValueError('Missing upstream TSAN debug controls')
        records.setdefault(str(source), []).append(line)
    if not records:
        raise ValueError('No instrumented first-party compile commands')
    return records


def execute(build, kind, directory, output):
    stack_limit = resource.getrlimit(resource.RLIMIT_STACK)[0]
    if stack_limit != specification(kind)['stack_limit_bytes']:
        raise ValueError('Required instrumented runtime stack limit is missing')
    dependency_proof = verify_dependencies(kind, directory)
    toolchain = tools(kind)
    cache = build_options((build / 'CMakeCache.txt').read_text())
    for key, expected in required_options(kind, directory).items():
        actual = cache.get(key)
        if key in ('CMAKE_C_COMPILER', 'CMAKE_CXX_COMPILER'):
            matches = actual and Path(actual).resolve() == Path(toolchain[expected]['path']).resolve()
        else:
            matches = actual == expected
        if not matches:
            raise ValueError('Wrong instrumented build setting: ' + key)
    commands = compile_commands(subprocess.check_output(['ninja', '-C', str(build), '-t', 'commands'], text=True),
                                kind, directory, build)
    binaries = {}
    symbols = output / 'symbols'
    symbols.mkdir(parents=True, exist_ok=True)
    for name in required_binaries(cache['ENABLE_POCX'] == 'ON'):
        if name == 'test_bitcoin-qt':
            continue
        path = build / 'bin' / name
        text = subprocess.check_output([toolchain['llvm-nm-22']['path'], str(path)], text=True)
        if ('__tsan_init' if kind == 'tsan' else '__msan_init') not in text:
            raise ValueError('Executable lacks required instrumentation: ' + name)
        log = symbols / (name + '-symbols.log')
        log.write_text(text)
        binaries[name] = {'sha256': sha256(path), 'symbols_sha256': sha256(log), 'symbols_log': str(log)}
    canaries = []
    environment = runtime_environment(kind, directory)
    folder = output / 'canaries'
    folder.mkdir(exist_ok=True)
    for name, (source, diagnostics) in CANARIES[kind].items():
        cpp, binary = folder / (name + '.cpp'), folder / name
        cpp.write_text(source)
        command = [toolchain['clang++-22']['path'], *shlex.split(dependency_flags(kind, directory)[1]),
                   '-O1', '-g', '-std=c++20', str(cpp), '-o', str(binary)]
        with (folder / (name + '-build.log')).open('w') as stream:
            subprocess.run(command, stdout=stream, stderr=subprocess.STDOUT, check=True)
        run = subprocess.run([str(binary)], capture_output=True, text=True,
                             env={**os.environ, **environment}, timeout=60)
        log = folder / (name + '.log')
        log.write_text(run.stdout + run.stderr)
        accepted = ((run.returncode != 0 and all(value in log.read_text() for value in diagnostics)) if diagnostics
                    else run.returncode == 0 and 'Sanitizer' not in log.read_text() and 'runtime error:' not in log.read_text())
        canaries.append({'canary': name, 'status': 'passed' if accepted else 'failed', 'returncode': run.returncode,
                         'expected_diagnostics': diagnostics, 'command': command, 'source_sha256': sha256(cpp),
                         'binary_sha256': sha256(binary), 'log': str(log), 'log_sha256': sha256(log)})
    return {'dependency_proof': dependency_proof, 'environment': environment, 'stack_limit': stack_limit,
            'instrumentation': {'compile_commands': commands, 'binaries': binaries}, 'canaries': canaries}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--sanitizer', choices=list(CANARIES), required=True)
    selection = parser.add_mutually_exclusive_group(required=True)
    selection.add_argument('--check-tools', action='store_true')
    selection.add_argument('--verify-dependencies', action='store_true')
    selection.add_argument('--build-dir', type=Path)
    parser.add_argument('--directory', type=Path)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if not args.check_tools and args.directory is None:
        parser.error('--directory is required for dependency/runtime verification')
    report = {'status': 'failed', 'scope': __doc__, 'sanitizer': args.sanitizer}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    try:
        report['tools'] = tools(args.sanitizer)
        directory = args.directory.resolve() if args.directory else None
        if directory is not None and (not directory.is_relative_to(ROOT) or directory == ROOT):
            raise ValueError('Instrumented dependencies must belong to this worktree')
        if args.verify_dependencies:
            report['dependency_proof'] = verify_dependencies(args.sanitizer, directory)
        if args.build_dir:
            build = args.build_dir.resolve()
            if not build.is_relative_to(ROOT) or build == ROOT:
                raise ValueError('Instrumented build must belong to this worktree')
            report.update(execute(build, args.sanitizer, directory, args.output.parent))
            if any(row['status'] != 'passed' for row in report['canaries']):
                raise ValueError('Required instrumented sanitizer runtime controls failed')
        report['status'] = 'passed'
        return 0
    except (OSError, ValueError, KeyError, subprocess.SubprocessError) as error:
        report['error'] = str(error)
        print(str(error), file=sys.stderr)
        return 1
    finally:
        args.output.write_text(json.dumps(report, indent=2) + '\n')


if __name__ == '__main__':
    sys.exit(main())
