#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin PoCX developers
# Distributed under the MIT software license; see COPYING.
"""Verify the required upstream ASan toolchain, instrumentation and fatal errors.

Runtime canaries validate the sanitizer controls; they are not Bitcoin/PoCX test
cases. Full framework selections remain independently required by ci.py.
"""
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

import pocx_bootstrap as pocx_bootstrap
from common import ROOT, build_options, sha256

CANARIES = {
    'clean': ('volatile int* p = new int[1]; p[0] = argc; delete[] p; return 0;', None),
    'address': ('volatile int* p = new int[1]; p[argc] = 7; delete[] p; return 0;', 'AddressSanitizer: heap-buffer-overflow'),
    'integer': ('volatile unsigned int n = ~0u; volatile unsigned int r = n + argc; return r;', 'unsigned integer overflow'),
    'undefined': ('volatile int n = 2147483647; volatile int r = n + argc; return r;', 'signed integer overflow'),
    'float_divide': ('volatile float z = 0; volatile float r = argc / z; return r == 0;', 'division by zero'),
    'leak': ('volatile int* p = new int[argc]; p[0] = argc; return 0;', 'LeakSanitizer: detected memory leaks'),
}
VENDORED = {'crc32c', 'leveldb', 'minisketch', 'secp256k1'}


def required_binaries(native):
    return ['test_pocx' if native else 'test_bitcoin', 'test_bitcoin-qt', 'test_kernel',
            'bitcoind', 'bitcoin-node', 'bitcoin-cli', 'bitcoin', 'bench_bitcoin',
            'bitcoin-chainstate', 'bitcoin-util', 'bitcoin-tx', 'bitcoin-wallet']


def specification(root=ROOT):
    record = json.loads((root / 'test/pocx/sanitizer-ci.json').read_text())
    for name, expected in record['source_sha256'].items():
        if sha256(root / name) != expected:
            raise ValueError('Required sanitizer source changed since review: ' + name)
    return record


def runtime_environment(root=ROOT):
    return {key: value.format(root=root) for key, value in specification(root)['runtime_environment'].items()}


def required_options(root=ROOT):
    spec = specification(root)
    return {**spec['build_options'], 'SANITIZERS': spec['sanitizers']}


def tools(root=ROOT):
    _spec = specification(root)
    result = {}
    for name in ('clang-22', 'clang++-22', 'llvm-symbolizer-22', 'llvm-nm-22', 'mold'):
        path = shutil.which(name)
        if path is None:
            raise ValueError('Missing required sanitizer tool: ' + name)
        version = subprocess.check_output([path, '--version'], text=True)
        if name != 'mold' and not re.search(r'\bversion\s+22\.', version):
            raise ValueError('Wrong required sanitizer tool version: ' + name)
        result[name] = {'path': path, 'sha256': sha256(Path(path)), 'version': version}
    if Path(result['llvm-symbolizer-22']['path']).resolve() != Path(runtime_environment(root)['ASAN_SYMBOLIZER_PATH']).resolve():
        raise ValueError('Sanitizer symbolizer does not match the required runtime environment')
    return result


def verify_compile_commands(commands, root=ROOT, build=None):
    """Check first-party C++ inputs, including their final overriding flags."""
    spec = specification(root)
    records = {}
    for line in commands.splitlines():
        tokens = shlex.split(line)
        if '-c' not in tokens or '-o' not in tokens:
            continue
        source = Path(tokens[tokens.index('-c') + 1])
        if source.suffix not in ('.cpp', '.cc'):
            continue
        if not source.is_absolute():
            if build is None:
                raise ValueError('Relative sanitizer source requires the build directory')
            source = (build / source).resolve()
        if not source.is_relative_to(root / 'src'):
            continue
        relative = source.relative_to(root / 'src')
        if relative.parts[0] in VENDORED or relative.parts[:2] == ('ipc', 'libmultiprocess'):
            continue
        sanitizer_flags = [token for token in tokens if token.startswith('-fsanitize=')]
        standards = [token for token in tokens if token.startswith('-std=')]
        if (sanitizer_flags != ['-fsanitize=' + spec['sanitizers']] or
                not any(Path(token).name == 'clang++-22' for token in tokens[:tokens.index('-c')]) or
                any(token.startswith(('-fno-sanitize=', '-fsanitize-recover=')) for token in tokens) or
                not standards or standards[-1] != '-std=c++23' or
                any(flag not in tokens for flag in ('-ftrivial-auto-var-init=pattern', '-DARENA_DEBUG', '-DDEBUG_LOCKORDER'))):
            raise ValueError('Missing, overridden or weakened sanitizer compile flags: ' + str(source))
        records.setdefault(str(source), []).append(line)
    if not records:
        raise ValueError('No first-party sanitizer compile inputs')
    return records


def run_canaries(compiler, sanitizer_flags, environment, output):
    """Accept clean code and require each deliberate error to fail diagnostically."""
    output.mkdir(parents=True, exist_ok=True)
    env = {**os.environ, **environment}
    results = []
    for name, (body, diagnostic) in CANARIES.items():
        source, binary = output / (name + '.cpp'), output / name
        source.write_text('int main(int argc, char**) { ' + body + ' }\n')
        command = [str(compiler), '-O1', '-g', '-fno-omit-frame-pointer',
                   '-fsanitize=' + sanitizer_flags, str(source), '-o', str(binary)]
        build_log = output / (name + '-build.log')
        with build_log.open('w') as stream:
            subprocess.run(command, stdout=stream, stderr=subprocess.STDOUT, check=True)
        execution = subprocess.run([str(binary)], env=env, capture_output=True, text=True, timeout=30)
        log = output / (name + '.log')
        log.write_text(execution.stdout + execution.stderr)
        text = log.read_text()
        if diagnostic is None:
            accepted = execution.returncode == 0 and 'runtime error:' not in text and 'Sanitizer' not in text
        else:
            accepted = execution.returncode != 0 and diagnostic in text
        results.append({'canary': name, 'status': 'passed' if accepted else 'failed',
                        'returncode': execution.returncode, 'expected_diagnostic': diagnostic,
                        'command': command, 'source_sha256': sha256(source), 'binary_sha256': sha256(binary),
                        'log': str(log), 'log_sha256': sha256(log),
                        'build_log': str(build_log), 'build_log_sha256': sha256(build_log)})
    return results


def instrumentation(build, toolchain, output):
    options = build_options((build / 'CMakeCache.txt').read_text())
    expected = required_options()
    for key, value in expected.items():
        actual = options.get(key)
        if key in ('CMAKE_C_COMPILER', 'CMAKE_CXX_COMPILER'):
            if not actual or Path(actual).resolve() != Path(toolchain[value]['path']).resolve():
                raise ValueError('Wrong sanitizer compiler: ' + key)
        elif actual != value:
            raise ValueError('Wrong sanitizer build setting: ' + key)
    command = ['ninja', '-C', str(build), '-t', 'commands']
    records = verify_compile_commands(subprocess.check_output(command, text=True), build=build)
    names = required_binaries(options['ENABLE_POCX'] == 'ON')
    binaries = {}
    output.mkdir(parents=True, exist_ok=True)
    for name in names:
        path = build / 'bin' / name
        symbols = subprocess.check_output([toolchain['llvm-nm-22']['path'], str(path)], text=True)
        if '__asan_init' not in symbols or '__ubsan_handle_' not in symbols:
            raise ValueError('Required executable lacks sanitizer runtime symbols: ' + name)
        log = output / (name + '-symbols.log')
        log.write_text(symbols)
        binaries[name] = {'sha256': sha256(path), 'symbols_sha256': sha256(log), 'symbols_log': str(log)}
    return {'scope': 'First-party C++ compile commands and required executable sanitizer symbols; vendored dependencies and Rust instrumentation are not inferred.',
            'compile_commands': records, 'binaries': binaries}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check-tools', action='store_true')
    parser.add_argument('--build-dir', type=Path)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if args.check_tools == bool(args.build_dir):
        parser.error('Choose --check-tools or --build-dir')
    output = args.output.resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    report = {'status': 'failed', 'scope': __doc__}
    try:
        toolchain = tools()
        report.update(tools=toolchain, environment=runtime_environment())
        if args.build_dir:
            report['stack_limit'] = resource.getrlimit(resource.RLIMIT_STACK)[0]
            if report['stack_limit'] != 512 * 1024:
                raise ValueError('Required sanitizer runtime stack limit is 512 KiB')
            build = args.build_dir.resolve()
            if not build.is_relative_to(ROOT) or build == ROOT:
                raise ValueError('Sanitizer build must belong to this worktree')
            report['instrumentation'] = instrumentation(build, toolchain, output.parent / 'symbols')
            report['canaries'] = run_canaries(toolchain['clang++-22']['path'], specification()['sanitizers'],
                                             runtime_environment(), output.parent / 'canaries')
            if any(row['status'] != 'passed' for row in report['canaries']):
                raise ValueError('Sanitizer runtime controls failed')
        report['status'] = 'passed'
        return 0
    except (OSError, ValueError, KeyError, subprocess.SubprocessError) as error:
        report['error'] = str(error)
        print(str(error), file=sys.stderr)
        return 1
    finally:
        output.write_text(json.dumps(report, indent=2) + '\n')


if __name__ == '__main__':
    sys.exit(main())
