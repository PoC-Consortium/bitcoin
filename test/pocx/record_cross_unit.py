#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin PoCX developers
# Distributed under the MIT software license; see COPYING.
"""Record Windows cross-built unit inputs without executing the foreign binary.

Runtime discovery and assertion proof are deliberately absent. A target-host
consumer must verify the exported binary, inputs and complete runtime inventory.
"""
import argparse
import json
from pathlib import Path

from common import sha256
import build_configuration
import unit_matrix


def snapshot(binary, inputs, cache, source):
    source = source.resolve()
    build = cache.resolve().parent
    build_configuration.require_source(cache.read_text(), source)
    options, system = unit_matrix.configuration(build)
    if (options.get('target_system') != 'Windows' or options.get('ENABLE_POCX') != 'ON' or
            options.get('BUILD_TESTS') != 'ON' or 'set(CMAKE_CROSSCOMPILING "TRUE")' not in system.read_text()):
        raise ValueError('Deferred discovery requires a Windows cross-built PoCX unit target')
    paths = {Path(line).resolve() for line in inputs.read_text().splitlines() if line}
    if not paths:
        raise ValueError('Empty evaluated cross-unit source selection')
    sources = {}
    for path in sorted(paths):
        if path.is_relative_to(build):
            name = 'build/' + path.relative_to(build).as_posix()
        elif path.is_relative_to(source):
            name = 'source/' + path.relative_to(source).as_posix()
        else:
            raise ValueError('Cross-unit input outside the source/build trees: ' + str(path))
        sources[name] = sha256(path)
    return {'format': 1, 'kind': 'windows-cross-unit-inputs',
        'execution_status': 'not executed; runtime discovery required on target host',
        'runtime_inventory': None, 'binary_sha256': sha256(binary),
        'input_manifest_sha256': sha256(inputs), 'cache_sha256': sha256(cache),
        'target_system_sha256': sha256(system), 'build_options': options, 'sources': sources}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('binary', 'inputs', 'cache', 'source', 'output'):
        parser.add_argument('--' + name, required=True, type=Path)
    args = parser.parse_args()
    record = snapshot(args.binary, args.inputs, args.cache, args.source)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(record, indent=2) + '\n')
    print('Recorded Windows cross-unit inputs; runtime discovery remains unverified.', flush=True)


if __name__ == '__main__':
    main()
