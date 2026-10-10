# Copyright (c) 2026 The Bitcoin PoCX developers
# Distributed under the MIT software license; see COPYING.
"""Read upstream runner selections without executing the upstream runner."""
import ast
import hashlib
import json
from pathlib import Path
import shlex

TRANSPORT_FLAGS = {'--v1transport', '--v2transport'}


def case_spec(test, arguments):
    if (not isinstance(test, str) or Path(test).name != test or not test.endswith('.py') or
            not isinstance(arguments, list) or not all(isinstance(arg, str) and arg for arg in arguments) or
            any(arg.split('=', 1)[0] in {'--configfile', '--tmpdir', '--cachedir', '--portseed',
                                        '--randomseed', '--nocleanup', '--timeout-factor', *TRANSPORT_FLAGS}
                for arg in arguments)):
        raise ValueError('Invalid functional case arguments')
    return {'id': shlex.join([test, *arguments]), 'test': test, 'arguments': arguments}


def upstream_cases(source):
    constants = {}
    cases = []
    found = set()
    for node in ast.parse(Path(source).read_text()).body:
        if not isinstance(node, ast.Assign) or len(node.targets) != 1 or not isinstance(node.targets[0], ast.Name):
            continue
        name = node.targets[0].id
        if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
            constants[name] = node.value.value
        if name not in ('BASE_SCRIPTS', 'EXTENDED_SCRIPTS'):
            continue
        if name in found or not isinstance(node.value, ast.List) or not node.value.elts:
            raise ValueError('Unknown or empty upstream functional selection')
        found.add(name)
        for value in node.value.elts:
            if isinstance(value, ast.Constant) and isinstance(value.value, str):
                text = value.value
            elif isinstance(value, ast.Name) and value.id in constants:
                text = constants[value.id]
            else:
                raise ValueError('Unreviewed upstream functional selection expression')
            test, *arguments = shlex.split(text)
            transport = [arg for arg in arguments if arg in TRANSPORT_FLAGS]
            if len(transport) > 1:
                raise ValueError('Conflicting upstream transport flags')
            spec = case_spec(test, [arg for arg in arguments if arg not in TRANSPORT_FLAGS])
            cases.append({**spec, 'upstream_case': text, 'selection': name,
                          'upstream_transport': transport,
                          'dynamic': test == constants.get('TOOL_BENCH_SANITY_CHECK')})
    if found != {'BASE_SCRIPTS', 'EXTENDED_SCRIPTS'} or len({r['upstream_case'] for r in cases}) != len(cases):
        raise ValueError('Incomplete or duplicate upstream functional selection')
    return cases


def selected_cases(manifest, upstream):
    cases = []
    selected = set(manifest['tests']) | set(manifest['reused_tests'])
    excluded = manifest.get('excluded_tests', {})
    if (selected & excluded.keys() or excluded.keys() - {r['test'] for r in upstream} or
            any(not isinstance(reason, str) or not reason.strip() for reason in excluded.values())):
        raise ValueError('Invalid or overlapping functional exclusions')
    dynamic = manifest.get('dynamic_tests', {})
    if (dynamic.keys() - selected or any(name != 'tool_bench_sanity_check.py' or
            mode != 'aggregate-original-default' for name, mode in dynamic.items())):
        raise ValueError('Unreviewed dynamic functional selection')
    for test in [*manifest['tests'], *manifest['reused_tests']]:
        rows = [row for row in upstream if row['test'] == test]
        if any(row['dynamic'] for row in rows) and test not in dynamic:
            raise ValueError('Selected dynamic benchmark cases require build-specific expansion')
        # The unchanged benchmark script defaults to --bench=.*: all registered
        # sanity benchmarks. A disabled benchmark build retains its explicit skip.
        specs = [case_spec(test, row['arguments']) for row in rows] or [case_spec(test, [])]
        # Transport variants are executed by the outer matrix, not duplicated
        # here. Every other upstream argument set remains a separate case.
        for spec in specs:
            if spec not in cases:
                cases.append(spec)
    if not cases or len({row['id'] for row in cases}) != len(cases):
        raise ValueError('Empty or duplicate functional case selection')
    return cases


def selection_digest(cases):
    return hashlib.sha256(json.dumps(cases, sort_keys=True, separators=(',', ':')).encode()).hexdigest()
