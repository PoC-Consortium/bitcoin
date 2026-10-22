# Copyright (c) 2026 The Bitcoin PoCX developers
# Distributed under the MIT software license; see COPYING.
"""Translate upstream case/transport selections without adding configurations."""
import shlex

from functional_cases import TRANSPORT_FLAGS, selected_cases


def validate(scope):
    if (not isinstance(scope, dict) or set(scope) != {'extended', 'excluded', 'transport_flags'} or
            type(scope['extended']) is not bool or not isinstance(scope['excluded'], list) or
            scope['excluded'] not in ([], ['feature_dbcrash.py']) or
            not isinstance(scope['transport_flags'], list) or
            any(flag not in TRANSPORT_FLAGS for flag in scope['transport_flags']) or
            len(set(scope['transport_flags'])) != len(scope['transport_flags'])):
        raise ValueError('Invalid or unreviewed inherited functional selection')
    return scope


def effective_transport(arguments, scope):
    flags = [*shlex.split(arguments), *validate(scope)['transport_flags']]
    # Upstream gives v1 precedence regardless of argument order. Its default
    # is v1, but passing an explicit global v1 flag would override v2 cases.
    return 'v2' if '--v2transport' in flags and '--v1transport' not in flags else 'v1'


def upstream_rows(upstream, scope):
    validate(scope)
    return [row for row in upstream if row['test'] not in scope['excluded'] and
            (scope['extended'] or row['selection'] == 'BASE_SCRIPTS')]


def native_selection(manifest, upstream, scope):
    rows = upstream_rows(upstream, scope)
    original_tests = {row['test'] for row in upstream}
    modes_by_case = {}
    for row in rows:
        modes_by_case.setdefault(row['id'], set()).add(effective_transport(row['upstream_case'], scope))
    selection, transports = [], {}
    for spec in selected_cases(manifest, upstream):
        if spec['test'] in original_tests:
            modes = modes_by_case.get(spec['id'], set())
        else:
            # Legitimate PoCX-only cases belong to the inherited configuration,
            # using its default/global transport rather than an added matrix.
            modes = {effective_transport('', scope)}
        if modes:
            selection.append(spec)
            transports[spec['id']] = [mode for mode in ('v1', 'v2') if mode in modes]
    if not selection:
        raise ValueError('Empty inherited native functional selection')
    modes = [mode for mode in ('v1', 'v2') if any(mode in value for value in transports.values())]
    return selection, transports, modes


def verify(provenance, manifest, upstream):
    expected, transports, modes = native_selection(manifest, upstream, provenance['inherited_selection'])
    if (provenance['selected_cases'] != expected or provenance['case_transports'] != transports or
            provenance['transport_modes'] != modes):
        raise ValueError('Native case/transport selection differs from inherited upstream scope')
