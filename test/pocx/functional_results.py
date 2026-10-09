# Copyright (c) 2026 The Bitcoin PoCX developers
# Distributed under the MIT software license; see COPYING.
"""Validate execution identities before using transport-specific evidence."""
from functional_cases import case_spec, selection_digest


def transport_results(report):
    """Return (global transport, result) pairs; historical reports mean default v1.

    These labels describe upstream CLI flags, not every connection's protocol:
    individual tests retain explicit v1/v2 peers and intentional fallback cases.
    """
    provenance = report['provenance']
    results = report['results']
    version = provenance.get('format_version', 1)
    if type(version) is not int or version not in (1, 2, 3, 4):
        raise ValueError('Unknown functional execution format')
    seen = set()
    pairs = []
    for result in results:
        if version < 3 and ('case' in result or 'case_arguments' in result):
            raise ValueError('Historical functional report has unrecorded argument variant')
        mode = result.get('transport') if version >= 2 else 'v1'
        arguments = result.get('case_arguments') if version >= 3 else []
        spec = case_spec(result['test'], arguments)
        case = result.get('case') if version >= 3 else result['test']
        if version >= 3 and case != spec['id']:
            raise ValueError('Functional case identity differs from arguments')
        key = (case, mode)
        if mode not in ('v1', 'v2') or key in seen:
            raise ValueError('Invalid or duplicate functional transport case')
        seen.add(key)
        command = result['command']
        if not isinstance(command, list) or not all(isinstance(arg, str) for arg in command):
            raise ValueError('Invalid functional execution command')
        if version >= 2:
            flag = f'--{mode}transport'
            expected_arguments = [*arguments, flag]
            if (result.get('test_arguments') != expected_arguments or
                    command[-len(expected_arguments):] != expected_arguments or command.count(flag) != 1 or
                    f'--{"v1" if mode == "v2" else "v2"}transport' in command):
                raise ValueError('Functional transport label differs from executed flag')
        elif '--v2transport' in command or 'transport' in result:
            raise ValueError('Historical functional report has unrecorded transport mode')
        if type(result['returncode']) is not int or type(result['timed_out']) is not bool:
            raise ValueError('Missing terminal functional execution')
        passed = result['returncode'] == 0 and result['timed_out'] is False
        skipped = version >= 4 and result['returncode'] == 77 and not result['timed_out']
        expected_status = 'passed' if passed else 'skipped' if skipped else 'failed'
        if result['status'] != expected_status:
            raise ValueError('Functional status differs from terminal execution')
        if skipped and (not isinstance(result.get('skip_reason'), str) or not result['skip_reason'].strip()):
            raise ValueError('Functional skip requires a reported reason')
        pairs.append((mode, result))
    if version >= 2:
        tests, modes = provenance['selected_tests'], provenance['transport_modes']
        if version >= 3:
            cases = provenance['selected_cases']
            if (not cases or any(case != case_spec(case['test'], case['arguments']) for case in cases) or
                    len({case['id'] for case in cases}) != len(cases) or
                    set(tests) != {case['test'] for case in cases} or
                    provenance['case_selection']['selected_cases_sha256'] != selection_digest(cases)):
                raise ValueError('Incomplete or mismatched functional case selection')
            expected = {(case['id'], mode) for case in cases for mode in modes}
        else:
            expected = {(name, mode) for name in tests for mode in modes}
        if (not tests or len(tests) != len(set(tests)) or not modes or
                len(modes) != len(set(modes)) or set(modes) - {'v1', 'v2'} or
                seen != expected):
            raise ValueError('Incomplete functional transport selection')
    elif not results:
        raise ValueError('Empty historical functional selection')
    return pairs
