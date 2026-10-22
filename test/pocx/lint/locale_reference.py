#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin PoCX developers
# Distributed under the MIT software license; see COPYING.
"""Transfer the original locale-reference exception only for its exact copy.

The legacy conversion is an independent reference used by sixty original
assertions. Keep it and the complete original test, rather than replacing the
reference with the implementation under test. No whole-file exception is added.
"""
import ast
import hashlib
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[3]
CHECKER = 'test/lint/lint-locale-dependence.py'
ADAPTED_CHECKER = 'test/pocx/lint/locale_dependence.py'
ORIGINAL = 'src/test/util_tests.cpp'
ADAPTED = 'src/pocx/test/adapted/util_tests.cpp'
CHECKER_SHA256 = 'b88885df387243d0f861fc68556710f05ab1b05ab8395786d0368ec536490ee0'
REFERENCE_SHA256 = '68264d4c9f248408651083176af6bd8c8759a58aada7d862af0396755ac03e41'


def reference_block(text):
    start = 'int64_t atoi64_legacy('
    end = 'BOOST_AUTO_TEST_CASE(test_ToIntegralHex)'
    if text.count(start) != 1 or text.count(end) != 1:
        raise ValueError('Legacy locale reference boundary is missing or ambiguous')
    block = text[text.index(start):text.index(end, text.index(start))]
    if hashlib.sha256(block.encode()).hexdigest() != REFERENCE_SHA256:
        raise ValueError('Legacy reference or original locale assertions changed')
    return block


def verify_checker_copy(original, adapted):
    if hashlib.sha256(original.encode()).hexdigest() != CHECKER_SHA256:
        raise ValueError('Original locale checker changed; explicit policy review required')
    original_tree = ast.parse(original)
    adapted_tree = ast.parse(adapted)
    imports = [node for node in adapted_tree.body if isinstance(node, ast.ImportFrom)
               and node.module == 'locale_reference']
    expected_import = ast.parse('from locale_reference import reviewed_legacy_exception').body[0]
    if len(imports) != 1 or ast.dump(imports[0]) != ast.dump(expected_import):
        raise ValueError('Unexpected locale policy import')
    adapted_tree.body.remove(imports[0])
    assignments = [node for node in ast.walk(adapted_tree) if isinstance(node, ast.Assign)
                   and any(isinstance(target, ast.Name) and target.id == 'regexp_ignore_known_violations'
                           for target in node.targets)]
    expected = ast.parse('"|".join([*KNOWN_VIOLATIONS, reviewed_legacy_exception()])').body[0].value
    if len(assignments) != 1 or ast.dump(assignments[0].value) != ast.dump(expected):
        raise ValueError('Locale policy must add exactly the checked legacy reference')
    assignments[0].value = ast.parse('"|".join(KNOWN_VIOLATIONS)').body[0].value
    if ast.dump(original_tree) != ast.dump(adapted_tree):
        raise ValueError('Owned locale checker differs beyond the reviewed reference policy')


def reviewed_legacy_exception(root=None):
    root = ROOT if root is None else root
    original_checker = (root / CHECKER).read_text()
    verify_checker_copy(original_checker, (root / ADAPTED_CHECKER).read_text())
    original = (root / ORIGINAL).read_text()
    adapted = (root / ADAPTED).read_text()
    if reference_block(original) != reference_block(adapted):
        raise ValueError('Adapted legacy reference differs from original')
    # An identical call elsewhere in this file must not share this exception.
    if adapted.count('strtoll(') != 1:
        raise ValueError('Additional legacy conversion calls require their own review')
    line = ADAPTED + ':    return strtoll(str.c_str(), nullptr, 10);'
    policy = next(node.value for node in ast.parse(original_checker).body
                  if isinstance(node, ast.Assign) and any(isinstance(target, ast.Name)
                  and target.id == 'KNOWN_VIOLATIONS' for target in node.targets))
    known = ast.literal_eval(policy)
    if not any(re.search(pattern, line.replace(ADAPTED, ORIGINAL, 1)) for pattern in known):
        raise ValueError('Original checker no longer permits this legacy reference')
    return '^' + re.escape(line) + '$'
