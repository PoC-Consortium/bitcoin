#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin PoCX developers
# Distributed under the MIT software license; see COPYING.
"""Check the fixed Qt baseline and reviewed source ownership, without executing Qt."""
import argparse
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
BASELINE_SHA256 = '21ad5232554abc391ed9e49923532fa20053d51895180b5e8ac3410c88350396'


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def check(root):
    issues = []
    baseline_path = root / 'test/pocx/qt-baseline.json'
    if not baseline_path.is_file() or digest(baseline_path) != BASELINE_SHA256:
        return [{'source': 'test/pocx/qt-baseline.json', 'reason': 'fixed original Qt baseline changed'}]
    baseline = json.loads(baseline_path.read_text())
    review = json.loads((root / 'test/pocx/qt-parity.json').read_text())
    if (review.get('baseline_sha256') != BASELINE_SHA256 or
            baseline['case_count'] != 9 or len(set(baseline['cases'])) != 9 or
            review.get('additional') != ['PoCXURITests::nativePaymentURIs']):
        issues.append({'source': 'test/pocx/qt-parity.json', 'reason': 'Qt case ownership or baseline review changed'})
    original = {name: sha for name, sha in baseline['upstream_files_sha256'].items()
                if name.endswith(('.cpp', '.h'))}
    if len(original) != 15:
        issues.append({'source': 'test/pocx/qt-baseline.json', 'reason': 'original Qt source inventory changed'})
    owned = {str(path.relative_to(root)) for path in (root / 'src/pocx/test/qt').iterdir()
             if path.is_file()}
    if owned != set(review['owned_sources']):
        issues.append({'source': 'src/pocx/test/qt', 'reason': 'owned Qt source inventory changed since review'})
    for name, sha in {**original, **review['owned_sources'], **review['reviewed_build_sources']}.items():
        path = root / name
        if not path.is_file() or digest(path) != sha:
            issues.append({'source': name, 'reason': 'original Qt file or reviewed native adaptation changed'})
    return issues


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check', action='store_true', required=True)
    parser.parse_args()
    issues = check(ROOT)
    print(json.dumps({'status': 'review required' if issues else 'passed', 'issues': issues}, indent=2))
    return bool(issues)


if __name__ == '__main__':
    raise SystemExit(main())
