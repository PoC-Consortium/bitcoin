# Copyright (c) 2026 The Bitcoin PoCX developers
# Distributed under the MIT software license; see COPYING.
"""Locate bounded execution reports, including canonical short temporary paths."""
from common import short_tmpdir
from functional_retention import ordinary_directory


def result_directories(build, prefixes):
    result = set()
    for parent in {build, short_tmpdir(build, create=False)}:
        if ordinary_directory(parent):
            result.update(path for path in parent.iterdir()
                          if path.name.startswith(prefixes) and ordinary_directory(path))
    return result


def functional_logs(result):
    """Read fixed case log locations; never recurse into nodes or wallets."""
    for parent in (result, result / 'v2'):
        if not ordinary_directory(parent):
            continue
        for path in sorted(parent.iterdir()):
            if path.suffix == '.log' and not path.is_symlink() and path.is_file():
                yield path
            if ordinary_directory(path):
                log = path / 'test_framework.log'
                if not log.is_symlink() and log.is_file():
                    yield log


def relative_path(path, build, result):
    if path.is_relative_to(build):
        return path.relative_to(build)
    return type(path)('short-results') / result.name / path.relative_to(result)
