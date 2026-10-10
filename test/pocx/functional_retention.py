#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin PoCX developers
# Distributed under the MIT software license; see COPYING.
"""Release passed cases' generated databases while retaining diagnostic evidence."""
from pathlib import Path
import re
import shutil


def ordinary_directory(path):
    # Junctions are directory links too, but Path.is_junction needs Python 3.12.
    return (not path.is_symlink() and
            not getattr(path, 'is_junction', lambda: False)() and path.is_dir())


def prune_passed_case(directory, *, status, process_control):
    if status != 'passed':
        return []
    if process_control.get('cleanup_complete') is not True:
        raise ValueError('Database retention requires completed process cleanup')
    directory = Path(directory)
    if not ordinary_directory(directory):
        return []
    pruned = []
    # Inspect only the framework's direct node roots. A recursive search could
    # remove a retained fixture or a database belonging to a different layout.
    for node in sorted(directory.iterdir()):
        if not re.fullmatch(r'node[0-9]+', node.name) or not ordinary_directory(node):
            continue
        chain = node / 'regtest'
        if not ordinary_directory(chain):
            continue
        for name in ('blocks', 'chainstate', 'indexes'):
            database = chain / name
            if ordinary_directory(database):
                shutil.rmtree(database)
                pruned.append(database.relative_to(directory).as_posix())
    return pruned
