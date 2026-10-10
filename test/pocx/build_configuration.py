#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin PoCX developers
# Distributed under the MIT software license; see COPYING.
"""Select one explicit CMake configuration for both building and executing tests."""
import os
from pathlib import Path

from common import build_options


def require_source(cache, root):
    # CMake uses forward slashes in Windows cache paths. Native pathlib
    # normalization also preserves the identity of symlinked source paths.
    prefix = 'CMAKE_HOME_DIRECTORY:INTERNAL='
    homes = [line[len(prefix):] for line in cache.splitlines() if line.startswith(prefix)]
    if len(homes) != 1 or not homes[0] or Path(homes[0]).resolve() != root.resolve():
        raise ValueError('Build belongs to a different source worktree')


def configuration(cache, requested=None):
    options = build_options(cache)
    choices = options.get('CMAKE_CONFIGURATION_TYPES', '').split(';')
    if choices != ['']:
        if requested is None:
            raise ValueError('Multi-configuration builds require --config (for example Release)')
        if requested not in choices:
            raise ValueError(f'Unknown build configuration {requested!r}; configured choices: {choices}')
    elif requested is not None and requested != options.get('CMAKE_BUILD_TYPE', ''):
        raise ValueError('Requested configuration differs from CMAKE_BUILD_TYPE')
    if requested is not None and (not requested or requested in ('.', '..') or
                                  '/' in requested or '\\' in requested):
        raise ValueError('Invalid build configuration name')
    return requested


def executable(build, name, cache, selected=None):
    configuration(cache, selected)
    directory = build / 'bin'
    if build_options(cache).get('CMAKE_CONFIGURATION_TYPES'):
        directory /= selected
    return directory / (name + ('.exe' if os.name == 'nt' else ''))


def build_arguments(selected):
    return ['--config', selected] if selected is not None else []


def ctest_arguments(selected):
    return ['--build-config', selected] if selected is not None else []
