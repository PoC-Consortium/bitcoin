#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin PoCX developers
# Distributed under the MIT software license; see COPYING.
"""Give build tools their normal stack without changing the caller's test limit."""
import os
import subprocess

BUILD_STACK_BYTES = 8 * 1024 * 1024


def _build_stack(hard):
    import resource
    resource.setrlimit(resource.RLIMIT_STACK, (BUILD_STACK_BYTES, hard))


def run_build(command, **kwargs):
    if os.name == 'posix':
        import resource
        from functools import partial
        soft, hard = resource.getrlimit(resource.RLIMIT_STACK)
        if soft != resource.RLIM_INFINITY and soft < BUILD_STACK_BYTES:
            if hard != resource.RLIM_INFINITY and hard < BUILD_STACK_BYTES:
                raise ValueError('Build tools need an 8 MiB stack; apply the test stack restriction to the soft limit only')
            kwargs['preexec_fn'] = partial(_build_stack, hard)
    return subprocess.run(command, **kwargs)
