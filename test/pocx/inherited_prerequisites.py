# Copyright (c) 2026 The Bitcoin PoCX developers
# Distributed under the MIT software license; see COPYING.
"""Optional Python prerequisites omitted by specific original CI recipes."""
import importlib

# Derived from the pinned original environment scripts and workflow install
# steps. ASan explicitly provisions tracing; these other profiles do not.
OPTIONAL_MODULES = {
    'ci_native_asan': [],
    'ci_native_tsan': ['bcc'],
    'ci_native_msan': ['bcc', 'zmq'],
    'ci_native_nowallet': ['bcc'],
    'ci_native_previous_releases': ['bcc', 'capnp'],
    'ci_native_alpine_musl': ['bcc'],
    'ci_i686_no_multiprocess': ['bcc', 'zmq'],
    'ci_arm_linux': ['bcc', 'capnp'],
    'ancestor': ['bcc'],
}
MODULE_GUARDS = {'bcc': 'skip_if_no_python_bcc', 'capnp': 'skip_if_no_py_capnp',
                 'zmq': 'skip_if_no_py3_zmq'}


def policy(environment):
    recipe = environment.get('POCX_INHERITED_RECIPE', environment.get('CONTAINER_NAME'))
    return {'recipe': recipe, 'optional_modules': OPTIONAL_MODULES.get(recipe, [])}


def available(name):
    try:
        importlib.import_module(name)
    except ImportError:
        return False
    return True
