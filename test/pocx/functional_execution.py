# Copyright (c) 2026 The Bitcoin PoCX developers
# Distributed under the MIT software license; see COPYING.
"""Attest inherited CLI/multiprocess settings independently of functional case IDs."""
import shlex
import os

import build_configuration

BINARY_ENVIRONMENT = {
    'bitcoin': 'BITCOIN_BIN', 'bitcoind': 'BITCOIND', 'bitcoin-cli': 'BITCOINCLI',
    'bench_bitcoin': 'BITCOIN_BENCH', 'bitcoin-util': 'BITCOINUTIL',
    'bitcoin-tx': 'BITCOINTX', 'bitcoin-chainstate': 'BITCOINCHAINSTATE',
    'bitcoin-wallet': 'BITCOINWALLET',
}
BINARY_NAMES = (*BINARY_ENVIRONMENT, 'bitcoin-node', 'pocx_chainstate_test_clock')


def binary_paths(build, cache, selected_config=None):
    return {name: build_configuration.executable(build, name, cache, selected_config)
            for name in BINARY_NAMES}


def binary_environment(paths, inherited_path):
    # Pin unavailable tools to their expected selected path as well. Falling
    # back to bin/ or another configuration could conceal a missing feature.
    result = {variable: str(paths[name]) for name, variable in BINARY_ENVIRONMENT.items()}
    result['PATH'] = os.pathsep.join([str(paths['bitcoind'].parent), inherited_path])
    return result


def settings(use_cli=False, multiprocess=False):
    result = {'use_cli': use_cli, 'multiprocess': multiprocess}
    if any(type(value) is not bool for value in result.values()):
        raise ValueError('Functional execution settings must be booleans')
    return result


def recorded(provenance):
    if provenance.get('format_version', 1) < 7:
        if 'execution_options' in provenance:
            raise ValueError('Historical report has unrecorded functional execution settings')
        return settings()
    value = provenance.get('execution_options')
    if not isinstance(value, dict) or set(value) != {'use_cli', 'multiprocess'}:
        raise ValueError('Missing or unknown functional execution settings')
    return settings(**value)


def arguments(provenance, case_arguments):
    return ['--usecli'] if recorded(provenance)['use_cli'] and '--usecli' not in case_arguments else []


def environment(provenance, binaries, options):
    if not recorded(provenance)['multiprocess']:
        return {}
    if options.get('ENABLE_IPC') != 'ON' or not {'bitcoin', 'bitcoin-node'}.issubset(binaries):
        raise ValueError('Multiprocess functional execution requires IPC, bitcoin and bitcoin-node')
    return {'BITCOIN_CMD': shlex.join([str(binaries['bitcoin']), '-m'])}
