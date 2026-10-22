# Copyright (c) 2026 The Bitcoin PoCX developers
# Distributed under the MIT software license; see COPYING.
"""Explicit prerequisite flags, kept separate from original functional case identities."""
import json
import math
import os
from pathlib import Path
import subprocess

PREVIOUS_RELEASES = ('v0.14.3', 'v0.20.1', 'v0.21.0', 'v22.0', 'v23.0',
                     'v24.0.1', 'v25.0', 'v28.2')
PROFILE_KEYS = {'previous_releases', 'network_addresses'}


def timeout_arguments(provenance):
    if provenance.get('format_version', 1) < 6:
        if 'timeout_factor' in provenance:
            raise ValueError('Historical report has an unrecorded timeout factor')
        return []
    factor = provenance.get('timeout_factor')
    if type(factor) not in (int, float) or not math.isfinite(factor) or factor <= 0:
        raise ValueError('Functional timeout factor must be finite and positive')
    return ['--timeout-factor=' + str(factor)]


def arguments(test, profile):
    if set(profile) != PROFILE_KEYS or any(type(value) is not bool for value in profile.values()):
        raise ValueError('Invalid functional prerequisite profile')
    result = ['--previous-releases'] if profile['previous_releases'] else []
    if profile['network_addresses']:
        if test == 'feature_bind_port_discover.py':
            result.append('--ihave1111and2222')
        elif test == 'feature_bind_port_externalip.py':
            result.append('--ihave1111')
    return result


def release_binaries(directory):
    paths = {}
    for version in PREVIOUS_RELEASES:
        names = ('bitcoind', 'bitcoin-cli', 'bitcoin-wallet') if version == 'v28.2' else ('bitcoind', 'bitcoin-cli')
        for name in names:
            path = Path(directory) / version / 'bin' / (name + ('.exe' if os.name == 'nt' else ''))
            if not path.is_file():
                raise ValueError(f'Missing required previous-release binary: {path}')
            paths[f'{version}/{name}'] = path.resolve()
    return paths


def verify_network_addresses():
    interfaces = json.loads(subprocess.check_output(['ip', '-j', 'address', 'show'], text=True))
    addresses = {entry['local'] for interface in interfaces
                 if 'UP' in interface.get('flags', []) and 'LOOPBACK' not in interface.get('flags', [])
                 for entry in interface.get('addr_info', [])}
    if not {'1.1.1.1', '2.2.2.2'}.issubset(addresses):
        raise ValueError('Special-address profile requires isolated, up, non-loopback interfaces with 1.1.1.1 and 2.2.2.2')
    return interfaces
