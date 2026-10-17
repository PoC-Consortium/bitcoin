#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin PoCX developers
# Distributed under the MIT software license; see COPYING.
"""Select Bitcoin OFF, then execute the unchanged inherited fuzz recipes."""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import subprocess

from common import ROOT


def environment_for_fuzz(environment):
    if environment.get('CI_PRODUCT') != 'bitcoin':
        raise ValueError('Inherited fuzz execution requires CI_PRODUCT=bitcoin; PoCX fuzz is deferred')
    return dict(environment, BITCOIN_CONFIG=environment.get('BITCOIN_CONFIG', '') + ' -DENABLE_POCX=OFF')


def run_windows(root=ROOT, *, load=None):
    if load is None:
        spec = importlib.util.spec_from_file_location('original_windows_fuzz', root / '.github/ci-windows.py')
        driver = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(driver)
    else:
        driver = load()
    # Keep all original toolchain options and driver steps, selecting only the
    # product whose upstream fuzz targets and assertions are being exercised.
    driver.GENERATE_OPTIONS['fuzz'] = [*driver.GENERATE_OPTIONS['fuzz'], '-DENABLE_POCX=OFF']
    driver.generate('fuzz')
    cache = (root / 'build/CMakeCache.txt').read_text()
    if 'ENABLE_POCX:BOOL=OFF' not in cache.splitlines():
        raise ValueError('Inherited Windows fuzz configuration did not select Bitcoin OFF')
    for step in (driver.build, driver.check_manifests, driver.prepare_tests, driver.run_tests):
        step('fuzz')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--windows', action='store_true')
    parser.add_argument('--plan', action='store_true', help='Print selection only; does not execute fuzz tests')
    args = parser.parse_args()
    environment = environment_for_fuzz(os.environ)
    if args.plan:
        print(json.dumps({'product': 'bitcoin', 'ENABLE_POCX': 'OFF',
                          'recipe': '.github/ci-windows.py' if args.windows else 'ci/test/03_test_script.sh',
                          'BITCOIN_CONFIG': environment['BITCOIN_CONFIG'],
                          'status': 'not executed'}, indent=2))
        return
    if args.windows:
        if os.name != 'nt':
            raise ValueError('The inherited Windows fuzz recipe requires native Windows execution')
        from windows_ci import verify_recipe
        verify_recipe()
        run_windows()
    else:
        if environment.get('RUN_FUZZ_TESTS') != 'true':
            raise ValueError('The inherited POSIX fuzz recipe requires RUN_FUZZ_TESTS=true')
        root = Path(environment['BASE_ROOT_DIR']).resolve()
        if root != ROOT.resolve():
            raise ValueError('Inherited fuzz source tree does not match this worktree')
        from inherited_ci import verify_recipe
        verify_recipe()
        subprocess.run(['bash', str(root / 'ci/test/03_test_script.sh')], cwd=root, env=environment, check=True)


if __name__ == '__main__':
    main()
