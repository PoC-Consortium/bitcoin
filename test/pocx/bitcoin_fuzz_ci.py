#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin PoCX developers
# Distributed under the MIT software license; see COPYING.
"""Execute matching inherited fuzz recipes for the selected product."""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import subprocess

from common import ROOT


def environment_for_fuzz(environment):
    product = environment.get('CI_PRODUCT')
    if product not in ('bitcoin', 'pocx'):
        raise ValueError('Fuzz execution requires CI_PRODUCT=bitcoin or pocx')
    selected = 'OFF' if product == 'bitcoin' else 'ON'
    return dict(environment, BITCOIN_CONFIG=environment.get('BITCOIN_CONFIG', '') + f' -DENABLE_POCX={selected}')


def pocx_posix_recipe(original):
    """Retain every inherited setup/build step; replace only fuzz dispatch."""
    marker = '\nif [ "$RUN_FUZZ_TESTS" = "true" ]; then\n'
    if original.count(marker) != 2:
        raise ValueError('Inherited fuzz dispatch changed')
    prefix, _, original_dispatch = original.rpartition(marker)
    if not original_dispatch.endswith('\nfi\n') or 'test/fuzz/test_runner.py' not in original_dispatch:
        raise ValueError('Inherited fuzz runner changed')
    replacement = '''
if [ "$RUN_FUZZ_TESTS" = "true" ]; then
  LD_LIBRARY_PATH="${DEPENDS_DIR}/${HOST}/lib" \\
  python3 "${BASE_ROOT_DIR}/test/pocx/ci_fuzz_run.py" \\
    --build-dir "${BASE_BUILD_DIR}" --upstream "${DIR_FUZZ_IN}" \\
    --makejobs="${MAKEJOBS}" --fuzz-tests-config="${FUZZ_TESTS_CONFIG}"
fi
'''
    return prefix + replacement


def run_windows(root=ROOT, *, product='bitcoin', load=None, run_pocx=None):
    if product not in ('bitcoin', 'pocx'):
        raise ValueError('Unknown fuzz product')
    if load is None:
        spec = importlib.util.spec_from_file_location('original_windows_fuzz', root / '.github/ci-windows.py')
        driver = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(driver)
    else:
        driver = load()
    # Keep all original toolchain options and driver steps, selecting only the
    # product whose upstream fuzz targets and assertions are being exercised.
    selected = 'OFF' if product == 'bitcoin' else 'ON'
    driver.GENERATE_OPTIONS['fuzz'] = [*driver.GENERATE_OPTIONS['fuzz'], f'-DENABLE_POCX={selected}']
    driver.generate('fuzz')
    cache = (root / 'build/CMakeCache.txt').read_text()
    if f'ENABLE_POCX:BOOL={selected}' not in cache.splitlines():
        raise ValueError('Inherited Windows fuzz configuration selected wrong product')
    for step in (driver.build, driver.check_manifests, driver.prepare_tests):
        step('fuzz')
    if product == 'bitcoin':
        driver.run_tests('fuzz')
    elif run_pocx is not None:
        run_pocx()
    else:
        subprocess.run([os.environ.get('PYTHON', 'python'), str(root / 'test/pocx/ci_fuzz_run.py'),
                        '--build-dir', str(root / 'build'), '--config', 'Release',
                        '--upstream', str(root / 'qa-assets/fuzz_corpora'),
                        '--jobs', str(os.process_cpu_count())], cwd=root, check=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--windows', action='store_true')
    parser.add_argument('--plan', action='store_true', help='Print selection only; does not execute fuzz tests')
    args = parser.parse_args()
    environment = environment_for_fuzz(os.environ)
    if args.plan:
        print(json.dumps({'product': environment['CI_PRODUCT'],
                          'ENABLE_POCX': 'OFF' if environment['CI_PRODUCT'] == 'bitcoin' else 'ON',
                          'recipe': '.github/ci-windows.py' if args.windows else 'ci/test/03_test_script.sh',
                          'BITCOIN_CONFIG': environment['BITCOIN_CONFIG'],
                          'status': 'not executed'}, indent=2))
        return
    if args.windows:
        if os.name != 'nt':
            raise ValueError('The inherited Windows fuzz recipe requires native Windows execution')
        from windows_ci import verify_recipe
        verify_recipe()
        run_windows(product=environment['CI_PRODUCT'])
    else:
        if environment.get('RUN_FUZZ_TESTS') != 'true':
            raise ValueError('The inherited POSIX fuzz recipe requires RUN_FUZZ_TESTS=true')
        root = Path(environment['BASE_ROOT_DIR']).resolve()
        if root != ROOT.resolve():
            raise ValueError('Inherited fuzz source tree does not match this worktree')
        from inherited_ci import verify_recipe
        verify_recipe()
        script = root / 'ci/test/03_test_script.sh'
        if environment['CI_PRODUCT'] == 'bitcoin':
            subprocess.run(['bash', str(script)], cwd=root, env=environment, check=True)
        else:
            recipe = pocx_posix_recipe(script.read_text())
            subprocess.run(['bash', '-s'], cwd=root, env=environment,
                           input=recipe, text=True, check=True)


if __name__ == '__main__':
    main()
