#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin PoCX developers
# Distributed under the MIT software license, see the accompanying file COPYING.
"""PoCX selection/staging around upstream per-test process and RPC mechanics."""
import argparse
from concurrent.futures import ThreadPoolExecutor
from contextlib import nullcontext
import json
import math
import os
import re
from pathlib import Path
from queue import Queue
from threading import Lock
import subprocess
import sys
import tempfile
import time
sys.dont_write_bytecode = True
from stage import stage, sha256
from common import exclusive_lock
import functional_environment
import functional_execution
import process_tree
import rpc_coverage
from functional_cases import selected_cases, selection_digest, upstream_cases


def port_seeds(base, jobs, max_nodes, port_range):
    # Upstream accepts port index MAX_NODES too. Leave one seed between slots
    # so this boundary cannot overlap the next slot's first node.
    capacity = (port_range - 1 - max_nodes) // (2 * max_nodes)
    if not 1 <= jobs <= capacity:
        raise ValueError(f'jobs must be between 1 and {capacity} for upstream port ranges')
    return [base + 2 * slot for slot in range(jobs)]


def shared_resource(case):
    spec, _mode = case
    # This unchanged upstream case binds literal ports 32171 and 32172.
    # Port seeds cannot isolate simultaneous copies in the transport matrix.
    if spec['test'] == 'rpc_bind.py' and '--ipv4' in spec['arguments']:
        return 'rpc_bind_literal_ports'
    if spec['test'] in ('feature_bind_port_discover.py', 'feature_bind_port_externalip.py'):
        return 'special_address_literal_ports'
    return None


def run_in_port_slots(cases, seeds, operation, resource_key=None):
    cases = list(cases)
    locks = {key: Lock() for case in cases
             if resource_key and (key := resource_key(case)) is not None}
    available = Queue()
    for seed in seeds:
        available.put(seed)

    def run(case):
        key = resource_key(case) if resource_key else None
        with locks[key] if key is not None else nullcontext():
            seed = available.get()
            try:
                return operation(case, seed)
            finally:
                available.put(seed)

    with ThreadPoolExecutor(max_workers=len(seeds)) as pool:
        return list(pool.map(run, cases))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--build-dir", required=True)
    parser.add_argument('--config', help='Explicit CMake configuration, required for multi-config generators')
    parser.add_argument("--jobs", type=int, default=2)
    parser.add_argument("--timeout", type=int, default=600)
    parser.add_argument('--timeout-factor', type=float,
                        help='Explicit upstream wait scaling, recorded separately from case identity')
    parser.add_argument('--transport', choices=['v1', 'v2', 'matrix'], default='v1',
                        help='Global upstream transport flag; matrix executes both modes')
    parser.add_argument('--case', action='append', default=[],
                        help='Exact case ID, e.g. "wallet_multiwallet.py --usecli"; repeatable')
    parser.add_argument('--usecli', action='store_true', help='Preserve inherited global CLI execution')
    parser.add_argument('--multiprocess', action='store_true', help='Use the pinned bitcoin -m wrapper')
    parser.add_argument('--previous-releases', action='store_true')
    parser.add_argument('--coverage', action='store_true', help='Require complete upstream RPC coverage per transport')
    parser.add_argument('--previous-releases-dir', type=Path)
    parser.add_argument('--network-addresses', action='store_true',
                        help='Require configured special addresses and run both address-dependent tests')
    parser.add_argument("tests", nargs="*")
    args = parser.parse_args()
    if args.jobs < 1 or args.timeout < 1:
        parser.error("jobs and timeout must be positive")
    if args.timeout_factor is not None and (not math.isfinite(args.timeout_factor) or args.timeout_factor <= 0):
        parser.error('timeout factor must be finite and positive')
    if args.case and args.tests:
        parser.error('Use either filename selection or --case')
    if args.previous_releases_dir and not args.previous_releases:
        parser.error('--previous-releases-dir requires --previous-releases')
    build = Path(args.build_dir).resolve()
    # Serialize staging and port allocation across invocations for this build.
    with exclusive_lock(build / "pocx-runner.lock"):
        tree, manifest, provenance = stage(build, selected_config=args.config)
        inventory = list(manifest["tests"]) + manifest["reused_tests"]
        tests = args.tests or inventory
        if not tests or len(tests) != len(set(tests)) or set(tests) - set(inventory):
            parser.error("Empty, duplicate or unknown test selection")
        upstream_runner = Path(__file__).resolve().parents[1] / 'functional/test_runner.py'
        inventory_cases = selected_cases(manifest, upstream_cases(upstream_runner))
        if args.case:
            if len(args.case) != len(set(args.case)) or set(args.case) - {case['id'] for case in inventory_cases}:
                parser.error('Duplicate or unknown functional case selection')
            selection = [case for case in inventory_cases if case['id'] in args.case]
        else:
            selection = [case for case in inventory_cases if case['test'] in tests]
        tests = list(dict.fromkeys(case['test'] for case in selection))
        paths = functional_execution.binary_paths(build, (build / 'CMakeCache.txt').read_text(),
                                                  provenance['build_configuration'])
        for name in ('bitcoind', 'bitcoin-cli'):
            if not paths[name].is_file():
                raise ValueError(f'Missing binary: {paths[name]}')
        binaries = {name: path for name, path in paths.items() if path.is_file()}
        provenance["binaries"] = {name: {"path": str(path), "sha256": sha256(path)} for name, path in binaries.items()}
        environment_profile = {'previous_releases': args.previous_releases,
                               'network_addresses': args.network_addresses}
        functional_environment.arguments('', environment_profile)
        if args.network_addresses:
            provenance['network_interfaces'] = functional_environment.verify_network_addresses()
        releases = (args.previous_releases_dir or Path(__file__).resolve().parents[2] / 'releases').resolve()
        previous_binaries = functional_environment.release_binaries(releases) if args.previous_releases else {}
        provenance['previous_release_binaries'] = {
            name: {'path': str(path), 'sha256': sha256(path)} for name, path in previous_binaries.items()}
        provenance['previous_releases_directory'] = str(releases) if args.previous_releases else None
        modes = ['v1', 'v2'] if args.transport == 'matrix' else [args.transport]
        provenance.update(format_version=9, process_controller=process_tree.description(),
                          selected_tests=tests, selected_cases=selection, transport_modes=modes,
                          environment_profile=environment_profile,
                          case_selection={'source': 'test/pocx/functional_cases.py',
                                          'sha256': sha256(Path(__file__).with_name('functional_cases.py')),
                                          'selected_cases_sha256': selection_digest(selection)},
                          upstream_runner={'source': 'test/functional/test_runner.py',
                                           'sha256': sha256(upstream_runner)},
                          runner={'source': 'test/pocx/test_runner.py',
                                  'sha256': sha256(Path(__file__).resolve())})
        provenance.update(execution_options=functional_execution.settings(args.usecli, args.multiprocess),
                          timeout_factor=args.timeout_factor if args.timeout_factor is not None else 1)
        # Start long upstream extended cases early, with both transports next
        #to each other. Preserve the declared selection and every case identity.
        extended = {row['id'] for row in upstream_cases(upstream_runner)
                    if row['selection'] == 'EXTENDED_SCRIPTS'}
        dispatch = sorted(selection, key=lambda spec: spec['id'] not in extended)
        cases = [(spec, mode) for spec in dispatch for mode in modes]
        results_dir = Path(tempfile.mkdtemp(prefix="pocx-results-", dir=build))
        coverage_directories = {}
        if args.coverage:
            provenance.update(format_version=10, rpc_coverage=True,
                              rpc_coverage_helper_sha256=sha256(Path(rpc_coverage.__file__)))
            for mode in modes:
                directory = (results_dir if mode == 'v1' else results_dir / 'v2') / 'rpc-coverage'
                directory.mkdir(parents=True)
                coverage_directories[mode] = directory
        env = {key: value for key, value in os.environ.items()
               if key not in {"PYTHONPATH", "BITCOIN_CMD", "BITCOIND", "BITCOINCLI", "BITCOIN_BIN", "BITCOIN_BENCH", "BITCOINUTIL", "BITCOINTX", "BITCOINCHAINSTATE", "BITCOINWALLET"}}
        env['PYTHONDONTWRITEBYTECODE'] = '1'
        env.update(functional_execution.binary_environment(paths, os.environ.get('PATH', '')))
        env.update(functional_execution.environment(provenance, binaries, provenance['build_options']))
        # Upstream auto-enables older releases when this directory is populated.
        # Keep a disabled profile deterministic even with inherited environment.
        env['PREVIOUS_RELEASES_DIR'] = str(releases if args.previous_releases else build / 'previous-releases-disabled')
        if not args.previous_releases and Path(env['PREVIOUS_RELEASES_DIR']).exists():
            raise ValueError('Disabled previous-release profile directory must not exist')
        # Validate every imported framework module's origin before running tests.
        probe = "import json,pathlib,sys; from test_framework import test_framework,util; root=pathlib.Path.cwd(); assert all(pathlib.Path(m.__file__).resolve().is_relative_to(root) for n,m in sys.modules.items() if n.startswith('test_framework') and getattr(m,'__file__',None)); print(json.dumps([util.MAX_NODES,util.PORT_RANGE]))"
        max_nodes, port_range = json.loads(subprocess.check_output([sys.executable, '-c', probe], cwd=tree, env=env, text=True))
        seeds = port_seeds(os.getpid(), args.jobs, max_nodes, port_range)
        provenance['port_allocation'] = {'seeds': seeds, 'max_nodes': max_nodes, 'port_range': port_range,
                                       'scope': 'Concurrent slots reused only after owned process-group cleanup'}

        def run(item, seed):
            spec, mode = item
            name = spec['test']
            suffix = '-' + selection_digest([spec])[:16] if spec['arguments'] else ''
            directory = name.removesuffix('.py') + suffix
            logfile = name + suffix + '.log'
            mode_dir = results_dir if mode == 'v1' else results_dir / 'v2'
            mode_dir.mkdir(exist_ok=True)
            test_arguments = [*spec['arguments'], *functional_execution.arguments(provenance, spec['arguments']),
                              *functional_environment.arguments(name, environment_profile),
                              *functional_environment.timeout_arguments(provenance),
                              *(['--coveragedir=' + str(coverage_directories[mode])] if args.coverage else []),
                              f'--{mode}transport']
            command = [sys.executable, str(tree / name), f"--configfile={tree / 'config.ini'}",
                       f"--tmpdir={mode_dir / directory}",
                       f"--cachedir={results_dir / 'cache'}", f"--portseed={seed}",
                       "--randomseed=0", "--nocleanup", *test_arguments]
            start = time.monotonic()
            with (mode_dir / logfile).open("w") as log:
                execution = process_tree.execute(command, cwd=tree, env=env, log=log, timeout=args.timeout)
            code, timed_out = execution['returncode'], execution['timed_out']
            status = 'passed' if code == 0 and not timed_out else 'skipped' if code == 77 and not timed_out else 'failed'
            result = {"test": name, 'case': spec['id'], 'case_arguments': spec['arguments'],
                      'transport': mode, 'test_arguments': test_arguments, 'port_seed': seed,
                      'output_dir': str(mode_dir / directory),
                      'log': str(mode_dir / logfile),
                      "command": command, "returncode": code, "timed_out": timed_out,
                      "status": status,
                      'process_control': execution['process_control'],
                      "seconds": time.monotonic() - start}
            if provenance.get('format_version', 1) >= 7:
                result['execution_options'] = functional_execution.recorded(provenance)
            if status == 'skipped':
                reasons = re.findall(r'Test Skipped: (.+)', (mode_dir / logfile).read_text())
                result['skip_reason'] = reasons[-1] if reasons else 'Exit 77 without a reported skip reason; review required'
            print(f"{spec['id']} ({mode}): {result['status']}", flush=True)
            return result

        results = run_in_port_slots(cases, seeds, run, shared_resource)
        if any(sha256(path) != provenance['binaries'][name]['sha256'] for name, path in binaries.items()) or any(
                sha256(path) != provenance['previous_release_binaries'][name]['sha256']
                for name, path in previous_binaries.items()):
            raise ValueError('Functional executable changed during execution')
        report = {"provenance": provenance, "results": results}
        if args.coverage:
            report['rpc_coverage'] = {}
            # Retain terminal cases even if a missing reference prevents the
            # coverage evaluator from completing. An incomplete gate fails.
            (results_dir / "results.json").write_text(json.dumps(report, indent=2) + "\n")
            for mode, directory in coverage_directories.items():
                report['rpc_coverage'][mode] = rpc_coverage.evaluate(directory, env)
                (results_dir / "results.json").write_text(json.dumps(report, indent=2) + "\n")
        (results_dir / "results.json").write_text(json.dumps(report, indent=2) + "\n")
        print(f"Results: {results_dir}")
        return 0 if all(result["status"] == "passed" for result in results) and rpc_coverage.verify(report) else 1


if __name__ == "__main__":
    sys.exit(main())
