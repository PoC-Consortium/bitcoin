#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin PoCX developers
# Distributed under the MIT software license, see the accompanying file COPYING.
"""PoCX selection/staging around upstream per-test process and RPC mechanics."""
import argparse
from concurrent.futures import ThreadPoolExecutor
from contextlib import nullcontext
import fcntl
import json
import os
import re
from pathlib import Path
from queue import Queue
from threading import Lock
import signal
import subprocess
import sys
import tempfile
import time
sys.dont_write_bytecode = True
from stage import stage, sha256
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
    return 'rpc_bind_literal_ports' if spec['test'] == 'rpc_bind.py' and '--ipv4' in spec['arguments'] else None


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
    parser.add_argument("--jobs", type=int, default=2)
    parser.add_argument("--timeout", type=int, default=600)
    parser.add_argument('--transport', choices=['v1', 'v2', 'matrix'], default='v1',
                        help='Global upstream transport flag; matrix executes both modes')
    parser.add_argument('--case', action='append', default=[],
                        help='Exact case ID, e.g. "wallet_multiwallet.py --usecli"; repeatable')
    parser.add_argument("tests", nargs="*")
    args = parser.parse_args()
    if args.jobs < 1 or args.timeout < 1:
        parser.error("jobs and timeout must be positive")
    if args.case and args.tests:
        parser.error('Use either filename selection or --case')
    build = Path(args.build_dir).resolve()
    # Serialize staging and port allocation across invocations for this build.
    with (build / "pocx-runner.lock").open("w") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        tree, manifest, provenance = stage(build)
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
        binaries = {name: build / "bin" / name for name in ["bitcoind", "bitcoin-cli"]}
        for name, path in binaries.items():
            if not path.is_file():
                raise ValueError(f"Missing binary: {path}")
        provenance["binaries"] = {name: {"path": str(path), "sha256": sha256(path)} for name, path in binaries.items()}
        modes = ['v1', 'v2'] if args.transport == 'matrix' else [args.transport]
        provenance.update(format_version=4, selected_tests=tests, selected_cases=selection, transport_modes=modes,
                          case_selection={'source': 'test/pocx/functional_cases.py',
                                          'sha256': sha256(Path(__file__).with_name('functional_cases.py')),
                                          'selected_cases_sha256': selection_digest(selection)},
                          upstream_runner={'source': 'test/functional/test_runner.py',
                                           'sha256': sha256(upstream_runner)},
                          runner={'source': 'test/pocx/test_runner.py',
                                  'sha256': sha256(Path(__file__).resolve())})
        # Start long upstream extended cases early, with both transports next
        #to each other. Preserve the declared selection and every case identity.
        extended = {row['id'] for row in upstream_cases(upstream_runner)
                    if row['selection'] == 'EXTENDED_SCRIPTS'}
        dispatch = sorted(selection, key=lambda spec: spec['id'] not in extended)
        cases = [(spec, mode) for spec in dispatch for mode in modes]
        results_dir = Path(tempfile.mkdtemp(prefix="pocx-results-", dir=build))
        env = {key: value for key, value in os.environ.items()
               if key not in {"PYTHONPATH", "BITCOIN_CMD", "BITCOIND", "BITCOINCLI", "BITCOIN_BIN", "BITCOIN_BENCH", "BITCOINUTIL", "BITCOINTX", "BITCOINCHAINSTATE", "BITCOINWALLET"}}
        env.update(PYTHONDONTWRITEBYTECODE="1", BITCOIND=str(binaries["bitcoind"]), BITCOINCLI=str(binaries["bitcoin-cli"]))
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
            test_arguments = [*spec['arguments'], f'--{mode}transport']
            command = [sys.executable, str(tree / name), f"--configfile={tree / 'config.ini'}",
                       f"--tmpdir={mode_dir / directory}",
                       f"--cachedir={results_dir / 'cache'}", f"--portseed={seed}",
                       "--randomseed=0", "--nocleanup", *test_arguments]
            start = time.monotonic()
            timed_out = False
            with (mode_dir / logfile).open("w") as log:
                process = subprocess.Popen(command, cwd=tree, env=env, stdout=log, stderr=subprocess.STDOUT, start_new_session=True)
                try:
                    code = process.wait(timeout=args.timeout)
                except subprocess.TimeoutExpired:
                    timed_out = True
                    os.killpg(process.pid, signal.SIGTERM)
                    try:
                        process.wait(timeout=15)
                    except subprocess.TimeoutExpired:
                        os.killpg(process.pid, signal.SIGKILL)
                        process.wait()
                    code = process.returncode
                finally:
                    # Own session only: also clean descendants left by an abnormal test exit.
                    try:
                        os.killpg(process.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
            status = 'passed' if code == 0 and not timed_out else 'skipped' if code == 77 and not timed_out else 'failed'
            result = {"test": name, 'case': spec['id'], 'case_arguments': spec['arguments'],
                      'transport': mode, 'test_arguments': test_arguments, 'port_seed': seed,
                      'output_dir': str(mode_dir / directory),
                      'log': str(mode_dir / logfile),
                      "command": command, "returncode": code, "timed_out": timed_out,
                      "status": status,
                      "seconds": time.monotonic() - start}
            if status == 'skipped':
                reasons = re.findall(r'Test Skipped: (.+)', (mode_dir / logfile).read_text())
                result['skip_reason'] = reasons[-1] if reasons else 'Exit 77 without a reported skip reason; review required'
            print(f"{spec['id']} ({mode}): {result['status']}", flush=True)
            return result

        results = run_in_port_slots(cases, seeds, run, shared_resource)
        (results_dir / "results.json").write_text(json.dumps({"provenance": provenance, "results": results}, indent=2) + "\n")
        print(f"Results: {results_dir}")
        return 0 if all(result["status"] == "passed" for result in results) else 1


if __name__ == "__main__":
    sys.exit(main())
