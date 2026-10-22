#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin PoCX developers
# Distributed under the MIT software license; see COPYING.
"""Register every compiled Boost suite, failing missing/empty discovery."""
import argparse
import json
from pathlib import Path
import re
import subprocess
import pocx_bootstrap as pocx_bootstrap
from unit_build import snapshot

parser = argparse.ArgumentParser()
parser.add_argument("--binary", required=True)
parser.add_argument("--output", required=True)
parser.add_argument("--inputs", type=Path)
parser.add_argument("--cache", type=Path)
args = parser.parse_args()
result = subprocess.run([args.binary, "--list_content"], text=True, capture_output=True, check=True)
output = result.stdout + result.stderr
suites = re.findall(r"^([A-Za-z_][A-Za-z_0-9]*)\*?$", output, re.M)
if not suites or not {"pocx_tests", "pocx_simd_tests"}.issubset(suites):
    raise SystemExit(f"Missing PoCX suites or empty discovery:\n{output}")
if not args.inputs or not args.cache:
    raise SystemExit('Missing evaluated source inputs or cache for unit build provenance')
evidence = snapshot(Path(args.binary), args.inputs, args.cache, suites)
lines = []
for suite in suites:
    lines.append(f'add_test([=[{suite}]=] [=[{args.binary}]=] --run_test={suite} --catch_system_error=no --log_level=test_suite -- DEBUG_LOG_OUT)')
    # A per-test TIMEOUT overrides CTest's --timeout. Keep timing with the
    # runner: ordinary unit runs request180seconds, inherited sanitizer CI2400.
    lines.append(f'set_tests_properties([=[{suite}]=] PROPERTIES FAIL_REGULAR_EXPRESSION "no test cases matching filter" SKIP_REGULAR_EXPRESSION "skipping script_assets_test;skipping total_ram")')
Path(args.output).write_text("\n".join(lines) + "\n")
Path(args.output).with_suffix('.boost.txt').write_text(output)
Path(args.output).with_suffix('.build.json').write_text(json.dumps(evidence, indent=2) + '\n')
print(f"Registered {len(suites)} compiled PoCX suites")
