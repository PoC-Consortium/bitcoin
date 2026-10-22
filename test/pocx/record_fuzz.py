#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin PoCX developers
# Distributed under the MIT software license; see COPYING.
"""Record post-link fuzz build provenance without executing cross-built code."""
import argparse
import json
from pathlib import Path

import fuzz_build


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for option in ('binary', 'inputs', 'cache', 'output'):
        parser.add_argument('--' + option, type=Path, required=True)
    args = parser.parse_args()
    args.output.write_text(json.dumps(fuzz_build.snapshot(args.binary, args.inputs, args.cache), indent=2) + '\n')


if __name__ == '__main__':
    main()
