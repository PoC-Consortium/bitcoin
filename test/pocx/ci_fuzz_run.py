#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin PoCX developers
# Distributed under the MIT software license; see COPYING.
"""Stage complete upstream corpora and execute the selected PoCX fuzz binary."""
import argparse
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import sys

from common import ROOT
import fuzz_parity
import stage_fuzz_corpus


def jobs_from_makejobs(value):
    words = shlex.split(value)
    if not words:
        return os.process_cpu_count()
    if len(words) == 2 and words[0] in ('-j', '--parallel'):
        return int(words[1])
    if len(words) == 1 and words[0].startswith('-j'):
        return int(words[0][2:])
    raise ValueError('Unsupported inherited MAKEJOBS setting: ' + value)


def run(build, upstream, *, config=None, jobs=None, makejobs=None, fuzz_tests_config=''):
    if os.environ.get('CI_PRODUCT') not in (None, 'pocx'):
        raise ValueError('PoCX fuzz driver cannot execute the original Bitcoin product')
    fuzz_extra = shlex.split(fuzz_tests_config)
    if fuzz_extra not in ([], ['--valgrind']):
        raise ValueError('Unreviewed inherited FUZZ_TESTS_CONFIG: ' + fuzz_tests_config)
    if makejobs is not None:
        if jobs is not None:
            raise ValueError('Specify jobs or MAKEJOBS, not both')
        jobs = jobs_from_makejobs(makejobs)
    if jobs is None:
        jobs = os.process_cpu_count()
    if jobs < 1:
        raise ValueError('Fuzz worker count must be positive')
    problems = fuzz_parity.check()
    if problems:
        raise ValueError('Fuzz source review failed: ' + str(problems))
    build = build.resolve()
    corpus = stage_fuzz_corpus.stage(build, upstream.resolve(), selected_config=config)
    before = set(build.glob('fuzz-results-*'))
    command = [sys.executable, str(ROOT / 'test/pocx/run_fuzz.py'),
               '--build-dir', str(build), '--corpus', str(corpus), '--jobs', str(jobs)]
    if config is not None:
        command += ['--config', config]
    if fuzz_extra:
        command += fuzz_extra
    try:
        subprocess.run(command, cwd=ROOT, check=True)
    finally:
        # Preserve both passing and failing reports from the disposable CI
        # container, with their exact logs and build/corpus provenance.
        generated = set(build.glob('fuzz-results-*')) - before
        if generated:
            if len(generated) != 1:
                raise ValueError('Ambiguous PoCX fuzz result directories')
            evidence = ROOT / 'artifacts/pocx-inherited/fuzz'
            evidence.mkdir(parents=True, exist_ok=True)
            run_record = generated.pop()
            retained = evidence / run_record.name
            shutil.copytree(run_record, retained)
            shutil.copyfile(corpus.parent / 'provenance.json', retained / 'corpus-provenance.json')
            build_record = build / 'pocx-fuzz-build'
            if config is not None and (build_record / config).is_dir():
                build_record /= config
            for name in ('build.json', 'build-inputs.txt', 'selection.txt'):
                shutil.copyfile(build_record / name, retained / name)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--build-dir', type=Path, required=True)
    parser.add_argument('--upstream', type=Path, required=True)
    parser.add_argument('--config')
    parser.add_argument('--jobs', type=int)
    parser.add_argument('--makejobs')
    parser.add_argument('--fuzz-tests-config', default='')
    args = parser.parse_args()
    run(args.build_dir, args.upstream, config=args.config, jobs=args.jobs,
        makejobs=args.makejobs, fuzz_tests_config=args.fuzz_tests_config)


if __name__ == '__main__':
    main()
