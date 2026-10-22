# Copyright (c) 2026 The Bitcoin PoCX developers
# Distributed under the MIT software license; see COPYING.
"""Stream recipe output to the job console and retain identical raw log bytes."""
import os
import subprocess
import sys


def run_live(command, *, cwd, env, stdout, stderr):
    with subprocess.Popen(command, cwd=cwd, env=env, stdout=subprocess.PIPE, stderr=stderr) as child:
        try:
            while block := os.read(child.stdout.fileno(), 65536):
                stdout.buffer.write(block)
                stdout.flush()
                console = getattr(sys.stdout, 'buffer', None)
                if console is None:
                    sys.stdout.write(block.decode('utf-8', errors='replace'))
                else:
                    console.write(block)
                sys.stdout.flush()
            return subprocess.CompletedProcess(command, child.wait())
        except BaseException:
            child.kill()
            child.wait()
            raise
