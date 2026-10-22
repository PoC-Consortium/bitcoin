#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin PoCX developers
# Distributed under the MIT software license; see COPYING.
"""Exercise real child limits without changing the test harness's own stack."""
import json
import os
from pathlib import Path
import re
import shlex
import subprocess
import sys
import unittest
from unittest.mock import patch

from build_environment import run_build


class BuildEnvironmentTests(unittest.TestCase):
    @unittest.skipUnless(os.name == 'posix', 'POSIX shell/resource limits')
    def test_actual_inherited_shell_preserves_hard_limit_and_restricts_only_tests(self):
        import resource
        recipe = Path(__file__).parent / 'ci/inherited_test_script.sh'
        block = re.search(r'if \[ -n "\$\{CI_LIMIT_STACK_SIZE\}" \]; then\n.*?\nfi',
                          recipe.read_text(), re.S).group()
        initial_soft, initial_hard = resource.getrlimit(resource.RLIMIT_STACK)
        probe = '''import json,os,resource,sys
from build_environment import run_build
soft,hard=resource.getrlimit(resource.RLIMIT_STACK)
assert soft==int(os.environ['EXPECTED_TEST_STACK_SOFT'])
assert hard==int(os.environ['EXPECTED_TEST_STACK_HARD'])
child=run_build([sys.executable,'-c','import resource;print(resource.getrlimit(resource.RLIMIT_STACK)[0])'],capture_output=True,text=True,check=True)
assert int(child.stdout)>=8388608
assert resource.getrlimit(resource.RLIMIT_STACK)==(soft,hard)
print(json.dumps({'soft':soft,'hard':hard}))
'''
        for enabled in ('', '1'):
            with self.subTest(enabled=enabled):
                env = dict(os.environ, CI_LIMIT_STACK_SIZE=enabled,
                           EXPECTED_TEST_STACK_SOFT=str(524288 if enabled else initial_soft),
                           EXPECTED_TEST_STACK_HARD=str(initial_hard))
                execution = subprocess.run(['bash', '-ec', block + '\n' +
                    shlex.join([sys.executable, '-c', probe])], cwd=Path(__file__).parent,
                    env=env, capture_output=True, text=True, check=True)
                self.assertEqual(json.loads(execution.stdout)['hard'], initial_hard)

    @unittest.skipUnless(os.name == 'posix', 'POSIX resource limits')
    def test_build_child_gets_normal_stack_and_success_or_failure_preserves_test_limit(self):
        script = '''import json,resource,subprocess,sys
from build_environment import run_build
resource.setrlimit(resource.RLIMIT_STACK,(524288,resource.getrlimit(resource.RLIMIT_STACK)[1]))
child=run_build([sys.executable,'-c','import resource;print(resource.getrlimit(resource.RLIMIT_STACK)[0])'],capture_output=True,text=True,check=True)
assert int(child.stdout)==8388608
assert resource.getrlimit(resource.RLIMIT_STACK)[0]==524288
try:run_build([sys.executable,'-c','raise SystemExit(17)'],check=True)
except subprocess.CalledProcessError as error:assert error.returncode==17
else:raise AssertionError('Build failure was hidden')
print(json.dumps({'test_stack':resource.getrlimit(resource.RLIMIT_STACK)[0]}))
'''
        result = subprocess.run([sys.executable, '-c', script], cwd=Path(__file__).parent,
                                capture_output=True, text=True, check=True)
        self.assertEqual(json.loads(result.stdout)['test_stack'], 524288)

    @unittest.skipUnless(os.name == 'posix', 'POSIX resource limits')
    def test_insufficient_hard_limit_rejects_build_without_relaxing_test_stack(self):
        script = '''import resource,sys
from build_environment import run_build
resource.setrlimit(resource.RLIMIT_STACK,(524288,524288))
try:run_build([sys.executable,'-c','raise SystemExit(99)'],check=True)
except ValueError as error:assert 'soft limit only' in str(error)
else:raise AssertionError('Unsafe build limit was accepted')
assert resource.getrlimit(resource.RLIMIT_STACK)==(524288,524288)
'''
        subprocess.run([sys.executable, '-c', script], cwd=Path(__file__).parent,
                       capture_output=True, text=True, check=True)

    def test_windows_build_does_not_request_posix_child_setup(self):
        with patch('build_environment.os.name', 'nt'), patch('build_environment.subprocess.run') as run:
            run_build(['cmake', '--build', 'build'], check=True)
        run.assert_called_once_with(['cmake', '--build', 'build'], check=True)


if __name__ == '__main__':
    unittest.main()
