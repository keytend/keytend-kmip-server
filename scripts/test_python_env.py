# Copyright 2026 Jeremiah Jordan
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Tests for the scripts' virtual environment helper (scripts/python_env.py). No network."""
import ast
import pathlib
import re
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import python_env  # noqa: E402

ROOT = python_env.ROOT


def requirement_names(path):
    return {re.split(r'[=; \\]', line)[0].lower().replace('_', '-') for line in path.read_text().splitlines()
            if line and not line.startswith((' ', '#'))}


class PythonEnv(unittest.TestCase):
    def test_marker_must_match_the_current_lock(self):
        with tempfile.TemporaryDirectory() as directory:
            venv = pathlib.Path(directory)
            self.assertFalse(python_env.built(venv))
            (venv/python_env.MARKER).write_text('0'*64+'\n')
            self.assertFalse(python_env.built(venv))
            (venv/python_env.MARKER).write_text(python_env.lock_sha256()+'\n')
            self.assertTrue(python_env.built(venv))

    def test_default_dir_is_keyed_by_the_lock(self):
        with mock.patch.dict('os.environ', {'KEYTEND_CACHE_DIR': '/c'}):
            name = python_env.default_dir()
        self.assertEqual(name.parent, pathlib.Path('/c/python'))
        self.assertTrue(name.name.startswith('scripts-'+python_env.lock_sha256()[:16]+'-py'))
        with mock.patch.dict('os.environ', {'KEYTEND_CACHE_DIR': '/c'}):
            self.assertTrue(python_env.default_dir(python_env.INTEROP_LOCK).name.startswith('interop-'))

    def test_environment_puts_the_venv_first(self):
        env = python_env.environment(pathlib.Path('/v'), {'PATH': '/usr/bin', 'PYTHONHOME': '/x'})
        self.assertEqual(env['PATH'], '/v/bin:/usr/bin')
        self.assertEqual(env['VIRTUAL_ENV'], '/v')
        self.assertNotIn('PYTHONHOME', env)

    @staticmethod
    def fake_run(calls, venv_code=0, pip_code=0):
        def run(command, **options):
            calls.append([str(c) for c in command])
            if command[1:3] == ['-m', 'venv']:
                pathlib.Path(command[3]).mkdir(parents=True)
                (pathlib.Path(command[3])/'pyvenv.cfg').write_text('home = /usr/bin\n')
                return subprocess.CompletedProcess(command, venv_code)
            return subprocess.CompletedProcess(command, pip_code)
        return run

    def test_ensure_installs_the_lock_with_hashes_once(self):
        calls = []
        with tempfile.TemporaryDirectory() as directory, mock.patch('subprocess.run', self.fake_run(calls)):
            venv = pathlib.Path(directory)/'v'
            self.assertEqual(python_env.ensure(venv), venv)
            self.assertTrue(python_env.built(venv))
            pip = calls[1]
            for flag in ('--require-hashes', '--only-binary=:all:', str(python_env.LOCK)):
                self.assertIn(flag, pip)
            python_env.ensure(venv)
            self.assertEqual(len(calls), 2, 'a built environment is reused')
            python_env.ensure(pathlib.Path(directory)/'i', python_env.INTEROP_LOCK)
            self.assertIn(str(python_env.INTEROP_LOCK), calls[-1])

    def test_ensure_refuses_a_directory_that_is_not_an_environment(self):
        with tempfile.TemporaryDirectory() as directory, mock.patch('subprocess.run', self.fake_run([])):
            (pathlib.Path(directory)/'keep.txt').write_text('x')
            with self.assertRaisesRegex(SystemExit, 'not a virtual environment'):
                python_env.ensure(directory)
            self.assertTrue((pathlib.Path(directory)/'keep.txt').exists())

    def test_ensure_explains_failures(self):
        with tempfile.TemporaryDirectory() as directory:
            with mock.patch('subprocess.run', self.fake_run([], venv_code=1)), self.assertRaisesRegex(SystemExit, 'python3-venv'):
                python_env.ensure(pathlib.Path(directory)/'a')
            with mock.patch('subprocess.run', self.fake_run([], pip_code=1)), self.assertRaisesRegex(SystemExit, 'PyPI'):
                python_env.ensure(pathlib.Path(directory)/'b')
            self.assertFalse(python_env.built(pathlib.Path(directory)/'b'))
            with mock.patch.object(python_env.sys, 'version_info', (3, 11, 9)), self.assertRaisesRegex(SystemExit, '3.12 or later'):
                python_env.ensure(pathlib.Path(directory)/'c')

    def test_activate_restarts_in_the_environment(self):
        venv = pathlib.Path('/v')
        with mock.patch.object(python_env, 'ensure', return_value=venv), mock.patch.object(python_env, 'current', return_value=None), \
                mock.patch.dict('os.environ', {'PATH': '/usr/bin'}, clear=True), mock.patch('os.execve') as execve:
            python_env.activate()
            path, argv, env = execve.call_args.args
            self.assertEqual((path, argv[0]), (venv/'bin/python3', '/v/bin/python3'))
            self.assertEqual(argv[1:], sys.orig_argv[1:])
            self.assertEqual((env['PATH'], env['KEYTEND_PYTHON_ENV']), ('/v/bin:/usr/bin', '/v'))
            with mock.patch.dict('os.environ', {'KEYTEND_PYTHON_ENV': '/v'}), self.assertRaises(SystemExit):
                python_env.activate()

    def test_activate_in_the_environment_puts_it_first_on_path(self):
        venv = pathlib.Path('/v')
        with mock.patch.object(python_env, 'ensure', return_value=venv), mock.patch.object(python_env, 'current', return_value=venv), \
                mock.patch.dict('os.environ', {'PATH': '/usr/bin'}, clear=True), mock.patch('os.execve') as execve:
            self.assertEqual(python_env.activate(), venv)
            execve.assert_not_called()
            self.assertEqual(python_env.os.environ['PATH'], '/v/bin:/usr/bin')

    def test_record(self):
        record = python_env.record()
        self.assertEqual(record['lock'], 'scripts/requirements.txt')
        self.assertEqual(record['lock_sha256'], python_env.lock_sha256())
        self.assertIsInstance(record['packages'], dict)
        self.assertEqual(record['version'], '.'.join(map(str, sys.version_info[:3])))

    def test_lock_needs_uv_and_reports_its_failure(self):
        with mock.patch('shutil.which', return_value=None), self.assertRaisesRegex(SystemExit, 'pipx install uv'):
            python_env.lock()
        failed = subprocess.CompletedProcess([], 1, '')
        with mock.patch('shutil.which', return_value='/bin/uv'), mock.patch('subprocess.run', return_value=failed), \
                self.assertRaisesRegex(SystemExit, 'could not resolve'):
            python_env.lock([python_env.LOCK])

    def test_lock_keeps_the_header(self):
        with tempfile.TemporaryDirectory() as directory:
            lock = pathlib.Path(directory)/'requirements.txt'
            lock.write_text('# licence\n#\n# text\n\n# how to regenerate\n\nold==1 \\\n    --hash=sha256:00\n')
            compiled = subprocess.CompletedProcess([], 0, 'new==2 \\\n    --hash=sha256:11\n')
            lock.with_suffix('.in').write_text('')
            with mock.patch.object(python_env, 'ROOT', pathlib.Path(directory)), mock.patch('shutil.which', return_value='/bin/uv'), \
                    mock.patch('subprocess.run', return_value=compiled):
                python_env.lock([lock])
            self.assertEqual(lock.read_text(), '# licence\n#\n# text\n\n# how to regenerate\n\nnew==2 \\\n    --hash=sha256:11\n')

    def test_every_pin_has_hashes_and_the_direct_requirements_are_locked(self):
        for lock in python_env.LOCKS:
            blocks = re.split(r'\n(?=\S)', lock.read_text().split('\n\n', 2)[2].strip())
            self.assertTrue(blocks)
            for block in blocks:
                self.assertRegex(block, r'^\S+==\S+', block)
                self.assertIn('--hash=sha256:', block, block)
        for lock in python_env.LOCKS:
            self.assertLessEqual(requirement_names(lock.with_suffix('.in')), requirement_names(lock))

    def test_third_party_imports_are_requirements(self):
        """Every module the scripts and export import is the standard library, a local module or in requirements.in."""
        provided = {'bs4': 'beautifulsoup4', 'cryptography': 'cryptography', 'yaml': 'pyyaml'}
        direct = requirement_names(python_env.SCRIPTS/'requirements.in')
        files = [*(ROOT/'scripts').glob('*.py'), *(ROOT/'export').glob('*.py')]
        local = {path.stem for path in files}
        for path in files:
            for node in ast.walk(ast.parse(path.read_text())):
                names = [a.name for a in node.names] if isinstance(node, ast.Import) else \
                    [node.module] if isinstance(node, ast.ImportFrom) and node.level == 0 else []
                for name in names:
                    top = name.split('.')[0]
                    if top in sys.stdlib_module_names or top in local:
                        continue
                    self.assertIn(provided.get(top), direct, f'{path.name} imports {top}')


if __name__ == '__main__':
    unittest.main()
