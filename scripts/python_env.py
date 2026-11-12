#!/usr/bin/env python3
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

"""The scripts' Python: a virtual environment built from the hash-locked scripts/requirements.txt.

Third-party modules come only from hash-locked virtual environments, never from
system packages. A local release run (scripts/release_candidate.py) restarts itself
in this one with its bin/ first on PATH, so every step started as `python3` uses it;
the release workflow builds it with `scripts/ci_runner.sh python`. The interop
clients' environment (interop/requirements.txt) is built the same way.

    python_env.py               create the environment if needed and print its directory
    python_env.py --venv DIR    the same, in DIR
    python_env.py lock          regenerate every requirements.txt from its requirements.in (needs uv)

The default directory is in the shared cache, named after the lock's SHA-256, the
Python version and the machine, so a changed lock gets a new environment. This file
uses only the standard library: it runs on the system Python before any environment exists.
"""
import argparse
import fcntl
import hashlib
import importlib.metadata
import os
import pathlib
import platform
import shutil
import subprocess
import sys

SCRIPTS = pathlib.Path(__file__).resolve().parent
ROOT = SCRIPTS.parent
LOCK = SCRIPTS/'requirements.txt'
INTEROP_LOCK = ROOT/'interop/requirements.txt'
# Every lock, generated from the requirements.in beside it.
LOCKS = [LOCK, INTEROP_LOCK]
# The locks are compiled for this version and later.
MINIMUM = (3, 12)
# Written last into a finished environment: the SHA-256 of the lock it was built from.
MARKER = 'requirements.sha256'
COMPILE = ['uv', 'pip', 'compile', '--universal', '--python-version', '.'.join(map(str, MINIMUM)), '--generate-hashes', '--no-header', '--quiet']


def lock_sha256(lock=LOCK):
    return hashlib.sha256(pathlib.Path(lock).read_bytes()).hexdigest()


def built(venv, lock=LOCK):
    """True when venv is a finished environment built from the current lock."""
    try:
        return (pathlib.Path(venv)/MARKER).read_text().strip() == lock_sha256(lock)
    except OSError:
        return False


def current():
    """This interpreter's environment, when it was built from the current scripts lock."""
    return pathlib.Path(sys.prefix) if sys.prefix != sys.base_prefix and built(sys.prefix) else None


def default_dir(lock=LOCK):
    import toolchain
    lock = pathlib.Path(lock)
    return toolchain.canonical_cache()/'python'/f'{lock.parent.name}-{lock_sha256(lock)[:16]}-py{sys.version_info[0]}.{sys.version_info[1]}-{platform.machine()}'


def ensure(venv=None, lock=LOCK):
    """Directory of an environment built from lock: venv, else this one (scripts lock), else the default."""
    if venv is None and lock == LOCK and current():
        return current()
    if sys.version_info[:2] < MINIMUM:
        raise SystemExit(f'Python {".".join(map(str, MINIMUM))} or later is needed for {lock}; {sys.executable} is {platform.python_version()}')
    venv = pathlib.Path(venv or default_dir(lock)).absolute()
    if built(venv, lock):
        return venv
    venv.parent.mkdir(parents=True, exist_ok=True)
    with open(venv.parent/f'.{venv.name}.lock', 'w') as guard:
        fcntl.flock(guard, fcntl.LOCK_EX)
        if not built(venv, lock):
            if venv.is_dir() and any(venv.iterdir()) and not (venv/'pyvenv.cfg').exists():
                raise SystemExit(f'{venv} is not empty and not a virtual environment; remove it or choose another directory')
            digest = lock_sha256(lock)
            shutil.rmtree(venv, ignore_errors=True)
            if subprocess.run([sys.executable, '-m', 'venv', str(venv)], stdout=sys.stderr).returncode:
                raise SystemExit(f'{sys.executable} cannot create a virtual environment: install its venv module (Debian and Ubuntu: python3-venv)')
            if subprocess.run([str(venv/'bin/python'), '-m', 'pip', 'install', '-q', '--disable-pip-version-check', '--no-input',
                               '--require-hashes', '--only-binary=:all:', '-r', str(lock)], stdout=sys.stderr).returncode:
                raise SystemExit(f'pip could not install {lock} into {venv} (its output is above); check access to PyPI')
            (venv/MARKER).write_text(digest+'\n')
    return venv


def environment(venv, environ=None):
    """environ with venv active: its bin/ first on PATH."""
    environ = dict(os.environ if environ is None else environ)
    environ.pop('PYTHONHOME', None)
    environ['VIRTUAL_ENV'] = str(venv)
    environ['PATH'] = str(pathlib.Path(venv)/'bin') + os.pathsep + environ.get('PATH', '')
    return environ


def activate():
    """Run this program in the scripts' environment, its bin/ first on PATH; restarts the program when needed."""
    venv = ensure()
    if current() == venv:
        if os.environ.get('PATH', '').split(os.pathsep)[0] != str(venv/'bin'):
            os.environ.update(environment(venv))
        return venv
    if os.environ.get('KEYTEND_PYTHON_ENV') == str(venv):
        raise SystemExit(f'{venv} does not start as a virtual environment built from {LOCK}')
    python = venv/'bin/python3'
    os.execve(python, [str(python), *sys.orig_argv[1:]], {**environment(venv), 'KEYTEND_PYTHON_ENV': str(venv)})


def record():
    """What a release manifest records about the Python that ran it."""
    return {'executable': sys.executable, 'version': platform.python_version(), 'environment': str(current()),
            'lock': str(LOCK.relative_to(ROOT)), 'lock_sha256': lock_sha256(),
            'packages': dict(sorted((d.metadata['Name'], d.version) for d in importlib.metadata.distributions()))}


def lock(locks=LOCKS):
    """Regenerate each lock from the requirements.in beside it, keeping the lock's header."""
    if not shutil.which('uv'):
        raise SystemExit('uv is needed only to regenerate the locks: install it, for example with `pipx install uv`')
    for path in locks:
        header = path.read_text().split('\n\n', 2)
        done = subprocess.run([*COMPILE, str(path.with_suffix('.in').relative_to(ROOT))], cwd=ROOT, stdout=subprocess.PIPE, text=True)
        if done.returncode:
            raise SystemExit(f'uv could not resolve {path.with_suffix(".in").relative_to(ROOT)} (its output is above)')
        path.write_text(header[0]+'\n\n'+header[1]+'\n\n'+done.stdout)


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument('command', nargs='?', choices=['lock'])
    parser.add_argument('--venv', type=pathlib.Path, help='environment directory (default: in the shared cache)')
    args = parser.parse_args()
    if args.command == 'lock':
        lock()
    else:
        print(ensure(args.venv))


if __name__ == '__main__':
    main()
