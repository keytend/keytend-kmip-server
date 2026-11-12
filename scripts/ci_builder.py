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

"""Run cargo in the pinned UBI builder image (the release workflow's rust job).

The server needs OpenSSL 3.5. A host whose system OpenSSL is older (GitHub's
Ubuntu 24.04 runners have 3.0) runs cargo inside the image build's UBI builder,
with the image build's openssl-devel, as an ordinary user (the tests check file
modes, which root ignores). The checkout is mounted at its own path, so
target/ is shared with the host. This builds and tests the source; every
qualification test runs the release image instead (scripts/image_server.py).

    ci_builder.py start            start the builder container and install gcc, OpenSSL and Rust
    ci_builder.py run CMD...       run CMD in the checkout inside it (cargo clippy, cargo test, ...)
    ci_builder.py stop

RUST_TOOLCHAIN names the Rust release (default: the stable channel).
"""
import argparse
import os
import pathlib
import shlex
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT/'scripts'))
from image_evidence import base_images, dockerfile_arg  # noqa: E402

NAME = 'keytend-ci-builder'
HOME = ROOT/'target/ci-builder-home'


def arch():
    return {'x86_64': 'amd64', 'aarch64': 'arm64'}[os.uname().machine]


def packages():
    """The image build's openssl-devel, and the openssl command of the same version (the tests use it)."""
    devel = [p for p in dockerfile_arg('BUILD_PACKAGES').split() if p.startswith('openssl-devel-')]
    assert len(devel) == 1, 'BUILD_PACKAGES names no single openssl-devel'
    return ['gcc', 'git', 'python3', devel[0], 'openssl-'+devel[0].removeprefix('openssl-devel-')]


def podman(*args, **kwargs):
    print('+ podman', ' '.join(map(str, args)), flush=True)
    return subprocess.run(['podman', *map(str, args)], check=True, **kwargs)


def exec_args(user=None, workdir=ROOT):
    return ['exec', *(['--user', user] if user else []), '--workdir', workdir, NAME]


def start():
    HOME.mkdir(parents=True, exist_ok=True)
    builder = base_images(arch())['UBI_BUILDER']
    toolchain = os.environ.get('RUST_TOOLCHAIN', 'stable')
    # keep-id: the commands run as the host user, so target/ stays the host user's.
    podman('run', '--detach', '--rm', '--name', NAME, '--userns', 'keep-id', '--network', 'host',
           '--volume', f'{ROOT}:{ROOT}', '--env', f'HOME={HOME}', '--env', f'CARGO_TARGET_DIR={ROOT}/target',
           '--env', f'OPENSSL_CONF={ROOT}/image/openssl.cnf', '--env', 'CARGO_TERM_COLOR=never', builder, 'sleep', 'infinity')
    podman(*exec_args('0'), 'dnf', 'install', '-y', '-q', '--nodocs', '--setopt=install_weak_deps=0', *packages())
    rustup = ('curl -fsSL https://sh.rustup.rs | sh -s -- -y -q --no-modify-path --profile minimal '
              f'--default-toolchain {shlex.quote(toolchain)} -c clippy')
    podman(*exec_args(), 'bash', '-euo', 'pipefail', '-c', rustup)


def run(command):
    script = '. "$HOME/.cargo/env" && exec "$@"'
    return subprocess.run(['podman', *exec_args(), 'bash', '-c', script, 'run', *command]).returncode


def stop():
    subprocess.run(['podman', 'rm', '--force', '--time', '5', NAME], check=False)


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest='command', required=True)
    sub.add_parser('start')
    sub.add_parser('run').add_argument('cmd', nargs=argparse.REMAINDER)
    sub.add_parser('stop')
    args = parser.parse_args()
    if args.command == 'start':
        start()
    elif args.command == 'run':
        raise SystemExit(run(args.cmd))
    else:
        stop()


if __name__ == '__main__':
    main()
