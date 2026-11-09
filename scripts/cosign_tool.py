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

"""Pinned cosign release binary, signing key custody paths and offline signing helpers.

The binary is downloaded once into .cache/bin and checked against the SHA-256
published in the release's cosign_checksums.txt (pinned below). No system
install. Signing is offline: no transparency-log upload and no keyless identity
(see docs/release-signing.md).
"""
import argparse
import hashlib
import os
import pathlib
import platform
import subprocess
import urllib.request

ROOT = pathlib.Path(__file__).resolve().parents[1]
VERSION = '3.1.4'
# From https://github.com/sigstore/cosign/releases/download/v3.1.4/cosign_checksums.txt
# (that file's keyless Sigstore bundle was verified when the pin was taken; docs/release-signing.md).
SHA256 = {
    'amd64': '424e2c97d0b45fd7a6b608a87f090f35633f4c23ece5f092d48bba11aaf4bbfa',
    'arm64': 'ade83b7aac62e131cacfe96d958948b2150cc9efec46a570a2649b8e27dedad2',
}
URL = 'https://github.com/sigstore/cosign/releases/download/v{version}/cosign-linux-{arch}'
# Private key and its password live outside Git, readable only by the owner.
KEY_DIR = pathlib.Path(os.environ.get('KEYTEND_KMIP_SERVER_SIGNING_DIR', pathlib.Path.home()/'.config/keytend-kmip-server/signing'))
PRIVATE_KEY = KEY_DIR/'cosign.key'
PASSWORD_FILE = KEY_DIR/'cosign.password'
PUBLIC_KEY = ROOT/'signing/cosign.pub'
# Sigstore signing config with no Rekor, TSA or Fulcio service (`cosign signing-config create` with no
# services): signatures are made with the key alone and nothing is uploaded to a transparency log.
OFFLINE_SIGNING_CONFIG = ROOT/'signing/offline-signing-config.json'


def sha256(path):
    with pathlib.Path(path).open('rb') as file:
        return hashlib.file_digest(file, 'sha256').hexdigest()


def host_arch():
    machine = platform.machine()
    return {'x86_64': 'amd64', 'aarch64': 'arm64', 'arm64': 'arm64'}[machine]


def binary(arch=None):
    """Path of the pinned cosign binary, downloading and checking it on first use."""
    arch = arch or host_arch()
    path = ROOT/'.cache/bin'/f'cosign-{VERSION}-linux-{arch}'
    if not path.exists():
        path.parent.mkdir(parents=True, exist_ok=True)
        with urllib.request.urlopen(URL.format(version=VERSION, arch=arch), timeout=120) as response:
            data = response.read(300*1024*1024+1)
        assert len(data) <= 300*1024*1024, 'cosign download is unexpectedly large'
        assert hashlib.sha256(data).hexdigest() == SHA256[arch], 'cosign release binary SHA-256 differs from the pin'
        temporary = path.with_suffix('.partial')
        temporary.write_bytes(data)
        temporary.chmod(0o700)
        temporary.replace(path)
    assert sha256(path) == SHA256[arch], 'cached cosign binary SHA-256 differs from the pin: '+str(path)
    return path


def check_private_key():
    for path in (PRIVATE_KEY, PASSWORD_FILE):
        assert path.is_file(), 'missing signing material: '+str(path)
        mode = path.stat().st_mode & 0o777
        assert mode == 0o600, f'{path} has mode {oct(mode)}; expected 0600'


def environment():
    """Environment for cosign: password from the custody file, never on the command line."""
    env = {k: v for k, v in os.environ.items() if not k.startswith(('COSIGN_', 'SIGSTORE_'))}
    env['COSIGN_PASSWORD'] = PASSWORD_FILE.read_text().strip() if PASSWORD_FILE.exists() else ''
    # Offline: never contact a TUF mirror for a trusted root.
    env['TUF_ROOT'] = str(ROOT/'.cache/cosign-tuf-unused')
    return env


def run(args, check=True):
    result = subprocess.run([str(binary()), *map(str, args)], stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        text=True, env=environment(), timeout=600)
    if check and result.returncode != 0:
        raise RuntimeError(f'cosign {args[0]} failed ({result.returncode}): {result.stdout[-2000:]}')
    return result


def sign_blob(path, bundle):
    """Key-based blob signature in a Sigstore bundle; no transparency-log upload."""
    check_private_key()
    run(['sign-blob', '--yes', '--key', PRIVATE_KEY, '--signing-config', OFFLINE_SIGNING_CONFIG, '--bundle', bundle, path])


def verify_blob(path, bundle, public_key=PUBLIC_KEY):
    return run(['verify-blob', '--key', public_key, '--insecure-ignore-tlog=true', '--bundle', bundle, path], check=False)


def generate_key_pair():
    """Create the release key pair: private key and password under KEY_DIR (0600), public key in signing/."""
    assert not PRIVATE_KEY.exists(), 'refusing to overwrite '+str(PRIVATE_KEY)
    KEY_DIR.mkdir(parents=True, exist_ok=True)
    KEY_DIR.chmod(0o700)
    descriptor = os.open(PASSWORD_FILE, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, 'w') as file:
        file.write(os.urandom(32).hex()+'\n')
    subprocess.run([str(binary()), 'generate-key-pair', '--output-key-prefix', str(KEY_DIR/'cosign')],
        cwd=KEY_DIR, env=environment(), check=True, stdout=subprocess.DEVNULL, timeout=120)
    PRIVATE_KEY.chmod(0o600)
    public = (KEY_DIR/'cosign.pub').read_text()
    PUBLIC_KEY.parent.mkdir(exist_ok=True)
    from check_license import source_header
    PUBLIC_KEY.write_text(source_header(PUBLIC_KEY)+'# keytend-kmip-server release signing public key (cosign, ECDSA P-256). See docs/release-signing.md.\n'+public)
    check_private_key()
    return PUBLIC_KEY


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument('command', choices=['fetch', 'generate-key-pair', 'version'])
    args = parser.parse_args()
    if args.command == 'fetch':
        print(binary(), sha256(binary()))
    elif args.command == 'generate-key-pair':
        print(generate_key_pair())
    else:
        print(run(['version']).stdout)


if __name__ == '__main__':
    main()
