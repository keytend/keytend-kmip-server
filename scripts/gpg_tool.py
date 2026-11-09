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

"""OpenPGP signature over a release set's SHA256SUMS, next to the cosign bundles.

Every Keytend project is verifiable against one published OpenPGP release key
(RELEASE_FINGERPRINT). Each project signs with its own signing subkey of that
key, so one project's subkey can be revoked or rotated without affecting the
others. Verification therefore accepts a signature exactly when gpg reports it
valid and VALIDSIG names the release key as the primary, whichever subkey made
it; a foreign key, an expired or revoked key and a bad signature are refused.

Signing uses a dedicated keyring that holds only this project's subkey secret
(the primary is a stub). The passphrase is read by gpg from a file
(`--passphrase-file`), never passed on the command line, and the subkey is
pinned with a trailing `!` so gpg cannot pick another key.

    KEYTEND_SIGNING_HOME             GNUPGHOME of the signing keyring
    KEYTEND_SIGNING_PASSPHRASE_FILE  file holding the subkey passphrase (mode 0600)
    KEYTEND_SIGNING_SUBKEY           fingerprint of the signing subkey
"""
import os
import pathlib
import shutil
import subprocess
import tempfile

import cosign_tool

ROOT = pathlib.Path(__file__).resolve().parents[1]
# The published release key: Ed25519 [SC], "keytend-kmip releases <releases@keytend.dev>".
RELEASE_FINGERPRINT = '3A84912AFBE7D2B04EBA2A8A51E65DD49C6F987F'
# This project's signing subkey of the release key (Ed25519 [S]).
SERVER_SUBKEY = 'CE9BFF243C9F66C2A2129E3AB02F69EFAEB7DBB5'
PUBLIC_KEY = ROOT/'signing/keytend-release-key.asc'
SIGNATURE_SUFFIX = '.asc'
# Signature-level status keywords that refuse a signature even if gpg also reports VALIDSIG:
# a bad or unverifiable signature, an expired signature, and a good signature made by an expired
# (EXPKEYSIG) or revoked (REVKEYSIG) key. KEYEXPIRED and KEYREVOKED are not here: gpg emits them for
# any expired or revoked subkey it considers, so after a rotation they would refuse every
# signature by the current subkey too.
REFUSED = {'BADSIG', 'ERRSIG', 'EXPSIG', 'EXPKEYSIG', 'REVKEYSIG', 'NO_PUBKEY', 'FAILURE'}


def signing_home():
    return pathlib.Path(os.environ.get('KEYTEND_SIGNING_HOME') or cosign_tool.KEY_DIR/'gpg/gnupg')


def passphrase_file():
    return pathlib.Path(os.environ.get('KEYTEND_SIGNING_PASSPHRASE_FILE') or cosign_tool.KEY_DIR/'gpg/passphrase')


def signing_subkey():
    return os.environ.get('KEYTEND_SIGNING_SUBKEY') or SERVER_SUBKEY


def check_signing_keyring(home=None, passphrase=None):
    """Refuse clearly unless the keyring and an owner-only passphrase file exist."""
    home, passphrase = pathlib.Path(home or signing_home()), pathlib.Path(passphrase or passphrase_file())
    if not home.is_dir():
        raise SystemExit(f'OpenPGP signing keyring {home} is missing (set KEYTEND_SIGNING_HOME); see docs/release-signing.md')
    if home.stat().st_mode & 0o077:
        raise SystemExit(f'OpenPGP signing keyring {home} must not be accessible by group or others (mode 0700)')
    if not passphrase.is_file():
        raise SystemExit(f'OpenPGP passphrase file {passphrase} is missing (set KEYTEND_SIGNING_PASSPHRASE_FILE)')
    if passphrase.stat().st_mode & 0o077:
        raise SystemExit(f'OpenPGP passphrase file {passphrase} must have mode 0600 or stricter, not {oct(passphrase.stat().st_mode & 0o777)}')
    return home, passphrase


def gpg_env(home):
    env = {k: v for k, v in os.environ.items() if k not in ('GNUPGHOME', 'GPG_AGENT_INFO')}
    env['GNUPGHOME'] = str(home)
    return env


def gpg(home, *args, input=None, check=True):
    return subprocess.run(['gpg', '--batch', '--no-tty', '--no-greeting', *map(str, args)], env=gpg_env(home), input=input,
                          capture_output=True, timeout=300, check=check)


def sign_detached(path, signature=None, *, home=None, passphrase=None, subkey=None):
    """ASCII-armored detached signature of PATH, made by the pinned subkey only."""
    home, passphrase = check_signing_keyring(home, passphrase)
    subkey = subkey or signing_subkey()
    signature = pathlib.Path(signature or str(path)+SIGNATURE_SUFFIX)
    result = gpg(home, '--pinentry-mode', 'loopback', '--passphrase-file', passphrase, '--local-user', subkey+'!',
                 '--armor', '--detach-sign', '--yes', '--output', signature, path, check=False)
    if result.returncode:
        raise SystemExit(f'gpg could not sign {path} with subkey {subkey}: {result.stderr.decode(errors="replace")[-2000:]}')
    return signature


def parse_status(text):
    return [line[len('[GNUPG:] '):].split() for line in text.splitlines() if line.startswith('[GNUPG:] ')]


def verify(path, signature, public_key=PUBLIC_KEY, primary=RELEASE_FINGERPRINT):
    """Verify SIGNATURE over PATH in a keyring that holds only PUBLIC_KEY.

    Accepted when gpg exits 0, reports GOODSIG and VALIDSIG, VALIDSIG's last field (the primary
    key fingerprint) is PRIMARY, and no refusing status (expired, revoked, bad, missing key)
    appears. Returns a JSON-able record."""
    record = dict(signature=pathlib.Path(signature).name, public_key=pathlib.Path(public_key).name,
                  release_fingerprint=primary, verified=False)
    home = pathlib.Path(tempfile.mkdtemp(prefix='keytend-gpg-verify-'))
    try:
        home.chmod(0o700)
        imported = gpg(home, '--import', public_key, check=False)
        listed = gpg(home, '--with-colons', '--fingerprint', '--list-keys', check=False).stdout.decode()
        primaries = [line.split(':')[9] for prev, line in zip([''] + listed.splitlines(), listed.splitlines())
                     if line.startswith('fpr:') and prev.startswith('pub:')]
        record['keyring_primaries'] = primaries
        if imported.returncode or primaries != [primary]:
            record['reason'] = f'the verification keyring must hold exactly the release key {primary}, found {primaries}'
            return record
        result = gpg(home, '--status-fd', '1', '--verify', signature, path, check=False)
        status = parse_status(result.stdout.decode(errors='replace'))
        keywords = {s[0] for s in status if s}
        valid = [s for s in status if s and s[0] == 'VALIDSIG']
        record['status'] = sorted(keywords)
        refused = sorted(keywords & REFUSED)
        if valid:
            record['signer_fingerprint'] = valid[0][1]
            record['primary_fingerprint'] = valid[0][-1]
        if result.returncode or refused or 'GOODSIG' not in keywords or len(valid) != 1:
            record['reason'] = f'gpg exit {result.returncode}; refusing status {refused}' if refused or result.returncode else 'no single good signature'
        elif valid[0][-1] != primary:
            record['reason'] = f'signed by {valid[0][1]}, whose primary {valid[0][-1]} is not the release key {primary}'
        else:
            record['verified'] = True
        return record
    finally:
        subprocess.run(['gpgconf', '--kill', 'all'], env=gpg_env(home), capture_output=True, check=False)
        shutil.rmtree(home, ignore_errors=True)


def available():
    return shutil.which('gpg') is not None and shutil.which('gpgconf') is not None
