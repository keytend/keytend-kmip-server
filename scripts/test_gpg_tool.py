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

"""Unit tests for scripts/gpg_tool.py with throwaway keys in temporary GNUPGHOMEs.

A test release key (Ed25519 [SC]) gets signing subkeys: a current one, one that expired and
one that is revoked; a foreign key stands in for any other signer. Signing goes through
sign_detached with a passphrase file, so the loopback path the release uses is exercised.
"""
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import gpg_tool

PASS = 'test passphrase'


def run(home, *args, input=None):
    return subprocess.run(['gpg', '--batch', '--no-tty', '--pinentry-mode', 'loopback', '--passphrase', PASS, *args],
                          env=gpg_tool.gpg_env(home), input=input, capture_output=True, text=True, check=True, timeout=120)


def fingerprints(home, kind):
    out = subprocess.run(['gpg', '--batch', '--with-colons', '--with-subkey-fingerprints', '--list-secret-keys'],
                         env=gpg_tool.gpg_env(home), capture_output=True, text=True, check=True).stdout.splitlines()
    return [b.split(':')[9] for a, b in zip(out, out[1:]) if a.startswith(kind+':') and b.startswith('fpr:')]


@unittest.skipUnless(gpg_tool.available(), 'gpg and gpgconf are required')
class OpenPgpTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = pathlib.Path(tempfile.mkdtemp(prefix='gpgt-'))
        cls.home = cls.temp/'release'
        cls.foreign_home = cls.temp/'foreign'
        for home in (cls.home, cls.foreign_home):
            home.mkdir(mode=0o700)
        # Created in the past (no expiry) so a subkey can be valid for one day in 2020.
        run(cls.home, '--faked-system-time', '20191201T000000!', '--quick-gen-key', 'Test release <release@test.invalid>', 'ed25519', 'sign,cert', 'never')
        cls.primary = fingerprints(cls.home, 'sec')[0]
        run(cls.home, '--quick-add-key', cls.primary, 'ed25519', 'sign', '2y')
        cls.subkey = fingerprints(cls.home, 'ssb')[0]
        # A subkey that was valid for one day in 2020, and a signature made inside that day.
        run(cls.home, '--faked-system-time', '20200101T000000!', '--quick-add-key', cls.primary, 'ed25519', 'sign', '1d')
        cls.expired = fingerprints(cls.home, 'ssb')[1]
        run(cls.home, '--quick-add-key', cls.primary, 'ed25519', 'sign', '2y')
        cls.revoked = fingerprints(cls.home, 'ssb')[2]
        run(cls.foreign_home, '--quick-gen-key', 'Foreign <foreign@test.invalid>', 'ed25519', 'sign,cert', '2y')
        cls.foreign = fingerprints(cls.foreign_home, 'sec')[0]
        cls.data = cls.temp/'SHA256SUMS'
        cls.data.write_text('a'*64+'  artifact\n')
        cls.passphrase = cls.temp/'passphrase'
        cls.passphrase.write_text(PASS+'\n')
        cls.passphrase.chmod(0o600)
        # Signatures by each key, made before the revocation so the revoked one was once valid.
        cls.signatures = {}
        for name, key, extra in [('subkey', cls.subkey, []), ('primary', cls.primary, []), ('revoked', cls.revoked, []),
                                 ('expired', cls.expired, ['--faked-system-time', '20200101T120000!'])]:
            out = cls.temp/f'{name}.asc'
            run(cls.home, *extra, '--local-user', key+'!', '--armor', '--detach-sign', '--output', str(out), str(cls.data))
            cls.signatures[name] = out
        out = cls.temp/'foreign.asc'
        run(cls.foreign_home, '--local-user', cls.foreign+'!', '--armor', '--detach-sign', '--output', str(out), str(cls.data))
        cls.signatures['foreign'] = out
        # Revoke the third subkey (reason 0, no description).
        index = 1+[cls.subkey, cls.expired, cls.revoked].index(cls.revoked)
        subprocess.run(['gpg', '--batch', '--no-tty', '--pinentry-mode', 'loopback', '--passphrase', PASS, '--command-fd', '0',
                        '--status-fd', '2', '--edit-key', cls.primary], input=f'key {index}\nrevkey\ny\n0\n\ny\nsave\n',
                       env=gpg_tool.gpg_env(cls.home), capture_output=True, text=True, check=True, timeout=120)
        cls.public = cls.temp/'release.asc'
        cls.public.write_text(run(cls.home, '--armor', '--export', cls.primary).stdout)
        cls.foreign_public = cls.temp/'foreign-public.asc'
        cls.foreign_public.write_text(run(cls.foreign_home, '--armor', '--export', cls.foreign).stdout)

    @classmethod
    def tearDownClass(cls):
        for home in (cls.home, cls.foreign_home):
            subprocess.run(['gpgconf', '--kill', 'all'], env=gpg_tool.gpg_env(home), capture_output=True)
        shutil.rmtree(cls.temp, ignore_errors=True)

    def verify(self, name, data=None, public=None):
        return gpg_tool.verify(data or self.data, self.signatures[name], public or self.public, self.primary)

    def test_subkey_signature_is_accepted_by_its_primary(self):
        record = self.verify('subkey')
        self.assertTrue(record['verified'], record)
        self.assertEqual((record['signer_fingerprint'], record['primary_fingerprint']), (self.subkey, self.primary))

    def test_primary_signature_is_accepted(self):
        record = self.verify('primary')
        self.assertTrue(record['verified'], record)
        self.assertEqual(record['signer_fingerprint'], self.primary)

    def test_foreign_key_is_refused(self):
        record = self.verify('foreign')
        self.assertFalse(record['verified'])
        self.assertTrue({'ERRSIG', 'NO_PUBKEY'} & set(record['status']), record)

    def test_keyring_must_hold_only_the_release_key(self):
        record = self.verify('foreign', public=self.foreign_public)
        self.assertFalse(record['verified'])
        self.assertIn('must hold exactly the release key', record['reason'])
        both = self.temp/'both.asc'
        both.write_text(self.public.read_text()+self.foreign_public.read_text())
        self.assertFalse(self.verify('subkey', public=both)['verified'])

    def test_expired_subkey_is_refused(self):
        record = self.verify('expired')
        self.assertFalse(record['verified'])
        self.assertIn('EXPKEYSIG', record['status'], record)

    def test_revoked_subkey_is_refused(self):
        record = self.verify('revoked')
        self.assertFalse(record['verified'])
        self.assertIn('REVKEYSIG', record['status'], record)

    def test_tampered_data_is_refused(self):
        tampered = self.temp/'tampered'
        tampered.write_text('b'*64+'  artifact\n')
        record = self.verify('subkey', data=tampered)
        self.assertFalse(record['verified'])
        self.assertIn('BADSIG', record['status'], record)

    def test_sign_detached_uses_the_pinned_subkey_and_passphrase_file(self):
        out = self.temp/'made.asc'
        gpg_tool.sign_detached(self.data, out, home=self.home, passphrase=self.passphrase, subkey=self.subkey)
        self.assertTrue(out.read_text().startswith('-----BEGIN PGP SIGNATURE-----'))
        record = gpg_tool.verify(self.data, out, self.public, self.primary)
        self.assertTrue(record['verified'], record)
        self.assertEqual(record['signer_fingerprint'], self.subkey)

    def test_a_keyring_without_the_subkey_secret_cannot_sign(self):
        stub = self.temp/'stub'
        stub.mkdir(mode=0o700)
        secret = run(self.home, '--armor', '--export-secret-subkeys', self.subkey+'!').stdout
        run(stub, '--import', input=secret)
        with self.assertRaises(SystemExit):
            gpg_tool.sign_detached(self.data, self.temp/'other.asc', home=stub, passphrase=self.passphrase, subkey=self.primary)
        out = gpg_tool.sign_detached(self.data, self.temp/'ok.asc', home=stub, passphrase=self.passphrase, subkey=self.subkey)
        self.assertTrue(gpg_tool.verify(self.data, out, self.public, self.primary)['verified'])
        subprocess.run(['gpgconf', '--kill', 'all'], env=gpg_tool.gpg_env(stub), capture_output=True)

    def test_missing_or_loose_signing_material_is_refused(self):
        with self.assertRaises(SystemExit):
            gpg_tool.check_signing_keyring(self.temp/'absent', self.passphrase)
        with self.assertRaises(SystemExit):
            gpg_tool.check_signing_keyring(self.home, self.temp/'absent')
        loose = self.temp/'loose'
        loose.write_text(PASS)
        loose.chmod(0o644)
        with self.assertRaises(SystemExit) as caught:
            gpg_tool.check_signing_keyring(self.home, loose)
        self.assertIn('0600', str(caught.exception))


class ReleaseKeyTests(unittest.TestCase):
    @unittest.skipUnless(gpg_tool.available(), 'gpg and gpgconf are required')
    def test_committed_public_key_is_the_release_key_with_the_server_subkey(self):
        home = pathlib.Path(tempfile.mkdtemp(prefix='gpgk-'))
        try:
            home.chmod(0o700)
            subprocess.run(['gpg', '--batch', '--import', str(gpg_tool.PUBLIC_KEY)], env=gpg_tool.gpg_env(home), capture_output=True, check=True)
            out = subprocess.run(['gpg', '--batch', '--with-colons', '--with-subkey-fingerprints', '--list-keys'],
                                 env=gpg_tool.gpg_env(home), capture_output=True, text=True, check=True).stdout.splitlines()
            pubs = [b.split(':')[9] for a, b in zip(out, out[1:]) if a.startswith('pub:') and b.startswith('fpr:')]
            subs = [b.split(':')[9] for a, b in zip(out, out[1:]) if a.startswith('sub:') and b.startswith('fpr:')]
            self.assertEqual(pubs, [gpg_tool.RELEASE_FINGERPRINT])
            self.assertIn(gpg_tool.SERVER_SUBKEY, subs)
        finally:
            subprocess.run(['gpgconf', '--kill', 'all'], env=gpg_tool.gpg_env(home), capture_output=True)
            shutil.rmtree(home, ignore_errors=True)


if __name__ == '__main__':
    unittest.main()
