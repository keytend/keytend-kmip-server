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

"""Integrity and failure-path tests for pinned primary-source fetching (no servers)."""
import contextlib
import http.client
import io
import json
import pathlib
import tempfile
import unittest
from unittest import mock
import urllib.error

import fetch_specs as specs


class Response(io.BytesIO):
    def __init__(self, data, url='https://docs.oasis-open.org/redirected', status=200):
        super().__init__(data)
        self.url = url
        self.status = status

    def geturl(self):
        return self.url


class FetchTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.cache = pathlib.Path(self.directory.name) / 'specs'
        self.path = self.cache / '2.1.html'
        self.data = b'<html><body><p>The server SHALL reject tampering.</p></body></html>'
        self.item = {'version': '2.1', 'url': 'https://docs.oasis-open.org/pinned.html',
                     'sha256': specs.digest(self.data)}
        self.network = mock.patch.object(specs.urllib.request, 'urlopen').start()
        self.addCleanup(mock.patch.stopall)

    def seed(self, data=None):
        self.cache.mkdir()
        self.path.write_bytes(self.data if data is None else data)
        return self.path.stat()

    def fetch(self, **kwargs):
        return specs.fetch(self.item, cache=self.cache, **kwargs)

    def assertFailure(self, *, origin, actual='unavailable', cache_state, **kwargs):
        with self.assertRaises(specs.FetchError) as caught:
            self.fetch(**kwargs)
        text = str(caught.exception)
        for expected in [self.item['url'], self.item['sha256'], str(self.path),
                         f'origin={origin}', f'actual_sha256={actual}',
                         f'cache_state={cache_state}', 'cache_action=not-written']:
            self.assertIn(expected, text)
        self.assertNotIn('\n', text)
        return text

    def test_verified_cache_is_checked_without_network_or_rewrite(self):
        before = self.seed()
        self.assertIn('origin=cache', self.fetch())
        self.network.assert_not_called()
        self.assertEqual(self.path.stat(), before)

    def test_tampered_cache_is_rejected_even_during_refresh(self):
        bad = b'altered normative text'
        self.seed(bad)
        for refresh in [False, True]:
            text = self.assertFailure(origin='cache', actual=specs.digest(bad),
                                      cache_state='checksum-mismatch', refresh=refresh)
            self.assertIn(f'cache_sha256={specs.digest(bad)}', text)
            self.assertEqual(self.path.read_bytes(), bad)
        self.network.assert_not_called()

    def test_empty_cache_rejects_changed_download_without_publishing(self):
        bad = b'changed source'
        self.network.return_value = Response(bad)
        self.assertFailure(origin='network', actual=specs.digest(bad), cache_state='missing')
        self.assertFalse(self.cache.exists())

    def test_analytics_only_byte_change_is_still_rejected(self):
        self.data = b'<html><body>Normative text<script src="analytics.js"></script></body></html>'
        self.item['sha256'] = specs.digest(self.data)
        self.seed()
        changed = b'<html><body>Normative text</body></html>'
        self.network.return_value = Response(changed)
        self.assertFailure(origin='network', actual=specs.digest(changed),
                           cache_state='verified', refresh=True)
        self.assertEqual(self.path.read_bytes(), self.data)

    def test_failed_refresh_preserves_verified_cache_and_fails_without_fallback(self):
        before = self.seed()
        bad = b'changed source'
        self.network.return_value = Response(bad)
        text = self.assertFailure(origin='network', actual=specs.digest(bad),
                                  cache_state='verified', refresh=True)
        self.assertIn(f'cache_sha256={self.item["sha256"]}', text)
        self.assertEqual(self.path.read_bytes(), self.data)
        self.assertEqual(self.path.stat(), before)
        self.assertEqual(list(self.cache.iterdir()), [self.path])

    def test_network_timeout_is_not_successful_cached_refresh(self):
        before = self.seed()
        self.network.side_effect = TimeoutError('timed out')
        text = self.assertFailure(origin='network', cache_state='verified', refresh=True)
        self.assertIn('TimeoutError', text)
        self.assertEqual(self.path.stat(), before)

    def test_http_error_reports_final_url_without_reading_error_body(self):
        self.network.side_effect = urllib.error.HTTPError(
            'https://docs.oasis-open.org/final', 403, 'Forbidden', {}, None)
        text = self.assertFailure(origin='network', cache_state='missing')
        self.assertIn('HTTPError', text)
        self.assertIn('403', text)
        self.assertIn("response_url='https://docs.oasis-open.org/final'", text)
        self.assertFalse(self.path.exists())

    def test_short_response_failure_is_not_published(self):
        response = Response(self.data)
        response.read = mock.Mock(side_effect=http.client.IncompleteRead(b'partial', 10))
        self.network.return_value = response
        text = self.assertFailure(origin='network', cache_state='missing')
        self.assertIn('IncompleteRead', text)
        self.assertFalse(self.cache.exists())

    def test_oversized_remote_source_preserves_verified_cache(self):
        before = self.seed()
        self.network.return_value = Response(b'x' * 100)
        with mock.patch.object(specs, 'MAX_SOURCE_BYTES', len(self.data)):
            text = self.assertFailure(origin='network', cache_state='verified', refresh=True)
        self.assertIn('byte limit', text)
        self.assertIn('full SHA-256 unavailable', text)
        self.assertEqual(self.path.stat(), before)

    def test_oversized_cache_fails_before_network(self):
        self.seed(b'x' * 100)
        with mock.patch.object(specs, 'MAX_SOURCE_BYTES', 50):
            self.assertFailure(origin='cache', cache_state='unverified')
        self.network.assert_not_called()

    def test_unreadable_cache_fails_before_network(self):
        self.cache.mkdir()
        self.path.mkdir()  # Portable read failure, including under privileged test runners.
        self.assertFailure(origin='cache', cache_state='unreadable')
        self.network.assert_not_called()

    def test_matching_download_is_published_only_after_verification(self):
        self.network.return_value = Response(self.data)
        replace = specs.os.replace
        def checked_replace(source, destination):
            self.assertFalse(self.path.exists())
            self.assertEqual(pathlib.Path(source).read_bytes(), self.data)
            replace(source, destination)
        with mock.patch.object(specs.os, 'replace', side_effect=checked_replace) as publish:
            result = self.fetch()
        self.assertIn('origin=network', result)
        self.assertIn('stored-verified', result)
        self.assertIn(self.item['sha256'], result)
        publish.assert_called_once()
        self.assertEqual(self.path.read_bytes(), self.data)
        self.assertEqual(list(self.cache.iterdir()), [self.path])
        self.network.assert_called_once_with(self.item['url'], timeout=specs.TIMEOUT_SECONDS)

    def test_successful_refresh_keeps_verified_cache_inode(self):
        before = self.seed()
        self.network.return_value = Response(self.data)
        self.assertIn('preserved-verified', self.fetch(refresh=True))
        self.assertEqual(self.path.stat(), before)
        self.network.assert_called_once()

    def test_failed_atomic_publication_cleans_temporary_file(self):
        self.network.return_value = Response(self.data)
        with mock.patch.object(specs.os, 'replace', side_effect=OSError('storage failure')):
            text = self.assertFailure(origin='network', actual=self.item['sha256'], cache_state='missing')
        self.assertIn('storage failure', text)
        self.assertEqual(list(self.cache.iterdir()), [])

    def test_redirect_checksum_mismatch_names_both_urls(self):
        self.network.return_value = Response(b'bad', url='https://docs.oasis-open.org/new-location')
        text = self.assertFailure(origin='network', actual=specs.digest(b'bad'), cache_state='missing')
        self.assertIn("response_url='https://docs.oasis-open.org/new-location'", text)

    def test_non_200_response_never_accepts_even_matching_body(self):
        self.network.return_value = Response(self.data, status=206)
        text = self.assertFailure(origin='network', cache_state='missing')
        self.assertIn('HTTP status 206', text)
        self.assertFalse(self.cache.exists())

    def test_exception_detail_is_bounded_and_single_line(self):
        self.network.side_effect = OSError('first line\n' + 'x' * 10000)
        text = self.assertFailure(origin='network', cache_state='missing')
        self.assertLess(len(text), 1300)

    def test_manifest_filename_and_profile_naming_are_preserved(self):
        self.network.side_effect = lambda *args, **kwargs: Response(self.data)
        self.item['filename'] = '1.4-errata01.html'
        specs.fetch(self.item, cache=self.cache)
        self.assertEqual((self.cache / '1.4-errata01.html').read_bytes(), self.data)
        del self.item['filename']
        specs.fetch(self.item, True, cache=self.cache)
        self.assertEqual((self.cache / 'profiles-2.1.zip').read_bytes(), self.data)

    def test_cli_reports_every_failed_source_and_returns_failure(self):
        root = pathlib.Path(self.directory.name)
        manifest_dir = root / 'docs/specs'
        manifest_dir.mkdir(parents=True)
        for name in ['sources.json', 'profiles.json']:
            (manifest_dir / name).write_text(json.dumps([self.item, self.item]))
        stdout, stderr = io.StringIO(), io.StringIO()
        with mock.patch.object(specs, 'ROOT', root), \
             mock.patch.object(specs, 'MANIFESTS', [('sources.json', False), ('profiles.json', True)]), \
             mock.patch.object(specs, 'fetch', side_effect=specs.FetchError('source mismatch')) as fetch, \
             contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            self.assertEqual(specs.main(['--refresh']), 1)
        self.assertEqual(fetch.call_count, 4)
        self.assertTrue(all(call.kwargs['refresh'] for call in fetch.call_args_list))
        self.assertEqual(stderr.getvalue().count('ERROR manifest='), 4)
        self.assertIn('FAIL: 4 source(s)', stderr.getvalue())
        self.assertNotIn('Traceback', stderr.getvalue())
        self.assertEqual(stdout.getvalue(), '')

    def test_cli_default_success_does_not_request_refresh(self):
        root = pathlib.Path(self.directory.name)
        manifest_dir = root / 'docs/specs'
        manifest_dir.mkdir(parents=True)
        (manifest_dir / 'sources.json').write_text(json.dumps([self.item]))
        with mock.patch.object(specs, 'ROOT', root), \
             mock.patch.object(specs, 'MANIFESTS', [('sources.json', False)]), \
             mock.patch.object(specs, 'fetch', return_value='verified cached source') as fetch, \
             contextlib.redirect_stdout(io.StringIO()) as stdout:
            self.assertEqual(specs.main([]), 0)
        self.assertEqual(stdout.getvalue(), 'verified cached source\n')
        fetch.assert_called_once_with(self.item, False, refresh=False)


if __name__ == '__main__':
    unittest.main()
