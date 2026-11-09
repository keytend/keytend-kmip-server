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

"""Download exact OASIS sources; reject content changes against committed SHA-256s."""
import argparse
import concurrent.futures
import hashlib
import http.client
import json
import os
import pathlib
import sys
import tempfile
import urllib.error
import urllib.request

ROOT = pathlib.Path(__file__).resolve().parents[1]
CACHE = ROOT / '.cache/specs'
MANIFESTS = [('sources.json', False), ('profiles.json', True),
             ('errata.json', False), ('additional-traces.json', False)]
MAX_SOURCE_BYTES = 32 * 1024 * 1024  # Largest pinned source is currently 19 MB.
TIMEOUT_SECONDS = 30


class FetchError(RuntimeError):
    """A source could not be verified; its cache was not written."""


def digest(data):
    return hashlib.sha256(data).hexdigest()


def fetch(item, profiles=False, *, cache=CACHE, refresh=False):
    """Use only verified cache bytes, or verify a download before atomic publication.

    Refresh explicitly checks the remote source even with verified cached bytes.
    A failed refresh never falls back to those bytes or replaces them. Corrupt
    cache entries fail before network access, including during refresh.
    """
    name = item.get('filename') or (f'profiles-{item["version"]}.zip'
                                   if profiles else f'{item["version"]}.html')
    path = pathlib.Path(cache) / name
    expected = item['sha256']
    url = item['url']
    cache_state, cache_sha = 'unreadable', 'unavailable'
    origin, actual, response_url = 'cache', 'unavailable', 'unavailable'

    def failure(reason):
        # One bounded line per manifest entry, with exact hashes and byte origin.
        return FetchError(
            f'{name}: {reason}; source_url={url!r}; origin={origin}; '
            f'expected_sha256={expected}; actual_sha256={actual}; '
            f'response_url={response_url!r}; cache_path={str(path)!r}; '
            f'cache_state={cache_state}; cache_sha256={cache_sha}; cache_action=not-written'
        )

    def read_bounded(stream):
        data = stream.read(MAX_SOURCE_BYTES + 1)
        if len(data) > MAX_SOURCE_BYTES:
            raise ValueError(f'source exceeds {MAX_SOURCE_BYTES} byte limit (full SHA-256 unavailable)')
        return data

    cached = None
    try:
        try:
            with path.open('rb') as stream:
                cache_state = 'unverified'
                cached = read_bounded(stream)
        except FileNotFoundError:
            cache_state = 'missing'
        if cached is not None:
            cache_sha = actual = digest(cached)
            cache_state = 'verified' if cache_sha == expected else 'checksum-mismatch'
            if cache_sha != expected:
                raise failure('cached source checksum mismatch; isolate this entry and restore exact pinned bytes')
            if not refresh:
                return f'verified {name} origin=cache sha256={cache_sha} source_url={url!r} cache_path={str(path)!r}'

        origin, actual = 'network', 'unavailable'
        # Preserve urllib's request behavior. No header-based selection, content
        # normalization, unchecked fallback, or repinning is used for acceptance.
        with urllib.request.urlopen(url, timeout=TIMEOUT_SECONDS) as response:
            response_url = response.geturl()
            if response.status != 200:
                raise failure(f'unexpected HTTP status {response.status}')
            data = read_bounded(response)
        actual = digest(data)
        if actual != expected:
            raise failure('downloaded source checksum mismatch; preserve historical bytes and investigate primary source')
        if cached is None:
            path.parent.mkdir(parents=True, exist_ok=True)
            temporary = None
            try:
                with tempfile.NamedTemporaryFile(dir=path.parent, prefix=f'.{name}.', delete=False) as stream:
                    temporary = pathlib.Path(stream.name)
                    stream.write(data)
                os.replace(temporary, path)
            finally:
                if temporary is not None:
                    temporary.unlink(missing_ok=True)
        return (f'verified {name} origin=network sha256={actual} source_url={url!r} '
                f'response_url={response_url!r} cache_path={str(path)!r} '
                f'cache_action={"preserved-verified" if cached is not None else "stored-verified"}')
    except FetchError:
        raise
    except (OSError, ValueError, http.client.HTTPException) as error:
        if isinstance(error, urllib.error.HTTPError):
            response_url = error.geturl()
        # Do not emit response bodies or an unbounded traceback on fetch failure.
        raise failure(f'{type(error).__name__}: {str(error)[:240]!r}') from error


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--refresh', action='store_true',
                        help='check every live URL against its pin, preserving verified cache on failure; no fallback')
    args = parser.parse_args(argv)
    failures = 0
    for manifest, profiles in MANIFESTS:
        items = json.loads((ROOT / 'docs/specs' / manifest).read_text())
        # Collect every failure rather than abandoning later sources after the
        # first mismatch. Messages remain ordered by committed manifest entries.
        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
            futures = [pool.submit(fetch, item, profiles, refresh=args.refresh) for item in items]
            for future in futures:
                try:
                    print(future.result())
                except FetchError as error:
                    failures += 1
                    print(f'ERROR manifest={manifest}: {error}', file=sys.stderr)
    if failures:
        print(f'FAIL: {failures} source(s) could not be verified; no unchecked bytes accepted', file=sys.stderr)
    return 1 if failures else 0


if __name__ == '__main__':
    sys.exit(main())
