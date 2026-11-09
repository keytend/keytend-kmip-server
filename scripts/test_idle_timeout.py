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

"""`--idle-timeout` on the TTLV listener of the native binary or the image.

A short custom timeout keeps the lane fast (docs/interpretations.md,
idle timeout). With `--idle-timeout 2` a connection quiet for 1 s still serves
its next request and one quiet for QUIET seconds is closed by the server (its
`idle_timeout_total` counter rises). With `--idle-timeout 0` a connection quiet
for the same QUIET seconds, longer than the 2 s that closed it before, serves
its next request, and the counter stays 0. Each case uses its own disposable
server and PKI; nothing else is started, stopped or removed.
"""
import argparse, datetime, hashlib, json, pathlib, ssl, tempfile, time
from image_evidence import ROOT, local_image_id, packaged_evidence, source_commit
from network_fixture import metrics
from test_database import ContainerServer
from test_runtime import Server
from wire import create_key, key_value

SHORT = 2
QUIET = 3.5


def wait_for(server, predicate, seconds=5):
    end = time.monotonic() + seconds
    while True:
        current = metrics(server)
        if predicate(current) or time.monotonic() > end:
            return current
        time.sleep(.05)


def closed(c, identifier, expected):
    """True when the connection no longer serves a request: EOF, reset or TLS close."""
    try:
        return key_value(c, identifier, (2, 1)) != expected
    except (EOFError, OSError, ssl.SSLError):
        return True


def case(server, timeout):
    server.extra_args = ['--idle-timeout', str(timeout)]
    server.start()
    try:
        with server.connect() as c:
            identifier = create_key(c, (2, 1))
            expected = key_value(c, identifier, (2, 1))
            time.sleep(1)
            assert key_value(c, identifier, (2, 1)) == expected, 'a connection quiet for 1 s must still serve'
            time.sleep(QUIET)
            started = time.monotonic()
            gone = closed(c, identifier, expected)
            answered_after = round(time.monotonic() - started, 3)
        after = wait_for(server, lambda m: m['active'] == 0)
        return dict(idle_timeout=timeout, quiet_seconds=QUIET, closed_after_quiet=gone,
                    request_seconds=answered_after, counters=after)
    finally:
        server.stop()


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--image', help='run against this image instead of target/debug/keytend-kmip-server')
    p.add_argument('--engine', default='podman')
    p.add_argument('--output', type=pathlib.Path)
    a = p.parse_args()
    out = a.output or ROOT / 'artifacts' / ('idle-timeout-image.json' if a.image else 'idle-timeout.json')
    out.parent.mkdir(parents=True, exist_ok=True)
    binary = hashlib.sha256((ROOT / 'target/debug/keytend-kmip-server').read_bytes()).hexdigest()
    identity = packaged_evidence(local_image_id(a.engine, a.image)) if a.image else {'source_commit': source_commit()[0]}
    report = dict(status='running', started_at=datetime.datetime.now(datetime.timezone.utc).isoformat(),
                  target='image' if a.image else 'native', image=a.image,
                  runtime_binary_sha256=binary, **identity, cases=[],
                  limits='TTLV listener only; the HTTPS idle close and the other deadlines are covered by '
                         'src/server_http.rs unit tests. One client, development PKI.')
    try:
        for timeout in [SHORT, 0]:
            with tempfile.TemporaryDirectory(prefix='keytend-idle-') as d:
                server = ContainerServer(d, a.engine, a.image, log_path=pathlib.Path(d) / 'server.log') if a.image else Server(d)
                result = case(server, timeout)
            report['cases'].append(result)
            counters = result['counters']
            if timeout:
                assert result['closed_after_quiet'] and counters['idle_timeout_total'] == 1, result
                print(f'PASS --idle-timeout {timeout}: served after 1 s quiet, closed by the server after {QUIET} s quiet', flush=True)
            else:
                assert not result['closed_after_quiet'] and counters['idle_timeout_total'] == 0, result
                print(f'PASS --idle-timeout 0: served after 1 s and after {QUIET} s quiet; no idle close', flush=True)
        report['status'] = 'passed'
    except BaseException as error:
        report.update(status='failed', error=f'{type(error).__name__}: {error}'[-2000:])
        raise
    finally:
        report['finished_at'] = datetime.datetime.now(datetime.timezone.utc).isoformat()
        out.write_text(json.dumps(report, indent=2) + '\n')


if __name__ == '__main__':
    main()
