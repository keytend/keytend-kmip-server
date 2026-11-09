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

"""Independent socket/TLS regressions for bounded shared listener admission."""
import argparse
import concurrent.futures
import contextlib
import hashlib
import json
import pathlib
import shutil
import socket
import ssl
import tempfile
import time
from image_evidence import source_commit
from network_fixture import NetworkServer, metrics
from wire import create_key, key_value, connect


def wait_for(server, predicate, seconds=3):
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        current = metrics(server)
        if predicate(current):
            return current
        time.sleep(.02)
    raise AssertionError(('counter condition timed out', current))


def run(server, old_drop):
    results = []
    server.network_observations = {}
    def passed(name):
        results.append(name)
        print('PASS', name, flush=True)
    if old_drop:
        with contextlib.ExitStack() as stack:
            for _ in range(2):
                stack.enter_context(socket.create_connection(('127.0.0.1', server.port), timeout=2))
            time.sleep(.2)
            failures = []
            for _ in range(8):
                try:
                    with server.connect():
                        raise AssertionError('old server unexpectedly admitted an extra connection')
                except OSError as error:
                    failures.append(type(error).__name__)
            passed('baseline accepted-at-cap socket loss reproduced: ' + str(failures))
        return results

    def idle():
        return wait_for(server, lambda m: m['active'] == 0)
    idle()
    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
        # Both listeners share two permits. A queued TLS client must survive until
        # a permit is freed, rather than seeing a pre-handshake accepted-socket reset.
        with contextlib.ExitStack() as stack:
            first = stack.enter_context(socket.create_connection(('127.0.0.1', server.port), timeout=2))
            stack.enter_context(socket.create_connection(('127.0.0.1', server.https), timeout=2))
            full = wait_for(server, lambda m: m['active'] == 2 and m['tls_started_total'] >= 2)
            future = pool.submit(server.connect)
            time.sleep(.3)
            saturated = metrics(server)
            assert not future.done(), 'queued TLS was reset instead of backpressured'
            assert saturated['tcp_accepted_total'] == full['tcp_accepted_total']
            assert saturated['active'] == 2 and saturated['admission_waiting'] == 1
            server.network_observations['saturated'] = saturated
            first.close()
            with future.result(timeout=3) as c:
                identifier = create_key(c, (2, 1))
                expected = key_value(c, identifier, (2, 1))
                assert len(expected) == 32
        m = idle()
        assert m['ttlv_accepted_total'] >= 2 and m['https_accepted_total'] == 1
        assert m['admission_wait_total'] > 0 and m['admission_wait_ns_total'] > 0
        passed('shared TTLV/HTTPS cap queues TLS; health counters remain responsive; release resumes work')

        before = metrics(server)
        with contextlib.ExitStack() as stack:
            for _ in range(2):
                stack.enter_context(socket.create_connection(('127.0.0.1', server.port), timeout=2))
            wait_for(server, lambda m: m['active'] == 2)
            began = time.monotonic()
            def patient_connect():
                ctx = ssl.create_default_context(cafile=str(server.pki / 'ca.pem'))
                ctx.load_cert_chain(server.pki / 'client.pem', server.pki / 'client.key')
                raw = socket.create_connection(('127.0.0.1', server.port), timeout=13)
                try:
                    return ctx.wrap_socket(raw, server_hostname='localhost')
                except BaseException:
                    raw.close()
                    raise
            future = pool.submit(patient_connect)
            with future.result(timeout=13) as c:
                assert key_value(c, identifier, (2, 1)) == expected
            assert 8 < time.monotonic() - began < 13
        after = idle()
        assert after['tls_timeout_total'] - before['tls_timeout_total'] == 2
        server.network_observations['after_handshake_timeouts'] = after
        passed('10s handshake deadline frees saturated slots and queued authenticated Get succeeds')

    def gets(_):
        for _ in range(20):
            with server.connect() as c:
                assert key_value(c, identifier, (2, 1)) == expected
    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
        list(pool.map(gets, range(8)))
    with server.connect() as c:
        for _ in range(20):
            assert key_value(c, identifier, (2, 1)) == expected
    idle()
    passed('160 fresh TLS Gets at eight clients/two slots plus 20 persistent Gets preserve exact key')

    before = metrics(server)
    with socket.create_connection(('127.0.0.1', server.port), timeout=2) as c:
        c.sendall(b'not a TLS record')
    after = wait_for(server, lambda m: m['tls_failed_total'] > before['tls_failed_total'] and m['active'] == 0)
    assert after['tcp_accepted_total'] == after['closed_total']
    assert after['tls_started_total'] == (after['tls_succeeded_total'] + after['tls_failed_total'] + after['tls_timeout_total'])
    assert after['cancelled_total'] == 0
    server.network_observations['quiescent_after_churn_and_bad_tls'] = after
    passed('bad TLS counted separately; quiescent accepted/closed and handshake outcomes reconcile')

    held = [socket.create_connection(('127.0.0.1', server.port), timeout=2) for _ in range(2)]
    try:
        before = wait_for(server, lambda m: m['active'] == 2 and m['admission_waiting'] == 1)
        queued = socket.create_connection(('127.0.0.1', server.port), timeout=2)
        try:
            server.process.terminate()
            time.sleep(.1)
        finally:
            queued.close()
    finally:
        for c in held:
            c.close()
    server.process.wait(timeout=3)
    assert server.process.returncode == 0
    final = [json.loads(line)['fields'] for line in (server.root / 'server.log').read_text().splitlines() if line.startswith('{')]
    final = next(json.loads(item['counters']) for item in final if item.get('phase') == 'shutdown')
    assert final['admission_waiting'] == 0 and final['active'] == 0
    assert final['tcp_accepted_total'] == before['tcp_accepted_total']
    server.network_observations['shutdown'] = final
    passed('SIGTERM interrupts admission wait and drains owned connections promptly')
    return results


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--binary', type=pathlib.Path, required=True)
    p.add_argument('--output', type=pathlib.Path, required=True)
    p.add_argument('--expect-old-drop', action='store_true')
    a = p.parse_args()
    a.output.mkdir(parents=True, exist_ok=True)
    binary = a.binary.resolve()
    sha = lambda f: hashlib.sha256(f.read_bytes()).hexdigest()
    digest = sha(binary)
    report = dict(status='running', runtime_binary_sha256=digest, source_commit=source_commit()[0],
                  baseline=a.expect_old_drop)
    try:
        with tempfile.TemporaryDirectory(prefix='keytend-churn-eb997888-') as directory:
            server = NetworkServer(directory, binary, max_connections=2, https=True)
            try:
                server.start()
                report['passed'] = run(server, a.expect_old_drop)
                report['observations'] = server.network_observations
            finally:
                server.stop()
                shutil.copyfile(server.root / 'server.log', a.output / 'server.log')
        report['status'] = 'baseline_defect_reproduced' if a.expect_old_drop else 'passed'
    except BaseException as error:
        report['status'] = 'failed'
        report['error'] = repr(error)
        raise
    finally:
        (a.output / 'summary.json').write_text(json.dumps(report, indent=2) + '\n')


if __name__ == '__main__':
    main()
