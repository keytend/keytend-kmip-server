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

"""`/metrics` on the health listener of the native binary or the image.

One disposable server (own PKI, ports and container name) is scraped before
and after a fixed set of requests: binary TTLV Create, Get, Obtain Lease
(refused while Pre-Active, granted after Activate), a JSON Query over HTTPS,
a CA-valid unlisted certificate, a client without a certificate and a
plaintext request on the TLS port. The lane checks the exposition syntax, the
counter deltas, the object census, that no identifier, principal or Name is
exposed, that `/readyz`, `/livez` and `keytend-kmip-server healthcheck` still answer,
and that `--metrics off` answers 404. Nothing else is started, stopped or
removed (docs/metrics.md).
"""
import argparse, datetime, hashlib, http.client, json, pathlib, re, socket, ssl, subprocess, tempfile, time
from image_evidence import ROOT, local_image_id, packaged_evidence, source_commit, native_sha256
from https_client import HttpsContainer, HttpsServer, post
from wire import enumeration, exchange, get, integer, payload, probe_counted, reason, request, status, structure, text, uid

CENSUS_INTERVAL = 10
NAME = 'metrics-lane-secret-name'
SAMPLE = re.compile(r'^([a-zA-Z_:][a-zA-Z0-9_:]*)(\{(.*)\})? (\S+)$')
LABEL = re.compile(r'([a-zA-Z_][a-zA-Z0-9_]*)="((?:[^"\\]|\\.)*)"(,|$)')


def http_get(server, path):
    c = http.client.HTTPConnection('127.0.0.1', server.health, timeout=5)
    try:
        c.request('GET', path)
        r = c.getresponse()
        return r.status, r.headers.get('Content-Type'), r.read().decode()
    finally:
        c.close()


def parse(document):
    """Strict reading of the text format: TYPE before samples, valid names,
    labels and values, histogram suffixes only on histograms."""
    types, samples = {}, {}
    for line in document.splitlines():
        if line.startswith('# HELP '):
            continue
        if line.startswith('# TYPE '):
            _, _, name, kind = line.split(' ', 3)
            assert kind in {'counter', 'gauge', 'histogram'} and name not in types, line
            types[name] = kind
            continue
        m = SAMPLE.match(line)
        assert m, f'malformed sample line: {line!r}'
        name, _, body, value = m.groups()
        family = name
        for suffix in ['_bucket', '_sum', '_count']:
            if name.endswith(suffix) and types.get(name[:-len(suffix)]) == 'histogram':
                family = name[:-len(suffix)]
        assert family in types, f'{name} has no TYPE line'
        labels = {}
        rest = body or ''
        while rest:
            lm = LABEL.match(rest)
            assert lm, f'malformed labels: {body!r}'
            labels[lm.group(1)] = lm.group(2)
            rest = rest[lm.end():]
        float(value.replace('+Inf', 'inf').replace('-Inf', '-inf'))
        key = (name, tuple(sorted(labels.items())))
        assert key not in samples, f'duplicate series {key}'
        samples[key] = float(value.replace('+Inf', 'inf').replace('-Inf', '-inf'))
    return types, samples


def scrape(server):
    code, content_type, body = http_get(server, '/metrics')
    assert code == 200, (code, body)
    assert content_type == 'text/plain; version=0.0.4; charset=utf-8', content_type
    return body, parse(body)[1]


def value(samples, name, **labels):
    """Sum of the series of `name` whose labels include `labels`."""
    return sum(v for (n, ls), v in samples.items()
               if n == name and all(dict(ls).get(k) == str(want) for k, want in labels.items()))


def raw_tls_failures(server):
    """A client without a certificate and a plaintext request on the KMIP port."""
    try:
        with server.connect(cert=False) as c:
            exchange(c, request(24, [enumeration(0x420074, 1)]))
    except (OSError, EOFError, ssl.SSLError):
        pass
    else:
        raise AssertionError('client without a certificate was accepted')
    with socket.create_connection(('127.0.0.1', server.port), timeout=5) as s:
        s.sendall(b'GET / HTTP/1.1\r\nHost: x\r\n\r\n')
        try:
            s.recv(64)
        except OSError:
            pass


def healthcheck(server, image, engine):
    if image:
        command = [engine, 'exec', server.name, '/usr/local/bin/keytend-kmip-server', 'healthcheck']
    else:
        command = [server.binary, 'healthcheck', '--address', f'127.0.0.1:{server.health}']
    return subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=30)


def image_binary_sha256(engine, image):
    """SHA-256 of the server executable in the image (the image has no shell; the file is copied out)."""
    container = subprocess.check_output([engine, 'create', image], text=True).strip()
    try:
        with tempfile.TemporaryDirectory() as d:
            subprocess.run([engine, 'cp', f'{container}:/usr/local/bin/keytend-kmip-server', d], check=True)
            return hashlib.sha256((pathlib.Path(d)/'keytend-kmip-server').read_bytes()).hexdigest()
    finally:
        subprocess.run([engine, 'rm', '-f', container], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def exercise(server, image, engine):
    results = {}
    if image:
        probe_counted(server.health)  # ContainerServer.start's readiness probe of the KMIP port
    before_text, before = scrape(server)
    assert value(before, 'kmip_build_info') == 1
    build = [dict(ls) for (n, ls), _ in before.items() if n == 'kmip_build_info'][0]
    assert build['version'] and build['fips_mode'] == 'false', build
    assert value(before, 'kmip_ready') == 1 and value(before, 'kmip_fips_mode') == 0
    assert value(before, 'kmip_object_census_interval_seconds') == CENSUS_INTERVAL
    v = (2, 1)
    with server.connect() as c:
        # A named AES key; the lane later looks for the Name in the exposition.
        attributes = structure(0x420125, enumeration(0x420028, 3), integer(0x42002a, 256), integer(0x42002c, 12),
                               structure(0x420053, text(0x420055, NAME), enumeration(0x420054, 1)))
        id = get(payload(exchange(c, request(1, [enumeration(0x420057, 2), attributes], v))), 0x420094)[2]
        refused = exchange(c, request(16, [uid(id, v)], v))
        assert status(refused) == 1 and reason(refused) == 12, refused
        payload(exchange(c, request(18, [uid(id, v)], v)))
        payload(exchange(c, request(16, [uid(id, v)], v)))
        payload(exchange(c, request(10, [uid(id, v)], v)))
    payload(post(server, request(24, [enumeration(0x420074, 1)], v), 'JSON'))
    with server.connect(identity='unlisted') as c:
        r = exchange(c, request(24, [enumeration(0x420074, 1)], v))
        assert status(r) == 1 and reason(r) == 12
    raw_tls_failures(server)
    # Connection counters settle once the server has closed every connection.
    end = time.monotonic() + 10
    while True:
        after_text, after = scrape(server)
        if value(after, 'kmip_connections_active') == 0 or time.monotonic() > end:
            break
        time.sleep(.1)
    delta = lambda name, **labels: value(after, name, **labels) - value(before, name, **labels)
    expected = {
        ('kmip_requests_total', (('encoding', 'ttlv'), ('version', '2.1'))): 6,
        ('kmip_requests_total', (('encoding', 'json'), ('version', '2.1'))): 1,
    }
    for (name, labels), want in expected.items():
        assert delta(name, **dict(labels)) == want, (name, labels, delta(name, **dict(labels)))
    checks = {
        'Create succeeded': delta('kmip_operations_total', version='2.1', encoding='ttlv', operation='Create', status='Success'),
        'Obtain Lease refused': delta('kmip_operations_total', operation='ObtainLease', status='OperationFailed', reason='PermissionDenied'),
        'JSON Query': delta('kmip_operations_total', encoding='json', operation='Query', status='Success'),
        'unlisted Query denied': delta('kmip_operations_total', operation='Query', status='OperationFailed', reason='PermissionDenied'),
        'leases granted': delta('kmip_leases_granted_total'),
        'leases refused': delta('kmip_leases_refused_total', reason='PermissionDenied'),
        'unlisted connection': delta('kmip_connections_refused_unlisted_total', listener='ttlv'),
        'HTTPS connection': delta('kmip_connections_accepted_total', listener='https'),
        'no client certificate': delta('kmip_tls_handshake_failures_total', listener='ttlv', reason='no_client_certificate'),
        'plaintext on TLS port': delta('kmip_tls_handshake_failures_total', listener='ttlv', reason='not_tls'),
        'Get timed': delta('kmip_request_duration_seconds_count', operation='Get'),
    }
    for name, got in checks.items():
        assert got == 1, (name, got, after_text)
    assert delta('kmip_connections_accepted_total', listener='ttlv') == 4, (before_text, after_text)
    assert delta('kmip_request_batch_items_count') == 7
    assert value(after, 'kmip_connections_active') == 0
    results['deltas'] = checks
    # The census (every CENSUS_INTERVAL s) reports the key, Active after Activate.
    end = time.monotonic() + 3 * CENSUS_INTERVAL
    while value(after, 'kmip_objects', type='SymmetricKey', state='Active') != 1:
        assert time.monotonic() < end, after_text
        time.sleep(1)
        after_text, after = scrape(server)
    assert value(after, 'kmip_objects_unreadable') == 0
    results['census_objects'] = value(after, 'kmip_objects')
    assert value(after, 'kmip_store_database_bytes') > 0
    policy = json.loads((server.pki / 'policy.json').read_text())['principals']
    secrets = [id, NAME, str(server.pki)] + list(policy) + [p['name'] for p in policy.values()]
    # Identifiers and Names nowhere; principal names (generic words in the
    # development policy) and fingerprints in no label value.
    for secret in [id, NAME, str(server.pki)] + list(policy):
        assert secret not in after_text, f'{secret} exposed'
    values = {v for (_, labels), _ in after.items() for _, v in labels}
    for secret in secrets:
        assert not any(secret in v for v in values), f'{secret} exposed in a label value'
    results['binary_sha256_reported'] = [dict(ls) for (n, ls), _ in after.items() if n == 'kmip_build_info'][0]['binary_sha256']
    # The executable that runs reports its own digest: the native file, or the image's.
    assert results['binary_sha256_reported'] == (image_binary_sha256(engine, image) if image else
                                                 hashlib.sha256(pathlib.Path(server.binary).read_bytes()).hexdigest())
    for path, want in [('/livez', 'alive\n'), ('/readyz', 'ready\n')]:
        assert http_get(server, path)[::2] == (200, want), path
    assert http_get(server, '/connection-metrics')[0] == 200
    r = healthcheck(server, image, engine)
    assert r.returncode == 0, r.stdout
    results['families'] = len(parse(after_text)[0])
    results['series'] = len(after)
    return results


def run(server, image, engine, args):
    server.extra_args = args
    server.start()
    try:
        return server
    except BaseException:
        server.stop()
        raise


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--image', help='run against this image instead of target/debug/keytend-kmip-server')
    p.add_argument('--engine', default='podman')
    p.add_argument('--output', type=pathlib.Path)
    a = p.parse_args()
    out = a.output or ROOT / 'artifacts' / ('metrics-image.json' if a.image else 'metrics.json')
    out.parent.mkdir(parents=True, exist_ok=True)
    binary = native_sha256(a.image)
    identity = packaged_evidence(local_image_id(a.engine, a.image)) if a.image else {'source_commit': source_commit()[0]}
    report = dict(status='running', started_at=datetime.datetime.now(datetime.timezone.utc).isoformat(),
                  target='image' if a.image else 'native', image=a.image,
                  runtime_binary_sha256=binary, **identity, cases=[],
                  limits='One client and development PKI; counters are checked as deltas of one scrape pair. '
                         'No Prometheus server, alert rule or Kubernetes scrape was exercised.')
    try:
        with tempfile.TemporaryDirectory(prefix='keytend-metrics-') as d:
            make = (lambda: HttpsContainer(d, a.engine, a.image, log_path=pathlib.Path(d) / 'server.log')) if a.image else (lambda: HttpsServer(d))
            server = make()
            run(server, a.image, a.engine, ['--metrics-object-census-interval', str(CENSUS_INTERVAL)])
            try:
                result = exercise(server, a.image, a.engine)
            finally:
                server.stop()
            report['cases'].append(dict(case='metrics on', **result))
            print('PASS /metrics: exposition syntax, request/lease/connection/TLS deltas, census, no identifiers; '
                  '/livez, /readyz and healthcheck answer', flush=True)
            run(server, a.image, a.engine, ['--metrics', 'off'])
            try:
                code = http_get(server, '/metrics')[0]
                ready = http_get(server, '/readyz')[0]
                check = healthcheck(server, a.image, a.engine).returncode
            finally:
                server.stop()
            assert (code, ready, check) == (404, 200, 0), (code, ready, check)
            report['cases'].append(dict(case='metrics off', metrics_status=code, readyz_status=ready, healthcheck_exit=check))
            print('PASS --metrics off: /metrics 404; /readyz and healthcheck unchanged', flush=True)
        report['status'] = 'passed'
    except BaseException as error:
        report.update(status='failed', error=f'{type(error).__name__}: {error}'[-2000:])
        raise
    finally:
        report['finished_at'] = datetime.datetime.now(datetime.timezone.utc).isoformat()
        out.write_text(json.dumps(report, indent=2) + '\n')


if __name__ == '__main__':
    main()
