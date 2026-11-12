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

"""Rotate, deactivate, lease, decrypt and destroy over the real TLS listener.

A lease-honouring client's key rotation (docs/lifecycle.md#leases): the old
key is re-keyed, deactivated, leased again to read its data, the data is
re-encrypted under the replacement, and the old key is destroyed; a restart
keeps the outcome. The server is also started with
`KMIP_LEASE_STATES=active` and `KMIP_MAX_LEASE_SECONDS=0` to check both
settings, natively and with --image (the container gets the KMIP_* settings
of this process's environment).
"""
import argparse
import hashlib
import json
import os
import pathlib
import platform
import ssl
import tempfile

from image_evidence import ROOT, local_image_id, packaged_evidence, source_commit, native_sha256
from test_database import ContainerServer
from test_runtime import Server
from wire import binary, create_key, enumeration, exchange, get, payload, reason, request, status, structure, uid

DATA, IV, CP, MODE, PADDING = 0x4200c2, 0x42003d, 0x42002b, 0x420011, 0x42005f
LEASE_TIME, REVOCATION_REASON, REVOCATION_CODE = 0x420049, 0x420081, 0x420082
PERMISSION_DENIED, WRONG_KEY_LIFECYCLE_STATE = 0x0c, 0x43
RECORD = b'customer record protected before the rotation'
DESTROYED = 'A Destroyed object cannot receive a lease'
ACTIVE_ONLY = 'A Deactivated object cannot receive a lease (server lease policy: Active objects only)'


def call(server, v, op, fields=()):
    with server.connect() as client:
        return exchange(client, request(op, list(fields), v))


def ok(server, v, op, fields=()):
    return payload(call(server, v, op, fields))


def refused(response, expected, message=None):
    item = get(response, 0x42000f)
    assert status(response) == 1 and reason(response) == expected, (status(response), reason(response), expected)
    if message is not None:
        assert get(item, 0x42007d)[2] == message, get(item, 0x42007d)[2]


def lease(server, v, key):
    return get(ok(server, v, 16, [uid(key, v)]), LEASE_TIME)[2]


def crypt(server, v, op, key, data):
    parameters = structure(CP, enumeration(MODE, 1), enumeration(PADDING, 3))
    return call(server, v, op, [uid(key, v), parameters, binary(DATA, data), binary(IV, b'\x07'*16)])


def deactivate(server, v, key):
    if v[0] >= 3:
        ok(server, v, 64, [uid(key, v)])
    else:
        ok(server, v, 19, [uid(key, v), structure(REVOCATION_REASON, enumeration(REVOCATION_CODE, 5))])


def active_key(server, v):
    with server.connect() as client:
        key = create_key(client, v)
    ok(server, v, 18, [uid(key, v)])
    return key


def rotation(server, v):
    """Default settings: the full lifecycle. Returns (old, new, ciphertext)."""
    old = active_key(server, v)
    assert lease(server, v, old) == 3600
    cipher = get(payload(crypt(server, v, 31, old, RECORD)), DATA)[2]
    new = get(ok(server, v, 4, [uid(old, v)]), 0x420094)[2]
    if status(call(server, v, 18, [uid(new, v)])) != 0:
        # Re-key may already have activated the replacement.
        assert lease(server, v, new) == 3600
    deactivate(server, v, old)
    # The Deactivated key is leased again so the client may read its data.
    assert lease(server, v, old) == 3600
    plain = get(payload(crypt(server, v, 32, old, cipher)), DATA)[2]
    assert plain == RECORD
    refused(crypt(server, v, 31, old, RECORD), WRONG_KEY_LIFECYCLE_STATE if v[0] >= 2 else PERMISSION_DENIED)
    rewrapped = get(payload(crypt(server, v, 31, new, plain)), DATA)[2]
    ok(server, v, 20, [uid(old, v)])
    refused(call(server, v, 16, [uid(old, v)]), PERMISSION_DENIED, DESTROYED)
    assert status(crypt(server, v, 32, old, cipher)) == 1
    return old, new, rewrapped


def run(server, editions, settings):
    rows = []
    with server:
        kept = {v: rotation(server, v) for v in editions}
        rows.append('rotate, deactivate, lease, decrypt, re-encrypt and destroy at ' + ', '.join('%d.%d' % v for v in editions))
        server.stop()
        server.start()
        for v, (old, new, rewrapped) in kept.items():
            refused(call(server, v, 16, [uid(old, v)]), PERMISSION_DENIED, DESTROYED)
            assert lease(server, v, new) == 3600
            assert get(payload(crypt(server, v, 32, new, rewrapped)), DATA)[2] == RECORD
        rows.append('restart keeps the destroyed old key unleased and the re-encrypted data readable')
    if not settings:
        return rows
    for name, value in [('KMIP_LEASE_STATES', 'active'), ('KMIP_MAX_LEASE_SECONDS', '0')]:
        previous = os.environ.get(name)
        os.environ[name] = value
        try:
            with server:
                for v in editions:
                    key = active_key(server, v)
                    if name == 'KMIP_LEASE_STATES':
                        assert lease(server, v, key) == 3600
                        deactivate(server, v, key)
                        refused(call(server, v, 16, [uid(key, v)]), PERMISSION_DENIED, ACTIVE_ONLY)
                    else:
                        # Lease Time 0: "no lease interval is effective" (1.4 4.17, 2.1 6.1.35).
                        assert lease(server, v, key) == 0
                        deactivate(server, v, key)
                        assert lease(server, v, key) == 0
        finally:
            if previous is None:
                os.environ.pop(name)
            else:
                os.environ[name] = previous
        rows.append('%s=%s at %s' % (name, value, ', '.join('%d.%d' % v for v in editions)))
    return rows


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--image')
    parser.add_argument('--engine', default='podman', choices=['podman', 'docker'])
    args = parser.parse_args()
    output = ROOT/'artifacts/lease-lifecycle'
    output.mkdir(parents=True, exist_ok=True)
    binary_sha = native_sha256(args.image)
    config = local_image_id(args.engine, args.image) if args.image else None
    package = packaged_evidence(config) if config else {'runtime_binary_sha256': binary_sha, 'source_commit': source_commit()[0]}
    report = dict(status='running', **package, python_version=platform.python_version(), python_openssl=ssl.OPENSSL_VERSION)
    path = output/('image.json' if args.image else 'native.json')
    path.write_text(json.dumps(report, indent=2)+'\n')
    try:
        editions = [(1, 4), (2, 1), (3, 0)]
        with tempfile.TemporaryDirectory(prefix='keytend-lease-') as directory:
            # The image takes the KMIP_* settings of the second part from the environment too (ContainerServer).
            server = ContainerServer(directory, args.engine, args.image, draft=True) if args.image else Server(directory, draft=True)
            report['passed'] = run(server, editions, True)
            if not args.image:
                (output/'native-server.log').write_text((pathlib.Path(directory)/'server.log').read_text())
        report['status'] = 'passed'
    except BaseException as error:
        report.update(status='failed', error_type=type(error).__name__, error=str(error))
        raise
    finally:
        path.write_text(json.dumps(report, indent=2)+'\n')
    for row in report['passed']:
        print('PASS', row, flush=True)
    print('PASS lease lifecycle suite', 'image' if args.image else 'native', flush=True)


if __name__ == '__main__':
    main()
