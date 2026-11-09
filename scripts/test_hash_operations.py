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

"""Fingerprint real-listener SHA Hash selection, version boundaries and streams."""
import argparse
import hashlib
import json
import pathlib
import platform
import ssl
import tempfile

from image_evidence import ROOT, local_image_id, packaged_evidence, source_commit
from test_database import ContainerServer
from test_runtime import Server
from wire import binary, children, enumeration, exchange, get, integer, node, payload, reason, request, status, structure

DATA, CP, HASH, CORR, INIT, FINAL = 0x4200c2, 0x42002b, 0x420038, 0x4200d6, 0x4200d7, 0x4200d8
HASHES = {4:'sha1', 5:'sha224', 6:'sha256', 7:'sha384', 8:'sha512',
    12:'sha512_224', 13:'sha512_256', 14:'sha3_224', 15:'sha3_256', 16:'sha3_384', 17:'sha3_512'}


def call(server, version, fields):
    # A fresh verified mutual-TLS connection for each part proves that the
    # correlation token, not socket affinity, selects the provider context.
    with server.connect() as client:
        return exchange(client, request(39, fields, version))


def cp(algorithm):
    return structure(CP, enumeration(HASH, algorithm))


def blob(body, tag=DATA):
    return get(body, tag)[2] if children(body, tag) else None


def denied(response, expected):
    assert status(response) == 1 and reason(response) == expected, (status(response), reason(response), expected)
    assert not children(get(response, 0x42000f), 0x42007c)


def run(server, editions):
    rows = []
    message = bytes(range(256))*521+b'\x00database-hash-boundaries\xff'
    for version in editions:
        if version < (1, 2):
            denied(call(server, version, [cp(6), binary(DATA, b'abc')]), 5)
            rows.append(dict(version='.'.join(map(str, version)), hash_operation_unavailable=True))
            continue
        forms = [[]]
        if version >= (1, 3):
            forms += [[node(INIT, 6, False)], [node(INIT, 6, True), node(FINAL, 6, True)]]
        positive = []
        for algorithm, name in HASHES.items():
            if algorithm >= 14 and version < (1, 4):
                for flags in forms:
                    denied(call(server, version, [cp(algorithm), binary(DATA, b'abc'), *flags]), 8)
                if version >= (1, 3):
                    denied(call(server, version, [cp(algorithm), binary(DATA, b'a'), node(INIT, 6, True)]), 8)
                continue
            for value in [b'', b'abc', message]:
                expected = hashlib.new(name, value).digest()
                for flags in forms:
                    result = payload(call(server, version, [cp(algorithm), binary(DATA, value), *flags]))
                    assert blob(result) == expected, (version, name, len(value))
                    assert not children(result, CORR)
            if version >= (1, 3):
                chunks = [message[:1], message[1:137], message[137:8193], message[8193:]]
                token = None
                for i, chunk in enumerate(chunks):
                    fields = [binary(DATA, chunk)]
                    if i == 0:
                        fields += [cp(algorithm), node(INIT, 6, True)]
                    else:
                        fields += [binary(CORR, token)]
                    if i == len(chunks)-1:
                        # A refused parameter change must not consume this part
                        # or destroy the original context before the retry.
                        wrong = 6 if algorithm != 6 else 7
                        denied(call(server, version, [*fields, cp(wrong), node(FINAL, 6, True)]), 7)
                        fields += [node(FINAL, 6, True)]
                    result = payload(call(server, version, fields))
                    if i == 0:
                        token = blob(result, CORR)
                        assert len(token) == 32 and blob(result) is None
                    elif i != len(chunks)-1:
                        assert blob(result) is None
                    else:
                        assert blob(result) == hashlib.new(name, message).digest()
                        assert not children(result, CORR)
                # 1.x HASH errors: no outstanding operation with this Correlation Value is Item Not Found.
                denied(call(server, version, [binary(CORR, token), node(FINAL, 6, True)]), 0x2e if version[0] >= 2 else 1)
            positive.append(name)
        for flags in forms:
            # A wrongly typed Hashing Algorithm is an invalid field value. A repeated
            # field is Invalid Message in the 1.x General errors table ("the same field
            # is contained in a ... payload more than once"); the 2.x tables give
            # Invalid Field.
            malformed = [(structure(CP, integer(HASH, 6)), 7),
                (structure(CP, enumeration(HASH, 6), enumeration(HASH, 7)), 4 if version[0] == 1 else 7)]
            for parameters, expected in malformed:
                denied(call(server, version, [parameters, binary(DATA, b'abc'), *flags]), expected)
            for unsupported in [0, 1, 2, 3, 9, 10, 11, 18, 0x80000001]:
                denied(call(server, version, [cp(unsupported), binary(DATA, b'abc'), *flags]), 8)
        row = dict(version='.'.join(map(str, version)), mechanisms=positive,
            empty_abc_binary_exact_hashlib=True, single_forms=len(forms),
            multipart_cross_connection=version >= (1,3), failed_parameter_change_retry=version >= (1,3),
            completed_token_replay_denied=version >= (1,3), malformed_and_unsupported_denied=True,
            sha3_before_1_4_denied=version < (1,4), largest_input_bytes=len(message))
        rows.append(row)
        print('PASS Hash', row['version'], len(positive), 'SHA mechanisms; exact independent digests and versioned denials', flush=True)
    return rows


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--image')
    parser.add_argument('--engine', default='podman', choices=['podman', 'docker'])
    args = parser.parse_args()
    output = ROOT/'artifacts/hash-operations'
    output.mkdir(parents=True, exist_ok=True)
    binary_sha = hashlib.sha256((ROOT/'target/debug/keytend-kmip-server').read_bytes()).hexdigest()
    config = local_image_id(args.engine, args.image) if args.image else None
    package = packaged_evidence(config) if config else {'runtime_binary_sha256': binary_sha, 'source_commit': source_commit()[0]}
    report = dict(status='running', **package, python_version=platform.python_version(), python_openssl=ssl.OPENSSL_VERSION)
    path = output/('image.json' if args.image else 'native.json')
    path.write_text(json.dumps(report, indent=2)+'\n')
    try:
        editions = [(1,0), (1,1), (1,2), (1,3), (1,4), (2,0), (2,1)]
        with tempfile.TemporaryDirectory(prefix='keytend-hash-') as directory:
            server = ContainerServer(directory, args.engine, args.image) if args.image else Server(directory, draft=True)
            if not args.image:
                editions.append((3,0))
            with server:
                report['versions'] = run(server, editions)
            if not args.image:
                (output/'native-server.log').write_text((pathlib.Path(directory)/'server.log').read_text())
        report['status'] = 'passed'
    except BaseException as error:
        report.update(status='failed', error_type=type(error).__name__, error=str(error))
        raise
    finally:
        path.write_text(json.dumps(report, indent=2)+'\n')
    print('PASS Hash operation suite', 'image' if args.image else 'native', flush=True)


if __name__ == '__main__':
    main()
