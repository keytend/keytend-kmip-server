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

"""Focused aggregate response-node regression over real mTLS HTTPS and TTLV.

Uses an explicit binary or a packaged image, unique owned temporary fixtures
and exact audit/state assertions. Image checks label the native executable as
fixture setup only; the image's own CLI verifies its store. No full-conformance
or production credit.
--baseline expects the pre-fix defect from the given (pre-fix) binary.
"""
import argparse
import json
import pathlib
import subprocess
import tempfile

from image_evidence import source_commit, local_image_id, packaged_evidence
from https_client import HttpsServer, HttpsContainer, decoded
from test_runtime import sha
from test_response_size import ATTRS, CONTINUE, STOP, UNDO, audit, batch, objects, results, send, state
from test_runtime import ROOT
from wire import attr, children, create_key, encode, enumeration, exchange, get, payload, request, structure, uid


def resources(n):
    sub = [resources(c) for c in n[2]] if n[1] == 1 else []
    return 1 + sum(x[0] for x in sub), max([0] + [x[1] + 1 for x in sub])


def fresh(s, identifier):
    with s.connect() as c:
        p = payload(exchange(c, request(11, [uid(identifier, (2, 1)), enumeration(0x42013b, 0x4200a8)], (2, 1))))
    return get(get(p, 0x420125), 0x4200a8)[2]


def receive(s, n, transport):
    if transport == 'native-TTLV':
        with s.connect() as c:
            response = exchange(c, n)
        return None, encode(response), response
    code, body = send(s, n, transport)
    return code, body, decoded(body, transport) if code == 200 else None


def aggregate(s, baseline):
    lanes = []
    for transport in ['TTLV', 'JSON', 'XML', 'native-TTLV']:
        for v in [(1, 4), (2, 1), (3, 0)]:
            for continuation in [STOP, CONTINUE, UNDO]:
                for maximum in [None, 8 * 1024 * 1024]:
                    with s.connect() as c:
                        existing = create_key(c, v)
                        other = create_key(c, v)
                    before = objects(s)
                    seq = len(audit(s))
                    # Reuse the established 1.x Attribute projection.
                    attrs = structure(0x420091, *map(attr, ATTRS)) if v[0] == 1 else structure(0x420125, *ATTRS)
                    placeholder = [enumeration(0x420094, 1)] if v[0] >= 3 else []
                    entries = [(1, [enumeration(0x420057, 2), attrs]), (10, placeholder), (10, [uid(existing, v)])]
                    entries += [(24, [enumeration(0x420074, 2)] * 512)] * 4
                    entries += [(10, placeholder), (20, [uid(other, v)])]
                    code, body, response = receive(s, batch(v, entries, maximum, continuation, 'nodes'), transport)
                    rows = audit(s)[seq:]
                    created = objects(s) - before
                    destroyed = state(s, other) == 5
                    exposed = not fresh(s, existing)
                    if baseline and transport != 'native-TTLV':
                        assert code == 400 and response is None, (transport, v, code)
                        assert rows == [] and not created and not destroyed and not exposed
                        statuses, count, depth = [], None, None
                    else:
                        assert code in [None, 200], (transport, v, code)
                        r = results(response)
                        statuses = [st for _, st, _ in r]
                        count, depth = resources(response)
                        if baseline:
                            assert statuses == [0] * 9 and count > 16384
                        else:
                            expected = [3 if continuation == UNDO else 0] * 6 + [1]
                            if continuation == CONTINUE:
                                expected += [0, 0]
                            assert statuses == expected, (transport, v, continuation, statuses)
                            assert all(reason == 2 for _, status, reason in r if status == 1)
                            assert count <= 16384 and depth <= 32
                            assert destroyed == (continuation == CONTINUE)
                        assert rows == [(op, status) for op, status, _ in r], (rows, r)
                        assert len(created) == (1 if baseline or continuation != UNDO else 0)
                        assert exposed, 'a retained Get (including Undone) must keep exposure history'
                        if baseline or continuation == CONTINUE:
                            first = get(get(children(response, 0x42000f)[0], 0x42007c), 0x420094)[2]
                            last = get(get(children(response, 0x42000f)[7], 0x42007c), 0x420094)[2]
                            assert first == last, 'placeholder must survive the failed Query'
                        if v[0] < 3:
                            assert [get(i, 0x420093)[2] for i in children(response, 0x42000f)] == [bytes([i]) for i in range(len(r))]
                        assert len(encode(response)) <= 1024 * 1024
                        # The client limit is binary TTLV-equivalent (Profiles sections 5.4 and 5.5).
                        assert maximum is None or len(encode(response)) <= maximum
                        assert len(body) <= 8 * 1024 * 1024
                    lanes.append(dict(transport=transport, wire_version='.'.join(map(str, v)), continuation=continuation,
                                      maximum_response_size=maximum, http_status=code, wire_bytes=len(body),
                                      response_nodes=count, response_depth=depth, statuses=statuses,
                                      audit_rows=rows, created_count=len(created), destroyed=destroyed,
                                      retained_get_exposure=exposed))
    return lanes


def expansion(s):
    lanes = []
    v = (2, 1)
    for transport in ['TTLV', 'JSON', 'XML', 'native-TTLV']:
        for continuation in [STOP, CONTINUE, UNDO]:
            before = objects(s)
            seq = len(audit(s))
            entries = [(1, [enumeration(0x420057, 2), structure(0x420125, *ATTRS)])] * 2
            # 27 fixed response nodes + 16,352 Query nodes + five failure nodes.
            entries += [(24, [enumeration(0x420074, 3)] * 8176), (10, [enumeration(0x420094, 3)])]
            code, body, response = receive(s, batch(v, entries, None, continuation), transport)
            assert code in [None, 200], (transport, code)
            r = results(response)
            expected = [3 if continuation == UNDO else 0] * 3 + [1]
            assert [status for _, status, _ in r] == expected, (transport, continuation, r)
            assert r[-1][2] == 2 and not children(children(response, 0x42000f)[-1], 0x42007d)
            rows = audit(s)[seq:]
            assert rows == [(op, status) for op, status, _ in r]
            assert resources(response)[0] == 16384
            created = objects(s) - before
            assert len(created) == (0 if continuation == UNDO else 2)
            assert all(fresh(s, identifier) for identifier in created), 'failed expanded Get must not expose either key'
            assert [get(i, 0x420093)[2] for i in children(response, 0x42000f)] == [bytes([i]) for i in range(4)]
            lanes.append(dict(transport=transport, continuation=continuation, maximum_response_size=None,
                              wire_bytes=len(body), response_nodes=resources(response)[0], statuses=expected,
                              audit_rows=rows, created_count=len(created), failed_get_exposure=False))
    return lanes


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=pathlib.Path)
    parser.add_argument('--image')
    parser.add_argument('--engine', default='podman', choices=['podman', 'docker'])
    parser.add_argument('--output', required=True, type=pathlib.Path)
    parser.add_argument('--baseline', action='store_true', help='expect the pre-fix defect from a pre-fix --binary')
    args = parser.parse_args()
    if args.image and (args.binary or args.baseline):
        parser.error('--image is incompatible with --binary and --baseline')
    if not args.image and not args.binary:
        parser.error('provide --binary or --image')
    binary = (args.binary or ROOT / 'target/debug/keytend-kmip-server').resolve()
    digest = sha(binary)
    image_identity = packaged_evidence(local_image_id(args.engine, args.image)) if args.image else {}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='keytend-t3-aab8-response-nodes-') as directory:
        s = HttpsContainer(directory, args.engine, args.image, draft=True, binary=binary, log_path=args.output.with_suffix('.server.log')) if args.image else HttpsServer(directory, draft=True, binary=binary)
        try:
            s.start()
            lanes = aggregate(s, args.baseline)
            expanded = [] if args.baseline else expansion(s)
            s.stop()
            command = (s.base() + [args.image, 'check-store', '--database', '/data/kmip.sqlite',
                '--master-key', '/tls/master.key']) if args.image else [str(binary), 'check-store',
                '--database', str(s.data / 'kmip.sqlite'), '--master-key', str(s.pki / 'master.key')]
            checked = subprocess.run(command, capture_output=True, text=True)
            assert checked.returncode == 0, checked.stderr
        finally:
            s.stop()
    if args.image:
        assert not s.container_exists()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(dict(status='baseline_defect_reproduced' if args.baseline else 'passed',
        **({'server_mode':'container', 'fixture_cli_binary_sha256':digest, **image_identity} if args.image else
           {'server_mode':'native', 'runtime_binary_sha256':digest, 'source_commit':source_commit()[0]}),
        aggregate_lanes=lanes, exact_node_expansion_lanes=expanded, check_store_exit=checked.returncode), indent=2) + '\n')
    print(f"PASS {'baseline reproduction' if args.baseline else 'aggregate node regression'}: {len(lanes)} aggregate + {len(expanded)} expansion lanes; audit/store verified")


if __name__ == '__main__':
    main()
