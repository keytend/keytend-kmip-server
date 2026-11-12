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

"""Replay authentic encrypted snapshots under a live mTLS process, without restart."""
import argparse
import hashlib
import http.client
import json
import pathlib
import shutil
import sqlite3
import subprocess
import tempfile

from image_evidence import ROOT, source_commit, local_image_id, packaged_evidence, native_sha256
from test_database import ContainerServer, command
from test_object_state import verify_format
from test_runtime import Server
from test_storage_rotation import cli
from wire import create_key, key_value, exchange, request, payload, uid, structure, enumeration, status, reason

OUT = ROOT/'artifacts/live-history'


class ImageServer(ContainerServer):
    def stop(self):
        if self.container_exists():
            with (self.root/'server.log').open('a') as log:
                log.write(command([self.engine, 'logs', self.name]))
        super().stop()


def identity(server):
    if hasattr(server, 'image'):
        return json.loads(command([server.engine, 'inspect', server.name]))[0]['Id']
    return server.process.pid


def sha(path):
    with pathlib.Path(path).open('rb') as file:
        return hashlib.file_digest(file, 'sha256').hexdigest()


def snapshot(database, output):
    with sqlite3.connect(database) as source, sqlite3.connect(output) as target:
        source.backup(target)
    output.chmod(0o600)


def replay(database, old):
    with sqlite3.connect(database, isolation_level=None) as db:
        db.execute('ATTACH DATABASE ? AS old', (str(old),))
        db.executescript('''BEGIN IMMEDIATE;
            DELETE FROM objects; DELETE FROM object_state; DELETE FROM audit; DELETE FROM meta;
            INSERT INTO objects(rowid,id,owner,sealed) SELECT rowid,id,owner,sealed FROM old.objects;
            INSERT INTO object_state SELECT * FROM old.object_state;
            INSERT INTO audit SELECT * FROM old.audit;
            INSERT INTO meta SELECT * FROM old.meta;
            COMMIT;''')


def health(server, path):
    connection = http.client.HTTPConnection('127.0.0.1', server.health, timeout=5)
    try:
        connection.request('GET', path)
        response = connection.getresponse()
        result = response.status, response.read()
        return result
    finally:
        connection.close()


def lane(directory, detection, image=None, engine='podman'):
    server = ImageServer(directory, engine, image) if image else Server(directory)
    checks = []
    try:
        server.start()
        initial_process = identity(server)
        assert health(server, '/readyz') == (200, b'ready\n')
        with server.connect() as client:
            identifier = create_key(client, (2, 1))
            payload(exchange(client, request(18, [uid(identifier)], (2, 1))))
            material = key_value(client, identifier, (2, 1))
        database = server.data/'kmip.sqlite'
        old, current = server.root/'before.sqlite', server.root/'after.sqlite'
        snapshot(database, old)
        original = verify_format(old, server.pki/'master.key')
        cli(server, 'check-store', database=old, master_key=server.pki/'master.key').check_returncode()
        with server.connect() as client:
            payload(exchange(client, request(19, [uid(identifier),
                structure(0x420081, enumeration(0x420082, 6))], (2, 1))))
            payload(exchange(client, request(20, [uid(identifier)], (2, 1))))
        snapshot(database, current)
        destroyed = verify_format(current, server.pki/'master.key')
        assert destroyed['audit_entries'] > original['audit_entries']
        assert health(server, '/readyz') == (200, b'ready\n')
        checks.append('independent SQLite snapshots and Python AVL/HMAC verification establish an authentic historical key-bearing snapshot and a later valid destroyed-key state')

        replay(database, old)
        # The replay itself remains a cryptographically valid database. A new
        # process without a required external floor cannot infer its age.
        verify_format(database, server.pki/'master.key')
        if detection == 'readiness-first':
            assert health(server, '/readyz') == (503, b'unavailable\n')
        with server.connect() as client:
            denied = exchange(client, request(10, [uid(identifier)], (2, 1)))
            assert status(denied) == 1 and reason(denied) == 0x100, 'live rollback did not produce General Failure'
            from wire import encode
            assert material not in encode(denied)
        assert health(server, '/readyz') == (503, b'unavailable\n')
        assert health(server, '/livez') == (200, b'alive\n')
        checks.append(detection+': whole-store replay under the unchanged process produces explicit KMIP General Failure without historical key material and readiness 503 while liveness remains 200')

        replay(database, current)
        with server.connect() as client:
            denied = exchange(client, request(10, [uid(identifier)], (2, 1)))
            assert status(denied) == 1 and reason(denied) == 0x100
        assert health(server, '/readyz') == (503, b'unavailable\n')
        assert identity(server) == initial_process
        checks.append('reinstalling the latest authentic snapshot cannot clear the running process failure latch')
        server.stop()
        server.start()
        assert health(server, '/readyz') == (200, b'ready\n')
        with server.connect() as client:
            denied = exchange(client, request(10, [uid(identifier)], (2, 1)))
            # 2.x reports the owner's destroyed object as Object Destroyed.
            assert status(denied) == 1 and reason(denied) == 0x36
        checks.append('checked restart on the current authentic database restores readiness and retains destroyed-key denial; no old material is reintroduced')
        return dict(status='passed', detection=detection, checks=checks,
            historical_snapshot_sha256=sha(old), current_snapshot_sha256=sha(current),
            historical_audit_entries=original['audit_entries'], current_audit_entries=destroyed['audit_entries'])
    finally:
        server.stop()
        shutil.copyfile(server.root/'server.log', OUT/(('image-' if image else '')+detection+'.log'))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--image')
    parser.add_argument('--engine', default='podman')
    args = parser.parse_args()
    OUT.mkdir(parents=True, exist_ok=True)
    binary = native_sha256(args.image)
    evidence = packaged_evidence(local_image_id(args.engine, args.image)) if args.image else {'source_commit': source_commit()[0]}
    report = dict(status='running', runtime_binary_sha256=binary, lanes=[], **evidence,
        limits='Process-local freshness and readiness tests on local SQLite under actual mTLS. No database-client, Kubernetes, remote witness, cross-restart freshness without a required independent floor, privileged memory attacker, production durability/capacity or full-spec qualification.')
    if args.image:
        report['server_image'] = args.image
    path = OUT/('image.json' if args.image else 'native.json')
    try:
        for detection in ['get-first', 'readiness-first']:
            with tempfile.TemporaryDirectory(prefix='keytend-live-history-') as directory:
                report['lanes'].append(lane(directory, detection, args.image, args.engine))
                path.write_text(json.dumps(report, indent=2)+'\n')
                print('PASS', detection, flush=True)
        report['status'] = 'passed'
    except BaseException as error:
        report.update(status='failed', error_type=type(error).__name__, error=str(error))
        raise
    finally:
        logs = [('image-' if args.image else '')+detection+'.log' for detection in ['get-first', 'readiness-first']]
        report['log_sha256'] = {str((OUT/name).relative_to(ROOT)): sha(OUT/name) for name in logs if (OUT/name).exists()}
        path.write_text(json.dumps(report, indent=2)+'\n')


if __name__ == '__main__':
    main()
