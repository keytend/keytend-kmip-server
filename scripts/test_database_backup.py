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

"""Restore real encrypted Percona hot backups across KMIP key rotation.

Disposable single-host replicas and isolated standalone restores. This does not
qualify cluster-wide backup consistency, PITR, a backup service or an RPO/RTO.
"""
import argparse
import hashlib
import json
import pathlib
import shutil
import subprocess
import tempfile
import time

import test_database
import test_database_replicaset
from image_evidence import ROOT, local_image_id, packaged_evidence
from test_database import PERCONA
from test_database_replicaset import ReplicaSet, USER, command
from test_runtime import free_port
from wire import exchange, get, key_value, payload, request, structure, enumeration, uid

OUT = ROOT / 'artifacts/database-backup'


def sha(path):
    with pathlib.Path(path).open('rb') as file:
        return hashlib.file_digest(file, 'sha256').hexdigest()


def manifest(directory):
    return {str(path.relative_to(directory)): sha(path)
            for path in sorted(directory.rglob('*')) if path.is_file()}


def key_state(server, identifier):
    with server.connect() as client:
        return get(get(payload(exchange(client, request(11, [uid(identifier),
            enumeration(0x42013b, 0x42008d)], (2, 1)))), 0x420125), 0x42008d)[2]


class BackupSet(ReplicaSet):
    def __init__(self, *args):
        super().__init__(*args)
        self.backups = self.root / 'hot-backups'
        self.backups.mkdir(mode=0o700)
        self.restore_names = []

    def base(self, member):
        return super().base(member) + ['-v', f'{self.backups}:/backups']

    def snapshot(self, member):
        return self.shell(member, """(()=>{
            db.getMongo().setReadPref('secondaryPreferred');
            const c=db.getSiblingDB('qualification').records;
            return {documents:c.find({}).sort({_id:1}).toArray(),
                indexes:c.getIndexes().map(i=>({name:i.name,key:i.key,unique:!!i.unique}))
                    .sort((a,b)=>a.name.localeCompare(b.name))};
        })()""")

    def hot_backup(self, member, label):
        directory = self.backups / label
        assert not directory.exists()
        expected = self.snapshot(member)
        started = time.monotonic()
        result = self.shell(member, 'db.getSiblingDB("admin").runCommand(' +
            json.dumps({'createBackup': 1, 'backupDir': '/backups/' + label}) + ')')
        assert result['ok'] == 1, result
        assert self.snapshot(member) == expected
        files = manifest(directory)
        assert 'WiredTiger' in files and any('key' in name.lower() for name in files)
        return {'label': label, 'directory': directory, 'expected': expected,
                'files': files, 'observed_backup_seconds': round(time.monotonic()-started, 3)}

    def vault_backup(self, label):
        self.server.backup()
        path = self.root / (label + '.sqlite')
        shutil.copyfile(self.server.data / 'backup.sqlite', path)
        path.chmod(0o600)
        # The next backup must not overwrite an existing output.
        (self.server.data / 'backup.sqlite').unlink()
        return path

    def switch_vault(self, snapshot, label):
        self.server.stop()
        directory = self.root / ('vault-' + label)
        directory.mkdir(mode=0o700)
        shutil.copyfile(snapshot, directory / 'kmip.sqlite')
        (directory / 'kmip.sqlite').chmod(0o600)
        assert sha(directory / 'kmip.sqlite') == sha(snapshot)
        self.server.data = directory
        self.server.start()

    def restore(self, backup, label, expected_key, success):
        # Never join the source replica set: otherwise initial sync could hide
        # an unreadable physical backup by replacing its database contents.
        assert manifest(backup['directory']) == backup['files']
        directory = self.root / ('restore-' + label)
        shutil.copytree(backup['directory'], directory)
        assert manifest(directory) == backup['files']
        directory.chmod(0o700)
        member = 0
        original_name, original_directory, original_port = (
            self.names[member], self.directories[member], self.ports[member])
        name = original_name + '-' + label
        self.restore_names.append(name)
        self.names[member], self.directories[member], self.ports[member] = name, directory, free_port()
        flags = self.flags(member)
        for option in ['--replSet', '--keyFile']:
            at = flags.index(option)
            del flags[at:at+2]
        flags.append('--auth')
        started = time.monotonic()
        try:
            command(self.base(member)+['-d', '--name', name, PERCONA]+flags)
            if success:
                self.ready(member)
                assert self.shell(member, '!!db.adminCommand({hello:1}).setName') is False
                assert self.key_id(member) == expected_key
                actual = self.snapshot(member)
                assert actual == backup['expected'], 'Restored documents/indexes differ from backup boundary'
                assert self.shell(member, 'db.getSiblingDB("qualification").runCommand({validate:"records",full:true}).valid') is True
                assert self.shell(member, 'db.runCommand({connectionStatus:1}).authInfo.authenticatedUsers') == [{'user': USER, 'db': 'admin'}]
                unauthorized = self.shell(member, "(()=>{try{db.getSiblingDB('qualification').records.findOne({});return 0;}catch(e){return e.code;}})()", auth=False)
                assert unauthorized == 13
                try:
                    self.shell(member, 'db.adminCommand({ping:1}).ok', auth=False, tls=False)
                except subprocess.CalledProcessError:
                    pass
                else:
                    raise AssertionError('Restored database accepted plaintext transport')
                result = {'label': label, 'status': 'recovered', 'key_id': expected_key,
                    'documents': len(actual['documents']), 'indexes': actual['indexes'],
                    'snapshot_sha256': hashlib.sha256(json.dumps(actual, sort_keys=True).encode()).hexdigest()}
            else:
                def exited():
                    state = self.inspect(member)['State']
                    return state if not state['Running'] else None
                state = self.eventually(exited, timeout=25)
                assert state['ExitCode'] != 0
                logs = command([self.engine, 'logs', name])
                events = [json.loads(line) for line in logs.splitlines() if line.startswith('{')]
                errors = [event['attr']['error']['reason'] for event in events
                          if event.get('id') == 29120]
                assert len(errors) == 1 and errors[0]['what'] == 'key reading failed'
                error = errors[0]
                assert error['keyManagementFacilityType'] == 'KMIP server'
                assert error['keyIdentifier']['kmipKeyIdentifier'] == expected_key
                # Check the structured encryption error, not a timeout or a
                # generic container failure. Percona calls a missing key absent.
                if label == 'new-with-stale-vault':
                    assert error['reason'] == 'Cannot start. Master encryption key is absent on the key management facility. Check configuration options.'
                else:
                    assert error['keyState'] == 'Compromised'
                    assert error['reason'] == 'Master encryption key is not in the active state on the key management facility.'
                result = {'label': label, 'status': 'refused', 'key_id': expected_key,
                    'exit_code': state['ExitCode'], 'encryption_error': error}
            result['observed_seconds'] = round(time.monotonic()-started, 3)
            return result
        finally:
            try:
                (OUT/(label+'.log')).write_text(command([self.engine, 'logs', name]))
            finally:
                subprocess.run([self.engine, 'rm', '-f', name], stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL, timeout=45, check=True)
                self.names[member], self.directories[member], self.ports[member] = (
                    original_name, original_directory, original_port)
            assert manifest(backup['directory']) == backup['files'], 'Restore modified the retained backup'


def run(fixture, report):
    def passed(description):
        report['passed'].append(description)
        (OUT/'image.json').write_text(json.dumps(report, indent=2)+'\n')
        print('PASS', description, flush=True)

    fixture.server.start()
    for member in range(3):
        fixture.start(member)
    fixture.eventually(lambda: fixture.shell(0, 'db.adminCommand({ping:1}).ok', auth=False))
    config = {'_id': 'qualification', 'members': [
        {'_id': member, 'host': 'localhost:'+str(port)} for member, port in enumerate(fixture.ports)],
        'settings': {'electionTimeoutMillis': 2000}}
    assert fixture.shell(0, 'rs.initiate('+json.dumps(config)+').ok', auth=False) == 1
    primary = fixture.primary(auth=False)
    assert fixture.shell(primary, "db.getSiblingDB('admin').runCommand({createUser:"+json.dumps(USER)+",pwd:require('fs').readFileSync('/tls/admin-password','utf8'),roles:[{role:'root',db:'admin'}],writeConcern:{w:'majority',wtimeout:15000}}).ok", auth=False) == 1
    for member in range(3):
        fixture.ready(member)
    build = fixture.shell(primary, '(()=>{const b=db.adminCommand({buildInfo:1});return {version:b.version,gitVersion:b.gitVersion};})()')
    assert build['version'].startswith('8.0.34')
    config_id = local_image_id(fixture.engine, PERCONA)
    assert all(fixture.inspect(member)['Image'].removeprefix('sha256:') == config_id for member in range(3))
    identifiers = [fixture.key_id(member) for member in range(3)]
    assert len(set(identifiers)) == 3 and all(key_state(fixture.server, key) == 2 for key in identifiers)
    selected = next(member for member in range(3) if member != primary)
    old_id = identifiers[selected]
    with fixture.server.connect() as client:
        old_material = key_value(client, old_id)
    report.update(database_build=build, database_image_config_id=config_id,
                  backup_member=selected, initial_key_id=old_id)
    assert fixture.shell(primary, """(()=>{const c=db.getSiblingDB('qualification').records;
        c.createIndex({account:1},{name:'unique_account',unique:true});
        return c.insertMany(Array.from({length:32},(_,i)=>({_id:i,account:'account-'+i,
            balance:1000+i,phase:'before-rotation'})),
            {writeConcern:{w:'majority',j:true,wtimeout:15000}}).acknowledged;})()""") is True
    expected = fixture.snapshot(primary)
    assert len(expected['documents']) == 32 and len(expected['indexes']) == 2
    for member in range(3):
        fixture.eventually(lambda member=member: True if fixture.snapshot(member) == expected else None)
    passed('three authenticated TLS members retain 32 majority/journaled records, a unique index and distinct active KMIP keys before backup')

    old = fixture.hot_backup(selected, 'before-rotation')
    pre_vault = fixture.vault_backup('before-rotation-vault')
    passed('live createBackup from a secondary produces an immutable physical encrypted backup and a separate clean KMIP snapshot before rotation')

    fixture.stop(selected)
    rotation = command(fixture.base(selected)+['--rm', PERCONA]+fixture.flags(selected)+['--kmipRotateMasterKey'])
    (OUT/'rotation.log').write_text(rotation)
    fixture.start(selected)
    fixture.ready(selected)
    new_id = fixture.key_id(selected)
    assert new_id != old_id and key_state(fixture.server, new_id) == 2
    with fixture.server.connect() as client:
        assert key_value(client, old_id) == old_material
        new_material = key_value(client, new_id)
        assert new_material != old_material
    changes = fixture.shell(primary, """(()=>{const c=db.getSiblingDB('qualification').records;
        const w={writeConcern:{w:'majority',j:true,wtimeout:15000}};
        const updated=c.updateOne({_id:0},{$set:{balance:7777,phase:'after-rotation'}},w).modifiedCount;
        const deleted=c.deleteOne({_id:1},w).deletedCount;
        const inserted=c.insertOne({_id:100,account:'new-account',balance:42,phase:'after-rotation'},w).acknowledged;
        return {updated,deleted,inserted};})()""")
    assert changes == {'updated': 1, 'deleted': 1, 'inserted': True}
    expected_new = fixture.snapshot(primary)
    assert len(expected_new['documents']) == 32 and expected_new != expected
    fixture.eventually(lambda: True if fixture.snapshot(selected) == expected_new else None)
    new = fixture.hot_backup(selected, 'after-rotation')
    assert fixture.shell(primary, "db.getSiblingDB('qualification').records.insertOne({_id:200,account:'after-backup',balance:99},{writeConcern:{w:'majority',j:true,wtimeout:15000}}).acknowledged") is True
    for member in range(3):
        fixture.stop(member)
    post_vault = fixture.vault_backup('after-rotation-vault')
    fixture.server.stop()
    report['rotated_key_id'] = new_id
    report['backups'] = [{key: value for key, value in backup.items() if key not in ['directory', 'expected']}
                         for backup in [old, new]]
    report['vault_snapshot_sha256'] = {'before_rotation': sha(pre_vault), 'after_rotation': sha(post_vault)}
    passed('secondary master-key rotation retains the original key; a second live backup captures acknowledged insert/update/delete state and excludes a later acknowledged insert')

    report['restore_lanes'] = []
    fixture.switch_vault(pre_vault, 'pre')
    assert key_state(fixture.server, old_id) == 2
    report['restore_lanes'].append(fixture.restore(old, 'old-with-original-vault', old_id, True))
    passed('pre-rotation physical backup cold-restores with its original KMIP snapshot, exact 32 records/indexes, valid collections and retained database authentication/TLS')
    # A stale vault genuinely lacks the new key: verify this before observing
    # the database failure so a transport problem cannot earn negative credit.
    with fixture.server.connect() as client:
        response = exchange(client, request(10, [uid(new_id)]))
        from wire import status, reason
        assert status(response) == 1 and reason(response) == 1
    report['restore_lanes'].append(fixture.restore(new, 'new-with-stale-vault', new_id, False))
    passed('post-rotation physical backup cannot cold-start with a stale KMIP snapshot that lacks its new key; explicit missing-key database failure is retained')

    fixture.switch_vault(post_vault, 'post')
    with fixture.server.connect() as client:
        assert key_value(client, old_id) == old_material and key_value(client, new_id) == new_material
    report['restore_lanes'].append(fixture.restore(old, 'old-with-retained-key', old_id, True))
    report['restore_lanes'].append(fixture.restore(new, 'new-with-current-key', new_id, True))
    passed('post-rotation KMIP snapshot restores both backup generations in separate standalone directories with exact key IDs/bytes, backup-boundary data/indexes and no source initial sync')

    with fixture.server.connect() as client:
        payload(exchange(client, request(19, [uid(old_id), structure(0x420081, enumeration(0x420082, 2))])))
    assert key_state(fixture.server, old_id) == 4 and key_state(fixture.server, new_id) == 2
    report['restore_lanes'].append(fixture.restore(old, 'old-with-compromised-key', old_id, False))
    report['restore_lanes'].append(fixture.restore(new, 'new-after-old-compromise', new_id, True))
    passed('compromising the retained historical key prevents old-backup cold-start while the new-key backup still recovers exactly; no key state is reset to obtain a pass')


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--engine', default='podman', choices=['podman', 'docker'])
    parser.add_argument('--image', required=True)
    args = parser.parse_args()
    OUT.mkdir(parents=True, exist_ok=True)
    # Shared fixture helpers write logs to their module-level artifact directory;
    # redirect only this process so earlier checkpoint logs remain unchanged.
    test_database.ART = OUT
    test_database_replicaset.OUT = OUT
    evidence = packaged_evidence(local_image_id(args.engine, args.image))
    report = dict(status='running', **evidence, server_image=args.image, database_image=PERCONA, members=3, passed=[],
        limits='Single-host disposable replica set and isolated standalone physical restores; quiescent backup-boundary application writes. No cluster-wide coordinated backup, concurrent-write snapshot stress, PBM, PITR/oplog replay, remote retention/encryption, independent failure domains, capacity or RPO/RTO qualification. No physical-backup plaintext scan or independent encryption audit.')
    path = OUT/'image.json'
    path.write_text(json.dumps(report, indent=2)+'\n')
    try:
        with tempfile.TemporaryDirectory(prefix='keytend-percona-backup-') as directory:
            fixture = BackupSet(directory, args.engine, args.image)
            try:
                run(fixture, report)
            finally:
                fixture.cleanup()
        report['status'] = 'passed'
    except BaseException as error:
        report.update(status='failed', error_type=type(error).__name__)
        if isinstance(error, subprocess.CalledProcessError):
            report.update(command=error.cmd, command_output=error.output)
        else:
            report['error'] = str(error)
        raise
    finally:
        report['log_sha256'] = {str(p.relative_to(ROOT)): sha(p) for p in OUT.glob('*.log')}
        path.write_text(json.dumps(report, indent=2)+'\n')
    print('PASS physical Percona backup recovery:', len(report['passed']), 'checks;',
          len(report['restore_lanes']), 'isolated cold-start lanes')


if __name__ == '__main__':
    main()
