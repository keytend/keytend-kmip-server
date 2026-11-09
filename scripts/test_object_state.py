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

"""Independent audit/index validation and selective-replay CLI checks.
Subset evidence only: no full-store rollback prevention or production approval.
"""
import argparse, hashlib, hmac, json, pathlib, shutil, sqlite3, tempfile
from image_evidence import ROOT, source_commit, local_image_id, packaged_evidence
from test_runtime import Server
from test_storage_rotation import DraftContainer, cli
from wire import *


def encoded(value):
    return json.dumps(value, ensure_ascii=False, separators=(',', ':')).encode()


def verify_format(database, master):
    """Recompute the tree and audit MACs without calling the Rust verifier."""
    with sqlite3.connect(database) as db:
        assert db.execute('pragma user_version').fetchone()[0] == 18
        nodes = {identifier: (raw, json.loads(raw)) for identifier, raw in db.execute('select id,node from object_state')}
        objects = {identifier: (owner, rowid, sealed) for identifier, owner, rowid, sealed in db.execute('select id,owner,rowid,sealed from objects')}
        children = {ref['id'] for _, node in nodes.values() for ref in [node['left'], node['right']] if ref['id'] is not None}
        roots = set(nodes) - children
        empty = dict(id=None, hash=[0]*32, height=0, count=0)
        seen = set()
        def visit(identifier, lower=None, upper=None):
            if identifier is None:
                return empty
            assert identifier not in seen
            seen.add(identifier)
            raw, node = nodes[identifier]
            assert node['id'] == identifier and (lower is None or lower < identifier) and (upper is None or identifier < upper)
            left = visit(node['left']['id'], lower, identifier)
            right = visit(node['right']['id'], identifier, upper)
            assert node['left'] == left and node['right'] == right
            assert abs(left['height'] - right['height']) <= 1
            owner, rowid, sealed = objects[identifier]
            assert (node['owner'], node['rowid'], bytes(node['value_hash'])) == (owner, rowid, hashlib.sha256(sealed).digest())
            assert raw == encoded(node)
            return dict(id=identifier, hash=list(hashlib.sha256(b'keytend-kmip-server object state node v1\0'+raw).digest()), height=1+max(left['height'],right['height']), count=1+left['count']+right['count'])
        assert len(roots) == (1 if nodes else 0)
        root = visit(next(iter(roots))) if nodes else empty
        assert seen == set(nodes) == set(objects)
        commitment = hashlib.sha256(b'keytend-kmip-server object state commitment v1\0'+encoded(root)).digest()
        previous = bytes(32)
        rows = db.execute('select seq,timestamp,principal,operation,object_id,status,previous,mac,state_root from audit order by seq').fetchall()
        for expected_sequence, row in enumerate(rows, 1):
            seq, time, principal, operation, identifier, status_code, prev, mac, state = row
            assert seq == expected_sequence and prev == previous
            fields = [seq,time,principal,operation,identifier,status_code,prev.hex()]
            domain, body = (b'keytend-kmip-server audit v1\0', fields) if state is None else (b'keytend-kmip-server audit v2\0', [fields,state.hex()])
            assert hmac.compare_digest(mac,hmac.new(master.read_bytes(),domain+encoded(body),'sha256').digest())
            previous = mac
        assert rows and rows[-1][-1] == commitment
        return dict(objects=len(objects), audit_entries=len(rows))


def copy_store(source, destination):
    shutil.copyfile(source, destination)
    destination.chmod(0o600)


def run(server):
    checks=[]
    server.start()
    try:
        with server.connect() as client:
            identifier=create_key(client,(2,1))
            assert len(key_value(client,identifier,(2,1))) == 32
        database=server.data/'kmip.sqlite'
        old=server.root/'before.sqlite'
        cli(server,'backup',database=database,master_key=server.pki/'master.key',output=old).check_returncode()
        with server.connect() as client:
            for op, extra in [(18,[]),(19,[structure(0x420081,enumeration(0x420082,1))]),(20,[])]:
                payload(exchange(client,request(op,[uid(identifier),*extra],(2,1))))
    finally:
        server.stop()
    master=server.pki/'master.key'
    verify_format(database,master)
    checks.append('Independent Python SHA256 AVL index and v2 HMAC audit validation matches current object ciphertext inventory')
    with sqlite3.connect(old) as db:
        old_record=db.execute('select sealed from objects where id=?',(identifier,)).fetchone()[0]
        old_root=db.execute("select value from meta where name='object-state-root'").fetchone()[0]
        old_nodes=db.execute('select id,node from object_state').fetchall()
    for label, mutation in [
        ('old_ciphertext','update objects set sealed=? where id=?'),
        ('deleted_record','delete from objects where id=?'),
        ('owner_substitution',"update objects set owner='other' where id=?"),
        ('rowid_substitution','update objects set rowid=rowid+100 where id=?'),
        ('missing_index','delete from object_state where id=?'),
        ('changed_index',"update object_state set node=x'7b7d' where id=?"),
        ('old_root_and_tree',None),
    ]:
        candidate=server.root/(label+'.sqlite');copy_store(database,candidate)
        with sqlite3.connect(candidate) as db:
            if label == 'old_root_and_tree':
                db.execute('update objects set sealed=? where id=?',(old_record,identifier))
                db.execute('delete from object_state');db.executemany('insert into object_state values(?,?)',old_nodes)
                db.execute("update meta set value=? where name='object-state-root'",(old_root,))
            else:
                db.execute(mutation,(old_record,identifier) if label=='old_ciphertext' else (identifier,))
        assert cli(server,'check-store',database=candidate,master_key=master).returncode != 0,label
        backup=server.root/(label+'-backup.sqlite')
        assert cli(server,'backup',database=candidate,master_key=master,output=backup).returncode != 0 and not backup.exists(),label
        floor=server.root/(label+'-floor.json')
        assert cli(server,'audit-checkpoint',database=candidate,master_key=master,output=floor).returncode != 0 and not floor.exists(),label
        checks.append(label+': current history retained; integrity, backup and checkpoint export fail closed')
    # A legacy encoder uses the pre-upgrade snapshot, removes state metadata,
    # and independently rebuilds its genuine v1 audit chain under schema 17.
    legacy=server.root/'schema17.sqlite';copy_store(old,legacy)
    with sqlite3.connect(legacy) as db:
        rows=db.execute('select seq,timestamp,principal,operation,object_id,status from audit order by seq').fetchall()
        db.execute('drop table audit')
        db.execute('create table audit(seq integer primary key,timestamp integer not null,principal text not null,operation integer not null,object_id text,status integer not null,previous blob not null,mac blob not null)')
        previous=bytes(32)
        for row in rows:
            mac=hmac.new(master.read_bytes(),b'keytend-kmip-server audit v1\0'+encoded([*row,previous.hex()]),'sha256').digest()
            db.execute('insert into audit values(?,?,?,?,?,?,?,?)',(*row,previous,mac));previous=mac
        db.execute('drop table object_state');db.execute("delete from meta where name='object-state-root'");db.execute('pragma user_version=17')
    unchanged=legacy.read_bytes()
    checked=cli(server,'check-store',database=legacy,master_key=master);checked.check_returncode()
    assert 'Storage schema 17 is older' in checked.stdout,checked.stdout
    assert legacy.read_bytes()==unchanged,'check-store changed the schema-17 store'
    checks.append('Read-only check-store verifies the schema-17/v1 fixture without changing or upgrading it')
    # The server upgrades it when it first opens it.
    for suffix in ['','-wal','-shm']:
        pathlib.Path(str(database)+suffix).unlink(missing_ok=True)
    copy_store(legacy,database)
    server.start();server.stop()
    verify_format(database,master)
    with sqlite3.connect(database) as db:
        assert db.execute('select mac from audit where seq=?',(len(rows),)).fetchone()[0]==previous
        assert db.execute('select principal from audit order by seq desc limit 1').fetchone()[0]=='keytend-kmip-server/storage-migration'
    checks.append('Independent schema-17/v1 fixture migrates atomically, preserves old MAC bytes and commits existing state with v2')
    return checks


def main():
    parser=argparse.ArgumentParser();parser.add_argument('--image');parser.add_argument('--engine',default='podman');args=parser.parse_args()
    evidence=packaged_evidence(local_image_id(args.engine,args.image)) if args.image else {'runtime_binary_sha256':hashlib.sha256((ROOT/'target/debug/keytend-kmip-server').read_bytes()).hexdigest(),'source_commit':source_commit()[0]}
    out=ROOT/'artifacts/object-state';out.mkdir(parents=True,exist_ok=True)
    report=dict(status='running',**evidence)
    path=out/('image.json' if args.image else 'native.json');path.write_text(json.dumps(report,indent=2)+'\n')
    try:
        with tempfile.TemporaryDirectory(prefix='keytend-object-state-') as directory:
            server=DraftContainer(directory,args.engine,args.image) if args.image else Server(directory,draft=True)
            try:report['checks']=run(server)
            finally:server.stop()
        report['status']='passed'
    except BaseException as error:
        report['status']='failed';report['error']=str(error);raise
    finally:path.write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps(report['checks']))

if __name__=='__main__':main()
