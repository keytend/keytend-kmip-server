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

"""Audit floor export, independent HMAC, startup denial and storage-key transition."""
import argparse, hashlib, hmac, json, os, pathlib, shutil, sqlite3, tempfile
from image_evidence import source_commit, local_image_id, packaged_evidence, native_sha256
from test_runtime import ROOT, Server
from test_database import ContainerServer
from test_storage_rotation import cli
from wire import *

def independent_checkpoint(server, path, database, master):
    data=json.loads(path.read_text())
    body=json.dumps([data['version'],data['store_id'],data['sequence'],data['head_mac']],separators=(',',':')).encode()
    expected=hmac.new(master.read_bytes(),b'keytend-kmip-server external audit checkpoint v1\0'+body,'sha256').hexdigest()
    assert hmac.compare_digest(data['authentication'],expected)
    with sqlite3.connect(database) as c:
        assert data['store_id']==hashlib.sha256(c.execute("select value from meta where name='key-check'").fetchone()[0]).hexdigest()
        row=c.execute('select seq,mac from audit order by seq desc limit 1').fetchone()
        assert (data['sequence'],data['head_mac'])==((row[0],row[1].hex()) if row else (0,'00'*32))
    return data

def rejected_start(server,database,master,checkpoint):
    result=cli(server,'serve',timeout=10,database=database,master_key=master,audit_checkpoint=checkpoint,
               cert=server.pki/'server.pem',key=server.pki/'server.key',ca=server.pki/'ca.pem',policy=server.pki/'policy.json')
    assert result.returncode!=0 and 'checkpoint' in result.stderr.lower(),result.stderr

class AnchoredServer(Server):
    checkpoint=None
    def start(self):
        previous=os.environ.get('KMIP_AUDIT_CHECKPOINT')
        try:
            if self.checkpoint:os.environ['KMIP_AUDIT_CHECKPOINT']=str(self.checkpoint)
            super().start()
        finally:
            if previous is None:os.environ.pop('KMIP_AUDIT_CHECKPOINT',None)
            else:os.environ['KMIP_AUDIT_CHECKPOINT']=previous

class AnchoredContainer(ContainerServer):
    checkpoint=None
    def base(self):
        args=super().base()
        if self.checkpoint:args+=['-v',f'{self.checkpoint.parent}:/checkpoint:ro','-e','KMIP_AUDIT_CHECKPOINT=/checkpoint/'+self.checkpoint.name]
        return args

def run(server):
    checks=[];server.start()
    try:
        with server.connect() as c:identifier=create_key(c,(2,1));material=key_value(c,identifier,(2,1))
    finally:server.stop()
    original=server.data/'kmip.sqlite';master=server.pki/'master.key';old=server.root/'old.sqlite'
    cli(server,'backup',database=original,master_key=master,output=old).check_returncode()
    checkpoints=server.root/'checkpoints';checkpoints.mkdir(mode=0o700);first=checkpoints/'first.json'
    cli(server,'audit-checkpoint',database=original,master_key=master,output=first).check_returncode()
    independent_checkpoint(server,first,original,master);server.checkpoint=first
    server.start()
    try:
        with server.connect() as c:
            assert key_value(c,identifier,(2,1))==material
            second=create_key(c,(2,1));second_material=key_value(c,second,(2,1))
            # Retain a same-state audit prefix: Get may update retrieval metadata.
            # Removing only the last Query must isolate the external floor check.
            for _ in range(2):payload(exchange(c,request(24,[enumeration(0x420074,1)],(2,1))))
        latest=checkpoints/'latest.json'
        cli(server,'audit-checkpoint',database=original,master_key=master,output=latest,previous=first).check_returncode()
        floor=independent_checkpoint(server,latest,original,master)
    finally:server.stop()
    checks.append('native/container CLI exports match independent Python HMAC, store identity and audit head; guarded service accepts current history and forward progress')
    cli(server,'check-store',database=old,master_key=master).check_returncode()
    assert cli(server,'check-store',database=old,master_key=master,audit_checkpoint=latest).returncode!=0
    rejected_start(server,old,master,latest)
    lower=checkpoints/'must-not-exist.json'
    assert cli(server,'audit-checkpoint',database=old,master_key=master,output=lower,previous=latest).returncode!=0 and not lower.exists()
    next_key=server.root/'next.key';cli(server,'generate-master-key',output=next_key).check_returncode()
    rotated=server.root/'refused.sqlite'
    assert cli(server,'rotate-master-key',database=old,master_key=master,new_master_key=next_key,output=rotated,audit_checkpoint=latest).returncode!=0 and not rotated.exists()
    checks.append('valid old snapshot is refused at startup/check-store; previous-floor export and rotation cannot lower or reauthenticate it')
    copy=server.root/'truncated.sqlite';cli(server,'backup',database=original,master_key=master,output=copy).check_returncode()
    with sqlite3.connect(copy) as c:c.execute('delete from audit where seq>=?',(floor['sequence'],))
    cli(server,'check-store',database=copy,master_key=master).check_returncode();rejected_start(server,copy,master,latest)
    bad=checkpoints/'bad.json';value=json.loads(latest.read_text());value['sequence']=0;bad.write_text(json.dumps(value));rejected_start(server,original,master,bad)
    rejected_start(server,original,master,checkpoints/'missing.json')
    missing=server.root/'missing.sqlite';rejected_start(server,missing,master,latest);assert not missing.exists()
    checks.append('startup refuses valid-prefix truncation, modified/missing floor and missing database before serving requests')
    rotated_dir=server.root/'rotated';rotated_dir.mkdir(mode=0o700);rotated=rotated_dir/'kmip.sqlite'
    cli(server,'rotate-master-key',database=original,master_key=master,new_master_key=next_key,output=rotated,audit_checkpoint=latest).check_returncode()
    rejected_start(server,rotated,next_key,latest)
    new_floor=checkpoints/'new-generation.json';cli(server,'audit-checkpoint',database=rotated,master_key=next_key,output=new_floor).check_returncode()
    independent_checkpoint(server,new_floor,rotated,next_key)
    server.data=rotated_dir;server.checkpoint=new_floor;shutil.copyfile(next_key,master)
    if hasattr(server,'image'):shutil.copyfile(next_key,server.tls/'master.key')
    for _ in range(2):
        server.start()
        try:
            with server.connect() as c:
                assert key_value(c,identifier,(2,1))==material and key_value(c,second,(2,1))==second_material
        finally:server.stop()
    checks.append('checked rotation requires an explicit newly authenticated floor; matched snapshot/key/floor survives two guarded restarts with exact keys')
    return checks

def main():
    parser=argparse.ArgumentParser();parser.add_argument('--image');parser.add_argument('--engine',default='podman');a=parser.parse_args()
    binary=native_sha256(a.image)
    evidence=packaged_evidence(local_image_id(a.engine,a.image)) if a.image else {'runtime_binary_sha256':binary,'source_commit':source_commit()[0]}
    out=ROOT/'artifacts/audit-checkpoint';out.mkdir(exist_ok=True);path=out/('image.json' if a.image else 'native.json')
    report=dict(status='running',**evidence)
    path.write_text(json.dumps(report,indent=2)+'\n')
    try:
        with tempfile.TemporaryDirectory(prefix='keytend-audit-floor-') as d:
            server=AnchoredContainer(d,a.engine,a.image) if a.image else AnchoredServer(d)
            try:report['checks']=run(server)
            finally:server.stop()
        report['status']='passed'
    except BaseException as error:
        report['status']='failed';report['error']=str(error)
        if hasattr(error,'output'):report['command_output']=str(error.output)
        raise
    finally:path.write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps(report['checks']))
if __name__=='__main__':main()
