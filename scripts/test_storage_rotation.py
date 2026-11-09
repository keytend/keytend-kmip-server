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

"""Storage key rotation and recovery using actual native/container commands.
The independent wire helper is a transport test, not another qualified SDK.
"""
import argparse, hashlib, json, os, pathlib, shutil, sqlite3, subprocess, tempfile
from image_evidence import source_commit, local_image_id, packaged_evidence
from test_runtime import ROOT, Server
from test_database import ContainerServer
from wire import *

class DraftContainer(ContainerServer):
    def base(self): return super().base()+['-e','KMIP_EXPERIMENTAL_V3=true']

def cli(server, operation, timeout=30, **paths):
    args=[operation]
    for name,path in paths.items():
        value=str(path) if not hasattr(server,'image') else '/work/'+str(pathlib.Path(path).relative_to(server.root))
        args+=['--'+name.replace('_','-'), value]
    if hasattr(server,'image'):
        prefix=[server.engine,'run','--rm']+(['--userns','keep-id:uid=10001,gid=10001'] if server.engine=='podman' else ['--user',f'{os.getuid()}:{os.getgid()}'])
        prefix+=['--read-only','--tmpfs','/tmp:rw,nosuid,nodev,noexec,size=64m,mode=1777','--cap-drop=all','--security-opt=no-new-privileges','-v',f'{server.root}:/work',server.image]
    else: prefix=[server.binary]
    return subprocess.run(prefix+args,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,timeout=timeout)

def rotate_container(server):
    """Stopped disposable database fixture: rotate with the tested image command."""
    new_key=server.root/'next-master.key'
    cli(server,'generate-master-key',output=new_key).check_returncode()
    new_data=server.root/'rotated-data';new_data.mkdir(mode=0o700)
    result=cli(server,'rotate-master-key',database=server.data/'kmip.sqlite',master_key=server.pki/'master.key',new_master_key=new_key,output=new_data/'kmip.sqlite')
    result.check_returncode()
    cli(server,'check-store',database=new_data/'kmip.sqlite',master_key=new_key).check_returncode()
    assert cli(server,'check-store',database=new_data/'kmip.sqlite',master_key=server.pki/'master.key').returncode!=0
    shutil.copyfile(server.pki/'master.key',server.root/'previous-master.key')
    shutil.copyfile(new_key,server.pki/'master.key');shutil.copyfile(new_key,server.tls/'master.key')
    server.data=new_data

def material_records(server,records):
    checked=0
    with server.connect() as c:
        for row in records:
            v=tuple(row['version']);assert key_value(c,row['id'],v)==row['material']
            if row['active']:
                cp=structure(0x42002b,enumeration(0x420011,2),enumeration(0x42005f,1))
                ciphertext=get(payload(exchange(c,request(31,[uid(row['id'],v),cp,binary(0x4200c2,b'0123456789abcdef')],v))),0x4200c2)[2]
                plaintext=get(payload(exchange(c,request(32,[uid(row['id'],v),cp,binary(0x4200c2,ciphertext)],v))),0x4200c2)[2]
                assert plaintext==b'0123456789abcdef'
            checked+=1
    return checked

def run(server):
    phases=[];records=[]
    server.start()
    try:
        with server.connect() as c:
            for v in [(1,1),(1,2),(1,3),(1,4),(2,0),(2,1),(3,0)]:
                identifier=create_key(c,v);material=key_value(c,identifier,v)
                payload(exchange(c,request(18,[uid(identifier,v)],v)))
                records.append(dict(id=identifier,version=v,material=material,active=v>=(1,2)))
        phases.append(dict(phase='before_rotation',keys=material_records(server,records)))
    finally:server.stop()
    source=server.data/'kmip.sqlite';old_key=server.pki/'master.key';next_key=server.root/'next-master.key'
    original=(server.root/'original-master.key');shutil.copyfile(old_key,original);original.chmod(0o600)
    old_backup=server.root/'old-backup.sqlite';cli(server,'backup',database=source,master_key=old_key,output=old_backup).check_returncode()
    cli(server,'generate-master-key',output=next_key).check_returncode()
    for bad in [original]:
        output=server.root/'refused.sqlite'
        assert cli(server,'rotate-master-key',database=source,master_key=old_key,new_master_key=bad,output=output).returncode!=0
        assert not output.exists()
    new_data=server.root/'rotated';new_data.mkdir(mode=0o700);rotated=new_data/'kmip.sqlite'
    before=sqlite3.connect(source)
    old_ciphertexts=[r[0] for r in before.execute('select sealed from objects order by rowid')];before.close()
    cli(server,'rotate-master-key',database=source,master_key=old_key,new_master_key=next_key,output=rotated).check_returncode()
    # No-overwrite failure cannot damage a completed candidate.
    digest=hashlib.sha256(rotated.read_bytes()).hexdigest()
    assert cli(server,'rotate-master-key',database=source,master_key=old_key,new_master_key=next_key,output=rotated).returncode!=0
    assert hashlib.sha256(rotated.read_bytes()).hexdigest()==digest
    cli(server,'check-store',database=rotated,master_key=next_key).check_returncode()
    assert cli(server,'check-store',database=rotated,master_key=original).returncode!=0
    assert cli(server,'check-store',database=source,master_key=next_key).returncode!=0
    cli(server,'check-store',database=source,master_key=original).check_returncode()
    raw=rotated.read_bytes()
    assert all(value not in raw for value in old_ciphertexts+[r['material'] for r in records])
    server.data=new_data;shutil.copyfile(next_key,old_key)
    if hasattr(server,'image'):shutil.copyfile(next_key,server.tls/'master.key')
    server.start()
    try:phases.append(dict(phase='rotated_restart',keys=material_records(server,records)))
    finally:server.stop()
    backup=server.root/'new-backup.sqlite';cli(server,'backup',database=rotated,master_key=next_key,output=backup).check_returncode()
    restore=server.root/'restore';restore.mkdir(mode=0o700);shutil.copyfile(backup,restore/'kmip.sqlite');(restore/'kmip.sqlite').chmod(0o600);server.data=restore
    server.start()
    try:phases.append(dict(phase='new_backup_restore',keys=material_records(server,records)))
    finally:server.stop()
    legacy=server.root/'legacy';legacy.mkdir(mode=0o700);shutil.copyfile(old_backup,legacy/'kmip.sqlite');(legacy/'kmip.sqlite').chmod(0o600);server.data=legacy
    shutil.copyfile(original,old_key)
    if hasattr(server,'image'):shutil.copyfile(original,server.tls/'master.key')
    server.start()
    try:phases.append(dict(phase='old_backup_restore',keys=material_records(server,records)))
    finally:server.stop()
    return phases

def main():
    p=argparse.ArgumentParser();p.add_argument('--image');p.add_argument('--engine',default='podman');a=p.parse_args()
    evidence=packaged_evidence(local_image_id(a.engine,a.image)) if a.image else {'runtime_binary_sha256':hashlib.sha256((ROOT/'target/debug/keytend-kmip-server').read_bytes()).hexdigest(),'source_commit':source_commit()[0]}
    out=ROOT/'artifacts/storage-rotation';out.mkdir(parents=True,exist_ok=True)
    report=dict(status='running',**evidence)
    path=out/('image.json' if a.image else 'native.json');path.write_text(json.dumps(report,indent=2)+'\n')
    try:
        with tempfile.TemporaryDirectory(prefix='keytend-storage-rotation-') as d:
            server=DraftContainer(d,a.engine,a.image) if a.image else Server(d,draft=True)
            try:report['phases']=run(server)
            finally:server.stop()
        report['status']='passed'
    except BaseException as e:report['status']='failed';report['error']=str(e);raise
    finally:path.write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps(report['phases']))
if __name__=='__main__':main()
