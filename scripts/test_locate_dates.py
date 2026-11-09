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

"""Independent date-predicate oracle over real mTLS and durable recovery.
The Python transport is an independent test encoder, not a production client SDK.
"""
import argparse, hashlib, json, pathlib, random, shutil, tempfile, time
from image_evidence import ROOT, source_commit, local_image_id, packaged_evidence
from test_runtime import Server
from test_storage_rotation import DraftContainer, cli
from wire import *

NAMES={0x420001:'Activation Date',0x42002f:'Deactivation Date',0x420020:'Compromise Date',0x420039:'Initial Date',0x420028:'Cryptographic Algorithm',0x42002a:'Cryptographic Length',0x42002c:'Cryptographic Usage Mask',0x420056:'Object Group'}
MAX=2**63-1
VERSIONS=[(1,1),(1,2),(1,3),(1,4),(2,0),(2,1),(3,0)]


def sha(path):return hashlib.sha256(pathlib.Path(path).read_bytes()).hexdigest()


def fields(version, values, create=False):
    if version[0]>=2:return [structure(0x420125,*values)]
    attributes=[structure(0x420008,text(0x42000a,NAMES[n[0]]),node(0x42000b,n[1],n[2])) for n in values]
    return [structure(0x420091,*attributes)] if create else attributes


def query(client,version,group,predicates,mask=1,identity=None):
    values=[text(0x420056,group)]+[node(tag,9,value) for tag,value in predicates]
    result=payload(exchange(client,request(8,fields(version,values)+[integer(0x42008e,mask)],version)))
    return [n[2] for n in children(result,0x420094)]


def expected(rows,predicates,mask=1,version=(2,1)):
    groups={}
    for tag,value in predicates:groups.setdefault(tag,[]).append(value)
    result=[]
    for row in reversed(rows):
        eligible=bool(mask & (2 if row.get('archived') else 1))
        if not eligible:continue
        if all((values[0]==row.get(tag,MAX) if len(values)==1 else min(values)<=row.get(tag,MAX)<=max(values)) for tag,values in groups.items()):result.append(row['id'])
    return result


def run(server):
    rng=random.Random(0x44415445);future=int(time.time())+1_000_000
    lanes=[];saved=[];checks=0
    server.start()
    try:
        with server.connect() as client:
            for version in VERSIONS:
                group='date-oracle-'+str(version);rows=[]
                for index in range(12):
                    row={}
                    if index%4:row[0x420001]=future+100*(index%5)
                    if index%3:row[0x42002f]=future+1000+100*(index%5)
                    values=[enumeration(0x420028,3),integer(0x42002a,256),integer(0x42002c,12),text(0x420056,group)]+[node(tag,9,value) for tag,value in row.items()]
                    row['id']=get(payload(exchange(client,request(1,[enumeration(0x420057,2),*fields(version,values,True)],version))),0x420094)[2];rows.append(row)
                predicates=[[(0x420001,MAX)],[(0x420001,future+100)],[(0x420001,future),(0x420001,future+400)],[(0x420001,MAX),(0x420001,future+400)],[(0x420001,-2**63),(0x420001,MAX)],[(0x420020,MAX)]]
                for _ in range(24):
                    low,high=sorted(rng.sample(range(-1,7),2))
                    p=[(0x420001,future+low*100),(0x420001,MAX if high==6 else future+high*100)]
                    if rng.randrange(2):p.reverse()
                    if rng.randrange(2):p += [(0x42002f,future+1200),(0x42002f,MAX)]
                    predicates.append(p)
                for p in predicates:
                    assert query(client,version,group,p)==expected(rows,p,version=version),(version,p)
                    checks+=1
                # Archived storage remains a separate eligibility condition.
                payload(exchange(client,request(21,[uid(rows[-1]['id'],version)],version)));rows[-1]['archived']=True
                for mask in [1,2,3]:
                    p=[(0x420001,-2**63),(0x420001,MAX)]
                    assert query(client,version,group,p,mask)==expected(rows,p,mask,version);checks+=1
                with server.connect(identity='other') as foreign:
                    assert query(foreign,version,group,[(0x420001,MAX)])==[];checks+=1
                for values in [[node(0x420001,3,1)],[node(0x420001,9,future)]*3]:
                    result=exchange(client,request(8,fields(version,values),version));assert status(result)==1 and reason(result)==7;checks+=1
                lanes.append(dict(version=list(version),queries=36,objects=12))
                saved.append((version,group,rows))
        backup=server.root/'backup.sqlite';cli(server,'backup',database=server.data/'kmip.sqlite',master_key=server.pki/'master.key',output=backup).check_returncode()
    finally:server.stop()
    for phase in ['restart','clean_backup_restore']:
        if phase=='clean_backup_restore':
            restored=server.root/'restored';restored.mkdir(mode=0o700);shutil.copyfile(backup,restored/'kmip.sqlite');(restored/'kmip.sqlite').chmod(0o600);server.data=restored
        server.start()
        try:
            with server.connect() as client:
                for version,group,rows in saved:
                    for p in [[(0x420001,MAX)],[(0x420001,future),(0x420001,future+400)]]:
                        assert query(client,version,group,p)==expected(rows,p,version=version);checks+=1
            lanes.append(dict(phase=phase,queries=14))
        finally:server.stop()
    cli(server,'check-store',database=server.data/'kmip.sqlite',master_key=server.pki/'master.key').check_returncode()
    return dict(lanes=lanes,queries_verified=checks,encrypted_backup_sha256=sha(backup))


def main():
    p=argparse.ArgumentParser();p.add_argument('--image');p.add_argument('--engine',default='podman');a=p.parse_args()
    binary=sha(ROOT/'target/debug/keytend-kmip-server');config=local_image_id(a.engine,a.image) if a.image else None
    evidence=packaged_evidence(config) if config else {'runtime_binary_sha256':binary,'source_commit':source_commit()[0]}
    out=ROOT/'artifacts/locate-dates';out.mkdir(parents=True,exist_ok=True);path=out/('image.json' if a.image else 'native.json')
    report=dict(status='running',**evidence)
    path.write_text(json.dumps(report,indent=2)+'\n')
    try:
        with tempfile.TemporaryDirectory(prefix='keytend-locate-date-') as directory:
            server=DraftContainer(directory,a.engine,a.image) if a.image else Server(directory,draft=True)
            try:report.update(run(server))
            finally:
                server.stop()
                log=pathlib.Path(directory)/'server.log'
                if log.exists():
                    saved=out/(path.stem+'-server.log');shutil.copyfile(log,saved);report['log_sha256']={str(saved.relative_to(ROOT)):sha(saved)}
        report['status']='passed'
    except BaseException as error:report.update(status='failed',error=str(error));raise
    finally:path.write_text(json.dumps(report,indent=2)+'\n')
    print('PASS Locate dates',path.stem,report['queries_verified'],'independent query comparisons including recovery')

if __name__=='__main__':main()
