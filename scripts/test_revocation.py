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

"""Versioned Revoke over real mTLS, including restart and encrypted backup restore.
This independent wire harness is not another production SDK.
"""
import argparse, hashlib, json, pathlib, shutil, subprocess, tempfile, time
from image_evidence import source_commit, local_image_id, packaged_evidence
from test_runtime import ROOT, Server
from test_database import ContainerServer
from wire import *

VERSIONS=[(1,1),(1,2),(1,3),(1,4),(2,0),(2,1),(3,0)]
class DraftContainer(ContainerServer):
    def base(self):return super().base()+['-e','KMIP_EXPERIMENTAL_V3=true']
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def attrs(s,key,v):
    p=payload(exchange(s,request(11,[uid(key,v)],v)))
    if v[0]>=2:return {n[0]:n for n in get(p,0x420125)[2]}
    names={'State':0x42008d,'Initial Date':0x420039,'Compromise Date':0x420020,'Compromise Occurrence Date':0x420021}
    return {names[get(n,0x42000a)[2]]:get(n,0x42000b) for n in children(p,0x420008) if get(n,0x42000a)[2] in names}
def reason_node(code):return structure(0x420081,enumeration(0x420082,code))
def run(server,records):
    observations=0
    with server.connect() as s:
        for v in VERSIONS:
            for code in (range(8) if v[0]>=3 else range(1,8)):
                key=create_key(s,v);initial=attrs(s,key,v)[0x420039][2];fields=[uid(key,v)]
                compromised=v[0]>=3 or code==2 or (code==3 and v>=(1,3))
                # Non-compromise Revoke uses only the Active -> Deactivated
                # edge. Through 1.2 CA Compromise follows this legacy path.
                if not compromised:payload(exchange(s,request(18,[uid(key,v)],v)))
                if code:fields.append(reason_node(code))
                if v[0]<3 and compromised:fields.append(node(0x420021,9,initial-60))
                payload(exchange(s,request(19,fields,v)));observations+=1
                a=attrs(s,key,v);expected=4 if compromised else 3
                assert a[0x42008d][2]==expected
                if expected==4:
                    assert a[0x420020][1]==9
                    assert a[0x420021][2]==(initial if v[0]>=3 else initial-60)
                records.append(dict(version=v,key=key,state=expected))
            # Missing reason remains invalid in final editions, with no mutation.
            if v[0]<3:
                key=create_key(s,v)
                assert status(exchange(s,request(19,[uid(key,v)],v)))!=0
                assert attrs(s,key,v)[0x42008d][2]==1;observations+=1
                records.append(dict(version=v,key=key,state=1))
            if v in [(1,1),(1,2)]:
                key=create_key(s,v);before=attrs(s,key,v)
                assert status(exchange(s,request(19,[uid(key,v),reason_node(2)],v)))!=0
                assert attrs(s,key,v)==before;observations+=1
                payload(exchange(s,request(19,[uid(key,v),reason_node(2),node(0x420021,9,before[0x420039][2])],v)))
                assert attrs(s,key,v)[0x42008d][2]==4;observations+=1
                records.append(dict(version=v,key=key,state=4))
            if v >= (1,3):
                key=create_key(s,v);initial_date=attrs(s,key,v)[0x420039][2]
                payload(exchange(s,request(19,[uid(key,v),reason_node(2)],v)))
                assert attrs(s,key,v)[0x420021][2]==initial_date;observations+=1
                records.append(dict(version=v,key=key,state=4))
            key=create_key(s,v)
            # Failed fields leave both state and metadata untouched.
            before=attrs(s,key,v)
            for extra in [[reason_node(8)],[reason_node(2),node(0x420021,9,int(time.time())+3600)],[reason_node(2),integer(0x420021,1)]]:
                assert status(exchange(s,request(19,[uid(key,v)]+extra,v)))!=0
                assert attrs(s,key,v)==before;observations+=1
            # Only the draft permits an occurrence for Unspecified.
            # Activate final-edition objects so a refusal tests the occurrence
            # rule rather than being masked by an invalid lifecycle edge.
            if v[0]<3:payload(exchange(s,request(18,[uid(key,v)],v)))
            fields=[uid(key,v),reason_node(1),node(0x420021,9,before[0x420039][2]-10)]
            r=exchange(s,request(19,fields,v));observations+=1
            assert (status(r)==0)==(v[0]>=3)
            records.append(dict(version=v,key=key,state=4 if v[0]>=3 else 2))
    return observations

def verify(server,records):
    with server.connect() as s:
        for row in records:assert attrs(s,row['key'],tuple(row['version']))[0x42008d][2]==row['state']
    return len(records)
def main():
    p=argparse.ArgumentParser();p.add_argument('--image');p.add_argument('--engine',default='podman');p.add_argument('--binary',type=pathlib.Path,help='explicit native binary; native mode only');a=p.parse_args()
    if a.image and a.binary:p.error('--binary is only supported for native probes')
    binary_path=(a.binary or ROOT/'target/debug/keytend-kmip-server').resolve()
    evidence=packaged_evidence(local_image_id(a.engine,a.image)) if a.image else {'runtime_binary_sha256':sha(binary_path),'source_commit':source_commit()[0]}
    out=ROOT/'artifacts/revocation';out.mkdir(parents=True,exist_ok=True);mode='image' if a.image else 'native'
    report=dict(status='running',**evidence,phases=[])
    path=out/(mode+'.json');path.write_text(json.dumps(report,indent=2)+'\n')
    records=[]
    try:
        with tempfile.TemporaryDirectory(prefix='keytend-revocation-') as d:
            server=DraftContainer(d,a.engine,a.image,log_path=out/'image-server.log') if a.image else Server(d,binary=binary_path,draft=True)
            try:
                server.start();report['phases'].append(dict(phase='create',checked_transitions=run(server,records)))
                server.stop()
                backup=pathlib.Path(d)/'backup.sqlite'
                subprocess.run([server.binary,'backup','--database',str(server.data/'kmip.sqlite'),'--master-key',str(server.pki/'master.key'),'--output',str(backup)],check=True)
                server.start();report['phases'].append(dict(phase='restart',checked_states=verify(server,records)));server.stop()
                clean=pathlib.Path(d)/'restore';clean.mkdir(mode=0o700);shutil.copyfile(backup,clean/'kmip.sqlite');(clean/'kmip.sqlite').chmod(0o600);server.data=clean
                server.start();report['phases'].append(dict(phase='restore',checked_states=verify(server,records)))
            finally:server.stop()
        report['status']='passed'
    except BaseException as e:report['status']='failed';report['error']=str(e);raise
    finally:path.write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps(report['phases']))
if __name__=='__main__':main()
