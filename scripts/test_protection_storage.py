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

"""Published-SDK protection-storage probes with durable restore verification."""
import argparse, hashlib, json, os, pathlib, shutil, subprocess, tempfile
from image_evidence import source_commit, local_image_id, packaged_evidence
from https_client import HttpsServer, HttpsContainer, post
from test_database import ContainerServer
from test_runtime import ROOT
from keytend_kmip_release import release, sha
from wire import *


def numeric(server):
    records=[]
    for version in [(2,0),(2,1),(3,0)]:
        for transport in ['TLS','TTLV','JSON','XML']:
            def send(op, fields):
                message=request(op,fields,v=version)
                if transport=='TLS':
                    with server.connect() as connection:return exchange(connection,message)
                return post(server,message,transport)
            def masks(values):return structure(0x42015f,*[integer(0x42015e,n) for n in values])
            attrs=structure(0x420125,enumeration(0x420028,3),integer(0x42002a,128),integer(0x42002c,12))
            for values, expected in [([0],0),([2,1],1)]:
                key=get(payload(send(1,[enumeration(0x420057,2),attrs,masks(values)])),0x420094)[2]
                value=get(get(payload(send(11,[uid(key,version),enumeration(0x42013b,0x42015e)])),0x420125),0x42015e)
                assert value==(0x42015e,2,expected)
                records.append(dict(version=version,transport=transport,key=key,mask=expected))
            for values in [[2],[3],[],[128,4096]]:
                assert reason(send(1,[enumeration(0x420057,2),attrs,masks(values)]))==0x44
            malformed=structure(0x42015f,integer(0x42015e,1),text(0x42015e,'invalid after acceptable mask'))
            assert reason(send(1,[enumeration(0x420057,2),attrs,malformed]))==7
            assert reason(send(2,[structure(0x420164,integer(0x42015e,2))]))==0x48
            assert reason(send(2,[structure(0x420165,integer(0x42015e,2))]))==0x49
    assert len(records)==24
    for version in [(1,0),(1,1),(1,2),(1,3),(1,4)]:
        for transport in ['TLS','TTLV','JSON','XML']:
            def send_legacy(op, fields, selected=version):
                message=request(op,fields,v=selected)
                if transport=='TLS':
                    with server.connect() as connection:return exchange(connection,message)
                return post(server,message,transport)
            fields=[enumeration(0x420057,2),structure(0x420091)]
            assert reason(send_legacy(1,fields+[structure(0x42015f,integer(0x42015e,1))]))==7
            key=get(payload(send_legacy(1,fields)),0x420094)[2]
            attrs=children(payload(send_legacy(11,[uid(key,version)])),0x420008)
            assert all(get(a,0x42000a)[2]!='Protection Storage Mask' for a in attrs)
            value=get(get(payload(send_legacy(11,[uid(key,(2,1)),enumeration(0x42013b,0x42015e)],(2,1))),0x420125),0x42015e)
            assert value==(0x42015e,2,1)
            records.append(dict(version=(2,1),transport=transport,key=key,mask=1,legacy_origin=version))
    assert len(records)==44
    return records


def verify_numeric(server, records):
    for record in records:
        version=tuple(record['version']);message=request(11,[uid(record['key'],version),enumeration(0x42013b,0x42015e)],v=version)
        if record['transport']=='TLS':
            with server.connect() as connection:response=exchange(connection,message)
        else:response=post(server,message,record['transport'])
        assert get(get(payload(response),0x420125),0x42015e)==(0x42015e,2,record['mask'])


class DraftContainer(HttpsContainer):
    def base(self):return super().base()+['-e','KMIP_EXPERIMENTAL_V3=true']


def main():
    parser=argparse.ArgumentParser();parser.add_argument('--image');parser.add_argument('--engine',default='podman');parser.add_argument('--java',action='append',required=True);args=parser.parse_args()
    client,jars,artifact=release();binary=ROOT/'target/debug/keytend-kmip-server';binary_hash=sha(binary)
    evidence=packaged_evidence(local_image_id(args.engine,args.image)) if args.image else {'runtime_binary_sha256':binary_hash,'source_commit':source_commit()[0]}
    out=ROOT/'artifacts/protection-storage';out.mkdir(parents=True,exist_ok=True);mode='image' if args.image else 'native'
    classes=pathlib.Path(tempfile.mkdtemp(prefix=f'java-protection-{mode}-',dir=ROOT/'.cache'));classpath=os.pathsep.join(map(str,[classes]+jars))
    subprocess.run(['javac','--release','17','-cp',classpath,'-d',str(classes),str(ROOT/'interop/java/ServerProtection.java')],check=True)
    compiled={str(p.relative_to(ROOT)):sha(p) for p in classes.rglob('*.class')}
    (out/f'{mode}.json').write_text(json.dumps({'status':'running'})+'\n');lanes=[];logs=[]
    with tempfile.TemporaryDirectory(prefix='keytend-protection-') as directory:
        server=DraftContainer(directory,args.engine,args.image) if args.image else HttpsServer(directory,draft=True)
        subprocess.run(['openssl','pkcs12','-export','-in',str(server.pki/'client.pem'),'-inkey',str(server.pki/'client.key'),'-certfile',str(server.pki/'ca.pem'),'-out',str(server.pki/'client.p12'),'-passout','pass:changeit'],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        try:
            server.start();manifests=[]
            for index,java in enumerate(args.java):
                manifest=pathlib.Path(directory)/f'jdk{index}.tsv';manifests.append(manifest)
                log=out/f'{mode}-jdk{index}-create.log'
                with log.open('w') as stream:subprocess.run([java,'-cp',classpath,'dev.keytend.kmip.interop.ServerProtection',str(server.pki),str(server.port),str(server.https),'create',str(manifest)],stdout=stream,stderr=subprocess.STDOUT,check=True,timeout=120)
                assert len(manifest.read_text().splitlines())==8;logs.append(log)
                lanes.append({'jdk':subprocess.check_output([java,'-version'],stderr=subprocess.STDOUT,text=True).splitlines()[0],'cases':8})
            records=numeric(server)
            if args.image:
                subprocess.run(ContainerServer.base(server)+[args.image,'backup','--database','/data/kmip.sqlite','--master-key','/tls/master.key','--output','/data/backup.sqlite'],check=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
                backup=server.data/'backup.sqlite'
            else:
                backup=pathlib.Path(directory)/'backup.sqlite'
                subprocess.run([str(binary),'backup','--database',str(server.data/'kmip.sqlite'),'--master-key',str(server.pki/'master.key'),'--output',str(backup)],check=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
            backup_hash=sha(backup)
            for phase in ['restart','restore']:
                server.stop()
                if phase=='restore':
                    restored=pathlib.Path(directory)/'restored-data';restored.mkdir(mode=0o700);shutil.copyfile(backup,restored/'kmip.sqlite');(restored/'kmip.sqlite').chmod(0o600);server.data=restored
                server.start()
                for index,(java,manifest) in enumerate(zip(args.java,manifests)):
                    log=out/f'{mode}-jdk{index}-{phase}.log'
                    with log.open('w') as stream:subprocess.run([java,'-cp',classpath,'dev.keytend.kmip.interop.ServerProtection',str(server.pki),str(server.port),str(server.https),'verify',str(manifest)],stdout=stream,stderr=subprocess.STDOUT,check=True,timeout=120)
                    logs.append(log)
                verify_numeric(server,records)
        finally:server.stop()
    client_findings=sorted({'CLIENT-PROTECTION-001'} if any('CLIENT-PROTECTION-001' in log.read_text() for log in logs) else set())
    report={'status':'passed','known_client_findings':['CLIENT-PROTECTION-001: keytend-kmip 0.9 moves the non-standard top-level Protection Storage Masks field of Import (a server extension; not in the KMIP 2.x Import request table) into Attributes, where the server refuses it; the Java lane restores without it and the server check is covered by tests/protection_storage.rs'] if client_findings else [],'scope':'Published keytend-kmip SDK: KMIP 2.0/2.1 on TLS and HTTPS TTLV/JSON/XML; whole mask alternatives, immutable metadata, Create/Split/Join/Import, pair role constraints/errors and exact material after restart/clean backup restore. Separate numeric driver covers 2.0/2.1, draft and legacy rejection/projection. No full-spec or deployment certification.',
        'client_artifact':artifact,'compiled_adapter_sha256':compiled,**evidence,'lanes':lanes,'java_cases':sum(l['cases'] for l in lanes),'java_restart_cases':sum(l['cases'] for l in lanes),'java_restore_cases':sum(l['cases'] for l in lanes),'numeric_records':44,'numeric_restart_records':44,'numeric_restore_records':44,'legacy_rejection_and_projection_lanes':20,'encrypted_backup_sha256':backup_hash,'log_sha256':{str(p.relative_to(ROOT)):sha(p) for p in logs}}
    (out/f'{mode}.json').write_text(json.dumps(report,indent=2)+'\n');print('PASS protection storage',mode,report['java_cases'],'released-SDK cases, 44 numeric records including 20 legacy lanes; exact restart and backup restore')


if __name__=='__main__':main()
