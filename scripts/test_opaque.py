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

"""Published-SDK opaque type/empty value probes and durable restore."""
import argparse, hashlib, json, os, pathlib, shutil, subprocess, tempfile
from image_evidence import source_commit, local_image_id, packaged_evidence
from https_client import HttpsServer, HttpsContainer, post
from test_database import ContainerServer
from test_runtime import ROOT
from keytend_kmip_release import release, sha
from wire import *


def send(server,transport,op,fields,version):
    message=request(op,fields,v=version)
    if transport=='TLS':
        with server.connect() as connection:return exchange(connection,message)
    return post(server,message,transport)


def numeric(server):
    records=[]
    for version in [(1,0),(3,0)]:
        for transport in ['TLS','TTLV','JSON','XML']:
            for kind in [0x80000000,0x80000001,0x80012345,0x8fffffff]:
                for data in [b'',bytes(i%256 for i in range(65536))]:
                    obj=structure(0x42005b,enumeration(0x420059,kind),binary(0x42005a,data))
                    attrs=structure(0x420091 if version[0]==1 else 0x420125)
                    key=get(payload(send(server,transport,3,[enumeration(0x420057,8),attrs,obj],version)),0x420094)[2]
                    records.append(dict(version=version,transport=transport,key=key,kind=kind,data_sha256=hashlib.sha256(data).hexdigest(),length=len(data)))
    verify_numeric(server,records);assert len(records)==64
    return records


def verify_numeric(server,records):
    for r in records:
        obj=get(payload(send(server,r['transport'],10,[uid(r['key'],r['version'])],r['version'])),0x42005b)
        assert get(obj,0x420059)==(0x420059,5,r['kind'])
        data=get(obj,0x42005a)[2]
        assert len(data)==r['length'] and hashlib.sha256(data).hexdigest()==r['data_sha256']


class DraftContainer(HttpsContainer):
    def base(self):return super().base()+['-e','KMIP_EXPERIMENTAL_V3=true']


def main():
    parser=argparse.ArgumentParser();parser.add_argument('--image');parser.add_argument('--engine',default='podman');parser.add_argument('--java',action='append',required=True);args=parser.parse_args()
    client,jars,artifact=release();binary=ROOT/'target/debug/keytend-kmip-server';binary_hash=sha(binary)
    evidence=packaged_evidence(local_image_id(args.engine,args.image)) if args.image else {'runtime_binary_sha256':binary_hash,'source_commit':source_commit()[0]}
    out=ROOT/'artifacts/opaque';out.mkdir(parents=True,exist_ok=True);mode='image' if args.image else 'native'
    classes=pathlib.Path(tempfile.mkdtemp(prefix=f'java-opaque-{mode}-',dir=ROOT/'.cache'));classpath=os.pathsep.join(map(str,[classes]+jars))
    subprocess.run(['javac','--release','17','-cp',classpath,'-d',str(classes),str(ROOT/'interop/java/ServerOpaque.java')],check=True)
    compiled={str(p.relative_to(ROOT)):sha(p) for p in classes.rglob('*.class')}
    (out/f'{mode}.json').write_text(json.dumps({'status':'running'})+'\n');lanes=[];logs=[]
    with tempfile.TemporaryDirectory(prefix='keytend-opaque-') as directory:
        server=DraftContainer(directory,args.engine,args.image) if args.image else HttpsServer(directory,draft=True)
        subprocess.run(['openssl','pkcs12','-export','-in',str(server.pki/'client.pem'),'-inkey',str(server.pki/'client.key'),'-certfile',str(server.pki/'ca.pem'),'-out',str(server.pki/'client.p12'),'-passout','pass:changeit'],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        try:
            server.start();manifests=[]
            for index,java in enumerate(args.java):
                manifest=pathlib.Path(directory)/f'jdk{index}.tsv';manifests.append(manifest)
                log=out/f'{mode}-jdk{index}-create.log'
                with log.open('w') as stream:subprocess.run([java,'-cp',classpath,'dev.keytend.kmip.interop.ServerOpaque',str(server.pki),str(server.port),str(server.https),'create',str(manifest)],stdout=stream,stderr=subprocess.STDOUT,check=True,timeout=600)
                assert len(manifest.read_text().splitlines())==192;logs.append(log)
                lanes.append({'jdk':subprocess.check_output([java,'-version'],stderr=subprocess.STDOUT,text=True).splitlines()[0],'cases':192})
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
                    with log.open('w') as stream:subprocess.run([java,'-cp',classpath,'dev.keytend.kmip.interop.ServerOpaque',str(server.pki),str(server.port),str(server.https),'verify',str(manifest)],stdout=stream,stderr=subprocess.STDOUT,check=True,timeout=600)
                    logs.append(log)
                verify_numeric(server,records)
        finally:server.stop()
    report={'status':'passed','scope':'Published Java SDK: final KMIP 1.1-1.4/2.0/2.1; four opaque extension types and empty/65536-byte values on TLS and HTTPS TTLV/JSON/XML. Intrinsic type and privileged Import checks in 2.x. Exact type/data after restart and clean encrypted backup restore. Numeric 1.0 and draft coverage is separate. No full-spec or production approval',
        'client_artifact':artifact,'compiled_adapter_sha256':compiled,**evidence,'lanes':lanes,'java_cases':sum(l['cases'] for l in lanes),'java_restart_cases':sum(l['cases'] for l in lanes),'java_restore_cases':sum(l['cases'] for l in lanes),'numeric_records':64,'numeric_restart_records':64,'numeric_restore_records':64,'encrypted_backup_sha256':backup_hash,'log_sha256':{str(p.relative_to(ROOT)):sha(p) for p in logs}}
    (out/f'{mode}.json').write_text(json.dumps(report,indent=2)+'\n');print('PASS opaque',mode,report['java_cases'],'released-SDK cases, 64 numeric legacy/draft cases; exact restart and backup restore')


if __name__=='__main__':main()
