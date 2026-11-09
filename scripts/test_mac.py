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

"""Published-SDK MAC probes, independent JCA/Python oracles and durable restore."""
import argparse, hashlib, json, os, pathlib, shutil, subprocess, tempfile
from image_evidence import source_commit, local_image_id, packaged_evidence
from https_client import HttpsServer, HttpsContainer, post
from test_database import ContainerServer
from test_runtime import ROOT
from keytend_kmip_release import release, sha
from wire import *


def send(server,transport,op,fields):
    message=request(op,fields,v=(3,0))
    if transport=='TLS':
        with server.connect() as connection:return exchange(connection,message)
    return post(server,message,transport)


def numeric(server):
    import hmac
    records=[];key=bytes.fromhex('2b7e151628aed2a6abf7158809cf4f3c');data=bytes(i%256 for i in range(521))
    message=bytes.fromhex('6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710')
    algorithms=[(7,'sha1'),(8,'sha224'),(9,'sha256'),(10,'sha384'),(11,'sha512'),(12,'md5'),(35,'sha3_224'),(36,'sha3_256'),(37,'sha3_384'),(38,'sha3_512')]
    for transport in ['TLS','TTLV','JSON','XML']:
        attrs=structure(0x420125,integer(0x42002c,0x180))
        obj=structure(0x42008f,structure(0x420040,enumeration(0x420042,1),enumeration(0x420028,3),integer(0x42002a,128),structure(0x420045,binary(0x420043,key))))
        identifier=get(payload(send(server,transport,3,[enumeration(0x420057,2),attrs,obj])),0x420094)[2]
        payload(send(server,transport,18,[uid(identifier,(3,0))]))
        for algorithm,name in algorithms:
            cp=structure(0x42002b,enumeration(0x420028,algorithm))
            records.append(dict(transport=transport,key=identifier,cp=cp,data=data,expected=hmac.new(key,data,name).digest()))
        for length,expected in [(0,'bb1d6929e95937287fa37d129b756746'),(16,'070a16b46b4d4144f79bdd9dd04a287c'),(40,'dfa66747de9ae63030ca32611497c827'),(64,'51f0bebf7e3b9d92fc49741779363cfe')]:
            cp=structure(0x42002b,enumeration(0x420028,3),enumeration(0x420011,7))
            records.append(dict(transport=transport,key=identifier,cp=cp,data=message[:length],expected=bytes.fromhex(expected)))
    verify_numeric(server,records);assert len(records)==56
    return records


def verify_numeric(server,records):
    for r in records:
        fields=[uid(r['key'],(3,0)),r['cp'],binary(0x4200c2,r['data'])]
        assert get(payload(send(server,r['transport'],35,fields)),0x4200c6)[2]==r['expected']
        verified=payload(send(server,r['transport'],36,fields+[binary(0x4200c6,r['expected'])]))
        assert get(verified,0x42009b)[2]==1


class DraftContainer(HttpsContainer):
    def base(self):return super().base()+['-e','KMIP_EXPERIMENTAL_V3=true']


def main():
    parser=argparse.ArgumentParser();parser.add_argument('--image');parser.add_argument('--engine',default='podman');parser.add_argument('--java',action='append',required=True);args=parser.parse_args()
    client,jars,artifact=release();binary=ROOT/'target/debug/keytend-kmip-server';binary_hash=sha(binary)
    config=local_image_id(args.engine,args.image) if args.image else None
    evidence=packaged_evidence(config) if args.image else {'runtime_binary_sha256':binary_hash,'source_commit':source_commit()[0]}
    out=ROOT/'artifacts/mac';out.mkdir(parents=True,exist_ok=True);mode='image' if args.image else 'native'
    classes=pathlib.Path(tempfile.mkdtemp(prefix=f'java-mac-{mode}-',dir=ROOT/'.cache'));classpath=os.pathsep.join(map(str,[classes]+jars))
    subprocess.run(['javac','--release','17','-cp',classpath,'-d',str(classes),str(ROOT/'interop/java/ServerMac.java')],check=True)
    compiled={str(p.relative_to(ROOT)):sha(p) for p in classes.rglob('*.class')}
    (out/f'{mode}.json').write_text(json.dumps({'status':'running'})+'\n');lanes=[];logs=[]
    with tempfile.TemporaryDirectory(prefix='keytend-mac-') as directory:
        server=DraftContainer(directory,args.engine,args.image) if args.image else HttpsServer(directory,draft=True)
        subprocess.run(['openssl','pkcs12','-export','-in',str(server.pki/'client.pem'),'-inkey',str(server.pki/'client.key'),'-certfile',str(server.pki/'ca.pem'),'-out',str(server.pki/'client.p12'),'-passout','pass:changeit'],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        try:
            server.start();manifests=[]
            for index,java in enumerate(args.java):
                manifest=pathlib.Path(directory)/f'jdk{index}.tsv';manifests.append(manifest)
                log=out/f'{mode}-jdk{index}-create.log'
                with log.open('w') as stream:subprocess.run([java,'-cp',classpath,'dev.keytend.kmip.interop.ServerMac',str(server.pki),str(server.port),str(server.https),'create',str(manifest)],stdout=stream,stderr=subprocess.STDOUT,check=True,timeout=120)
                assert len(manifest.read_text().splitlines())==248;logs.append(log)
                lanes.append({'jdk':subprocess.check_output([java,'-version'],stderr=subprocess.STDOUT,text=True).splitlines()[0],'cases':248})
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
                    with log.open('w') as stream:subprocess.run([java,'-cp',classpath,'dev.keytend.kmip.interop.ServerMac',str(server.pki),str(server.port),str(server.https),'verify',str(manifest)],stdout=stream,stderr=subprocess.STDOUT,check=True,timeout=120)
                    logs.append(log)
                verify_numeric(server,records)
        finally:server.stop()
    report={'status':'passed','scope':'Published Java SDK: final KMIP 1.2-1.4/2.0/2.1; ten HMAC algorithms where versioned and AES-CMAC on TLS/HTTPS TTLV/JSON/XML. Independent SunJCE and RFC4493 values; single/multipart, verification, changed parameters and exact MAC after restart/CLI backup restore. Numeric draft 3.0 uses Python HMAC and RFC4493. No full-spec or production approval',
        'client_artifact':artifact,'compiled_adapter_sha256':compiled,**evidence,'lanes':lanes,'java_cases':sum(l['cases'] for l in lanes),'java_restart_cases':sum(l['cases'] for l in lanes),'java_restore_cases':sum(l['cases'] for l in lanes),'numeric_records':56,'numeric_restart_records':56,'numeric_restore_records':56,'encrypted_backup_sha256':backup_hash,'log_sha256':{str(p.relative_to(ROOT)):sha(p) for p in logs}}
    (out/f'{mode}.json').write_text(json.dumps(report,indent=2)+'\n');print('PASS MAC',mode,report['java_cases'],'released-SDK cases, 56 numeric draft cases; exact restart and backup restore')


if __name__=='__main__':main()
