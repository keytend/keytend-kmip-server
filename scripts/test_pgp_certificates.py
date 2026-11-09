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

"""Released Java Type-2 certificates with independent GnuPG and recovery checks."""
import argparse,base64,json,os,pathlib,shutil,subprocess,tempfile
from image_evidence import source_commit,local_image_id,packaged_evidence
from https_client import HttpsServer,HttpsContainer
from test_database import ContainerServer
from test_runtime import ROOT
from keytend_kmip_release import release,sha
from wire import *


def fixtures(directory):
    original=json.loads((ROOT/'tests/fixtures/openpgp.json').read_text())
    values=json.loads((ROOT/'tests/fixtures/pgp-certificates.json').read_text())['fixtures']
    values={**values,'rsa':{'armored':original['v4_public'],'fingerprint':original['v4_fingerprint'],'algorithm':4,'bits':2048,'signature_algorithms':[7]}}
    rows=[]
    for name,value in values.items():
        data=value['armored'].encode();(directory/(name+'.asc')).write_bytes(data)
        body=False;encoded=[]
        for line in data.decode().splitlines():
            if not body:
                if not line:body=True
            elif line.startswith('-----END'):break
            elif not line.startswith('='):encoded.append(line)
        (directory/(name+'.bin')).write_bytes(base64.b64decode(''.join(encoded),validate=True))
        assert len(value['signature_algorithms'])==1
        rows.append('\t'.join(map(str,[name,value['algorithm'],value['bits'],value['signature_algorithms'][0]])))
    (directory/'metadata.tsv').write_text('\n'.join(rows)+'\n');return values


def numeric_oracle(server,values,directory):
    records=[];home=pathlib.Path(directory)/'gpg';home.mkdir(mode=0o700)
    with server.connect() as c:
        for name,value in values.items():
            data=value['armored'].encode();p=payload(exchange(c,request(3,[enumeration(0x420057,1),structure(0x420013,enumeration(0x42001d,2),binary(0x42001e,data)),structure(0x420125,enumeration(0x420028,value['algorithm']),integer(0x42002a,value['bits']),integer(0x42002c,0),integer(0x4200ad,len(data)))],v=(2,1))))
            identifier=get(p,0x420094)[2];returned=get(payload(exchange(c,request(10,[uid(identifier)],v=(2,1)))),0x420013)
            assert get(returned,0x42001d)[2]==2 and get(returned,0x42001e)[2]==data
            result=subprocess.run(['gpg','--batch','--no-autostart','--homedir',str(home),'--with-colons','--import-options','show-only','--dry-run','--import'],input=data,stdout=subprocess.PIPE,stderr=subprocess.PIPE,check=True)
            fingerprints=[line.split(':')[9] for line in result.stdout.decode().splitlines() if line.startswith('fpr:')];assert fingerprints[0]==value['fingerprint']
            records.append({'name':name,'id':identifier,'fingerprint':fingerprints[0],'sha256':__import__('hashlib').sha256(data).hexdigest()})
    return records


def main():
    p=argparse.ArgumentParser();p.add_argument('--image');p.add_argument('--engine',default='podman');p.add_argument('--java',action='append',required=True);a=p.parse_args()
    _,jars,artifact=release();binary=ROOT/'target/debug/keytend-kmip-server';binary_hash=sha(binary)
    config=local_image_id(a.engine,a.image) if a.image else None;evidence=packaged_evidence(config) if config else {'runtime_binary_sha256':binary_hash,'source_commit':source_commit()[0]}
    mode='image' if config else 'native';out=ROOT/'artifacts/pgp-certificates';out.mkdir(parents=True,exist_ok=True)
    classes=pathlib.Path(tempfile.mkdtemp(prefix='java-pgp-certificate-'+mode+'-',dir=ROOT/'.cache'));classpath=os.pathsep.join(map(str,[classes]+jars))
    subprocess.run(['javac','--release','17','-cp',classpath,'-d',str(classes),str(ROOT/'interop/java/ServerPgpCertificate.java')],check=True)
    compiled={str(path.relative_to(ROOT)):sha(path) for path in classes.rglob('*.class')};logs=[];lanes=[]
    (out/(mode+'.json')).write_text(json.dumps({'status':'running'})+'\n')
    with tempfile.TemporaryDirectory(prefix='keytend-pgp-certificate-') as directory:
        fixture_dir=pathlib.Path(directory)/'fixtures';fixture_dir.mkdir(mode=0o700);values=fixtures(fixture_dir)
        retained=out/(mode+'-fixtures');retained.mkdir(exist_ok=True);fixture_hashes={}
        for path in fixture_dir.iterdir():
            target=retained/path.name;shutil.copyfile(path,target);fixture_hashes[str(target.relative_to(ROOT))]=sha(target)
        server=HttpsContainer(directory,a.engine,a.image) if config else HttpsServer(directory)
        subprocess.run(['openssl','pkcs12','-export','-in',str(server.pki/'client.pem'),'-inkey',str(server.pki/'client.key'),'-certfile',str(server.pki/'ca.pem'),'-out',str(server.pki/'client.p12'),'-passout','pass:changeit'],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        manifests=[pathlib.Path(directory)/('jdk'+str(i)+'.tsv') for i in range(len(a.java))]
        try:
            server.start()
            for phase in ['create','restart','restore']:
                if phase!='create':
                    server.stop()
                    if phase=='restore':
                        clean=pathlib.Path(directory)/'clean';clean.mkdir(mode=0o700);shutil.copyfile(backup,clean/'kmip.sqlite');(clean/'kmip.sqlite').chmod(0o600);server.data=clean
                    server.start()
                for index,(java,manifest) in enumerate(zip(a.java,manifests)):
                    log=out/(mode+'-jdk'+str(index)+'-'+phase+'.log');logs.append(log)
                    with log.open('w') as stream:subprocess.run([java,'-cp',classpath,'dev.keytend.kmip.interop.ServerPgpCertificate',str(server.pki),str(server.port),str(server.https),'create' if phase=='create' else 'verify',str(manifest),str(fixture_dir)],check=True,stdout=stream,stderr=subprocess.STDOUT,timeout=240)
                    assert len(log.read_text().splitlines())==24
                    lanes.append({'phase':phase,'jdk':subprocess.check_output([java,'-version'],stderr=subprocess.STDOUT,text=True).splitlines()[0],'cases':240})
                if phase=='create':
                    oracle=numeric_oracle(server,values,directory)
                    if config:
                        subprocess.run(ContainerServer.base(server)+[a.image,'backup','--database','/data/kmip.sqlite','--master-key','/tls/master.key','--output','/data/backup.sqlite'],check=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE);backup=server.data/'backup.sqlite'
                    else:
                        backup=pathlib.Path(directory)/'backup.sqlite';subprocess.run([str(binary),'backup','--database',str(server.data/'kmip.sqlite'),'--master-key',str(server.pki/'master.key'),'--output',str(backup)],check=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
                    backup_hash=sha(backup)
                else:
                    with server.connect() as connection:
                        for row in oracle:
                            cert=get(payload(exchange(connection,request(10,[uid(row['id'])],v=(2,1)))),0x420013)
                            assert get(cert,0x42001d)[2]==2 and __import__('hashlib').sha256(get(cert,0x42001e)[2]).hexdigest()==row['sha256']
        finally:server.stop()
    report=dict(status='passed',scope='Type-2 PGP certificates through unchanged published Java JAR on six final editions and TLS/HTTPS TTLV/JSON/XML; armored/binary RSA, DSA and P-256/P-384/P-521 with ECDH subkeys. Exact type/bytes, primary algorithm/length and signature attributes; 1.4+ live Import; restart and clean encrypted backup restoration. Independent GnuPG fingerprints use a separate numeric 2.1 driver. No draft Java, PGP trust-validation or full certificate-family credit.',client_artifact=artifact,**evidence,compiled_adapter_sha256=compiled,lanes=lanes,java_cases_per_phase=240*len(a.java),fixture_sha256=fixture_hashes,gpg_oracle=oracle,encrypted_backup_sha256=backup_hash,log_sha256={str(path.relative_to(ROOT)):sha(path) for path in logs})
    (out/(mode+'.json')).write_text(json.dumps(report,indent=2)+'\n');print('PASS PGP certificates',mode,report['java_cases_per_phase'],'Java cases per phase; independent GnuPG and restart/backup recovery')
if __name__=='__main__':main()
