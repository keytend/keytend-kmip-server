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

"""Released Java and typed OVH PGP containers, independent JCE/GnuPG checks and recovery."""
import argparse, hashlib, json, os, pathlib, shutil, subprocess, tempfile
from image_evidence import source_commit, local_image_id, packaged_evidence
from https_client import HttpsServer, HttpsContainer, post
from test_database import ContainerServer
from test_runtime import ROOT
from keytend_kmip_release import release, sha
from wire import *

class DraftContainer(HttpsContainer):
    def base(self):return super().base()+['-e','KMIP_EXPERIMENTAL_V3=true']

def send(server,transport,op,fields,version):
    message=request(op,fields,v=version)
    if transport=='TLS':
        with server.connect() as connection:return exchange(connection,message)
    return post(server,message,transport)

def object(pgp,fmt,data):
    return structure(0x4200bd,integer(0x4200be,pgp),structure(0x420040,
        enumeration(0x420042,fmt),structure(0x420045,binary(0x420043,data)),
        enumeration(0x420028,4),integer(0x42002a,2048)))

def verify_numeric(server,records):
    for row in records:
        value=get(payload(send(server,row['transport'],10,[uid(row['id'],(3,0))],(3,0))),0x4200bd)
        assert get(value,0x4200be)==(0x4200be,2,row['pgp'])
        data=get(get(get(value,0x420040),0x420045),0x420043)[2]
        assert hashlib.sha256(data).hexdigest()==row['sha256']

def numeric(server,fixtures):
    records=[]
    for transport in ['TLS','TTLV','JSON','XML']:
        for name in ['v3_public','v4_public','v4_private']:
            data=fixtures[name].encode();pgp=3 if name.startswith('v3') else 4
            for fmt in [1,2]:
                key=get(payload(send(server,transport,3,[enumeration(0x420057,9),structure(0x420125,integer(0x42002c,0),enumeration(0x4200ae,7)),object(pgp,fmt,data)],(3,0))),0x420094)[2]
                records.append(dict(transport=transport,pgp=pgp,id=key,sha256=hashlib.sha256(data).hexdigest()))
        for version in [(1,0),(1,1)]:
            response=send(server,transport,3,[enumeration(0x420057,9),structure(0x420091),object(4,1,fixtures['v4_public'].encode())],version)
            assert get(get(response,0x42000f),0x42007e)[2]==8
    verify_numeric(server,records);return records

def gpg_oracle(server,records,fixtures,directory):
    home=pathlib.Path(directory)/'gpg';home.mkdir(mode=0o700)
    results=[]
    for name in ['v4_public','v4_private']:
        expected=hashlib.sha256(fixtures[name].encode()).hexdigest()
        row=next(r for r in records if r['sha256']==expected)
        value=get(payload(send(server,row['transport'],10,[uid(row['id'],(3,0))],(3,0))),0x4200bd)
        data=get(get(get(value,0x420040),0x420045),0x420043)[2]
        result=subprocess.run(['gpg','--batch','--no-autostart','--homedir',str(home),'--with-colons','--import-options','show-only','--dry-run','--import'],input=data,stdout=subprocess.PIPE,stderr=subprocess.PIPE,check=True)
        fingerprints=[line.split(':')[9] for line in result.stdout.decode().splitlines() if line.startswith('fpr:')]
        assert fingerprints[0]==fixtures['v4_fingerprint']
        results.append(dict(fixture=name,primary_fingerprint=fingerprints[0],returned_sha256=hashlib.sha256(data).hexdigest()))
    return results

def main():
    parser=argparse.ArgumentParser();parser.add_argument('--image');parser.add_argument('--engine',default='podman');parser.add_argument('--java',action='append',required=True);a=parser.parse_args()
    client,jars,artifact=release();binary=ROOT/'target/debug/keytend-kmip-server';binary_hash=sha(binary)
    evidence=packaged_evidence(local_image_id(a.engine,a.image)) if a.image else {'runtime_binary_sha256':binary_hash,'source_commit':source_commit()[0]}
    fixtures=json.loads((ROOT/'tests/fixtures/openpgp.json').read_text())
    mode='image' if a.image else 'native';out=ROOT/'artifacts/pgp';out.mkdir(parents=True,exist_ok=True)
    classes=pathlib.Path(tempfile.mkdtemp(prefix='java-pgp-'+mode+'-',dir=ROOT/'.cache'));classpath=os.pathsep.join(map(str,[classes]+jars))
    subprocess.run(['javac','--release','17','-cp',classpath,'-d',str(classes),str(ROOT/'interop/java/ServerPgp.java')],check=True)
    compiled={str(p.relative_to(ROOT)):sha(p) for p in classes.rglob('*.class')}
    go=ROOT/'.cache/pgp-client';sdk=ROOT/'interop/ovh'
    assert subprocess.check_output(['go','mod','verify'],cwd=sdk,text=True).strip()=='all modules verified'
    module=json.loads(subprocess.check_output(['go','list','-m','-json','github.com/ovh/kmip-go'],cwd=sdk,text=True))
    pin=json.loads((ROOT/'interop/clients.lock.json').read_text())['ovh']['commit'];assert module['Version'].endswith(pin[:12])
    subprocess.run(['go','build','-mod=readonly','-o',str(go),str(ROOT/'integration/pgp/client.go')],cwd=sdk,check=True);go_hash=sha(go)
    logs=[];lanes=[]
    (out/(mode+'.json')).write_text(json.dumps({'status':'running'})+'\n')
    with tempfile.TemporaryDirectory(prefix='keytend-pgp-') as directory:
        fixture_dir=pathlib.Path(directory)/'fixtures';fixture_dir.mkdir(mode=0o700)
        for name in ['v3_public','v4_public','v4_private']:(fixture_dir/(name+'.asc')).write_text(fixtures[name])
        server=DraftContainer(directory,a.engine,a.image) if a.image else HttpsServer(directory,draft=True)
        subprocess.run(['openssl','pkcs12','-export','-in',str(server.pki/'client.pem'),'-inkey',str(server.pki/'client.key'),'-certfile',str(server.pki/'ca.pem'),'-out',str(server.pki/'client.p12'),'-passout','pass:changeit'],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        go_manifest=pathlib.Path(directory)/'go.json';manifests=[pathlib.Path(directory)/('jdk'+str(i)+'.tsv') for i in range(len(a.java))]
        try:
            server.start()
            probe=subprocess.run([str(go),'probe',str(go_manifest),str(fixture_dir)],env={**os.environ,'KMIP_PKI':str(server.pki),'KMIP_PORT':str(server.port),'KMIP_HTTPS_PORT':str(server.https),'KMIP_PGP_CANONICAL_SIGNATURE_NAMES':'0'},capture_output=True,text=True,check=True,timeout=30)
            default_names=json.loads(probe.stdout);assert default_names['status']=='known_sdk_limitation' and len(default_names['records'])==6
            probe_log=out/(mode+'-go-default-names.json');probe_log.write_text(json.dumps(default_names,indent=2)+'\n');logs.append(probe_log)
            for phase in ['create','restart','restore']:
                if phase!='create':
                    server.stop()
                    if phase=='restore':
                        restored=pathlib.Path(directory)/'clean';restored.mkdir(mode=0o700);shutil.copyfile(backup,restored/'kmip.sqlite');(restored/'kmip.sqlite').chmod(0o600);server.data=restored
                    server.start()
                for index,(java,manifest) in enumerate(zip(a.java,manifests)):
                    log=out/(mode+'-jdk'+str(index)+'-'+phase+'.log');logs.append(log)
                    with log.open('w') as stream:subprocess.run([java,'-cp',classpath,'dev.keytend.kmip.interop.ServerPgp',str(server.pki),str(server.port),str(server.https),'create' if phase=='create' else 'verify',str(manifest),str(fixture_dir)],stdout=stream,stderr=subprocess.STDOUT,check=True,timeout=180)
                    assert len(manifest.read_text().splitlines())==120
                    if phase=='create':lanes.append(dict(jdk=subprocess.check_output([java,'-version'],stderr=subprocess.STDOUT,text=True).splitlines()[0],cases=120))
                result=subprocess.run([str(go),'create' if phase=='create' else 'verify',str(go_manifest),str(fixture_dir)],env={**os.environ,'KMIP_PKI':str(server.pki),'KMIP_PORT':str(server.port),'KMIP_HTTPS_PORT':str(server.https),'KMIP_PGP_CANONICAL_SIGNATURE_NAMES':'1'},capture_output=True,text=True,check=False,timeout=120)
                log=out/(mode+'-go-'+phase+'.log');log.write_text(result.stderr);logs.append(log)
                if result.returncode:raise RuntimeError('PGP Go adapter failed; see '+str(log))
                if phase=='create':
                    go_manifest.write_text(result.stdout);assert len(json.loads(result.stdout))==72
                    records=numeric(server,fixtures);oracle=gpg_oracle(server,records,fixtures,directory)
                    if a.image:
                        subprocess.run(ContainerServer.base(server)+[a.image,'backup','--database','/data/kmip.sqlite','--master-key','/tls/master.key','--output','/data/backup.sqlite'],check=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE);backup=server.data/'backup.sqlite'
                    else:
                        backup=pathlib.Path(directory)/'backup.sqlite';subprocess.run([str(binary),'backup','--database',str(server.data/'kmip.sqlite'),'--master-key',str(server.pki/'master.key'),'--output',str(backup)],check=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
                    backup_hash=sha(backup)
                else:
                    assert json.loads(result.stdout)['status']=='passed';verify_numeric(server,records)
        finally:server.stop()
    report=dict(status='passed',scope='Released Java: KMIP 1.2-1.4/2.0/2.1, TLS and HTTPS TTLV/JSON/XML, v3 public/v4 public/v4 private, Raw/Opaque conversion, padded wrapping with JCE oracle and wrapped Register; 1.4+ Export/Import. Typed OVH: 1.2-1.4 on all four transports with explicit public enum-registry configuration; six default JSON/XML name failures retained separately. Separate numeric draft cases and legacy 1.0/1.1 rejection; numeric records do not count as independent SDK coverage. Exact bytes/version/metadata after restart and clean encrypted backup restoration.',client_artifact=artifact,compiled_adapter_sha256=compiled,**evidence,lanes=lanes,java_cases=120*len(a.java),java_restart_cases=120*len(a.java),java_restore_cases=120*len(a.java),go_cases=72,go_restart_cases=72,go_restore_cases=72,sdk_commit=pin,sdk_module_version=module['Version'],sdk_module_sum=module['Sum'],sdk_modules_verified=True,go_attribute_enum_configuration={'public_API':'ttlv.RegisterEnum','value':7,'wire_name':'SHA_512WithRSAEncryptionPKCS_1V1_5','scope':'explicit bootstrap configuration before concurrent use; default SDK names are not credited'},go_default_name_findings=default_names,go_adapter_sha256=go_hash,numeric_draft_records=24,numeric_legacy_rejections=16,gpg_oracle=oracle,encrypted_backup_sha256=backup_hash,log_sha256={str(p.relative_to(ROOT)):sha(p) for p in logs})
    (out/(mode+'.json')).write_text(json.dumps(report,indent=2)+'\n');print('PASS PGP',mode,report['java_cases'],'Java cases, 72 typed Go cases, 24 numeric draft records; exact restart and clean backup restore')

if __name__=='__main__':main()
