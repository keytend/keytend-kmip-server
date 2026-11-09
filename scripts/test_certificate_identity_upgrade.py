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

"""Actual schema-16 to 17 certificate identity migration and older-writer refusal."""
import argparse,hashlib,json,pathlib,shutil,sqlite3,ssl,subprocess,tempfile
from image_evidence import source_commit,local_image_id
from test_database import ContainerServer
from test_runtime import ROOT,Server,free_port
from test_runtime import sha
from wire import *
from cryptography import x509


def main():
    p=argparse.ArgumentParser();p.add_argument('--older-image',required=True);p.add_argument('--engine',default='podman');a=p.parse_args()
    executable=ROOT/'target/debug/keytend-kmip-server';binary_hash=sha(executable);older=local_image_id(a.engine,a.older_image)
    out=ROOT/'artifacts/certificate-identity-upgrade';out.mkdir(exist_ok=True);passed=[]
    def done(message):passed.append(message);print('PASS',message,flush=True)
    def schema(path):
        c=sqlite3.connect(path)
        try:return c.execute('PRAGMA user_version').fetchone()[0]
        finally:c.close()
    with tempfile.TemporaryDirectory(prefix='keytend-certificate-identity-upgrade-') as directory:
        s=ContainerServer(directory,a.engine,a.older_image);native=False;data=json.loads((ROOT/'tests/fixtures/openpgp.json').read_text())['v4_public'].encode()
        old_der=ssl.PEM_cert_to_DER_cert((s.pki/'server.pem').read_text());parsed=x509.load_der_x509_certificate(old_der);certificate=structure(0x420013,enumeration(0x42001d,1),binary(0x42001e,old_der))
        def rpc(connection,operation,fields):return exchange(connection,request(operation,fields,v=(2,1)))
        def cert(connection,identifier,kind,expected):
            value=get(payload(rpc(connection,10,[uid(identifier)])),0x420013);assert get(value,0x42001d)[2]==kind and get(value,0x42001e)[2]==expected
        def identity(connection,identifier):
            attrs=get(payload(rpc(connection,11,[uid(identifier),*[enumeration(0x42013b,t) for t in [0x4200b5,0x4200b6,0x4200b7]]])),0x420125)
            assert get(get(attrs,0x4200b5),0x4200b2)[2]==parsed.issuer.public_bytes()
            number=parsed.serial_number;raw=number.to_bytes(max(1,(number.bit_length()+7)//8),'big');raw=(b'\0'+raw) if raw[0]&128 else raw;serial=bytes([2,len(raw)])+raw
            assert get(get(attrs,0x4200b5),0x4200af)[2]==serial
            assert get(get(attrs,0x4200b7),0x4200b4)[2]==parsed.subject.public_bytes()
            assert get(get(attrs,0x4200b6),0x4200b2)[2]==parsed.issuer.public_bytes()
            return attrs[2]
        try:
            s.start()
            with s.connect() as c:
                original_key=create_key(c);key_bytes=key_value(c,original_key)
                original_cert=get(payload(rpc(c,3,[enumeration(0x420057,1),certificate,structure(0x420125,enumeration(0x420028,4),integer(0x42002a,2048),integer(0x42002c,0),integer(0x4200ad,len(old_der)))])),0x420094)[2]
                parts=[n[2] for n in children(payload(rpc(c,40,[enumeration(0x420057,5),uid(original_cert),integer(0x42008b,3),integer(0x42008c,2),enumeration(0x42008a,4),structure(0x420125)])),0x420094)]
                missing=rpc(c,11,[uid(original_cert),enumeration(0x42013b,0x4200b5)]);assert status(missing)==0 and not children(payload(missing),0x420125)
                tombstone=get(payload(rpc(c,3,[enumeration(0x420057,1),certificate,structure(0x420125,enumeration(0x420028,4),integer(0x42002a,2048),integer(0x42002c,0),integer(0x4200ad,len(old_der)))])),0x420094)[2]
                payload(rpc(c,20,[uid(tombstone)]));destroyed=payload(rpc(c,43,[uid(tombstone)]))[2]
            s.stop();database=s.data/'kmip.sqlite' ;assert schema(database)==16
            done('previous immutable schema-16 image created exact AES/X.509, old shares and a tombstone; its X.509 identity selector is absent')
            s.port=free_port();s.health=free_port();native=True;Server.start(s)
            with s.connect() as c:
                assert key_value(c,original_key)==key_bytes;cert(c,original_cert,1,old_der)
                done('schema-17 reader retains exact managed AES and certificate bytes')
                repaired=identity(c,original_cert);done('prior live X.509 record gains exact issuer/subject and complete serial DER from its retained certificate')
                absent=rpc(c,11,[uid(tombstone),enumeration(0x42013b,0x4200b5)]);assert status(absent)==0 and not children(payload(absent),0x420125)
                incomplete=rpc(c,42,destroyed+[node(0x420124,6,True)]);assert status(incomplete)==1 and reason(incomplete)==6
                restored=[]
                for n in destroyed:
                    restored.append(structure(0x420125,*n[2],*repaired) if n[0]==0x420125 else n)
                payload(rpc(c,42,restored+[node(0x420124,6,True)]));identity(c,tombstone)
                done('missing old tombstone identity is not invented; owner restores exact attributes derived from the retained original certificate')
                joined=get(payload(rpc(c,41,[enumeration(0x420057,1),uid(parts[2]),uid(parts[0]),structure(0x420125)])),0x420094)[2];cert(c,joined,1,old_der);identity(c,joined)
                done('old local Certificate shares reconstruct exact DER and derive the new identity fields')
                pgp=get(payload(rpc(c,3,[enumeration(0x420057,1),structure(0x420013,enumeration(0x42001d,2),binary(0x42001e,data)),structure(0x420125,enumeration(0x420028,4),integer(0x42002a,2048),integer(0x42002c,0),integer(0x4200ad,len(data)))])),0x420094)[2];cert(c,pgp,2,data)
            Server.stop(s);assert schema(database)==17
            before=sha(database)
            rejected=subprocess.run(ContainerServer.base(s)+[a.older_image,'check-store','--database','/data/kmip.sqlite','--master-key','/tls/master.key'],stdout=subprocess.PIPE,stderr=subprocess.STDOUT)
            assert rejected.returncode and b'schema is newer' in rejected.stdout and sha(database)==before
            done('previous schema-16 writer refuses the upgraded store before it can misproject identity fields; database bytes remain unchanged')
            Server.start(s)
            with s.connect() as c:cert(c,original_cert,1,old_der);identity(c,original_cert);identity(c,tombstone);identity(c,joined);cert(c,pgp,2,data);assert key_value(c,original_key)==key_bytes
            done('restart retains both certificate types and exact earlier key material')
            backup=pathlib.Path(directory)/'backup.sqlite';subprocess.run([str(executable),'backup','--database',str(database),'--master-key',str(s.pki/'master.key'),'--output',str(backup)],check=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
            backup_hash=sha(backup);Server.stop(s);clean=pathlib.Path(directory)/'clean';clean.mkdir(mode=0o700);shutil.copyfile(backup,clean/'kmip.sqlite');(clean/'kmip.sqlite').chmod(0o600);s.data=clean;Server.start(s)
            with s.connect() as c:cert(c,original_cert,1,old_der);identity(c,original_cert);identity(c,tombstone);identity(c,joined);cert(c,pgp,2,data);assert key_value(c,original_key)==key_bytes
            done('clean-directory encrypted backup restore retains Type 1, Type 2, exact bytes and the prior managed AES key')
            check=subprocess.run([str(executable),'check-store','--database',str(s.data/'kmip.sqlite'),'--master-key',str(s.pki/'master.key')],check=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
            assert b'verified' in check.stdout.lower();done('current binary verifies the restored wrapping key and complete audit chain')
        finally:
            if native:Server.stop(s)
            else:s.stop()
    report=dict(status='passed',scope='Actual schema-16 encrypted certificate/share/tombstone records, schema-17 identity extraction and explicit owner repair, exact reconstruction, older-writer refusal and clean backup restoration; numeric TLS driver, not SDK coverage',source_commit=source_commit()[0],runtime_binary_sha256=binary_hash,older_image_config_id=older,older_storage_schema=16,current_storage_schema=17,passed=passed,backup_sha256=backup_hash)
    (out/'native.json').write_text(json.dumps(report,indent=2)+'\n')
if __name__=='__main__':main()
