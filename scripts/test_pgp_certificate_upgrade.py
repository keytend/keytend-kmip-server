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

"""Actual schema-15 to 16 migration and older-writer refusal for stored Certificate Type."""
import argparse,hashlib,json,pathlib,shutil,sqlite3,ssl,subprocess,tempfile
from image_evidence import source_commit,local_image_id
from test_database import ContainerServer
from test_runtime import ROOT,Server,free_port
from test_runtime import sha
from wire import *


def main():
    p=argparse.ArgumentParser();p.add_argument('--older-image',required=True);p.add_argument('--engine',default='podman');a=p.parse_args()
    executable=ROOT/'target/debug/keytend-kmip-server';binary_hash=sha(executable);older=local_image_id(a.engine,a.older_image)
    out=ROOT/'artifacts/pgp-certificate-upgrade';out.mkdir(exist_ok=True);passed=[]
    def done(message):passed.append(message);print('PASS',message,flush=True)
    def schema(path):
        c=sqlite3.connect(path)
        try:return c.execute('PRAGMA user_version').fetchone()[0]
        finally:c.close()
    with tempfile.TemporaryDirectory(prefix='keytend-pgp-certificate-upgrade-') as directory:
        s=ContainerServer(directory,a.engine,a.older_image);native=False;data=json.loads((ROOT/'tests/fixtures/openpgp.json').read_text())['v4_public'].encode()
        old_der=ssl.PEM_cert_to_DER_cert((s.pki/'server.pem').read_text());certificate=structure(0x420013,enumeration(0x42001d,1),binary(0x42001e,old_der))
        def rpc(connection,operation,fields):return exchange(connection,request(operation,fields,v=(2,1)))
        def cert(connection,identifier,kind,expected):
            value=get(payload(rpc(connection,10,[uid(identifier)])),0x420013);assert get(value,0x42001d)[2]==kind and get(value,0x42001e)[2]==expected
        try:
            s.start()
            with s.connect() as c:
                original_key=create_key(c);key_bytes=key_value(c,original_key)
                original_cert=get(payload(rpc(c,3,[enumeration(0x420057,1),certificate,structure(0x420125,enumeration(0x420028,4),integer(0x42002a,2048),integer(0x42002c,0),integer(0x4200ad,len(old_der)))])),0x420094)[2]
                parts=[n[2] for n in children(payload(rpc(c,40,[enumeration(0x420057,5),uid(original_cert),integer(0x42008b,3),integer(0x42008c,2),enumeration(0x42008a,4),structure(0x420125)])),0x420094)]
            s.stop();database=s.data/'kmip.sqlite';assert schema(database)==15
            done('previous immutable image created schema-15 AES, X.509 and local-share records without the new stored type field')
            s.port=free_port();s.health=free_port();native=True;Server.start(s)
            with s.connect() as c:
                assert key_value(c,original_key)==key_bytes;cert(c,original_cert,1,old_der)
                done('schema-16 reader defaults earlier certificates to X.509 and retains exact managed AES and certificate bytes')
                joined=get(payload(rpc(c,41,[enumeration(0x420057,1),uid(parts[2]),uid(parts[0]),structure(0x420125)])),0x420094)[2];cert(c,joined,1,old_der)
                done('old local Certificate share provenance defaults to Type 1 and reconstructs without changing its DER')
                pgp=get(payload(rpc(c,3,[enumeration(0x420057,1),structure(0x420013,enumeration(0x42001d,2),binary(0x42001e,data)),structure(0x420125,enumeration(0x420028,4),integer(0x42002a,2048),integer(0x42002c,0),integer(0x4200ad,len(data)))])),0x420094)[2];cert(c,pgp,2,data)
            Server.stop(s);assert schema(database)==16
            before=sha(database)
            rejected=subprocess.run(ContainerServer.base(s)+[a.older_image,'check-store','--database','/data/kmip.sqlite','--master-key','/tls/master.key'],stdout=subprocess.PIPE,stderr=subprocess.STDOUT)
            assert rejected.returncode and b'schema is newer' in rejected.stdout and sha(database)==before
            done('previous schema-15 writer refuses the upgraded store before it can discard the Type-2 field; database bytes remain unchanged')
            Server.start(s)
            with s.connect() as c:cert(c,original_cert,1,old_der);cert(c,pgp,2,data);assert key_value(c,original_key)==key_bytes
            done('restart retains both certificate types and exact earlier key material')
            backup=pathlib.Path(directory)/'backup.sqlite';subprocess.run([str(executable),'backup','--database',str(database),'--master-key',str(s.pki/'master.key'),'--output',str(backup)],check=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
            backup_hash=sha(backup);Server.stop(s);clean=pathlib.Path(directory)/'clean';clean.mkdir(mode=0o700);shutil.copyfile(backup,clean/'kmip.sqlite');(clean/'kmip.sqlite').chmod(0o600);s.data=clean;Server.start(s)
            with s.connect() as c:cert(c,original_cert,1,old_der);cert(c,pgp,2,data);assert key_value(c,original_key)==key_bytes
            done('clean-directory encrypted backup restore retains Type 1, Type 2, exact bytes and the prior managed AES key')
            check=subprocess.run([str(executable),'check-store','--database',str(s.data/'kmip.sqlite'),'--master-key',str(s.pki/'master.key')],check=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
            assert b'verified' in check.stdout.lower();done('current binary verifies the restored wrapping key and complete audit chain')
        finally:
            if native:Server.stop(s)
            else:s.stop()
    report=dict(status='passed',scope='Actual old-image encrypted schema-15 records, schema-16 type preservation, local share recovery, older-writer refusal and clean backup restoration; numeric TLS driver, not SDK coverage',source_commit=source_commit()[0],runtime_binary_sha256=binary_hash,older_image_config_id=older,older_storage_schema=15,current_storage_schema=16,passed=passed,backup_sha256=backup_hash)
    (out/'native.json').write_text(json.dumps(report,indent=2)+'\n')
if __name__=='__main__':main()
