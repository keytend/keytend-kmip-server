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

"""Actual schema-15 X.509 records from the previous image, with no invented tombstone metadata."""
import argparse,hashlib,json,pathlib,ssl,tempfile
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import rsa
from image_evidence import source_commit,local_image_id
from test_database import ContainerServer
from test_runtime import ROOT,Server,free_port
from test_runtime import sha
from wire import *


def main():
    p=argparse.ArgumentParser();p.add_argument('--older-image',required=True);p.add_argument('--engine',default='podman');a=p.parse_args()
    binary_hash=sha(ROOT/'target/debug/keytend-kmip-server');older=local_image_id(a.engine,a.older_image)
    out=ROOT/'artifacts/certificate-upgrade';out.mkdir(exist_ok=True);passed=[]
    def done(message):passed.append(message);print('PASS',message,flush=True)
    with tempfile.TemporaryDirectory(prefix='keytend-certificate-upgrade-') as directory:
        s=ContainerServer(directory,a.engine,a.older_image);native=False
        der=ssl.PEM_cert_to_DER_cert((s.pki/'server.pem').read_text());oracle=x509.load_der_x509_certificate(der);key=oracle.public_key()
        algorithm=4 if isinstance(key,rsa.RSAPublicKey) else 6
        signature={'1.2.840.113549.1.1.11':5,'1.2.840.10045.4.3.2':14}[oracle.signature_algorithm_oid.dotted_string]
        certificate=structure(0x420013,enumeration(0x42001d,1),binary(0x42001e,der))
        expected=[enumeration(0x42001d,1),integer(0x4200ad,len(der)),enumeration(0x420028,algorithm),integer(0x42002a,key.key_size),integer(0x42002c,0),enumeration(0x4200ae,signature)]
        fixture=out/'original.der';fixture.write_bytes(der)
        def rpc(c,operation,fields):return exchange(c,request(operation,fields,v=(2,1)))
        def attributes(c,identifier):
            result=payload(rpc(c,11,[uid(identifier)]+[enumeration(0x42013b,n[0]) for n in expected]));collections=children(result,0x420125)
            return {n[0]:n for n in collections[0][2]} if collections else {}
        def check(c,identifier):
            assert get(payload(rpc(c,10,[uid(identifier)])),0x420013)==certificate
            assert attributes(c,identifier)=={n[0]:n for n in expected}
        try:
            s.start()
            with s.connect() as c:
                register=lambda:get(payload(rpc(c,3,[enumeration(0x420057,1),certificate])),0x420094)[2]
                live,destroyed=register(),register()
                assert not attributes(c,live), 'old source unexpectedly supplied mandatory metadata'
                parts=[n[2] for n in children(payload(rpc(c,40,[enumeration(0x420057,5),uid(live),integer(0x42008b,3),integer(0x42008c,2),enumeration(0x42008a,4),structure(0x420125)])),0x420094)]
                payload(rpc(c,20,[uid(destroyed)]))
            done('previous immutable image created live, destroyed and shared certificates without mandatory metadata; earlier permissive Register behavior reproduced')
            s.stop();s.port=free_port();s.health=free_port();native=True;Server.start(s)
            with s.connect() as c:
                check(c,live);done('current native server derives live X.509 metadata from actual previous-image DER and preserves exact bytes')
                joined=get(payload(rpc(c,41,[enumeration(0x420057,1),uid(parts[0]),uid(parts[2]),structure(0x420125)])),0x420094)[2]
                check(c,joined);done('old local share provenance reconstructs a fresh certificate with exact bytes and derived metadata')
                known=attributes(c,destroyed)
                assert 0x4200ad not in known and 0x4200ae not in known
                done('missing certificate length and signature metadata are not invented for an old destroyed record')
                exported=payload(rpc(c,43,[uid(destroyed)]))
                assert reason(rpc(c,42,[*exported[2],node(0x420124,6,True)]))==6
                done('incomplete destroyed Certificate Import is rejected rather than inventing required metadata')
                fields=[]
                for n in exported[2]:
                    if n[0]==0x420125:
                        wanted={x[0] for x in expected};n=structure(0x420125,*[x for x in n[2] if x[0] not in wanted],*expected)
                    fields.append(n)
                payload(rpc(c,42,[*fields,node(0x420124,6,True)]));assert attributes(c,destroyed)=={n[0]:n for n in expected}
                done('explicit owner restore supplies missing tombstone metadata extracted from the retained original certificate')
            Server.stop(s);Server.start(s)
            with s.connect() as c:
                check(c,live);check(c,joined);assert attributes(c,destroyed)=={n[0]:n for n in expected}
            done('derived live metadata and explicitly repaired tombstone metadata survive native restart')
            import sqlite3
            db=sqlite3.connect(s.data/'kmip.sqlite');version=db.execute('PRAGMA user_version').fetchone()[0];db.close();assert version==15
            done('existing encrypted schema 15 remains schema 15; no new storage fields or fabricated migration values')
        finally:
            if native:Server.stop(s)
            else:s.stop()
    report=dict(status='passed',scope='Real previous-image schema-15 X.509 admission/read/share/tombstone upgrade; numeric TLS driver, not independent SDK coverage',source_commit=source_commit()[0],runtime_binary_sha256=binary_hash,older_image_config_id=older,older_storage_schema=15,current_storage_schema=15,fixture_sha256={str(fixture.relative_to(ROOT)):sha(fixture)},passed=passed)
    (out/'native.json').write_text(json.dumps(report,indent=2)+'\n')

if __name__=='__main__':main()
