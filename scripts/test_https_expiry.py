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

"""A real client certificate expires while its authenticated HTTP connection lives."""
import argparse,datetime,hashlib,http.client,json,shutil,ssl,tempfile,time
from cryptography import x509
from cryptography.hazmat.primitives import hashes,serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID,NameOID
from image_evidence import local_image_id,packaged_evidence,source_commit
from https_client import HttpsServer,HttpsContainer,context,encoded,decoded
from test_runtime import sha
from test_runtime import ROOT
from wire import *

def main():
    p=argparse.ArgumentParser();p.add_argument('--image');p.add_argument('--engine',default='podman');a=p.parse_args()
    binary=sha(ROOT/'target/debug/keytend-kmip-server')
    image_id=local_image_id(a.engine,a.image) if a.image else None;image=packaged_evidence(image_id) if image_id else {}
    with tempfile.TemporaryDirectory(prefix='keytend-https-expiry-') as directory:
        s=HttpsContainer(directory,a.engine,a.image) if a.image else HttpsServer(directory)
        for ext in ['pem','key']:shutil.copyfile(s.pki/f'client.{ext}',s.pki/f'controller.{ext}')
        issuer=x509.load_pem_x509_certificate((s.pki/'ca.pem').read_bytes())
        issuer_key=serialization.load_pem_private_key((s.pki/'ca.key').read_bytes(),password=None)
        key=ec.generate_private_key(ec.SECP256R1());now=datetime.datetime.now(datetime.timezone.utc);expires=now+datetime.timedelta(seconds=20)
        cert=x509.CertificateBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,'https-expiry-test')])).issuer_name(issuer.subject).public_key(key.public_key()).serial_number(x509.random_serial_number()).not_valid_before(now-datetime.timedelta(days=1)).not_valid_after(expires).add_extension(x509.BasicConstraints(ca=False,path_length=None),critical=True).add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]),critical=False).add_extension(x509.KeyUsage(digital_signature=True,content_commitment=False,key_encipherment=False,data_encipherment=False,key_agreement=False,key_cert_sign=False,crl_sign=False,encipher_only=False,decipher_only=False),critical=True).sign(issuer_key,hashes.SHA256())
        (s.pki/'client.pem').write_bytes(cert.public_bytes(serialization.Encoding.PEM));(s.pki/'client.key').write_bytes(key.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption()));(s.pki/'client.key').chmod(0o600)
        policy_path=s.pki/'policy.json';policy=json.loads(policy_path.read_text());original=hashlib.sha256(ssl.PEM_cert_to_DER_cert((s.pki/'controller.pem').read_text())).hexdigest();policy['principals'][cert.fingerprint(hashes.SHA256()).hex()]=policy['principals'][original];policy_path.write_text(json.dumps(policy))
        if a.image:shutil.copyfile(policy_path,s.tls/'policy.json')
        c=None
        try:
            s.start()
            with s.connect(identity='controller') as control:before=len(children(payload(exchange(control,request(8,v=(2,1)))),0x420094))
            c=http.client.HTTPSConnection('localhost',s.https,context=context(s),timeout=5)
            query=encoded(request(24,[enumeration(0x420074,1)],(2,1)),'JSON')
            headers={'Content-Type':'application/json','Cache-Control':'no-cache'}
            c.request('POST','/kmip',query,headers);r=c.getresponse();assert r.status==200;payload(decoded(r.read(),'JSON'));connection=c.sock;assert connection is not None
            while time.time()<cert.not_valid_after_utc.timestamp()-2:
                c.request('POST','/kmip',query,headers);r=c.getresponse();assert r.status==200;payload(decoded(r.read(),'JSON'))
                assert c.sock is connection,'authenticated connection was replaced'
                time.sleep(.5)
            until=cert.not_valid_after_utc.timestamp()+1
            while time.time()<=until:time.sleep(min(.2,until-time.time()+.01))
            create=encoded(request(1,[enumeration(0x420057,2),structure(0x420125,enumeration(0x420028,3),integer(0x42002a,256),integer(0x42002c,12))],(2,1)),'JSON')
            assert c.sock is connection,'authenticated connection was replaced'
            c.request('POST','/kmip',create,headers);r=c.getresponse();assert r.status==403;assert r.read()==b'Forbidden'
            with s.connect(identity='controller') as control:
                after=len(children(payload(exchange(control,request(8,v=(2,1)))),0x420094));assert after==before
        finally:
            if c:c.close()
            s.stop()
    result={'status':'passed',**(image if a.image else {'runtime_binary_sha256':binary,'source_commit':source_commit()[0]}),'certificate_not_after':cert.not_valid_after_utc.isoformat(),'same_authenticated_connection':True,'post_expiry_status':403,'post_expiry_create_did_not_mutate':True}
    out=ROOT/'artifacts'/('https-expiry-image.json' if a.image else 'https-expiry.json');out.write_text(json.dumps(result,indent=2)+'\n')
    print('PASS real certificate expiry on persistent HTTPS connection: 403 before Create; independent authorized controller still works')
if __name__=='__main__':main()
