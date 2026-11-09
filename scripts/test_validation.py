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


"""Exercise explicit Validate trust over real TLS; optional unchanged Java SDK codec."""
import argparse,concurrent.futures,datetime,hashlib,json,os,shutil,ssl,subprocess,tempfile,time,uuid
from cryptography import x509
from cryptography.hazmat.primitives import hashes,serialization
from cryptography.hazmat.primitives.asymmetric import ec,rsa
from cryptography.x509.oid import NameOID,ObjectIdentifier
from image_evidence import local_image_id,packaged_evidence,source_commit
from test_database import ContainerServer
from test_runtime import ROOT,Server
from test_runtime import sha
import keytend_kmip_release
from wire import *

class ValidationServer(Server):
    use_trust=False
    def start(self):
        previous=os.environ.pop('KMIP_VALIDATION_CA',None)
        if self.use_trust:os.environ['KMIP_VALIDATION_CA']=str(self.pki/'validation-ca.pem')
        try:super().start()
        finally:
            os.environ.pop('KMIP_VALIDATION_CA',None)
            if previous is not None:os.environ['KMIP_VALIDATION_CA']=previous
class ValidationContainer(ContainerServer):
    use_trust=False
    def base(self):return super().base()+(['-e','KMIP_VALIDATION_CA=/tls/validation-ca.pem'] if self.use_trust else [])

def fixtures(pki):
    at=datetime.datetime.now(datetime.timezone.utc)
    def issue(name,serial,issuer=None,ca=False,large=False):
        key=ec.generate_private_key(ec.SECP256R1());subject=x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,name)])
        parent,pkey=issuer if issuer else (None,key)
        builder=x509.CertificateBuilder().subject_name(subject).issuer_name(parent.subject if parent else subject).public_key(key.public_key()).serial_number(serial).not_valid_before(at-datetime.timedelta(days=1)).not_valid_after(at+datetime.timedelta(days=7)).add_extension(x509.BasicConstraints(ca=ca,path_length=None),critical=True).add_extension(x509.KeyUsage(digital_signature=not ca,content_commitment=False,key_encipherment=False,data_encipherment=False,key_agreement=False,key_cert_sign=ca,crl_sign=ca,encipher_only=False,decipher_only=False),critical=True).add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()),critical=False).add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(pkey.public_key()),critical=False)
        if large:builder=builder.add_extension(x509.UnrecognizedExtension(ObjectIdentifier('1.2.3.4.5'),b'x'*(60*1024)),critical=False)
        return builder.sign(pkey,hashes.SHA256()),key
    root,rkey=issue('explicit-validation-root',1,ca=True);inter,ikey=issue('validation-intermediate',2,(root,rkey),True);leaf,_=issue('validation-leaf',3,(inter,ikey));rogue,_=issue('request-rogue-root',4,ca=True);large,_=issue('large-validation-leaf',5,(root,rkey),large=True)
    values={name:cert.public_bytes(serialization.Encoding.DER) for name,cert in [('root',root),('intermediate',inter),('leaf',leaf),('rogue',rogue),('large',large)]}
    for name,der in values.items():(pki/('validation-'+name+'.der')).write_bytes(der)
    (pki/'validation-ca.pem').write_bytes(root.public_bytes(serialization.Encoding.PEM));(pki/'validation-rogue.pem').write_bytes(rogue.public_bytes(serialization.Encoding.PEM));return values

def certificate(der):return structure(0x420013,enumeration(0x42001d,1),binary(0x42001e,der))
def call(s,v,fields,op=23,identity='client'):
    with s.connect(identity=identity) as c:return exchange(c,request(op,fields,v))
def validity(r):return get(payload(r),0x42009b)[2]
def register(s,v,der):
    cert=x509.load_der_x509_certificate(der);key=cert.public_key()
    attrs=[enumeration(0x420028,4 if isinstance(key,rsa.RSAPublicKey) else 6),integer(0x42002a,key.key_size),integer(0x42002c,0)]
    if v>=(1,1):attrs.append(integer(0x4200ad,len(der)))
    if v[0]==1:
        names={0x420028:'Cryptographic Algorithm',0x42002a:'Cryptographic Length',0x42002c:'Cryptographic Usage Mask',0x4200ad:'Certificate Length'}
        container=structure(0x420091,*[structure(0x420008,text(0x42000a,names[a[0]]),(0x42000b,a[1],a[2])) for a in attrs])
    else:container=structure(0x420125,*attrs)
    return get(payload(call(s,v,[enumeration(0x420057,1),container,certificate(der)],3)),0x420094)[2]
def configure(s,enabled):
    s.stop();s.use_trust=enabled
    if isinstance(s,ContainerServer):shutil.copyfile(s.pki/'validation-ca.pem',s.tls/'validation-ca.pem')
    s.start()
def run(s,certs,editions):
    default=[]
    for v in editions:
        assert validity(call(s,v,[certificate(certs['leaf']),certificate(certs['intermediate']),certificate(certs['root'])]))==3
        default.append('.'.join(map(str,v)))
    configure(s,True);versions=[];last=None
    for v in editions:
        fields=[certificate(certs['root']),certificate(certs['leaf']),certificate(certs['intermediate'])]
        assert validity(call(s,v,fields))==1
        lid=register(s,v,certs['leaf']);iid=register(s,v,certs['intermediate']);last=(v,lid,iid)
        assert validity(call(s,v,[uid(iid,v),uid(lid,v)]))==1
        assert validity(call(s,v,[uid(lid,v),certificate(certs['intermediate'])]))==1
        denied=call(s,v,[uid(lid,v),uid(iid,v)],identity='other');assert status(denied)==1 and reason(denied)==1
        assert validity(call(s,v,[*fields,node(0x42009a,9,int(time.time()+86400*20))]))==2
        assert validity(call(s,v,[*fields,certificate(certs['rogue'])]))==2
        assert validity(call(s,v,[certificate(certs['rogue'])]))==2
        bad=bytearray(certs['leaf']);bad[-1]^=1
        assert validity(call(s,v,[certificate(bytes(bad)),certificate(certs['intermediate'])]))==2
        invalid=call(s,v,[]);assert status(invalid)==1 and reason(invalid)==7
        invalid=call(s,v,[*fields,integer(0x42009a,1)]);assert status(invalid)==1 and reason(invalid)==7
        invalid=call(s,v,[certificate(b'x'*65537)]);assert status(invalid)==1 and reason(invalid)==2
        versions.append({'wire_version':'.'.join(map(str,v)),'inline_stored_mixed_unordered':True,'other_owner_denied':True,'requested_expiry_enforced':True,'whole_chain_required':True,'request_root_not_trusted':True,'corrupt_signature_invalid':True,'empty_wrong_date_and_work_bound_rejected':True})
    v=(2,1);large=[register(s,v,certs['large']) for _ in range(18)];invalid=call(s,v,[uid(id,v) for id in large]);assert status(invalid)==1 and reason(invalid)==2
    invalid=call(s,v,[uid(large[0],v)]*33);assert status(invalid)==1 and reason(invalid)==2
    # Application trust changes independently of transport CA; it is loaded at restart.
    original=(s.pki/'validation-ca.pem').read_bytes();(s.pki/'validation-ca.pem').write_bytes((s.pki/'validation-rogue.pem').read_bytes());configure(s,True)
    v,lid,iid=last;assert validity(call(s,v,[uid(lid,v),uid(iid,v)]))==2
    (s.pki/'validation-ca.pem').write_bytes(original);configure(s,True)
    assert validity(call(s,v,[uid(lid,v),uid(iid,v)]))==1
    retrieved=payload(call(s,v,[uid(lid,v)],10));assert get(get(retrieved,0x420013),0x42001e)[2]==certs['leaf']
    # Concurrent requests must not share verification dates or mutable path state.
    def worker(index):
        for step in range(16):
            expired=(index+step)%2==1
            fields=[uid(lid,v),uid(iid,v),node(0x42009a,9,int(time.time()+(86400*20 if expired else 0)))]
            assert validity(call(s,v,fields))==(2 if expired else 1)
        return 16
    with concurrent.futures.ThreadPoolExecutor(max_workers=16) as pool:assert sum(pool.map(worker,range(16)))==256
    return {'versions':versions,'no_configured_trust_unknown_editions':default,'concurrent_date_isolation':{'workers':16,'requests':256,'expected_valid_and_expired':True},'stored_chain_total_byte_limit':True,'repeated_uid_count_limit':True,'controlled_trust_reload_preserves_certificates':True}

def startup_failures(s):
    path=s.pki/'validation-ca.pem';original=path.read_bytes();results=[]
    try:
        for name,bad in [('malformed',b'not a PEM root'),('oversized',b'x'*(1024*1024+1)),('duplicate',original+original)]:
            path.write_bytes(bad)
            container=isinstance(s,ContainerServer)
            if container:shutil.copyfile(path,s.tls/'validation-ca.pem')
            prefix='/tls/' if container else str(s.pki)+'/'
            database='/data/invalid-validation.sqlite' if container else str(s.data/'invalid-validation.sqlite')
            args=['serve','--listen','127.0.0.1:0','--health-listen','127.0.0.1:0','--cert',prefix+'server.pem','--key',prefix+'server.key','--ca',prefix+'ca.pem','--policy',prefix+'policy.json','--master-key',prefix+'master.key','--database',database,'--validation-ca',prefix+'validation-ca.pem']
            owned='keytend-invalid-trust-'+uuid.uuid4().hex[:12]
            command=s.base()+['--name',owned,s.image]+args if container else [s.binary]+args
            try:
                response=subprocess.run(command,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,timeout=10)
                assert response.returncode!=0 and b'validation trust' in response.stdout,response.stdout.decode(errors='replace')
                assert not (s.data/'invalid-validation.sqlite').exists(),'invalid trust configuration created storage'
                results.append({'case':name,'startup_rejected':True,'store_not_created':True,'error_sha256':hashlib.sha256(response.stdout).hexdigest()})
            finally:
                if container:subprocess.run([s.engine,'rm','--force',owned],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    finally:
        path.write_bytes(original)
        if isinstance(s,ContainerServer):shutil.copyfile(path,s.tls/'validation-ca.pem')
    return results

def main():
    p=argparse.ArgumentParser();p.add_argument('--image');p.add_argument('--engine',default='podman');p.add_argument('--java',action='append',default=[]);a=p.parse_args()
    runtime=packaged_evidence(local_image_id(a.engine,a.image)) if a.image else {'runtime_binary_sha256':sha(ROOT/'target/debug/keytend-kmip-server'),'source_commit':source_commit()[0]}
    editions=[(1,0),(1,1),(1,2),(1,3),(1,4),(2,0),(2,1)]+([] if a.image else [(3,0)]);lanes=[]
    with tempfile.TemporaryDirectory(prefix='keytend-validation-') as directory:
        s=ValidationContainer(directory,a.engine,a.image) if a.image else ValidationServer(directory,draft=True);values=fixtures(s.pki)
        policy_path=s.pki/'policy.json';policy=json.loads(policy_path.read_text());fingerprint=hashlib.sha256(ssl.PEM_cert_to_DER_cert((s.pki/'other.pem').read_text())).hexdigest();policy['principals'][fingerprint]['operations'].append(23);policy_path.write_text(json.dumps(policy))
        if a.image:shutil.copyfile(policy_path,s.tls/'policy.json')
        try:
            startup=startup_failures(s)
            s.start();results=run(s,values,editions)
            if a.java:
                # The signed keytend-kmip release; the adapter compiled against it.
                _,_,artifact=keytend_kmip_release.release();PIN=artifact['commit']
                subprocess.run(['openssl','pkcs12','-export','-in',str(s.pki/'client.pem'),'-inkey',str(s.pki/'client.key'),'-certfile',str(s.pki/'ca.pem'),'-out',str(s.pki/'client.p12'),'-passout','pass:changeit'],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
                classpath=keytend_kmip_release.adapters(['ServerValidation'],ROOT/'.cache/java-validation-adapter',a.java[0])
                for j,java in enumerate(a.java):
                    jdk=subprocess.check_output([java,'-version'],stderr=subprocess.STDOUT,text=True).splitlines()[0]
                    for version in ['1.1','1.2','1.3','1.4','2.0','2.1']:
                        command=[java,'-cp',classpath,'dev.keytend.kmip.interop.ServerValidation',str(s.pki),str(s.port),version]
                        result=subprocess.run(command,check=True,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True,timeout=60)
                        log=ROOT/'artifacts'/f'validation-java-{version}-jdk{j}.log';log.write_text(result.stdout);lanes.append({'wire_version':version,'jdk':jdk,'status':'passed','client_commit':PIN,'log':str(log.relative_to(ROOT)),'log_sha256':sha(log)})
        finally:s.stop()
    name='validation-image.json' if a.image else 'validation.json'
    record={'status':'passed',**runtime,'invalid_trust_startup':startup,**results,'java_sdk_lanes':lanes,'limits':['Explicit root trust and path/date/key-strength policy; no AIA fetching, CRL or OCSP assertion','Supplemental SDK Validate and Java PKIX probes; unchanged 164-case catalog outcomes are separate']}
    (ROOT/'artifacts'/name).write_text(json.dumps(record,indent=2)+'\n');print('PASS Validate real TLS',len(editions),'editions;',len(lanes),'Java SDK/PKIX lanes')
if __name__=='__main__':main()
