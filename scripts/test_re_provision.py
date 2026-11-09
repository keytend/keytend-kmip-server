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

"""Re-Provision against the real TLS binary (docs/re-provision.md).

Startup refusals of the provisioning CA; the no-parameter form with the
minimum allowlist and no database inspection, through to the reconnect; the
certificate-request form over HTTPS; a client whose certificate comes from an
intermediate it sends itself (root-only trust); old certificates refused on
new connections while open connections continue; restarts with and without
the flags; and the lockout recovery runbook. Independent wire harness, not a
production client library.
"""
import argparse,datetime,hashlib,http.client,json,os,pathlib,shutil,socket,ssl,subprocess,tempfile,time
from cryptography import x509
from cryptography.hazmat.primitives import hashes,serialization
from cryptography.hazmat.primitives.asymmetric import ec,rsa
from cryptography.x509.oid import ExtendedKeyUsageOID,NameOID
from test_runtime import ROOT,Server,free_port,sha
from wire import *

V21=(2,1)
ATTRIBUTE_REFERENCE=0x42013b;LINK=0x42004a;LINK_TYPE=0x42004b;LINKED=0x42004c
CERTIFICATE=0x420013;CERTIFICATE_TYPE=0x42001d;CERTIFICATE_VALUE=0x42001e
CERTIFICATE_REQUEST=0x420018;REQUEST_TYPE=0x420019;REQUEST_VALUE=0x420140
PRIVATE_KEY=0x420064;UID=0x420094;ATTRIBUTES=0x420125;OBJECT_TYPE=0x420057

def now():return datetime.datetime.now(datetime.timezone.utc)
def name(cn):return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,cn)])
def fingerprint(cert):return hashlib.sha256(cert.public_bytes(serialization.Encoding.DER)).hexdigest()
def issue(cn,key,issuer,issuer_key,ca=False,dns=None,server=False,days=7,digest=None):
    b=(x509.CertificateBuilder().subject_name(name(cn)).issuer_name(issuer.subject if issuer else name(cn))
        .public_key(key.public_key()).serial_number(x509.random_serial_number())
        .not_valid_before(now()-datetime.timedelta(minutes=5)).not_valid_after(now()+datetime.timedelta(days=days))
        .add_extension(x509.BasicConstraints(ca=ca,path_length=0 if ca and issuer else None),critical=True))
    if ca:b=b.add_extension(x509.KeyUsage(digital_signature=False,content_commitment=False,key_encipherment=False,data_encipherment=False,key_agreement=False,key_cert_sign=True,crl_sign=True,encipher_only=False,decipher_only=False),critical=True)
    else:
        b=b.add_extension(x509.KeyUsage(digital_signature=True,content_commitment=False,key_encipherment=isinstance(key,rsa.RSAPrivateKey),data_encipherment=False,key_agreement=False,key_cert_sign=False,crl_sign=False,encipher_only=False,decipher_only=False),critical=True)
        b=b.add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH if server else ExtendedKeyUsageOID.CLIENT_AUTH]),critical=False)
    if dns:b=b.add_extension(x509.SubjectAlternativeName([x509.DNSName(n) for n in dns]+([x509.IPAddress(__import__('ipaddress').ip_address('127.0.0.1'))] if server else [])),critical=False)
    return b.sign(issuer_key or key,digest or hashes.SHA256())
def pem(cert):return cert.public_bytes(serialization.Encoding.PEM)
def key_pem(key):return key.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption())
def write_identity(pki,label,cert,key,chain=()):
    (pki/f'{label}.pem').write_bytes(pem(cert)+b''.join(pem(c) for c in chain))
    path=pki/f'{label}.key';path.write_bytes(key_pem(key));path.chmod(0o600)
def load_ca(pki):
    return x509.load_pem_x509_certificate((pki/'ca.pem').read_bytes()),serialization.load_pem_private_key((pki/'ca.key').read_bytes(),None)
def policy(pki):return json.loads((pki/'policy.json').read_text())
def save_policy(pki,p):(pki/'policy.json').write_text(json.dumps(p,indent=2)+'\n')

def batch(items,v=V21):
    header=structure(0x420077,version(v),integer(0x42000d,len(items)))
    return structure(0x420078,header,*[structure(0x42000f,enumeration(0x42005c,op),binary(0x420093,bytes([i])),structure(0x420079,*p)) for i,(op,p) in enumerate(items)])
def items(r):return children(r,0x42000f)
def item_status(i):return get(i,0x42007f)[2]
def item_payload(i):
    assert item_status(i)==0,repr(i);return get(i,0x42007c)
def csr_node(key,cn='intruder'):
    request=x509.CertificateSigningRequestBuilder().subject_name(name(cn)).add_extension(x509.SubjectAlternativeName([x509.DNSName('evil.example')]),critical=False).sign(key,hashes.SHA256())
    return structure(CERTIFICATE_REQUEST,enumeration(REQUEST_TYPE,2),binary(REQUEST_VALUE,request.public_bytes(serialization.Encoding.DER)))
def generated(c):
    """[Re-Provision, Get(ph), Get Attributes(ph, Link)]: the key and the certificate identifier."""
    r=exchange(c,batch([(53,[]),(10,[]),(11,[enumeration(ATTRIBUTE_REFERENCE,LINK)])]))
    reprovision,key,attributes=items(r)
    key_id=get(item_payload(reprovision),UID)[2];assert get(item_payload(key),UID)[2]==key_id
    der=get(get(get(get(item_payload(key),PRIVATE_KEY),0x420040),0x420045),0x420043)[2]
    links=[l for l in children(get(item_payload(attributes),ATTRIBUTES),LINK) if get(l,LINK_TYPE)[2]==0x10c]
    return key_id,serialization.load_der_private_key(der,None),get(links[0],LINKED)[2]
def certificate_of(c,id):
    p=payload(exchange(c,request(10,[uid(id,V21)],V21)))
    return x509.load_der_x509_certificate(get(get(p,CERTIFICATE),CERTIFICATE_VALUE)[2])
def refused_unlisted(s,label):
    """A new connection with a retired certificate: the TLS handshake completes, one Permission Denied answer, then close."""
    with s.connect(identity=label) as c:
        r=exchange(c,request(24,[enumeration(0x420074,1)],V21))
        assert status(r)==1 and reason(r)==12,r
        try:c.sendall(encode(request(24,[enumeration(0x420074,1)],V21)));recv_exact(c,8)
        except (OSError,EOFError):pass
        else:raise AssertionError('the connection stayed open for a retired certificate')
def located(c,v=V21):return [n[2] for n in children(payload(exchange(c,request(8,[],v))),UID)]
def offered(c):return [n[2] for n in children(payload(exchange(c,request(24,[enumeration(0x420074,1)],V21))),0x42005c)]

def https(s,label,message):
    """One TTLV request over the HTTPS listener on a fresh connection."""
    ctx=ssl.create_default_context(cafile=str(s.pki/'ca.pem'));ctx.load_cert_chain(s.pki/f'{label}.pem',s.pki/f'{label}.key')
    conn=http.client.HTTPSConnection('127.0.0.1',s.https,context=ctx,timeout=10)
    try:
        conn.request('POST','/kmip',body=encode(message),headers={'Content-Type':'application/octet-stream','Host':'localhost'})
        response=conn.getresponse();body=response.read();assert response.status==200,(response.status,body)
        return decode(body)
    finally:conn.close()

def serve_args(s,extra):
    return [s.binary,'serve','--listen',f'127.0.0.1:{free_port()}','--health-listen',f'127.0.0.1:{free_port()}','--policy',str(s.pki/'policy.json'),'--database',str(s.root/'refused.sqlite'),'--master-key',str(s.pki/'master.key')]+extra
def refused_start(s,extra,expected):
    r=subprocess.run(serve_args(s,extra),stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True,timeout=60)
    assert r.returncode!=0 and expected in r.stdout,(r.returncode,r.stdout[-2000:])
def starts(s,extra):
    process=subprocess.Popen(serve_args(s,extra),stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True)
    try:
        time.sleep(3);assert process.poll() is None,process.stdout.read()
    finally:
        process.terminate();process.wait(timeout=25)

def startup(s,results):
    pki=s.pki;ca,ca_key=load_ca(pki);tls=['--cert',str(pki/'server.pem'),'--key',str(pki/'server.key')]
    flags=lambda c,k:['--provisioning-ca',str(c),'--provisioning-ca-key',str(k)]
    r=subprocess.run(serve_args(s,tls+['--ca',str(pki/'ca.pem'),'--provisioning-ca',str(pki/'ca.pem')]),stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True,timeout=60)
    assert r.returncode==2 and 'provisioning-ca-key' in r.stdout,r.stdout
    loose=s.root/'loose.key';shutil.copyfile(pki/'ca.key',loose);loose.chmod(0o644)
    refused_start(s,tls+['--ca',str(pki/'ca.pem')]+flags(pki/'ca.pem',loose),'other users')
    # A dedicated provisioning CA beside the client CA, in the --ca bundle.
    sub_key=rsa.generate_private_key(public_exponent=65537,key_size=2048);sub=issue('provisioning only',sub_key,None,None,ca=True)
    (pki/'sub.pem').write_bytes(pem(sub));(pki/'sub.key').write_bytes(key_pem(sub_key));(pki/'sub.key').chmod(0o600)
    bundle=s.root/'bundle.pem';bundle.write_bytes((pki/'ca.pem').read_bytes()+pem(sub))
    refused_start(s,tls+['--ca',str(pki/'ca.pem')]+flags(pki/'sub.pem',pki/'sub.key'),'--ca bundle')
    starts(s,tls+['--ca',str(bundle)]+flags(pki/'sub.pem',pki/'sub.key'))
    # --crl without a CRL from the provisioning CA: CRL_CHECK_ALL would
    # refuse every certificate it issues.
    def crl(issuer,key):
        return (x509.CertificateRevocationListBuilder().issuer_name(issuer.subject).last_update(now()-datetime.timedelta(minutes=5))
            .next_update(now()+datetime.timedelta(days=1)).sign(key,hashes.SHA256())).public_bytes(serialization.Encoding.PEM)
    client_only=s.root/'client-only.crl';client_only.write_bytes(crl(ca,ca_key))
    refused_start(s,tls+['--ca',str(bundle),'--crl',str(client_only)]+flags(pki/'sub.pem',pki/'sub.key'),"listener's verification")
    both=s.root/'both.crl';both.write_bytes(crl(ca,ca_key)+crl(sub,sub_key))
    starts(s,tls+['--ca',str(bundle),'--crl',str(both)]+flags(pki/'sub.pem',pki/'sub.key'))
    # A Suite B 192 profile with an RSA provisioning CA.
    b_key=ec.generate_private_key(ec.SECP384R1());b_ca=issue('suite b ca',b_key,None,None,ca=True,digest=hashes.SHA384())
    server_key=ec.generate_private_key(ec.SECP384R1());server=issue('localhost',server_key,b_ca,b_key,dns=['localhost'],server=True,digest=hashes.SHA384())
    write_identity(pki,'suite-b-server',server,server_key)
    suite_b=s.root/'suite-b.pem';suite_b.write_bytes(pem(b_ca)+pem(sub))
    b_tls=['--cert',str(pki/'suite-b-server.pem'),'--key',str(pki/'suite-b-server.key'),'--ca',str(suite_b),'--tls-profile','kmip-1-suite-b-192']
    starts(s,b_tls)
    refused_start(s,b_tls+flags(pki/'sub.pem',pki/'sub.key'),"listener's verification")
    results.append('startup refuses a world-readable CA key, a CA outside --ca, a CRL set without the CA, and an RSA CA under Suite B 192')

def run(s,results):
    pki=s.pki;ca,ca_key=load_ca(pki);p=policy(pki)
    identities={}
    def principal(label,key,ops,issuer=(ca,ca_key),chain=()):
        cert=issue(label,key,issuer[0],issuer[1],dns=[label+'.example'])
        write_identity(pki,label,cert,key,chain);identities[label]=cert
        p['principals'][fingerprint(cert)]={'name':label,'operations':ops}
    # The minimum allowlist for the no-parameter form.
    principal('minimal',rsa.generate_private_key(public_exponent=65537,key_size=2048),[10,11,53])
    principal('csr',ec.generate_private_key(ec.SECP256R1()),[1,8,10,53])
    principal('recover',rsa.generate_private_key(public_exponent=65537,key_size=2048),[1,8,10,11,53])
    # An intermediate that only the client sends; --ca holds the root.
    inter_key=ec.generate_private_key(ec.SECP256R1());inter=issue('client intermediate',inter_key,ca,ca_key,ca=True)
    principal('chained',ec.generate_private_key(ec.SECP256R1()),[8,10,53],issuer=(inter,inter_key),chain=[inter])
    save_policy(pki,p)
    s.https=free_port()
    provisioning=['--provisioning-ca',str(pki/'ca.pem'),'--provisioning-ca-key',str(pki/'ca.key')]
    s.extra_args=['--https-listen',f'127.0.0.1:{s.https}']+provisioning
    s.start()
    with s.connect() as c:assert 53 in offered(c)
    results.append('Query lists Re-Provision with --provisioning-ca')
    # No parameters, minimum allowlist, no database inspection.
    with s.connect(identity='minimal') as old:
        key_id,new_key,cert_id=generated(old)
        new=certificate_of(old,cert_id)
        assert new.subject==identities['minimal'].subject and new.public_key().public_numbers()==new_key.public_key().public_numbers()
        assert new.public_key().key_size==2048 and new.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value==x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH])
        write_identity(pki,'minimal-new',new,new_key)
        assert reason(exchange(old,request(10,[uid(key_id,V21)],V21)))==0x37
        refused_unlisted(s,'minimal')
        # The open connection continues, but cannot re-provision again.
        assert certificate_of(old,cert_id)==new
        r=exchange(old,batch([(53,[csr_node(ec.generate_private_key(ec.SECP256R1()))]),(10,[])]))
        assert item_status(items(r)[0])==1 and get(items(r)[0],0x42007e)[2]==12
    with s.connect(identity='minimal-new') as c:assert certificate_of(c,cert_id)==new
    results.append('no-parameter form: key and certificate delivered, old certificate refused on new connections, open connection continues, new certificate accepted')
    # The certificate-request form over HTTPS.
    r=https(s,'csr',batch([(53,[csr_node(csr_key:=ec.generate_private_key(ec.SECP256R1()))]),(10,[])]))
    issued=x509.load_der_x509_certificate(get(get(item_payload(items(r)[1]),CERTIFICATE),CERTIFICATE_VALUE)[2])
    assert issued.subject==identities['csr'].subject
    assert issued.extensions.get_extension_for_class(x509.SubjectAlternativeName).value.get_values_for_type(x509.DNSName)==['csr.example']
    write_identity(pki,'csr-new',issued,csr_key)
    r=https(s,'csr',request(8,[],V21));assert status(r)==1 and reason(r)==12
    r=https(s,'csr-new',request(8,[],V21));assert len(children(payload(r),UID))==1
    results.append('certificate-request form over HTTPS: subject and SAN from the old certificate; old refused, new accepted')
    # Re-verification with the intermediate the client sent.
    with s.connect(identity='chained') as c:
        r=exchange(c,batch([(53,[csr_node(chained_key:=ec.generate_private_key(ec.SECP256R1()))]),(10,[])]))
        chained=x509.load_der_x509_certificate(get(get(item_payload(items(r)[1]),CERTIFICATE),CERTIFICATE_VALUE)[2])
    write_identity(pki,'chained-new',chained,chained_key)
    refused_unlisted(s,'chained')
    with s.connect(identity='chained-new') as c:assert len(located(c))==1
    results.append('a certificate from a client-sent intermediate (root-only trust) re-provisions; the new one chains to the provisioning CA')
    # Restart: retirement persists; the startup log lists the records.
    s.stop();s.start()
    refused_unlisted(s,'minimal')
    with s.connect(identity='minimal-new') as c:assert certificate_of(c,cert_id)==new
    log=(s.root/'server.log').read_text()
    assert log.count('provisioning record')>=6 and fingerprint(identities['minimal']) in log
    assert f"{fingerprint(identities['minimal'])} anchors active {fingerprint(new)}" in log
    # Without the flags: Re-Provision is not offered, retirement still holds.
    s.stop();s.extra_args=['--https-listen',f'127.0.0.1:{s.https}'];s.start()
    refused_unlisted(s,'minimal')
    with s.connect(identity='minimal-new') as c:assert certificate_of(c,cert_id)==new
    with s.connect() as c:assert 53 not in offered(c)
    results.append('restarts keep the retirement, with and without --provisioning-ca; the startup log lists the records and the anchor warning')
    # Lockout recovery (docs/re-provision.md#lockout-recovery).
    s.stop();s.extra_args=['--https-listen',f'127.0.0.1:{s.https}']+provisioning;s.start()
    with s.connect(identity='recover') as c:
        kept=get(payload(exchange(c,request(1,[enumeration(OBJECT_TYPE,2),structure(ATTRIBUTES,enumeration(0x420028,3),integer(0x42002a,256),integer(0x42002c,12))],V21))),UID)[2]
        generated(c)  # the client never fetches its new certificate
    refused_unlisted(s,'recover')
    fresh_key=rsa.generate_private_key(public_exponent=65537,key_size=2048)
    fresh=issue('recover',fresh_key,ca,ca_key,dns=['recover.example']);write_identity(pki,'recover-fresh',fresh,fresh_key)
    p=policy(pki);old_fp=fingerprint(identities['recover'])
    p['principals'][fingerprint(fresh)]=dict(p['principals'].pop(old_fp));save_policy(pki,p)
    s.stop();s.start()
    with s.connect(identity='recover-fresh') as c:assert kept in located(c)
    refused_unlisted(s,'recover')
    assert 'is refused: its anchor '+old_fp in (s.root/'server.log').read_text()
    results.append('lockout recovery: a fresh certificate under the same name in the policy, a restart, and the principal objects are reachable again')
    s.stop()

def main():
    parser=argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument('--skip-build',action='store_true');parser.add_argument('--binary',type=pathlib.Path)
    a=parser.parse_args()
    if not a.skip_build and not a.binary:subprocess.run(['cargo','build','--locked'],cwd=ROOT,check=True)
    binary=(a.binary or ROOT/'target/debug/keytend-kmip-server').resolve()
    from image_evidence import source_commit
    out=ROOT/'artifacts/re-provision';out.mkdir(parents=True,exist_ok=True)
    report=dict(status='running',source_commit=source_commit()[0],runtime_binary_sha256=sha(binary),passed=[])
    (out/'native.json').write_text(json.dumps(report,indent=2)+'\n')
    try:
        with tempfile.TemporaryDirectory(prefix='keytend-re-provision-') as d:
            s=Server(d,binary=binary)
            try:
                startup(s,report['passed']);run(s,report['passed'])
            finally:
                s.stop()
                if (s.root/'server.log').exists():shutil.copyfile(s.root/'server.log',out/'native-server.log')
        report['status']='passed'
    except BaseException as error:
        report.update(status='failed',error=repr(error));raise
    finally:(out/'native.json').write_text(json.dumps(report,indent=2)+'\n')
    for line in report['passed']:print('PASS',line)

if __name__=='__main__':main()
