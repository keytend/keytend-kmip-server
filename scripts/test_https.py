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

"""Real HTTPS/profile/adversarial tests plus optional independent SDK transports.

The small Python encoders only generate numeric tag/enum forms. JSON responses,
which carry tag and enumeration names (docs/interpretations.md), are
read with the independent Profiles-text codec. Full independent codec
interoperability is exercised by the unchanged Java and Go client SDKs.
"""
import argparse,datetime,hashlib,http.client,json,os,sqlite3,ssl,subprocess,tempfile,time,xml.etree.ElementTree as ET
import cryptography
from cryptography.hazmat.primitives.ciphers import Cipher,algorithms,modes
from image_evidence import local_image_id,packaged_evidence,source_commit
from test_database import ContainerServer
from test_runtime import sha
import keytend_kmip_release
from test_runtime import ROOT,Server,free_port
from wire import *
# Load the replay's registry-spelling fallback first (harness registry "Rekey"
# versus the normalized "ReKey" the server and the OASIS traces write).
import oasis_profile_replay  # noqa: F401
import profile_text_codec

from https_client import MEDIA,KINDS,HttpsServer,HttpsContainer,encoded,decoded,context,post  # noqa: F401

def run(s,editions):
    cases=[];versions=[]
    # Exercise names whose numeric fallbacks would hide registry-table defects.
    for fmt in ['JSON','XML']:
        n=structure(0x420078,structure(0x420077,version((2,1)),integer(0x42000d,2),enumeration(0x42000e,3)),
            structure(0x42000f,binary(0x420093,b'first'),enumeration(0x42005c,1),structure(0x420079,enumeration(0x420057,2),structure(0x420125,enumeration(0x420028,3),integer(0x42002a,256),integer(0x42002c,12)))),
            structure(0x42000f,binary(0x420093,b'second'),enumeration(0x42005c,10),structure(0x420079,text(0x420094,'symbolic-missing-key'))))
        data=encoded(n,fmt)
        names={0x42000e:{3:'Undo'},0x42005c:{1:'Create',10:'Get'},0x420057:{2:'SymmetricKey'},0x420028:{3:'AES'}}
        if fmt=='JSON':
            def symbolic(o):
                tag=int(o['tag'],16)
                if tag in names:o['value']=names[tag][int(o['value'],16)]
                if o['type']=='Structure':
                    for child in o['value']:symbolic(child)
            o=json.loads(data);symbolic(o);data=json.dumps(o).encode()
        else:
            o=ET.fromstring(data)
            for e in o.iter():
                tag=int(e.attrib['tag'],16)
                if tag in names:e.set('value',names[tag][int(e.attrib['value'],16)])
            data=ET.tostring(o)
        c=http.client.HTTPSConnection('localhost',s.https,context=context(s),timeout=5)
        try:
            c.request('POST','/kmip',data,{'Content-Type':MEDIA[fmt]});r=c.getresponse();assert r.status==200
            response=decoded(r.read(),fmt);assert [get(i,0x42007f)[2] for i in children(response,0x42000f)]==[3,1]
        finally:c.close()
    cases.append('named 2.1 operations, AES and Undo fields execute and roll back through JSON and XML')
    for v in editions:
        for fmt in MEDIA:
            attrs=[enumeration(0x420028,3),integer(0x42002a,256),integer(0x42002c,12)]
            attributes=structure(0x420091,*map(attr,attrs)) if v[0]==1 else structure(0x420125,*attrs)
            created=payload(post(s,request(1,[enumeration(0x420057,2),attributes],v),fmt))
            id=get(created,0x420094)[2]
            with s.connect() as c:key=key_value(c,id,v)
            assert len(key)==32
            for out in MEDIA:
                r=payload(post(s,request(10,[uid(id,v)],v),fmt,out))
                assert get(get(get(get(r,0x42008f),0x420040),0x420045),0x420043)[2]==key
            # REQ:51d684c791d650d7 1.0/1.1 the creator is the identity authenticated by the mTLS channel: another client cannot reach the object
            # REQ:791dac5c6b79c864 1.2 the owner is the identity authenticated by the mTLS channel: another client cannot reach the object
            # Another owner's object fails exactly like a missing one: 1.x Item Not
            # Found, 2.x/3.0 Object Not Found 0x37 (2.1 Table 222; docs/messages.md#unknown-identifiers).
            denied=post(s,request(10,[uid(id,v)],v),fmt,identity='other');assert status(denied)==1 and reason(denied)==(1 if v[0]==1 else 0x37)
            # REQ:ff6a9e3fd4a2594a the lifecycle runs over both HTTP/1.0 and HTTP/1.1 inside TLS
            payload(post(s,request(18,[uid(id,v)],v),fmt,http10=True))
            payload(post(s,request(19,[uid(id,v),structure(0x420081,enumeration(0x420082,1))],v),fmt))
            payload(post(s,request(20,[uid(id,v)],v),fmt))
            versions.append({'wire_version':'.'.join(map(str,v)),'encoding':fmt,'cross_encoding_outputs':list(MEDIA),'http10_lifecycle_http11_get':True,'same_binary_store':True,'other_owner_denied':True})
    cases.append('all requested editions and encodings: lifecycle, cross-encoding, binary-store identity, tenant isolation, HTTP/1.0 and HTTP/1.1')
    # Keep-alive and pipelined requests must have exact independent framing.
    query=encoded(request(24,[enumeration(0x420074,1)],(2,1)),'JSON')
    headers=b'POST /kmip HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: '+str(len(query)).encode()+b'\r\n\r\n'
    with connect(s.pki,s.https) as c:
        c.sendall((headers+query)*3)
        class Unbuffered:
            def makefile(self,mode):return c.makefile(mode,buffering=0)
        for _ in range(3):
            r=http.client.HTTPResponse(Unbuffered());r.begin();assert r.status==200;payload(decoded(r.read(),'JSON'))
    cases.append('HTTP/1.1 persistent pipelining preserves three response boundaries')
    # Header/body rejection happens before protocol execution.
    def raw(message):
        with connect(s.pki,s.https) as c:
            c.sendall(message);r=http.client.HTTPResponse(c);r.begin();r.read();return r.status
    checks=[
        ('wrong method',b'GET /kmip HTTP/1.1\r\nHost: localhost\r\n\r\n',405),
        ('wrong path',headers.replace(b'/kmip',b'/wrong')+query,404),
        ('query string',headers.replace(b'/kmip',b'/kmip?x=1')+query,404),
        ('missing host',headers.replace(b'Host: localhost\r\n',b'')+query,400),
        ('duplicate host',headers.replace(b'Host: localhost',b'Host: localhost\r\nHost: localhost')+query,400),
        ('missing length',headers.replace(b'Content-Length: '+str(len(query)).encode()+b'\r\n',b'')+query,411),
        ('conflicting length',headers.replace(b'Content-Length:',b'Content-Length: 1\r\nContent-Length:')+query,400),
        ('unsupported media',headers.replace(b'application/json',b'text/plain')+query,415),
        ('unsupported charset',headers.replace(b'application/json',b'application/json; charset=latin1')+query,415),
        ('unsupported accept',headers.replace(b'Content-Type:',b'Accept: image/png\r\nContent-Type:')+query,406),
        ('chunked forbidden',b'POST /kmip HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n',400),
        ('smuggling length plus chunked',headers.replace(b'Content-Type:',b'Transfer-Encoding: chunked\r\nContent-Type:')+query,400),
        ('large text',headers.replace(str(len(query)).encode(),b'8388609'),413),
        ('large TTLV',headers.replace(b'application/json',b'application/octet-stream').replace(str(len(query)).encode(),b'1048577'),413),
    ]
    for name,message,expected in checks:assert raw(message)==expected,name
    cases.append({'headers_rejected_before_execution':[name for name,_,_ in checks]})
    try:
        c=http.client.HTTPSConnection('localhost',s.https,context=context(s,'client',False),timeout=5)
        try:c.request('POST','/kmip',query,{'Content-Type':'application/json'});r=c.getresponse();r.read()
        finally:c.close()
    except (OSError,http.client.HTTPException):pass
    else:raise AssertionError('HTTPS accepted a TLS client without a certificate')
    # A CA-valid certificate without a policy entry gets the binary listener's
    # answer: a KMIP response with Permission Denied (reason 0x0c in every
    # edition), HTTP 200 because a KMIP response exists, then the connection closes.
    for fmt in ['JSON','XML','TTLV']:
        for v in [(1,4),(2,1)]:
            c=http.client.HTTPSConnection('localhost',s.https,context=context(s,'unlisted'),timeout=5)
            try:
                c.request('POST','/kmip',encoded(request(24,[enumeration(0x420074,1)],v),fmt),{'Content-Type':MEDIA[fmt]});r=c.getresponse()
                assert r.status==200 and r.getheader('Connection')=='close',(fmt,v,r.status)
                denied=decoded(r.read(),fmt);assert status(denied)==1 and reason(denied)==12,(fmt,v)
            finally:c.close()
    # REQ:c190e4961691def0 the HTTPS binding is HTTP over TLS with a trusted, listed client certificate
    cases.append('HTTPS requires a trusted mTLS client; an unlisted one gets KMIP Permission Denied')
    for fmt,bad in [('JSON',b'{"tag":"RequestMessage","tag":"RequestMessage","value":[]}'),('XML',b'<!DOCTYPE TTLV [<!ENTITY x SYSTEM "file:///etc/passwd">]><TTLV tag="RequestMessage"/>'),('XML',b'<TTLV tag="RequestMessage"/><TTLV tag="RequestMessage"/>'),('TTLV',b'not TTLV')]:
        c=http.client.HTTPSConnection('localhost',s.https,context=context(s),timeout=5)
        try:
            c.request('POST','/kmip',bad,{'Content-Type':MEDIA[fmt]});r=c.getresponse();assert r.status==200
            failure=decoded(r.read(),fmt);assert status(failure)==1 and reason(failure)==4
        finally:c.close()
    cases.append('malformed encodings and DTD return encoded KMIP Invalid Message without mutation')
    # Exhaust all four bounded request slots with incomplete bodies; a fifth is rejected.
    held=[]
    try:
        for _ in range(4):
            c=connect(s.pki,s.https);c.sendall(headers+query[:1]);held.append(c)
        time.sleep(.1)
        assert raw(headers+query)==503
    finally:
        for c in held:c.close()
    until=time.monotonic()+5
    while True:
        try:payload(post(s,request(24,[enumeration(0x420074,1)],(2,1))));break
        except AssertionError:
            if time.monotonic()>until:raise
            time.sleep(.05)
    cases.append('four unfinished bodies bound concurrency; fifth receives 503; capacity recovers on disconnect')
    # An XML-inexpressible echoed correlation must be rejected before Create.
    n=request(1,[enumeration(0x420057,2),structure(0x420125,enumeration(0x420028,3),integer(0x42002a,256),integer(0x42002c,12))],(2,1),[text(0x420105,'bad\x00correlation')])
    b=encoded(n,'JSON');message=b'POST /kmip HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nAccept: text/xml\r\nContent-Length: '+str(len(b)).encode()+b'\r\n\r\n'+b
    with s.connect() as c:before=len(children(payload(exchange(c,request(8,v=(2,1)))),0x420094))
    assert raw(message)==406
    with s.connect() as c:assert len(children(payload(exchange(c,request(8,v=(2,1)))),0x420094))==before
    cases.append('unrepresentable XML correlation rejects Create before storage mutation')
    cases.extend(transactions(s))
    with s.connect() as c:id=create_key(c);key=key_value(c,id)
    s.stop();s.start()
    for fmt in MEDIA:
        r=payload(post(s,request(10,[uid(id)],(1,4)),fmt));assert get(get(get(get(r,0x42008f),0x420040),0x420045),0x420043)[2]==key
    cases.append('server restart preserves exact key bytes across every HTTPS encoding')
    return {'lanes':versions,'cases':cases}

def transactions(s):
    v=(2,1)
    attrs=structure(0x420125,enumeration(0x420028,3),integer(0x42002a,256),integer(0x42002c,12),structure(0x420095,node(0x420097,3,1),enumeration(0x420098,2)))
    with s.connect() as c:
        id=get(payload(exchange(c,request(1,[enumeration(0x420057,2),attrs],v))),0x420094)[2]
        key=key_value(c,id,v);payload(exchange(c,request(18,[uid(id,v)],v)))
    fields=[uid(id,v),structure(0x42002b,enumeration(0x420011,6),enumeration(0x42005f,1)),binary(0x42003d,b'\1'*16),binary(0x4200c2,b'\2'*4096),node(0x4200d7,6,True)]
    message=request(31,fields,v,[integer(0x420050,5000)])
    # Maximum Response Size bounds the binary TTLV equivalent in JSON too (Profiles 5.5).
    r=post(s,request(31,fields,v,[integer(0x420050,4096)]),'JSON');assert status(r)==1 and reason(r)==2
    def remaining():
        with s.connect() as c:
            a=payload(exchange(c,request(11,[uid(id,v),enumeration(0x42013b,0x420095)],v)))
            return get(get(get(a,0x420125),0x420095),0x420096)[2]
    assert remaining()==1
    with s.connect() as c:
        r=payload(exchange(c,message));correlation=get(r,0x4200d6)[2]
        encryptor=Cipher(algorithms.AES(key),modes.CTR(b'\1'*16)).encryptor()
        assert get(r,0x4200c2)[2]==encryptor.update(b'\2'*4096)+encryptor.finalize()
        finish=payload(exchange(c,request(31,[uid(id,v),binary(0x4200d6,correlation),node(0x4200d8,6,True)],v)))
        assert not children(finish,0x4200c2) or get(finish,0x4200c2)[2]==b''
    assert remaining()==0
    with s.connect() as c:
        ordinary=create_key(c,v)
        exported=payload(exchange(c,request(43,[uid(ordinary,v)],v)))
        # Import refuses NUL (reserved for hidden record identifiers);
        # U+0001 is also outside XML 1.0 but a valid imported identifier.
        nul='https\0literal-key'
        nul_attrs=structure(0x420125,*[text(0x420094,nul) if n[0]==0x420094 else binary(0x420136,hashlib.sha256(nul.encode()).digest()) if n[0]==0x420136 else n for n in get(exported,0x420125)[2]])
        r=exchange(c,request(42,[uid(nul,v),get(exported,0x420057),nul_attrs,get(exported,0x42008f)],v));assert status(r)==1 and reason(r)==7
        target='https\x01literal-key'
        attrs=structure(0x420125,*[text(0x420094,target) if n[0]==0x420094 else binary(0x420136,hashlib.sha256(target.encode()).digest()) if n[0]==0x420136 else n for n in get(exported,0x420125)[2]])
        fields=[uid(target,v),get(exported,0x420057),attrs,get(exported,0x42008f)]
        payload(exchange(c,request(42,fields,v)))
    # JSON can transport U+0001 in an ID; XML 1.0 cannot echo that ID in Get.
    r=post(s,request(10,[uid(target,v)],v),'JSON','XML');assert status(r)==1 and reason(r)==8
    r=post(s,request(10,[uid(target,v)],v),'JSON');assert get(payload(r),0x420094)[2]==target
    with s.connect() as c:fresh_id=create_key(c,v)
    db=sqlite3.connect(s.data/'kmip.sqlite')
    try:
        db.execute("CREATE TRIGGER fail_http_audit BEFORE INSERT ON audit BEGIN SELECT RAISE(ABORT,'test audit unavailable'); END");db.commit()
        r=post(s,request(10,[uid(fresh_id,v)],v),'JSON');assert status(r)==1 and reason(r)==0x100
        assert not children(get(r,0x42000f),0x42007c)
    finally:
        db.execute('DROP TRIGGER IF EXISTS fail_http_audit');db.commit();db.close()
    with s.connect() as c:
        a=payload(exchange(c,request(11,[uid(fresh_id,v),enumeration(0x42013b,0x4200a8)],v)))
        assert get(get(a,0x420125),0x4200a8)[2]==1
        assert len(key_value(c,fresh_id,v))==32
    return ['encoded JSON Maximum Response Size rolls back usage and multipart creation; exact binary retry succeeds with independent CTR bytes','XML-inexpressible Get returns KMIP failure while JSON can retrieve the same key','audit failure after response encoding returns no key payload and preserves Fresh until successful retry']

def main():
    p=argparse.ArgumentParser();p.add_argument('--image');p.add_argument('--engine',default='podman');p.add_argument('--go',action='store_true')
    p.add_argument('--java',action='append',default=[],help='JDK java executable for the keytend-kmip SDK lanes; repeat for several JDKs')
    a=p.parse_args();javas=a.java
    artifact=None
    if javas:
        _,jars,artifact=keytend_kmip_release.release();pin=artifact['commit']
    art=ROOT/'artifacts';art.mkdir(parents=True,exist_ok=True);output=art/('https-image.json' if a.image else 'https.json');output.write_text(json.dumps({'status':'running'})+'\n')
    binary=ROOT/'target/debug/keytend-kmip-server';digest=sha(binary);image_id=local_image_id(a.engine,a.image) if a.image else None;image=packaged_evidence(image_id) if image_id else {}
    editions=[(1,0),(1,1),(1,2),(1,3),(1,4),(2,0),(2,1)]+([] if a.image else [(3,0)]);lanes=[]
    with tempfile.TemporaryDirectory(prefix='keytend-https-') as directory:
        s=HttpsContainer(directory,a.engine,a.image,log_path=art/'https-image-server.log') if a.image else HttpsServer(directory,draft=True)
        try:
            s.start();results=run(s,editions)
            if a.go:
                executable=ROOT/'.cache/ovh-https-adapter'
                subprocess.run(['go','build','-mod=readonly','-o',str(executable),'.'],cwd=ROOT/'interop/ovh',check=True)
                result=subprocess.run([str(executable)],env={**os.environ,'KMIP_PKI':str(s.pki),'KMIP_HTTPS_ONLY':'1','KMIP_HTTPS_PORT':str(s.https)},stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True,timeout=120)
                log=art/f'https-{"image" if a.image else "native"}-ovh.log';log.write_text(result.stdout);assert result.returncode==0,result.stdout
                results['ovh']={'status':'passed','lanes':15,'client_commit':json.loads((ROOT/'interop/clients.lock.json').read_text())['ovh']['commit'],'log':str(log.relative_to(ROOT)),'log_sha256':sha(log),'adapter_binary_sha256':sha(executable),'go_version':subprocess.check_output(['go','version'],text=True).strip()}
                print(result.stdout,flush=True)
            if javas:
                subprocess.run(['openssl','pkcs12','-export','-in',str(s.pki/'client.pem'),'-inkey',str(s.pki/'client.key'),'-certfile',str(s.pki/'ca.pem'),'-out',str(s.pki/'client.p12'),'-passout','pass:changeit'],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
                classpath=keytend_kmip_release.adapters(['ServerHttps'],ROOT/'.cache/java-https-adapter',javas[0])
                for j,java in enumerate(javas):
                    jdk=subprocess.check_output([java,'-version'],stderr=subprocess.STDOUT,text=True).splitlines()[0]
                    for version in ['1.1','1.2','1.3','1.4','2.0','2.1']:
                        for fmt in MEDIA:
                            command=[java,'-cp',classpath,'dev.keytend.kmip.interop.ServerHttps',str(s.pki),str(s.https),version,fmt,str(s.port)]
                            result=subprocess.run(command,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True,timeout=60)
                            log=art/f'https-{"image" if a.image else "native"}-java-{version}-{fmt}-jdk{j}.log';log.write_text(result.stdout)
                            assert result.returncode==0,(str(log),result.stdout)
                            lanes.append({'wire_version':version,'encoding':fmt,'jdk':jdk,'status':'passed','client_commit':pin,'log':str(log.relative_to(ROOT)),'log_sha256':sha(log)})
                            print(result.stdout.strip(),flush=True)
        finally:
            s.stop()
            if not a.image:(art/'https-native-server.log').write_text((s.root/'server.log').read_text())
    output.write_text(json.dumps({'client_artifact':artifact,'status':'passed',**({'runtime_binary_sha256':digest,'source_commit':source_commit()[0]} if not a.image else image),**results,'java_lanes':lanes,'python_cryptography_version':cryptography.__version__},indent=2)+'\n')
    print('PASS HTTPS bindings, encodings, parser defenses, transactional preflight and requested independent Java SDK lanes',flush=True)
if __name__=='__main__':main()
