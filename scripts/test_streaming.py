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

"""Independent multi-frame TLS streaming, authentication and durable-budget checks."""
import argparse,hashlib,json,shutil,ssl,tempfile
from cryptography.hazmat.primitives.ciphers import Cipher,algorithms,modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.padding import PKCS7
from image_evidence import local_image_id,packaged_evidence,source_commit
from test_database import ContainerServer
from test_runtime import ROOT,Server
from wire import *

CORR=0x4200d6;INIT=0x4200d7;FINAL=0x4200d8;DATA=0x4200c2

def blob(p,tag=DATA):return get(p,tag)[2] if children(p,tag) else b''
def call(s,v,op,fields,identity='client',header=()):
    # Each part uses a new authenticated connection, proving server-side context.
    with s.connect(identity=identity) as c:return exchange(c,request(op,fields,v,header))
def attrs(values,v):
    names={0x42002c:'Cryptographic Usage Mask',0x420095:'Usage Limits'}
    if v[0]!=1:return structure(0x420125,*values)
    return structure(0x420091,*[structure(0x420008,text(0x42000a,names[n[0]]),node(0x42000b,n[1],n[2])) for n in values])
def key(s,v,limits=None):
    a=[integer(0x42002c,12)]
    if limits:a.append(structure(0x420095,node(0x420097,3,limits),enumeration(0x420098,2)))
    obj=structure(0x42008f,structure(0x420040,enumeration(0x420042,1),structure(0x420045,binary(0x420043,bytes(range(32)))),enumeration(0x420028,3),integer(0x42002a,256)))
    id=get(payload(call(s,v,3,[enumeration(0x420057,2),attrs(a,v),obj])),0x420094)[2]
    payload(call(s,v,18,[uid(id,v)]));return id

def aes_modes(s,v,id,raw,iv,message):
    tested=[]
    for mode,python_mode in [(1,modes.CBC(iv)),(2,modes.ECB()),(4,modes.CFB(iv)),(5,modes.OFB(iv)),(6,modes.CTR(iv))]:
        padded=message
        if mode in [1,2]:
            padder=PKCS7(128).padder();padded=padder.update(message)+padder.finalize()
        encryptor=Cipher(algorithms.AES(raw),python_mode).encryptor()
        encrypted=encryptor.update(padded)+encryptor.finalize()
        cp=structure(0x42002b,enumeration(0x420011,mode),enumeration(0x42005f,3 if mode in [1,2] else 1))
        for op,data,expected in [(31,message,encrypted),(32,encrypted,message)]:
            output=[];token=None
            for i,chunk in enumerate([data[:7],data[7:39],data[39:]]):
                fields=[uid(id,v),binary(DATA,chunk)]
                if i==0:fields += [cp,node(INIT,6,True)]+([] if mode==2 else [binary(0x42003d,iv)])
                else:fields += [binary(CORR,token)]
                if i==2:fields += [node(FINAL,6,True)]
                p=payload(call(s,v,op,fields));output.append(blob(p))
                if i==0:token=blob(p,CORR)
            assert b''.join(output)==expected,(v,mode,op)
        tested.append({'mode':mode,'encrypt_and_decrypt':'independent exact bytes','padding':'PKCS5' if mode in [1,2] else 'None'})
    return tested

def run(s,editions):
    versions=[];message=bytes(range(251))*5;raw=bytes(range(32));iv=bytes(range(16))
    for v in editions:
        id=key(s,v);cp=structure(0x42002b,enumeration(0x420011,6),enumeration(0x42005f,1))
        out=[];token=None
        for i,chunk in enumerate([message[:7],message[7:39],message[39:]]):
            fields=[uid(id,v),binary(DATA,chunk)]
            if i==0:fields += [cp,binary(0x42003d,iv),node(INIT,6,True)]
            else:fields += [binary(CORR,token)]
            if i==2:fields += [node(FINAL,6,True)]
            p=payload(call(s,v,31,fields));out.append(blob(p))
            if i==0:token=blob(p,CORR);assert len(token)==32
        cipher=Cipher(algorithms.AES(raw),modes.CTR(iv)).encryptor()
        assert b''.join(out)==cipher.update(message)+cipher.finalize()
        r=call(s,v,31,[uid(id,v),binary(CORR,token),node(FINAL,6,True)])
        assert status(r)==1 and reason(r)==(0x2e if v[0]>=2 else 7)
        hashcp=structure(0x42002b,enumeration(0x420038,6))
        p=payload(call(s,v,39,[hashcp,node(INIT,6,True),binary(DATA,message[:3])]))
        token=blob(p,CORR);assert not blob(p)
        foreign=call(s,v,39,[hashcp,binary(CORR,token),node(FINAL,6,True),binary(DATA,message[3:])],identity='other')
        assert status(foreign)==1 and reason(foreign)==(0x2e if v[0]>=2 else 7)
        p=payload(call(s,v,39,[hashcp,binary(CORR,token),node(FINAL,6,True),binary(DATA,message[3:])]))
        assert blob(p)==hashlib.sha256(message).digest()
        row={'aes_mode_oracles':aes_modes(s,v,id,raw,iv,message),'version':'.'.join(map(str,v)),'cross_connection_ctr_exact_bytes':True,'final_replay_denied':True,'cross_principal_hash_token_denied':True,'sha256_independent_oracle':True}
        if v>=(1,4):
            nonce=bytes(range(12));aad=b'database-envelope';encrypted=AESGCM(raw).encrypt(nonce,message,aad)
            gc=structure(0x42002b,enumeration(0x420011,9),enumeration(0x42005f,1))
            p=payload(call(s,v,32,[uid(id,v),gc,binary(0x42003d,nonce),binary(0x4200fe,aad),binary(0x4200ff,encrypted[-16:]),node(INIT,6,True),binary(DATA,encrypted[:20])]))
            token=blob(p,CORR);assert not blob(p)
            # A failed final must leave the original provider state retryable.
            bad=bytearray(encrypted[20:-16]);bad[-1]^=1
            r=call(s,v,32,[uid(id,v),binary(CORR,token),node(FINAL,6,True),binary(DATA,bytes(bad))])
            assert status(r)==1 and reason(r)==10 and not children(get(r,0x42000f),0x42007c)
            p=payload(call(s,v,32,[uid(id,v),binary(CORR,token),node(FINAL,6,True),binary(DATA,encrypted[20:-16])]))
            assert blob(p)==message
            row['authenticated_gcm_no_prefix_or_failure_plaintext']=True;row['failed_final_retry_exact_plaintext']=True
        versions.append(row)
    v=(2,1);id=key(s,v);cp=structure(0x42002b,enumeration(0x420011,6),enumeration(0x42005f,1))
    large=bytes(range(256))*(3*4096+17);expected=Cipher(algorithms.AES(raw),modes.CTR(iv)).encryptor();token=None;actual=hashlib.sha256();oracle=hashlib.sha256()
    for offset in range(0,len(large),32768):
        chunk=large[offset:offset+32768];fields=[uid(id,v),binary(DATA,chunk)]
        fields += [cp,binary(0x42003d,iv),node(INIT,6,True)] if token is None else [binary(CORR,token)]
        if offset+len(chunk)==len(large):fields+=[node(FINAL,6,True)]
        p=payload(call(s,v,31,fields));actual.update(blob(p));oracle.update(expected.update(chunk))
        if token is None:token=blob(p,CORR)
    oracle.update(expected.finalize());assert actual.digest()==oracle.digest()
    # Initial response rollback restores both the quota slot and durable budget.
    limited=key(s,v,1)
    initial=[uid(limited,v),cp,binary(0x42003d,iv),node(INIT,6,True),binary(DATA,b'x'*4096)]
    r=call(s,v,31,initial,header=[integer(0x420050,400)]);assert status(r)==1
    token=blob(payload(call(s,v,31,initial)),CORR)
    # Restart intentionally drops ephemeral contexts, while allocation survives.
    s.stop();s.start()
    r=call(s,v,31,[uid(limited,v),binary(CORR,token),node(FINAL,6,True)])
    assert status(r)==1 and reason(r)==0x2e
    r=call(s,v,31,initial);assert status(r)==1 and reason(r)==12
    return {'versions':versions,'large_stream':{'bytes':len(large),'chunk_bytes':32768,'independent_ctr_sha256':actual.hexdigest()},'response_budget_rolls_back_initial_allocation':True,'restart_discards_context_preserves_consumed_budget':True}

def main():
    parser=argparse.ArgumentParser();parser.add_argument('--image');parser.add_argument('--engine',default='podman');a=parser.parse_args()
    runtime=packaged_evidence(local_image_id(a.engine,a.image)) if a.image else {'runtime_binary_sha256':hashlib.sha256((ROOT/'target/debug/keytend-kmip-server').read_bytes()).hexdigest(),'source_commit':source_commit()[0]}
    editions=[(1,3),(1,4),(2,0),(2,1)]+([] if a.image else [(3,0)])
    with tempfile.TemporaryDirectory(prefix='keytend-streaming-') as d:
        s=ContainerServer(d,a.engine,a.image,log_path=ROOT/'artifacts/streaming-image-server.log') if a.image else Server(d,draft=True)
        # Permit Hash for the isolated second principal to exercise context binding.
        policy_path=s.pki/'policy.json';policy=json.loads(policy_path.read_text())
        fingerprint=hashlib.sha256(ssl.PEM_cert_to_DER_cert((s.pki/'other.pem').read_text())).hexdigest()
        policy['principals'][fingerprint]['operations'].append(39);policy_path.write_text(json.dumps(policy))
        if a.image:shutil.copyfile(policy_path,s.tls/'policy.json')
        try:s.start();results=run(s,editions)
        finally:s.stop()
    output='streaming-image.json' if a.image else 'streaming.json'
    (ROOT/'artifacts'/output).write_text(json.dumps({'status':'passed',**runtime,**results},indent=2)+'\n')
    print('PASS',len(editions),'editions: cross-connection multipart TLS, independent AES/SHA and restart accounting')
if __name__=='__main__':main()
