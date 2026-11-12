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

"""Small independent TTLV test transport (not a production client library)."""
import json,socket,ssl,struct,time
from pathlib import Path

def node(tag,kind,value):return (tag,kind,value)
def structure(tag,*children):return node(tag,1,list(children))
def integer(tag,value):return node(tag,2,value)
def enumeration(tag,value):return node(tag,5,value)
def text(tag,value):return node(tag,7,value)
def binary(tag,value):return node(tag,8,value)
def encode(n):
    tag,kind,value=n
    if kind==1:b=b''.join(map(encode,value))
    elif kind in (2,5,10):b=struct.pack('>I',value&0xffffffff)
    elif kind in (3,6,9,11):b=struct.pack('>q',value)
    elif kind in (7,12,13,14):b=value.encode()
    else:b=value
    return tag.to_bytes(3,'big')+bytes([kind])+len(b).to_bytes(4,'big')+b+b'\0'*((-len(b))%8)
def decode(b):
    tag=int.from_bytes(b[:3],'big');kind=b[3];size=int.from_bytes(b[4:8],'big');raw=b[8:8+size]
    if kind==1:
        value=[];i=0
        while i<size:
            length=8+((int.from_bytes(raw[i+4:i+8],'big')+7)//8)*8
            value.append(decode(raw[i:i+length]));i+=length
    elif kind in (2,3,5,6,9,10,11):value=int.from_bytes(raw,'big',signed=kind in (2,3,9,11))
    elif kind in (7,12,13,14):value=raw.decode()
    else:value=raw
    return node(tag,kind,value)
def children(n,tag):return [c for c in n[2] if c[0]==tag]
def get(n,tag):return children(n,tag)[0]
def version(v):return structure(0x420069,integer(0x42006a,v[0]),integer(0x42006b,v[1]))
def request(op,p=(),v=(1,4),extra_header=()):return structure(0x420078,structure(0x420077,version(v),*([integer(0x42000d,1)] if v[0]<3 else []),*extra_header),structure(0x42000f,enumeration(0x42005c,op),structure(0x420079,*p)))
def status(response):return get(get(response,0x42000f),0x42007f)[2]
def reason(response):return get(get(response,0x42000f),0x42007e)[2]
def payload(response):
    assert status(response)==0,repr(response)
    return get(get(response,0x42000f),0x42007c)
def recv_exact(s,n):
    data=b''
    while len(data)<n:
        part=s.recv(n-len(data))
        if not part:raise EOFError('connection closed')
        data+=part
    return data
def exchange(s,n):
    s.sendall(encode(n));h=recv_exact(s,8);size=int.from_bytes(h[4:8],'big');assert size<=1024*1024
    return decode(h+recv_exact(s,((size+7)//8)*8))
def connect(pki,port,identity='client',cert=True):
    pki=Path(pki);ctx=ssl.create_default_context(cafile=str(pki/'ca.pem'));ctx.minimum_version=ssl.TLSVersion.TLSv1_2
    if cert:ctx.load_cert_chain(pki/f'{identity}.pem',pki/f'{identity}.key')
    return ctx.wrap_socket(socket.create_connection(('127.0.0.1',port),timeout=5),server_hostname='localhost')
def connection_metrics(health,timeout=2):
    """Server lifecycle counters from the plaintext health listener (no TLS connection)."""
    with socket.create_connection(('127.0.0.1',health),timeout=timeout) as c:
        c.sendall(b'GET /connection-metrics HTTP/1.1\r\nHost: localhost\r\n\r\n');data=b''
        while chunk:=c.recv(65536):data+=chunk
    head,_,body=data.partition(b'\r\n\r\n')
    if not head.startswith(b'HTTP/1.1 200'):raise OSError('connection-metrics unavailable')
    return json.loads(body)
def probe_counted(health,timeout=10):
    """Wait until the server has accepted and closed a readiness probe's TCP connect to its KMIP
    port. Through a container engine's port forward it can accept the probe after the connect
    returns, so a counter baseline taken sooner would count the probe as a later connection."""
    until=time.monotonic()+timeout
    while True:
        m=connection_metrics(health)
        if m['ttlv_accepted_total']>=1 and m['active']==0:return m
        if time.monotonic()>=until:raise TimeoutError(f'readiness probe not counted: {m}')
        time.sleep(.05)
def attr(n):
    names={0x420028:'Cryptographic Algorithm',0x42002a:'Cryptographic Length',0x42002c:'Cryptographic Usage Mask',0x420053:'Name',0x42008d:'State',0x420122:'Extractable'}
    return structure(0x420008,text(0x42000a,names[n[0]]),(0x42000b,n[1],n[2]))
def create_key(s,v=(1,4)):
    attrs=[enumeration(0x420028,3),integer(0x42002a,256),integer(0x42002c,12)]
    a=structure(0x420091,*map(attr,attrs)) if v[0]==1 else structure(0x420125,*attrs)
    return get(payload(exchange(s,request(1,[enumeration(0x420057,2),a],v))),0x420094)[2]
def uid(id,v=(1,4)):return node(0x420094,12 if v[0]>=3 else 7,id)
def key_value(s,id,v=(1,4)):
    p=payload(exchange(s,request(10,[uid(id,v)],v)));return get(get(get(get(p,0x42008f),0x420040),0x420045),0x420043)[2]
