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

"""End-to-end server-to-client Notify/Put through the real binary.

A Python TLS listener (independent TTLV decoder in wire.py) plays the KMIP
client endpoint. It requires a CA-issued client certificate from the server,
decodes each server-initiated request on each connection and answers it:
Discover Versions and Query (2.x) with its versions and operations, anything
else with an empty successful response. A second scenario reverses a client
connection with Set Endpoint Role and plays the client endpoint on it. Policy
validation of the client_endpoint block is also exercised.
"""
import argparse,copy,json,pathlib,queue,socket,ssl,subprocess,sys,tempfile,threading
sys.path.insert(0,str(pathlib.Path(__file__).resolve().parent))
from wire import *
from test_runtime import Server
ROOT=pathlib.Path(__file__).resolve().parents[1]
OPERATION,PAYLOAD,UID,PUT_FUNCTION,SYMMETRIC_KEY,ATTRIBUTE,NAME,VALUE=0x42005c,0x420079,0x420094,0x420070,0x42008f,0x420008,0x42000a,0x42000b
PROTOCOL_VERSION,ENDPOINT_ROLE,QUERY_FUNCTION,ATTRIBUTES=0x420069,0x420151,0x420074,0x420125
CLIENT_VERSIONS=[(2,1),(2,0),(1,4)];CLIENT_OPERATIONS=[24,27,28,30,50]

def answer(message):
    """The client endpoint's response to one server-initiated request."""
    header=get(message,0x420077);item=get(message,0x42000f);op=get(item,OPERATION)[2];p=get(item,PAYLOAD)
    if op==30:out=[v for v in children(p,PROTOCOL_VERSION) if v in map(version,CLIENT_VERSIONS)]
    elif op==24:out=[enumeration(OPERATION,o) for o in CLIENT_OPERATIONS]
    elif op==50:out=[get(p,ENDPOINT_ROLE)]
    else:out=[]
    return structure(0x42007b,structure(0x42007a,get(header,0x420069),node(0x420092,9,0),integer(0x42000d,1)),structure(0x42000f,get(item,OPERATION),enumeration(0x42007f,0),*([structure(0x42007c,*out)] if out else [])))
def read(s):
    h=recv_exact(s,8);size=int.from_bytes(h[4:8],'big');assert size<=1024*1024
    return decode(h+recv_exact(s,((size+7)//8)*8))
def op_of(message):return get(get(message,0x42000f),OPERATION)[2]

class Listener:
    def __init__(self,pki):
        self.received=queue.Queue()
        ctx=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);ctx.minimum_version=ssl.TLSVersion.TLSv1_2
        ctx.load_cert_chain(pki/'server.pem',pki/'server.key');ctx.load_verify_locations(pki/'ca.pem');ctx.verify_mode=ssl.CERT_REQUIRED
        self.sock=socket.create_server(('127.0.0.1',0));self.port=self.sock.getsockname()[1];self.ctx=ctx
        threading.Thread(target=self.serve,daemon=True).start()
    def serve(self):
        while True:
            try:raw,_=self.sock.accept()
            except OSError:return
            # Unrelated local connections (no client certificate) are ignored.
            try:s=self.ctx.wrap_socket(raw,server_side=True)
            except (OSError,ssl.SSLError):raw.close();continue
            try:
                with s:
                    peer=dict(x[0] for x in s.getpeercert()['subject'])['commonName']
                    while True:
                        try:message=read(s)
                        except EOFError:break
                        s.sendall(encode(answer(message)));self.received.put((message,peer))
            except Exception as e:self.received.put((e,None))
    def next(self,timeout=15):
        message,peer=self.received.get(timeout=timeout)
        if isinstance(message,Exception):raise message
        return message,peer
    def close(self):self.sock.close()

def configure(server,endpoint):
    policy=json.loads((server.pki/'policy.json').read_text())
    for principal in policy['principals'].values():
        principal.pop('client_endpoint',None)
        if principal['name']=='database' and endpoint is not None:principal['client_endpoint']=endpoint
    (server.pki/'policy.json').write_text(json.dumps(policy))

def run(s):
    results=[];passed=lambda name:(results.append(name),print('PASS',name,flush=True))
    listener=Listener(s.pki)
    endpoint={'address':f'127.0.0.1:{listener.port}','server_name':'localhost','ca':str(s.pki/'ca.pem'),'certificate':str(s.pki/'client.pem'),'key':str(s.pki/'client.key'),'protocol_version':'1.4','operations':[27,28]}
    reverse_only={'protocol_version':'2.1','operations':[27,28]}
    for name,bad in [('unknown field',dict(endpoint,retries=9)),('draft version',dict(endpoint,protocol_version='3.0')),('client operation',dict(endpoint,operations=[1])),('bad address',dict(endpoint,address='127.0.0.1')),('partial dial-out',{k:v for k,v in endpoint.items() if k!='key'}),('1.x without an address',dict(reverse_only,protocol_version='1.4'))]:
        configure(s,bad)
        try:s.start()
        except RuntimeError:s.stop()
        else:s.stop();raise AssertionError(f'policy with {name} accepted')
    passed('client_endpoint policy rejects unknown fields, draft versions, client operations, bad or partial addresses and 1.x without an address')
    configure(s,endpoint);s.start()
    try:
        with s.connect() as c:
            ops={o[2] for o in children(payload(exchange(c,request(24,[enumeration(0x420074,1)]))),OPERATION)}
            assert {6,7,27,28}<=ops,ops
        with s.connect(identity='other') as c:
            ops={o[2] for o in children(payload(exchange(c,request(24,[enumeration(0x420074,1)]))),OPERATION)}
            assert not {27,28}&ops,ops
        passed('Query lists Notify/Put only for the principal with a configured endpoint')
        with s.connect() as c:
            id=create_key(c)
            message,peer=listener.next()
            assert peer=='client',peer
            assert get(get(message,0x420077),0x420069)==version((1,4))
            item=get(message,0x42000f);assert get(item,OPERATION)[2]==28
            p=get(item,PAYLOAD);assert get(p,UID)[2]==id and get(p,PUT_FUNCTION)[2]==1
            pushed=get(get(get(get(p,SYMMETRIC_KEY),0x420040),0x420045),0x420043)[2]
            assert pushed==key_value(c,id) and len(pushed)==32
            passed('Create pushes Put New with the Get-equivalent key over mTLS')
            exchange(c,request(13,[uid(id),structure(ATTRIBUTE,text(NAME,'Contact Information'),text(VALUE,'ops@example'))]))
            while True:
                message,_=listener.next();item=get(message,0x42000f)
                assert get(item,OPERATION)[2]==27
                p=get(item,PAYLOAD);assert get(p,UID)[2]==id
                names={get(a,NAME)[2]:a for a in children(p,ATTRIBUTE)}
                assert 'Last Change Date' in names,names
                if 'Contact Information' in names:
                    assert get(names['Contact Information'],VALUE)[2]=='ops@example';break
            passed('Add Attribute sends Notify with the changed attribute and Last Change Date')
        # The other tenant may only read; its reads of nothing it owns produce no messages.
        with s.connect(identity='other') as c:
            assert reason(exchange(c,request(10,[uid(id)])))==1
        try:listener.next(timeout=3)
        except queue.Empty:pass
        else:raise AssertionError('message sent for another tenant request')
        passed('another tenant request produces no message')
    finally:
        s.stop();listener.close()
    # 2.1 dial-out: each session starts with Discover Versions and Query.
    configure(s,dict(endpoint,protocol_version='2.1'));s.start()
    try:
        with s.connect() as c:
            id=create_key(c,(2,1))
            ops=[];dv=None
            while 28 not in ops:
                message,_=listener.next();ops.append(op_of(message))
                if op_of(message)==30:dv=message
            assert ops==[30,24,28],ops
            offered=children(get(get(dv,0x42000f),PAYLOAD),PROTOCOL_VERSION)
            assert offered[0]==version((2,1)) and version((3,0)) not in offered,offered
            assert get(get(message,0x42000f),PAYLOAD)[2][0]==(UID,7,id)
        passed('a 2.1 session sends Discover Versions and Query before the first Put')
    finally:
        s.stop()
    # Reverse only: no address; the client reverses its own connection.
    configure(s,reverse_only);s.start()
    try:
        with s.connect() as c:
            role=lambda r:get(payload(exchange(c,request(50,[enumeration(ENDPOINT_ROLE,r)],(2,1)))),ENDPOINT_ROLE)[2]
            assert role(2)==2
            # Another version than the endpoint's cannot be reversed.
            assert reason(exchange(c,request(50,[enumeration(ENDPOINT_ROLE,1)],(2,0))))==8
            assert role(1)==1
            c.settimeout(60)
            seen=[]
            for _ in range(2):
                message=read(c);seen.append(op_of(message));c.sendall(encode(answer(message)))
            assert seen==[30,24],seen
            passed('Set Endpoint Role reverses the channel; the server probes the client on it')
            with s.connect() as other:id=create_key(other,(2,1))
            message=read(c);c.sendall(encode(answer(message)))
            item=get(message,0x42000f);assert get(item,OPERATION)[2]==28
            assert get(get(item,PAYLOAD),UID)[2]==id
            passed('Put travels over the reversed channel')
            message=read(c);item=get(message,0x42000f)
            assert get(item,OPERATION)[2]==50 and get(get(item,PAYLOAD),ENDPOINT_ROLE)[2]==1
            c.sendall(encode(answer(message)))
            ops={o[2] for o in children(payload(exchange(c,request(24,[enumeration(QUERY_FUNCTION,1)],(2,1)))),OPERATION)}
            assert {27,28,50}<=ops and 0x34 not in ops,ops
            passed('the idle reversed channel is handed back and serves requests again')
        with s.connect(identity='other') as c:
            assert reason(exchange(c,request(50,[enumeration(ENDPOINT_ROLE,1)],(2,1))))==12
        passed('a principal without a client endpoint cannot reverse')
    finally:
        s.stop()
    r=subprocess.run([s.binary,'check-store','--database',str(s.data/'kmip.sqlite'),'--master-key',str(s.pki/'master.key')],stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
    assert r.returncode==0,r.stderr
    passed('delivery outcome audits keep the audit chain verifiable')
    return results

if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('--skip-build',action='store_true');args=parser.parse_args()
    if not args.skip_build:subprocess.run(['cargo','build','--locked'],cwd=ROOT,check=True)
    with tempfile.TemporaryDirectory(prefix='keytend-kmip-server-s2c-') as d:
        run(Server(d))
