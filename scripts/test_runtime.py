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

"""Exercise the real TLS binary, restart persistence, tenancy and hostile frames."""
import argparse,hashlib,hmac,concurrent.futures,contextlib,json,os,pathlib,random,socket,ssl,subprocess,sys,tempfile,time
from wire import *
ROOT=pathlib.Path(__file__).resolve().parents[1]
def sha(path):return hashlib.sha256(pathlib.Path(path).read_bytes()).hexdigest()

def free_port():
    with socket.socket() as s:s.bind(('127.0.0.1',0));return s.getsockname()[1]
def stable_port():
    """A free port below the kernel's ephemeral range, for a server that restarts on the same
    port: outbound connections never take it while the server is down."""
    try:low=int(open('/proc/sys/net/ipv4/ip_local_port_range').read().split()[0])
    except (OSError,ValueError,IndexError):low=32768
    for _ in range(200):
        port=random.randrange(10000,max(10001,low))
        try:
            with socket.socket() as s:s.bind(('127.0.0.1',port));return port
        except OSError:continue
    return free_port()
class Server:
    def __init__(self,directory,binary=None,draft=False):
        self.root=pathlib.Path(directory);self.pki=self.root/'pki';self.data=self.root/'data';self.data.mkdir(mode=0o700);self.port=stable_port();self.health=free_port();self.binary=str(binary or ROOT/'target/debug/keytend-kmip-server');self.draft=draft;self.process=None;self.crl=None;self.users=None;self.extra_args=[]
        subprocess.run([str(ROOT/'scripts/dev-pki.sh'),str(self.pki)],check=True)
        self.generate_master_key(self.pki/'master.key')
    def generate_master_key(self,path):
        subprocess.run([self.binary,'generate-master-key','--output',str(path)],check=True)
    def start(self):
        self.log=open(self.root/'server.log','a')
        args=[self.binary,'serve','--listen',f'127.0.0.1:{self.port}','--health-listen',f'127.0.0.1:{self.health}','--cert',str(self.pki/'server.pem'),'--key',str(self.pki/'server.key'),'--ca',str(self.pki/'ca.pem'),'--policy',str(self.pki/'policy.json'),'--database',str(self.data/'kmip.sqlite'),'--master-key',str(self.pki/'master.key')]
        if self.draft:args+=['--experimental-v3']
        # Draft 3.0 credential traces assume a configured administrator user.
        if self.draft and (self.pki/'users.json').exists():args+=['--users',str(self.pki/'users.json')]
        # An explicit users file (header credentials in any version) replaces it.
        elif self.users:args+=['--users',str(self.users)]
        if self.crl:args+=['--crl',str(self.crl)]
        args+=self.extra_args
        self.process=subprocess.Popen(args,stdout=self.log,stderr=self.log)
        until=time.monotonic()+30  # loaded runners start containers slowly
        while time.monotonic()<until:
            if self.process.poll() is not None:raise RuntimeError((self.root/'server.log').read_text())
            try:
                with socket.create_connection(('127.0.0.1',self.health),timeout=.2):return
            except OSError:time.sleep(.05)
        raise TimeoutError('server did not start')
    def stop(self):
        if self.process and self.process.poll() is None:
            self.process.terminate()
            try:self.process.wait(timeout=25)
            except subprocess.TimeoutExpired:self.process.kill();self.process.wait();raise
        if hasattr(self,'log'):self.log.close()
    def connect(self,**kw):return connect(self.pki,self.port,**kw)
    def __enter__(self):self.start();return self
    def __exit__(self,*exc):self.stop()

def run(s):
    results=[]
    def passed(name):results.append(name);print('PASS',name,flush=True)
    missing=s.root/'does-not-exist.sqlite'
    for operation,extra in [('check-store',[]),('backup',['--output',str(s.root/'bad-backup.sqlite')])]:
        r=subprocess.run([s.binary,operation,'--database',str(missing),'--master-key',str(s.pki/'master.key')]+extra,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        assert r.returncode!=0 and not missing.exists()
    passed('verification/backup refuse missing sources without creating a new store')
    with s.connect() as c:
        id=create_key(c);key=key_value(c,id)
        assert len(key)==32
    try:
        with s.connect(cert=False) as c:exchange(c,request(24,[enumeration(0x420074,1)]))
    except (OSError,EOFError):pass
    else:raise AssertionError('Client without a certificate accepted')
    # A CA-valid certificate without a policy entry gets one definite KMIP refusal
    # (Permission Denied for every item, in the request's version) and the connection
    # closes, instead of a reset that clients must treat as a transient network failure.
    for v in [(1,0),(1,4),(2,1)]:
        with s.connect(identity='unlisted') as c:
            r=exchange(c,request(1,[enumeration(0x420057,2)],v))
            assert status(r)==1 and reason(r)==12,('unlisted',v)
            assert get(get(r,0x42007a),0x420069)==get(get(request(1,[],v),0x420077),0x420069)
            try:
                c.sendall(encode(request(24,[enumeration(0x420074,1)],v)));recv_exact(c,8)
            except (OSError,EOFError):pass
            else:raise AssertionError('connection stayed open for an unlisted certificate')
    passed('mTLS required; CA-valid unlisted client refused with Permission Denied, then closed')
    with s.connect(identity='other') as c:
        assert reason(exchange(c,request(10,[uid(id)])))==1
        assert not children(payload(exchange(c,request(8))),0x420094)
        assert reason(exchange(c,request(1,[enumeration(0x420057,2)])))==12
    passed('certificate principals isolate Get/Locate and enforce operation ACLs')
    with s.connect() as c:
        malformed=bytearray(encode(request(24,[enumeration(0x420074,1)])));malformed[-1]=1;c.sendall(malformed)
        h=recv_exact(c,8);r=decode(h+recv_exact(c,int.from_bytes(h[4:8],'big')));assert reason(r)==4
    with s.connect() as c:
        c.sendall(bytes.fromhex('42007801ffffffff'))
        assert c.recv(1)==b''
    passed('malformed padding and oversized frame rejected')
    def concurrent_key(_):
        with s.connect() as c:
            id=create_key(c);return id,key_value(c,id)
    with concurrent.futures.ThreadPoolExecutor(max_workers=12) as pool:keys=list(pool.map(concurrent_key,range(32)))
    assert len({k for _,k in keys})==32;passed('concurrent clients create distinct durable keys')
    def create_named(_):
        with s.connect() as c:
            attributes=structure(0x420125,enumeration(0x420028,3),integer(0x42002a,256),integer(0x42002c,12),
                structure(0x420053,text(0x420055,'shared-database-name'),enumeration(0x420054,1)))
            response=exchange(c,request(1,[enumeration(0x420057,2),attributes],v=(2,1)))
            if status(response)==0:return get(payload(response),0x420094)[2]
            assert reason(response)==0x35
            return None
    with concurrent.futures.ThreadPoolExecutor(max_workers=12) as pool:named=list(pool.map(create_named,range(32)))
    assert len([id for id in named if id])==1
    passed('32 concurrent named-key requests create one key and reject 31 duplicate names')
    with s.connect() as c:
        limited_attrs=structure(0x420125,enumeration(0x420028,3),integer(0x42002a,256),integer(0x42002c,12),
            structure(0x420095,node(0x420097,3,8),node(0x420096,3,999),enumeration(0x420098,2)))
        limited_id=get(payload(exchange(c,request(1,[enumeration(0x420057,2),limited_attrs],v=(2,1)))),0x420094)[2]
        payload(exchange(c,request(18,[uid(limited_id)],v=(2,1))))
    def allocate_one(_):
        with s.connect() as c:
            r=exchange(c,request(17,[uid(limited_id),node(0x420096,3,1)],v=(2,1)))
            if status(r)==0:return True
            assert reason(r)==0x1a
            return False
    with concurrent.futures.ThreadPoolExecutor(max_workers=12) as pool:allocated=list(pool.map(allocate_one,range(32)))
    assert sum(allocated)==8 and len(allocated)==32
    s.stop();s.start()
    with s.connect() as c:
        r=exchange(c,request(17,[uid(limited_id),node(0x420096,3,1)],v=(2,1)));assert reason(r)==0x1a
        r=payload(exchange(c,request(11,[uid(limited_id),enumeration(0x42013b,0x420095)],v=(2,1))))
        assert get(get(get(r,0x420125),0x420095),0x420096)[2]==0
    passed('32 concurrent allocations grant exactly eight units; exhaustion remains after restart')
    s.stop();s.start()
    with s.connect() as c:assert key_value(c,id)==key
    for file in s.data.glob('kmip.sqlite*'):assert key not in file.read_bytes()
    passed('process restart retains exact key; no plaintext key in SQLite/WAL')
    with s.connect() as c:
        assert reason(exchange(c,request(59,v=(3,0))))==0x3f
        assert reason(exchange(c,request(0x34,v=(2,1))))==5  # Interop is never offered
    passed('3.0 disabled by default; unsupported operations fail explicitly')
    with s.connect() as c:
        history_id=create_key(c)
        history_key=key_value(c,history_id)
        payload(exchange(c,request(18,[uid(history_id)])))
    def replace_once(_):
        with s.connect() as c:
            response=exchange(c,request(4,[uid(history_id)],v=(2,1)))
            if status(response)==0:return get(payload(response),0x420094)[2]
            assert reason(response)==12
            return None
    with concurrent.futures.ThreadPoolExecutor(max_workers=12) as pool:replacements=list(pool.map(replace_once,range(32)))
    replacement_ids=[value for value in replacements if value]
    assert len(replacement_ids)==1
    with s.connect() as c:
        assert key_value(c,history_id)==history_key
        replacement_key=key_value(c,replacement_ids[0]);assert replacement_key!=history_key
        payload(exchange(c,request(15,[uid(history_id),text(0x42000a,'Link'),integer(0x420009,0)])))
    s.stop();s.start()
    with s.connect() as c:
        assert reason(exchange(c,request(4,[uid(history_id)],v=(2,1))))==12
        assert key_value(c,replacement_ids[0])==replacement_key
    passed('32 concurrent Re-key requests create one replacement; deleting its link and restarting cannot fork history')
    with s.connect() as c:
        pair=payload(exchange(c,request(2,[structure(0x420126,enumeration(0x420028,4),integer(0x42002a,2048)),
            structure(0x420127,integer(0x42002c,1)),structure(0x420128,integer(0x42002c,2))],v=(2,1))))
        private_id=get(pair,0x420066)[2];public_id=get(pair,0x42006f)[2]
        def private_bytes(c,id):
            p=payload(exchange(c,request(10,[uid(id)],v=(2,1))))
            return get(get(get(get(p,0x420064),0x420040),0x420045),0x420043)[2]
        original_private=private_bytes(c,private_id)
    def replace_pair_once(_):
        with s.connect() as c:
            response=exchange(c,request(29,[text(0x420066,private_id)],v=(2,1)))
            if status(response)==0:
                p=payload(response);return get(p,0x420066)[2],get(p,0x42006f)[2]
            assert reason(response)==12
            return None
    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:pair_results=list(pool.map(replace_pair_once,range(16)))
    pair_results=[value for value in pair_results if value];assert len(pair_results)==1
    next_private,next_public=pair_results[0]
    with s.connect() as c:
        new_private=private_bytes(c,next_private);assert new_private!=original_private
        assert private_bytes(c,private_id)==original_private
        for id in [private_id,public_id]:
            payload(exchange(c,request(15,[uid(id),text(0x42000a,'Link'),integer(0x420009,1)])))
    s.stop();s.start()
    with s.connect() as c:
        assert private_bytes(c,next_private)==new_private and private_bytes(c,private_id)==original_private
        assert reason(exchange(c,request(29,[text(0x420066,private_id)],v=(2,1))))==12
        p=payload(exchange(c,request(10,[uid(next_public)],v=(2,1))));assert get(p,0x42006d)
    passed('16 concurrent Re-key Key Pair requests create one matching pair; both history guards and exact material survive link deletion and restart')
    with s.connect() as c:
        wrap_attrs=structure(0x420125,enumeration(0x420028,3),integer(0x42002a,128),integer(0x42002c,48),
            structure(0x42002b,enumeration(0x420011,12)),structure(0x420095,node(0x420097,3,8),enumeration(0x420098,2)))
        wrap_id=get(payload(exchange(c,request(1,[enumeration(0x420057,2),wrap_attrs],v=(2,1)))),0x420094)[2]
        payload(exchange(c,request(18,[uid(wrap_id)],v=(2,1))))
        original=bytes(range(32))
        sensitive_attrs=structure(0x420125,integer(0x42002c,12),node(0x420120,6,True))
        target=structure(0x42008f,structure(0x420040,enumeration(0x420042,1),structure(0x420045,node(0x420043,8,original)),enumeration(0x420028,3),integer(0x42002a,256)))
        sensitive_id=get(payload(exchange(c,request(3,[enumeration(0x420057,2),sensitive_attrs,target],v=(2,1)))),0x420094)[2]
        assert reason(exchange(c,request(10,[uid(sensitive_id)],v=(2,1))))==0x16
    def wrapped_once(_):
        with s.connect() as c:
            spec=structure(0x420047,enumeration(0x42009e,1),structure(0x420036,uid(wrap_id)),enumeration(0x4200a3,1))
            response=exchange(c,request(10,[uid(sensitive_id),spec],v=(2,1)))
            if status(response)==0:return get(payload(response),0x42008f)
            assert reason(response)==0x1a
            return None
    with concurrent.futures.ThreadPoolExecutor(max_workers=12) as pool:wrapped=list(pool.map(wrapped_once,range(32)))
    wrapped=[value for value in wrapped if value];assert len(wrapped)==8
    s.stop();s.start()
    with s.connect() as c:
        assert wrapped_once(0) is None
        r=payload(exchange(c,request(3,[enumeration(0x420057,2),structure(0x420125,integer(0x42002c,12)),wrapped[0]],v=(2,1))))
        recovered=get(r,0x420094)[2];assert key_value(c,recovered,(2,1))==original
        assert reason(exchange(c,request(10,[uid(sensitive_id)],v=(2,1))))==0x16
    passed('concurrent wrapped Get grants exactly eight uses; exhausted wrapping budget and Sensitive policy survive restart; wrapped Register preserves exact key bytes')
    def import_fields(exported, target, object=None, wrap=None):
        attrs=get(exported,0x420125)
        attrs=structure(0x420125,*[text(0x420094,target) if n[0]==0x420094 else node(0x420136,8,hashlib.sha256(target.encode()).digest()) if n[0]==0x420136 and get(exported,0x420094)[2]!=target else n for n in attrs[2]])
        fields=[uid(target),get(exported,0x420057),attrs,object or get(exported,0x42008f)]
        if wrap is not None:fields.append(enumeration(0x4200f8,wrap))
        return fields
    with s.connect() as c:
        exported=payload(exchange(c,request(43,[uid(recovered)],v=(2,1))))
    def import_once(_):
        with s.connect() as c:
            response=exchange(c,request(42,import_fields(exported,'concurrent-restored-key'),v=(2,1)))
            if status(response)==0:return True
            assert reason(response)==24
            return False
    with concurrent.futures.ThreadPoolExecutor(max_workers=12) as pool:imports=list(pool.map(import_once,range(32)))
    assert sum(imports)==1
    with s.connect() as c:
        assert key_value(c,'concurrent-restored-key',(2,1))==original
        payload(exchange(c,request(42,import_fields(exported,'opaque-runtime-key',wrapped[0],2),v=(2,1))))
        assert key_value(c,'opaque-runtime-key',(2,1))==original
    s.stop();s.start()
    with s.connect() as c:
        assert key_value(c,'concurrent-restored-key',(2,1))==original
        assert key_value(c,'opaque-runtime-key',(2,1))==original
        payload(exchange(c,request(19,[uid(wrap_id),structure(0x420081,enumeration(0x420082,1))],v=(2,1))))
        payload(exchange(c,request(20,[uid(wrap_id)],v=(2,1))))
        assert reason(exchange(c,request(10,[uid('opaque-runtime-key')],v=(2,1))))==0x13
        value=payload(exchange(c,request(10,[uid('opaque-runtime-key'),enumeration(0x4200f8,2)],v=(2,1))))
        assert get(value,0x42008f)==wrapped[0]
        payload(exchange(c,request(11,[uid('opaque-runtime-key')],v=(2,1))))
    passed('32 concurrent Import requests create one owned ID; collisions fail and exact material survives restart')
    passed('As Registered ciphertext survives restart and KEK destruction; plaintext retrieval then fails while metadata and ciphertext remain available')
    derive_key=bytes([7])*32
    with s.connect() as c:
        attrs=structure(0x420125,integer(0x42002c,512),structure(0x420095,node(0x420097,3,8),enumeration(0x420098,2)))
        value=structure(0x42008f,structure(0x420040,enumeration(0x420042,1),structure(0x420045,node(0x420043,8,derive_key)),enumeration(0x420028,9),integer(0x42002a,256)))
        base=get(payload(exchange(c,request(3,[enumeration(0x420057,2),attrs,value],v=(2,1)))),0x420094)[2]
        payload(exchange(c,request(18,[uid(base)],v=(2,1))))
    def derive_once(index):
        data=f'database-key-{index}'.encode()
        fields=[enumeration(0x420057,2),uid(base),enumeration(0x420031,3),structure(0x420032,node(0x420030,8,data)),structure(0x420125,enumeration(0x420028,3),integer(0x42002a,256),integer(0x42002c,12))]
        with s.connect() as c:
            response=exchange(c,request(5,fields,v=(2,1)))
            if status(response)==0:
                derived=get(payload(response),0x420094)[2]
                assert key_value(c,derived,(2,1))==hmac.digest(derive_key,data,'sha256')
                return derived,data
            assert reason(response)==0x1a
            return None
    with concurrent.futures.ThreadPoolExecutor(max_workers=12) as pool:derived=list(pool.map(derive_once,range(32)))
    derived=[value for value in derived if value];assert len(derived)==8 and len({id for id,_ in derived})==8
    s.stop();s.start()
    with s.connect() as c:
        for id,data in derived:assert key_value(c,id,(2,1))==hmac.digest(derive_key,data,'sha256')
        attrs=get(payload(exchange(c,request(11,[uid(base)],v=(2,1)))),0x420125)
        assert get(get(attrs,0x420095),0x420096)[2]==0
        links=[link for link in children(attrs,0x42004a) if get(link,0x42004b)[2]==0x105]
        assert len(links)==8
    assert derive_once(99) is None
    passed('32 concurrent Derive Key requests grant eight independently verified keys; source budget and reciprocal history survive restart')
    with s.connect() as c:
        attrs=structure(0x420125,integer(0x42002c,12),node(0x420120,6,True),node(0x420122,6,False))
        obj=structure(0x42008f,structure(0x420040,enumeration(0x420042,1),structure(0x420045,node(0x420043,8,bytes([14])*32)),enumeration(0x420028,3),integer(0x42002a,256)))
        observed_id=get(payload(exchange(c,request(3,[enumeration(0x420057,2),attrs,obj],v=(2,1)))),0x420094)[2]
        def metadata(c):return get(payload(exchange(c,request(11,[uid(observed_id)],v=(2,1)))),0x420125)
        before=metadata(c);assert get(before,0x4200a8)[2]==1 and get(before,0x420121)[2]==1 and get(before,0x420123)[2]==1
        items=[(49,[uid(observed_id),structure(0x42013d,node(0x420120,6,False))]),(49,[uid(observed_id),structure(0x42013d,node(0x420122,6,True))]),(10,[uid(observed_id)]),(10,[uid('missing-undo-key')])]
        batch=structure(0x420078,structure(0x420077,version((2,1)),integer(0x42000d,4),enumeration(0x42000e,3)),*[structure(0x42000f,enumeration(0x42005c,op),node(0x420093,8,bytes([i])),structure(0x420079,*fields)) for i,(op,fields) in enumerate(items)])
        result=exchange(c,batch);responses=children(result,0x42000f);assert len(responses)==4 and get(responses[2],0x42007f)[2]==3
        material=get(get(get(get(get(responses[2],0x42007c),0x42008f),0x420040),0x420045),0x420043)[2]
        assert material==bytes([14])*32
        after=metadata(c);assert get(after,0x420120)[2]==1 and get(after,0x420122)[2]==0
        assert all(get(after,tag)[2]==0 for tag in [0x4200a8,0x420121,0x420123])
    s.stop();s.start()
    with s.connect() as c:
        after=metadata(c);assert all(get(after,tag)[2]==0 for tag in [0x4200a8,0x420121,0x420123])
        assert reason(exchange(c,request(10,[uid(observed_id)],v=(2,1))))==0x16
    passed('Undo restores extraction policy but cannot reset Fresh or extraction histories after returning key material; facts survive restart')
    with s.connect() as c:
        archive_id=create_key(c);archive_key=key_value(c,archive_id)
    def archive_once(index):
        with s.connect() as c:
            result=exchange(c,request(21,[uid(archive_id)]))
            if status(result)==0:return True
            assert reason(result)==13;return False
    with concurrent.futures.ThreadPoolExecutor(max_workers=12) as pool:
        assert sum(pool.map(archive_once,range(32)))==1
    s.stop();s.start()
    with s.connect() as c:
        assert reason(exchange(c,request(10,[uid(archive_id)])))==13
        assert archive_id in [n[2] for n in children(payload(exchange(c,request(8,[integer(0x42008e,2)]))),0x420094)]
    with s.connect(identity='other') as c:
        assert reason(exchange(c,request(22,[uid(archive_id)])))==12
    def recover_once(index):
        with s.connect() as c:
            payload(exchange(c,request(22,[uid(archive_id)])))
            assert key_value(c,archive_id)==archive_key
    with concurrent.futures.ThreadPoolExecutor(max_workers=12) as pool:list(pool.map(recover_once,range(32)))
    s.stop();s.start()
    with s.connect() as c:assert key_value(c,archive_id)==archive_key
    passed('32 Archive requests produce one archival transition; policy and exact material survive restart; authorized concurrent recovery preserves bytes')
    s.stop();s.draft=True;s.start()
    with s.connect() as c:
        payload(exchange(c,request(59,v=(3,0))))
        id3=create_key(c,(3,0));draft_key=key_value(c,id3,(3,0));assert len(draft_key)==32
        payload(exchange(c,request(13,[uid(id3,(3,0)),structure(0x42013d,text(0x420053,'draft-native-key'))],v=(3,0))))
        response=payload(exchange(c,request(10,[node(0x420094,14,'draft-native-key')],v=(3,0))))
        assert get(response,0x420094)[1:]==(12,id3)
    s.stop();s.start()
    with s.connect() as c:
        response=payload(exchange(c,request(10,[node(0x420094,13,id3)],v=(3,0))))
        assert get(response,0x420094)[1:]==(12,id3)
        assert key_value(c,id3,(3,0))==draft_key and key_value(c,id3,(1,4))==draft_key
    passed('experimental 3.0 opt-in Ping and baseline lifecycle')
    passed('draft Identifier/Reference/NameReference preserve exact key bytes across restart and final-version access')
    s.stop()
    ca=s.pki
    (ca/'index.txt').write_text('');(ca/'newcerts').mkdir()
    config=ca/'ca.conf'
    config.write_text(f"""[ca]
    default_ca=CA_default
    [CA_default]
    database={ca}/index.txt
    new_certs_dir={ca}/newcerts
    certificate={ca}/ca.pem
    private_key={ca}/ca.key
    serial={ca}/ca.srl
    default_md=sha256
    default_crl_days=1
    policy=policy_any
    [policy_any]
    commonName=supplied
    """)
    subprocess.run(['openssl','ca','-config',str(config),'-revoke',str(ca/'client.pem'),'-batch'],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    s.crl=ca/'ca.crl'
    subprocess.run(['openssl','ca','-config',str(config),'-gencrl','-out',str(s.crl),'-batch'],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    s.start()
    try:
        with s.connect() as c:exchange(c,request(24,[enumeration(0x420074,1)]))
    except (OSError,EOFError):pass
    else:raise AssertionError('Revoked client certificate was accepted')
    with s.connect(identity='other') as c:payload(exchange(c,request(24,[enumeration(0x420074,1)])))
    passed('CRL rejects revoked authorized client; unaffected authorized client still works')
    return results
if __name__=='__main__':
    from image_evidence import source_commit,local_image_id,packaged_evidence
    parser=argparse.ArgumentParser();parser.add_argument('--skip-build',action='store_true')
    parser.add_argument('--binary',help='server executable (default target/debug), such as the image run as one (scripts/image_server.py)')
    parser.add_argument('--image',help='the image that --binary runs, recorded as the tested runtime');parser.add_argument('--engine',default='podman');args=parser.parse_args()
    if not args.skip_build and not args.binary:subprocess.run(['cargo','build','--locked'],cwd=ROOT,check=True)
    binary=args.binary or ROOT/'target/debug/keytend-kmip-server'
    evidence=packaged_evidence(local_image_id(args.engine,args.image)) if args.image else {'source_commit':source_commit()[0],'runtime_binary_sha256':sha(binary)}
    with tempfile.TemporaryDirectory(prefix='keytend-kmip-server-runtime-') as d:
        with Server(d,binary=binary) as s:results=run(s)
    out=ROOT/'artifacts';out.mkdir(exist_ok=True);(out/'runtime.json').write_text(json.dumps(dict(status='passed',passed=results,server=str(binary),**evidence),indent=2)+'\n')
