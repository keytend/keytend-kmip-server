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

"""Maximum Response Size over the native HTTPS and TTLV listeners.

Sweeps requested limits for each HTTPS encoding and checks every reply, the
batch continuation semantics, durable side effects and audit outcomes. For JSON
and XML the limit is the binary TTLV-equivalent length (Profiles 1.3-2.1 and
draft 3.0 sections 5.4 and 5.5): each received text body is decoded and
re-encoded as TTLV by this harness, not by the server. Text bodies are bounded
separately by the 8 MiB server frame. This is focused regression evidence, not
complete KMIP conformance.
"""
import argparse,http.client,json,pathlib,sqlite3,ssl,tempfile
from image_evidence import source_commit,local_image_id,packaged_evidence
from https_client import HttpsServer,HttpsContainer,MEDIA,context,decoded,encoded
from test_runtime import sha
from test_runtime import ROOT
from wire import *

STOP,CONTINUE,UNDO=2,1,3
TEXT_FRAME=8*1024*1024
ATTRS=[enumeration(0x420028,3),integer(0x42002a,256),integer(0x42002c,12)]

def batch(v,items,max=None,continuation=None,correlation=None):
    header=[version(v)]
    if max is not None:header.append(integer(0x420050,max))
    if correlation is not None:header.append(text(0x420105,correlation))
    if continuation is not None:header.append(enumeration(0x42000e,continuation))
    if v[0]<3:header.append(integer(0x42000d,len(items)))
    out=[]
    for i,(op,p) in enumerate(items):
        out.append(structure(0x42000f,enumeration(0x42005c,op),*([binary(0x420093,bytes([i]))] if v[0]<3 else []),structure(0x420079,*p)))
    return structure(0x420078,structure(0x420077,*header),*out)
def send(s,n,fmt):
    c=http.client.HTTPSConnection('localhost',s.https,context=context(s),timeout=15)
    try:
        c.request('POST','/kmip',encoded(n,fmt),{'Content-Type':MEDIA[fmt],'Accept':MEDIA[fmt]})
        r=c.getresponse();return r.status,r.read()
    finally:c.close()
def binary_size(body,fmt):
    """Binary TTLV-equivalent length from this harness's own decoder and encoder."""
    return len(body) if fmt=='TTLV' else len(encode(decoded(body,fmt)))
def bounded(body,fmt,max):
    assert len(body)<=TEXT_FRAME and binary_size(body,fmt)<=max,(fmt,max,len(body),binary_size(body,fmt))
def results(response):
    return [(get(i,0x42005c)[2] if children(i,0x42005c) else None,get(i,0x42007f)[2],get(i,0x42007e)[2] if children(i,0x42007e) else None) for i in children(response,0x42000f)]
def audit(s):
    db=sqlite3.connect(s.data/'kmip.sqlite')
    try:return db.execute('SELECT operation,status FROM audit ORDER BY seq').fetchall()
    finally:db.close()
def objects(s):
    """Every stored object ID, including Destroyed ones. Locate returns at most
    1000 items by default, so after long sweeps a Destroy could reveal an
    older ID that looks newly created."""
    db=sqlite3.connect(s.data/'kmip.sqlite')
    try:return {row[0] for row in db.execute('SELECT id FROM objects')}
    finally:db.close()
def state(s,id):
    with s.connect() as c:
        p=payload(exchange(c,request(11,[uid(id,(2,1)),enumeration(0x42013b,0x42008d)],(2,1))))
    return get(get(p,0x420125),0x42008d)[2]

def query_limits(s):
    """Small fixed limits plus a sweep: every reply fits, Stop returns a prefix."""
    lanes=[];query=(24,[enumeration(0x420074,1),enumeration(0x420074,2)])
    for fmt in MEDIA:
        for v,count in [((1,4),1),((2,1),3)]:
            seen={}
            for max in sorted({300,600,*range(0,12000,113)}):
                for continuation in [STOP,CONTINUE,UNDO]:
                    option=continuation if count>1 else None
                    code,body=send(s,batch(v,[query]*count,max,option,'c'*40),fmt)
                    if code==400:
                        seen.setdefault('no conforming response (HTTP 400)',max);continue
                    assert code==200,(fmt,v,max,code);bounded(body,fmt,max)
                    r=results(decoded(body,fmt));statuses=[x[1] for x in r]
                    assert all(x[0]==24 for x in r),r
                    if option==CONTINUE:assert len(r)==count,r
                    elif 1 in statuses:
                        assert statuses.index(1)==len(r)-1,r
                        if option==UNDO:assert all(x==3 for x in statuses[:-1]),r
                    seen.setdefault('fits' if 1 not in statuses else 'Response Too Large item',max)
            assert len(seen)==3,(fmt,v,seen)
            lanes.append({'encoding':fmt,'wire_version':'.'.join(map(str,v)),'items':count,'first_limit_observed':seen})
    return lanes

def batch_side_effects(s):
    """[Create, Get placeholder, Destroy other]: completed work, rollback and audit."""
    v=(2,1);lanes=[]
    for fmt in MEDIA:
        for continuation in [STOP,UNDO,CONTINUE]:
            shapes=set()
            for max in range(300,4200,31):
                with s.connect() as c:other=create_key(c,v)
                count=objects(s);seq=len(audit(s))
                code,body=send(s,batch(v,[(1,[enumeration(0x420057,2),structure(0x420125,*ATTRS)]),(10,[]),(20,[uid(other,v)])],max,continuation),fmt)
                rows=audit(s)[seq:];created=len(objects(s)-count);destroyed=state(s,other)==5
                if code==400:
                    assert rows==[] and created==0 and not destroyed,(fmt,continuation,max)
                    shapes.add('no response');continue
                assert code==200,(fmt,continuation,max,code);bounded(body,fmt,max)
                r=results(decoded(body,fmt));statuses=tuple(x[1] for x in r)
                assert [x[0] for x in r]==[1,10,20][:len(r)],r
                assert rows==[(op,st) for op,st,_ in r],(rows,r)
                if continuation==CONTINUE:
                    assert len(r)==3 and created==(statuses[0]==0) and destroyed==(statuses[2]==0),(r,created,destroyed)
                elif continuation==STOP:
                    assert 1 not in statuses[:-1] and (len(r)==3 or statuses[-1]==1),r
                    assert created==(statuses[0]==0) and destroyed==(statuses==(0,0,0)),(r,created,destroyed)
                else:
                    assert statuses==(0,0,0) or (all(x==3 for x in statuses[:-1]) and statuses[-1]==1),r
                    assert created==(statuses==(0,0,0)) and destroyed==(statuses==(0,0,0)),(r,created,destroyed)
                if 1 in statuses:assert r[statuses.index(1)][2]==2,r
                shapes.add(statuses)
            expected={STOP:(0,1),UNDO:(3,1),CONTINUE:(0,1,0)}[continuation]
            assert expected in shapes,(fmt,continuation,shapes)
            lanes.append({'encoding':fmt,'continuation':{STOP:'Stop',UNDO:'Undo',CONTINUE:'Continue'}[continuation],'shapes':sorted(map(str,shapes))})
    return lanes

def correlation_and_transport(s):
    cases=[];v=(2,1);query=(24,[enumeration(0x420074,1),enumeration(0x420074,2)])
    for fmt in MEDIA:
        echoed=dropped=None
        for max in range(200,3000,29):
            code,body=send(s,batch(v,[query,query],max,None,'c'*200),fmt)
            if code!=200:continue
            bounded(body,fmt,max)
            header=get(decoded(body,fmt),0x42007a)
            if children(header,0x420105):echoed=echoed or max
            else:dropped=dropped or max
        assert dropped is not None and echoed is not None and dropped<echoed,(fmt,dropped,echoed)
        cases.append({'encoding':fmt,'first_limit_without_echo':dropped,'first_limit_with_echo':echoed})
    count=objects(s);seq=len(audit(s))
    create=batch(v,[(1,[enumeration(0x420057,2),structure(0x420125,*ATTRS)])],0)
    for fmt in MEDIA:
        code,_=send(s,create,fmt);assert code==400
    with s.connect() as c:
        c.sendall(encode(create))
        try:data=c.recv(8)
        except (ConnectionError,ssl.SSLError):data=b''
        assert data==b'',data
    assert audit(s)[seq:]==[] and objects(s)==count
    cases.append('limit 0: HTTPS 400 in every encoding and TTLV closes without a reply; no mutation or audit')
    return cases

def aggregate_binary_limit(s):
    """Individually valid payloads must fit both aggregate encoding budgets."""
    v=(2,1);lanes=[]
    with s.connect() as c:
        r=exchange(c,request(3,[enumeration(0x420057,8),structure(0x420125),
            structure(0x42005b,enumeration(0x420059,0x80000001),binary(0x42005a,b'Z'*65536))],v))
        opaque=get(payload(r),0x420094)[2]
    for fmt in MEDIA:
        for continuation in [STOP,CONTINUE,UNDO]:
            for maximum in [None,8*1024*1024]:
                with s.connect() as c:other=create_key(c,v)
                entries=[(10,[uid(opaque,v)])]*17+[(20,[uid(other,v)])]
                seq=len(audit(s))
                code,body=send(s,batch(v,entries,maximum,continuation),fmt)
                assert code==200,(fmt,continuation,maximum,code)
                response=decoded(body,fmt);r=results(response)
                expected=[0]*15+[1,1,0] if continuation==CONTINUE else [3 if continuation==UNDO else 0]*15+[1]
                assert [x[1] for x in r]==expected,(fmt,continuation,r)
                assert all(reason==2 for _,status,reason in r if status==1),r
                assert audit(s)[seq:]==[(op,status) for op,status,_ in r]
                assert len(encode(response))<=1024*1024
                bounded(body,fmt,maximum or 1024*1024)
                assert state(s,other)==(5 if continuation==CONTINUE else 1)
                assert [get(n,0x420093)[2] for n in children(response,0x42000f)]==[bytes([i]) for i in range(len(r))]
                lanes.append(dict(encoding=fmt,continuation=continuation,maximum_response_size=maximum,
                    wire_bytes=len(body),binary_equivalent_bytes=len(encode(response)),statuses=expected))
    return lanes

QUERY=(24,[enumeration(0x420074,1),enumeration(0x420074,2)])
def exact_query_limits(s):
    """Three Queries at the complete reply's binary-equivalent size and one below."""
    lanes=[]
    for fmt in MEDIA:
        for v in [(1,4),(2,1),(3,0)]:
            for continuation in [STOP,CONTINUE,UNDO]:
                code,body=send(s,batch(v,[QUERY]*3,None,continuation,'correlation'),fmt)
                assert code==200 and [x[1] for x in results(decoded(body,fmt))]==[0,0,0],(fmt,v,code)
                exact=binary_size(body,fmt);observed={}
                for max in [exact,exact-1]:
                    code,body=send(s,batch(v,[QUERY]*3,max,continuation,'correlation'),fmt)
                    assert code==200,(fmt,v,continuation,max,code);bounded(body,fmt,max)
                    response=decoded(body,fmt);r=results(response);statuses=[x[1] for x in r]
                    assert children(get(response,0x42007a),0x420105),'correlation must still be echoed'
                    assert [x[0] for x in r]==[24]*3,r
                    if v[0]<3:assert [get(n,0x420093)[2] for n in children(response,0x42000f)]==[bytes([i]) for i in range(3)]
                    if max==exact:
                        assert statuses==[0,0,0] and binary_size(body,fmt)==exact,(fmt,v,continuation,r)
                        assert fmt=='TTLV' or len(body)>max,(fmt,len(body),max)
                    else:
                        first=3 if continuation==UNDO else 0
                        assert statuses==[first,first,1] and r[2][2]==2,(fmt,v,continuation,r)
                    observed[max]=dict(statuses=statuses,wire_bytes=len(body),binary_equivalent_bytes=binary_size(body,fmt))
                lanes.append(dict(encoding=fmt,wire_version='.'.join(map(str,v)),continuation=continuation,exact_limit=exact,results=observed))
    return lanes

def exact_batch_side_effects(s):
    """[Create, Get placeholder, Destroy other] at the exact binary-equivalent limit and one below."""
    v=(2,1);lanes=[]
    def run(fmt,continuation,max):
        with s.connect() as c:other=create_key(c,v)
        count=objects(s);seq=len(audit(s))
        code,body=send(s,batch(v,[(1,[enumeration(0x420057,2),structure(0x420125,*ATTRS)]),(10,[]),(20,[uid(other,v)])],max,continuation),fmt)
        assert code==200,(fmt,continuation,max,code)
        return body,audit(s)[seq:],len(objects(s)-count),state(s,other)
    for fmt in MEDIA:
        for continuation in [STOP,UNDO,CONTINUE]:
            body,_,_,_=run(fmt,continuation,None);exact=binary_size(body,fmt);observed={}
            for max in [exact,exact-1]:
                body,rows,created,other_state=run(fmt,continuation,max);bounded(body,fmt,max)
                response=decoded(body,fmt);r=results(response);statuses=tuple(x[1] for x in r)
                assert [x[0] for x in r]==[1,10,20] and rows==[(op,st) for op,st,_ in r],(r,rows)
                assert [get(n,0x420093)[2] for n in children(response,0x42000f)]==[bytes([i]) for i in range(3)]
                if max==exact:
                    assert statuses==(0,0,0) and created==1 and other_state==5,(fmt,continuation,r,created,other_state)
                    assert binary_size(body,fmt)==exact and (fmt=='TTLV' or len(body)>max),(fmt,len(body),max)
                else:
                    first=3 if continuation==UNDO else 0
                    assert statuses==(first,first,1) and r[2][2]==2,(fmt,continuation,r)
                    assert created==(0 if continuation==UNDO else 1) and other_state==1,(fmt,continuation,created,other_state)
                observed[max]=dict(statuses=list(statuses),audit_rows=rows,created=created,other_state=other_state,
                    wire_bytes=len(body),binary_equivalent_bytes=binary_size(body,fmt))
            lanes.append(dict(encoding=fmt,continuation={STOP:'Stop',UNDO:'Undo',CONTINUE:'Continue'}[continuation],exact_limit=exact,results=observed))
    return lanes

def oasis_message_encoding_vectors(s):
    """MSGENC-JSON-M-1 and MSGENC-XML-M-1: Query with limits 256 (Response Too Large) and 2048 (Success)."""
    lanes=[]
    for fmt in ['JSON','XML']:
        for v in [(1,3),(1,4),(2,0),(2,1),(3,0)]:
            for step,max in [(0,256),(1,2048)]:
                label=f'MSGENC-{fmt}-M-1-{v[0]}{v[1]} step={step}'
                code,body=send(s,batch(v,[QUERY],max,None,label if v>=(2,0) else None),fmt)
                assert code==200,(label,code);bounded(body,fmt,max)
                r=results(decoded(body,fmt))
                expected=[(24,1,2)] if step==0 else [(24,0,None)]
                assert r==expected,(label,r)
                if step==1:assert len(body)>max,(label,len(body))
                lanes.append(dict(vector=label,maximum_response_size=max,results=r,wire_bytes=len(body),binary_equivalent_bytes=binary_size(body,fmt)))
    return lanes
GROUPS={'aggregate_binary_limit':aggregate_binary_limit,'query_limits':query_limits,'batch_side_effects':batch_side_effects,
    'correlation_and_transport':correlation_and_transport,'exact_query_limits':exact_query_limits,
    'exact_batch_side_effects':exact_batch_side_effects,'oasis_message_encoding_vectors':oasis_message_encoding_vectors}

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary',type=pathlib.Path,help='explicit native server; incompatible with --image')
    parser.add_argument('--image',help='packaged container server; native executable is used only for fixture setup')
    parser.add_argument('--engine',default='podman',choices=['podman','docker'])
    parser.add_argument('--output',type=pathlib.Path)
    parser.add_argument('--aggregate-only',action='store_true',help='only the aggregate binary-equivalent regression')
    parser.add_argument('--only',nargs='+',choices=list(GROUPS),help='run only these lane groups, in this order')
    args=parser.parse_args()
    if args.image and args.binary:parser.error('--binary is incompatible with --image')
    if args.aggregate_only and args.only:parser.error('--aggregate-only is incompatible with --only')
    groups=['aggregate_binary_limit'] if args.aggregate_only else args.only or list(GROUPS)
    # Earlier reports bounded JSON/XML bodies by Maximum Response Size; keep them.
    output=args.output or ROOT/('artifacts/response-size-ttlv-equivalent-image.json' if args.image else 'artifacts/response-size-ttlv-equivalent.json');output.parent.mkdir(parents=True,exist_ok=True)
    binary=(args.binary or ROOT/'target/debug/keytend-kmip-server').resolve();digest=sha(binary)
    identity=packaged_evidence(local_image_id(args.engine,args.image)) if args.image else {'runtime_binary_sha256':digest,'source_commit':source_commit()[0]}
    with tempfile.TemporaryDirectory(prefix='keytend-response-size-') as directory:
        s=HttpsContainer(directory,args.engine,args.image,draft=True,log_path=output.with_suffix('.server.log')) if args.image else HttpsServer(directory,draft=True,binary=binary)
        try:
            s.start()
            evidence={name:GROUPS[name](s) for name in groups}
        finally:s.stop()
    output.write_text(json.dumps({'status':'passed',**identity,'fixture_cli_binary_sha256':digest,'aggregate_only':args.aggregate_only,'experimental_v3_fixture':True,'groups':groups,'size_rule':'Maximum Response Size bounds binary TTLV-equivalent bytes; JSON/XML bodies are bounded by the 8 MiB server frame',**evidence},indent=2)+'\n')
    print('PASS Maximum Response Size over '+('container' if args.image else 'native')+' HTTPS (TTLV, JSON, XML) and TTLV',flush=True)
if __name__=='__main__':main()
