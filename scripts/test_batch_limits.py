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

"""Independent TTLV/native or image probes for bounded batch failures and durable audit."""
import argparse, hashlib, json, pathlib, sqlite3, subprocess, tempfile
from image_evidence import source_commit, local_image_id, packaged_evidence
from test_runtime import Server
from test_database import ContainerServer
from wire import *

VERSIONS=[(1,1),(1,2),(1,3),(1,4),(2,0),(2,1),(3,0)]

def batch(v, entries, continuation):
    header=[version(v),enumeration(0x42000e,continuation)]
    if v[0]<3:header.append(integer(0x42000d,len(entries)))
    return structure(0x420078,structure(0x420077,*header),*[
        structure(0x42000f,enumeration(0x42005c,op),
            *([binary(0x420093,bytes([i]))] if v[0]<3 else []),structure(0x420079,*fields))
        for i,(op,fields) in enumerate(entries)])

def create(v):
    attrs=[enumeration(0x420028,3),integer(0x42002a,256),integer(0x42002c,12)]
    return 1,[enumeration(0x420057,2),structure(0x420091,*map(attr,attrs)) if v[0]==1 else structure(0x420125,*attrs)]

def audit(s):
    with sqlite3.connect(s.data/'kmip.sqlite') as db:
        return db.execute('SELECT operation,status FROM audit ORDER BY seq').fetchall()

def objects(s):
    with sqlite3.connect(s.data/'kmip.sqlite') as db:
        return db.execute('SELECT COUNT(*) FROM objects').fetchone()[0]

def results(response,v,entries,expected,indices=None):
    items=children(response,0x42000f)
    assert [get(i,0x42007f)[2] for i in items]==expected,(v,expected,response)
    if v[0]<3:assert get(get(response,0x42007a),0x42000d)[2]==len(items)
    else:assert not children(get(response,0x42007a),0x42000d)
    indices=indices or list(range(len(items)))
    for i,index in zip(items,indices):
        assert get(i,0x42005c)[2]==entries[index][0]
        if v[0]<3:assert get(i,0x420093)[2]==bytes([index])
        else:assert not children(i,0x420093)
        if get(i,0x42007f)[2]==1:assert not children(i,0x42007c)
    return items

def restart_check(s):
    s.stop()
    command=(s.base()+[s.image,'check-store','--database','/data/kmip.sqlite',
        '--master-key','/tls/master.key']) if isinstance(s,ContainerServer) else [s.binary,
        'check-store','--database',str(s.data/'kmip.sqlite'),'--master-key',str(s.pki/'master.key')]
    subprocess.run(command,check=True,stdout=subprocess.DEVNULL)
    s.start()

def protection(s):
    lanes=[]
    for v in VERSIONS:
        for op in [5,31,33,35,10,43]:
            fields=[structure(0x420047)] if op in [10,43] else []
            entries=[create(v),(op,fields),create(v),(24,[enumeration(0x420074,1)])]
            start=len(audit(s));before=objects(s)
            with s.connect() as c:response=exchange(c,batch(v,entries,3))
            items=results(response,v,entries,[3,1])
            # The invalid protection request now executes and fails for its own
            # reason; Undo no longer refuses protection output as a capability.
            assert get(items[1],0x42007e) is not None
            assert objects(s)==before and audit(s)[start:]==[(1,3),(op,1)]
            lanes.append(dict(version=list(v),operation=op,statuses=[3,1]))
    restart_check(s)
    assert objects(s)==0 and len(audit(s))==84
    return lanes

def split(s):
    lanes=[]
    for v in VERSIONS[1:]:
        for count,parts in [(5,3),(3,43),(4,32)]:
            for continuation in [1,2,3]:
                fields=[enumeration(0x420057,5),integer(0x42008b,parts),integer(0x42008c,2),
                    enumeration(0x42008a,4),
                    structure(0x420125,*create(v)[1][1][2],enumeration(0x4201b6,2)) if v[0]>=3 else create(v)[1][1]]
                entries=[(40,fields)]*count+[(24,[enumeration(0x420074,1)])]
                expected=[0]*(count+1) if count==4 else [3 if continuation==3 else 0]*(count-1)+[1]+([0] if continuation==1 else [])
                start=len(audit(s));before=objects(s)
                with s.connect() as c:response=exchange(c,batch(v,entries,continuation))
                items=results(response,v,entries,expected)
                if count!=4:assert get(items[count-1],0x42007e)[2]==(0x3a if v[0]>=2 else 0x100)
                assert audit(s)[start:]==[(entries[i][0],status) for i,status in enumerate(expected)]
                increase=128 if count==4 else (0 if continuation==3 else (count-1)*parts)
                restart_check(s)
                assert objects(s)==before+increase
                lanes.append(dict(version=list(v),continuation=continuation,factories=count,parts=parts,statuses=expected))
    return lanes

def expansion(s):
    v=(2,1);lanes=[];first=None
    with s.connect() as c:
        for _ in range(125):
            identifier=create_key(c,v)
            first=first or identifier
    for count in [125,126,128]:
        while objects(s)<count:
            with s.connect() as c:create_key(c,v)
        for continuation in [1,2,3]:
            # Check is mutation free, so the same objects exercise every mode.
            entries=[(9,[uid(first,v)]),(8,[]),(10,[enumeration(0x420094,11)]),(24,[enumeration(0x420074,1)])]
            expected=[0]*128 if count==125 else [3 if continuation==3 else 0]*2+[1]+([0] if continuation==1 else [])
            indices=[0,1]+[2]*125+[3] if count==125 else None
            start=len(audit(s))
            with s.connect() as c:response=exchange(c,batch(v,entries,continuation))
            items=results(response,v,entries,expected,indices)
            if count>125:assert get(items[2],0x42007e)[2]==0x3a
            expected_ops=[entries[i][0] for i in (indices or list(range(len(expected))))]
            assert audit(s)[start:]==list(zip(expected_ops,expected))
            restart_check(s);assert objects(s)==count
            lanes.append(dict(objects=count,continuation=continuation,response_items=len(items),statuses=expected if count>125 else '128 successes'))
    return lanes

def validation_capacity(s):
    lanes=[]
    for v in VERSIONS:
        for continuation in [1,2,3]:
            with s.connect() as c:
                boundary=exchange(c,request(23,[uid('missing-'+str(i),v) for i in range(32)],v))
            assert get(children(boundary,0x42000f)[0],0x42007e)[2]==1
            entries=[(24,[enumeration(0x420074,1)]),(23,[uid('missing-'+str(i),v) for i in range(33)]),(24,[enumeration(0x420074,1)])]
            start=len(audit(s))
            with s.connect() as c:response=exchange(c,batch(v,entries,continuation))
            expected=[0,1,0] if continuation==1 else [0 if continuation==2 else 3,1]
            items=results(response,v,entries,expected)
            actual=get(items[1],0x42007e)[2];wanted=0x3a if v[0]>=2 else 0x100
            if actual!=wanted:print('FAIL validation capacity',v,continuation,'expected reason',wanted,'received',actual,flush=True)
            assert actual==wanted,(v,continuation,wanted,actual)
            assert audit(s)[start:]==[(entries[i][0],status) for i,status in enumerate(expected)]
            restart_check(s);assert objects(s)==0
            lanes.append(dict(version=list(v),continuation=continuation,identifiers=33,reason=actual,statuses=expected))
    return lanes

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary',type=pathlib.Path)
    parser.add_argument('--image')
    parser.add_argument('--engine',default='podman',choices=['podman','docker'])
    parser.add_argument('--output',type=pathlib.Path,required=True)
    parser.add_argument('--probe',action='append',choices=['protection','split','expansion','validation'])
    args=parser.parse_args()
    if args.image and args.binary:parser.error('--image is incompatible with --binary')
    if not args.image and not args.binary:parser.error('provide --binary or --image')
    from test_runtime import ROOT
    binary=(args.binary or ROOT/'target/debug/keytend-kmip-server').resolve()
    args.output.parent.mkdir(parents=True,exist_ok=True)
    digest=hashlib.sha256(binary.read_bytes()).hexdigest()
    identity=packaged_evidence(local_image_id(args.engine,args.image)) if args.image else {}
    lanes={}
    for name,probe in [('protection',protection),('split',split),('expansion',expansion),('validation',validation_capacity)]:
        if args.probe and name not in args.probe:continue
        with tempfile.TemporaryDirectory(prefix='keytend-batch-ca4e477c-'+name+'-') as directory:
            server=ContainerServer(directory,args.engine,args.image,binary=binary,draft=True,log_path=args.output.with_name(args.output.stem+'-'+name+'-server.log')) if args.image else Server(directory,binary=binary,draft=True)
            try:
                server.start();lanes[name]=probe(server)
            finally:server.stop()
            if args.image:assert not server.container_exists()
        print('PASS',name,len(lanes[name]),flush=True)
    result=dict(status='passed',scope='Focused batch/SQLite fixture only; no production database or full conformance claim',
        lanes=lanes,
        **({'server_mode':'container','fixture_cli_sha256':digest,**identity} if args.image else
           {'server_mode':'native','runtime_binary_sha256':digest,'source_commit':source_commit()[0]}))
    args.output.parent.mkdir(parents=True,exist_ok=True)
    args.output.write_text(json.dumps(result,indent=2)+'\n')

if __name__=='__main__':main()
