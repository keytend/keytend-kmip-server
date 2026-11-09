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

"""Independent live checks for catalog fixture/correlation findings.
These probes never rewrite or reclassify the unchanged Java catalog results.
"""
import argparse,hashlib,json,tempfile
from cryptography.hazmat.primitives.keywrap import aes_key_unwrap
from image_evidence import local_image_id,packaged_evidence
from test_database import ContainerServer
from test_runtime import ROOT
from wire import *

def attributes(values,v):
    return structure(0x420091,*map(attr,values)) if v[0]==1 else structure(0x420125,*values)
def register(c,v,key,usage):
    obj=structure(0x42008f,structure(0x420040,enumeration(0x420042,1),structure(0x420045,binary(0x420043,key)),enumeration(0x420028,3),integer(0x42002a,len(key)*8)))
    return get(payload(exchange(c,request(3,[enumeration(0x420057,2),attributes([integer(0x42002c,usage)],v),obj],v))),0x420094)[2]
def record_attr(n):
    return structure(0x420008,text(0x42000a,'Cryptographic Parameters'),node(0x42000b,n[1],n[2]))
def run(server):
    reports=[]
    for v in [(1,1),(1,2),(1,3),(1,4),(2,0),(2,1)]:
        with server.connect() as c:
            kek=bytes(range(16));key=bytes(range(32));kek_id=register(c,v,kek,48);target=register(c,v,key,12)
            payload(exchange(c,request(18,[uid(kek_id,v)],v)))
            cp=structure(0x42002b,enumeration(0x420011,13))
            kws=structure(0x420047,enumeration(0x42009e,1),structure(0x420036,uid(kek_id,v),cp),enumeration(0x4200a3,1))
            rejected=exchange(c,request(10,[uid(target,v),kws],v));assert status(rejected)==1 and reason(rejected)==(1 if v[0]==1 else 7)
            payload(exchange(c,request(13,[uid(kek_id,v),record_attr(cp) if v[0]==1 else structure(0x42013d,cp)],v)))
            wrapped=payload(exchange(c,request(10,[uid(target,v),kws],v)))
            ciphertext=get(get(get(wrapped,0x42008f),0x420040),0x420045)[2]
            assert aes_key_unwrap(kek,ciphertext)==key
            # An ordered Undo stops at failure and returns the processed prefix.
            create=structure(0x42000f,enumeration(0x42005c,1),structure(0x420079,enumeration(0x420057,2),attributes([enumeration(0x420028,3),integer(0x42002a,256),integer(0x42002c,12)],v)))
            missing=structure(0x42000f,enumeration(0x42005c,10),structure(0x420079,uid('missing-catalog-probe',v)))
            identified=[structure(item[0],binary(0x420093,bytes([i])),*item[2]) for i,item in enumerate([create,missing,create],1)]
            batch=structure(0x420078,structure(0x420077,version(v),integer(0x42000d,3),enumeration(0x42000e,3),node(0x420010,6,True)),*identified)
            result=exchange(c,batch);items=children(result,0x42000f)
            assert [get(i,0x42007f)[2] for i in items]==[3,1], repr(result)
            assert get(get(result,0x42007a),0x42000d)[2]==2
            undone=get(get(items[0],0x42007c),0x420094)[2]
            absent=exchange(c,request(10,[uid(undone,v)],v));assert status(absent)==1 and reason(absent)==(0x37 if v[0]>=2 else 1)  # Object Not Found in 2.x tables
            row={'wire_version':'.'.join(map(str,v)),'missing_stored_wrapping_parameters':{'status':1,'reason':reason(rejected)},'matching_stored_wrapping_parameters':'independently unwrapped exact AES key','undo_response_statuses':[3,1],'undo_response_batch_count':2,'undone_object_absent':True}
            if v>=(1,4):
                exported=payload(exchange(c,request(43,[uid(target,v)],v)))
                restored='rust-catalog:雪:'+('x'*256)
                if v[0]==1:
                    attrs=[]
                    for a in children(exported,0x420008):
                        if get(a,0x42000a)[2]=='Unique Identifier':
                            a=structure(0x420008,*[text(0x42000b,restored) if n[0]==0x42000b else n for n in a[2]])
                        attrs.append(a)
                else:
                    attrs=[structure(0x420125,*[text(0x420094,restored) if n[0]==0x420094 else binary(0x420136,hashlib.sha256((restored+str(v)).encode()).digest()) if n[0]==0x420136 else n for n in get(exported,0x420125)[2]])]
                # Separate version fixtures share storage, so scope the caller ID.
                restored+=':'+str(v)
                if v[0]==1:
                    attrs=[structure(0x420008,*[text(0x42000b,restored) if n[0]==0x42000b else n for n in a[2]]) if get(a,0x42000a)[2]=='Unique Identifier' else a for a in attrs]
                else:
                    attrs=[structure(0x420125,*[text(0x420094,restored) if n[0]==0x420094 else n for n in attrs[0][2]])]
                imported=payload(exchange(c,request(42,[uid(restored,v),enumeration(0x420057,2),*attrs,get(exported,0x42008f)],v)))
                assert get(imported,0x420094)[2]==restored and key_value(c,restored,v)==key
                row['unicode_explicit_uid_restore']={'exact_utf8':True,'bytes':len(restored.encode()),'restore_metadata':'supplied from Export'}
            reports.append(row)
    return reports

def main():
    p=argparse.ArgumentParser();p.add_argument('--engine',default='podman');p.add_argument('--image',default='localhost/keytend-kmip-server:dev');a=p.parse_args()
    image=packaged_evidence(local_image_id(a.engine,a.image))
    with tempfile.TemporaryDirectory(prefix='keytend-contract-') as directory:
        server=ContainerServer(directory,a.engine,a.image)
        try:server.start();results=run(server)
        finally:server.stop()
    (ROOT/'artifacts/catalog-probes.json').write_text(json.dumps({'status':'passed','scope':'Independent normative contract probes, not unchanged Java catalog passes',**image,'versions':results},indent=2)+'\n')
    print('PASS six-version wrapping and Undo probes; three-version Unicode restore')
if __name__=='__main__':main()
