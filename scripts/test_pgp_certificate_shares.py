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

"""Numeric certificate sharing matrix, including non-byte-aligned EC lengths and external shares."""
import argparse,json,pathlib,re,tempfile
from image_evidence import source_commit,local_image_id,packaged_evidence
from test_database import ContainerServer
from test_runtime import ROOT,Server
from test_pgp_certificates import fixtures
from test_runtime import sha
from wire import *
class DraftContainer(ContainerServer):
    def base(self):return super().base()+['-e','KMIP_EXPERIMENTAL_V3=true']

def main():
    p=argparse.ArgumentParser();p.add_argument('--image');p.add_argument('--engine',default='podman');a=p.parse_args()
    config=local_image_id(a.engine,a.image) if a.image else None;evidence=packaged_evidence(config) if config else {'runtime_binary_sha256':sha(ROOT/'target/debug/keytend-kmip-server'),'source_commit':source_commit()[0]}
    tags=(ROOT/'src/tags.rs').read_text()
    constant=lambda name:int(re.search(r'pub const '+name+r': u32 = (0x[0-9A-Fa-f]+)',tags).group(1),16)
    out=ROOT/'artifacts/pgp-certificate-shares';out.mkdir(exist_ok=True);rows=[]
    with tempfile.TemporaryDirectory(prefix='keytend-pgp-cert-shares-') as directory:
        path=pathlib.Path(directory)/'fixtures';path.mkdir(mode=0o700);values=fixtures(path);server=DraftContainer(directory,a.engine,a.image) if config else Server(directory,draft=True)
        def rpc(c,v,op,fields):return exchange(c,request(op,fields,v=v))
        def verify(c,v,identifier,data,meta):
            obj=get(payload(rpc(c,v,10,[uid(identifier,v)])),0x420013);assert get(obj,0x42001d)[2]==2 and get(obj,0x42001e)[2]==data
            tags=[0x42001d,0x4200ad,0x420028,0x42002a]
            selectors=[text(0x42000a,n) for n in ['Certificate Type','Certificate Length','Cryptographic Algorithm','Cryptographic Length']] if v[0]==1 else [enumeration(0x42013b,n) for n in tags]
            response=payload(rpc(c,v,11,[uid(identifier,v)]+selectors));actual={}
            if v[0]==1:
                mapping=dict(zip(['Certificate Type','Certificate Length','Cryptographic Algorithm','Cryptographic Length'],tags))
                actual={mapping[get(n,0x42000a)[2]]:get(n,0x42000b)[2] for n in children(response,0x420008)}
            else:actual={n[0]:n[2] for n in get(response,0x420125)[2]}
            assert actual==dict(zip(tags,[2,len(data),meta['algorithm'],meta['bits']]))
        def run(c,v,name,fmt,method):
            meta=values[name];data=(path/(name+'.'+fmt)).read_bytes();attributes=[enumeration(0x420028,meta['algorithm']),integer(0x42002a,meta['bits']),integer(0x42002c,0),integer(0x4200ad,len(data))]
            if v[0]==1:
                labels=['Cryptographic Algorithm','Cryptographic Length','Cryptographic Usage Mask','Certificate Length'];attributes=[structure(0x420008,text(0x42000a,label),node(0x42000b,n[1],n[2])) for label,n in zip(labels,attributes)]
            container=lambda data:structure(0x420091 if v[0]==1 else 0x420125,*data)
            certificate=structure(0x420013,enumeration(0x42001d,2),binary(0x42001e,data));identifier=get(payload(rpc(c,v,3,[enumeration(0x420057,1),container(attributes),certificate])),0x420094)[2]
            poly=[]
            # Resolve the draft tag from our pinned constant rather than guessing.
            if v[0]>=3 and method in [2,4]:
                poly=[enumeration(constant('SPLIT_KEY_POLYNOMIAL'),2)]
            fields=[enumeration(0x420057,5),uid(identifier,v),integer(0x42008b,3),integer(0x42008c,3 if method==1 else 2),enumeration(0x42008a,method),container(poly)]
            if method==3:fields.append(node(constant('PRIME_FIELD_SIZE'),4,((1<<4253)-1).to_bytes(536,'big')))
            parts=[n[2] for n in children(payload(rpc(c,v,40,fields)),0x420094)];selected=parts if method==1 else [parts[0],parts[2]]
            joined=get(payload(rpc(c,v,41,[enumeration(0x420057,1),*[uid(n,v) for n in selected],container([])])),0x420094)[2];verify(c,v,joined,data,meta)
            external=[]
            for part in selected:
                obj=get(payload(rpc(c,v,10,[uid(part,v)])),0x420089);external.append(get(payload(rpc(c,v,3,[enumeration(0x420057,5),container(poly),obj])),0x420094)[2])
            copied=get(payload(rpc(c,v,41,[enumeration(0x420057,1),*[uid(n,v) for n in external],container([])])),0x420094)[2];verify(c,v,copied,data,meta)
            rows.append({'version':'.'.join(map(str,v)),'fixture':name,'format':fmt,'method':method,'bits':meta['bits'],'local_join':joined,'external_join':copied})
        try:
            server.start()
            with server.connect() as c:
                for version in [(1,2),(1,3),(1,4),(2,0),(2,1),(3,0)]:
                    for name in values:
                        for fmt in ['asc','bin']:
                            for method in [1,2,4]:run(c,version,name,fmt,method)
                run(c,(2,1),'p256','bin',3)
            server.stop();server.start()
            with server.connect() as c:
                for row in rows:
                    v=tuple(map(int,row['version'].split('.')));data=(path/(row['fixture']+'.'+row['format'])).read_bytes();verify(c,v,row['local_join'],data,values[row['fixture']]);verify(c,v,row['external_join'],data,values[row['fixture']])
        finally:server.stop()
    report=dict(status='passed',scope='Numeric TLS 1.2/1.3/1.4/2.0/2.1/draft 3.0, five key families and armored/binary values, XOR/GF16/GF8 local/external reconstruction; one 2.1 P-256 binary prime-field case, then exact typed metadata and bytes after restart. Numeric records are not SDK coverage.',**evidence,records=rows,local_joins=len(rows),external_joins=len(rows),restart_checks=len(rows)*2)
    (out/('image.json' if config else 'native.json')).write_text(json.dumps(report,indent=2)+'\n');print('PASS PGP certificate sharing',len(rows),'local and external cases; exact restart checks')
if __name__=='__main__':main()
