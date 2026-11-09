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

"""Actual Split Key registration/transfer across restart; no factory claim."""
import argparse,hashlib,json,os,pathlib,subprocess,tempfile
from image_evidence import local_image_id,packaged_evidence,source_commit
from https_client import HttpsServer,HttpsContainer,post
from test_runtime import ROOT
from wire import *

class SplitContainer(HttpsContainer):
    def base(self):return super().base()+['-e','KMIP_EXPERIMENTAL_V3=true']

def sha(path):return hashlib.sha256(path.read_bytes()).hexdigest()
def object_value(method,fmt):
    fields=[integer(0x42008b,3),integer(0x420044,2),integer(0x42008c,3 if method==1 else 2),enumeration(0x42008a,method)]
    if method==3:fields.append(node(0x420062,4,b'\0'*6+b'\1\1'))
    material=b'\0\xfe' if method==3 else bytes.fromhex('66c46a7754f94de420c7b1a7fff5ec56')
    fields.append(structure(0x420040,enumeration(0x420042,fmt),structure(0x420045,binary(0x420043,material))))
    return structure(0x420089,*fields)
def register_fields(v,method,fmt,polynomial):
    attrs=[enumeration(0x4201b6,polynomial)] if v[0]>=3 and method in [2,4] else []
    return [enumeration(0x420057,5),structure(0x420125 if v[0]>=2 else 0x420091,*attrs),object_value(method,fmt)]
def exchange_with(s,transport,n):
    if transport=='TLS':
        with s.connect() as c:return exchange(c,n)
    return post(s,n,transport.removeprefix('HTTPS-'))
def main():
    parser=argparse.ArgumentParser();parser.add_argument('--image');parser.add_argument('--engine',default='podman');args=parser.parse_args()
    runtime=packaged_evidence(local_image_id(args.engine,args.image)) if args.image else {'runtime_binary_sha256':sha(ROOT/'target/debug/keytend-kmip-server'),'source_commit':source_commit()[0]}
    sdk=ROOT/'interop/ovh';executable=ROOT/'.cache/split-go'
    verification=subprocess.check_output(['go','mod','verify'],cwd=sdk,text=True).strip();assert verification=='all modules verified',verification
    module=json.loads(subprocess.check_output(['go','list','-m','-json','github.com/ovh/kmip-go'],cwd=sdk,text=True))
    pin=json.loads((ROOT/'interop/clients.lock.json').read_text())['ovh']['commit']
    assert module['Version'].endswith(pin[:12]),module['Version']
    subprocess.run(['go','build','-mod=readonly','-o',str(executable),str(ROOT/'integration/split/client.go')],cwd=sdk,check=True)
    adapter_sha=sha(executable)
    out=ROOT/'artifacts';suffix='image' if args.image else 'native';report_path=out/f'split-objects-{suffix}.json'
    report_path.write_text(json.dumps({'status':'running'})+'\n')
    records=[];rejections=0;restores=0
    with tempfile.TemporaryDirectory(prefix='keytend-split-') as directory:
        server=SplitContainer(directory,args.engine,args.image) if args.image else HttpsServer(directory)
        server.draft=True
        try:
            server.start()
            env={**os.environ,'KMIP_PKI':str(server.pki),'KMIP_PORT':str(server.port),'KMIP_HTTPS_PORT':str(server.https)}
            created=subprocess.run([str(executable),'create'],env=env,text=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=120)
            (out/f'split-objects-{suffix}-go-create.log').write_text(created.stderr)
            assert created.returncode==0,created.stderr
            go_records=json.loads(created.stdout);assert len(go_records)==144
            manifest=pathlib.Path(directory)/'go-records.json';manifest.write_text(created.stdout)
            for v in [(1,0),(1,1),(1,2),(1,3),(1,4),(2,0),(2,1),(3,0)]:
                for method in [1,2,3,4]:
                    for fmt in [1,2]:
                        for polynomial in ([1,2] if v[0]>=3 and method in [2,4] else [2]):
                            for transport in ['TLS','HTTPS-TTLV','HTTPS-JSON','HTTPS-XML']:
                                response=exchange_with(server,transport,request(3,register_fields(v,method,fmt,polynomial),v=v))
                                if v[0]==1 and v[1]<2 and method==4:
                                    assert reason(response)==8;rejections+=1;continue
                                key=get(payload(response),0x420094)[2]
                                got=exchange_with(server,transport,request(10,[uid(key,v)],v=v))
                                assert get(payload(got),0x420089)==object_value(method,fmt)
                                if v[0]>=3 and method in [2,4] and polynomial==1:
                                    assert reason(exchange_with(server,transport,request(10,[uid(key)],v=(2,1))))==8;rejections+=1
                                records.append(dict(version=v,method=method,format=fmt,polynomial=polynomial,transport=transport,identifier=key))
            assert len(records)==256 and rejections==32
            server.stop();server.start()
            verified=subprocess.run([str(executable),'verify',str(manifest)],env=env,text=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=120)
            (out/f'split-objects-{suffix}-go-restart.log').write_text(verified.stderr)
            assert verified.returncode==0,verified.stderr
            assert json.loads(verified.stdout)['status']=='passed'
            for r in records:
                v=tuple(r['version']);transport=r['transport'];key=r['identifier']
                def call(op):return exchange_with(server,transport,request(op,[uid(key,v)],v=v))
                assert get(payload(call(10)),0x420089)==object_value(r['method'],r['format'])
                payload(call(21));assert reason(call(10))==13
                payload(call(22));assert get(payload(call(10)),0x420089)==object_value(r['method'],r['format'])
                exported=payload(call(43)) if v>=(1,4) else None
                payload(call(20));assert reason(call(10))==(0x36 if v>=(2,0) else 11)
                if exported is not None:
                    restored=exchange_with(server,transport,request(42,[*exported[2],node(0x420124,6,True)],v=v))
                    assert get(payload(restored),0x420094)[2]==key
                    assert get(payload(call(10)),0x420089)==object_value(r['method'],r['format'])
                    payload(call(20));restores+=1
        finally:server.stop()
    assert restores==144
    log_names=[f'split-objects-{suffix}-go-create.log',f'split-objects-{suffix}-go-restart.log']
    report=dict(status='passed',scope='Split Key Register/Get, ownership/version checks, archive/recover, exact bytes after real server restart, Destroy and 1.4+ Export/Import restore. Raw and Opaque formats. No Create/Join factory or full-conformance credit.',
        **runtime,
        sdk_repository='https://github.com/ovh/kmip-go',sdk_commit=pin,sdk_module_version=module['Version'],sdk_module_sum=module['Sum'],
        sdk_modules_verified=True,adapter_binary_sha256=adapter_sha,go_lanes=144,go_restart_lanes=144,numeric_lanes=256,numeric_restart_lanes=256,
        expected_numeric_rejections=rejections,export_import_restore_lanes=restores,go_version=subprocess.check_output(['go','version'],text=True).strip(),
        log_sha256={str(pathlib.Path('artifacts')/n):sha(out/n) for n in log_names})
    report_path.write_text(json.dumps(report,indent=2)+'\n')
    print(f'PASS {suffix}: 144 independent OVH SDK lanes and 256 numeric lanes, all exact after restart; 144 export/import restores; 32 version rejections')
if __name__=='__main__':main()
