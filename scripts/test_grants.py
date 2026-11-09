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

"""Real TLS grants, operation intersection, fresh-auth revocation and encrypted identity."""
import hashlib,json,ssl,subprocess,tempfile
from image_evidence import source_commit
from test_runtime import ROOT,Server
from wire import *

def run(server):
    passed=[];policy_path=server.pki/'policy.json';policy=json.loads(policy_path.read_text());other=hashlib.sha256(ssl.PEM_cert_to_DER_cert((server.pki/'other.pem').read_text())).hexdigest()
    def configure(identifier,operations,global_ops=None):
        server.stop();principal=policy['principals'][other];principal['object_grants']=[] if identifier is None else [{'owner':'database','identifier':identifier,'operations':operations}]
        if global_ops is not None:principal['operations']=global_ops
        policy_path.write_text(json.dumps(policy));server.start()
    def denied(identifier,version):
        with server.connect(identity='other') as c:assert reason(exchange(c,request(10,[uid(identifier,version)],version))) in [1,12]
    for version in [(1,1),(1,2),(1,3),(1,4),(2,0),(2,1),(3,0)]:
        with server.connect() as c:
            shared=create_key(c,version);hidden=create_key(c,version);original=key_value(c,shared,version)
        denied(shared,version);configure(shared,[10],[8,10,11,12,24,30])
        with server.connect(identity='other') as c:
            assert key_value(c,shared,version)==original
            assert reason(exchange(c,request(10,[uid(hidden,version)],version)))==1
            assert reason(exchange(c,request(11,[uid(shared,version)],version)))==1
            assert not children(payload(exchange(c,request(8,[],version))),0x420094)
            for op in [1,13,20]:assert reason(exchange(c,request(op,[uid(shared,version)],version)))==12
        configure(shared,[8])
        with server.connect(identity='other') as c:
            listing=payload(exchange(c,request(8,[],version)));assert [n[2] for n in children(listing,0x420094)]==[shared]
            assert reason(exchange(c,request(10,[uid(shared,version)],version)))==1
        configure(shared,[10],[8,11,12,24,30]);denied(shared,version)
        configure(shared,[10],[8,10,11,12,24,30])
        with server.connect(identity='other') as c:assert key_value(c,shared,version)==original
        configure(None,[]);denied(shared,version)
        with server.connect() as c:assert key_value(c,shared,version)==original
        passed.append({'wire_version':'.'.join(map(str,version)),'get_only':True,'list_only':True,'exact_object_isolation':True,'read_only_operation_acl':True,'global_operation_intersection':True,'fresh_auth_revocation_after_restart':True,'owner_exact_bytes_preserved':True})
    # Exercise exact grant identity with actual caller-chosen restored IDs.
    version=(2,1);identifiers=['tenant:雪:'+('x'*256)+':literal*key', 'tenant:雪:'+('x'*256)+':literal-other-key', 'tenant:é', 'tenant:e\u0301', 'tenant:nul\0key']
    expected={}
    with server.connect() as c:
        for identifier in identifiers:
            source=create_key(c,version);expected[identifier]=key_value(c,source,version)
            exported=payload(exchange(c,request(43,[uid(source,version)],version)))
            original_attrs=get(exported,0x420125)
            attrs=structure(0x420125,*[text(0x420094,identifier) if n[0]==0x420094 else binary(0x420136,hashlib.sha256(identifier.encode()).digest()) if n[0]==0x420136 else n for n in original_attrs[2]])
            imported=payload(exchange(c,request(42,[uid(identifier,version),get(exported,0x420057),attrs,get(exported,0x42008f)],version)))
            assert get(imported,0x420094)[2]==identifier
        assert len(set(expected.values()))==len(identifiers)
    for identifier in identifiers:
        configure(identifier,[10])
        with server.connect(identity='other') as c:
            assert key_value(c,identifier,version)==expected[identifier]
            for hidden in identifiers:
                if hidden!=identifier:assert reason(exchange(c,request(10,[uid(hidden,version)],version)))==1
    configure(None,[])
    server.stop()
    subprocess.run([server.binary,'check-store','--database',str(server.data/'kmip.sqlite'),'--master-key',str(server.pki/'master.key')],check=True)
    return passed,{'long_unicode_literal_wildcard':True,'nfc_nfd_distinct_keys':True,'embedded_nul_literal':True,'exact_grant_and_revocation':True}

def main():
    binary=ROOT/'target/debug/keytend-kmip-server';binary_hash=hashlib.sha256(binary.read_bytes()).hexdigest()
    with tempfile.TemporaryDirectory(prefix='keytend-grants-') as directory:
        server=Server(directory,draft=True)
        try:server.start();results,identifiers=run(server)
        finally:server.stop()
    (ROOT/'artifacts/grants.json').write_text(json.dumps({'status':'passed','source_commit':source_commit()[0],'runtime_binary_sha256':binary_hash,'versions':results,'opaque_identifiers':identifiers,'limits':['Read grants only: Locate, Get, Get Attributes, Get Attribute List','Policy changes require controlled restart; existing connections are closed','No ownership transfer or foreign wrapping-key use is authorized']},indent=2)+'\n');print('PASS real TLS object grants on seven versions and audit integrity')
if __name__=='__main__':main()
