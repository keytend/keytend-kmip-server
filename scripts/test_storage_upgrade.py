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

"""Verify an older schema-v1 through v14 image upgrades and refuses the resulting v15 store.
Requires an older local image; uses only disposable containers/data/certificates.
"""
import argparse,hashlib,json,pathlib,sqlite3,subprocess,tempfile
from test_runtime import ROOT,Server,free_port
from test_database import ContainerServer
from image_evidence import local_image_id,source_commit
from wire import *

def schema(path):
    connection=sqlite3.connect(f'file:{path}?mode=ro',uri=True)
    try:return connection.execute('PRAGMA user_version').fetchone()[0]
    finally:connection.close()

def main():
    p=argparse.ArgumentParser();p.add_argument('--older-image',required=True);p.add_argument('--engine',default='podman',choices=['podman','docker']);p.add_argument('--output',type=pathlib.Path,default=ROOT/'artifacts/storage-upgrade.json');a=p.parse_args()
    output=a.output;output.parent.mkdir(exist_ok=True)
    output.write_text(json.dumps({'status':'running'})+'\n')
    subprocess.run(['cargo','build','--locked'],cwd=ROOT,check=True)
    binary_sha=hashlib.sha256((ROOT/'target/debug/keytend-kmip-server').read_bytes()).hexdigest()
    older_id=local_image_id(a.engine,a.older_image);passed=[]
    with tempfile.TemporaryDirectory(prefix='keytend-kmip-server-storage-upgrade-') as d:
        legacy=ContainerServer(d,a.engine,a.older_image)
        try:
            legacy.start()
            legacy_pgp_id=None;legacy_pgp_parts=[]
            with legacy.connect() as c:
                id=create_key(c);key=key_value(c,id);payload(exchange(c,request(18,[uid(id)])))
                old_opaque=structure(0x42005b,enumeration(0x420059,0x80000000),binary(0x42005a,b'legacy opaque object'))
                old_opaque_id=get(payload(exchange(c,request(3,[enumeration(0x420057,8),structure(0x420091),old_opaque]))),0x420094)[2]
                if schema(legacy.data/'kmip.sqlite')>=14:
                    old_pgp_bytes=json.loads((ROOT/'tests/fixtures/openpgp.json').read_text())['v3_public'].encode()
                    old_pgp=structure(0x4200bd,integer(0x4200be,3),structure(0x420040,enumeration(0x420042,2),
                        structure(0x420045,binary(0x420043,old_pgp_bytes)),enumeration(0x420028,4),integer(0x42002a,2048)))
                    legacy_pgp_id=get(payload(exchange(c,request(3,[enumeration(0x420057,9),structure(0x420125,integer(0x42002c,0)),old_pgp],v=(2,1)))),0x420094)[2]
                    legacy_pgp_parts=[n[2] for n in children(payload(exchange(c,request(40,[enumeration(0x420057,5),uid(legacy_pgp_id),integer(0x42008b,3),integer(0x42008c,2),enumeration(0x42008a,4),structure(0x420125)],v=(2,1)))),0x420094)]

            legacy.stop();database=legacy.data/'kmip.sqlite';older_schema=schema(database);assert older_schema in range(1,15)
            passed.append(f'previous image created and activated a durable key in a schema-v{older_schema} store')
            # Reuse its data and credentials with the current native server.
            # Use fresh endpoints so a rootless port-forward's asynchronous
            # teardown cannot be mistaken for readiness of the replacement.
            legacy.port=free_port();legacy.health=free_port();legacy.draft=True
            Server.start(legacy)
            with legacy.connect() as c:
                assert key_value(c,id)==key
                def storage_mask(identifier):
                    return get(get(payload(exchange(c,request(11,[uid(identifier),enumeration(0x42013b,0x42015e)],v=(2,1)))),0x420125),0x42015e)[2]
                assert storage_mask(id)==1
                if legacy_pgp_id:
                    assert get(payload(exchange(c,request(10,[uid(legacy_pgp_id)],v=(2,1)))),0x4200bd)==old_pgp
                    exported=payload(exchange(c,request(43,[uid(legacy_pgp_id)],v=(2,1))))
                    assert not children(get(exported,0x420125),0x4200ae),'do not invent legacy signature algorithms'
                    fields=[structure(0x420125,*n[2],enumeration(0x4200ae,7)) if n[0]==0x420125 else n for n in exported[2]]
                    payload(exchange(c,request(42,[*fields,node(0x420124,6,True)],v=(2,1))))
                    assert reason(exchange(c,request(41,[enumeration(0x420057,9),uid(legacy_pgp_parts[0]),uid(legacy_pgp_parts[2])],v=(2,1))))==6
                    legacy_pgp_join=get(payload(exchange(c,request(41,[enumeration(0x420057,9),uid(legacy_pgp_parts[0]),uid(legacy_pgp_parts[2]),structure(0x420125,enumeration(0x4200ae,7))],v=(2,1)))),0x420094)[2]
                    assert get(payload(exchange(c,request(10,[uid(legacy_pgp_join)],v=(2,1)))),0x4200bd)==old_pgp
                    passed.append('schema-14 PGP remains byte-exact; explicit privileged metadata restoration and declared Join metadata repair the missing signature attribute without guessing')

                assert get(payload(exchange(c,request(10,[uid(old_opaque_id)]))),0x42005b)==old_opaque
                assert get(get(payload(exchange(c,request(11,[uid(old_opaque_id),enumeration(0x42013b,0x420059)],v=(2,1)))),0x420125),0x420059)[2]==0x80000000
                new_opaque=structure(0x42005b,enumeration(0x420059,0x80001234),binary(0x42005a,b'new opaque object'))
                new_opaque_id=get(payload(exchange(c,request(3,[enumeration(0x420057,8),structure(0x420125),new_opaque],v=(2,1)))),0x420094)[2]
                empty_opaque=structure(0x42005b,enumeration(0x420059,0x8fffffff),binary(0x42005a,b''))
                empty_opaque_id=get(payload(exchange(c,request(3,[enumeration(0x420057,8),structure(0x420125),empty_opaque],v=(2,1)))),0x420094)[2]
                metadata=get(payload(exchange(c,request(11,[uid(id),*[enumeration(0x42013b,tag) for tag in [0x4200a8,0x420121,0x420123]]],v=(2,1)))),0x420125)
                assert get(metadata,0x4200a8)[2]==0
                assert get(metadata,0x420121)[2]==0 and get(metadata,0x420123)[2]==0
                password=structure(0x420085,enumeration(0x420086,1),structure(0x420040,enumeration(0x420042,1),structure(0x420045,node(0x420043,8,b'upgrade-password'))))
                password_id=get(payload(exchange(c,request(3,[enumeration(0x420057,7),structure(0x420125,integer(0x42002c,512)),password],v=(2,1)))),0x420094)[2]
                usage=structure(0x420095,node(0x420097,3,1),enumeration(0x420098,2))
                payload(exchange(c,request(13,[uid(id),structure(0x42013d,usage)],v=(2,1))))
                payload(exchange(c,request(17,[uid(id),node(0x420096,3,1)],v=(2,1))))
                assert reason(exchange(c,request(17,[uid(id),node(0x420096,3,1)],v=(2,1))))==0x1a
                for value in ['first','second']:
                    attribute=structure(0x420008,text(0x42000a,'x-migration'),text(0x42000b,value))
                    payload(exchange(c,request(13,[uid(id),attribute],v=(1,4))))
                payload(exchange(c,request(15,[uid(id),text(0x42000a,'x-migration'),integer(0x420009,0)],v=(1,4))))
                def split_source(identifier, method):
                    return [n[2] for n in children(payload(exchange(c,request(40,[enumeration(0x420057,5),uid(identifier),
                        integer(0x42008b,3),integer(0x42008c,2),enumeration(0x42008a,method),structure(0x420125),structure(0x42015f,integer(0x42015e,0))],v=(2,1)))),0x420094)]
                factory_parts=split_source(id,2)
                opaque_parts=split_source(new_opaque_id,4)
                outer_parts=split_source(factory_parts[0],4)
                pgp_fixture=json.loads((ROOT/'tests/fixtures/openpgp.json').read_text())['v3_public'].encode()
                pgp=structure(0x4200bd,integer(0x4200be,3),structure(0x420040,enumeration(0x420042,2),
                    structure(0x420045,binary(0x420043,pgp_fixture)),enumeration(0x420028,4),integer(0x42002a,2048)))
                pgp_id=get(payload(exchange(c,request(3,[enumeration(0x420057,9),structure(0x420125,integer(0x42002c,0),enumeration(0x4200ae,7)),pgp],v=(2,1)))),0x420094)[2]
                pgp_parts=split_source(pgp_id,4)

                joined_id=get(payload(exchange(c,request(41,[enumeration(0x420057,2),uid(factory_parts[0]),uid(factory_parts[2])],v=(2,1)))),0x420094)[2]
                assert key_value(c,joined_id)==key
                link=node(0x42019c,14,'future-database')
                payload(exchange(c,request(13,[uid(id,(3,0)),structure(0x42013d,link)],v=(3,0))))
                split=structure(0x420089,integer(0x42008b,3),integer(0x420044,2),integer(0x42008c,2),enumeration(0x42008a,4),
                    structure(0x420040,enumeration(0x420042,1),structure(0x420045,node(0x420043,8,b'schema-eleven-share'))))
                split_id=get(payload(exchange(c,request(3,[enumeration(0x420057,5),structure(0x420125,enumeration(0x4201b6,2)),split],v=(3,0)))),0x420094)[2]
            assert schema(database)==15
            passed.append('current server upgraded to schema v15, preserved exact key bytes and enforced a lifetime allocation')
            refused=subprocess.run(legacy.base()+[a.older_image,'check-store','--database','/data/kmip.sqlite','--master-key','/tls/master.key'],stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True,timeout=30)
            assert refused.returncode!=0 and 'database schema is newer than this binary' in refused.stdout,refused.stdout
            passed.append('previous binary refused the v15 store before dropping split fields, budgets or stable attribute indices')
            Server.stop(legacy);Server.start(legacy)
            with legacy.connect() as c:
                assert key_value(c,id)==key
                assert get(payload(exchange(c,request(10,[uid(old_opaque_id)]))),0x42005b)==old_opaque
                assert get(payload(exchange(c,request(10,[uid(new_opaque_id)]))),0x42005b)==new_opaque
                assert get(payload(exchange(c,request(10,[uid(empty_opaque_id)]))),0x42005b)==empty_opaque
                assert get(payload(exchange(c,request(10,[uid(pgp_id)],v=(2,1)))),0x4200bd)==pgp
                pgp_join=get(payload(exchange(c,request(41,[enumeration(0x420057,9),uid(pgp_parts[0]),uid(pgp_parts[2])],v=(2,1)))),0x420094)[2]
                assert get(payload(exchange(c,request(10,[uid(pgp_join)],v=(2,1)))),0x4200bd)==pgp
                for identifier in [pgp_id,pgp_join]+([legacy_pgp_id,legacy_pgp_join] if legacy_pgp_id else []):
                    signature_attrs=get(payload(exchange(c,request(11,[uid(identifier),enumeration(0x42013b,0x4200ae)],v=(2,1)))),0x420125)
                    assert get(signature_attrs,0x4200ae)[2]==7


                opaque_join=get(payload(exchange(c,request(41,[enumeration(0x420057,8),uid(opaque_parts[0]),uid(opaque_parts[2])],v=(2,1)))),0x420094)[2]
                assert get(payload(exchange(c,request(10,[uid(opaque_join)]))),0x42005b)==new_opaque
                assert reason(exchange(c,request(17,[uid(id),node(0x420096,3,1)],v=(2,1))))==0x1a
                stored_attrs=children(payload(exchange(c,request(11,[uid(id),text(0x42000a,'x-migration')],v=(1,4)))),0x420008)
                assert len(stored_attrs)==1 and get(stored_attrs[0],0x420009)[2]==1 and get(stored_attrs[0],0x42000b)[2]=='second'
                attrs=get(payload(exchange(c,request(11,[uid(id,(3,0)),enumeration(0x42013b,0x42019c)],v=(3,0)))),0x420125)
                assert get(attrs,0x42019c)[1:]==(14,'future-database')
                secret=get(payload(exchange(c,request(10,[uid(password_id)],v=(2,1)))),0x420085)
                assert get(secret,0x420086)[2]==1
                assert get(payload(exchange(c,request(10,[uid(split_id,(3,0))],v=(3,0)))),0x420089)==split
                split_attrs=get(payload(exchange(c,request(11,[uid(split_id,(3,0))],v=(3,0)))),0x420125)
                assert get(split_attrs,0x4201b6)[2]==2 and get(split_attrs,0x42008a)[2]==4
                assert get(get(get(secret,0x420040),0x420045),0x420043)[2]==b'upgrade-password'
                metadata=get(payload(exchange(c,request(11,[uid(id),*[enumeration(0x42013b,tag) for tag in [0x4200a8,0x420121,0x420123]]],v=(2,1)))),0x420125)
                assert get(metadata,0x4200a8)[2]==0
                assert get(metadata,0x420121)[2]==0 and get(metadata,0x420123)[2]==0
                restored_part=get(payload(exchange(c,request(41,[enumeration(0x420057,5),uid(outer_parts[2]),uid(outer_parts[0])],v=(2,1)))),0x420094)[2]
                restored_key=get(payload(exchange(c,request(41,[enumeration(0x420057,2),uid(restored_part),uid(factory_parts[2])],v=(2,1)))),0x420094)[2]
                assert key_value(c,restored_key)==key and key_value(c,joined_id)==key
                assert storage_mask(id)==1 and all(storage_mask(part)==0 for part in factory_parts+outer_parts)
                assert storage_mask(joined_id)==1 and storage_mask(restored_part)==1 and storage_mask(restored_key)==1
            passed.append('legacy records default to Software; explicit zero selections and independent factory storage survive upgrade/restart')
            passed.append('legacy opaque type defaults correctly; non-default and empty opaque objects and Split Key provenance retain exact types/data after upgrade and restart')
            passed.append('PGP v3 container, declared primary-key length and exact bytes survive upgrade/restart and local Split Key reconstruction')
            passed.append('schema-15 encrypted factory provenance restored nested Split Key metadata and exact key material after restart')
            passed.append('upgraded server restart retained exact key material and exhausted budget')
            passed.append('conservative Fresh and extraction histories remain correct after upgrade and restart')
            passed.append('Password Secret Data type and exact bytes survive the schema-v15 store restart')
            passed.append('Split Key fields, polynomial and exact share bytes survive upgrade and restart')
            passed.append('stable attribute index 1 survived deletion of index 0 and server restart')
            passed.append('late-bound draft NameReference remained typed and persisted across restart')
            with legacy.connect() as c:
                payload(exchange(c,request(15,[uid(id,(3,0)),enumeration(0x42013b,0x42019c)],v=(3,0))))
                replacement_id=get(payload(exchange(c,request(4,[uid(id)],v=(2,1)))),0x420094)[2]
                replacement_key=key_value(c,replacement_id)
                payload(exchange(c,request(15,[uid(id),text(0x42000a,'Link'),integer(0x420009,0)])))
            Server.stop(legacy);Server.start(legacy)
            with legacy.connect() as c:
                assert reason(exchange(c,request(4,[uid(id)],v=(2,1))))==12
                assert key_value(c,id)==key and key_value(c,replacement_id)==replacement_key
            passed.append('server-owned Re-key guard survived mutable link deletion and restart')
            with legacy.connect() as c:payload(exchange(c,request(21,[uid(replacement_id)],v=(2,1))))
            Server.stop(legacy);Server.start(legacy)
            with legacy.connect() as c:
                assert reason(exchange(c,request(10,[uid(replacement_id)],v=(2,1))))==13
                payload(exchange(c,request(22,[uid(replacement_id)],v=(2,1))))
                assert key_value(c,replacement_id)==replacement_key
            passed.append('archival access policy survived restart; explicit recovery retained exact replacement material')
        finally:
            Server.stop(legacy);legacy.stop()
            log=pathlib.Path(d)/'server.log'
            if log.exists():output.with_suffix('.log').write_text(log.read_text())
    output.write_text(json.dumps({'status':'passed','older_image_config_id':older_id,'older_storage_format':older_schema,'source_commit':source_commit()[0],'runtime_binary_sha256':binary_sha,'storage_format':15,'passed':passed},indent=2)+'\n')
    for item in passed:print('PASS',item,flush=True)

if __name__=='__main__':main()
