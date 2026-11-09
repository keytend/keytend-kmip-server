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

"""Test an existing disposable cluster. Applies only the keytend-kmip-server namespace.
Load the built image into the cluster before running; requires kubectl on PATH.
"""
import argparse,hashlib,json,os,pathlib,ssl,subprocess,time
from types import SimpleNamespace
from https_client import MEDIA,post
from test_runtime import ROOT,free_port
from wire import *
from image_evidence import normalized_id,packaged_evidence
parser=argparse.ArgumentParser();parser.add_argument('--kubeconfig',required=True);parser.add_argument('--image',help='override the fixture StatefulSet image with an already loaded image');parser.add_argument('--pki',default=str(ROOT/'.cache/kube-pki'));parser.add_argument('--kubectl',default='kubectl');parser.add_argument('--kind-node',help='optional local kind node container for CRI/package identity verification');parser.add_argument('--engine',default='podman',choices=['podman','docker']);a=parser.parse_args()
k=[a.kubectl,'--kubeconfig',str(pathlib.Path(a.kubeconfig).resolve())]
def command(*args,**kwargs):return subprocess.check_output(k+list(args),text=True,stderr=subprocess.STDOUT,**kwargs)
def resource(args):
    # Secret material stays in the subprocess pipe and is never printed.
    encoded=command(*args,'--dry-run=client','-o','json')
    subprocess.run(k+['apply','-f','-'],input=encoded,text=True,stdout=subprocess.DEVNULL,check=True)
pki=pathlib.Path(a.pki).resolve();out=ROOT/'artifacts';out.mkdir(exist_ok=True)
(out/'kubernetes.json').write_text(json.dumps({'status':'running'}))
command('apply','-f',str(ROOT/'deploy/kubernetes/namespace.yaml'))
resource(['-n','keytend-kmip-server','create','secret','generic','keytend-kmip-server-tls','--from-file='+str(pki/'server.pem'),'--from-file='+str(pki/'server.key'),'--from-file='+str(pki/'ca.pem')])
resource(['-n','keytend-kmip-server','create','secret','generic','keytend-kmip-server-master','--from-file='+str(pki/'master.key')])
resource(['-n','keytend-kmip-server','create','configmap','keytend-kmip-server-policy','--from-file='+str(pki/'policy.json')])
if a.image:
    rendered=command('create','--dry-run=client','-k',str(ROOT/'deploy/kubernetes'),'-o','json').lstrip()
    manifests={'apiVersion':'v1','kind':'List','items':[]};decoder=json.JSONDecoder()
    # kubectl may print one JSON document per rendered resource rather than a List.
    while rendered:
        value,consumed=decoder.raw_decode(rendered)
        manifests['items'].extend(value['items'] if value.get('kind')=='List' else [value])
        rendered=rendered[consumed:].lstrip()
    changed=0
    for resource_value in manifests['items']:
        if resource_value['kind']=='StatefulSet' and resource_value['metadata']['name']=='keytend-kmip-server':
            for container in resource_value['spec']['template']['spec']['containers']:
                if container['name']=='kmip':container['image']=a.image;changed+=1
    assert changed==1,'fixture image override must select exactly one managed container'
    subprocess.run(k+['apply','-f','-'],input=json.dumps(manifests),text=True,stdout=subprocess.DEVNULL,check=True)
else:command('apply','-k',str(ROOT/'deploy/kubernetes'))
command('-n','keytend-kmip-server','rollout','restart','statefulset/keytend-kmip-server')
command('-n','keytend-kmip-server','rollout','status','statefulset/keytend-kmip-server','--timeout=120s')
results=[]
def passed(msg):results.append(msg);print('PASS',msg,flush=True)
info=json.loads(command('-n','keytend-kmip-server','get','pod','keytend-kmip-server-0','-o','json'))
assert info['spec']['securityContext']['runAsUser']==10001
assert info['spec']['automountServiceAccountToken'] is False
scratch=next(v for v in info['spec']['volumes'] if v['name']=='scratch')
assert scratch['emptyDir']=={'medium':'Memory','sizeLimit':'64Mi'}
# /tmp is writable (the image ships no shell, so prove it with the executable).
command('-n','keytend-kmip-server','exec','keytend-kmip-server-0','--','keytend-kmip-server','generate-master-key','--output','/tmp/writable-probe.key')
assert json.loads(command('-n','keytend-kmip-server','get','pvc','data-keytend-kmip-server-0','-o','json'))['status']['phase']=='Bound'
command('-n','keytend-kmip-server','exec','keytend-kmip-server-0','--','keytend-kmip-server','healthcheck')
passed('StatefulSet is ready as UID 10001 with read-only root filesystem, probes and bound PVC')
def forward_action(fn,identity='client'):
    port=free_port()
    with open(out/'kubernetes-port-forward.log','a') as log:
        p=subprocess.Popen(k+['-n','keytend-kmip-server','port-forward','pod/keytend-kmip-server-0',f'{port}:5696','--address=127.0.0.1'],stdout=log,stderr=log)
        try:
            until=time.monotonic()+10
            while time.monotonic()<until:
                try:
                    with connect(pki,port,identity=identity) as c:return fn(c)
                except ConnectionRefusedError:time.sleep(.1)
            raise TimeoutError('port-forward unavailable')
        finally:p.terminate();p.wait(timeout=5)
id,key=forward_action(lambda c: ((id:=create_key(c)),key_value(c,id)))
passed('independent mTLS client creates and retrieves a 256-bit key from Kubernetes service')
def protection_mask(identifier):
    return forward_action(lambda c:get(get(payload(exchange(c,request(11,[uid(identifier),enumeration(0x42013b,0x42015e)],v=(2,1)))),0x420125),0x42015e)[2])
assert protection_mask(id)==1
storage_id=forward_action(lambda c:get(payload(exchange(c,request(1,[enumeration(0x420057,2),
    structure(0x420125,enumeration(0x420028,3),integer(0x42002a,128),integer(0x42002c,12)),
    structure(0x42015f,integer(0x42015e,0))],v=(2,1)))),0x420094)[2])
assert protection_mask(storage_id)==0
storage_key=forward_action(lambda c:key_value(c,storage_id))
assert forward_action(lambda c:reason(exchange(c,request(1,[enumeration(0x420057,2),structure(0x420125),
    structure(0x42015f,integer(0x42015e,2))],v=(2,1)))))==0x44

# Exercise operation-selected MACs using one durable AES managed key.
import hmac
mac_key=bytes.fromhex('2b7e151628aed2a6abf7158809cf4f3c')
mac_object=structure(0x42008f,structure(0x420040,enumeration(0x420042,1),enumeration(0x420028,3),integer(0x42002a,128),structure(0x420045,binary(0x420043,mac_key))))
mac_cp=structure(0x42002b,enumeration(0x420028,9))
cmac_cp=structure(0x42002b,enumeration(0x420028,3),enumeration(0x420011,7))
mac_id=forward_action(lambda c:get(payload(exchange(c,request(3,[enumeration(0x420057,2),structure(0x420125,integer(0x42002c,0x180),mac_cp),mac_object],v=(2,1)))),0x420094)[2])
forward_action(lambda c:payload(exchange(c,request(18,[uid(mac_id)],v=(2,1)))))
def check_macs():
    actual=forward_action(lambda c:get(payload(exchange(c,request(35,[uid(mac_id),binary(0x4200c2,b'durable MAC')],v=(2,1)))),0x4200c6)[2])
    assert actual==hmac.new(mac_key,b'durable MAC','sha256').digest()
    actual=forward_action(lambda c:get(payload(exchange(c,request(35,[uid(mac_id),cmac_cp,binary(0x4200c2,b'')],v=(2,1)))),0x4200c6)[2])
    assert actual==bytes.fromhex('bb1d6929e95937287fa37d129b756746')
check_macs()

opaque_values=[structure(0x42005b,enumeration(0x420059,0x80001234),binary(0x42005a,b'kubernetes-opaque')),
               structure(0x42005b,enumeration(0x420059,0x8fffffff),binary(0x42005a,b''))]
opaque_ids=[forward_action(lambda c,obj=obj:get(payload(exchange(c,request(3,[enumeration(0x420057,8),structure(0x420125),obj],v=(2,1)))),0x420094)[2]) for obj in opaque_values]
def check_opaque():
    for identifier,expected in zip(opaque_ids,opaque_values):
        assert forward_action(lambda c:get(payload(exchange(c,request(10,[uid(identifier)],v=(2,1)))),0x42005b))==expected
        assert forward_action(lambda c:get(get(payload(exchange(c,request(11,[uid(identifier),enumeration(0x42013b,0x420059)],v=(2,1)))),0x420125),0x420059))==get(expected,0x420059)
check_opaque()

pgp_fixture=json.loads((ROOT/'tests/fixtures/openpgp.json').read_text())['v3_public'].encode()
pgp_object=structure(0x4200bd,integer(0x4200be,3),structure(0x420040,enumeration(0x420042,2),
    structure(0x420045,binary(0x420043,pgp_fixture)),enumeration(0x420028,4),integer(0x42002a,2048)))
pgp_id=forward_action(lambda c:get(payload(exchange(c,request(3,[enumeration(0x420057,9),structure(0x420125,integer(0x42002c,0),enumeration(0x4200ae,7)),pgp_object],v=(2,1)))),0x420094)[2])
pgp_parts=forward_action(lambda c:[n[2] for n in children(payload(exchange(c,request(40,[
    enumeration(0x420057,5),uid(pgp_id),integer(0x42008b,3),integer(0x42008c,2),
    enumeration(0x42008a,4),structure(0x420125)],v=(2,1)))),0x420094)])
def check_pgp():
    assert forward_action(lambda c:get(payload(exchange(c,request(10,[uid(pgp_id)],v=(2,1)))),0x4200bd))==pgp_object
    joined=forward_action(lambda c:get(payload(exchange(c,request(41,[enumeration(0x420057,9),uid(pgp_parts[0]),uid(pgp_parts[2])],v=(2,1)))),0x420094)[2])
    assert forward_action(lambda c:get(payload(exchange(c,request(10,[uid(joined)],v=(2,1)))),0x4200bd))==pgp_object
    for identifier in [pgp_id,joined]:
        assert forward_action(lambda c:get(get(payload(exchange(c,request(11,[uid(identifier),enumeration(0x42013b,0x4200ae)],v=(2,1)))),0x420125),0x4200ae)[2])==7
check_pgp()

# Managed certificate metadata must retain subject/issuer distinctions on the PVC.
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import rsa
certificate_der=ssl.PEM_cert_to_DER_cert((pki/'server.pem').read_text())
certificate_oracle=x509.load_der_x509_certificate(certificate_der);certificate_key=certificate_oracle.public_key()
certificate_algorithm=4 if isinstance(certificate_key,rsa.RSAPublicKey) else 6
certificate_signature={'1.2.840.113549.1.1.11':5,'1.2.840.113549.1.1.12':6,'1.2.840.10045.4.3.2':14}[certificate_oracle.signature_algorithm_oid.dotted_string]
certificate_object=structure(0x420013,enumeration(0x42001d,1),binary(0x42001e,certificate_der))
certificate_id=forward_action(lambda c:get(payload(exchange(c,request(3,[enumeration(0x420057,1),certificate_object,
    structure(0x420125,enumeration(0x420028,certificate_algorithm),integer(0x42002a,certificate_key.key_size),integer(0x42002c,0),integer(0x4200ad,len(certificate_der)))],v=(2,1)))),0x420094)[2])
certificate_parts=forward_action(lambda c:[n[2] for n in children(payload(exchange(c,request(40,[enumeration(0x420057,5),uid(certificate_id),integer(0x42008b,3),integer(0x42008c,2),enumeration(0x42008a,4),structure(0x420125)],v=(2,1)))),0x420094)])
def check_certificate_metadata():
    joined=forward_action(lambda c:get(payload(exchange(c,request(41,[enumeration(0x420057,1),uid(certificate_parts[0]),uid(certificate_parts[2]),structure(0x420125)],v=(2,1)))),0x420094)[2])
    expected=[enumeration(0x42001d,1),integer(0x4200ad,len(certificate_der)),enumeration(0x420028,certificate_algorithm),integer(0x42002a,certificate_key.key_size),integer(0x42002c,0),enumeration(0x4200ae,certificate_signature)]
    for identifier in [certificate_id,joined]:
        assert forward_action(lambda c:get(payload(exchange(c,request(10,[uid(identifier)],v=(2,1)))),0x420013))==certificate_object
        attrs=forward_action(lambda c:get(payload(exchange(c,request(11,[uid(identifier)]+[enumeration(0x42013b,n[0]) for n in expected],v=(2,1)))),0x420125))
        assert {n[0]:n for n in attrs[2]}=={n[0]:n for n in expected}
        identity=forward_action(lambda c:get(payload(exchange(c,request(11,[uid(identifier),*[enumeration(0x42013b,t) for t in [0x4200b5,0x4200b6,0x4200b7]]],v=(2,1)))),0x420125))
        serial=certificate_oracle.serial_number;value=serial.to_bytes(max(1,(serial.bit_length()+7)//8),'big');value=b'\0'+value if value[0]&128 else value;encoded_serial=bytes([2,len(value)])+value
        assert get(get(identity,0x4200b5),0x4200af)[2]==encoded_serial
        assert get(get(identity,0x4200b5),0x4200b2)[2]==certificate_oracle.issuer.public_bytes()
        assert get(get(identity,0x4200b6),0x4200b2)[2]==certificate_oracle.issuer.public_bytes()
        assert get(get(identity,0x4200b7),0x4200b4)[2]==certificate_oracle.subject.public_bytes()
    for part in certificate_parts:
        attrs=forward_action(lambda c:get(payload(exchange(c,request(11,[uid(part)],v=(2,1)))),0x420125))
        assert not any(n[0] in [0x4200b5,0x4200b6,0x4200b7] or 0x420108<=n[0]<=0x42011f for n in attrs[2])

check_certificate_metadata()

pgp_certificate_bytes=json.loads((ROOT/'tests/fixtures/openpgp.json').read_text())['v4_public'].encode()
pgp_certificate_object=structure(0x420013,enumeration(0x42001d,2),binary(0x42001e,pgp_certificate_bytes))
pgp_certificate_id=forward_action(lambda c:get(payload(exchange(c,request(3,[enumeration(0x420057,1),pgp_certificate_object,
    structure(0x420125,enumeration(0x420028,4),integer(0x42002a,2048),integer(0x42002c,0),integer(0x4200ad,len(pgp_certificate_bytes)))],v=(2,1)))),0x420094)[2])
pgp_certificate_parts=forward_action(lambda c:[n[2] for n in children(payload(exchange(c,request(40,[enumeration(0x420057,5),uid(pgp_certificate_id),integer(0x42008b,3),integer(0x42008c,2),enumeration(0x42008a,4),structure(0x420125)],v=(2,1)))),0x420094)])
def check_pgp_certificate():
    joined=forward_action(lambda c:get(payload(exchange(c,request(41,[enumeration(0x420057,1),uid(pgp_certificate_parts[0]),uid(pgp_certificate_parts[2]),structure(0x420125)],v=(2,1)))),0x420094)[2])
    for identifier in [pgp_certificate_id,joined]:
        assert forward_action(lambda c:get(payload(exchange(c,request(10,[uid(identifier)],v=(2,1)))),0x420013))==pgp_certificate_object
        attrs=forward_action(lambda c:get(payload(exchange(c,request(11,[uid(identifier)]+[enumeration(0x42013b,tag) for tag in [0x42001d,0x4200ad,0x4200ae]],v=(2,1)))),0x420125))
        assert get(attrs,0x42001d)[2]==2 and get(attrs,0x4200ad)[2]==len(pgp_certificate_bytes) and get(attrs,0x4200ae)[2]==7
check_pgp_certificate()

split=structure(0x420089,integer(0x42008b,3),integer(0x420044,2),integer(0x42008c,2),enumeration(0x42008a,4),
    structure(0x420040,enumeration(0x420042,1),structure(0x420045,binary(0x420043,b'kubernetes-split-share'))))
split_id=forward_action(lambda c:get(payload(exchange(c,request(3,[enumeration(0x420057,5),structure(0x420125),split],v=(2,1)))),0x420094)[2])
# Factory provenance must remain usable without the original source object in memory.
factory_parts=forward_action(lambda c:[n[2] for n in children(payload(exchange(c,request(40,[
    enumeration(0x420057,5),uid(id),integer(0x42008b,3),integer(0x42008c,2),
    enumeration(0x42008a,4),structure(0x420125)],v=(2,1)))),0x420094)])
assert len(factory_parts)==3
def join_factory():
    return forward_action(lambda c:get(payload(exchange(c,request(41,[enumeration(0x420057,2),
        uid(factory_parts[2]),uid(factory_parts[0])],v=(2,1)))),0x420094)[2])
factory_joined=join_factory()
assert forward_action(lambda c:key_value(c,factory_joined))==key
def https_key():
    port=free_port()
    with open(out/'kubernetes-port-forward.log','a') as log:
        p=subprocess.Popen(k+['-n','keytend-kmip-server','port-forward','service/keytend-kmip-server',f'{port}:5697','--address=127.0.0.1'],stdout=log,stderr=log)
        try:
            until=time.monotonic()+10
            while True:
                try:
                    for fmt in MEDIA:
                        r=payload(post(SimpleNamespace(pki=pki,https=port),request(10,[uid(id)]),fmt))
                        assert get(get(get(get(r,0x42008f),0x420040),0x420045),0x420043)[2]==key
                        r=payload(post(SimpleNamespace(pki=pki,https=port),request(10,[uid(split_id)],v=(2,1)),fmt))
                        assert get(r,0x420089)==split
                    return
                except ConnectionRefusedError:
                    if time.monotonic()>until:raise TimeoutError('HTTPS service port-forward unavailable')
                    time.sleep(.1)
        finally:p.terminate();p.wait(timeout=5)
service=json.loads(command('-n','keytend-kmip-server','get','service','keytend-kmip-server','-o','json'))
assert {p['port'] for p in service['spec']['ports']}=={5696,5697}
https_key()
passed('HTTPS Service port 5697 returns the same key through TTLV, JSON and XML over mTLS')
forward_action(lambda c:payload(exchange(c,request(21,[uid(id)]))))
old_uid=info['metadata']['uid']
command('-n','keytend-kmip-server','delete','pod','keytend-kmip-server-0','--wait=true','--timeout=60s')
command('-n','keytend-kmip-server','wait','--for=condition=Ready','pod/keytend-kmip-server-0','--timeout=120s')
new=json.loads(command('-n','keytend-kmip-server','get','pod','keytend-kmip-server-0','-o','json'));assert new['metadata']['uid']!=old_uid
assert forward_action(lambda c:reason(exchange(c,request(10,[uid(id)]))))==13
forward_action(lambda c:payload(exchange(c,request(22,[uid(id)]))))
assert forward_action(lambda c:key_value(c,id))==key
https_key()
passed('pod replacement retained archival access policy; recovery preserved the same key ID and exact bytes on the PVC')
assert forward_action(lambda c:get(payload(exchange(c,request(10,[uid(split_id)],v=(2,1)))),0x420089))==split
passed('Split Key metadata and exact share bytes survive pod replacement and all three HTTPS encodings on the PVC')
assert forward_action(lambda c:key_value(c,factory_joined))==key
factory_after_restart=join_factory()
assert forward_action(lambda c:key_value(c,factory_after_restart))==key
passed('Create/Join Split Key provenance and reconstructed key bytes survive pod replacement; a fresh Join recovers the original key from the PVC')
assert protection_mask(id)==1 and protection_mask(storage_id)==0
assert forward_action(lambda c:key_value(c,storage_id))==storage_key
passed('mandatory Software metadata and explicit zero protection-storage selection survive pod replacement; unsupported hardware selection is rejected')
check_macs()
passed('stored HMAC selection on an AES key and explicit AES-CMAC return exact independent values after pod replacement')
check_opaque()
passed('non-default opaque extension types, empty values and immutable type metadata retain exact contents after pod replacement')
check_pgp()
passed('PGP version, immutable signature metadata, declared primary-key length and exact bytes survive pod replacement; fresh Join retains local PGP share provenance on the PVC')
check_certificate_metadata()
passed('X.509 subject-key, issuer signature, byte length and readonly metadata survive pod replacement; a fresh certificate Join reconstructs exact bytes from durable shares')
passed('X.509 issuer/subject DER and complete serial survive pod replacement and fresh Join; certificate identity never propagates to share attributes')
check_pgp_certificate()
passed('PGP Certificate Type 2, byte length, immutable signature metadata and exact public bytes survive pod replacement; a fresh Join preserves the certificate type')
# Transport trust alone must not authorize application certificate validation.
def pem_der(name):return ssl.PEM_cert_to_DER_cert((pki/name).read_text())
def validation_request():
    certificates=[structure(0x420013,enumeration(0x42001d,1),binary(0x42001e,pem_der(name))) for name in ['server.pem','ca.pem']]
    return request(23,certificates,v=(2,1))
def chain_validity():return forward_action(lambda c:get(payload(exchange(c,validation_request())),0x42009b)[2])
assert chain_validity()==3
try:
    command('-n','keytend-kmip-server','set','env','statefulset/keytend-kmip-server','KMIP_VALIDATION_CA=/tls/ca.pem')
    command('-n','keytend-kmip-server','rollout','status','statefulset/keytend-kmip-server','--timeout=120s')
    assert chain_validity()==1
    assert forward_action(lambda c:key_value(c,id))==key
finally:
    command('-n','keytend-kmip-server','set','env','statefulset/keytend-kmip-server','KMIP_VALIDATION_CA-')
    command('-n','keytend-kmip-server','rollout','status','statefulset/keytend-kmip-server','--timeout=120s')
assert chain_validity()==3
passed('Validate trust is explicit: Unknown by default, Valid after configured CA and rollout, Unknown after removal; exact key survives')
# Update the actual mounted management policy; restart closes old TLS sessions.
base_policy=json.loads((pki/'policy.json').read_text())
def cert_fingerprint(identity):return hashlib.sha256(ssl.PEM_cert_to_DER_cert((pki/(identity+'.pem')).read_text())).hexdigest()
reader=cert_fingerprint('other');owner=base_policy['principals'][cert_fingerprint('client')]['name'];policy_actions=[]
def configure_grants(permissions):
    policy=json.loads(json.dumps(base_policy))
    if permissions is not None:policy['principals'][reader]['object_grants']=[] if not permissions else [{'owner':owner,'identifier':id,'operations':permissions}]
    document=json.dumps(policy)
    config={'apiVersion':'v1','kind':'ConfigMap','metadata':{'name':'keytend-kmip-server-policy','namespace':'keytend-kmip-server'},'data':{'policy.json':document}}
    subprocess.run(k+['apply','-f','-'],input=json.dumps(config),text=True,stdout=subprocess.DEVNULL,check=True)
    command('-n','keytend-kmip-server','rollout','restart','statefulset/keytend-kmip-server')
    command('-n','keytend-kmip-server','rollout','status','statefulset/keytend-kmip-server','--timeout=120s')
    policy_actions.append({'permissions':permissions,'policy_sha256':hashlib.sha256(document.encode()).hexdigest()})
hidden_id=forward_action(lambda c:create_key(c))
assert forward_action(lambda c:reason(exchange(c,request(10,[uid(id)]))),identity='other')==1
try:
    configure_grants([10])
    assert forward_action(lambda c:key_value(c,id),identity='other')==key
    assert forward_action(lambda c:reason(exchange(c,request(10,[uid(hidden_id)]))),identity='other')==1
    assert forward_action(lambda c:reason(exchange(c,request(11,[uid(id)]))),identity='other')==1
    assert not forward_action(lambda c:children(payload(exchange(c,request(8))),0x420094),identity='other')
    for op in [1,13,20]:assert forward_action(lambda c:reason(exchange(c,request(op,[uid(id)]))),identity='other')==12
    passed('ConfigMap Get-only grant returns exactly one foreign key; hidden keys, metadata, listing and writes remain denied')
    configure_grants([8])
    assert forward_action(lambda c:[n[2] for n in children(payload(exchange(c,request(8))),0x420094)],identity='other')==[id]
    assert forward_action(lambda c:reason(exchange(c,request(10,[uid(id)]))),identity='other')==1
    passed('ConfigMap Locate-only grant lists the exact permitted object and grants no key retrieval')
    configure_grants([])
    assert forward_action(lambda c:reason(exchange(c,request(10,[uid(id)]))),identity='other')==1
    assert not forward_action(lambda c:children(payload(exchange(c,request(8))),0x420094),identity='other')
    assert forward_action(lambda c:key_value(c,id))==key
    passed('ConfigMap grant revocation takes effect after pod restart; exact owner key bytes survive all permission changes')
finally:configure_grants(None)
new=json.loads(command('-n','keytend-kmip-server','get','pod','keytend-kmip-server-0','-o','json'))
command('-n','keytend-kmip-server','exec','keytend-kmip-server-0','--','keytend-kmip-server','check-store','--database','/data/kmip.sqlite','--master-key','/master/master.key')
passed('restored pod verifies storage wrapping key and audit-chain integrity')
version=json.loads(command('version','-o','json'))['serverVersion']['gitVersion']
result={'status':'passed','kubernetes_version':version,'image':new['spec']['containers'][0]['image'],'image_id':new['status']['containerStatuses'][0]['imageID'],'passed':results,'policy_actions':policy_actions,'limits':'single-node kind smoke test; kindnet does not enforce NetworkPolicy; HA and production CNI enforcement untested'}
result.update({'https_encodings':list(MEDIA),'https_key_survived_pod_replacement':True,'split_factory_survived_pod_replacement':True,'protection_storage_survived_pod_replacement':True,'mac_selection_survived_pod_replacement':True,'opaque_types_survived_pod_replacement':True,'pgp_container_survived_pod_replacement':True,'certificate_metadata_survived_pod_replacement':True,'certificate_identity_survived_pod_replacement':True,'pgp_certificate_type_survived_pod_replacement':True})
if a.kind_node:
    # Pod imageID identifies a manifest; CRI status.id identifies its config.
    # Resolve the running pod's immutable manifest, not just its mutable tag.
    reference=result['image_id'].removeprefix('docker-pullable://').removeprefix('containerd://')
    images=json.loads(subprocess.check_output([a.engine,'exec',a.kind_node,'crictl','images','-o','json']))['images']
    matches=[i for i in images if reference in i.get('repoDigests',[]) or normalized_id(reference)==normalized_id(i['id'])]
    assert len(matches)==1,'running pod image must resolve to exactly one CRI image'
    cri=json.loads(subprocess.check_output([a.engine,'exec',a.kind_node,'crictl','inspecti',matches[0]['id']]))['status']
    assert reference in cri['repoDigests'] or normalized_id(reference)==normalized_id(cri['id'])
    result.update(packaged_evidence(cri['id']))
(out/'kubernetes.json').write_text(json.dumps(result,indent=2)+'\n')
