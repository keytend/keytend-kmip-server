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

"""Supplemental unchanged IBM libkmipclient codecs, TLS and HTTPS transport."""
import argparse,hashlib,json,pathlib,re,shutil,subprocess,tarfile,tempfile
from image_evidence import local_image_id,packaged_evidence,source_commit
from https_client import HttpsServer,HttpsContainer
from test_runtime import sha
from test_runtime import ROOT

PIN='8840053a7bbaeea1de3834fbc7f84b16813fc409'
SDK=ROOT/'.cache/s390-tools-client'
def build_client(engine,image):
    if not SDK.exists():subprocess.run(['git','clone','--quiet','--depth','1','--branch','v2.44.1','https://github.com/ibm-s390-linux/s390-tools',str(SDK)],check=True)
    assert subprocess.check_output(['git','-C',str(SDK),'rev-parse','HEAD'],text=True).strip()==PIN
    assert not subprocess.check_output(['git','-C',str(SDK),'diff','--name-only'],text=True).strip()
    archive=ROOT/'.cache/s390-tools-v2.44.1.tar'
    subprocess.run(['git','-C',str(SDK),'archive','--format=tar','--output',str(archive),PIN],check=True)
    with tempfile.TemporaryDirectory(prefix='ibm-client-build-',dir=ROOT/'.cache') as directory:
        context=pathlib.Path(directory);sdk=context/'sdk';sdk.mkdir()
        with tarfile.open(archive) as t:t.extractall(sdk,filter='data')
        shutil.copyfile(ROOT/'integration/ibm/client.c',context/'client.c')
        with (ROOT/'artifacts/ibm-client-image-build.log').open('w') as log:
            subprocess.run([engine,'build']+(['--format','docker'] if engine=='podman' else [])+['-f',str(ROOT/'integration/ibm/Dockerfile'),'-t',image,str(context)],stdout=log,stderr=subprocess.STDOUT,check=True)
def untrusted_pki(pki):
    """A second CA and a client certificate it issued, for the trust negatives."""
    run=lambda *a:subprocess.run(a,check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    run('openssl','req','-x509','-newkey','rsa:2048','-nodes','-keyout',str(pki/'wrong-ca.key'),'-out',str(pki/'wrong-ca.pem'),'-days','2','-subj','/CN=keytend-kmip-server-wrong-ca','-addext','basicConstraints=critical,CA:TRUE','-addext','keyUsage=critical,keyCertSign,cRLSign')
    run('openssl','req','-new','-newkey','rsa:2048','-nodes','-keyout',str(pki/'untrusted.key'),'-out',str(pki/'untrusted.csr'),'-subj','/CN=client')
    (pki/'untrusted.ext').write_text('basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=clientAuth\n')
    run('openssl','x509','-req','-in',str(pki/'untrusted.csr'),'-CA',str(pki/'wrong-ca.pem'),'-CAkey',str(pki/'wrong-ca.key'),'-CAcreateserial','-out',str(pki/'untrusted.pem'),'-days','2','-extfile',str(pki/'untrusted.ext'))
def main():
    p=argparse.ArgumentParser();p.add_argument('--image');p.add_argument('--engine',default='podman');p.add_argument('--client-image',default='localhost/keytend-kmip-server-ibm-client:2.44.1');p.add_argument('--build-client',action='store_true');a=p.parse_args()
    (ROOT/'artifacts').mkdir(exist_ok=True)
    if a.build_client:build_client(a.engine,a.client_image)
    image=packaged_evidence(local_image_id(a.engine,a.image)) if a.image else {'runtime_binary_sha256':sha(ROOT/'target/debug/keytend-kmip-server'),'source_commit':source_commit()[0]}
    assert subprocess.check_output(['git','-C',str(SDK),'rev-parse','HEAD'],text=True).strip()==PIN
    assert not subprocess.check_output(['git','-C',str(SDK),'diff','--name-only'],text=True).strip(),'upstream tracked source modified'
    client_id=local_image_id(a.engine,a.client_image)
    included=subprocess.check_output([a.engine,'run','--rm','--entrypoint','cat',client_id,'/client.c'])
    assert hashlib.sha256(included).hexdigest()==sha(ROOT/'integration/ibm/client.c')
    sdk_files=sorted((SDK/'libkmipclient').glob('*.c'))+sorted((SDK/'libkmipclient').glob('*.h'))+[SDK/'include/kmipclient/kmipclient.h',SDK/'libkmipclient/Makefile',SDK/'common.mak']
    sdk_hashes={str(f.relative_to(SDK)):sha(f) for f in sdk_files}
    checks=subprocess.check_output([a.engine,'run','--rm','--entrypoint','sha256sum',client_id]+['/src/'+name for name in sdk_hashes],text=True)
    assert {name.removeprefix('/src/'):digest for digest,name in (line.split() for line in checks.splitlines())}==sdk_hashes
    library_sha=subprocess.check_output([a.engine,'run','--rm','--entrypoint','sha256sum',client_id,'/src/libkmipclient/libkmipclient.so.1.0'],text=True).split()[0]
    archive=ROOT/'.cache/s390-tools-v2.44.1.tar'
    assert subprocess.check_output(['git','-C',str(SDK),'archive','--format=tar','v2.44.1'])==archive.read_bytes()
    out=ROOT/'artifacts';output=out/('ibm-client-image.json' if a.image else 'ibm-client.json');output.write_text(json.dumps({'status':'running'})+'\n')
    with tempfile.TemporaryDirectory(prefix='keytend-ibm-client-') as directory:
        s=HttpsContainer(directory,a.engine,a.image) if a.image else HttpsServer(directory)
        try:
            s.start()
            command=[a.engine,'run','--rm','--network=host','--read-only','--tmpfs','/tmp:rw,nosuid,nodev,noexec,size=64m,mode=1777','--cap-drop=all','--security-opt=no-new-privileges','--pids-limit=64','--memory=256m']
            if a.engine=='podman':command+=['--userns','keep-id:uid=10001,gid=10001']
            command+=['-v',f'{s.pki}:/pki:ro',client_id,str(s.port),str(s.https)]
            result=subprocess.run(command,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True,timeout=120)
            log=out/('ibm-client-image.log' if a.image else 'ibm-client.log');log.write_text(result.stdout)
            if result.returncode==0:
                probe=command.copy();probe[probe.index(client_id):probe.index(client_id)]=['-e','KEYTEND_IBM_BOOL_PROBE=1']
                regression=subprocess.run(probe,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True,timeout=20)
                with log.open('a') as f:f.write(regression.stdout)
                assert regression.returncode==0 and 'KNOWN SDK LIMITATION:' in regression.stdout,regression.stdout
                # Separate invocation: ACL, trust, hostname and identity negatives.
                untrusted_pki(pathlib.Path(s.pki))
                probe=command.copy();probe[probe.index(client_id):probe.index(client_id)]=['-e','KEYTEND_IBM_NEGATIVES=1','--add-host','wrong-kmip.test:127.0.0.1']
                negative=subprocess.run(probe,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True,timeout=120)
                with log.open('a') as f:f.write(negative.stdout)
                negatives=re.findall(r'PASS IBM libkmipclient negatives (\d+\.\d+) transport=(\d+):',negative.stdout)
                assert negative.returncode==0 and len(set(negatives))==4,negative.stdout
        finally:s.stop()
    lanes=[{'wire_version':f'{major}.{minor}','transport':int(transport),'encoding':int(encoding)} for major,minor,transport,encoding in re.findall(r'PASS IBM libkmipclient (\d+)\.(\d+) transport=(\d+) encoding=(\d+):',result.stdout)]
    negatives=[{'wire_version':v,'transport':int(t)} for v,t in re.findall(r'PASS IBM libkmipclient negatives (\d+\.\d+) transport=(\d+):',log.read_text())]
    passed=result.returncode==0 and len(lanes)==28 and len({tuple(x.values()) for x in lanes})==28 and len(negatives)==4
    report={'status':'passed' if passed else 'failed','sdk_repository':'https://github.com/ibm-s390-linux/s390-tools','sdk_release':'v2.44.1','sdk_commit':PIN,'sdk_archive_sha256':sha(archive),'sdk_source_sha256':sdk_hashes,'sdk_library_sha256':library_sha,'client_image_config_id':client_id,**image,'lanes':lanes,'negatives':negatives,'exit_code':result.returncode,'log':str(log.relative_to(ROOT)),'log_sha256':sha(log),'known_sdk_limits':['Pinned SDK serializes Boolean True in host byte order on the little-endian test image; deterministic Query regression expects strict Invalid Message. Single-item TTLV positive lanes use the public Batch Order Option False; JSON/XML use True.'] if passed else [],'scope':'additional independent SDK subset with ACL and trust/hostname/identity negatives on 1.4 and 2.1 over binary TLS and HTTPS; production qualification, platform support and resource tests remain incomplete'}
    output.write_text(json.dumps(report,indent=2)+'\n');print(result.stdout,flush=True)
    if not passed:raise SystemExit(1)
if __name__=='__main__':main()
