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

"""Published keytend-kmip SDK, JCA oracles, TLS/HTTPS and persistent ChaCha keys."""
import argparse
import json
import os
import pathlib
import shutil
import subprocess
import tempfile

from image_evidence import source_commit,local_image_id,packaged_evidence
from https_client import HttpsServer,HttpsContainer
from test_runtime import ROOT
import keytend_kmip_release as trial

class DraftContainer(HttpsContainer):
    def base(self):return super().base()+['-e','KMIP_EXPERIMENTAL_V3=true']

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--image')
    parser.add_argument('--engine',default='podman')
    parser.add_argument('--java',action='append',required=True)
    args=parser.parse_args()
    _,jars,artifact=trial.release()
    javas=sorted(args.java,key=lambda j:trial.major(j)[0])
    assert trial.major(javas[0])[0]==17
    binary=ROOT/'target/debug/keytend-kmip-server'
    binary_hash=trial.sha(binary)
    mode='image' if args.image else 'native'
    evidence=packaged_evidence(local_image_id(args.engine,args.image)) if args.image else {'runtime_binary_sha256':binary_hash,'source_commit':source_commit()[0]}
    out=ROOT/'artifacts/chacha-java'
    out.mkdir(parents=True,exist_ok=True)
    report=dict(status='running',client_artifact=artifact,lanes=[],**evidence,
                scope='JCA raw 64/96-bit nonce and full-tag AEAD oracles, one-shot and multipart, generated nonce, bad tag and no unauthenticated prefix; 1.4/2.0/2.1/draft3.0, TLS/HTTPS TTLV/JSON/XML; restart and encrypted backup restore. No truncated-tag, full profile, transfer/KDF/accounting or production SDK qualification.')
    path=out/(mode+'.json')
    def save():path.write_text(json.dumps(report,indent=2)+'\n')
    save()
    try:
        classes=pathlib.Path(tempfile.mkdtemp(prefix='java-chacha-'+mode+'-',dir=ROOT/'.cache'))
        subprocess.run([str(pathlib.Path(javas[0]).with_name('javac')),'--release','17','-Xlint:all','-Werror',
                        '-cp',str(jars[0]),'-d',str(classes),str(ROOT/'interop/java/ServerChaCha.java')],check=True)
        compiled={str(p.relative_to(ROOT)):trial.sha(p) for p in classes.rglob('*.class')}
        report['compiled_adapter_sha256']=compiled
        with tempfile.TemporaryDirectory(prefix='kmip-java-chacha-') as directory:
            server=DraftContainer(directory,args.engine,args.image) if args.image else HttpsServer(directory,draft=True)
            subprocess.run(['openssl','pkcs12','-export','-in',str(server.pki/'client.pem'),'-inkey',str(server.pki/'client.key'),
                            '-certfile',str(server.pki/'ca.pem'),'-out',str(server.pki/'client.p12'),'-passout','pass:changeit'],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
            manifests=[pathlib.Path(directory)/('jdk'+str(i)+'.tsv') for i in range(len(javas))]
            backup=pathlib.Path(directory)/'backup.sqlite'
            try:
                server.start()
                for phase in ['create','restart','restore']:
                    if phase!='create':
                        server.stop()
                        if phase=='restore':
                            clean=pathlib.Path(directory)/'clean'
                            clean.mkdir(mode=0o700)
                            shutil.copyfile(backup,clean/'kmip.sqlite')
                            (clean/'kmip.sqlite').chmod(0o600)
                            server.data=clean
                        server.start()
                    for java,manifest in zip(javas,manifests):
                        major,runtime=trial.major(java)
                        log=out/(mode+'-jdk'+str(major)+'-'+phase+'.log')
                        with log.open('w') as stream:
                            subprocess.run([java,'-cp',os.pathsep.join(map(str,[classes,*jars])),'dev.keytend.kmip.interop.ServerChaCha',
                                            str(server.pki),str(server.port),str(server.https),'create' if phase=='create' else 'verify',str(manifest)],
                                            check=True,stdout=stream,stderr=subprocess.STDOUT,timeout=600)
                        rows=[line.split('\t') for line in log.read_text().splitlines()]
                        assert len(rows)==16 and {(int(r[1]),r[2]) for r in rows}=={(v,t) for v in [14,20,21,30] for t in ['TLS','TTLV','JSON','XML']}
                        assert all(len(r)==4 and r[0]=='PASS' for r in rows)
                        assert sum(int(r[3]) for r in rows)==(512 if phase=='create' else 448)
                        report['lanes'].append(dict(phase=phase,jdk=major,runtime=runtime,
                            checked_responses=sum(int(r[3]) for r in rows),version_transport_views=16,
                            log=str(log.relative_to(ROOT)),log_sha256=trial.sha(log)))
                        save()
                    if phase=='create':
                        subprocess.run([str(binary),'backup','--database',str(server.data/'kmip.sqlite'),'--master-key',str(server.pki/'master.key'),'--output',str(backup)],check=True)
            finally:server.stop()
        report['status']='passed'
    except BaseException as error:
        report['status']='failed'
        report['error']=str(error)
        raise
    finally:save()
    print(mode,'PASS',sum(l['checked_responses'] for l in report['lanes']))

if __name__=='__main__':main()
