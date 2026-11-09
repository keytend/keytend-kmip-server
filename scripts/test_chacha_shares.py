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

"""Released Java client validates external XOR reconstruction and malformed ChaCha shares."""
import argparse
import json
import os
import pathlib
import subprocess
import tempfile
from image_evidence import source_commit,local_image_id,packaged_evidence
from test_chacha_java import DraftContainer
from https_client import HttpsServer
from test_runtime import ROOT
import keytend_kmip_release as trial


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--image')
    parser.add_argument('--engine',default='podman')
    parser.add_argument('--java',action='append',required=True)
    args=parser.parse_args()
    _,jars,artifact=trial.release()
    javas=sorted(args.java,key=lambda j:trial.major(j)[0])
    assert [trial.major(j)[0] for j in javas]==[17,21,25]
    binary=ROOT/'target/debug/keytend-kmip-server';binary_hash=trial.sha(binary)
    mode='image' if args.image else 'native'
    evidence=packaged_evidence(local_image_id(args.engine,args.image)) if args.image else {'runtime_binary_sha256':binary_hash,'source_commit':source_commit()[0]}
    out=ROOT/'artifacts/chacha-shares';out.mkdir(parents=True,exist_ok=True)
    report=dict(status='running',client_artifact=artifact,lanes=[],**evidence,
                scope='JDK17/21/25; malformed share width/metadata rejection; independently constructed external XOR shares yield exact known key; raw and AEAD use checked against explicit SunJCE. TLS/HTTPS TTLV/JSON/XML, positive and negative server requests for 1.4/2.0/2.1/pinned3.0; legacy1.1-1.3 SDK preflight rejection only (no server request credit). No restart, transfer, other sharing-method SDK or complete-profile credit from this probe.')
    path=out/(mode+'.json')
    def save():path.write_text(json.dumps(report,indent=2)+'\n')
    save()
    try:
        classes=pathlib.Path(tempfile.mkdtemp(prefix='java-shares-'+mode+'-',dir=ROOT/'.cache'))
        adapters=[ROOT/'interop/java'/name for name in ['ServerChaCha.java','ChaChaShares.java']]
        subprocess.run([str(pathlib.Path(javas[0]).with_name('javac')),'--release','17','-Xlint:all','-Werror','-cp',str(jars[0]),'-d',str(classes),*map(str,adapters)],check=True)
        compiled={str(p.relative_to(ROOT)):trial.sha(p) for p in classes.rglob('*.class')}
        report['compiled_adapter_sha256']=compiled
        with tempfile.TemporaryDirectory(prefix='kmip-java-shares-') as directory:
            server=DraftContainer(directory,args.engine,args.image) if args.image else HttpsServer(directory,draft=True)
            subprocess.run(['openssl','pkcs12','-export','-in',str(server.pki/'client.pem'),'-inkey',str(server.pki/'client.key'),'-certfile',str(server.pki/'ca.pem'),'-out',str(server.pki/'client.p12'),'-passout','pass:changeit'],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
            try:
                server.start()
                for java in javas:
                    major,runtime=trial.major(java);log=out/(mode+'-jdk'+str(major)+'.log')
                    with log.open('w') as stream:
                        subprocess.run([java,'-cp',os.pathsep.join(map(str,[classes,*jars])),'dev.keytend.kmip.interop.ChaChaShares',str(server.pki),str(server.port),str(server.https)],check=True,stdout=stream,stderr=subprocess.STDOUT,timeout=600)
                    rows=[line.split('\t') for line in log.read_text().splitlines()]
                    assert len(rows)==28 and {(int(r[1]),r[2]) for r in rows}=={(v,t) for v in [11,12,13,14,20,21,30] for t in ['TLS','TTLV','JSON','XML']}
                    assert all(len(r)==4 and r[0]==('LOCAL' if int(r[1])<14 else 'PASS') and int(r[3])==(2 if int(r[1])<14 else 54) for r in rows)
                    report['lanes'].append(dict(jdk=major,runtime=runtime,checked_responses=sum(int(r[3]) for r in rows if r[0]=='PASS'),local_preflight_rejections=sum(int(r[3]) for r in rows if r[0]=='LOCAL'),server_version_transport_views=16,local_preflight_views=12,log=str(log.relative_to(ROOT)),log_sha256=trial.sha(log)));save()
            finally:server.stop()
        report['status']='passed'
    except BaseException as error:
        report['status']='failed';report['error']=str(error);raise
    finally:save()
    print(mode,'PASS',sum(l['checked_responses'] for l in report['lanes']))


if __name__=='__main__':main()
