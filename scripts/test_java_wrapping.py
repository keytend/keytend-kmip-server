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

"""Supplemental published-SDK wrapping probes; retain original catalog failures."""
import argparse,json,os,subprocess,tempfile
from image_evidence import source_commit,local_image_id,packaged_evidence,native_sha256
from test_runtime import ROOT,Server
from test_database import ContainerServer
from keytend_kmip_release import release,sha

def main():
    p=argparse.ArgumentParser();p.add_argument('--image');p.add_argument('--engine',default='podman');p.add_argument('--java',action='append',required=True);a=p.parse_args()
    client,jars,artifact=release();digest=native_sha256(a.image)
    image_id=local_image_id(a.engine,a.image) if a.image else None;evidence=packaged_evidence(image_id) if image_id else {'runtime_binary_sha256':digest,'source_commit':source_commit()[0]}
    out=ROOT/'artifacts/java-release-wrapping';out.mkdir(parents=True,exist_ok=True);mode='image' if a.image else 'native'
    classes=ROOT/'.cache/java-release-wrapping-adapter';classes.mkdir(exist_ok=True);classpath=os.pathsep.join(map(str,[classes]+jars))
    subprocess.run(['javac','--release','17','-cp',classpath,'-d',str(classes),str(ROOT/'interop/java/ServerReleaseWrapping.java')],check=True)
    lanes=[]
    with tempfile.TemporaryDirectory(prefix='keytend-release-wrapping-') as directory:
        server=ContainerServer(directory,a.engine,image_id) if a.image else Server(directory)
        subprocess.run(['openssl','pkcs12','-export','-in',str(server.pki/'client.pem'),'-inkey',str(server.pki/'client.key'),'-certfile',str(server.pki/'ca.pem'),'-out',str(server.pki/'client.p12'),'-passout','pass:changeit'],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        try:
            server.start()
            for index,java in enumerate(a.java):
                jdk=subprocess.check_output([java,'-version'],stderr=subprocess.STDOUT,text=True).splitlines()[0]
                report=out/f'{mode}-jdk{index}.json';log=report.with_suffix('.log')
                with log.open('w') as stream:subprocess.run([java,'-cp',classpath,'dev.keytend.kmip.interop.ServerReleaseWrapping',str(server.pki),str(server.port),str(report)],check=True,stdout=stream,stderr=subprocess.STDOUT,timeout=90)
                data=json.loads(report.read_text());assert len(data['versions'])==6 and all(r['no_encoding_wrap_and_independent_unwrap'] for r in data['versions'])
                lanes.append({'jdk':jdk,'report':str(report.relative_to(ROOT)),'report_sha256':sha(report),'log_sha256':sha(log)})
        finally:server.stop()
    (out/f'{mode}-summary.json').write_text(json.dumps({'status':'passed','scope':'corrected NoEncoding and versioned missing-parameter reason probes; no full-spec qualification','client_artifact':artifact,**evidence,'lanes':lanes},indent=2)+'\n')
    print('PASS supplemental SDK wrapping:',len(lanes)*6,'lanes; versioned missing-parameters reasons verified')
if __name__=='__main__':main()
