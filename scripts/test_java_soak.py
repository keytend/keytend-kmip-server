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

"""Run the published keytend-kmip SDK's unchanged CatalogSoak against one immutable owned server image.
Short durations produce SMOKE_ONLY; only a completed 24-hour run can earn PASS. The SDK
is the signed, pinned release (scripts/keytend_kmip_release.py), copied into the run's
own directory so nothing outside it can change the JARs during the soak.
"""
import argparse,json,os,pathlib,shutil,signal,subprocess,tempfile
from image_evidence import local_image_id,packaged_evidence,source_commit
from test_database import ContainerServer
import test_database
from test_runtime import ROOT
from test_java_catalog import fingerprint,sha
import keytend_kmip_release

def main():
    p=argparse.ArgumentParser();p.add_argument('--engine',default='podman');p.add_argument('--image',default='localhost/keytend-kmip-server:dev');p.add_argument('--java',default=shutil.which('java') or 'java',help='JDK java executable (default: java on PATH)');p.add_argument('--version',default='2.1',choices=['1.1','1.2','1.3','1.4','2.0','2.1']);p.add_argument('--duration',default='PT24H');p.add_argument('--output',type=pathlib.Path,default=ROOT/'artifacts/java-soak');a=p.parse_args()
    output=a.output.resolve();output.mkdir(parents=True,exist_ok=True)
    # Keep this long run's logs separate from completed database checkpoints.
    test_database.ART=output
    manifest=output/'manifest.json';assert not manifest.exists(),'use a fresh output directory; do not replace soak evidence'
    def save(data):
        temporary=manifest.with_suffix('.tmp');temporary.write_text(json.dumps(data,indent=2)+'\n');temporary.replace(manifest)
    # The signed release: the soak runs the SDK's own CatalogSoak class from its integration JAR.
    client,jars,artifact=keytend_kmip_release.release();PIN=artifact['commit']
    config=local_image_id(a.engine,a.image);image=packaged_evidence(config);runtime=image.get('source_commit') or source_commit()[0]
    sdk_hashes={str(j.relative_to(client)):sha(j) for j in jars}
    record={'status':'STARTING','pid':os.getpid(),'client_commit':PIN,'wire_version':a.version,'jdk':subprocess.check_output([a.java,'-version'],stderr=subprocess.STDOUT,text=True).splitlines()[0],'requested_duration':a.duration,'sdk_class_sha256':sdk_hashes,**image,'limits':['Client retained heap, threads and descriptor limits are checked by CatalogSoak','This workload is not full capacity, HA, server resource or production qualification','Runtime source changes after startup do not change this pinned image; this is evidence for that image only']};save(record)
    def interrupted(*_):raise InterruptedError('Soak interrupted')
    signal.signal(signal.SIGTERM,interrupted)
    with tempfile.TemporaryDirectory(prefix='keytend-java-soak-') as directory:
        root=pathlib.Path(directory);certs=root/'catalog-pki';copied=[]
        for j in jars:
            dest=root/j.name;shutil.copyfile(j,dest);copied.append(dest)
        classpath=os.pathsep.join(map(str,copied))
        with (output/'pki.log').open('w') as log:subprocess.run(['bash',str(client/'integration/catalog/generate-pki.sh'),str(certs)],check=True,stdout=log,stderr=subprocess.STDOUT)
        server=ContainerServer(root,a.engine,config)
        for source,target in [('server.pem','server.pem'),('server-key.pem','server.key'),('client.pem','client.pem'),('client-key.pem','client.key'),('ca.pem','ca.pem')]:shutil.copyfile(certs/source,server.pki/target)
        (server.pki/'policy.json').write_text(json.dumps({'principals':{fingerprint(certs/'client.pem'):{'name':'java-soak','operations':list(range(1,67))}}}))
        for name in ['server.pem','server.key','ca.pem','policy.json']:shutil.copyfile(server.pki/name,server.tls/name)
        (server.tls/'server.key').chmod(0o600)
        configuration=sha(server.tls/'policy.json');record.update(server_container=server.name,configuration_hash=configuration);save(record)
        try:
            server.start();record['status']='RUNNING';save(record)
            with (output/'client.log').open('w') as log:
                command=[a.java,'-Xmx256m','-Dkmip.server.build=runtime-'+runtime,'-Dkmip.server.image=sha256:'+config,'-Dkmip.client.commit='+PIN,'-Dkmip.server.configurationHash='+configuration,'-cp',classpath,'dev.keytend.kmip.interop.CatalogSoak','localhost',str(server.port),str(certs),'keytend-kmip-server',a.version,a.duration,str(output/'progress.json')]
                process=subprocess.Popen(command,stdout=log,stderr=subprocess.STDOUT,cwd=client)
                try:
                    code=process.wait(timeout=90000);assert code==0,'Java soak failed; see client.log'
                finally:
                    if process.poll() is None:
                        process.terminate()
                        try:process.wait(timeout=30)
                        except subprocess.TimeoutExpired:process.kill();process.wait()
            progress=json.loads((output/'progress.json').read_text());assert progress['status'] in ['PASS','SMOKE_ONLY']
            record['status']=progress['status'];record['progress_sha256']=sha(output/'progress.json');record['completed_elapsed_seconds']=progress['elapsed_seconds']
            if record['status']=='PASS':assert progress['elapsed_seconds']>=86400
        except BaseException as error:
            record['status']='FAILED';record['failure_type']=type(error).__name__;raise
        finally:
            try:server.stop()
            finally:save(record)
    print(record['status'],flush=True)
if __name__=='__main__':main()
