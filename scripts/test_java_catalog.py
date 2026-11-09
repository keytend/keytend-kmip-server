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

"""Run the published keytend-kmip SDK's unchanged catalog on owned container fixtures.
All outcomes are retained. --report-only is investigation, never qualification.

The SDK is the signed, pinned keytend-kmip release (scripts/keytend_kmip_release.py): its
integration JAR carries the catalog suite and its ZIP the catalog and PKI script. The
adapter interop/java/ServerCatalog.java is compiled with javac against the release JARs.
Each --java is a JDK java executable (default: java on PATH).
"""
import argparse,collections,datetime,hashlib,json,os,pathlib,shutil,socketserver,subprocess,tempfile,threading,time
from test_database import ContainerServer
from image_evidence import source_commit,local_image_id,packaged_evidence
from test_runtime import ROOT
import keytend_kmip_release

PIN=keytend_kmip_release.PIN['commit']
ADAPTER=ROOT/'interop/java/ServerCatalog.java'
ART=ROOT/'artifacts/java-catalog'

def sha(p):return hashlib.sha256(pathlib.Path(p).read_bytes()).hexdigest()
def run(args,**kwargs):return subprocess.run([str(a) for a in args],check=True,**kwargs)
def fingerprint(pem):
    import ssl
    return hashlib.sha256(ssl.PEM_cert_to_DER_cert(pem.read_text())).hexdigest()

class Control(socketserver.UnixStreamServer):
    def __init__(self,path,server,certs,log):
        self.fixture=server;self.certs=certs;self.control_log=pathlib.Path(log);self.failures=0
        class Handler(socketserver.StreamRequestHandler):
            def handle(handler):
                command=handler.rfile.readline(4096).decode().strip();started=time.monotonic()
                event={'at':datetime.datetime.now(datetime.timezone.utc).isoformat(),'action':command,'container':handler.server.fixture.name,'phase':'dispatch'}
                try:
                    fixture=handler.server.fixture;source=handler.server.certs
                    if command=='restart':
                        event['phase']='stop';fixture.stop();event['phase']='start';fixture.start()
                    elif command=='revoke' or command.startswith(('grant:','list-only:')):
                        event['phase']='stop';fixture.stop()
                        event['phase']='policy';policy=json.loads((fixture.tls/'policy.json').read_text())
                        principal=policy['principals'][fingerprint(source/'client-b.pem')]
                        if principal['name']!='other-tenant':raise ValueError('unexpected grant principal')
                        if command=='revoke':principal['object_grants']=[]
                        else:
                            mode,identifier=command.split(':',1)
                            if not identifier or len(identifier.encode())>1024:raise ValueError('invalid grant identifier')
                            principal['object_grants']=[{'owner':'database','identifier':identifier,'operations':[10] if mode=='grant' else [8]}]
                        (fixture.tls/'policy.json').write_text(json.dumps(policy));event['phase']='start';fixture.start()
                    elif command.startswith('identity:'):
                        name=command.split(':',1)[1]
                        if name not in ['server','chain-server','missing-chain','replacement-server','revoked-server','rollover-server']:raise ValueError('unknown identity')
                        event['phase']='stop';fixture.stop()
                        event['phase']='identity';cert=source/('full-chain-server.pem' if name=='chain-server' else 'chain-server.pem' if name=='missing-chain' else name+'.pem')
                        key=source/('chain-server-key.pem' if name=='missing-chain' else name+'-key.pem')
                        shutil.copyfile(cert,fixture.tls/'server.pem');shutil.copyfile(key,fixture.tls/'server.key');(fixture.tls/'server.key').chmod(0o600)
                        event['phase']='start';fixture.start()
                    else:raise ValueError('unsupported control')
                    event['phase']='reply';event['outcome']='success'
                    reply=('OK '+sha(fixture.tls/'policy.json')+'\n').encode()
                except Exception as error:
                    handler.server.failures+=1
                    event.update(outcome='error',exception_type=type(error).__name__,message=str(error)[:4096])
                    if isinstance(error,subprocess.CalledProcessError):event['command_output']=str(error.output)[-8192:]
                    reply=b'ERROR owned fixture control failed; see control log\n'
                finally:
                    event['duration_ms']=int((time.monotonic()-started)*1000)
                    with handler.server.control_log.open('a') as stream:stream.write(json.dumps(event)+'\n')
                handler.wfile.write(reply)
        super().__init__(str(path),Handler)

def main():
    p=argparse.ArgumentParser();p.add_argument('--engine',choices=['podman','docker'],default='podman');p.add_argument('--image',default='localhost/keytend-kmip-server:dev');p.add_argument('--java',action='append',help='JDK java executable; repeat for several lanes (default: java on PATH)');p.add_argument('--versions',nargs='+',default=['1.1','1.2','1.3','1.4','2.0','2.1']);p.add_argument('--report-only',action='store_true');a=p.parse_args()
    client,jars,artifact=keytend_kmip_release.release();pin=artifact['commit'];art=ART
    art.mkdir(parents=True,exist_ok=True);summary_path=art/'summary.json';summary_path.write_text(json.dumps({'status':'running'})+'\n')
    image_id=local_image_id(a.engine,a.image);image=packaged_evidence(image_id);runtime=image.get('source_commit') or source_commit()[0]
    # The catalog contract is the one in the signed release.
    catalog=client/'integration/catalog/catalog.json'
    java_default=shutil.which('java') or 'java'
    classpath=keytend_kmip_release.adapters(['ServerCatalog'],ROOT/'.cache/java-catalog-adapter',(a.java or [java_default])[0],h2=True)
    h2=keytend_kmip_release.h2_jar()
    previous=keytend_kmip_release.previous_jar()  # JAVA-07 upgrade and rollback
    lanes=[]
    with tempfile.TemporaryDirectory(prefix='keytend-java-') as directory:
        root=pathlib.Path(directory);certs=root/'catalog-pki'
        with (art/'pki.log').open('w') as log:run(['bash',client/'integration/catalog/generate-pki.sh',certs],stdout=log,stderr=subprocess.STDOUT)
        config_hash=hashlib.sha256(json.dumps({'adapter_sha256':sha(ADAPTER),'server_policy':'certificate allowlist; separate owners; read-only other-tenant principal with exact-object Get or Locate grants and controlled-restart revocation','transport':'binary_ttlv_mtls','certificates':{p.name:sha(p) for p in sorted(certs.glob('*.pem')) if 'key' not in p.name}},sort_keys=True).encode()).hexdigest()
        for java in a.java or [java_default]:
            jdk=subprocess.check_output([java,'-version'],stderr=subprocess.STDOUT,text=True).splitlines()[0]
            for version in a.versions:
                lane_dir=root/('lane-'+str(len(lanes)));lane_dir.mkdir(mode=0o700)
                server=ContainerServer(lane_dir,a.engine,a.image)
                for source,target in [('server.pem','server.pem'),('server-key.pem','server.key'),('client.pem','client.pem'),('client-key.pem','client.key'),('ca.pem','ca.pem')]:shutil.copyfile(certs/source,server.pki/target)
                policy={'principals':{fingerprint(certs/'client.pem'):{'name':'database','operations':list(range(1,67))},fingerprint(certs/'client-b.pem'):{'name':'other-tenant','operations':[8,10,11,12,24,30],'object_grants':[]},fingerprint(certs/'client-renewed.pem'):{'name':'database','operations':list(range(1,67))}}}
                (server.pki/'policy.json').write_text(json.dumps(policy));(server.pki/'server.key').chmod(0o600);(server.pki/'client.key').chmod(0o600)
                for name in ['server.pem','server.key','ca.pem','policy.json']:shutil.copyfile(server.pki/name,server.tls/name)
                (server.tls/'server.key').chmod(0o600)
                report=art/f'catalog-{version}-jdk{len(lanes)//len(a.versions)}.json';control_path=root/f'control-{len(lanes)}.sock'
                control_log=report.with_suffix('.control.jsonl');control_log.write_text('')
                controller=Control(control_path,server,certs,control_log);thread=threading.Thread(target=controller.serve_forever,daemon=True);thread.start()
                try:
                    server.start()
                    with report.with_suffix('.run.log').open('w') as log:
                        result=subprocess.run([java,'-Dkmip.catalog.p95Millis=1000','-Dkmip.catalog.p99Millis=2000','-Dkmip.catalog.previousArtifact='+str(previous),'-cp',classpath,'dev.keytend.kmip.interop.ServerCatalog',str(client),'localhost',str(server.port),str(certs),version,'runtime-'+runtime,'sha256:'+image_id,pin,config_hash,str(control_path),str(report),sha(ADAPTER)],stdout=log,stderr=subprocess.STDOUT,timeout=1800,cwd=client)
                    if result.returncode:raise RuntimeError('Java catalog process failed; see '+str(report.with_suffix('.run.log')))
                    data=json.loads(report.read_text());records=data['records'];assert len(records)==164 and {r['test_id'] for r in records}=={c['id'] for c in json.loads(catalog.read_text())['cases']}
                    counts=dict(collections.Counter(r['outcome'] for r in records));lane={'wire_version':version,'jdk':jdk,'report':str(report.relative_to(ROOT)),'report_sha256':sha(report),'outcomes':counts,'qualified':data['qualification']['qualified'],'control_log':str(control_log.relative_to(ROOT)),'control_log_sha256':sha(control_log),'control_failures':controller.failures};lanes.append(lane)
                    print(json.dumps(lane),flush=True)
                finally:
                    controller.shutdown();controller.server_close();thread.join(timeout=5);server.stop()
                    if control_path.exists():control_path.unlink()
    result={'client_artifact':artifact,'client_source':artifact['url'],'status':'passed' if lanes and all(l['qualified'] for l in lanes) else 'incomplete','client_commit':pin,'catalog_sha256':sha(catalog),'h2_jar_sha256':sha(h2),'previous_client':{'version':keytend_kmip_release.PIN['previous']['version'],'sdk_jar_sha256':sha(previous)},**image,'lanes':lanes,'limits':['Object-granular read permissions use real controlled policy restarts; remaining server/client findings stay explicit','Controlled-peer/codec cases retain their own layers','External vendor cases retain their prerequisites','This is not full-spec or production qualification']}
    summary_path.write_text(json.dumps(result,indent=2)+'\n')
    if result['status']!='passed' and not a.report_only:raise SystemExit(1)
if __name__=='__main__':main()
