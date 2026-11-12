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

"""Percona Server for MongoDB KMIP client: trust, hostname, identity and ACL
negatives, outage at start and an externally registered master key, against the server image.

The existing Percona lanes cover lifecycle, rotation, compromise polling, replica
sets, backup and PBM; this lane adds the client qualification negatives they lack.
Disposable named containers and directories only; PKI generated at test time.
"""
import argparse,datetime,hashlib,json,os,pathlib,shutil,subprocess,tempfile,time,uuid
from image_evidence import local_image_id,packaged_evidence,native_sha256
from test_database import ContainerServer,PERCONA
from test_database_mysql import Kmip,sha
from test_runtime import ROOT,free_port
from wire import *

OUT=ROOT/'artifacts/database-psmdb-negatives'
PROOF='psmdb exact material proof'

def register_key(kmip,material):
    """Register and activate an AES-256 key with known bytes (KMIP 1.4 Register)."""
    template=structure(0x420091,attr(enumeration(0x420028,3)),attr(integer(0x42002a,256)),attr(integer(0x42002c,12)))
    key=structure(0x42008f,structure(0x420040,enumeration(0x420042,1),structure(0x420045,binary(0x420043,material)),enumeration(0x420028,3),integer(0x42002a,256)))
    with connect(kmip.pki,kmip.port) as c:
        id=get(payload(exchange(c,request(3,[enumeration(0x420057,2),template,key]))),0x420094)[2]
        payload(exchange(c,request(18,[uid(id)])))
    return id

class Lane:
    def __init__(self,root,engine,image,out):
        self.root=pathlib.Path(root);self.engine=engine;self.out=out;self.run_id=uuid.uuid4().hex[:10]
        (self.root/'kmip').mkdir(mode=0o700)
        self.server=ContainerServer(self.root/'kmip',engine,image,log_path=out/'kmip-server.log')
        self.server.name='keytend-psmdb-neg-kmip-'+self.run_id
        self.kmip=Kmip(self.server.pki,self.server.port)
        self.tls=self.root/'mongo-tls';self.tls.mkdir(mode=0o700)
        p=self.server.pki
        shutil.copy(p/'ca.pem',self.tls/'ca.pem')
        for name in ['client','other','unlisted']:
            (self.tls/f'{name}.pem').write_bytes((p/f'{name}.pem').read_bytes()+(p/f'{name}.key').read_bytes())
        self.untrusted_pki()
        for f in self.tls.iterdir():f.chmod(0o600)
        self.port=free_port();self.containers=[];self.steps=[];self.findings=[]
    def untrusted_pki(self):
        t=self.root/'wrong-pki';t.mkdir(mode=0o700)
        run=lambda *a:subprocess.run(a,check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        run('openssl','req','-x509','-newkey','rsa:2048','-nodes','-keyout',str(t/'ca.key'),'-out',str(t/'ca.pem'),'-days','2','-subj','/CN=keytend-kmip-server-wrong-ca','-addext','basicConstraints=critical,CA:TRUE','-addext','keyUsage=critical,keyCertSign,cRLSign')
        run('openssl','req','-new','-newkey','rsa:2048','-nodes','-keyout',str(t/'client.key'),'-out',str(t/'client.csr'),'-subj','/CN=client')
        (t/'client.ext').write_text('basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=clientAuth\n')
        run('openssl','x509','-req','-in',str(t/'client.csr'),'-CA',str(t/'ca.pem'),'-CAkey',str(t/'ca.key'),'-CAcreateserial','-out',str(t/'client.pem'),'-days','2','-extfile',str(t/'client.ext'))
        shutil.copy(t/'ca.pem',self.tls/'wrong-ca.pem')
        (self.tls/'untrusted.pem').write_bytes((t/'client.pem').read_bytes()+(t/'client.key').read_bytes())
    def step(self,name,**detail):
        self.steps.append(dict(name=name,**detail));print('PASS' if detail.get('outcome','passed')=='passed' else 'OBSERVED',name,flush=True)
    def mongod(self,label,data,*,server_name='127.0.0.1',ca='/tls/ca.pem',cert='/tls/client.pem',key_id=None,add_hosts=(),timeout=60):
        """Start mongod and report whether it served requests or exited."""
        name=f'keytend-psmdb-neg-{self.run_id}-{label}';self.containers.append(name);self.name=name
        args=[self.engine,'run','-d','--name',name,'--network','host']+(['--userns','keep-id'] if self.engine=='podman' else [])
        args+=['--user',f'{os.getuid()}:{os.getgid()}','--entrypoint','mongod','-e','HOME=/tmp','-e','PERCONA_TELEMETRY_DISABLE=1','-v',f'{self.tls}:/tls:ro','-v',f'{data}:/data/db']
        for h in add_hosts:args+=['--add-host',f'{h}:127.0.0.1']
        flags=['--bind_ip','127.0.0.1','--port',str(self.port),'--dbpath','/data/db','--enableEncryption','--kmipServerName',server_name,'--kmipPort',str(self.server.port),
               '--kmipServerCAFile',ca,'--kmipClientCertificateFile',cert,'--kmipKeyStatePollingSeconds','2','--kmipConnectRetries','1','--kmipConnectTimeoutMS','3000']
        if key_id:flags+=['--kmipKeyIdentifier',key_id]
        subprocess.check_output(args+[PERCONA]+flags,text=True,stderr=subprocess.STDOUT)
        until=time.monotonic()+timeout;ready=False
        while time.monotonic()<until:
            if self.shell('if(db.adminCommand({ping:1}).ok!==1)quit(1)',check=False)[0]==0:ready=True;break
            if not self.running():break
            time.sleep(.3)
        return ready
    def running(self):
        r=subprocess.run([self.engine,'inspect','--format','{{.State.Running}}',self.name],stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,text=True)
        return r.stdout.strip()=='true'
    def shell(self,js,check=True):
        r=subprocess.run([self.engine,'exec','-e','HOME=/tmp',self.name,'mongosh','--port',str(self.port),'--quiet','--eval',js],stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True,timeout=60)
        if check and r.returncode:raise RuntimeError(r.stdout)
        return r.returncode,r.stdout.strip()
    def stop(self,label):
        if self.running():subprocess.run([self.engine,'stop','--time','30',self.name],check=True,stdout=subprocess.DEVNULL)
        log=subprocess.check_output([self.engine,'logs',self.name],text=True,stderr=subprocess.STDOUT)
        (self.out/f'{label}.log').write_text(log);subprocess.run([self.engine,'rm','-f',self.name],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        return log
    def key_id(self):return json.loads(self.shell('print(JSON.stringify(db.serverStatus().encryptionAtRest))')[1])['encryptionKeyId']['kmip']['keyId']
    def write_proof(self):self.shell(f'db.getSiblingDB("q1").proof.insertOne({{_id:"proof",value:"{PROOF}"}},{{writeConcern:{{w:1,j:true}}}})')
    def read_proof(self):return self.shell('const d=db.getSiblingDB("q1").proof.findOne({_id:"proof"});print(d?d.value:"")',check=False)
    def refused(self,label,data,expect,**kw):
        ready=self.mongod(label,data,**kw)
        log=self.stop(label)
        lines=[json.loads(l) for l in log.splitlines() if l.startswith('{')]
        errors=sorted({(l.get('msg','')+' '+json.dumps(l.get('attr',{})))[:300] for l in lines if l.get('s') in ('E','F') or 'KMIP' in l.get('msg','') or 'kmip' in json.dumps(l.get('attr',{})).lower()})[:8]
        evidence=[x for x in expect if x in log]
        obs=dict(label=label,ready=ready,exited=not ready,errors=errors,log_evidence=evidence)
        assert not ready and evidence==list(expect),obs
        return obs

def scenario(lane):
    k=lane.kmip;s=lane.server
    d1=lane.root/'db1';d1.mkdir(mode=0o700)
    assert lane.mongod('baseline',d1);lane.write_proof();key=lane.key_id()
    a=k.attributes(key);assert a['State']==2 and a['Cryptographic Length']==256,a
    lane.stop('baseline');lane.step('baseline: mongod registered and activated an AES-256 master key over verified mTLS and wrote durable data',key_id=key)
    cases=[
        ('wrong-server-ca',dict(ca='/tls/wrong-ca.pem'),['certificate verify failed']),
        # Same CA as the passing DNS-name control below; only the requested name differs.
        ('wrong-hostname',dict(server_name='wrong-kmip.test',add_hosts=('wrong-kmip.test',)),['certificate verify failed']),
        ('unlisted-client',dict(cert='/tls/unlisted.pem'),['Permission Denied; message: Operation denied by certificate policy']),
        ('untrusted-client',dict(cert='/tls/untrusted.pem'),['tlsv1 alert unknown ca']),
        # CA-valid principal without access to the database principal's objects.
        ('other-principal',dict(cert='/tls/other.pem'),['Master encryption key is absent on the key management facility']),
    ]
    for label,kw,expect in cases:
        obs=lane.refused(label,d1,expect,**kw)
        lane.step(f'negative {label}: mongod exits; encrypted data not served',observation=obs)
    # Operation ACL: a fresh data directory makes mongod Register a new master
    # key, which the read-only principal may not do.
    fresh=lane.root/'db-other';fresh.mkdir(mode=0o700)
    obs=lane.refused('other-principal-register',fresh,['Permission Denied'],cert='/tls/other.pem')
    lane.step('negative other-principal-register: Register denied by operation policy; mongod exits',observation=obs)
    assert lane.mongod('dns-name-control',d1,server_name='keytend-kmip-server',add_hosts=('keytend-kmip-server',))
    assert lane.read_proof()==(0,PROOF);lane.stop('dns-name-control')
    lane.step('control: a DNS name in the server certificate SAN starts and reads the data')
    s.stop()
    obs=lane.refused('kmip-outage',d1,['KMIP sessions failed for all the server hosts'])
    lane.step('KMIP server unavailable at start: mongod exits',observation=obs)
    s.start()
    assert lane.mongod('recovered',d1) and lane.read_proof()==(0,PROOF);lane.stop('recovered')
    lane.step('after every negative and the outage, the verified configuration reads the data again')
    # Externally supplied key: mongod adopts an independently registered key with
    # known bytes. It binds the identifier in its metadata, so another identifier
    # (even with the same bytes) is refused before any key bytes are used; the exact
    # bytes in use are therefore not observable through the PSMDB interface.
    material=os.urandom(32)
    a_id=register_key(k,material);same_id=register_key(k,material)
    assert k.get(a_id)['material']==material==k.get(same_id)['material']
    d2=lane.root/'db2';d2.mkdir(mode=0o700)
    assert lane.mongod('known-key',d2,key_id=a_id) and lane.key_id()==a_id;lane.write_proof();lane.stop('known-key')
    assert k.get(a_id)['material']==material and k.attributes(a_id)['State']==2
    lane.step('mongod adopted an independently registered AES-256 key (known bytes, Active) as its master key',key_id=a_id)
    binding='KMIP keyIdentifier is not equal to that the system is already configured'
    obs=lane.refused('same-bytes-other-identifier',d2,[binding],key_id=same_id)
    lane.step('key substitution refused: a second identifier holding the same bytes is rejected by identifier binding (exact bytes in use not observable)',outcome='observed',observation=obs)
    assert lane.mongod('known-key-again',d2,key_id=a_id) and lane.read_proof()==(0,PROOF);lane.stop('known-key-again')
    lane.step('original identifier still opens the data')

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--engine',default='podman');p.add_argument('--image',required=True);p.add_argument('--output',type=pathlib.Path,default=OUT)
    a=p.parse_args();out=a.output.resolve();out.mkdir(parents=True,exist_ok=True)
    binary=native_sha256(a.image)
    evidence=packaged_evidence(local_image_id(a.engine,a.image));db_config=local_image_id(a.engine,PERCONA)
    report=dict(status='running',started_at=datetime.datetime.now(datetime.timezone.utc).isoformat(),client='Percona Server for MongoDB built-in KMIP client',
        database_image=PERCONA,database_image_config_id=db_config,server_image=a.image,runtime_binary_sha256=binary,**evidence,
        limits='Single standalone mongod; complements the existing Percona lifecycle, rotation, compromise, replica-set, backup and PBM lanes. No full-spec or production approval.')
    path=out/'report.json';path.write_text(json.dumps(report,indent=2)+'\n');lane=None
    try:
        with tempfile.TemporaryDirectory(prefix='keytend-psmdb-neg-') as d:
            lane=Lane(d,a.engine,a.image,out)
            try:
                lane.server.start();scenario(lane)
            finally:
                for name in lane.containers:subprocess.run([a.engine,'rm','-f',name],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
                lane.server.stop()
        report['status']='passed' if all(s.get('outcome','passed')=='passed' for s in lane.steps) else 'passed_with_observations'
    except BaseException as error:
        report.update(status='failed',error_type=type(error).__name__,error=(getattr(error,'output',None) or str(error))[-4000:]);raise
    finally:
        if lane:report.update(steps=lane.steps,findings=lane.findings)
        report['finished_at']=datetime.datetime.now(datetime.timezone.utc).isoformat()
        report['log_sha256']={p.name:sha(p) for p in sorted(out.glob('*.log'))}
        path.write_text(json.dumps(report,indent=2)+'\n')
    print('PASS Percona Server for MongoDB KMIP negatives lane:',len(lane.steps),'steps')

if __name__=='__main__':main()
