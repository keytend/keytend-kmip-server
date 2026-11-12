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

"""Real encrypted Percona workload against the deliverable container image.
Runs only disposable named containers and directories; no external database is used.
"""
import argparse,json,os,pathlib,re,shutil,socket,subprocess,tempfile,time,uuid
from test_runtime import ROOT,Server,free_port,stable_port
from wire import *
from image_evidence import local_image_id,packaged_evidence
import image_server
PERCONA='docker.io/percona/percona-server-mongodb@sha256:e1004538c31619ec471aa39423ef9ffa39a598750661c2d6c66d785de852d538'
ART=ROOT/'artifacts';ART.mkdir(exist_ok=True)
def command(args,**kwargs):return subprocess.check_output(args,text=True,stderr=subprocess.STDOUT,**kwargs)
class ContainerServer(Server):
    def __init__(self,directory,engine,image,*,pki=None,data=None,binary=None,draft=False,log_path=None):
        if (pki is None)!=(data is None):raise ValueError('provide both pki and data, or neither')
        # Set first: Server.__init__ generates the master key, which the image does here (generate_master_key).
        self.engine=engine;self.image=image
        if pki is None:super().__init__(directory,binary=binary,draft=draft)
        else:
            self.root=pathlib.Path(directory);self.root.mkdir(parents=True,exist_ok=True)
            self.pki=pathlib.Path(pki);self.data=pathlib.Path(data);self.port=stable_port();self.health=free_port();self.draft=draft
        self.log_path=pathlib.Path(log_path) if log_path else ART/'database-kmip.log'
        # The image is the server: nothing here runs a native executable.
        self.binary=None;self.extra_args=[];self.name='keytend-server-'+uuid.uuid4().hex[:12];self.tls=self.root/'server-tls';self.tls.mkdir(mode=0o700)
        for name in ['server.pem','server.key','ca.pem','master.key','policy.json']:shutil.copy(self.pki/name,self.tls/name)
    def generate_master_key(self,path):
        """generate-master-key run by the image, writing as this user into the PKI directory."""
        user=['--userns','keep-id'] if self.engine=='podman' else []
        subprocess.run([self.engine,'run','--rm','--network','none',*user,'--user',f'{os.getuid()}:{os.getgid()}','--no-healthcheck',
                        '-v',f'{path.parent}:/out',self.image,'generate-master-key','--output','/out/'+path.name],check=True,stdout=subprocess.DEVNULL)
    def base(self):return [self.engine,'run','--rm','--label',f'{image_server.LABEL}={image_server.run_label()}']+(['--userns','keep-id:uid=10001,gid=10001'] if self.engine=='podman' else ['--user',f'{os.getuid()}:{os.getgid()}'])+['--read-only','--tmpfs','/tmp:rw,nosuid,nodev,noexec,size=64m,mode=1777','--cap-drop=all','--security-opt=no-new-privileges','--pids-limit=128','--memory=256m','--cpus=2','-v',f'{self.tls}:/tls:ro','-v',f'{self.data}:/data']
    def start(self):
        # Only readiness checks use the health port, so each start takes a new one: the old one
        # is in the ephemeral range and may be taken while the container is down (pasta then fails
        # with "Address already in use"). Clients reconnect to the KMIP port, so it stays; it is
        # below the ephemeral range (stable_port), and a start is retried while the previous
        # container's forward is still being released.
        self.health=free_port()
        # The server settings a native Server takes from this process's environment, except any base() sets.
        base=self.base();fixed={base[i+1].split('=',1)[0] for i,x in enumerate(base[:-1]) if x=='-e'}
        forwarded=image_server.passed(os.environ,fixed)
        args=base+['-d','--name',self.name,'-p',f'127.0.0.1:{self.port}:5696','-p',f'127.0.0.1:{self.health}:8080',*forwarded,self.image,'serve','--cert','/tls/server.pem','--key','/tls/server.key','--ca','/tls/ca.pem','--master-key','/tls/master.key','--policy','/tls/policy.json','--database','/data/kmip.sqlite']
        if self.draft:args+=['--experimental-v3']
        # As Server: draft 3.0 credential traces use the PKI's users file; otherwise an explicit one, and a CRL.
        users=self.pki/'users.json' if self.draft and (self.pki/'users.json').exists() else getattr(self,'users',None)
        if users:shutil.copy(users,self.tls/'users.json');args+=['--users','/tls/users.json']
        if getattr(self,'crl',None):shutil.copy(self.crl,self.tls/'ca.crl');args+=['--crl','/tls/ca.crl']
        args+=self.extra_args
        for attempt in range(10):
            try:command(args);break
            except subprocess.CalledProcessError as error:
                # pasta, slirp4netns/rootlessport and Docker word a port collision differently.
                if not re.search(r'address already in use|port is already allocated',error.output or '',re.I) or attempt==9:raise
                subprocess.run([self.engine,'rm','-f',self.name],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
                time.sleep(.5)
        until=time.monotonic()+20
        while time.monotonic()<until:
            try:
                with socket.create_connection(('127.0.0.1',self.health),timeout=.3) as c:
                    c.sendall(b'GET /readyz HTTP/1.1\r\nHost: localhost\r\n\r\n');assert c.recv(128).startswith(b'HTTP/1.1 200')
                # Health and KMIP use separate host port forwards. Both must be up.
                with socket.create_connection(('127.0.0.1',self.port),timeout=.3):pass
                return
            except (OSError,AssertionError):time.sleep(.1)
        raise RuntimeError(command([self.engine,'logs',self.name]))
    def container_exists(self):
        if self.engine=='podman':
            result=subprocess.run([self.engine,'container','exists',self.name],stdout=subprocess.PIPE,stderr=subprocess.PIPE)
            if result.returncode not in [0,1]:result.check_returncode()
            return result.returncode==0
        # A failed Docker CLI observation is an error, not proof of removal.
        return self.name in command([self.engine,'container','ls','--all','--format','{{.Names}}']).splitlines()
    def stop(self):
        if self.container_exists():
            with open(self.log_path,'a') as f:f.write(command([self.engine,'logs',self.name]))
            command([self.engine,'stop','--time','20',self.name])
            # --rm removal may still be in progress after stop returns. A new
            # run with this name must wait for the previous container to vanish.
            until=time.monotonic()+20
            while time.monotonic()<until:
                if not self.container_exists():return
                time.sleep(.05)
            raise RuntimeError('Owned fixture container was not removed after stop: '+self.name)
    def backup(self):
        command(self.base()+[self.image,'backup','--database','/data/kmip.sqlite','--master-key','/tls/master.key','--output','/data/backup.sqlite'])

def run(engine,image):
    results=[];name='keytend-db-'+uuid.uuid4().hex[:12];port=free_port()
    def passed(msg):results.append(msg);print('PASS',msg,flush=True)
    def exists():return subprocess.run([engine,'inspect',name],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL).returncode==0
    with tempfile.TemporaryDirectory(prefix='keytend-kmip-server-database-') as d:
        s=ContainerServer(d,engine,image)
        dbdata=pathlib.Path(d)/'database';dbdata.mkdir();dbtls=pathlib.Path(d)/'database-tls';dbtls.mkdir()
        shutil.copy(s.pki/'ca.pem',dbtls/'ca.pem');(dbtls/'client.pem').write_bytes((s.pki/'client.pem').read_bytes()+(s.pki/'client.key').read_bytes())
        # These files are private to the disposable 0700 test directory.
        (dbtls/'client.pem').chmod(0o600)
        base=[engine,'run','--network','host']+(['--userns','keep-id'] if engine=='podman' else [])+['--user',f'{os.getuid()}:{os.getgid()}','--entrypoint','mongod','-e','HOME=/tmp','-e','PERCONA_TELEMETRY_DISABLE=1','-v',f'{dbtls}:/tls:ro','-v',f'{dbdata}:/data/db']
        flags=['--bind_ip','127.0.0.1','--port',str(port),'--dbpath','/data/db','--enableEncryption','--kmipServerName','127.0.0.1','--kmipPort',str(s.port),'--kmipServerCAFile','/tls/ca.pem','--kmipClientCertificateFile','/tls/client.pem','--kmipKeyStatePollingSeconds','2']
        def shell(js):return command([engine,'exec','-e','HOME=/tmp',name,'mongosh','--port',str(port),'--quiet','--eval',js])
        def start_db():
            if exists():command([engine,'start',name])
            else:command(base+['-d','--name',name,PERCONA]+flags)
            until=time.monotonic()+45
            while time.monotonic()<until:
                try:
                    shell('if(db.adminCommand({ping:1}).ok!==1)quit(1)');return
                except subprocess.CalledProcessError:time.sleep(.2)
            raise RuntimeError(command([engine,'logs',name]))
        def state():return json.loads(shell('print(JSON.stringify(db.serverStatus().encryptionAtRest))'))
        def proof():shell('const d=db.getSiblingDB("kmip_test").proof.findOne({_id:"proof"});if(!d || d.value!=="durable encrypted payload")quit(1);')
        try:
            s.start();start_db()
            first=state();assert first['encryptionEnabled'] is True;first_id=first['encryptionKeyId']['kmip']['keyId']
            shell('db.getSiblingDB("kmip_test").proof.insertOne({_id:"proof",value:"durable encrypted payload"},{writeConcern:{w:1,j:true}})');proof()
            passed('container mTLS: Percona 8.0.34-15 registered/activated key and encrypted durable writes')
            command([engine,'stop','--time','30',name]);s.stop();s.backup()
            # Restore into a new directory with no original WAL/SHM files.
            restore=pathlib.Path(d)/'restored';restore.mkdir(mode=0o700);shutil.copy(s.data/'backup.sqlite',restore/'kmip.sqlite');s.data=restore
            s.start();start_db();proof();assert state()['encryptionKeyId']['kmip']['keyId']==first_id
            passed('both services restarted; encrypted SQLite backup restored; exact database key and data recovered')
            command([engine,'stop','--time','30',name]);s.stop()
            # This changes the server's storage encryption key, separately from
            # the database-managed KMIP key rotated by Percona below.
            from test_storage_rotation import rotate_container
            rotate_container(s)
            s.start();start_db();proof();assert state()['encryptionKeyId']['kmip']['keyId']==first_id
            passed('server storage master-key rotation and clean cutover preserved the database key identifier and encrypted data')
            command([engine,'stop','--time','30',name])
            rotation=command(base+['--rm',PERCONA]+flags+['--kmipRotateMasterKey']);(ART/'database-rotation.log').write_text(rotation)
            start_db();proof();rotated=state();new_id=rotated['encryptionKeyId']['kmip']['keyId'];assert new_id!=first_id
            passed('Percona master-key rotation created a new active KMIP key; original data remained readable')
            with s.connect() as c:
                payload(exchange(c,request(19,[uid(new_id),structure(0x420081,enumeration(0x420082,2))])))
            until=time.monotonic()+20
            while time.monotonic()<until:
                inspected=json.loads(command([engine,'inspect',name]))[0]
                if not inspected['State']['Running']:break
                time.sleep(.25)
            else:raise AssertionError('Database did not stop after key compromise')
            logs=command([engine,'logs',name]);assert 'not in the active state' in logs.lower() and new_id in logs and 'Compromised' in logs
            passed('key compromise revoked current key; database state polling shut the database down')
            (ART/'database.log').write_text(logs)
            return {'status':'passed','database_image':PERCONA,'server_image':image,'initial_key_id':first_id,'rotated_key_id':new_id,'passed':results}
        finally:
            if exists():
                try:
                    with open(ART/'database.log','a') as f:f.write(command([engine,'logs',name]))
                finally:subprocess.run([engine,'rm','-f',name],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
            s.stop()
if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('--engine',default='podman');parser.add_argument('--image',default='localhost/keytend-kmip-server:dev');a=parser.parse_args()
    (ART/'database.json').write_text(json.dumps({'status':'running'}))
    evidence=packaged_evidence(local_image_id(a.engine,a.image))
    result=run(a.engine,a.image)
    result.update(**evidence)
    (ART/'database.json').write_text(json.dumps(result,indent=2)+'\n')
