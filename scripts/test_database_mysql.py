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

"""Percona Server for MySQL 8.4 component_keyring_kmip against the server image.

Runs only disposable, uniquely named containers and directories. The PKI is
generated at test time (scripts/dev-pki.sh plus a second, untrusted CA) and is
removed with the temporary directory. Observed client behaviour, including
client defects, is recorded in the report rather than hidden: a step that
documents a known defect asserts the exact observed outcome.
"""
import argparse,datetime,hashlib,json,os,pathlib,shutil,subprocess,tempfile,time,uuid
from cryptography.hazmat.primitives.ciphers import Cipher,algorithms,modes
from image_evidence import local_image_id,packaged_evidence,native_sha256
from test_database import ContainerServer
from test_runtime import ROOT,free_port
from wire import *

# Official Percona image, 8.4.11-11.1 (8.4 LTS), multi-architecture index digest
# published 2026-10-27. Percona Server is GPLv2; it is pulled at test time and
# never enters Git or the server image.
MYSQL='docker.io/percona/percona-server@sha256:95d276d7f2b2718b725ad834a4d8a6f9e855b9566e51be8a9ff98d54b675f644'
COMPONENT='/usr/lib64/mysql/plugin/component_keyring_kmip.so'
OUT=ROOT/'artifacts/database-mysql'
GROUP='keytend-mysql-lane'
MARKER='keytend-kmip-server durable encrypted mysql marker'
UDF_KEY=b'q1-known-key-material-0123456789'  # keyring_udf passes a C string: no NUL bytes
STALE='Connection closed or error while reading'
NOT_UNIQUE="Name is not unique among the owner's objects"
STATE={1:'Pre-Active',2:'Active',3:'Deactivated',4:'Compromised',5:'Destroyed',6:'Destroyed Compromised'}

def sha(path):return hashlib.sha256(pathlib.Path(path).read_bytes()).hexdigest()
def command(args,**kw):return subprocess.check_output(args,text=True,stderr=subprocess.STDOUT,**kw)

def crc32c(data):
    c=0xffffffff
    for x in data:
        c^=x
        for _ in range(8):c=(c>>1)^(0x82f63b78 if c&1 else 0)
    return c^0xffffffff

# Page 0 offset of the encryption info for 16 KiB pages: FSP header end (150)
# plus 256 extent descriptors of 40 bytes (fsp_header_get_encryption_offset).
TABLESPACE_INFO=150+40*(16384//64)
def innodb_header(path,redo=False):
    """InnoDB encryption info (8.0+ magic "lCC"): master key ID, server UUID,
    tablespace key and IV encrypted with the master key (AES-256-ECB), CRC32-C
    of the plaintext (storage/innobase/os/os0enc.cc, Encryption::fill_encryption_info).
    Redo files carry it in their 2 KiB file header, tablespaces at a fixed offset."""
    data=pathlib.Path(path).read_bytes()[:16384]
    i=data[:2048].find(b'lCC') if redo else TABLESPACE_INFO
    if i<0 or data[i:i+3]!=b'lCC':return None
    return dict(master_key_id=int.from_bytes(data[i+3:i+7],'big'),server_uuid=data[i+7:i+43].decode(),
        encrypted=data[i+43:i+107],crc=int.from_bytes(data[i+107:i+111],'big'),offset=i)

def innodb_header_opens(header,key):
    d=Cipher(algorithms.AES(key),modes.ECB()).decryptor();plain=d.update(header['encrypted'])+d.finalize()
    return crc32c(plain)==header['crc']

def binlog_header(path):
    """Binary log encryption header v1 (sql/rpl_log_encryption.cc): magic
    FD 62 69 6E, version 1, then Key ID, encrypted file password and IV fields."""
    data=pathlib.Path(path).read_bytes()
    if data[:4]!=b'\xfdbin' or data[4]!=1:return None
    i=5;fields={}
    while i<512 and data[i]:
        kind=data[i];i+=1
        if kind==1:n=data[i];fields['key_id']=data[i+1:i+1+n].decode();i+=1+n
        elif kind==2:fields['password']=data[i:i+32];i+=32
        elif kind==3:fields['iv']=data[i:i+16];i+=16
        else:raise ValueError('unknown binlog header field')
    fields['body']=data[512:528]
    return fields

def binlog_opens(header,key):
    """Decrypt the file password (AES-256-CBC, replication master key), derive the
    file key/IV with EVP_BytesToKey(SHA-512, one round) and check that the first
    AES-256-CTR block decrypts to the plaintext binary log magic FE 62 69 6E."""
    d=Cipher(algorithms.AES(key),modes.CBC(header['iv'])).decryptor();password=d.update(header['password'])+d.finalize()
    digest=hashlib.sha512(password).digest()
    d=Cipher(algorithms.AES(digest[:32]),modes.CTR(digest[32:40]+bytes(8))).decryptor()
    return (d.update(header['body'])+d.finalize())[:4]==b'\xfebin'

class Kmip:
    """Independent check through this repository's own wire codec, not the MySQL client."""
    def __init__(self,pki,port):self.pki=pki;self.port=port
    def locate(self,name=None,state=None,identity='client'):
        filters=[]
        if name:filters.append(attr(structure(0x420053,text(0x420055,name),enumeration(0x420054,1))))
        if state:filters.append(attr(enumeration(0x42008d,state)))
        with connect(self.pki,self.port,identity) as c:
            return [x[2] for x in children(payload(exchange(c,request(8,filters))),0x420094)]
    def attributes(self,id):
        with connect(self.pki,self.port) as c:r=payload(exchange(c,request(11,[uid(id)])))
        result={}
        for a in children(r,0x420008):
            name=get(a,0x42000a)[2];value=get(a,0x42000b)
            result[name]=get(value,0x420055)[2] if name=='Name' else value[2]
        return result
    def get(self,id):
        with connect(self.pki,self.port) as c:r=exchange(c,request(10,[uid(id)]))
        if status(r):return dict(status=status(r),reason=reason(r))
        obj=[x for x in payload(r)[2] if x[0]==0x42008f][0]
        return dict(status=0,material=get(get(get(obj,0x420040),0x420045),0x420043)[2])
    def revoke(self,id,code):
        with connect(self.pki,self.port) as c:payload(exchange(c,request(19,[uid(id),structure(0x420081,enumeration(0x420082,code))])))
    def destroy(self,id):
        with connect(self.pki,self.port) as c:payload(exchange(c,request(20,[uid(id)])))
    def one(self,name):
        ids=self.locate(name)
        assert len(ids)==1,(name,ids)
        return ids[0]
    def inventory(self):
        rows=[]
        for id in self.locate():
            a=self.attributes(id)
            rows.append(dict(id=id,name=a.get('Name'),state=STATE.get(a.get('State')),algorithm=a.get('Cryptographic Algorithm'),length=a.get('Cryptographic Length'),group=a.get('Object Group')))
        return sorted(rows,key=lambda r:r['name'] or '')

class Lane:
    def __init__(self,root,engine,image,out):
        self.root=pathlib.Path(root);self.engine=engine;self.out=out;self.run_id=uuid.uuid4().hex[:10];(self.root/'kmip').mkdir(mode=0o700)
        self.server=ContainerServer(self.root/'kmip',engine,image,log_path=out/'kmip-server.log')
        self.server.name='keytend-mysql-kmip-'+self.run_id  # own name; never another runner's container
        self.kmip=Kmip(self.server.pki,self.server.port)
        self.data=self.root/'mysql';self.data.mkdir(mode=0o700)
        self.tls=self.root/'mysql-tls';self.tls.mkdir(mode=0o700)
        self.config=self.root/'config';self.config.mkdir(mode=0o700)
        for name in ['ca.pem','client.pem','client.key','other.pem','other.key','unlisted.pem','unlisted.key']:shutil.copy(self.server.pki/name,self.tls/name)
        self.untrusted_pki()
        (self.config/'mysqld.my').write_text(json.dumps({'components':'file://component_keyring_kmip'})+'\n')
        self.port=free_port();self.containers=[];self.steps=[];self.findings=[]
    def untrusted_pki(self):
        """A second CA, so a server CA mismatch and a client certificate from an
        untrusted issuer are both real chains, not malformed files."""
        t=self.tls;run=lambda *a:subprocess.run(a,check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        run('openssl','req','-x509','-newkey','rsa:2048','-nodes','-keyout',str(t/'wrong-ca.key'),'-out',str(t/'wrong-ca.pem'),'-days','2','-subj','/CN=keytend-kmip-server-wrong-ca','-addext','basicConstraints=critical,CA:TRUE','-addext','keyUsage=critical,keyCertSign,cRLSign')
        run('openssl','req','-new','-newkey','rsa:2048','-nodes','-keyout',str(t/'untrusted.key'),'-out',str(t/'untrusted.csr'),'-subj','/CN=client')
        (t/'untrusted.ext').write_text('basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=clientAuth\n')
        run('openssl','x509','-req','-in',str(t/'untrusted.csr'),'-CA',str(t/'wrong-ca.pem'),'-CAkey',str(t/'wrong-ca.key'),'-CAcreateserial','-out',str(t/'untrusted.pem'),'-days','2','-extfile',str(t/'untrusted.ext'))
        (t/'wrong-ca.key').unlink()
    def cnf(self,label,**over):
        c={'server_addr':'127.0.0.1','server_port':str(self.server.port),'client_ca':'/tls/client.pem','client_key':'/tls/client.key',
           'server_ca':'/tls/ca.pem','object_group':GROUP,'tls_peer_verification':True,'tls_hostname_verification':True}
        for k,v in over.items():
            if v is None:c.pop(k,None)
            else:c[k]=v
        path=self.config/f'{label}.cnf';path.write_text(json.dumps(c,indent=1)+'\n');return path,c
    def step(self,name,**detail):
        self.steps.append(dict(name=name,**detail));print('PASS' if detail.get('outcome','passed')=='passed' else 'OBSERVED',name,flush=True)
    def finding(self,kind,summary,**detail):
        self.findings.append(dict(kind=kind,summary=summary,**detail));print('FINDING',kind,summary,flush=True)
    # MySQL containers -------------------------------------------------------
    def base(self,cnf,add_hosts=()):
        args=[self.engine,'run','--network','host']
        args+=(['--userns','keep-id'] if self.engine=='podman' else [])+['--user',f'{os.getuid()}:{os.getgid()}']
        for h in add_hosts:args+=['--add-host',f'{h}:127.0.0.1']
        args+=['-e','PERCONA_TELEMETRY_DISABLE=1','--security-opt=no-new-privileges','--cap-drop=all','--memory=1g','--pids-limit=256',
               '-v',f'{self.data}:/var/lib/mysql','-v',f'{self.tls}:/tls:ro',
               '-v',f'{self.config/"mysqld.my"}:/usr/sbin/mysqld.my:ro','-v',f'{cnf}:/usr/lib64/mysql/plugin/component_keyring_kmip.cnf:ro','--entrypoint','mysqld']
        return args
    FLAGS=['--datadir=/var/lib/mysql','--bind-address=127.0.0.1','--mysqlx=OFF','--socket=/var/lib/mysql/mysql.sock','--pid-file=/var/lib/mysql/mysqld.pid',
           '--server-id=1','--log-error-verbosity=3','--percona-telemetry-disable=ON','--innodb-redo-log-encrypt=ON','--innodb-undo-log-encrypt=ON','--binlog-encryption=ON']
    def initialize(self):
        cnf,_=self.cnf('initialize')
        name=f'keytend-mysql-{self.run_id}-init';self.containers.append(name)
        r=subprocess.run(self.base(cnf)+['--name',name,MYSQL,'--initialize-insecure','--datadir=/var/lib/mysql','--log-error-verbosity=3'],stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True,timeout=300)
        (self.out/'mysql-initialize.log').write_text(r.stdout);subprocess.run([self.engine,'rm','-f',name],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        assert r.returncode==0,r.stdout[-2000:]
    def start(self,label,cnf_over=None,add_hosts=(),expect_ready=True,timeout=90):
        cnf,config=self.cnf(label,**(cnf_over or {}))
        self.name=f'keytend-mysql-{self.run_id}-{label}';self.containers.append(self.name)
        command(self.base(cnf,add_hosts)+['-d','--name',self.name,MYSQL,f'--port={self.port}',*self.FLAGS])
        until=time.monotonic()+timeout;ready=False
        while time.monotonic()<until:
            if self.sql('SELECT 1',check=False)[0]==0:ready=True;break
            if not self.running():break
            time.sleep(.5)
        observation=dict(label=label,config={k:v for k,v in config.items() if k not in ['server_port']},ready=ready,running=self.running())
        if expect_ready and not ready:raise RuntimeError(self.logs()[-4000:])
        return observation
    def running(self):
        r=subprocess.run([self.engine,'inspect','--format','{{.State.Running}}',self.name],stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,text=True)
        return r.stdout.strip()=='true'
    def logs(self):return command([self.engine,'logs',self.name])
    def stop(self):
        """Clean shutdown, so InnoDB page 0 and binary log headers are on disk."""
        if self.running():command([self.engine,'stop','--time','60',self.name])
        log=self.logs();(self.out/f'{self.name.removeprefix("keytend-mysql-"+self.run_id+"-")}.log').write_text(log)
        subprocess.run([self.engine,'rm','-f',self.name],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        return log
    def sql(self,statement,check=True):
        r=subprocess.run([self.engine,'exec',self.name,'mysql','-uroot','-S','/var/lib/mysql/mysql.sock','-NB','-e',statement],stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True,timeout=120)
        if check and r.returncode:raise RuntimeError(f'{statement}: {r.stdout}')
        return r.returncode,r.stdout.strip()
    def component_status(self):
        return dict(line.split('\t',1) for line in self.sql('SELECT STATUS_KEY,STATUS_VALUE FROM performance_schema.keyring_component_status')[1].splitlines())
    def server_uuid(self):return self.sql('SELECT @@server_uuid')[1]
    def count(self,text):return self.logs().count(text)
    def attempt(self,statement):
        """component_keyring_kmip keeps one TLS connection and does not detect
        that the server closed it (keytend-kmip-server closes connections idle for
        --idle-timeout, default 300 s; idle_lanes measures it): the first
        keyring write after an idle or restart close fails, the next reconnects.
        Retry exactly once, only for that logged cause, and record every retry."""
        before=self.count(STALE)
        rc,out=self.sql(statement,check=False)
        if rc and self.count(STALE)>before:
            rc,out=self.sql(statement,check=False)
            return rc,out,True
        return rc,out,False
    def mutate(self,statement):
        rc,out,retried=self.attempt(statement)
        if rc:raise RuntimeError(f'{statement}: {out}')
        return out,retried
    # Evidence helpers ------------------------------------------------------
    def innodb_key(self,uuid_,n):
        id=self.kmip.one(f'INNODBKey-{uuid_}-{n}');got=self.kmip.get(id);assert got['status']==0,got
        return id,got['material']
    def check_headers(self,uuid_,expected_id,files):
        """Each header opens with exactly one key: the KMIP bytes of the master
        key it names, and none of the other master keys or a random key."""
        result={};_,key=self.innodb_key(uuid_,expected_id)
        others=[self.innodb_key(uuid_,n)[1] for n in range(1,expected_id)]+[os.urandom(32)]
        for rel in files:
            h=innodb_header(self.data/rel,redo=rel.startswith('#innodb_redo'))
            assert h and h['server_uuid']==uuid_ and h['master_key_id']==expected_id,(rel,h)
            assert innodb_header_opens(h,key) and not any(innodb_header_opens(h,o) for o in others),rel
            result[rel]=dict(master_key_id=h['master_key_id'],offset=h['offset'])
        return result
    def check_binlogs(self):
        opened={}
        for path in sorted(self.data.glob('binlog.[0-9]*')):
            h=binlog_header(path);assert h,path.name
            got=self.kmip.get(self.kmip.one(h['key_id']));assert got['status']==0,got
            assert binlog_opens(h,got['material']) and not binlog_opens(h,os.urandom(32)),path.name
            opened[path.name]=h['key_id']
        return opened

def scenario(lane):
    k=lane.kmip;s=lane.server
    lane.initialize();lane.step('mysqld --initialize-insecure with component_keyring_kmip loaded over verified mTLS')
    lane.start('baseline')
    status=lane.component_status();uuid_=lane.server_uuid()
    assert status['Component_status']=='Active' and status['Tls_peer_verification']=='true' and status['Tls_hostname_verification']=='true',status
    variables=dict(l.split('\t') for l in lane.sql("SHOW GLOBAL VARIABLES WHERE Variable_name IN ('innodb_redo_log_encrypt','innodb_undo_log_encrypt','binlog_encryption')")[1].splitlines())
    assert set(variables.values())=={'ON'},variables
    lane.step('component status Active with explicit peer and hostname verification; redo, undo and binary log encryption ON',component_status={x:status[x] for x in ['Component_name','Component_status','Implementation_name','Version','Tls_peer_verification','Tls_hostname_verification','Object_group']},variables=variables)
    lane.sql(f"CREATE DATABASE q1; CREATE TABLE q1.t (id INT PRIMARY KEY, v VARCHAR(128)) ENCRYPTION='Y'; INSERT INTO q1.t VALUES (1,'{MARKER}')")
    assert lane.sql('SELECT v FROM q1.t WHERE id=1')[1]==MARKER
    assert lane.sql("SELECT ENCRYPTION FROM information_schema.INNODB_TABLESPACES WHERE NAME='q1/t'")[1]=='Y'
    key1_id,key1=lane.innodb_key(uuid_,1)
    a=k.attributes(key1_id);assert a['State']==2 and a['Cryptographic Algorithm']==3 and a['Cryptographic Length']==256 and a['Object Group']==GROUP,a
    lane.step('CREATE TABLE ... ENCRYPTION=Y created InnoDB master key 1 in keytend-kmip-server (Active AES-256, object group); insert/read',master_key=f'INNODBKey-{uuid_}-1',kmip_id=key1_id)
    # keyring_udf exposes exact key bytes through the same keyring service.
    lane.sql("INSTALL PLUGIN keyring_udf SONAME 'keyring_udf.so'; "+' '.join(f"CREATE FUNCTION {f} RETURNS {t} SONAME 'keyring_udf.so';" for f,t in [('keyring_key_store','INTEGER'),('keyring_key_fetch','STRING'),('keyring_key_remove','INTEGER'),('keyring_key_type_fetch','STRING')]))
    out,retried=lane.mutate(f"SELECT keyring_key_store('q1udf','AES','{UDF_KEY.decode()}')");assert out=='1'
    assert lane.sql("SELECT HEX(keyring_key_fetch('q1udf')), keyring_key_type_fetch('q1udf')")[1]==UDF_KEY.hex().upper()+'\tAES'
    udf_id=k.one('q1udf');got=k.get(udf_id);a=k.attributes(udf_id)
    assert got==dict(status=0,material=UDF_KEY) and a['State']==2 and a['Cryptographic Length']==256 and a['Object Group']==GROUP,(got,a)
    assert k.get(udf_id)==got
    lane.step('keyring_udf store: Register+Activate; independent KMIP Get returns the exact 32 bytes twice; typed attributes and state match',idle_retry=retried)
    out,retried=lane.mutate("SELECT keyring_key_remove('q1udf')");assert out=='1'
    refused=k.get(udf_id);a=k.attributes(udf_id)
    assert refused['status']==1 and a['State']==5 and k.locate('q1udf')==[] and k.locate('q1udf',state=5)==[udf_id],(refused,a)
    assert lane.sql("SELECT keyring_key_fetch('q1udf') IS NULL")[1]=='1'
    lane.step('keyring_udf remove: Revoke then Destroy; independent Get refused, state Destroyed, on-line Locate empty, client fetch NULL',refusal=refused,idle_retry=retried)
    before=lane.count(NOT_UNIQUE)
    rc,out,retried=lane.attempt(f"SELECT keyring_key_store('q1udf','AES','{UDF_KEY.decode()}')")
    if rc and lane.count(NOT_UNIQUE)>before:
        # --destroyed-name-reuse reserve: destroyed objects keep their Names.
        lane.finding('client-name-reuse','component_keyring_kmip reuses a Name after Revoke+Destroy; KMIP 2.1 section 6.1.15 retains a destroyed object\'s metadata and section 4.32 requires unique Names, and with --destroyed-name-reuse reserve keytend-kmip-server keeps destroyed Names reserved per owner, so storing a removed key name again fails',server_reason='Invalid Field (1.4)',affects=['keyring_udf name reuse','InnoDB DefaultMasterKey start-up probe','binary log master key rotation scratch names'])
        lane.step('re-storing a removed key name is refused by Name uniqueness (recorded client/server interaction, not a pass)',outcome='observed')
    else:
        # --destroyed-name-reuse allow (default): a Name held only by destroyed
        # objects may be given to a new object (docs/interpretations.md).
        assert rc==0 and out=='1',out
        reused=k.one('q1udf');got=k.get(reused)
        assert reused!=udf_id and got==dict(status=0,material=UDF_KEY) and k.attributes(reused)['State']==2,(reused,got)
        assert k.locate('q1udf',state=5)==[udf_id]
        assert lane.sql("SELECT HEX(keyring_key_fetch('q1udf'))")[1]==UDF_KEY.hex().upper()
        out,_=lane.mutate("SELECT keyring_key_remove('q1udf')");assert out=='1'
        assert k.locate('q1udf')==[] and sorted(k.locate('q1udf',state=5))==sorted([udf_id,reused])
        lane.step('re-storing a removed key name creates a new Active object with the exact bytes; the destroyed holder stays Destroyed; removing it again leaves both Destroyed',kmip_id=reused,idle_retry=retried)
    # Exact material at rest: InnoDB headers decrypt with the KMIP bytes.
    lane.stop();files=['q1/t.ibd','undo_001','undo_002']+sorted(str(p.relative_to(lane.data)) for p in (lane.data/'#innodb_redo').glob('#ib_redo*') if innodb_header(p,redo=True))
    headers=lane.check_headers(uuid_,1,files)
    binlogs=lane.check_binlogs()
    assert MARKER.encode() not in (lane.data/'q1/t.ibd').read_bytes()
    lane.step('at rest: table, undo and redo encryption headers decrypt only with the KMIP master-key bytes (CRC32-C); binary logs decrypt only with the KMIP replication key; marker absent from the .ibd file',innodb_headers=headers,binlogs=binlogs)
    # Restart both services; keys come back from the KMIP server.
    s.stop();s.start();lane.start('restart')
    assert lane.component_status()['Component_status']=='Active' and lane.sql('SELECT v FROM q1.t WHERE id=1')[1]==MARKER
    events=lane.sql('SHOW BINLOG EVENTS IN "binlog.000001" LIMIT 3')[1];assert 'Format_desc' in events
    log=lane.logs();assert 'Read redo log encryption metadata successful' in log
    lane.step('KMIP server and MySQL restarted: encrypted table, redo/undo metadata and encrypted binary log read with keys loaded from KMIP')
    out,retried=lane.mutate('ALTER INSTANCE ROTATE INNODB MASTER KEY')
    key2_id,key2=lane.innodb_key(uuid_,2)
    assert key2!=key1 and k.get(key1_id)==dict(status=0,material=key1) and k.attributes(key1_id)['State']==2
    assert lane.sql('SELECT v FROM q1.t WHERE id=1')[1]==MARKER
    lane.step('ALTER INSTANCE ROTATE INNODB MASTER KEY registered key 2; key 1 still Active with identical bytes; data readable',kmip_id=key2_id,idle_retry=retried)
    binlog_rotation=[]
    for _ in range(2):
        before=lane.count(NOT_UNIQUE);rc,out,retried=lane.attempt('ALTER INSTANCE ROTATE BINLOG MASTER KEY')
        binlog_rotation.append(dict(rc=rc,idle_retry=retried,error=out[-300:] if rc else None,name_reuse_refused=lane.count(NOT_UNIQUE)>before))
    if any(r['rc'] for r in binlog_rotation):
        assert all(r['name_reuse_refused'] for r in binlog_rotation if r['rc']),binlog_rotation
        lane.finding('client-binlog-rotation','ALTER INSTANCE ROTATE BINLOG MASTER KEY fails because the component re-registers scratch key names it destroyed earlier; the statement reports no effect and the previous binary log master key stays in use',attempts=binlog_rotation)
    lane.step('binary log master key rotation outcome recorded',outcome='passed' if not any(r['rc'] for r in binlog_rotation) else 'observed',attempts=binlog_rotation)
    idle_lanes(lane)
    lane.stop()
    lane.check_headers(uuid_,2,['q1/t.ibd']);binlogs=lane.check_binlogs()
    lane.step('after rotation the table header decrypts only with KMIP key 2; every binary log still decrypts with its recorded KMIP key',binlogs=binlogs)
    lane.start('rotated');assert lane.sql('SELECT v FROM q1.t WHERE id=1')[1]==MARKER
    # The component persists only the key Name on the KMIP server, not the
    # keyring owner (Auth ID), so a user key reloads without its owner.
    fetched=lane.sql("SELECT keyring_key_fetch('q1idle') IS NULL")[1]
    idle_id=k.one('q1idle')
    assert k.get(idle_id)['material']==b'q1-idle-key-material-0123456789x' and k.attributes(idle_id)['State']==2
    if fetched=='1':lane.finding('client-owner-not-persisted','keyring_udf user keys lose their owner across a restart: the key stays Active with the same bytes on the KMIP server, but keyring_key_fetch by its owner returns NULL after the component reloads it with an empty Auth ID')
    lane.stop()
    lane.step('restart after rotation reads the table; user-key ownership after reload recorded',outcome='observed' if fetched=='1' else 'passed')
    negatives(lane,uuid_)
    adverse(lane,uuid_,key2_id)
    return uuid_

IDLE_SHORT=15;IDLE_QUIET=20
def idle_lanes(lane):
    """The KMIP server's idle close against the component's single connection,
    bounded to two IDLE_QUIET-second quiet periods. The KMIP server restarts
    with a short --idle-timeout, then with the recommended --idle-timeout 0;
    the same quiet period, longer than the short
    timeout, precedes the measured keyring write each time. The rest of the
    lane keeps --idle-timeout 0."""
    k=lane.kmip;s=lane.server
    def prime(tag):
        # A KMIP server restart also leaves the component's connection stale:
        # one write (a second, new name only if the first failed) reconnects first.
        for n in (1,2):
            if lane.sql(f"SELECT keyring_key_store('q1prime-{tag}-{n}','AES','q1-prime-key-material-012345678{n}')",check=False)[0]==0:return n
        raise RuntimeError('keyring write failed twice after a KMIP server restart')
    def measured(timeout,name,material):
        s.stop();s.extra_args=['--idle-timeout',str(timeout)];s.start()
        primed=prime(f't{timeout}')
        time.sleep(IDLE_QUIET)
        before=lane.count(STALE);started=time.monotonic()
        rc1,out1=lane.sql(f"SELECT keyring_key_store('{name}','AES','{material}')",check=False)
        # Only a failed first write is repeated: storing the same key ID twice is
        # itself refused by the keyring.
        rc2,out2=lane.sql(f"SELECT keyring_key_store('{name}','AES','{material}')",check=False) if rc1 else (None,None)
        observation=dict(idle_timeout=timeout,quiet_seconds=IDLE_QUIET,prime_writes=primed,first_rc=rc1,first=out1[-200:],
                         first_seconds=round(time.monotonic()-started,3),second_rc=rc2,second=out2,logged_io_failure=lane.count(STALE)>before)
        assert (rc2==0 and out2=='1' if rc1 else out1=='1') and k.get(k.one(name))['material']==material.encode(),observation
        return observation
    short=measured(IDLE_SHORT,'q1idle-short','q1-idle-short-material-012345678')
    if short['first_rc']:lane.finding('client-stale-connection',f'after keytend-kmip-server closes an idle connection (--idle-timeout {IDLE_SHORT}, {IDLE_QUIET} s quiet), the first keyring write fails with an I/O error and the statement fails; the next statement reconnects',observation=short)
    lane.step(f'--idle-timeout {IDLE_SHORT}: keyring write after {IDLE_QUIET} s quiet recorded; next write succeeds with exact bytes',outcome='observed' if short['first_rc'] else 'passed',observation=short)
    recommended=measured(0,'q1idle','q1-idle-key-material-0123456789x')
    assert recommended['first_rc']==0 and not recommended['logged_io_failure'],recommended
    lane.step(f'--idle-timeout 0 (recommended for this client): the first keyring write after {IDLE_QUIET} s quiet, longer than the {IDLE_SHORT} s that closed the connection before, succeeds with exact bytes and no reconnect',observation=recommended)

def refused_start(lane,label,over,add_hosts=(),expect=()):
    """Start with a changed keyring configuration and record exactly what MySQL
    does; every expected log fragment must be present."""
    obs=lane.start(label,over,add_hosts=add_hosts,expect_ready=False)
    if obs['ready']:
        obs['component_status']=lane.component_status().get('Component_status')
        rc,out=lane.sql('SELECT v FROM q1.t WHERE id=1',check=False);obs['table_read']=dict(rc=rc,output=out[-300:])
    log=lane.stop()
    obs['log_evidence']=[x for x in expect if x in log]
    obs['component_errors']=sorted({line.split("reported: ")[-1][:300] for line in log.splitlines() if 'component_keyring_kmip reported' in line and ('ERROR' in line or 'Can not connect' in line)})[:6]
    obs['innodb_errors']=sorted({line.split('[InnoDB] ')[-1][:200] for line in log.splitlines() if '[ERROR]' in line and '[InnoDB]' in line})[:6]
    assert obs['log_evidence']==list(expect),(label,obs)
    return obs

def refused(obs):
    """With redo/undo encryption on, InnoDB needs the master key to start: mysqld
    must exit instead of serving the encrypted data (or any data) without it."""
    return not obs['ready'] and not obs['running']

def negatives(lane,uuid_):
    k=lane.kmip
    verify_failed='certificate verify failed'
    keyring_failed='Check keyring fail, please check the keyring is loaded.'
    redo_failed='Cannot read the encryption information in log file header'
    cases=[
        ('wrong-server-ca',dict(server_ca='/tls/wrong-ca.pem'),(),[verify_failed,keyring_failed]),
        # Same CA as the passing control below; only the requested name differs.
        ('wrong-hostname',dict(server_addr='wrong-kmip.test'),('wrong-kmip.test',),[verify_failed,keyring_failed]),
        ('unlisted-client',dict(client_ca='/tls/unlisted.pem',client_key='/tls/unlisted.key'),(),['Operation denied by certificate policy Operation: Query','Permission Denied',keyring_failed]),
        ('untrusted-client',dict(client_ca='/tls/untrusted.pem',client_key='/tls/untrusted.key'),(),[STALE,keyring_failed]),
        # CA-valid principal in the policy without Register and without access
        # to the database principal's objects (dev-pki.sh "other-tenant").
        ('other-principal',dict(client_ca='/tls/other.pem',client_key='/tls/other.key'),(),['Operation denied by certificate policy Operation: Register',redo_failed]),
    ]
    for label,over,hosts,expect in cases:
        obs=refused_start(lane,label,over,hosts,expect)
        assert refused(obs),(label,obs)
        lane.step(f'negative {label}: mysqld refuses to start; no data served without the KMIP key',observation=obs)
    # The untrusted client's EOF is a server-side TLS refusal: confirm it directly.
    try:
        with connect(lane.tls,lane.server.port,identity='untrusted') as c:exchange(c,request(24,[enumeration(0x420074,1)]))
    except (OSError,EOFError) as error:untrusted=type(error).__name__
    else:raise AssertionError('server accepted a client certificate from an untrusted CA')
    lane.step('independent probe: the server refuses the untrusted-CA client certificate during TLS',error=untrusted)
    obs=refused_start(lane,'dns-name-control',dict(server_addr='keytend-kmip-server'),('keytend-kmip-server',))
    assert obs['ready'] and obs['component_status']=='Active' and obs['table_read']['rc']==0,obs
    lane.step('control: a DNS name in the server certificate SAN with hostname verification succeeds')
    obs=refused_start(lane,'insecure-default',dict(server_ca='/tls/wrong-ca.pem',tls_peer_verification=None,tls_hostname_verification=None))
    assert obs['ready'] and obs['component_status']=='Active' and obs['table_read']['rc']==0,obs
    lane.finding('client-insecure-default','component_keyring_kmip 8.4.11 defaults tls_peer_verification and tls_hostname_verification to false: with an unrelated server_ca configured it connected, loaded keys and opened encrypted tables. Qualified use requires both options set to true.',observation=obs)
    lane.step('defaults without explicit verification accept a server outside the configured CA (insecure default recorded)',outcome='observed',observation=obs)
    lane.server.stop()
    obs=refused_start(lane,'kmip-outage',{},(),['Connection refused',keyring_failed])
    assert refused(obs),obs
    lane.step('KMIP server unavailable at MySQL start: mysqld refuses to start',observation=obs)
    lane.server.start()
    lane.start('recovered');assert lane.component_status()['Component_status']=='Active' and lane.sql('SELECT v FROM q1.t WHERE id=1')[1]==MARKER;lane.stop()
    lane.step('after every negative and the outage, the verified configuration reads the table again')
    assert all(r['state']=='Active' for r in k.inventory() if r['name'] and r['name'].startswith('INNODBKey-'))

def adverse(lane,uuid_,key2_id):
    k=lane.kmip
    k.revoke(key2_id,2)  # Key Compromise
    assert k.attributes(key2_id)['State']==4
    lane.start('compromised-key');compromised=dict(status=lane.component_status()['Component_status'],read=lane.sql('SELECT v FROM q1.t WHERE id=1',check=False))
    if compromised['read'][0]==0:
        lane.finding('client-ignores-key-state','component_keyring_kmip loads and uses a master key the KMIP server reports as Compromised (KMIP 1.4 section 3.22: a Compromised object must not be used to apply cryptographic protection); MySQL kept reading and writing with it. Compromise response must be an operator rotation, not KMIP revocation alone.',observation=compromised)
    out,retried=lane.mutate('ALTER INSTANCE ROTATE INNODB MASTER KEY')
    key3_id,key3=lane.innodb_key(uuid_,3)
    assert lane.sql('SELECT v FROM q1.t WHERE id=1')[1]==MARKER;lane.stop()
    lane.check_headers(uuid_,3,['q1/t.ibd'])
    lane.step('revoked (Compromised) master key: MySQL behaviour recorded; operator rotation moves the table to key 3',outcome='observed' if compromised['read'][0]==0 else 'passed',observation=compromised,idle_retry=retried)
    # Destroy the current master key: the data must become unavailable.
    k.revoke(key3_id,6);k.destroy(key3_id)
    assert k.attributes(key3_id)['State']==5 and k.get(key3_id)['status']==1
    obs=refused_start(lane,'destroyed-key',{},(),['Cannot read the encryption information in log file header'])
    assert refused(obs),obs
    lane.step('destroyed current master key: mysqld refuses to start; the encrypted data is unrecoverable (expected for this fixture)',observation=obs)

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--engine',default='podman');p.add_argument('--image',required=True);p.add_argument('--output',type=pathlib.Path,default=OUT)
    a=p.parse_args();out=a.output.resolve();out.mkdir(parents=True,exist_ok=True)
    binary=native_sha256(a.image);evidence=packaged_evidence(local_image_id(a.engine,a.image))
    subprocess.run([a.engine,'pull','--quiet',MYSQL],check=True,stdout=subprocess.DEVNULL)
    mysql_config=local_image_id(a.engine,MYSQL)
    identity=command([a.engine,'run','--rm','--entrypoint','bash',MYSQL,'-c',f'sha256sum {COMPONENT} /usr/sbin/mysqld; mysqld --version; rpm -q percona-server-server'])
    report=dict(status='running',started_at=datetime.datetime.now(datetime.timezone.utc).isoformat(),client='Percona Server for MySQL component_keyring_kmip',
        database_image=MYSQL,database_image_config_id=mysql_config,client_identity=identity.splitlines(),server_image=a.image,
        runtime_binary_sha256=binary,**evidence,kmip_wire_version='1.4 (component default)',
        limits='Single host, one MySQL instance, InnoDB/binlog/redo/undo encryption only. No replication, Group Replication, backup (xtrabyte) or upgrade qualification. The server uses the development PKI and policy generated at test time. No full-spec or production approval.')
    path=out/'report.json';path.write_text(json.dumps(report,indent=2)+'\n')
    lane=None
    try:
        with tempfile.TemporaryDirectory(prefix='keytend-mysql-') as d:
            lane=Lane(d,a.engine,a.image,out)
            try:
                lane.server.start()
                report['server_uuid']=scenario(lane)
                report['kmip_inventory']=lane.kmip.inventory() if lane.server.container_exists() else None
            finally:
                for name in lane.containers:subprocess.run([a.engine,'rm','-f',name],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
                lane.server.stop()
        report['status']='passed_with_findings' if lane.findings else 'passed'
    except BaseException as error:
        report.update(status='failed',error_type=type(error).__name__,error=(getattr(error,'output',None) or str(error))[-4000:])
        raise
    finally:
        if lane:report.update(steps=lane.steps,findings=lane.findings)
        report['finished_at']=datetime.datetime.now(datetime.timezone.utc).isoformat()
        report['log_sha256']={p.name:sha(p) for p in sorted(out.glob('*.log'))}
        path.write_text(json.dumps(report,indent=2)+'\n')
    print('PASS Percona Server for MySQL keyring_kmip lane:',len(lane.steps),'steps,',len(lane.findings),'recorded findings')

if __name__=='__main__':main()
