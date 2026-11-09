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

"""Disposable TLS/authenticated Percona replica-set qualification.
Local host-network smoke evidence, never production HA or durability approval.
"""
import argparse
import base64
import json
import os
import pathlib
import secrets
import shutil
import subprocess
import tempfile
import time
import uuid

from image_evidence import ROOT, local_image_id, packaged_evidence
from test_database import ContainerServer, PERCONA
from test_runtime import free_port
from wire import key_value, get, payload, exchange, request, uid, enumeration, structure

OUT = ROOT / 'artifacts/database-replicaset'
USER = 'qualification-admin'
MARKER = 'KEYTEND_RESULT:'


def command(args, **kwargs):
    return subprocess.check_output(args, text=True, stderr=subprocess.STDOUT, timeout=45, **kwargs)


class ReplicaSet:
    def __init__(self, root, engine, image):
        self.root = pathlib.Path(root)
        self.engine = engine
        self.server = ContainerServer(root, engine, image)
        self.tls = self.root / 'database-tls'
        self.tls.mkdir(mode=0o700)
        for name in ['ca.pem', 'client.pem']:
            shutil.copyfile(self.server.pki / name, self.tls / name)
        with (self.tls / 'client.pem').open('ab') as file:
            file.write((self.server.pki / 'client.key').read_bytes())
        # All members require TLS for clients and replication. The disposable
        # certificate supports server and client usage for intra-cluster TLS.
        ext = self.tls / 'mongod.ext'
        ext.write_text('basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth,clientAuth\nsubjectAltName=DNS:localhost,IP:127.0.0.1\n')
        command(['openssl', 'req', '-new', '-newkey', 'rsa:2048', '-nodes', '-keyout', str(self.tls/'mongod.key'), '-out', str(self.tls/'mongod.csr'), '-subj', '/CN=localhost/O=keytend-kmip-server-qualification'])
        command(['openssl', 'x509', '-req', '-in', str(self.tls/'mongod.csr'), '-CA', str(self.server.pki/'ca.pem'), '-CAkey', str(self.server.pki/'ca.key'), '-CAcreateserial', '-out', str(self.tls/'mongod.pem'), '-days', '7', '-extfile', str(ext)])
        with (self.tls/'mongod.pem').open('ab') as file:
            file.write((self.tls/'mongod.key').read_bytes())
        (self.tls/'replication.key').write_text(base64.b64encode(secrets.token_bytes(512)).decode())
        (self.tls/'admin-password').write_text(secrets.token_urlsafe(40))
        for file in self.tls.iterdir():
            file.chmod(0o600)
        self.ports = self.allocate_ports()
        assert len(set(self.ports)) == 3
        token = uuid.uuid4().hex[:12]
        self.names = ['keytend-repl-'+token+'-'+str(i) for i in range(3)]
        self.directories = [self.root/('member-'+str(i)) for i in range(3)]
        for directory in self.directories:
            directory.mkdir(mode=0o700)

    def allocate_ports(self):
        return [free_port() for _ in range(3)]

    def base(self, member):
        identity = ['--userns', 'keep-id'] if self.engine == 'podman' else []
        return [self.engine, 'run', '--network', 'host', *identity, '--user', f'{os.getuid()}:{os.getgid()}', '--entrypoint', 'mongod', '-e', 'HOME=/tmp', '-e', 'PERCONA_TELEMETRY_DISABLE=1', '-v', f'{self.tls}:/tls:ro', '-v', f'{self.directories[member]}:/data/db']

    def flags(self, member):
        return ['--bind_ip', '127.0.0.1', '--port', str(self.ports[member]), '--dbpath', '/data/db', '--replSet', 'qualification', '--keyFile', '/tls/replication.key', '--tlsMode', 'requireTLS', '--tlsCertificateKeyFile', '/tls/mongod.pem', '--tlsCAFile', '/tls/ca.pem', '--enableEncryption', '--kmipServerName', '127.0.0.1', '--kmipPort', str(self.server.port), '--kmipServerCAFile', '/tls/ca.pem', '--kmipClientCertificateFile', '/tls/client.pem', '--kmipKeyStatePollingSeconds', '2', '--kmipConnectRetries', '0', '--kmipConnectTimeoutMS', '1000']

    def exists(self, member):
        if self.engine == 'podman':
            result = subprocess.run([self.engine, 'container', 'exists', self.names[member]], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=15)
            if result.returncode not in [0, 1]:
                result.check_returncode()
            return result.returncode == 0
        return self.names[member] in command([self.engine,'container','ls','--all','--format','{{.Names}}']).splitlines()

    def start(self, member):
        if self.exists(member):
            command([self.engine, 'start', self.names[member]])
        else:
            command(self.base(member)+['-d', '--name', self.names[member], PERCONA]+self.flags(member))

    def stop(self, member, crash=False):
        command([self.engine, 'kill', '--signal', 'KILL', self.names[member]] if crash else [self.engine, 'stop', '--time', '30', self.names[member]])

    def inspect(self, member):
        return json.loads(command([self.engine, 'inspect', self.names[member]]))[0]

    def shell(self, member, expression, auth=True, tls=True):
        # Credentials are read inside the disposable container. They never
        # appear in arguments, reports, logs, Git or JavaScript error text.
        args = [self.engine, 'exec', '-i', '-e', 'HOME=/tmp', self.names[member], 'mongosh', '--quiet', '--norc', '--host', '127.0.0.1', '--port', str(self.ports[member])]
        if tls:
            args += ['--tls', '--tlsCAFile', '/tls/ca.pem', '--tlsCertificateKeyFile', '/tls/client.pem']
        args += ['--file', '/dev/stdin']
        login = "db.getSiblingDB('admin').auth({user:"+json.dumps(USER)+",pwd:require('fs').readFileSync('/tls/admin-password','utf8')});" if auth else ''
        script = login+'\nconst result=('+expression+");print('"+MARKER+"'+JSON.stringify(result));\n"
        output = command(args, input=script)
        values = [line[len(MARKER):] for line in output.splitlines() if line.startswith(MARKER)]
        if len(values) != 1:
            raise AssertionError('MongoDB shell did not return exactly one structured result')
        return json.loads(values[0])

    def eventually(self, action, timeout=45):
        until = time.monotonic()+timeout
        last = None
        while time.monotonic() < until:
            try:
                value = action()
                if value is not None:
                    return value
            except (subprocess.CalledProcessError, AssertionError) as error:
                last = type(error).__name__
            time.sleep(.25)
        raise AssertionError('Replica-set condition timed out; last failure type: '+str(last))

    def primary(self, auth=True):
        def find():
            for member in range(3):
                if not self.inspect(member)['State']['Running']:
                    continue
                try:
                    if self.shell(member, "db.adminCommand({hello:1}).isWritablePrimary", auth=auth):
                        return member
                except subprocess.CalledProcessError:
                    pass
            return None
        return self.eventually(find)

    def ready(self, member):
        return self.eventually(lambda: self.shell(member, 'db.adminCommand({ping:1}).ok'))

    def proof(self, member, identifier):
        expression = "(()=>{db.getMongo().setReadPref('secondaryPreferred');const d=db.getSiblingDB('qualification').proof.findOne({_id:"+json.dumps(identifier)+"});return d&&d.value==='durable encrypted replica payload';})()"
        def check():
            return True if self.shell(member, expression) is True else None
        return self.eventually(check)

    def write(self, primary, identifier):
        value = self.shell(primary, "db.getSiblingDB('qualification').proof.insertOne({_id:"+json.dumps(identifier)+",value:'durable encrypted replica payload'},{writeConcern:{w:'majority',j:true,wtimeout:15000}}).acknowledged")
        assert value is True

    def key_id(self, member):
        state = self.shell(member, 'db.serverStatus().encryptionAtRest')
        assert state['encryptionEnabled'] is True
        return state['encryptionKeyId']['kmip']['keyId']

    def cleanup(self):
        for member, name in enumerate(self.names):
            if self.exists(member):
                try:
                    (OUT/('member-'+str(member)+'.log')).write_text(command([self.engine, 'logs', name]))
                finally:
                    subprocess.run([self.engine, 'rm', '-f', name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=45)
        self.server.stop()


def run(fixture, report):
    def passed(description):
        report['passed'].append(description)
        (OUT/'image.json').write_text(json.dumps(report,indent=2)+'\n')
        print('PASS', description, flush=True)

    fixture.server.start()
    for member in range(3):
        fixture.start(member)
    fixture.eventually(lambda: fixture.shell(0, 'db.adminCommand({ping:1}).ok', auth=False))
    config = {'_id':'qualification', 'members':[{'_id':member,'host':'localhost:'+str(port)} for member,port in enumerate(fixture.ports)], 'settings':{'electionTimeoutMillis':2000}}
    assert fixture.shell(0, 'rs.initiate('+json.dumps(config)+').ok', auth=False) == 1
    primary = fixture.primary(auth=False)
    assert fixture.shell(primary, "db.getSiblingDB('admin').runCommand({createUser:"+json.dumps(USER)+",pwd:require('fs').readFileSync('/tls/admin-password','utf8'),roles:[{role:'root',db:'admin'}],writeConcern:{w:'majority',wtimeout:15000}}).ok", auth=False) == 1
    for member in range(3):
        fixture.ready(member)
    builds=[fixture.shell(member,'(()=>{const b=db.adminCommand({buildInfo:1});return {version:b.version,gitVersion:b.gitVersion};})()') for member in range(3)]
    assert all(build==builds[0] for build in builds) and builds[0]['version'].startswith('8.0.34')
    database_config=local_image_id(fixture.engine,PERCONA)
    assert all(fixture.inspect(member)['Image'].removeprefix('sha256:')==database_config for member in range(3))
    report.update(database_build=builds[0],database_image_config_id=database_config)
    connection = fixture.shell(primary, 'db.runCommand({connectionStatus:1}).authInfo.authenticatedUsers')
    assert connection == [{'user':USER,'db':'admin'}]
    unauthorized = fixture.shell(primary, "(()=>{try{db.getSiblingDB('qualification').proof.findOne({});return 0;}catch(e){return e.code;}})()", auth=False)
    assert unauthorized == 13
    try:
        fixture.shell(primary, 'db.adminCommand({ping:1}).ok', auth=False, tls=False)
    except subprocess.CalledProcessError:
        pass
    else:
        raise AssertionError('Database accepted an unencrypted connection')
    passed('three-member replica set requires database TLS, keyfile cluster authentication and authenticated data access; plaintext transport and unauthenticated reads refused')

    fixture.write(primary, 'before-failover')
    for member in range(3):
        fixture.proof(member, 'before-failover')
    initial_ids = [fixture.key_id(member) for member in range(3)]
    assert len(set(initial_ids)) == 3
    def key_state(client,identifier):
        return get(get(payload(exchange(client,request(11,[uid(identifier),enumeration(0x42013b,0x42008d)],(2,1)))),0x420125),0x42008d)[2]
    with fixture.server.connect() as client:
        assert all(key_state(client,identifier)==2 for identifier in initial_ids)
        initial_material = {identifier:key_value(client,identifier) for identifier in initial_ids}
    passed('all three members use distinct active KMIP keys and retain the same majority/journaled encrypted application data')

    started = time.monotonic()
    fixture.stop(primary, crash=True)
    next_primary = fixture.primary()
    assert next_primary != primary
    fixture.write(next_primary, 'after-failover')
    report['observed_failover_seconds'] = round(time.monotonic()-started,3)
    fixture.proof(next_primary, 'before-failover')
    fixture.start(primary)
    fixture.ready(primary)
    fixture.proof(primary, 'after-failover')
    assert fixture.key_id(primary) == initial_ids[primary]
    passed('SIGKILL of the primary preserves acknowledged data; surviving members elect a primary, accept a new majority write, and the restarted member catches up using its original KMIP key')

    fixture.stop(primary)
    rotation = command(fixture.base(primary)+['--rm', PERCONA]+fixture.flags(primary)+['--kmipRotateMasterKey'])
    (OUT/'rotation.log').write_text(rotation)
    fixture.start(primary)
    fixture.ready(primary)
    current_ids = [fixture.key_id(member) for member in range(3)]
    assert current_ids[primary] != initial_ids[primary]
    assert all(current_ids[member] == initial_ids[member] for member in range(3) if member != primary)
    with fixture.server.connect() as client:
        assert key_value(client,initial_ids[primary]) == initial_material[initial_ids[primary]]
        assert key_value(client,current_ids[primary]) != initial_material[initial_ids[primary]]
    for member in range(3):
        fixture.proof(member, 'before-failover')
        fixture.proof(member, 'after-failover')
    passed('stopped member master-key rotation creates a new KMIP key, retains the old key bytes, and rejoins with both acknowledged records intact')

    for member in range(3):
        fixture.stop(member)
    fixture.server.stop()
    fixture.server.backup()
    restored = fixture.root/'restored-kmip'
    restored.mkdir(mode=0o700)
    shutil.copyfile(fixture.server.data/'backup.sqlite',restored/'kmip.sqlite')
    (restored/'kmip.sqlite').chmod(0o600)
    fixture.server.data = restored
    fixture.start(primary)
    def refused():
        state=fixture.inspect(primary)['State']
        return state if not state['Running'] else None
    failed=fixture.eventually(refused,timeout=20)
    assert failed['ExitCode'] != 0
    (OUT/'kmip-unavailable-member.log').write_text(command([fixture.engine,'logs',fixture.names[primary]]))
    passed('encrypted member cannot cold-start while KMIP is unavailable; no cached key permits serving encrypted data')

    fixture.server.start()
    for member in range(3):
        fixture.start(member)
        fixture.ready(member)
    fixture.primary()
    for member in range(3):
        assert fixture.key_id(member) == current_ids[member]
        fixture.proof(member, 'before-failover')
        fixture.proof(member, 'after-failover')
    with fixture.server.connect() as client:
        assert key_value(client,initial_ids[primary]) == initial_material[initial_ids[primary]]
    passed('all members recover from cold restart after clean encrypted KMIP backup restore, retaining member key IDs, historical key bytes and both majority-acknowledged records')
    with fixture.server.connect() as client:
        assert all(key_state(client,identifier)==2 for identifier in current_ids)
        payload(exchange(client,request(19,[uid(current_ids[primary]),structure(0x420081,enumeration(0x420082,2))])))
        assert key_state(client,current_ids[primary])==4
    stopped=fixture.eventually(refused,timeout=20)
    assert stopped['ExitCode'] != 0
    logs=command([fixture.engine,'logs',fixture.names[primary]])
    assert 'not in the active state' in logs.lower() and current_ids[primary] in logs and 'Compromised' in logs
    survivors=[member for member in range(3) if member != primary]
    assert all(fixture.inspect(member)['State']['Running'] for member in survivors)
    survivor_primary=fixture.primary()
    assert survivor_primary in survivors
    fixture.write(survivor_primary,'after-compromise')
    for member in survivors:
        fixture.proof(member,'after-compromise')
        fixture.proof(member,'before-failover')
        fixture.proof(member,'after-failover')
    with fixture.server.connect() as client:
        assert all(key_state(client,current_ids[member])==2 for member in survivors)
    passed('compromise polling stops only the affected member; the other two retain active keys, elect a primary and accept a majority/journaled write with prior data intact')
    report.update(initial_key_ids=initial_ids,current_key_ids=current_ids,rotated_member=primary,compromised_member=primary)



def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--engine',default='podman',choices=['podman','docker'])
    parser.add_argument('--image',required=True)
    args=parser.parse_args()
    OUT.mkdir(parents=True,exist_ok=True)
    evidence=packaged_evidence(local_image_id(args.engine,args.image))
    report=dict(status='running',**evidence,database_image=PERCONA,server_image=args.image,members=3,passed=[],limits='Disposable single-host host-network replica set; no production failure domains, CSI/CNI, availability or durability SLO qualification, database backup/PITR, network partitions, ongoing KMIP outages or security review.')
    path=OUT/'image.json'
    path.write_text(json.dumps(report,indent=2)+'\n')
    try:
        with tempfile.TemporaryDirectory(prefix='keytend-percona-replicaset-') as directory:
            fixture=ReplicaSet(directory,args.engine,args.image)
            try:
                run(fixture,report)
            finally:
                fixture.cleanup()
        report['status']='passed'
    except BaseException as error:
        report['status']='failed'
        report['error_type']=type(error).__name__
        if isinstance(error,subprocess.CalledProcessError):
            # Args contain paths and public CLI flags; credentials stay in files.
            report['command']=error.cmd
            report['command_output']=error.output
        else:
            report['error']=str(error)
        raise
    finally:
        path.write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps(report['passed']))

if __name__=='__main__':
    main()
