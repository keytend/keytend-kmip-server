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

"""Observe bounded live KMIP outages and delayed revocation in a Percona replica set.
Loopback TLS byte relays inject failures without decrypting or recording traffic.
This is single-host diagnostic/qualification evidence, not an availability SLO.
"""
import argparse
import hashlib
import json
import pathlib
import select
import socket
import subprocess
import tempfile
import threading
import time

from image_evidence import ROOT, local_image_id, packaged_evidence
from test_database import PERCONA
from test_database_replicaset import ReplicaSet, USER, command
from wire import *

OUT=ROOT/'artifacts/database-outage'


def sha(path):
    with pathlib.Path(path).open('rb') as file:
        return hashlib.file_digest(file,'sha256').hexdigest()


class Relay:
    """Bounded disposable TCP relay. All KMIP authentication stays end-to-end TLS."""
    def __init__(self, target):
        self.target=target
        self.listener=socket.socket()
        self.listener.bind(('127.0.0.1',0));self.listener.listen(16);self.listener.settimeout(.2)
        self.port=self.listener.getsockname()[1]
        self.lock=threading.Lock();self.active=set();self.workers=[]
        self.slots=threading.BoundedSemaphore(16);self.stopped=threading.Event();self.mode='pass'
        self.counts={'connections':0,'stalled':0,'refused':0,'upstream_failures':0,'forwarded':0}
        self.thread=threading.Thread(target=self.accept,daemon=True);self.thread.start()

    def snapshot(self):
        with self.lock:return dict(self.counts)

    def change(self, mode):
        assert mode in ['pass','stall','refuse']
        with self.lock:
            self.mode=mode
            for connection in self.active:
                try:connection.shutdown(socket.SHUT_RDWR)
                except OSError:pass

    def accept(self):
        while not self.stopped.is_set():
            try:client,_=self.listener.accept()
            except socket.timeout:continue
            except OSError:break
            if not self.slots.acquire(blocking=False):client.close();continue
            worker=threading.Thread(target=self.forward,args=(client,),daemon=True)
            self.workers.append(worker);worker.start()

    def forward(self, client):
        upstream=None
        try:
            with self.lock:
                self.active.add(client);self.counts['connections']+=1;mode=self.mode
                if mode!='pass':self.counts['stalled' if mode=='stall' else 'refused']+=1
            if mode=='refuse':return
            if mode=='stall':self.stopped.wait(2.5);return
            try:upstream=socket.create_connection(('127.0.0.1',self.target),timeout=1)
            except OSError:
                with self.lock:self.counts['upstream_failures']+=1
                return
            with self.lock:
                self.active.add(upstream);self.counts['forwarded']+=1
            client.settimeout(1);upstream.settimeout(1)
            while not self.stopped.is_set():
                with self.lock:
                    if self.mode!='pass':return
                readable,_,_=select.select([client,upstream],[],[],.2)
                for source in readable:
                    data=source.recv(65536)
                    if not data:return
                    (upstream if source is client else client).sendall(data)
        except OSError:
            pass
        finally:
            with self.lock:
                self.active.discard(client)
                if upstream is not None:self.active.discard(upstream)
            client.close()
            if upstream is not None:upstream.close()
            self.slots.release()

    def close(self):
        self.stopped.set();self.change('refuse');self.listener.close();self.thread.join(timeout=3)
        for worker in self.workers:worker.join(timeout=3)
        assert not self.thread.is_alive() and not any(worker.is_alive() for worker in self.workers)


class OutageSet(ReplicaSet):
    def __init__(self, *args):
        super().__init__(*args)
        self.relays=[Relay(self.server.port) for _ in range(3)]

    def flags(self, member):
        flags=super().flags(member)
        flags[flags.index('--kmipPort')+1]=str(self.relays[member].port)
        return flags

    def cleanup(self):
        try:
            for member,name in enumerate(self.names):
                if self.exists(member):
                    try:(OUT/('member-'+str(member)+'.log')).write_text(command([self.engine,'logs',name]))
                    finally:subprocess.run([self.engine,'rm','-f',name],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=45)
            self.server.stop()
        finally:
            for relay in self.relays:relay.close()


def key_state(fixture, identifier):
    with fixture.server.connect() as client:
        return get(get(payload(exchange(client,request(11,[uid(identifier),enumeration(0x42013b,0x42008d)],(2,1)))),0x420125),0x42008d)[2]


def healthy_for(fixture, members, seconds, relay_counter=None):
    start=time.monotonic()
    while time.monotonic()-start<seconds:
        assert all(fixture.inspect(member)['State']['Running'] for member in members), 'Loaded database exited during KMIP communication failure'
        time.sleep(.2)
    if relay_counter is not None:assert relay_counter()>=2,'Expected repeated KMIP attempts were not observed'
    return round(time.monotonic()-start,3)


def run(fixture, report):
    def passed(description):
        report['passed'].append(description)
        (OUT/'image.json').write_text(json.dumps(report,indent=2)+'\n')
        print('PASS',description,flush=True)

    fixture.server.start()
    for member in range(3):fixture.start(member)
    fixture.eventually(lambda:fixture.shell(0,'db.adminCommand({ping:1}).ok',auth=False))
    config={'_id':'qualification','members':[{'_id':member,'host':'localhost:'+str(port)} for member,port in enumerate(fixture.ports)],'settings':{'electionTimeoutMillis':2000}}
    assert fixture.shell(0,'rs.initiate('+json.dumps(config)+').ok',auth=False)==1
    primary=fixture.primary(auth=False)
    assert fixture.shell(primary,"db.getSiblingDB('admin').runCommand({createUser:"+json.dumps(USER)+",pwd:require('fs').readFileSync('/tls/admin-password','utf8'),roles:[{role:'root',db:'admin'}],writeConcern:{w:'majority',wtimeout:15000}}).ok",auth=False)==1
    for member in range(3):fixture.ready(member)
    builds=[fixture.shell(member,'(()=>{const b=db.adminCommand({buildInfo:1});return {version:b.version,gitVersion:b.gitVersion};})()') for member in range(3)]
    assert all(build==builds[0] for build in builds) and builds[0]['version'].startswith('8.0.34')
    config_id=local_image_id(fixture.engine,PERCONA)
    assert all(fixture.inspect(member)['Image'].removeprefix('sha256:')==config_id for member in range(3))
    identifiers=[fixture.key_id(member) for member in range(3)]
    assert len(set(identifiers))==3 and all(key_state(fixture,identifier)==2 for identifier in identifiers)
    with fixture.server.connect() as client:material={identifier:key_value(client,identifier) for identifier in identifiers}
    fixture.write(primary,'before-isolation')
    for member in range(3):fixture.proof(member,'before-isolation')
    report.update(database_build=builds[0],database_image_config_id=config_id,member_key_ids=identifiers)
    passed('three authenticated TLS replica-set members use distinct active KMIP keys through independent end-to-end TLS relays and retain majority/journaled data')

    isolated=next(member for member in range(3) if member!=primary)
    relay=fixture.relays[isolated];relay.change('stall')
    duration=healthy_for(fixture,range(3),6,lambda:relay.snapshot()['stalled'])
    fixture.write(fixture.primary(),'during-isolation')
    fixture.proof(isolated,'during-isolation')
    assert fixture.key_id(isolated)==identifiers[isolated]
    report.update(isolated_member=isolated,blackhole_observation_seconds=duration,blackhole_relay_counts=relay.snapshot())
    passed('repeated blackholed KMIP attempts do not stop the already-open encrypted member; it retains its key ID and applies a new majority/journaled write')

    with fixture.server.connect() as client:
        payload(exchange(client,request(19,[uid(identifiers[isolated]),structure(0x420081,enumeration(0x420082,2))])))
        assert key_value(client,identifiers[isolated])==material[identifiers[isolated]]
    assert key_state(fixture,identifiers[isolated])==4
    before=relay.snapshot()['stalled']
    duration=healthy_for(fixture,[isolated],6,lambda:relay.snapshot()['stalled']-before)
    fixture.proof(isolated,'before-isolation')
    fixture.proof(isolated,'during-isolation')
    report['compromised_but_unreachable_observation_seconds']=duration
    report['security_finding']='Percona continues serving already-open encrypted data while the compromised key state is unreachable. Revocation enforcement is delayed until successful polling; no fail-closed communication-failure claim.'
    passed('server reports Compromised and retains historical bytes, while the isolated database still serves encrypted data through repeated failed polls; delayed enforcement is explicitly observed')

    healed=time.monotonic();relay.change('pass')
    def stopped():
        state=fixture.inspect(isolated)['State']
        return state if not state['Running'] else None
    state=fixture.eventually(stopped,timeout=25)
    assert state['ExitCode']!=0
    logs=command([fixture.engine,'logs',fixture.names[isolated]])
    assert 'not in the active state' in logs.lower() and 'Compromised' in logs and identifiers[isolated] in logs
    report['heal_to_compromised_exit_observed_seconds']=round(time.monotonic()-healed,3)
    survivors=[member for member in range(3) if member!=isolated]
    fixture.write(fixture.primary(),'after-heal')
    for member in survivors:fixture.proof(member,'after-heal')
    passed('restoring KMIP connectivity makes the compromised member shut down automatically; the surviving majority retains data and accepts journaled writes')

    snapshots=[r.snapshot()['upstream_failures'] for r in fixture.relays]
    fixture.server.stop()
    duration=healthy_for(fixture,survivors,6,lambda:min(fixture.relays[member].snapshot()['upstream_failures']-snapshots[member] for member in survivors))
    fixture.write(fixture.primary(),'during-server-outage')
    for member in survivors:fixture.proof(member,'during-server-outage')
    report['live_server_outage_observation_seconds']=duration
    passed('both already-open surviving members keep serving and commit a majority/journaled write during repeated KMIP server connection failures')

    fixture.server.start()
    assert key_state(fixture,identifiers[isolated])==4
    for member in survivors:
        assert fixture.key_id(member)==identifiers[member] and key_state(fixture,identifiers[member])==2
        with fixture.server.connect() as client:assert key_value(client,identifiers[member])==material[identifiers[member]]
    fixture.start(isolated)
    state=fixture.eventually(stopped,timeout=20)
    assert state['ExitCode']!=0
    fixture.write(fixture.primary(),'after-server-restart')
    for member in survivors:
        for identifier in ['before-isolation','during-isolation','after-heal','during-server-outage','after-server-restart']:fixture.proof(member,identifier)
    report['relay_counts']=[relay.snapshot() for relay in fixture.relays]
    passed('KMIP restart retains exact active keys and the compromised state; revoked member cold-start is refused and the surviving majority retains all five acknowledged records')


def main():
    parser=argparse.ArgumentParser();parser.add_argument('--engine',default='podman',choices=['podman','docker']);parser.add_argument('--image',required=True);args=parser.parse_args()
    OUT.mkdir(parents=True,exist_ok=True)
    evidence=packaged_evidence(local_image_id(args.engine,args.image))
    report=dict(status='running',**evidence,database_image=PERCONA,server_image=args.image,members=3,poll_seconds=2,connect_retries=0,connect_timeout_ms=1000,passed=[],limits='Single-host loopback fault injection with opaque TLS byte relays; bounded six-second observation windows and shell/container overhead, not SLOs, production network failure domains, indefinite outage safety, cold-key caching qualification or database PITR.')
    path=OUT/'image.json';path.write_text(json.dumps(report,indent=2)+'\n')
    try:
        with tempfile.TemporaryDirectory(prefix='keytend-percona-outage-') as directory:
            fixture=OutageSet(directory,args.engine,args.image)
            try:run(fixture,report)
            finally:fixture.cleanup()
        report['status']='passed_with_security_finding'
    except BaseException as error:
        report.update(status='failed',error_type=type(error).__name__)
        if isinstance(error,subprocess.CalledProcessError):report.update(command=error.cmd,command_output=error.output)
        else:report['error']=str(error)
        raise
    finally:
        report['log_sha256']={str(p.relative_to(ROOT)):sha(p) for p in OUT.glob('*.log')}
        path.write_text(json.dumps(report,indent=2)+'\n')
    print('PASS bounded Percona outage observations:',len(report['passed']),'checks; delayed revocation remains an operational limitation')

if __name__=='__main__':main()
