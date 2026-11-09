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

"""Real PBM physical PITR on an authenticated encrypted three-member replica set.

Uses unchanged pinned vendor binaries. All resources belong to a disposable local
fixture. No production cluster, external backup service or licensed SDK is used.
"""
import argparse
import copy
import ctypes
import errno
import fcntl
import hashlib
import json
import os
import pathlib
import socket
import subprocess
import tempfile
import time
import urllib.parse

import test_database
import test_database_replicaset
from image_evidence import ROOT, local_image_id, packaged_evidence
from test_database import PERCONA
from test_database_backup import BackupSet, key_state, manifest, sha
from test_database_replicaset import USER, command
from wire import key_value

PBM = 'docker.io/percona/percona-backup-mongodb@sha256:4b2ad0398d7099a009bf49388f57c3e4bd244fcd6d76e36b7355d421dd3a018e'
COMBINED = 'localhost/keytend-kmip-server-percona-pbm:2.17.0'
OUT = ROOT/'artifacts/database-pbm'

# The shell only observes the unchanged vendor process; it never restarts it.
# Positional arguments avoid interpolating configuration or credentials in code.
AGENT_WRAPPER = '''directory=$1
shift
umask 077
exec >"$directory/wrapper-stdout" 2>"$directory/wrapper-stderr"
"$@" >"$directory/stdout" 2>"$directory/stderr" &
agent_pid=$!
printf '%s\\n' "$agent_pid" >"$directory/pid"
wait "$agent_pid"
status=$?
printf '%s\\n' "$status" >"$directory/exit"
exit "$status"
'''


def inotify_observation():
    """One host-UID syscall witness, not attribution of a container failure."""
    record = dict(scope='harness host UID; distinct from vendor syscall', uid=os.getuid(),
        observed_utc_ns=time.time_ns())
    try:
        libc = ctypes.CDLL(None, use_errno=True)
        init = libc.inotify_init1
        init.argtypes = [ctypes.c_int]
        init.restype = ctypes.c_int
        fd = init(os.O_CLOEXEC | os.O_NONBLOCK)
        if fd < 0:
            number = ctypes.get_errno()
            record.update(ok=False, errno=number, error=os.strerror(number))
        else:
            os.close(fd)
            record['ok'] = True
    except (OSError, AttributeError) as error:
        record.update(ok=None, error=str(error))
    return record


def log_position(path):
    if not path.exists():
        return dict(exists=False, offset=0)
    stat = path.stat()
    return dict(exists=True, offset=stat.st_size, device=stat.st_dev, inode=stat.st_ino)


def ordered_ts(value):
    return value['t'], value['i']


# A physical restore starts a temporary mongod on a port the agent picks in
# (member port, member port + 1111] and checks free only once, tens of seconds
# before that mongod binds it (peekTmpPort in pbm/restore/physical.go, PBM
# 2.17.0). With member ports in the kernel's ephemeral range, any parallel
# bind(0) or outgoing connection could take that port first ("Address already
# in use"). Members therefore get a block below the ephemeral range that no
# automatic allocation uses, spaced so their temporary ranges never overlap,
# and held for the fixture's lifetime with a cross-process lock.
PBM_TMP_PORT_SPAN = 1111
PORT_BLOCK_STRIDE = PBM_TMP_PORT_SPAN+1
PORT_BLOCK = 3*PORT_BLOCK_STRIDE
PORT_BLOCK_FLOOR = 10000
PORT_BLOCK_LOCKS = pathlib.Path(tempfile.gettempdir())/'keytend-pbm-port-blocks'


def ephemeral_floor():
    try:
        return int(pathlib.Path('/proc/sys/net/ipv4/ip_local_port_range').read_text().split()[0])
    except (OSError, ValueError, IndexError):
        return 32768


def port_free(port):
    """True if a dual-stack wildcard listener (as PBM and mongod use) could bind the port."""
    try:
        sock = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
        sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
        address = ('::', port)
    except OSError:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        address = ('0.0.0.0', port)
    with sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            sock.bind(address)
        except OSError as error:
            if error.errno == errno.EADDRINUSE:
                return False
            raise
    return True


def reserve_port_block(timeout=1800):
    """Return (lock file, base) for a free block below the ephemeral range; waits while all are held."""
    ceiling = ephemeral_floor()
    bases = list(range(ceiling-PORT_BLOCK, PORT_BLOCK_FLOOR-1, -PORT_BLOCK))
    if not bases:
        raise RuntimeError(f'no PBM port block fits between {PORT_BLOCK_FLOOR} and the ephemeral range at {ceiling}')
    PORT_BLOCK_LOCKS.mkdir(mode=0o700, exist_ok=True)
    deadline = time.monotonic()+timeout
    while True:
        for base in bases:
            lock = (PORT_BLOCK_LOCKS/(str(base)+'.lock')).open('a')
            try:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                lock.close()
                continue
            if all(port_free(port) for port in range(base, base+PORT_BLOCK)):
                return lock, base
            lock.close()
        if time.monotonic() > deadline:
            raise RuntimeError(f'no free PBM port block below {ceiling} within {timeout} seconds')
        time.sleep(5)


class PbmSet(BackupSet):
    def allocate_ports(self):
        self.port_lock, base = reserve_port_block()
        return [base+member*PORT_BLOCK_STRIDE for member in range(3)]

    def release_ports(self):
        lock = getattr(self, 'port_lock', None)
        if lock is not None:
            lock.close()
            self.port_lock = None

    def __init__(self, *args):
        super().__init__(*args)
        self.storage = self.root/'pbm-storage'
        self.storage.mkdir(mode=0o700)
        self.controls = [self.root/('pbm-control-'+str(i)) for i in range(3)]
        self.password = (self.tls/'admin-password').read_text()
        for member, directory in enumerate(self.controls):
            directory.mkdir(mode=0o700)
            parameters = urllib.parse.urlencode(dict(authSource='admin', replicaSet='qualification',
                tls='true', tlsCAFile='/tls/ca.pem', tlsCertificateKeyFile='/tls/client.pem'))
            uri = 'mongodb://'+USER+':'+urllib.parse.quote(self.password, safe='')+'@localhost:'+str(self.ports[member])+'/?'+parameters
            (directory/'uri').write_text(uri+'\n')
            (directory/'agent.yaml').write_text(json.dumps({'mongodb-uri': uri}))
            (directory/'storage.yaml').write_text(json.dumps({
                'storage': {'type': 'filesystem', 'filesystem': {'path': '/backup-store'}},
                'pitr': {'enabled': False, 'oplogSpanMin': 0.1, 'compression': 'gzip'},
                'backup': {'compression': 's2', 'numParallelFiles': 2},
                'restore': {'mongodLocation': '/usr/bin/mongod', 'numDownloadWorkers': 2,
                    'downloadChunkMb': 4, 'maxDownloadBufferMb': 64, 'numParallelFiles': 2}}))
            for file in directory.iterdir():
                file.chmod(0o600)

    def redact(self, value):
        if isinstance(value, bytes):
            value = value.decode(errors='replace')
        value = str(value)
        return value.replace(self.password, '[redacted]').replace(
            urllib.parse.quote(self.password, safe=''), '[redacted]').replace(
            json.dumps(self.password)[1:-1], '[redacted]')

    def base(self, member):
        args = super().base(member)
        args[args.index('--entrypoint')+1] = '/usr/local/bin/pbm-qualification-node'
        return args+['-v', f'{self.storage}:/backup-store', '-v', f'{self.controls[member]}:/control']

    def start(self, member):
        if self.exists(member):
            command([self.engine, 'start', self.names[member]])
        else:
            command(self.base(member)+['-d', '--name', self.names[member], COMBINED]+self.flags(member))

    def agent_diagnostics(self, member, directory, observation):
        """Retain only selected state, never inspect environment/config secrets."""
        record = dict(member=member, container=self.names[member], observation=observation)
        destination = OUT/(directory.name+'.json')
        if destination.exists():
            previous = json.loads(destination.read_text())
            record['observations'] = [*previous.get('observations', []), previous['observation']]
        for name in ['pid', 'exit', 'stdout', 'stderr', 'wrapper-stdout', 'wrapper-stderr']:
            path = directory/name
            record[name] = self.redact(path.read_text(errors='replace')) if path.exists() else None
        try:
            state = json.loads(subprocess.check_output(
                [self.engine, 'inspect', '--format', '{{json .State}}', self.names[member]],
                text=True, stderr=subprocess.STDOUT, timeout=5))
            record['container_state'] = {k: state.get(k) for k in
                ['Status', 'Running', 'ExitCode', 'Error', 'OOMKilled']}
        except (subprocess.SubprocessError, OSError, ValueError) as error:
            record['state_error'] = self.redact(getattr(error, 'output', None) or str(error))
        # Keep the shared vendor log for existing restore-event consumers, but
        # distinguish this launch's append from old successful/restore exits.
        path = self.controls[member]/'agent.log'
        metadata = directory/'launch.json'
        if metadata.exists():
            record['launch'] = json.loads(metadata.read_text())
            before = record['launch']['agent_log_before']
            current = log_position(path)
            after = record['launch'].get('agent_log_end', current)
            record['agent_log_after'] = after
            same_file = not before['exists'] or all(before[k] == after.get(k)
                for k in ['device', 'inode'])
            valid = same_file and after['offset'] >= before['offset'] and (
                not after['exists'] or (current['exists'] and
                    all(after[k] == current[k] for k in ['device', 'inode']) and
                    current['offset'] >= after['offset']))
            launch_log = OUT/(directory.name+'-agent-launch.log')
            launch_log.unlink(missing_ok=True)
            record['agent_log_range_valid'] = valid
            record['agent_log_range_scope'] = 'shared log byte range, not PID attribution'
            if valid:
                record['agent_log_appended_bytes'] = 0
            if valid and after['exists']:
                with path.open('rb') as log:
                    log.seek(before['offset'])
                    appended = log.read(after['offset']-before['offset'])
                record['agent_log_appended_bytes'] = len(appended)
                launch_log.write_text(self.redact(appended))
            record['inotify_at_collection'] = inotify_observation()
        if path.exists():
            (OUT/(directory.name+'-agent.log')).write_text(self.redact(path.read_text(errors='replace')))
        destination.write_text(self.redact(json.dumps(record, indent=2))+'\n')
        return record

    def start_agent(self, member, seconds=15, stable_seconds=2):
        # A unique directory preserves every rotation/recovery launch attempt.
        directory = pathlib.Path(tempfile.mkdtemp(prefix=f'agent-start-{member}-', dir=self.controls[member]))
        if not hasattr(self, 'agent_starts'):
            self.agent_starts = {}
        previous = self.agent_starts.get(member)
        if previous is not None:
            metadata = previous/'launch.json'
            launch_record = json.loads(metadata.read_text())
            launch_record['agent_log_end'] = log_position(self.controls[member]/'agent.log')
            metadata.write_text(json.dumps(launch_record, indent=2)+'\n')
        self.agent_starts[member] = directory
        (directory/'launch.json').write_text(json.dumps(dict(
            started_utc_ns=time.time_ns(), agent_log_before=log_position(self.controls[member]/'agent.log'),
            inotify_before_launch=inotify_observation()), indent=2)+'\n')
        launch = [self.engine, 'exec', '-d', self.names[member], 'sh', '-c',
            AGENT_WRAPPER, 'pbm-agent-start', '/control/'+directory.name, 'pbm-agent',
            '--config=/control/agent.yaml', '--log-json', '--log-path=/control/agent.log']
        (OUT/(directory.name+'-execution.json')).write_text(json.dumps(
            dict(command=launch, startup_timeout_seconds=seconds, stable_seconds=stable_seconds), indent=2)+'\n')
        until = time.monotonic()+seconds
        observation = 'detached exec not yet observed'
        alive_since = None
        try:
            output = subprocess.check_output(launch, text=True, stderr=subprocess.STDOUT,
                timeout=max(.001, until-time.monotonic()))
            observation = self.redact(output)
            while time.monotonic() < until:
                if (directory/'exit').exists():
                    raise AssertionError('PBM agent exited during startup; exit='+
                        (directory/'exit').read_text().strip())
                if (directory/'pid').exists():
                    # Probe the actual child, not detached-exec success or a log file.
                    pid = (directory/'pid').read_text().strip()
                    if pid.isdecimal():
                        probe = subprocess.run([self.engine, 'exec', self.names[member],
                            'sh', '-c', 'kill -0 "$1" && test "$(cat /proc/"$1"/comm)" = pbm-agent',
                            'pbm-agent-probe', pid], text=True, stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT, timeout=max(.001, min(3, until-time.monotonic())))
                        observation = dict(exit_code=probe.returncode, output=self.redact(probe.stdout))
                        if probe.returncode == 0:
                            alive_since = alive_since or time.monotonic()
                            if time.monotonic()-alive_since >= stable_seconds:
                                return
                        else:
                            alive_since = None
                time.sleep(min(.2, max(0, until-time.monotonic())))
            raise AssertionError('PBM agent startup not verified within '+str(seconds)+' seconds')
        except (subprocess.SubprocessError, OSError, AssertionError) as error:
            observation = dict(last=observation,
                error=self.redact(getattr(error, 'output', None) or str(error)))
            raise AssertionError('PBM agent startup failed without restart; member='+str(member)+
                '; diagnostics='+directory.name+'.json') from None
        finally:
            self.agent_diagnostics(member, directory, observation)

    def cli(self, *args, member=0, label=None):
        try:
            output = command([self.engine, 'exec', self.names[member],
                '/usr/local/bin/pbm-qualification-command', *args])
        except subprocess.CalledProcessError as error:
            if label:
                (OUT/(label+'.log')).write_text(self.redact(error.output))
            raise
        if label:
            (OUT/(label+'.log')).write_text(self.redact(output))
        return output

    def cli_json(self, *args, **kwargs):
        return json.loads(self.cli(*args, '--out=json', **kwargs))

    def wait(self, action, seconds=600):
        until = time.monotonic()+seconds
        last = None
        while time.monotonic() < until:
            try:
                result = action()
                last = self.redact(json.dumps(dict(result=result,
                    agents=getattr(self, 'last_agent_health', None)), default=str))[-3000:]
                if result is not None:
                    return result
            except subprocess.CalledProcessError as error:
                last = self.redact(error.output)[-1500:]
            time.sleep(min(2, max(0, until-time.monotonic())))
        diagnostics = []
        for member, control in enumerate(self.controls):
            for directory in sorted(control.glob('agent-start-*')):
                self.agent_diagnostics(member, directory, dict(wait_action=getattr(action, '__name__', str(action)), last=last))
                diagnostics.append(directory.name+'.json')
        raise AssertionError('PBM observation timed out without restart; last observation: '+str(last)+
            '; startup diagnostics: '+', '.join(diagnostics))

    def agent_health(self):
        for member, directory in getattr(self, 'agent_starts', {}).items():
            if (directory/'exit').exists():
                self.agent_diagnostics(member, directory, 'agent exited before healthy registration')
                raise AssertionError('PBM agent exited without restart; member='+str(member)+
                    '; diagnostics='+directory.name+'.json')
        primary = self.primary()
        agents = self.shell(primary, "db.getSiblingDB('admin').pbmAgents.find({}, {_id:0,n:1,rs:1,v:1,pbms:1,nodes:1,stors:1,e:1}).toArray()")
        self.last_agent_health = agents
        if len(agents) == 3 and all(agent['v'] == '2.17.0' and not agent.get('e') and
                all(agent.get(field, {}).get('ok') for field in ['pbms', 'nodes', 'stors']) for agent in agents):
            return agents
        return None

    def snapshot(self, member):
        return self.shell(member, """(()=>{db.getMongo().setReadPref('secondaryPreferred');
            const c=db.getSiblingDB('qualification').records;
            return {documents:c.find({}).sort({_id:1}).toArray(),
                indexes:c.getIndexes().map(i=>({name:i.name,key:i.key,unique:!!i.unique,hidden:!!i.hidden}))
                    .sort((a,b)=>a.name.localeCompare(b.name))};})()""")

    def agree(self, expected):
        for member in range(3):
            self.wait(lambda member=member: True if self.snapshot(member) == expected else None, seconds=90)

    def backup(self, label):
        started = self.cli_json('backup', '--type=physical', label=label+'-start')
        name = started['name']
        def finished():
            status = self.cli_json('describe-backup', name, label=label+'-status')
            if status['status'] in ['error', 'cancelled']:
                raise RuntimeError('PBM backup is terminal: '+json.dumps(status))
            return status if status['status'] == 'done' else None
        status = self.wait(finished)
        assert status['type'] == 'physical' and status['pbm_version'] == '2.17.0'
        # Use the actual PBM control metadata for source identity, full oplog
        # timestamp and stored encryption options. No handwritten backup files.
        metadata = self.shell(self.primary(), "(()=>{const b=db.getSiblingDB('admin').pbmBackups.findOne({name:"+json.dumps(name)+"});return {name:b.name,status:b.status,type:b.type,replsets:b.replsets.map(r=>({name:r.name,node:r.node,status:r.status,security:r.mongod_opts.security})),last:{t:b.last_write_ts.getHighBitsUnsigned(),i:b.last_write_ts.getLowBitsUnsigned()}};})()")
        assert metadata['status'] == 'done' and len(metadata['replsets']) == 1
        return metadata

    def rotate(self, member, label):
        self.stop(member)
        args = self.base(member)
        args[args.index('--entrypoint')+1] = 'mongod'
        output = command(args+['--rm', COMBINED]+self.flags(member)+['--kmipRotateMasterKey'])
        (OUT/(label+'.log')).write_text(self.redact(output))
        self.start(member)
        self.ready(member)
        self.start_agent(member)
        return self.key_id(member)

    def chunks(self):
        return self.shell(self.primary(), "db.getSiblingDB('admin').pbmPITRChunks.find({rs:'qualification'}).sort({start_ts:1}).toArray().map(c=>({name:c.fname,rs:c.rs,size:c.size,start:{t:c.start_ts.getHighBitsUnsigned(),i:c.start_ts.getLowBitsUnsigned()},end:{t:c.end_ts.getHighBitsUnsigned(),i:c.end_ts.getLowBitsUnsigned()}}))")

    def cleanup(self):
        try:
            for member in range(3):
                for directory in sorted(self.controls[member].glob('agent-start-*')):
                    self.agent_diagnostics(member, directory, 'fixture cleanup; no restart')
                if self.exists(member):
                    (OUT/('member-'+str(member)+'.log')).write_text(self.redact(command([self.engine, 'logs', self.names[member]])))
                    log = self.controls[member]/'agent.log'
                    if log.exists():
                        (OUT/('agent-'+str(member)+'.log')).write_text(self.redact(log.read_text()))
                    restore_log = self.directories[member]/'pbm.restore.log'
                    if restore_log.exists():
                        (OUT/('restore-'+str(member)+'.log')).write_text(self.redact(restore_log.read_text()))
                    subprocess.run([self.engine, 'rm', '-f', self.names[member]], check=True,
                        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=45)
            self.server.stop()
        finally:
            self.release_ports()


def prepare_recovery(fixture, report, passed):
    """Produce the same real backup, rotations, mutations and oplog in every lane."""
    fixture.server.start()
    for member in range(3):
        fixture.start(member)
    fixture.eventually(lambda: fixture.shell(0, 'db.adminCommand({ping:1}).ok', auth=False))
    config = {'_id': 'qualification', 'members': [
        {'_id': member, 'host': 'localhost:'+str(port)} for member, port in enumerate(fixture.ports)],
        'settings': {'electionTimeoutMillis': 2000}}
    assert fixture.shell(0, 'rs.initiate('+json.dumps(config)+').ok', auth=False) == 1
    primary = fixture.primary(auth=False)
    assert fixture.shell(primary, "db.getSiblingDB('admin').runCommand({createUser:"+json.dumps(USER)+",pwd:require('fs').readFileSync('/tls/admin-password','utf8'),roles:[{role:'root',db:'admin'}],writeConcern:{w:'majority',wtimeout:15000}}).ok", auth=False) == 1
    for member in range(3):
        fixture.ready(member)
        assert fixture.inspect(member)['Image'].removeprefix('sha256:') == report['combined_database_image_config_id']
    build = fixture.shell(primary, '(()=>{const b=db.adminCommand({buildInfo:1});return {version:b.version,gitVersion:b.gitVersion};})()')
    assert build['version'].startswith('8.0.34')
    original_binary = command([fixture.engine, 'run', '--rm', '--entrypoint', 'sha256sum', PERCONA, '/usr/bin/mongod']).split()[0]
    actual_binary = command([fixture.engine, 'exec', fixture.names[0], 'sha256sum', '/usr/bin/mongod']).split()[0]
    assert original_binary == actual_binary
    version = command([fixture.engine, 'exec', fixture.names[0], 'pbm', 'version'])
    assert 'Version:   2.17.0' in version
    report.update(database_build=build, mongod_binary_sha256=actual_binary, pbm_version=version)
    initial_ids = [fixture.key_id(member) for member in range(3)]
    assert len(set(initial_ids)) == 3 and all(key_state(fixture.server, key) == 2 for key in initial_ids)
    with fixture.server.connect() as client:
        initial_material = {key: key_value(client, key) for key in initial_ids}
    documents = [{'_id': i, 'account': 'account-'+str(i), 'balance': 1000+i,
                  'phase': 'base'} for i in range(32)]
    assert fixture.shell(primary, "(()=>{const c=db.getSiblingDB('qualification').records;c.createIndex({account:1},{name:'unique_account',unique:true});c.createIndex({phase:1},{name:'legacy_phase'});return c.insertMany("+json.dumps(documents)+",{writeConcern:{w:'majority',j:true,wtimeout:15000}}).acknowledged;})()") is True
    base = {'documents': documents, 'indexes': [
        {'name': '_id_', 'key': {'_id': 1}, 'unique': False, 'hidden': False},
        {'name': 'legacy_phase', 'key': {'phase': 1}, 'unique': False, 'hidden': False},
        {'name': 'unique_account', 'key': {'account': 1}, 'unique': True, 'hidden': False}]}
    fixture.agree(base)
    for member in range(3):
        fixture.start_agent(member)
    fixture.cli('config', '--file=/control/storage.yaml', label='configuration')
    report['agents'] = fixture.wait(fixture.agent_health)
    passed('three authenticated TLS members run unchanged Percona mongod and PBM 2.17.0 binaries with healthy local agents, distinct active KMIP keys and exact majority/journaled baseline records/indexes')

    fixture.cli('config', '--set=pitr.enabled=true', label='enable-pitr')
    backup = fixture.backup('base-backup')
    backed_key = backup['replsets'][0]['security']['kmip']['keyIdentifier']
    assert backed_key in initial_ids
    report.update(backup=backup, initial_key_ids=initial_ids, restored_key_id=backed_key)
    passed('PBM creates a completed physical backup and records the actual source member KMIP identifier while continuous oplog slicing is enabled')

    rotated = [fixture.rotate(member, 'rotation-before-pitr-'+str(member)) for member in range(3)]
    assert len(set(rotated)) == 3 and not set(initial_ids).intersection(rotated)
    fixture.wait(fixture.agent_health)
    fixture.agree(base)
    with fixture.server.connect() as client:
        assert all(key_value(client, key) == material for key, material in initial_material.items())
    report['pre_restore_rotated_key_ids'] = rotated
    passed('all members rotate to distinct fresh KMIP keys after the base backup; old key bytes and acknowledged base data/indexes remain intact')

    primary = fixture.primary()
    mutation = fixture.shell(primary, """(()=>{const c=db.getSiblingDB('qualification').records;
        const w={writeConcern:{w:'majority',j:true,wtimeout:15000}};
        const updated=c.updateOne({_id:0},{$set:{balance:7777,phase:'after-rotation'}},w).modifiedCount;
        const deleted=c.deleteOne({_id:1},w).deletedCount;
        const inserted=c.insertOne({_id:100,account:'new-account',balance:42,phase:'after-rotation'},w).acknowledged;
        c.dropIndex('legacy_phase');c.createIndex({balance:1},{name:'balance_lookup'});
        const modified=db.getSiblingDB('qualification').runCommand({collMod:'records',index:{name:'balance_lookup',hidden:true},writeConcern:w.writeConcern}).ok;
        const s=db.getMongo().startSession();const t=s.getDatabase('qualification').records;
        s.startTransaction({writeConcern:w.writeConcern});
        const a=t.updateOne({_id:2},{$inc:{balance:-100}}).modifiedCount;
        const b=t.updateOne({_id:3},{$inc:{balance:100}}).modifiedCount;
        s.commitTransaction();s.endSession();return {updated,deleted,inserted,modified,transferred:a+b};})()""")
    assert mutation == {'updated': 1, 'deleted': 1, 'inserted': True, 'modified': 1, 'transferred': 2}
    expected = copy.deepcopy(base)
    expected['documents'] = [doc for doc in expected['documents'] if doc['_id'] != 1]
    for doc in expected['documents']:
        if doc['_id'] == 0:
            doc.update(balance=7777, phase='after-rotation')
        if doc['_id'] == 2:
            doc['balance'] -= 100
        if doc['_id'] == 3:
            doc['balance'] += 100
    expected['documents'].append({'_id': 100, 'account': 'new-account', 'balance': 42, 'phase': 'after-rotation'})
    expected['indexes'][1] = {'name': 'balance_lookup', 'key': {'balance': 1}, 'unique': False, 'hidden': True}
    fixture.agree(expected)
    target = fixture.shell(primary, "(()=>{const t=db.getSiblingDB('local').oplog.rs.find().sort({$natural:-1}).limit(1).next().ts;return {t:t.getHighBitsUnsigned(),i:t.getLowBitsUnsigned()};})()")
    assert ordered_ts(target) > ordered_ts(backup['last'])
    report['restore_target'] = target
    passed('after key rotation, majority-acknowledged insert/update/delete, an atomic two-record transaction, and index create/drop/hide changes match an independent Python target-state oracle')

    assert fixture.shell(primary, "db.getSiblingDB('qualification').records.deleteMany({},{writeConcern:{w:'majority',j:true,wtimeout:15000}}).deletedCount") == 32
    assert fixture.shell(primary, "db.getSiblingDB('qualification').records.insertOne({_id:999,account:'future-only',balance:-1},{writeConcern:{w:'majority',j:true,wtimeout:15000}}).acknowledged") is True
    future = fixture.shell(primary, "(()=>{const t=db.getSiblingDB('local').oplog.rs.find().sort({$natural:-1}).limit(1).next().ts;return {t:t.getHighBitsUnsigned(),i:t.getLowBitsUnsigned()};})()")
    assert ordered_ts(future) > ordered_ts(target)
    def covered():
        chunks = fixture.chunks()
        end = ordered_ts(backup['last'])
        for chunk in chunks:
            start, finish = ordered_ts(chunk['start']), ordered_ts(chunk['end'])
            if start <= end <= finish:
                end = max(end, finish)
        return chunks if end >= ordered_ts(future) else None
    report['oplog_chunks'] = fixture.wait(covered)
    report['future_operation'] = future
    fixture.cli('config', '--set=pitr.enabled=false', label='disable-pitr')
    fixture.wait(lambda: True if fixture.shell(fixture.primary(),
        "db.getSiblingDB('admin').pbmLock.countDocuments({})") == 0 else None)
    passed('real PBM oplog slices continuously cover the base backup through the exact target and a later destructive deletion/future-only insert; slicing is stopped before restore')
    return backup, expected, initial_material


def run(fixture, report):
    def passed(description):
        report['passed'].append(description)
        (OUT/'image.json').write_text(json.dumps(report, indent=2)+'\n')
        print('PASS', description, flush=True)

    backup, expected, initial_material = prepare_recovery(fixture, report, passed)
    target = report['restore_target']
    initial_ids = report['initial_key_ids']
    rotated = report['pre_restore_rotated_key_ids']
    backed_key = report['restored_key_id']

    # Ordinary physical PITR uses the running nodes' encryption settings and
    # restored key database. PBM's restore --config is reserved for --external;
    # it is not a security override for this workflow. Retain the backup's exact
    # historical key in KMIP and verify the recovered identifier/material below.
    restore_options = ['--base-snapshot='+backup['name'],
        '--time='+str(target['t'])+','+str(target['i']),
        '--fallback-enabled=true', '--allow-partly-done=false', '--yes']
    report['restore_start_options'] = restore_options
    started = time.monotonic()
    restore = fixture.cli_json('restore', *restore_options, label='restore-start')
    def finished():
        status = fixture.cli_json('describe-restore', restore['name'],
            '--config=/control/storage.yaml', label='restore-status')
        if status['status'] in ['error', 'partlyDone']:
            raise RuntimeError('PBM physical restore did not complete on all members: '+json.dumps(status))
        return status if status['status'] == 'done' else None
    result = fixture.wait(finished, seconds=900)
    assert result['type'] == 'physical' and len(result['replsets']) == 1
    nodes = result['replsets'][0]['nodes']
    assert len(nodes) == 3 and all(node['status'] == 'done' for node in nodes)
    report.update(restore=result, observed_physical_restore_seconds=round(time.monotonic()-started, 3))
    passed('PBM physical PITR reports Done on every node with fallback enabled and partial-restore/initial-sync success disabled')

    for member in range(3):
        fixture.stop(member)
        fixture.start(member)
    for member in range(3):
        fixture.ready(member)
    fixture.primary()
    fixture.agree(expected)
    assert all(fixture.key_id(member) == backed_key for member in range(3))
    with fixture.server.connect() as client:
        assert key_value(client, backed_key) == initial_material[backed_key]
    for member in range(3):
        assert fixture.shell(member, 'db.getSiblingDB("qualification").runCommand({validate:"records",full:true}).valid') is True
    report['target_snapshot_sha256'] = hashlib.sha256(json.dumps(expected, sort_keys=True).encode()).hexdigest()
    passed('all restarted members recover the exact target documents, transaction balances and hidden index definitions, exclude later destructive writes, and use the backup original KMIP key with its exact retained bytes')

    for member in range(3):
        fixture.start_agent(member)
    fixture.cli('config', '--force-resync', '--wait', label='resync-after-restore')
    fresh = [fixture.rotate(member, 'rotation-after-pitr-'+str(member)) for member in range(3)]
    assert len(set(fresh)) == 3 and not set(fresh).intersection(initial_ids+rotated)
    assert all(key_state(fixture.server, key) == 2 for key in fresh)
    fixture.agree(expected)
    fixture.wait(fixture.agent_health)
    report['post_restore_rotated_key_ids'] = fresh
    report['fresh_backup'] = fixture.backup('fresh-base-backup')
    assert report['fresh_backup']['replsets'][0]['security']['kmip']['keyIdentifier'] in fresh
    fixture.cli('config', '--set=pitr.enabled=true', label='resume-pitr')
    report['resumed_agents'] = fixture.wait(fixture.agent_health)
    passed('post-recovery rolling rotation restores three distinct fresh active member keys, exact data/indexes survive, and PBM completes a new physical base backup and re-enables PITR with healthy agents')


def execute(engine, image, output, runner=run):
    """Run a PBM lane against the given image and the verified combined fixture image."""
    global OUT
    OUT = pathlib.Path(output).resolve()
    OUT.mkdir(parents=True, exist_ok=True)
    test_database.ART = OUT
    test_database_replicaset.OUT = OUT
    db_config = local_image_id(engine, COMBINED)
    built = json.loads((ROOT/'artifacts/pbm-fixture-image.json').read_text())
    assert built['status'] == 'verified_fixture_image' and built['image_config_id'] == db_config
    evidence = packaged_evidence(local_image_id(engine, image))
    report = dict(status='running', agent_execution_wrapper=AGENT_WRAPPER,
        agent_execution_wrapper_sha256=hashlib.sha256(AGENT_WRAPPER.encode()).hexdigest(),
        **evidence, server_image=image, database_image=PERCONA, pbm_image=PBM,
        combined_database_image=COMBINED, combined_database_image_config_id=db_config,
        fixture_manifest_sha256=sha(ROOT/'artifacts/pbm-fixture-image.json'),
        vendor_binary_sha256=built['binaries_sha256'],
        members=3, passed=[], limits='Single-host authenticated TLS replica set and local shared filesystem storage. No sharded-cluster, independent failure domains, remote retention/backup encryption, throughput, RPO/RTO, storage exhaustion, adverse PITR/fallback or least-privilege PBM account qualification. Root database account and development KMIP policy are fixture-only. No external audit-floor rollback policy qualification. No full-spec or production approval.')
    path = OUT/'image.json'
    path.write_text(json.dumps(report, indent=2)+'\n')
    fixture = None
    try:
        with tempfile.TemporaryDirectory(prefix='keytend-percona-pbm-') as directory:
            fixture = PbmSet(directory, engine, image)
            report['member_ports'] = dict(ports=fixture.ports, ephemeral_floor=ephemeral_floor(),
                temporary_mongod_span=PBM_TMP_PORT_SPAN)
            try:
                runner(fixture, report)
            finally:
                fixture.cleanup()
        report['status'] = 'passed'
    except BaseException as error:
        report.update(status='failed', error_type=type(error).__name__)
        detail = error.output if isinstance(error, subprocess.CalledProcessError) else str(error)
        report['error'] = fixture.redact(detail) if fixture else detail
        raise
    finally:
        report['log_sha256'] = {str(p.relative_to(ROOT)): sha(p) for p in OUT.glob('*.log')}
        report['agent_startup_sha256'] = {str(p.relative_to(ROOT)): sha(p) for p in OUT.glob('agent-start-*') if p.is_file()}
        path.write_text(json.dumps(report, indent=2)+'\n')
    print('PASS PBM qualification:', report.get('scenario', 'physical-pitr'),
        len(report['passed']), 'checks, all three members')


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--engine', default='podman', choices=['podman', 'docker'])
    parser.add_argument('--image', required=True)
    parser.add_argument('--output', type=pathlib.Path, default=OUT)
    args = parser.parse_args()
    execute(args.engine, args.image, args.output)


if __name__ == '__main__':
    main()
