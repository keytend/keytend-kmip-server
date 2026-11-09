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

"""Opt-in metadata capture for one owned published-port benchmark fixture.

No packet, read/write buffer, TLS, environment or key contents are traced.
Process scans select an exact namespace argument, never a process-name match.
"""
import hashlib
import json
import os
import pathlib
import subprocess
import threading
import time


# Keep this explicit: %network would include send/receive buffers.
SOCKET_SYSCALLS = 'socket,bind,connect,accept,accept4,close,shutdown,getsockname,getpeername'


def process_identity(pid):
    root = pathlib.Path('/proc') / str(pid)
    stat = (root / 'stat').read_text().rsplit(')', 1)[1].split()
    return dict(pid=pid, start_ticks=int(stat[19]),
                argv=[s.decode() for s in (root / 'cmdline').read_bytes().split(b'\0') if s],
                exe=str((root / 'exe').readlink()),
                netns=str((root / 'ns/net').readlink()),
                userns=str((root / 'ns/user').readlink()),
                cgroup=(root / 'cgroup').read_text().strip())


def owns_pasta(identity, sandbox, ports):
    """Require namespace and exact host port mappings on the actual executable."""
    args = identity['argv']
    return (pathlib.Path(identity['exe']).name in ('pasta', 'pasta.avx2')
            and any(args[i:i + 2] == ['--netns', sandbox] for i in range(len(args)))
            and all(any(args[i:i + 2] == ['-t', mapping]
                        for i in range(len(args))) for mapping in ports))


def tcp_rows(text, ports, *, either=False):
    rows = []
    for line in text.splitlines()[1:]:
        fields = line.split()
        if len(fields) < 10:
            continue
        local, peer = fields[1:3]
        if int(local.rsplit(':', 1)[1], 16) in ports or (
                either and int(peer.rsplit(':', 1)[1], 16) in ports):
            rows.append(dict(local=local, peer=peer, state=fields[3], inode=fields[9]))
    return rows


class ForwardingCapture:
    def __init__(self, out, server, inspected, strace):
        self.out = pathlib.Path(out) / 'forwarding-forensics'
        self.out.mkdir()  # Never overwrite an earlier attempt.
        self.server = server
        self.inspected = inspected
        self.strace = pathlib.Path(strace).resolve()
        self.lock = threading.Lock()
        self.halt = threading.Event()
        self.tracer = None
        self.thread = None
        self.stream = None
        self.trace_log = None
        self.identity = dict(status='initializing', errors=[])

    def save(self):
        (self.out / 'identity.json').write_text(json.dumps(self.identity, indent=2) + '\n')

    def error(self, message):
        if message not in self.identity['errors'] and len(self.identity['errors']) < 8:
            self.identity['errors'].append(message)

    def emit(self, kind, **fields):
        record = dict(kind=kind, monotonic_ns=time.monotonic_ns(), wall_ns=time.time_ns(), **fields)
        with self.lock:
            self.stream.write(json.dumps(record) + '\n')
            self.stream.flush()

    def start(self):
        r = self.inspected
        assert r['Name'] == self.server.name and r['State']['Running']
        assert r['HostConfig']['NetworkMode'].split(':', 1)[0] == 'pasta', 'only the inspected pasta path is supported'
        sandbox = r['NetworkSettings']['SandboxKey']
        assert sandbox and pathlib.Path(sandbox).exists()
        mappings = [f'127.0.0.1/{self.server.port}-{self.server.port}:5696-5696',
                    f'127.0.0.1/{self.server.health}-{self.server.health}:8080-8080']
        matches = []
        for proc in pathlib.Path('/proc').glob('[0-9]*'):
            try:
                # Do not retain metadata for unrelated processes.
                if sandbox.encode() not in (proc / 'cmdline').read_bytes().split(b'\0'):
                    continue
                item = process_identity(int(proc.name))
                if owns_pasta(item, sandbox, mappings):
                    matches.append(item)
            except (OSError, UnicodeError):
                continue
        assert len(matches) == 1, f'cannot prove a unique owned pasta: {len(matches)}'
        forwarder = matches[0]
        server = process_identity(r['State']['Pid'])
        self.identity.update(container_id=r['Id'], container_name=r['Name'], image_id=r['Image'],
                             sandbox=sandbox, server=server, forwarder=forwarder,
                             published_ports=dict(kmip=self.server.port, health=self.server.health),
                             host_netns=str(pathlib.Path('/proc/self/ns/net').readlink()),
                             host_config={k:r['HostConfig'].get(k) for k in
                                          ('NetworkMode', 'Memory', 'CpuQuota', 'CpuPeriod', 'PidsLimit')},
                             strace_sha256=hashlib.sha256(self.strace.read_bytes()).hexdigest(),
                             traced_syscalls=SOCKET_SYSCALLS,
                             forwarder_exe_sha256=hashlib.sha256(pathlib.Path(
                                 f"/proc/{forwarder['pid']}/exe").read_bytes()).hexdigest())
        self.save()
        # Rootless Podman's mount namespace holds the nsfs bind mount; the host
        # mount namespace sees only its empty placeholder file.
        namespace_inode = int(subprocess.check_output(
            ['podman', 'unshare', 'stat', '-L', '-c', '%i', sandbox], text=True))
        self.identity['sandbox_nsfs_inode'] = namespace_inode
        assert os.stat(f"/proc/{server['pid']}/ns/net").st_ino == namespace_inode
        self.identity['namespace_tcp_settings'] = subprocess.check_output(
            # The image ships no cat; read the settings from the host inside the
            # container's network namespace.
            ['podman', 'unshare', 'nsenter', '-t', str(server['pid']), '-n', 'cat',
             '/proc/sys/net/ipv4/ip_local_port_range', '/proc/sys/net/ipv4/tcp_tw_reuse'], text=True)
        self.stream = (self.out / 'metadata.jsonl').open('w')
        self.trace_log = (self.out / 'strace-status.log').open('w')
        # Recheck identity immediately before attaching; never attach to the server,
        # engine, unrelated helpers or processes selected just by executable name.
        assert process_identity(forwarder['pid']) == forwarder
        self.tracer = subprocess.Popen([str(self.strace), '-ttt', '-T', '-e',
                                       'trace=' + SOCKET_SYSCALLS, '-o',
                                       str(self.out / 'forwarder-sockets.strace'),
                                       '-p', str(forwarder['pid'])],
                                      stdout=self.trace_log, stderr=self.trace_log)
        time.sleep(.1)
        assert self.tracer.poll() is None, 'owned forwarder strace attachment failed'
        self.identity['status'] = 'capturing'
        self.save()
        self.snapshot()
        self.thread = threading.Thread(target=self.poll, name='owned-forwarding-capture', daemon=True)
        self.thread.start()

    def snapshot(self):
        result = dict(tables={}, processes={}, cgroups={})
        for name, pid, ports, either in [
                ('host', os.getpid(), {self.server.port, self.server.health}, True),
                ('server', self.identity['server']['pid'], {5696, 8080}, True)]:
            rows = []
            try:
                for table in ('tcp', 'tcp6'):
                    rows += tcp_rows(pathlib.Path(f'/proc/{pid}/net/{table}').read_text(), ports, either=either)
                result['tables'][name] = rows
            except OSError as error:
                result['tables'][name] = dict(error=repr(error))
                self.error(f'{name} TCP tables: {error!r}')
        for name in ('forwarder', 'server'):
            item = self.identity[name]
            proc = pathlib.Path('/proc') / str(item['pid'])
            try:
                assert process_identity(item['pid']) == item, 'process identity changed'
                stat = (proc / 'stat').read_text().rsplit(')', 1)[1].split()
                inodes = []
                for fd in (proc / 'fd').iterdir():
                    try:
                        link = str(fd.readlink())
                        if link.startswith('socket:'):inodes.append(link)
                    except FileNotFoundError:
                        pass
                result['processes'][name] = dict(user_ticks=int(stat[11]), system_ticks=int(stat[12]),
                                                threads=int(stat[17]), fds=len(list((proc / 'fd').iterdir())),
                                                socket_inodes=inodes,
                                                limits=(proc / 'limits').read_text())
                cgroup = pathlib.Path('/sys/fs/cgroup') / item['cgroup'].split('::', 1)[1].lstrip('/')
                result['cgroups'][name] = {f:(cgroup / f).read_text() for f in
                                          ('cpu.stat', 'cpu.max', 'memory.events', 'memory.current',
                                           'memory.max', 'pids.current', 'pids.max') if (cgroup / f).exists()}
            except (OSError, AssertionError) as error:
                result['processes'][name] = dict(error=repr(error))
                self.error(f'{name} process metadata: {error!r}')
        self.emit('snapshot', **result)

    def poll(self):
        try:
            while not self.halt.wait(.5):
                self.snapshot()
        except Exception as error:
            self.error(repr(error))
            self.halt.set()

    def client(self, local, peer, stage, error=None):
        self.emit('client_connection', local=local, peer=peer, stage=stage,
                  error_type=type(error).__name__ if error else None,
                  errno=getattr(error, 'errno', None))

    def stop(self):
        self.halt.set()
        if self.thread:
            self.thread.join(timeout=10)
            assert not self.thread.is_alive()
        if self.stream:
            self.snapshot()
            self.stream.close()
        if self.tracer:
            if self.tracer.poll() is None:
                self.tracer.terminate()  # Detach the tracer, never signal its target.
            else:
                self.error('socket tracer exited before capture stop')
            self.identity['strace_exit_code'] = self.tracer.wait(timeout=10)
        if self.trace_log:
            self.trace_log.close()
        self.identity['status'] = ('capture_incomplete' if self.identity['status'] == 'initializing'
                                   else 'capture_errors' if self.identity['errors'] else 'captured')
        self.save()
        assert not self.identity['errors'], 'forwarding metadata collection failed'

    def after_cleanup(self):
        result = dict(container_removed=not self.server.container_exists(), processes_gone={})
        for name in ('server', 'forwarder'):
            item = self.identity.get(name)
            if item:
                try:
                    current = process_identity(item['pid'])
                    result['processes_gone'][name] = current['start_ticks'] != item['start_ticks']
                except FileNotFoundError:
                    result['processes_gone'][name] = True
        sandbox = self.identity.get('sandbox')
        result['sandbox_removed'] = not pathlib.Path(sandbox).exists() if sandbox else None
        rows = []
        for table in ('tcp', 'tcp6'):
            rows += tcp_rows(pathlib.Path('/proc/net/' + table).read_text(),
                             {self.server.port, self.server.health})
        result['published_port_listeners_remaining'] = [r for r in rows if r['state'] == '0A']
        self.identity['cleanup'] = result
        self.save()
        assert result['container_removed'] and all(result['processes_gone'].values())
        assert result['sandbox_removed'] is not False and not result['published_port_listeners_remaining']
