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

"""Run build and test commands on another podman host over SSH.

Used to build and test the linux/arm64 image natively on an arm64 machine
(`--build-host`/`--arm64-host`). Files go over as a deterministic tar on the SSH
channel; results come back with their SHA-256 computed on both ends, so a
transfer that does not match fails.
"""
import hashlib
import io
import json
import pathlib
import shlex
import subprocess
import tarfile


def deterministic_tar(files):
    """Tar of {archive name: local path} with sorted names, zero mtimes and root ownership."""
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode='w', format=tarfile.PAX_FORMAT) as tar:
        for name in sorted(files):
            path = pathlib.Path(files[name])
            data = path.read_bytes()
            info = tarfile.TarInfo(name)
            info.size, info.mtime, info.uid, info.gid, info.uname, info.gname = len(data), 0, 0, 0, '', ''
            info.mode = 0o755 if path.stat().st_mode & 0o111 else 0o644
            tar.addfile(info, io.BytesIO(data))
    return buffer.getvalue()


def shell_path(path):
    """Double-quoted shell word for a remote path; a leading ~/ becomes $HOME/."""
    path = str(path)
    if path.startswith('~/'):
        path = '$HOME/'+path[2:]
    assert '"' not in path and '`' not in path and '\\' not in path, 'unsupported remote path: '+path
    return '"'+path+'"'


class Host:
    """One SSH destination. `ssh` is the client command (for example `ssh -o BatchMode=yes`).

    With `root`, work stays under that remote directory: temporary files (TMPDIR), working
    directories and the rootless podman image store (XDG_DATA_HOME, so the store is
    <root>/data/containers/storage). Rootless podman 4.9 ignores CONTAINERS_STORAGE_CONF. podman's
    runtime state stays in the user's XDG_RUNTIME_DIR tmpfs, which rootless cgroup handling needs.
    """

    def __init__(self, name, ssh='ssh', root=None):
        self.name, self.ssh, self.root = name, shlex.split(ssh) if isinstance(ssh, str) else list(ssh), root
        self.prepared = False

    def prologue(self):
        if not self.root:
            return ''
        root = shell_path(self.root)
        return (f'KEYTEND_ROOT={root}; export TMPDIR="$KEYTEND_ROOT/tmp" XDG_DATA_HOME="$KEYTEND_ROOT/data"; '
                'mkdir -p "$TMPDIR" "$XDG_DATA_HOME"; ')

    def prepare(self):
        """Fail early unless podman's image store is under the remote root."""
        if self.root and not self.prepared:
            self.prepared = True
            store = self.text('podman info --format "{{.Store.GraphRoot}}" 2>/dev/null; echo "|$KEYTEND_ROOT"').strip()
            graph, root = store.rsplit('|', 1)
            assert not graph.strip() or graph.strip().startswith(root.rstrip('/')+'/'), f'{self.name}: podman image store {graph.strip()} is outside {root}'

    def command(self, script):
        return [*self.ssh, self.name, self.prologue()+script]

    def run(self, script, input=None, stdout=subprocess.PIPE, timeout=3600, check=True):
        """Run a POSIX shell script remotely; returns stdout bytes when captured."""
        result = subprocess.run(self.command(script), input=input, stdout=stdout, stderr=subprocess.STDOUT if stdout is not subprocess.PIPE else subprocess.PIPE,
            timeout=timeout)
        if check and result.returncode != 0:
            detail = (result.stderr or b'')[-2000:].decode(errors='replace') if stdout is subprocess.PIPE else 'see log'
            raise RuntimeError(f'{self.name}: remote command failed ({result.returncode}): {script[:200]}: {detail}')
        return result.stdout if stdout is subprocess.PIPE else result.returncode

    def text(self, script, **options):
        return self.run(script, **options).decode()

    def mktemp(self, prefix='keytend-kmip-server'):
        self.prepare()
        return self.text(f'mktemp -d "$TMPDIR"/{shlex.quote(prefix)}.XXXXXXXX' if self.root else f'mktemp -d -t {shlex.quote(prefix)}.XXXXXXXX').strip()

    def push(self, files, directory):
        """Copy {relative name: local path} into the remote directory; returns the tar SHA-256."""
        data = deterministic_tar(files)
        self.run(f'mkdir -p {shlex.quote(directory)} && tar -x -m -C {shlex.quote(directory)}', input=data)
        return hashlib.sha256(data).hexdigest()

    def sha256(self, path):
        return self.text(f'sha256sum {shlex.quote(path)}').split()[0]

    def fetch(self, path, local):
        """Copy a remote file to `local`; both ends' SHA-256 must agree. Returns the digest."""
        expected = self.sha256(path)
        local = pathlib.Path(local)
        partial = local.with_name('.'+local.name+'.partial')
        try:
            with partial.open('wb') as out:
                code = self.run(f'cat {shlex.quote(path)}', stdout=out, check=False)
            assert code == 0, f'{self.name}: could not read {path}'
            with partial.open('rb') as file:
                actual = hashlib.file_digest(file, 'sha256').hexdigest()
            assert actual == expected, f'transfer of {self.name}:{path} is corrupt: remote {expected}, local {actual}'
            partial.replace(local)
        finally:
            if partial.exists():
                partial.unlink()
        return expected

    def facts(self, engine='podman'):
        """Host identity recorded with every remote result."""
        self.prepare()
        uname = self.text('uname -srm').strip()
        release = self.text('cat /etc/os-release 2>/dev/null || true')
        fields = dict(line.split('=', 1) for line in release.splitlines() if '=' in line)
        version = json.loads(self.text(f'{shlex.quote(engine)} version --format json'))
        client = version.get('Client', version)
        storage = json.loads(self.text(f'{shlex.quote(engine)} info --format json')).get('store', {}).get('graphRoot') if engine == 'podman' else None
        return dict(host=self.name, root=self.root, image_store=storage, uname=uname, machine=uname.split()[-1], os=fields.get('PRETTY_NAME', '').strip('"'),
            engine=engine, engine_version=client.get('Version'), engine_os_arch=client.get('OsArch'))
