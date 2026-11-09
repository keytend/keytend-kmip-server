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

"""Owned native fixtures and health counters for connection lifecycle checks."""
import http.client
import json
import socket
import subprocess
import time
from test_runtime import Server, free_port


class NetworkServer(Server):
    def __init__(self, directory, binary, max_connections=64, https=False):
        super().__init__(directory, binary=binary)
        self.max_connections = max_connections
        self.https = free_port() if https else None

    def start(self):
        self.log = open(self.root / 'server.log', 'a')
        args = [self.binary, 'serve', '--listen', f'127.0.0.1:{self.port}',
                '--health-listen', f'127.0.0.1:{self.health}',
                '--max-connections', str(self.max_connections),
                '--cert', str(self.pki / 'server.pem'), '--key', str(self.pki / 'server.key'),
                '--ca', str(self.pki / 'ca.pem'), '--policy', str(self.pki / 'policy.json'),
                '--database', str(self.data / 'kmip.sqlite'),
                '--master-key', str(self.pki / 'master.key')]
        if self.https:
            args += ['--https-listen', f'127.0.0.1:{self.https}']
        self.process = subprocess.Popen(args, stdout=self.log, stderr=self.log)
        until = time.monotonic() + 10
        while time.monotonic() < until:
            if self.process.poll() is not None:
                raise RuntimeError((self.root / 'server.log').read_text())
            try:
                with socket.create_connection(('127.0.0.1', self.health), timeout=.2):
                    return
            except OSError:
                time.sleep(.05)
        raise TimeoutError('owned network server did not start')


def metrics(server):
    c = http.client.HTTPConnection('127.0.0.1', server.health, timeout=2)
    try:
        c.request('GET', '/connection-metrics')
        r = c.getresponse()
        if r.status != 200:
            raise RuntimeError(f'connection metrics returned HTTP {r.status}')
        return json.loads(r.read())
    finally:
        c.close()
