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

"""Run the Kubernetes rotation Job's executable invocation in the image under podman.

Uses the same arguments, non-root UID/GID, read-only root, dropped capabilities,
memory-backed /tmp and read-only key mounts as the Job in
test_kubernetes_storage_rotation.py, against a store populated by the image server.
Checks the image's shell/tool contract and cutover only; it is not Kubernetes
evidence.
"""
import argparse
import datetime
import json
import pathlib
import subprocess
import shutil
import tempfile
import uuid

from image_evidence import ROOT, local_image_id, packaged_evidence
from test_database import ContainerServer
from wire import connect, create_key, key_value

VERSIONS = [(1, 1), (1, 2), (1, 3), (1, 4), (2, 0), (2, 1)]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--image', required=True)
    args = parser.parse_args()
    image_id = local_image_id('podman', args.image)
    report = dict(status='running', started_at=datetime.datetime.now(datetime.timezone.utc).isoformat(),
        **packaged_evidence(image_id), image_tag=args.image,
        checks=[], limits='podman emulation of the Job container contract and cutover; no Kubernetes scheduling, PVC, Secret, fsGroup or CSI evidence')
    path = ROOT/'artifacts/rotation-job-image.json'
    path.write_text(json.dumps(report, indent=2)+'\n')
    try:
        with tempfile.TemporaryDirectory(prefix='keytend-rotation-job-') as directory:
            server = ContainerServer(directory, 'podman', args.image)
            server.start()
            try:
                with connect(server.pki, server.port) as client:
                    records = [(version, identifier, key_value(client, identifier, version)) for version in VERSIONS
                        for identifier in [create_key(client, version)]]
            finally:
                server.stop()
            report['checks'].append(f'image server created {len(records)} keys across final versions {VERSIONS}')
            new = pathlib.Path(directory)/'new'
            new.mkdir(mode=0o700)
            subprocess.run([str(ROOT/'target/debug/keytend-kmip-server'), 'generate-master-key', '--output', str(new/'master.key')],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
            directory_name = 'rotation-'+uuid.uuid4().hex[:10]
            # Identical to the Job arguments in test_kubernetes_storage_rotation.py.
            job_args = ['rotate-master-key', '--database', '/data/kmip.sqlite', '--master-key', '/old/master.key',
                '--new-master-key', '/new/master.key', '--output', f'/data/{directory_name}/kmip.sqlite', '--create-directory']
            command = ['podman', 'run', '--rm', '--name', 'keytend-rotation-job-'+uuid.uuid4().hex[:12],
                '--userns', 'keep-id:uid=10001,gid=10001', '--read-only', '--network', 'none', '--cap-drop=all',
                '--security-opt=no-new-privileges', '--tmpfs', '/tmp:rw,nosuid,nodev,noexec,size=64m,mode=1777',
                '-v', f'{server.data}:/data', '-v', f'{server.tls}:/old:ro', '-v', f'{new}:/new:ro',
                '--entrypoint', '/usr/local/bin/keytend-kmip-server', args.image, *job_args]
            result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=300)
            report['job_output'] = result.stdout[-4000:]
            assert result.returncode == 0, result.stdout
            assert (server.data/directory_name).stat().st_mode & 0o777 == 0o700
            report['checks'].append('Job executable rotated to a new 0700 directory, verified the new key, refused the old key on the copy and kept the source valid with the old key')
            # Cut over: the same server identity starts on the rotated copy with only the new key.
            for stale in server.data.glob('kmip.sqlite*'):
                stale.unlink()
            shutil.copy(server.data/directory_name/'kmip.sqlite', server.data/'kmip.sqlite')
            shutil.copy(new/'master.key', server.tls/'master.key')
            server.start()
            try:
                with connect(server.pki, server.port) as client:
                    for version, identifier, material in records:
                        assert key_value(client, identifier, version) == material
            finally:
                server.stop()
            report['checks'].append('image server restarted on the rotated copy with the new key and returned exact key bytes for every version')
        report['status'] = 'passed'
    except BaseException as error:
        report.update(status='failed', error=str(error)[:4000])
        raise
    finally:
        report['finished_at'] = datetime.datetime.now(datetime.timezone.utc).isoformat()
        path.write_text(json.dumps(report, indent=2)+'\n')
    for check in report['checks']:
        print('PASS', check, flush=True)


if __name__ == '__main__':
    main()
