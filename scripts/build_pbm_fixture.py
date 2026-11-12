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

"""Build the pinned combined PBM/mongod fixture and verify copied vendor binaries."""
import argparse
import json
import pathlib
import shutil
import subprocess
import tempfile

from image_evidence import ROOT, local_image_id
from test_database import PERCONA
from test_database_pbm import PBM, COMBINED
from test_database_backup import sha


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--engine', default='podman', choices=['podman', 'docker'])
    args = parser.parse_args()
    output = ROOT/'artifacts'
    names = ['interop/pbm/Dockerfile', 'interop/pbm/node.sh', 'interop/pbm/command.sh',
        'scripts/build_pbm_fixture.py', 'LICENSE', 'NOTICE']
    hashes = {name: sha(ROOT/name) for name in names}
    # A fresh checkout (a CI runner) may lack both.
    output.mkdir(exist_ok=True)
    (ROOT/'.cache').mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='pbm-image-', dir=ROOT/'.cache') as directory:
        context = pathlib.Path(directory)
        for name in ['Dockerfile', 'node.sh', 'command.sh']:
            shutil.copy2(ROOT/'interop/pbm'/name, context/name)
        for name in ['node.sh', 'command.sh']:
            (context/name).chmod(0o755)
        for name in ['LICENSE', 'NOTICE']:
            shutil.copyfile(ROOT/name, context/name)
        cmd = [args.engine, 'build'] + (['--format', 'docker'] if args.engine == 'podman' else [])
        with (output/'pbm-image-build.log').open('w') as log:
            subprocess.run(cmd+['-t', COMBINED, str(context)], check=True, stdout=log, stderr=subprocess.STDOUT)
    def capture(image, entrypoint, *arguments):
        return subprocess.check_output([args.engine, 'run', '--rm', '--entrypoint', entrypoint,
            image, *arguments], text=True, stderr=subprocess.STDOUT, timeout=60)
    binaries = {}
    for executable, upstream in [('mongod', PERCONA), ('pbm', PBM), ('pbm-agent', PBM)]:
        digest = capture(COMBINED, 'sha256sum', '/usr/bin/'+executable).split()[0]
        assert digest == capture(upstream, 'sha256sum', '/usr/bin/'+executable).split()[0]
        binaries[executable] = digest
    for filename in ['LICENSE.Dockerfile', 'LICENSE.Percona-Backup-for-MongoDB']:
        assert capture(COMBINED, 'cat', '/usr/share/licenses/pbm-upstream/'+filename) == capture(PBM, 'cat', '/licenses/'+filename)
    for filename in ['LICENSE', 'NOTICE']:
        assert capture(COMBINED, 'cat', '/usr/share/licenses/keytend-kmip-server-qualification/'+filename) == (ROOT/filename).read_text()
    version = capture(COMBINED, 'pbm', 'version')
    assert 'Version:   2.17.0' in version
    result = dict(status='verified_fixture_image', image_tag=COMBINED,
        image_config_id=local_image_id(args.engine, COMBINED), percona_image=PERCONA, pbm_image=PBM,
        source_sha256=hashes, binaries_sha256=binaries, pbm_version=version,
        limits='Combined disposable qualification image. Vendor binaries and bundled license files are unchanged; no vendor/image signature attestation, vulnerability qualification or production deployment approval.')
    (output/'pbm-fixture-image.json').write_text(json.dumps(result, indent=2)+'\n')
    print('PASS pinned combined fixture image and vendor binary/license preservation', result['image_config_id'])


if __name__ == '__main__':
    main()
