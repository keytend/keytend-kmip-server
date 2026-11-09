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

"""Report drift between Dockerfile pins and currently published upstream versions.

Compares each pinned RPM (runtime root and build stage) with the newest version
dnf selects from the UBI 9 repositories in the pinned builder, and each pinned
UBI base image digest with the registry's current digest for the tag and that
pin's architecture (linux/amd64 and linux/arm64), and records the current
multi-architecture index digest beside the one the pins were taken from. Exits 1 when any pin is behind. A current pin is not a vulnerability-free
or supported-runtime claim.
"""
import argparse
import datetime
import hashlib
import json
import re
import subprocess
import urllib.request
import uuid

from image_evidence import ROOT, base_indexes

REGISTRY = 'https://registry.access.redhat.com/v2/'
ACCEPT = ', '.join(['application/vnd.oci.image.index.v1+json', 'application/vnd.docker.distribution.manifest.list.v2+json',
    'application/vnd.oci.image.manifest.v1+json', 'application/vnd.docker.distribution.manifest.v2+json'])


def arg(text, name):
    return re.search(rf'^ARG {name}="?([^"\n]+)"?$', text, re.M).group(1)


def nvrs(value):
    return {nvr.rsplit('-', 2)[0]: '-'.join(nvr.rsplit('-', 2)[1:]) for nvr in value.split()}


def bases(text):
    images = []
    for stage, arch in [('UBI_BUILDER', 'amd64'), ('UBI_MICRO', 'amd64'), ('UBI_BUILDER_ARM64', 'arm64'), ('UBI_MICRO_ARM64', 'arm64')]:
        match = re.fullmatch(r'registry\.access\.redhat\.com/(ubi9/[a-z0-9-]+)@(sha256:[0-9a-f]{64})', arg(text, stage))
        images.append(dict(stage=stage, repository=match.group(1), tag='latest', digest=match.group(2), platform='linux/'+arch))
    return images


def registry_index(repository, tag):
    """(index digest, {architecture: manifest digest}) the tag currently resolves to (UBI is anonymously pullable)."""
    request = urllib.request.Request(f'{REGISTRY}{repository}/manifests/{tag}', headers={'Accept': ACCEPT})
    with urllib.request.urlopen(request, timeout=60) as response:
        raw = response.read()
    index = json.loads(raw)
    return 'sha256:'+hashlib.sha256(raw).hexdigest(), {m['platform']['architecture']: m['digest'] for m in index.get('manifests', []) if m['platform']['os'] == 'linux'}


def registry_digest(repository, tag, arch='amd64'):
    """The linux/<arch> manifest digest the tag currently resolves to."""
    digest = registry_index(repository, tag)[1].get(arch)
    assert digest, f'no linux/{arch} manifest for '+repository
    return digest


def candidates(engine, image, names):
    output = subprocess.check_output([engine, 'run', '--rm', '--name', 'keytend-update-check-'+uuid.uuid4().hex[:12], image,
        'dnf', '-q', 'repoquery', '--latest-limit', '1', '--arch', 'x86_64,noarch', '--qf', '%{name}\t%{version}-%{release}', *names],
        text=True, timeout=600)
    return dict(line.split('\t') for line in output.splitlines() if '\t' in line)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--engine', default='podman', choices=['podman', 'docker'])
    args = parser.parse_args()
    dockerfile = (ROOT/'Dockerfile').read_text()
    runtime, build = nvrs(arg(dockerfile, 'RUNTIME_PACKAGES')), nvrs(arg(dockerfile, 'BUILD_PACKAGES'))
    images = bases(dockerfile)
    available = candidates(args.engine, arg(dockerfile, 'UBI_BUILDER'), sorted(set(runtime) | set(build)))
    packages = []
    for scope, pinned in [('runtime', runtime), ('build', build)]:
        for name, version in sorted(pinned.items()):
            packages.append(dict(scope=scope, package=name, pinned=version, candidate=available.get(name), current=available.get(name) == version))
    indexes = {}
    for image in images:
        if image['repository'] not in indexes:
            indexes[image['repository']] = registry_index(image['repository'], image['tag'])
        image['registry_digest'] = indexes[image['repository']][1].get(image['platform'].split('/')[1])
        image['current'] = image['registry_digest'] == image['digest']
    pinned_indexes = {reference.split('@')[0].split('/', 1)[1]: reference.split('@')[1] for reference in base_indexes().values()}
    index_report = [dict(repository=name, pinned_from=pinned_indexes.get(name), registry_index=digest, current=pinned_indexes.get(name) == digest)
                    for name, (digest, _) in sorted(indexes.items())]
    behind = [p for p in packages if not p['current']] + [i for i in images if not i['current']]
    report = dict(status='updates_available' if behind else 'pins_current',
        checked_at=datetime.datetime.now(datetime.timezone.utc).isoformat(),
        dockerfile_sha256=hashlib.sha256(dockerfile.encode()).hexdigest(),
        packages=packages, base_images=images, base_indexes=index_report,
        limits='Drift against the UBI 9 repositories dnf and the registry return at check time. Not a vulnerability, support-lifecycle, FIPS-certificate or production assessment: a newer openssl-fips-provider build is not necessarily the CMVP-validated module.')
    output = ROOT/'artifacts/image-updates.json'
    output.parent.mkdir(exist_ok=True)
    output.write_text(json.dumps(report, indent=2)+'\n')
    for item in behind:
        print('BEHIND', json.dumps(item), flush=True)
    print(report['status'], flush=True)
    if behind:
        raise SystemExit(1)


if __name__ == '__main__':
    main()
