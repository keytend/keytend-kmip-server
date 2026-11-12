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

"""Check the Dockerfile pins against what Red Hat publishes now.

Compares each pinned RPM (runtime root and build stage) with the newest version
dnf selects from the UBI 9 repositories in the pinned builder, and each pinned
UBI base image digest with the registry's current digest for the tag and that
pin's architecture (linux/amd64 and linux/arm64), and records the current
multi-architecture index digest beside the one the pins were taken from (an
index also moves for other architectures, so it is reported, not checked).
It queries the registry and repositories at run time and needs no credentials.

Exit status: 0 when every pin is current; 1 when a pin is behind but still
published; 2 when a pinned package version or base image digest is no longer
published (the build would fail), or when the check could not run (network,
registry or repository error), which is never a pass. --annotate prints each
problem as a GitHub Actions annotation of that level; a missing pin or a failed
check is always an error. A current pin is not a vulnerability-free or
supported-runtime claim.
"""
import argparse
import datetime
import hashlib
import json
import re
import subprocess
import sys
import time
import urllib.error
import urllib.request
import uuid

from image_evidence import ROOT, base_indexes

REGISTRY = 'https://registry.access.redhat.com/v2/'
ACCEPT = ', '.join(['application/vnd.oci.image.index.v1+json', 'application/vnd.docker.distribution.manifest.list.v2+json',
    'application/vnd.oci.image.manifest.v1+json', 'application/vnd.docker.distribution.manifest.v2+json'])
OUTPUT = ROOT/'artifacts/image-updates.json'
REFRESH = 'refresh the pins before a release (docs/release-builds.md)'


class CheckError(Exception):
    """The check could not run (network, registry or repository error); never a pass."""


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


def fetch(url, attempts=3):
    """The body at url (UBI is anonymously pullable); None for a 404. Transient errors are retried."""
    for attempt in range(1, attempts+1):
        try:
            with urllib.request.urlopen(urllib.request.Request(url, headers={'Accept': ACCEPT}), timeout=60) as response:
                return response.read()
        except urllib.error.HTTPError as error:
            if error.code == 404:
                return None
            problem = f'HTTP {error.code} {error.reason}'
        except (urllib.error.URLError, OSError) as error:
            problem = str(getattr(error, 'reason', error))
        if attempt < attempts:
            time.sleep(5*attempt)
    raise CheckError(f'cannot read {url} after {attempts} attempts: {problem}')


def registry_index(repository, tag):
    """(index digest, {architecture: manifest digest}) the tag currently resolves to."""
    raw = fetch(f'{REGISTRY}{repository}/manifests/{tag}')
    try:
        index = json.loads(raw)
        manifests = {m['platform']['architecture']: m['digest'] for m in index['manifests'] if m['platform']['os'] == 'linux'}
    except (TypeError, ValueError, KeyError) as error:
        raise CheckError(f'{repository}:{tag} is not a multi-architecture index in the registry ({error!r})') from None
    return 'sha256:'+hashlib.sha256(raw).hexdigest(), manifests


def published(repository, digest):
    """Whether the registry still serves the manifest digest."""
    return fetch(f'{REGISTRY}{repository}/manifests/{digest}') is not None


def query(engine, image, pinned):
    """({name: newest version-release}, {name: pinned version-release found}) from the UBI 9 repositories, in one
    container of the pinned builder. Unreachable repositories fail (skip_if_unavailable=False)."""
    common = 'dnf -q --setopt=skip_if_unavailable=False repoquery --arch x86_64,noarch --qf "%{name}\t%{version}-%{release}"'
    script = f'set -e; {common} --latest-limit 1 "$@"; echo ---; {common} ' + ' '.join(f'{n}-{v}' for n, v in sorted(pinned.items()))
    command = [engine, 'run', '--rm', '--name', 'keytend-update-check-'+uuid.uuid4().hex[:12], image, 'bash', '-c', script, 'query', *sorted(pinned)]
    try:
        output = subprocess.run(command, capture_output=True, text=True, timeout=900)
    except subprocess.TimeoutExpired:
        raise CheckError('dnf repoquery in the pinned builder timed out') from None
    if output.returncode or '---' not in output.stdout.splitlines():
        raise CheckError(f'dnf repoquery in the pinned builder failed (exit {output.returncode}): {output.stderr.strip()[-1500:]}')
    latest, found = output.stdout.split('---\n', 1) if '---\n' in output.stdout else (output.stdout, '')
    table = lambda text: dict(line.split('\t') for line in text.splitlines() if '\t' in line)
    return table(latest), table(found)


def describe(item):
    if 'package' in item:
        if item.get('missing'):
            return f"{item['scope']} package {item['package']}-{item['pinned']} is no longer in the UBI 9 repositories (newest: {item['candidate']}); the build fails until it is updated"
        return f"{item['scope']} package {item['package']} is pinned at {item['pinned']}; {item['candidate']} is available"
    if item.get('missing'):
        return f"{item['stage']} ({item['platform']}) {item['digest']} is no longer in the registry; the build fails until it is updated"
    return f"{item['stage']} ({item['platform']}) is pinned at {item['digest']}; {item['repository']}:{item['tag']} is {item['registry_digest']}"


def check(engine):
    OUTPUT.unlink(missing_ok=True)  # a failed check leaves no earlier report behind
    dockerfile = (ROOT/'Dockerfile').read_text()
    runtime, build = nvrs(arg(dockerfile, 'RUNTIME_PACKAGES')), nvrs(arg(dockerfile, 'BUILD_PACKAGES'))
    images = bases(dockerfile)
    available, found = query(engine, arg(dockerfile, 'UBI_BUILDER'), {**runtime, **build})
    unknown = sorted((set(runtime) | set(build)) - set(available))
    if unknown:
        raise CheckError('the UBI 9 repositories returned no version of '+', '.join(unknown))
    packages = []
    for scope, pinned in [('runtime', runtime), ('build', build)]:
        for name, version in sorted(pinned.items()):
            packages.append(dict(scope=scope, package=name, pinned=version, candidate=available[name], current=available[name] == version,
                                 missing=found.get(name) != version))
    indexes = {}
    for image in images:
        if image['repository'] not in indexes:
            indexes[image['repository']] = registry_index(image['repository'], image['tag'])
        image['registry_digest'] = indexes[image['repository']][1].get(image['platform'].split('/')[1])
        if not image['registry_digest']:
            raise CheckError(f"{image['repository']}:{image['tag']} has no {image['platform']} manifest")
        image['current'] = image['registry_digest'] == image['digest']
        image['missing'] = not image['current'] and not published(image['repository'], image['digest'])
    pinned_indexes = {reference.split('@')[0].split('/', 1)[1]: reference.split('@')[1] for reference in base_indexes().values()}
    index_report = [dict(repository=name, pinned_from=pinned_indexes.get(name), registry_index=digest, current=pinned_indexes.get(name) == digest)
                    for name, (digest, _) in sorted(indexes.items())]
    behind = [p for p in packages if not p['current']] + [i for i in images if not i['current']]
    missing = [item for item in behind if item['missing']]
    report = dict(status='pins_missing' if missing else 'updates_available' if behind else 'pins_current',
        checked_at=datetime.datetime.now(datetime.timezone.utc).isoformat(),
        dockerfile_sha256=hashlib.sha256(dockerfile.encode()).hexdigest(),
        packages=packages, base_images=images, base_indexes=index_report,
        limits='Drift against the UBI 9 repositories dnf and the registry return at check time. Not a vulnerability, support-lifecycle, FIPS-certificate or production assessment: a newer openssl-fips-provider build is not necessarily the CMVP-validated module.')
    OUTPUT.parent.mkdir(exist_ok=True)
    OUTPUT.write_text(json.dumps(report, indent=2)+'\n')
    return report, behind


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--engine', default='podman', choices=['podman', 'docker'])
    parser.add_argument('--annotate', choices=['error', 'warning'], help='also print each stale pin as a GitHub Actions annotation of this level')
    args = parser.parse_args()
    annotate = lambda level, title, text: args.annotate and print(f'::{level} title={title}::{text}', flush=True)
    try:
        report, behind = check(args.engine)
    except Exception as error:  # any failure to check exits 2, never 1 (stale), which a manual run tolerates
        if not isinstance(error, CheckError):
            error = f'{type(error).__name__}: {error}'
        annotate('error', 'Image pin check failed', f'{error}. The check is not a pass.')
        print(f'error: the image pin check failed, which is not a pass: {error}', file=sys.stderr, flush=True)
        raise SystemExit(2)
    for item in behind:
        print('MISSING' if item['missing'] else 'BEHIND', json.dumps(item), flush=True)
        if item['missing']:
            annotate('error', 'Pinned image input no longer published', describe(item))
        else:
            annotate(args.annotate, 'Stale image pin', describe(item)+'; '+REFRESH)
    print(report['status'], flush=True)
    if any(item['missing'] for item in behind):
        print(f'error: a pinned package or base image is no longer published; {REFRESH}', file=sys.stderr, flush=True)
        raise SystemExit(2)
    if behind:
        print(f'pins are behind; {REFRESH}', file=sys.stderr, flush=True)
        raise SystemExit(1)


if __name__ == '__main__':
    main()
