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

"""Pinned Helm release binary and helpers for the chart in deploy/helm.

The release archive is downloaded once and checked against the SHA-256 pinned
below, and only the `helm` executable is extracted into .cache/bin. No system
install. The helpers below (rendering, metric and latest.json checks) are used
by scripts/test_helm_chart.py and tested in scripts/test_helm_tool.py.

    scripts/helm_tool.py fetch      # download, check and print the path
    scripts/helm_tool.py version
"""
import argparse
import hashlib
import io
import json
import pathlib
import re
import platform
import subprocess
import tarfile
import urllib.request

import yaml

ROOT = pathlib.Path(__file__).resolve().parents[1]
CHART = ROOT/'deploy/helm/keytend-kmip-server'
# The chart's copy of the suggested alert rules; test_helm_tool.py keeps it equal to the original.
CHART_RULES = CHART/'files/prometheus-rules.yaml'
RULES = ROOT/'deploy/prometheus/keytend-kmip-server-rules.yaml'
VERSION = '4.3.1'
# From https://get.helm.sh/helm-v4.3.1-linux-<arch>.tar.gz.sha256sum, matching the
# digests listed in the GitHub release notes of v4.3.1 when the pin was taken.
SHA256 = {
    'amd64': '0403a88ae20913d11b10a2467b50087721fea7581736da6b9d3992f5357fe54b',
    'arm64': '8cf8f66ecbc252ac8f7f06cca68aba88508ddfde3a6a34feb1678ad1694b4f88',
}
# SHA-256 of the `helm` executable inside each pinned archive, so a cached binary is checked
# without keeping the archive.
BINARY_SHA256 = {
    'amd64': 'b66cb19f2b31f9d427632ea6c4b4a1ff89b74ecaeaee323cd166da41a7af53bd',
    'arm64': 'd459cbff1331af4326a6f97ea83c547742b4056dac7404f20fc436c084178c43',
}
URL = 'https://get.helm.sh/helm-v{version}-linux-{arch}.tar.gz'
LIMIT = 200*1024*1024


def sha256(path):
    with pathlib.Path(path).open('rb') as file:
        return hashlib.file_digest(file, 'sha256').hexdigest()


def host_arch():
    return {'x86_64': 'amd64', 'aarch64': 'arm64', 'arm64': 'arm64'}[platform.machine()]


def cached(arch=None):
    arch = arch or host_arch()
    return ROOT/'.cache/bin'/f'helm-{VERSION}-linux-{arch}'


def extract(archive, arch):
    """The `linux-<arch>/helm` member of a release archive, as bytes; nothing else is read."""
    with tarfile.open(fileobj=io.BytesIO(archive), mode='r:gz') as tar:
        member = tar.getmember(f'linux-{arch}/helm')
        if not member.isfile():
            raise ValueError('helm member is not a regular file')
        return tar.extractfile(member).read()


def binary(arch=None):
    """Path of the pinned helm binary, downloading and checking the release archive on first use."""
    arch = arch or host_arch()
    path = cached(arch)
    if not path.exists():
        path.parent.mkdir(parents=True, exist_ok=True)
        with urllib.request.urlopen(URL.format(version=VERSION, arch=arch), timeout=120) as response:
            data = response.read(LIMIT+1)
        assert len(data) <= LIMIT, 'helm download is unexpectedly large'
        assert hashlib.sha256(data).hexdigest() == SHA256[arch], 'helm release archive SHA-256 differs from the pin'
        executable = extract(data, arch)
        assert hashlib.sha256(executable).hexdigest() == BINARY_SHA256[arch], 'helm executable SHA-256 differs from the pin'
        temporary = path.with_suffix('.partial')
        temporary.write_bytes(executable)
        temporary.chmod(0o700)
        temporary.replace(path)
    assert sha256(path) == BINARY_SHA256[arch], 'cached helm binary SHA-256 differs from the pin: '+str(path)
    return path


def run(args, check=True, helm=None, **kwargs):
    return subprocess.run([str(helm or binary()), *map(str, args)], check=check, text=True, capture_output=True, **kwargs)


def documents(text):
    """The non-empty YAML documents of rendered manifests."""
    return [d for d in yaml.safe_load_all(text) if d]


def render(values, release='keytend-kmip-server', namespace='keytend-kmip-server', helm=None, extra=()):
    """`helm template` of the chart with a values mapping; returns (documents, raw text)."""
    out = run(['template', release, CHART, '--namespace', namespace, '--values', '-', *extra],
              helm=helm, input=json.dumps(values))
    return documents(out.stdout), out.stdout


def find(docs, kind, name=None):
    matches = [d for d in docs if d['kind'] == kind and (name is None or d['metadata']['name'] == name)]
    assert len(matches) == 1, f'expected one {kind} {name or ""}, found {len(matches)}'
    return matches[0]


def metric_value(text, name, labels=None):
    """Value of one sample in the Prometheus text format (labels must match those given)."""
    for line in text.splitlines():
        if line.startswith('#') or not line.startswith(name):
            continue
        match = re.match(r'^([A-Za-z_:][A-Za-z0-9_:]*)(\{[^}]*\})?\s+(\S+)', line)
        if not match or match.group(1) != name:
            continue
        found = dict(re.findall(r'(\w+)="((?:[^"\\]|\\.)*)"', match.group(2) or ''))
        if all(found.get(k) == v for k, v in (labels or {}).items()):
            return float(match.group(3))
    return None


def latest_problems(latest, listing=()):
    """What is wrong with a backup directory's latest.json (empty when it describes a verified backup)."""
    problems = []
    for field in ('file', 'bytes', 'created', 'created_unix', 'verified', 'verification', 'pruned'):
        if field not in latest:
            problems.append(f'missing {field}')
    if latest.get('verified') is not True:
        problems.append('not verified')
    name = pathlib.PurePosixPath(str(latest.get('file', ''))).name
    if not re.fullmatch(r'backup-\d{8}T\d{6}Z\.sqlite', name):
        problems.append(f'unexpected file name {name!r}')
    if listing and name not in listing:
        problems.append(f'{name} is not in the directory')
    verification = latest.get('verification') or {}
    if not isinstance(verification.get('objects'), int) or not isinstance(verification.get('audit_entries'), int):
        problems.append('verification counts missing')
    return problems


def rules_in_sync():
    """The chart's rule file is byte-identical to deploy/prometheus's."""
    return CHART_RULES.read_bytes() == RULES.read_bytes()


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument('command', choices=['fetch', 'version'])
    args = parser.parse_args()
    if args.command == 'fetch':
        print(binary(), sha256(binary()))
    else:
        print(run(['version', '--short']).stdout.strip())


if __name__ == '__main__':
    main()
