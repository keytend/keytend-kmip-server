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

"""Fetch, verify and use the published keytend-kmip Java SDK release; never build or modify it.

The pin is interop/java/keytend-kmip-release.json. The release ZIP and its SHA256SUMS
are downloaded with `gh release download` into .cache/keytend-kmip-<version>/ and used
only when:

- the ZIP and its .sha256 file match the pinned sizes and digests, and the published
  SHA256SUMS matches its pinned digest;
- keytend-kmip-<version>.zip.asc and SHA256SUMS.asc verify against
  signing/keytend-release-key.asc with the Keytend release key as primary (scripts/gpg_tool.py);
- every ZIP entry stays inside one top directory, is not a link and is extracted
  byte-identically, the embedded release.json matches the pin, and every artifact and
  SHA256SUMS line matches its digest and is listed, with the packaged SHA256SUMS itself,
  in the signed SHA256SUMS.

The previous release's SDK JAR (pin `previous`), for the catalog's upgrade and rollback case,
is read from that release's ZIP and checked against its pinned digests. The test-only H2 JAR the catalog's consumer-database cases need is fetched from Maven
Central and checked against its pinned SHA-256 and SHA-1. The SDK's runtime dependencies
(slf4j-api; jackson-core for the integration classes) are the JARs the release ZIP ships,
listed under runtime_jars in the pin. Adapters in interop/java/
(package dev.keytend.kmip.interop, beside the SDK's own interop classes) are compiled
with javac against the release JARs.
"""
import argparse
import functools
import hashlib
import json
import os
import pathlib
import shutil
import stat
import subprocess
import sys
import urllib.request
import zipfile

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import gpg_tool  # noqa: E402

ROOT = pathlib.Path(__file__).resolve().parents[1]
MANIFEST = ROOT/'interop/java/keytend-kmip-release.json'
PIN = json.loads(MANIFEST.read_text())
ADAPTERS = ROOT/'interop/java'
CACHE = ROOT/f'.cache/keytend-kmip-{PIN["version"]}'
TOP = f'keytend-kmip-{PIN["version"]}'
SERVER_ID = 'keytend-kmip-server'


def sha(path):
    return hashlib.sha256(pathlib.Path(path).read_bytes()).hexdigest()


def download():
    CACHE.mkdir(parents=True, exist_ok=True)
    archive = CACHE/PIN['asset']
    wanted = [archive, archive.with_name(archive.name+'.sha256'), archive.with_name(archive.name+'.asc'), CACHE/'SHA256SUMS', CACHE/'SHA256SUMS.asc']
    if not all(p.exists() for p in wanted):
        subprocess.run(['gh', 'release', 'download', PIN['tag'], '--repo', PIN['repository'], '--dir', str(CACHE), '--skip-existing',
                        '--pattern', PIN['asset']+'*', '--pattern', 'SHA256SUMS*'], check=True)
    return archive


def verify_signatures(archive):
    records = {}
    for name in PIN['openpgp']['signed']:
        path = CACHE/name
        record = gpg_tool.verify(path, path.with_name(path.name+'.asc'), primary=PIN['openpgp']['primary'])
        if not record['verified']:
            raise SystemExit(f'{name}.asc does not verify against the Keytend release key: {record.get("reason")}')
        records[name] = dict(signer=record['signer_fingerprint'], primary=record['primary_fingerprint'])
    return records


@functools.cache  # verified once per process; adapters() and the lanes share the result
def release():
    """(directory, [sdk jar, integration jar, runtime jars...], evidence) of the verified, extracted release."""
    archive = download()
    checksum = archive.with_name(archive.name+'.sha256')
    assert archive.stat().st_size == PIN['asset_bytes'] and sha(archive) == PIN['asset_sha256'], 'release ZIP differs from pin'
    assert sha(checksum) == PIN['checksum_sha256'] and checksum.read_text().split() == [PIN['asset_sha256'], PIN['asset']], 'release .sha256 differs from pin'
    assert sha(CACHE/'SHA256SUMS') == PIN['sums_sha256'], 'published SHA256SUMS differs from pin'
    signatures = verify_signatures(archive)
    directory = CACHE/TOP
    with zipfile.ZipFile(archive) as z:
        names, total = set(), 0
        for entry in z.infolist():
            path = pathlib.PurePosixPath(entry.filename)
            assert not path.is_absolute() and '..' not in path.parts and path.parts[0] == TOP, 'unexpected ZIP entry '+entry.filename
            assert not stat.S_ISLNK(entry.external_attr >> 16) and entry.filename not in names
            names.add(entry.filename)
            total += entry.file_size
            assert total <= 64*1024*1024, 'unexpected unpacked size'
        if not directory.exists():
            partial = CACHE/(TOP+'.partial')
            shutil.rmtree(partial, ignore_errors=True)
            z.extractall(partial)
            for entry in z.infolist():
                if not entry.is_dir():
                    (partial/entry.filename).chmod((entry.external_attr >> 16) & 0o755 or 0o644)
            (partial/TOP).rename(directory)
            partial.rmdir()
        for entry in z.infolist():
            if not entry.is_dir():
                assert (CACHE/entry.filename).read_bytes() == z.read(entry), 'modified release entry: '+entry.filename
    data = json.loads((directory/'release.json').read_text())
    for key in ['version', 'tag', 'commit', 'java_release', 'artifacts']:
        assert data[key] == PIN[key], 'release.json differs from pin: '+key
    for artifact in data['artifacts']:
        path = directory/artifact['path']
        assert path.stat().st_size == artifact['bytes'] and sha(path) == artifact['sha256'], 'artifact differs: '+artifact['path']
    # The signed SHA256SUMS lists the ZIP and every packaged file under TOP/, the packaged SHA256SUMS included.
    signed = {name: digest for digest, name in (line.split() for line in (CACHE/'SHA256SUMS').read_text().splitlines())}
    assert signed.get(PIN['asset']) == PIN['asset_sha256'], 'signed SHA256SUMS does not list the pinned ZIP'
    assert signed.get(TOP+'/SHA256SUMS') == sha(directory/'SHA256SUMS'), 'packaged SHA256SUMS differs from the signed list'
    for line in (directory/'SHA256SUMS').read_text().splitlines():
        digest, name = line.split()
        path = pathlib.PurePosixPath(name)
        assert not path.is_absolute() and '..' not in path.parts
        assert sha(directory/name) == digest, 'packaged SHA256SUMS mismatch: '+name
        assert signed.get(f'{TOP}/{name}') == digest, 'packaged file missing from the signed SHA256SUMS: '+name
    jars = [directory/PIN['sdk_jar'], directory/PIN['integration_jar'], *(directory/jar for jar in PIN['runtime_jars'])]
    evidence = dict(kind='published_release_binary_jars', client=PIN['client'], repository=PIN['repository'], url=PIN['url'], tag=PIN['tag'],
                    version=PIN['version'], commit=PIN['commit'], zip_sha256=sha(archive), openpgp=signatures,
                    jars={str(p.relative_to(directory)): sha(p) for p in jars},
                    runtime_dependencies='from the release ZIP: '+', '.join(pathlib.PurePosixPath(jar).name for jar in PIN['runtime_jars'])
                    +'; consumer-database catalog cases: test-only H2 '+PIN['h2']['version'])
    return directory, jars, evidence


def previous_jar():
    """The previous release's SDK JAR (pin `previous`), for the catalog's upgrade and rollback case.

    Its ZIP comes from the GitHub release into .cache/keytend-kmip-<previous version>/ and must
    match the pinned size and SHA-256; the one JAR is read from it and checked against its own
    pinned digest. The pin, committed here, is the trust root; the ZIP was verified with its
    signatures when it was the current release."""
    prev = PIN['previous']
    cache = ROOT/f'.cache/keytend-kmip-{prev["version"]}'
    archive = cache/prev['asset']
    if not archive.exists():
        cache.mkdir(parents=True, exist_ok=True)
        subprocess.run(['gh', 'release', 'download', prev['tag'], '--repo', PIN['repository'], '--dir', str(cache), '--pattern', prev['asset']],
                       check=True)
    if archive.stat().st_size != prev['asset_bytes'] or sha(archive) != prev['asset_sha256']:
        raise SystemExit(f'{archive} differs from the pinned previous release')
    jar = cache/'previous'/pathlib.PurePosixPath(prev['sdk_jar']).name
    with zipfile.ZipFile(archive) as z:
        data = z.read(prev['sdk_jar'])
    if len(data) != prev['sdk_jar_bytes'] or hashlib.sha256(data).hexdigest() != prev['sdk_jar_sha256']:
        raise SystemExit(f'{prev["sdk_jar"]} in {archive} differs from the pinned previous SDK JAR')
    if not jar.exists() or jar.read_bytes() != data:
        jar.parent.mkdir(parents=True, exist_ok=True)
        jar.write_bytes(data)
    return jar


def h2_jar():
    pin = PIN['h2']
    path = ROOT/'.cache/h2'/f'h2-{pin["version"]}.jar'
    if not path.exists():
        path.parent.mkdir(parents=True, exist_ok=True)
        partial = path.with_name(path.name+'.partial')
        with urllib.request.urlopen(pin['url'], timeout=120) as response:
            data = response.read(16*1024*1024+1)
        assert len(data) <= 16*1024*1024, 'H2 download larger than expected'
        partial.write_bytes(data)
        partial.rename(path)
    data = path.read_bytes()
    if hashlib.sha256(data).hexdigest() != pin['sha256'] or hashlib.sha1(data).hexdigest() != pin['sha1']:
        raise SystemExit(f'{path} differs from the pinned H2 {pin["version"]}')
    return path


def major(java):
    """(major version, runtime version) of a java executable."""
    import re
    out = subprocess.run([str(java), '-XshowSettings:properties', '-version'], capture_output=True, text=True).stderr
    return int(re.search(r'java\.specification\.version = (\d+)', out).group(1)), re.search(r'java\.runtime\.version = (\S+)', out).group(1)


def javac(java=None):
    """javac beside the given java executable, else $JAVA_HOME/bin/javac, else javac on PATH."""
    for candidate in ([pathlib.Path(java).with_name('javac')] if java else []) + (
            [pathlib.Path(os.environ['JAVA_HOME'])/'bin/javac'] if os.environ.get('JAVA_HOME') else []):
        if candidate.is_file():
            return str(candidate)
    found = shutil.which('javac')
    if not found:
        raise SystemExit('javac not found: set JAVA_HOME or pass a JDK java executable')
    return found


def adapters(names, classes, java=None, h2=False):
    """Compile interop/java/<name>.java against the release; return the runtime classpath string."""
    _, jars, _ = release()
    entries = [*jars] + ([h2_jar()] if h2 else [])
    classes = pathlib.Path(classes)
    shutil.rmtree(classes, ignore_errors=True)
    classes.mkdir(parents=True)
    sources = [ADAPTERS/f'{name}.java' for name in names]
    subprocess.run([javac(java), '--release', str(PIN['java_release']), '-cp', os.pathsep.join(map(str, entries)), '-d', str(classes),
                    *map(str, sources)], check=True)
    return os.pathsep.join(map(str, [classes, *entries]))


def main():
    argparse.ArgumentParser(description=__doc__.splitlines()[0]).parse_args()
    print(json.dumps(release()[2], indent=2))


if __name__ == '__main__':
    main()
