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

"""Assemble, sign and verify one release set of image artifacts.

assemble  copies each platform's packaged outputs (scripts/package.py --arch) into
          <dir>/linux-<arch>/, builds the multi-architecture OCI index with
          `podman manifest`, copies each --extra file (the test reports archive)
          into <dir>/reports/ and writes SHA256SUMS over every file;
sign      signs SHA256SUMS twice: a cosign blob signature, SHA256SUMS.sigstore.json
          (offline key, no transparency log; with --keyless, the release
          workflow's GitHub OIDC identity, logged in Rekor), and a detached OpenPGP signature,
          SHA256SUMS.asc, by this project's signing subkey of the Keytend release
          key (scripts/gpg_tool.py);
verify    checks both signatures (cosign against signing/cosign.pub, or a keyless
          bundle against the release workflow identity for v<version>) and
          signing/keytend-release-key.asc, every listed digest, that each
          required platform is present and that the image index covers exactly
          the release's platforms. Writes <dir>/verification.json.

Signatures prove which key signed which bytes. They are not a production key
ceremony, an HSM-held key or a transparency-log record (docs/release-signing.md).
"""
import argparse
import datetime
import hashlib
import json
import pathlib
import shutil
import subprocess
import sys
import tarfile
import tomllib
import uuid

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import cosign_tool
import gpg_tool
import release_provenance
from image_evidence import PLATFORMS, ROOT, artifacts_dir, local_image_id
from image_rootfs import Rootfs

VERSION = tomllib.loads((ROOT/'Cargo.toml').read_text())['package']['version']
SUMS = 'SHA256SUMS'
COSIGN = SUMS+'.sigstore.json'
OPENPGP = SUMS+gpg_tool.SIGNATURE_SUFFIX
# Not listed in SHA256SUMS: the manifest itself, its two signatures and the verifier's own report.
UNLISTED = {SUMS, COSIGN, OPENPGP, 'verification.json'}
OCI_INDEX = 'application/vnd.oci.image.index.v1+json'


def sha(path):
    with pathlib.Path(path).open('rb') as file:
        return hashlib.file_digest(file, 'sha256').hexdigest()


def now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat(timespec='seconds').replace('+00:00', 'Z')


def release_files(directory):
    """Files SHA256SUMS lists: everything except UNLISTED and temporaries."""
    directory = pathlib.Path(directory)
    return sorted(p.relative_to(directory).as_posix() for p in directory.rglob('*')
                  if p.is_file() and p.relative_to(directory).as_posix() not in UNLISTED and not p.name.startswith('.'))


def write_sums(directory):
    (pathlib.Path(directory)/SUMS).write_text(''.join(f'{sha(pathlib.Path(directory)/n)}  {n}\n' for n in release_files(directory)))


def read_sums(directory):
    return {line[66:]: line[:64] for line in (pathlib.Path(directory)/SUMS).read_text().splitlines() if line}


def oci_index(engine, platforms, directory):
    """Multi-architecture OCI index of the packaged images, pushed to an oci-archive; returns the summary."""
    out = directory/'index'
    out.mkdir(parents=True, exist_ok=True)
    archive = out/f'keytend-kmip-server-{VERSION}.oci.tar'
    images = {arch: json.loads((directory/f'linux-{arch}'/'image.json').read_text()) for arch in platforms}
    name = f'localhost/keytend-kmip-server-release-index:{VERSION}-{uuid.uuid4().hex[:8]}'
    subprocess.run([engine, 'manifest', 'create', name], check=True, stdout=subprocess.DEVNULL)
    try:
        for arch, image in images.items():
            subprocess.run([engine, 'manifest', 'add', name, 'containers-storage:'+image['image_id'].removeprefix('sha256:')], check=True, stdout=subprocess.DEVNULL)
        subprocess.run([engine, 'manifest', 'push', '--all', '--format', 'oci', '--quiet', name, f'oci-archive:{archive}:keytend-kmip-server:{VERSION}'], check=True)
    finally:
        subprocess.run([engine, 'manifest', 'rm', name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    summary = read_oci_index(archive)
    (out/'oci-image-index.json').write_bytes(summary.pop('raw'))
    for arch, image in images.items():
        entry = summary['manifests'][arch]
        entry.update(bind(entry, directory/f'linux-{arch}'/image['archive'], arch))
        entry.pop('config')
    summary.update(archive=archive.name, archive_sha256=sha(archive), images={arch: image['image_id'] for arch, image in images.items()})
    (out/'image-index.json').write_text(json.dumps(summary, indent=2)+'\n')
    return summary


def read_oci_index(archive):
    """Read the top-level image index of an oci-archive and each platform manifest's config digest."""
    with tarfile.open(archive) as tar:
        def blob(digest):
            return tar.extractfile('blobs/sha256/'+digest.removeprefix('sha256:')).read()
        layout = json.loads(tar.extractfile('index.json').read())
        indexes = [m for m in layout['manifests'] if m['mediaType'] == OCI_INDEX]
        assert len(indexes) == 1, 'oci-archive does not hold exactly one image index'
        raw = blob(indexes[0]['digest'])
        assert 'sha256:'+hashlib.sha256(raw).hexdigest() == indexes[0]['digest']
        index = json.loads(raw)
        manifests = {}
        for entry in index['manifests']:
            image = json.loads(blob(entry['digest']))
            assert 'sha256:'+hashlib.sha256(blob(entry['digest'])).hexdigest() == entry['digest']
            arch = entry['platform']['architecture']
            assert arch not in manifests, 'duplicate platform in index: '+arch
            config = json.loads(blob(image['config']['digest']))
            manifests[arch] = dict(platform=f"{entry['platform']['os']}/{arch}", manifest_digest=entry['digest'], config_digest=image['config']['digest'],
                                   config=config)
    return dict(media_type=index.get('mediaType'), index_digest=indexes[0]['digest'], manifests=manifests, raw=raw)


def bind(entry, archive, arch):
    """Tie an index manifest to a Docker archive. Converting to OCI rewrites the image configuration (so its
    digest differs from the Docker config digest, the podman image ID) and drops the Docker-only Healthcheck;
    the layers (rootfs diff_ids), platform and every retained runtime field must be identical."""
    oci, docker = entry['config'], Rootfs(archive).config
    assert entry['platform'] == f"linux/{arch}" and (oci['os'], oci['architecture']) == (docker['os'], docker['architecture']), 'platform differs: '+arch
    assert oci['rootfs'] == docker['rootfs'], 'index image layers differ from the Docker archive: '+arch
    differing = sorted(key for key, value in oci['config'].items() if docker['config'].get(key) != value)
    assert not differing, f'index image runtime configuration differs from the Docker archive ({arch}): {differing}'
    dropped = sorted(key for key, value in docker['config'].items() if value not in (None, '', [], {}, False) and key not in oci['config'] and key not in {'Image'})
    return dict(docker_config_digest='sha256:'+Rootfs(archive).config_id, rootfs_diff_ids=oci['rootfs']['diff_ids'],
                dropped_docker_config_fields=dropped)


def assemble(args):
    directory = args.dir
    assert not directory.exists() or not any(directory.iterdir()), f'{directory} is not empty'
    directory.mkdir(parents=True, exist_ok=True)
    record = dict(version=VERSION, platforms={}, assembled_at=now())
    for arch in args.platforms:
        source, target = artifacts_dir(arch), directory/f'linux-{arch}'
        target.mkdir()
        image = json.loads((source/'image.json').read_text())
        assert image.get('arch', 'amd64') == arch and image['platform'] == PLATFORMS[arch]['platform'], f'{source}/image.json is not {arch}'
        assert local_image_id(args.engine, image['image_id']) == image['image_id'].removeprefix('sha256:')
        shutil.copy2(source/image['archive'], target/image['archive'])
        assert sha(target/image['archive']) == image['sha256'], 'archive differs from its package manifest: '+arch
        for name in ['image.json', 'sbom.cdx.json', 'provenance.intoto.json']:
            shutil.copy2(source/name, target/name)
        release_provenance.check(json.loads((target/'provenance.intoto.json').read_text()), image['archive'], image['sha256'], image['image_id'])
        record['platforms'][arch] = dict(image_id=image['image_id'], archive=image['archive'], archive_sha256=image['sha256'])
    record['index'] = oci_index(args.engine, args.platforms, directory)
    # Other signed files, such as the test reports archive, under reports/.
    for extra in args.extra:
        (directory/'reports').mkdir(exist_ok=True)
        shutil.copy2(extra, directory/'reports'/extra.name)
        record.setdefault('reports', []).append('reports/'+extra.name)
    write_sums(directory)
    print(json.dumps(record, indent=1))


def sign(args):
    directory = args.dir
    keyless = getattr(args, "keyless", False)
    if not keyless:
        cosign_tool.check_private_key()
    gpg_tool.check_signing_keyring()
    if keyless:
        cosign_tool.sign_blob_keyless(directory/SUMS, directory/COSIGN)
    else:
        cosign_tool.sign_blob(directory/SUMS, directory/COSIGN)
    gpg_tool.sign_detached(directory/SUMS, directory/OPENPGP)
    checked = gpg_tool.verify(directory/SUMS, directory/OPENPGP, gpg_tool.PUBLIC_KEY, gpg_tool.RELEASE_FINGERPRINT)
    if not checked['verified']:
        raise SystemExit(f'{OPENPGP} does not verify against {gpg_tool.PUBLIC_KEY.name}: {checked.get("reason")}')
    print('signed', SUMS, f'({len(read_sums(directory))} files) with cosign and with OpenPGP subkey',
          checked['signer_fingerprint'], 'of', checked['primary_fingerprint'])


def check(directory, public_key, openpgp_key, require_platforms=(), primary=gpg_tool.RELEASE_FINGERPRINT):
    """Verify a release set; returns (report, failures). The report holds names and digests, no local paths."""
    directory = pathlib.Path(directory)
    failures = []
    def expect(condition, message):
        if not condition:
            failures.append(message)
        return condition
    tuf = pathlib.Path(cosign_tool.environment()['TUF_ROOT'])
    # A workstation release is signed with the key pair, a release workflow run keyless.
    keyless = (directory/COSIGN).exists() and cosign_tool.is_keyless(directory/COSIGN)
    if keyless:
        cosign_ok = cosign_tool.verify_blob_keyless(directory/SUMS, directory/COSIGN, VERSION).returncode == 0
        expect(cosign_ok, f'{COSIGN} is not a keyless signature by {cosign_tool.RELEASE_WORKFLOW} for v{VERSION}')
    else:
        cosign_ok = (directory/COSIGN).exists() and cosign_tool.verify_blob(directory/SUMS, directory/COSIGN, public_key).returncode == 0
        expect(cosign_ok, f'{COSIGN} does not verify against {pathlib.Path(public_key).name}')
    # OpenPGP: the release key's public part only; any subkey of it may have signed.
    openpgp = gpg_tool.verify(directory/SUMS, directory/OPENPGP, openpgp_key, primary) if (directory/OPENPGP).exists() else dict(
        signature=OPENPGP, verified=False, reason='missing')
    expect(openpgp['verified'], f'{OPENPGP} does not verify against the release key: {openpgp.get("reason")}')
    sums, names = read_sums(directory), release_files(directory)
    expect(set(sums) == set(names), f'SHA256SUMS lists {sorted(set(sums) ^ set(names))} differently from the release files')
    for name, digest in sums.items():
        expect((directory/name).is_file() and sha(directory/name) == digest, 'SHA256SUMS digest differs: '+name)
    platforms = sorted(p.name.removeprefix('linux-') for p in directory.glob('linux-*') if p.is_dir())
    for arch in require_platforms:
        expect(arch in platforms, 'release set lacks platform '+arch)
    summary = json.loads((directory/'index/image-index.json').read_text())
    expect(sorted(summary['manifests']) == platforms, f'index platforms {sorted(summary["manifests"])} differ from the release set {platforms}')
    expect(not tuf.exists(), f'cosign created {tuf}: verification contacted a TUF repository')
    report = dict(status='verified' if not failures else 'failed', verified_at=now(), directory=directory.name,
        cosign=cosign_tool.VERSION, cosign_sha256=cosign_tool.SHA256[cosign_tool.host_arch()],
        cosign_signature=dict(signature=COSIGN, identity=cosign_tool.release_identity(VERSION), issuer=cosign_tool.OIDC_ISSUER, verified=cosign_ok) if keyless
            else dict(signature=COSIGN, public_key=pathlib.Path(public_key).name, public_key_sha256=sha(public_key), verified=cosign_ok),
        openpgp={**openpgp, 'public_key_sha256': sha(openpgp_key)},
        transparency_log='keyless: a Rekor entry is required and verified' if keyless else
            'not used: signed with an offline signing config (no Rekor/TSA/Fulcio); verified with --insecure-ignore-tlog=true',
        sums_sha256=sha(directory/SUMS), files_checked=len(sums), platforms=platforms,
        index=dict(index_digest=summary['index_digest'], archive=summary['archive'], archive_sha256=summary['archive_sha256']),
        failures=failures)
    return report, failures


def verify(args):
    report, failures = check(args.dir, args.public_key, args.openpgp_key, args.require_platforms or [])
    (args.dir/'verification.json').write_text(json.dumps(report, indent=1)+'\n')
    print(json.dumps({k: report[k] for k in ['status', 'files_checked', 'platforms', 'failures']}, indent=1))
    if failures:
        raise SystemExit(1)


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = parser.add_subparsers(dest='command', required=True)
    for name in ['assemble', 'sign', 'verify']:
        command = sub.add_parser(name)
        command.add_argument('--dir', type=pathlib.Path, required=True)
        if name == 'assemble':
            command.add_argument('--engine', default='podman', choices=['podman'])
            command.add_argument('--platforms', nargs='+', default=['amd64'], choices=sorted(PLATFORMS))
            command.add_argument('--extra', action='append', default=[], type=pathlib.Path, help='another file to sign, placed under reports/')
        if name == 'sign':
            command.add_argument('--keyless', action='store_true', help='sign with the GitHub Actions OIDC identity (release workflow)')
        if name == 'verify':
            command.add_argument('--public-key', type=pathlib.Path, default=cosign_tool.PUBLIC_KEY)
            command.add_argument('--require-platforms', nargs='+', choices=sorted(PLATFORMS))
            command.add_argument('--openpgp-key', type=pathlib.Path, default=gpg_tool.PUBLIC_KEY, help='armored public release key')
    args = parser.parse_args()
    args.dir = args.dir.resolve()
    {'assemble': assemble, 'sign': sign, 'verify': verify}[args.command](args)


if __name__ == '__main__':
    main()
