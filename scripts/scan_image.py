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

"""Scan the packaged image with a pinned Trivy release against the reviewed findings.

Findings listed with a statement in image/trivyignore.yaml are reviewed; the
scan exits 0 when every finding is reviewed and 1 when one is not, or when a
reviewed finding now has a fixed version (update the package pin instead).
Writes the raw Trivy JSON and a summary. Known vulnerability inventory only:
neither a passing scan nor RustSec replaces independent security review,
supply-chain attestation or release approval.
"""
import argparse
import collections
import datetime
import hashlib
import io
import json
import pathlib
import platform
import re
import subprocess
import tarfile
import urllib.request

from image_evidence import PLATFORMS, ROOT, artifacts_dir, local_image_id, packaged_evidence

VERSION = '0.76.2'
# Release archive SHA-256 from trivy_0.76.2_checksums.txt, per host architecture (the scanner runs on the
# host; the arm64 image's scan can run on a native arm64 host with the ARM64 release).
RELEASES = {'x86_64': ('Linux-64bit', 'bc0fc726e017b8927a62b2d3531d7a84ee01769daf5c99ed866dced54089fdbf'),
            'aarch64': ('Linux-ARM64', 'ab9d51f86e6a5fb936f605faff6b593ac51bc378fff4d3e8b9d58358b9c367c3')}
SUFFIX, ARCHIVE_SHA256 = RELEASES[platform.machine()]
CACHE = ROOT/'.cache/trivy/database'
URL = f'https://github.com/aquasecurity/trivy/releases/download/v{VERSION}/trivy_{VERSION}_{SUFFIX}.tar.gz'
# Reviewed findings: Trivy ignore file, one entry with a statement per vulnerability identifier.
REVIEWED = ROOT/'image/trivyignore.yaml'


def sha(path):
    with pathlib.Path(path).open('rb') as file:
        return hashlib.file_digest(file, 'sha256').hexdigest()


def executable():
    directory = ROOT/'.cache/trivy'/VERSION/(SUFFIX if SUFFIX != 'Linux-64bit' else '')
    directory.mkdir(parents=True, exist_ok=True)
    archive = directory/'release.tar.gz'
    if not archive.exists():
        with urllib.request.urlopen(URL, timeout=60) as response:
            data = response.read(100*1024*1024+1)
        assert len(data) <= 100*1024*1024 and hashlib.sha256(data).hexdigest() == ARCHIVE_SHA256
        archive.write_bytes(data)
    assert sha(archive) == ARCHIVE_SHA256, 'Pinned Trivy release archive hash differs'
    # Extract just the expected executable; never unpack arbitrary archive paths.
    with tarfile.open(fileobj=io.BytesIO(archive.read_bytes()), mode='r:gz') as tar:
        entry = tar.getmember('trivy')
        assert entry.isfile() and entry.size < 200*1024*1024
        data = tar.extractfile(entry).read()
    binary = directory/'trivy'
    binary.write_bytes(data)
    binary.chmod(0o700)
    return binary


def reviewed_ids(path=REVIEWED):
    """Identifiers listed in the reviewed-findings file; every entry must carry a statement."""
    text = path.read_text()
    ids = re.findall(r'^  - id: (\S+)$', text, re.M)
    assert ids and len(ids) == len(set(ids)) == len(re.findall(r'^    statement: "[^"]+"$', text, re.M)), 'each reviewed entry needs one id and one statement'
    return ids


def finding(target, item, statement=None):
    return dict(target=target, id=item['VulnerabilityID'], package=item['PkgName'], installed=item['InstalledVersion'],
        fixed=item.get('FixedVersion'), severity=item['Severity'], status=item.get('Status'),
        primary_url=item.get('PrimaryURL'), source=item.get('DataSource'), **({'statement': statement} if statement else {}))


def classify(report):
    """(unreviewed, reviewed, fixable, inventory): reviewed findings with a fixed version are fixable, not reviewed."""
    unreviewed, reviewed, fixable, inventory = [], [], [], []
    for row in report['Results']:
        # --show-suppressed; the key carries an Experimental prefix in the pinned release.
        modified = [m for m in row.get('ModifiedFindings', row.get('ExperimentalModifiedFindings')) or []
            if m.get('Type') == 'vulnerability' and m.get('Status') == 'ignored']
        inventory.append(dict(target=row['Target'], package_type=row.get('Type'), packages=len(row.get('Packages', [])),
            unreviewed=len(row.get('Vulnerabilities', [])), reviewed=len(modified)))
        unreviewed += [finding(row['Target'], item) for item in row.get('Vulnerabilities', [])]
        for m in modified:
            item = finding(row['Target'], m['Finding'], m.get('Statement'))
            (fixable if item['fixed'] else reviewed).append(item)
    return unreviewed, reviewed, fixable, inventory


def run_scan(binary, archive, output):
    """Scan one exported archive; returns the raw report, the classified findings and the report digests."""
    output.mkdir(parents=True, exist_ok=True)
    report_path, log_path = output/'trivy.json', output/'scan.log'
    command = [str(binary), 'image', '--input', str(archive),
        '--cache-dir', str(CACHE), '--scanners', 'vuln', '--offline-scan',
        '--list-all-pkgs', '--timeout', '10m', '--exit-code', '1',
        '--ignorefile', str(REVIEWED), '--show-suppressed',
        '--format', 'json', '--output', str(report_path)]
    with log_path.open('w') as log:
        result = subprocess.run(command, stdout=log, stderr=subprocess.STDOUT, timeout=660)
    assert result.returncode in [0, 1] and report_path.is_file(), 'Trivy execution failed; see '+str(log_path)
    report = json.loads(report_path.read_text())
    assert report['ArtifactType'] == 'container_image' and report['Metadata'].get('OS'), 'scanner did not detect the image OS'
    assert report.get('Results'), 'Scanner returned no package inventory'
    unreviewed, reviewed, fixable, inventory = classify(report)
    assert (result.returncode == 1) == bool(unreviewed), 'Scanner exit code does not match its unreviewed findings'
    refs = {str(path.relative_to(ROOT)): sha(path) for path in [report_path, log_path]}
    return report, unreviewed, reviewed, fixable, inventory, refs


def database():
    metadata = CACHE/'db/metadata.json'
    assert metadata.is_file(), 'Missing vulnerability database provenance'
    db = json.loads(metadata.read_text())
    assert db.get('UpdatedAt') and db.get('DownloadedAt')
    return dict(database_metadata=db, database_metadata_sha256=sha(metadata), database_sha256=sha(CACHE/'db/trivy.db'))


def counts(findings):
    return dict(collections.Counter(item['severity'] for item in findings))


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument('--engine', default='podman', choices=['podman', 'docker'])
    parser.add_argument('--image', required=True)
    parser.add_argument('--arch', default='amd64', choices=sorted(PLATFORMS), help='platform of --image; reads and writes artifacts/ or artifacts/linux-<arch>/')
    args = parser.parse_args()
    output = artifacts_dir(args.arch)/'image-vulnerabilities'
    output.mkdir(parents=True, exist_ok=True)
    summary_path = output/'summary.json'
    summary = dict(status='running', unreviewed=[])
    summary_path.write_text(json.dumps(summary, indent=2)+'\n')
    failing = True
    try:
        entries = reviewed_ids()
        image_id = local_image_id(args.engine, args.image)
        evidence = packaged_evidence(image_id, args.arch)
        package = json.loads((artifacts_dir(args.arch)/'image.json').read_text())
        binary = executable()
        report, unreviewed, reviewed, fixable, inventory, refs = run_scan(binary, artifacts_dir(args.arch)/package['archive'], output)
        assert report['Metadata']['ImageID'].removeprefix('sha256:') == image_id
        failing = bool(unreviewed or fixable)
        matched = {item['id'] for item in reviewed+fixable}
        summary = dict(status='unreviewed_findings' if failing else 'all_findings_reviewed' if reviewed else 'no_known_vulnerabilities_found',
            scanned_at=datetime.datetime.now(datetime.timezone.utc).isoformat(),
            **evidence, image_tag=args.image, platform=PLATFORMS[args.arch]['platform'],
            image_os_arch=report['Metadata'].get('ImageConfig', {}).get('architecture'),
            scanner=dict(name='Trivy', version=VERSION, release_url=URL, release_sha256=ARCHIVE_SHA256, binary_sha256=sha(binary),
                release_verification='Pinned GitHub release-asset SHA-256; no independent release-signature attestation.', **database()),
            os=report['Metadata']['OS'], inventory=inventory,
            counts=dict(unreviewed=counts(unreviewed), reviewed=counts(reviewed), reviewed_with_fix=counts(fixable)),
            unreviewed=unreviewed, reviewed_with_fix=fixable, reviewed=reviewed,
            # Entries for another platform's findings, or ones the database no longer matches; prune when stale on every platform.
            reviewed_entries_not_matched=sorted(set(entries)-matched), report_refs=refs,
            limits='Known-vulnerability package inventory from the recorded database. Reviewed findings remain present in the image; a review is a recorded justification, not a fix, exploit test or risk acceptance. Rust binary dependency coverage is not established by OS scanning; use the separately pinned RustSec report. No independent code/crypto audit, signature/provenance qualification or production approval.')
    except BaseException as error:
        summary.update(status='scan_failed', error_type=type(error).__name__, error=str(error))
        raise
    finally:
        summary_path.write_text(json.dumps(summary, indent=2)+'\n')
    print(summary['status'], summary['counts'], flush=True)
    for item in summary['unreviewed']+summary['reviewed_with_fix']:
        print('UNREVIEWED' if not item['fixed'] else 'FIXED UPSTREAM, update the pin:', item['id'], item['package'], item['installed'], item['severity'], flush=True)
    if failing:
        raise SystemExit(1)


if __name__ == '__main__':
    main()
