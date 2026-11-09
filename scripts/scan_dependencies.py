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

"""Scan the locked Rust dependency graph with two independent advisory sources.

Runs RustSec cargo-audit against a separately cloned advisory database and the
pinned Trivy release against Cargo.lock using the image scan's database. All
findings and warnings are retained. Neither source establishes the absence of
unknown vulnerabilities or replaces review.
"""
import datetime
import hashlib
import json
import pathlib
import shutil
import subprocess
import tempfile
import tomllib

from image_evidence import ROOT, source_commit
from scan_image import ARCHIVE_SHA256, CACHE, URL, VERSION, database, executable

ADVISORY_DB = 'https://github.com/rustsec/advisory-db'


def sha(path):
    with pathlib.Path(path).open('rb') as file:
        return hashlib.file_digest(file, 'sha256').hexdigest()


def cargo_audit(output):
    db = ROOT/'.cache/rustsec-advisory-db'
    report_path, log_path = output/'cargo-audit.json', output/'cargo-audit.log'
    with report_path.open('w') as report, log_path.open('w') as log:
        result = subprocess.run(['cargo', 'audit', '--json', '--db', str(db), '--url', ADVISORY_DB,
            '--file', str(ROOT/'Cargo.lock')], cwd=ROOT, stdout=report, stderr=log, timeout=600)
    assert result.returncode in [0, 1], 'cargo audit failed; see '+str(log_path)
    data = json.loads(report_path.read_text())
    version = subprocess.check_output(['cargo', 'audit', '--version'], text=True).strip()
    commit = subprocess.check_output(['git', '-C', str(db), 'rev-parse', 'HEAD'], text=True).strip()
    committed = subprocess.check_output(['git', '-C', str(db), 'log', '-1', '--format=%cI'], text=True).strip()
    vulnerabilities = [dict(id=item['advisory']['id'], package=item['package']['name'], version=item['package']['version'],
        title=item['advisory']['title'], aliases=item['advisory'].get('aliases', []),
        patched=item['versions'].get('patched', [])) for item in data['vulnerabilities']['list']]
    warnings = [dict(kind=kind, package=item['package']['name'], version=item['package']['version'],
        id=(item.get('advisory') or {}).get('id')) for kind, items in data.get('warnings', {}).items() for item in items]
    assert (result.returncode == 1) == bool(vulnerabilities), 'cargo audit exit code does not match its findings'
    return dict(tool=version, advisory_database=dict(url=ADVISORY_DB, commit=commit, committed_at=committed),
        exit_code=result.returncode, dependencies_scanned=data['lockfile']['dependency-count'],
        vulnerabilities=vulnerabilities, warnings=warnings,
        report_refs={str(p.relative_to(ROOT)): sha(p) for p in [report_path, log_path]})


def trivy_lockfile(output):
    binary = executable()
    report_path, log_path = output/'trivy-cargo.json', output/'trivy-cargo.log'
    with tempfile.TemporaryDirectory(prefix='keytend-dependency-scan-') as directory:
        # Scan copies of the manifests only, so no other repository lockfile is included.
        for name in ['Cargo.toml', 'Cargo.lock']:
            shutil.copy(ROOT/name, pathlib.Path(directory)/name)
        command = [str(binary), 'fs', directory, '--cache-dir', str(CACHE), '--scanners', 'vuln',
            '--skip-db-update', '--offline-scan', '--list-all-pkgs', '--exit-code', '1', '--format', 'json',
            '--output', str(report_path)]
        with log_path.open('w') as log:
            result = subprocess.run(command, stdout=log, stderr=subprocess.STDOUT, timeout=600)
    assert result.returncode in [0, 1] and report_path.is_file(), 'Trivy lockfile scan failed; see '+str(log_path)
    report = json.loads(report_path.read_text())
    rows = [row for row in report.get('Results', []) if row.get('Type') == 'cargo']
    assert len(rows) == 1 and rows[0]['Target'] == 'Cargo.lock', 'Trivy did not inventory Cargo.lock'
    findings = [dict(id=item['VulnerabilityID'], package=item['PkgName'], installed=item['InstalledVersion'],
        fixed=item.get('FixedVersion'), severity=item['Severity'], source=item.get('DataSource'))
        for item in rows[0].get('Vulnerabilities', [])]
    assert (result.returncode == 1) == bool(findings), 'Trivy exit code does not match its findings'
    packages = rows[0].get('Packages', [])
    locked = {(p['name'], p['version']) for p in tomllib.loads((ROOT/'Cargo.lock').read_text())['package']}
    # Trivy omits the dev-only subtree (proptest and its dependencies); cargo-audit covers the full lockfile.
    omitted = sorted(f'{name}@{version}' for name, version in locked-{(p['Name'], p['Version']) for p in packages})
    return dict(tool=dict(name='Trivy', version=VERSION, release_url=URL, release_sha256=ARCHIVE_SHA256, binary_sha256=sha(binary)),
        **database(), exit_code=result.returncode, packages_scanned=len(packages),
        lockfile_packages=len(locked), not_inventoried=omitted, findings=findings,
        report_refs={str(p.relative_to(ROOT)): sha(p) for p in [report_path, log_path]})


def main():
    output = ROOT/'artifacts/dependency-vulnerabilities'
    output.mkdir(parents=True, exist_ok=True)
    path = output/'summary.json'
    summary = dict(status='running', source_commit=source_commit()[0])
    path.write_text(json.dumps(summary, indent=2)+'\n')
    try:
        rustsec = cargo_audit(output)
        trivy = trivy_lockfile(output)
        found = bool(rustsec['vulnerabilities'] or trivy['findings'])
        summary.update(status='known_vulnerabilities_found' if found else 'no_known_vulnerabilities_found',
            scanned_at=datetime.datetime.now(datetime.timezone.utc).isoformat(),
            cargo_lock_sha256=sha(ROOT/'Cargo.lock'), rustsec=rustsec, trivy=trivy,
            limits='Known advisories for locked crate versions only, including dev-only crates. Warnings (unmaintained, yanked, unsound) are retained. No reachability decision, unknown-vulnerability claim, code or cryptographic review.')
    except BaseException as error:
        summary.update(status='scan_failed', error_type=type(error).__name__, error=str(error))
        raise
    finally:
        path.write_text(json.dumps(summary, indent=2)+'\n')
    print(summary['status'], len(summary['rustsec']['vulnerabilities']), 'RustSec,', len(summary['rustsec']['warnings']), 'warnings,',
        len(summary['trivy']['findings']), 'Trivy', flush=True)
    if found:
        raise SystemExit(1)


if __name__ == '__main__':
    main()
