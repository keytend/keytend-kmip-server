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

"""Run the image tests for one platform on a native host of that platform over SSH.

The tests that execute the image (hardening, the emulated-FIPS-host image test
and the Profiles 4.1 variation replay through the image wrapper) need a host
that runs the image's architecture. This copies the working tree's tracked
files, the packaged archive and image.json (scripts/package.py --arch) and the
trace archives to a temporary directory there, loads the archive, checks that
the loaded image is the packaged one, runs the selected tests with the same
scripts and fetches each report back with its SHA-256 checked on both ends.
The host needs python3 >= 3.12 with venv, access to PyPI, podman and openssl.
The tests run in the scripts' virtual environment (scripts/python_env.py), kept
under the remote root. The scan reads only the archive, so it can also run
locally (scripts/scan_image.py --arch).

--host local runs the same steps on this host, when it is a native host of the
platform (the release workflow's arm64 runner): the files are copied to a
temporary directory here instead of over SSH.
"""
import argparse
import datetime
import hashlib
import json
import pathlib
import shlex
import subprocess
import sys
import time

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from image_evidence import PLATFORMS, ROOT, artifacts_dir
import python_env
from remote_host import Host


class LocalHost(Host):
    """This host, with the interface of an SSH Host: commands run in a local shell."""

    def __init__(self):
        super().__init__('local', [], None)

    def command(self, script):
        return ['sh', '-c', script]

NATIVE = {'amd64': {'x86_64'}, 'arm64': {'aarch64', 'arm64'}}
# name: (command, reports relative to the platform's artifacts directory)
TESTS = {
    'hardening': ('python3 scripts/test_image_hardening.py --engine {engine} --arch {arch} --image {image}', ['image-hardening/report.json']),
    'fips': ('python3 scripts/test_image_fips.py --engine {engine} --arch {arch} --image {image}', ['image-fips/report.json']),
    # Exit 1 means a finding is not in image/trivyignore.yaml (scan_image.py).
    'scan': ('python3 scripts/scan_image.py --engine {engine} --arch {arch} --image {image}',
             ['image-vulnerabilities/summary.json', 'image-vulnerabilities/trivy.json']),
    'variations': ('python3 scripts/oasis_profile_replay.py --binary {wrapper} --image {image} --diagnose --output {out}/variations.json', ['variations.json']),
    'variations-fips-emulated': ('python3 scripts/oasis_profile_replay.py --binary {fips_wrapper} --image {image} --diagnose --output {out}/variations-fips-emulated.json',
                                 ['variations-fips-emulated.json']),
}


def sha(path):
    with pathlib.Path(path).open('rb') as file:
        return hashlib.file_digest(file, 'sha256').hexdigest()


def now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat(timespec='seconds').replace('+00:00', 'Z')


def tree(arch, traces):
    """{relative name: local path}: tracked and untracked-unignored files, the packaged image and the traces."""
    listing = subprocess.check_output(['git', 'ls-files', '-z', '--cached', '--others', '--exclude-standard'], cwd=ROOT).decode().split('\0')
    files = {name: ROOT/name for name in listing if name and (ROOT/name).is_file()}
    out = artifacts_dir(arch)
    image = json.loads((out/'image.json').read_text())
    for name in ['image.json', image['archive']]:
        files[str((out/name).relative_to(ROOT))] = out/name
    if traces:
        for archive in sorted((ROOT/'.cache/specs').glob('profiles-*.zip')):
            files[str(archive.relative_to(ROOT))] = archive
        for extra in json.loads((ROOT/'docs/specs/additional-traces.json').read_text()):
            files['.cache/specs/'+extra['filename']] = ROOT/'.cache/specs'/extra['filename']
    return files, image


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument('--host', required=True, help='SSH destination of a native host for --arch, or local for this host')
    parser.add_argument('--ssh', default='ssh -o BatchMode=yes', help='SSH client command')
    parser.add_argument('--engine', default='podman', choices=['podman'])
    parser.add_argument('--arch', default='arm64', choices=sorted(PLATFORMS))
    parser.add_argument('--tests', nargs='+', default=['hardening', 'fips', 'variations'], choices=sorted(TESTS))
    parser.add_argument('--output', type=pathlib.Path, help='summary JSON (default artifacts/linux-<arch>/remote-tests.json)')
    parser.add_argument('--keep', action='store_true', help='keep the remote working directory')
    parser.add_argument('--remote-dir', help='remote working root: sources, temporary files and the podman image store (default ~/keytend-kmip-server-<arch>)')
    args = parser.parse_args()
    host = LocalHost() if args.host == 'local' else Host(args.host, args.ssh, args.remote_dir or f'~/keytend-kmip-server-{args.arch}')
    facts = host.facts(args.engine)
    assert facts['machine'] in NATIVE[args.arch], f"{args.host} is {facts['machine']}, not a native {args.arch} host"
    python = host.text("python3 -c 'import sys;print(sys.version.split()[0])'").strip()
    assert tuple(map(int, python.split('.')[:2])) >= python_env.MINIMUM, f'{args.host} has python3 {python}; 3.12 or later is needed'
    files, image = tree(args.arch, any(t.startswith('variations') for t in args.tests))
    out = artifacts_dir(args.arch)
    relative = out.relative_to(ROOT)
    summary_path = args.output or out/'remote-tests.json'
    summary = dict(status='running', started_at=now(), host=facts, python=python, arch=args.arch, image_tag=image['image_tag'],
                   image_id=image['image_id'], archive=image['archive'], archive_sha256=image['sha256'], tests={})
    directory = host.mktemp('keytend-kmip-server-tests')
    summary['remote_directory'] = directory
    try:
        summary['pushed_tar_sha256'] = host.push(files, directory)
        summary['pushed_files'] = len(files)
        if args.host == 'local':
            venv = str(python_env.ensure())
        else:
            venv = host.text(f'cd {shlex.quote(directory)} && KEYTEND_CACHE_DIR="$KEYTEND_ROOT/.cache" python3 scripts/python_env.py', timeout=1800).strip().splitlines()[-1]
        summary['python_environment'] = venv
        cd = f'cd {shlex.quote(directory)} && PATH={shlex.quote(venv)}/bin:"$PATH" && export PATH && '
        assert host.sha256(f'{directory}/{relative}/{image["archive"]}') == image['sha256'], 'pushed archive differs'
        host.run(cd+f'{args.engine} load --input {shlex.quote(str(relative/image["archive"]))} >/dev/null', timeout=1800)
        loaded = json.loads(host.text(f'{args.engine} image inspect {shlex.quote(image["image_tag"])}'))[0]['Id']
        assert loaded.removeprefix('sha256:') == image['image_id'].removeprefix('sha256:'), f'{args.host} loaded {loaded}, not {image["image_id"]}'
        wrappers = host.text(cd+'python3 -c ' + shlex.quote(
            'import pathlib,sys;sys.path.insert(0,"scripts");from image_server import wrapper as image_wrapper;'
            f'd=pathlib.Path("{relative}").resolve();print(image_wrapper(d,"{image["image_tag"]}","{args.engine}"));print(image_wrapper(d,"{image["image_tag"]}","{args.engine}",fips=True))')).split()
        for name in args.tests:
            command, reports = TESTS[name]
            script = command.format(engine=args.engine, arch=args.arch, image=shlex.quote(image['image_tag']), wrapper=wrappers[0], fips_wrapper=wrappers[1], out=relative)
            log = out/f'remote-{name}.log'
            start = time.time()
            print(f'[{args.host}] {name}: {script}', flush=True)
            with log.open('wb') as stream:
                code = host.run(cd+script, stdout=stream, check=False, timeout=8*3600)
            fetched = {}
            for report in reports:
                target = out/report
                target.parent.mkdir(parents=True, exist_ok=True)
                try:
                    fetched[str(target.relative_to(ROOT))] = host.fetch(f'{directory}/{relative}/{report}', target)
                except (AssertionError, RuntimeError) as error:
                    fetched[str(target.relative_to(ROOT))] = f'not fetched: {error}'
            summary['tests'][name] = dict(command=script, exit=code, passed=code == 0, seconds=round(time.time()-start, 1), log=str(log.relative_to(ROOT)),
                                          log_sha256=sha(log), reports=fetched)
            print(f'[{args.host}] {name}: exit {code}', flush=True)
            summary_path.write_text(json.dumps(summary, indent=1)+'\n')
    finally:
        if not args.keep:
            host.run(f'rm -rf {shlex.quote(directory)}', check=False)
        summary['finished_at'] = now()
        failed = [n for n, r in summary['tests'].items() if not r['passed'] or any(str(v).startswith('not fetched') for v in r['reports'].values())]
        summary['status'] = 'passed' if summary['tests'] and not failed and len(summary['tests']) == len(args.tests) else 'failed'
        summary['failed'] = failed
        summary_path.write_text(json.dumps(summary, indent=1)+'\n')
    print(json.dumps({k: summary[k] for k in ['status', 'failed']}), flush=True)
    if summary['status'] != 'passed':
        raise SystemExit(1)


if __name__ == '__main__':
    main()
