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

"""Package one release run's test reports as an archive in the signed set.

    release_reports.py --bundle DIR --output FILE [--host NAME ...]
    release_reports.py --part --bundle DIR --output FILE

The archive (`reports/keytend-kmip-server-<version>-test-reports.tar.gz` in
the release set, so SHA256SUMS and both signatures cover it) holds the run's
manifest and step logs, the conformance, TLS, security and Java reports in the
bundle, and every step output the manifest lists outside the bundle (under
`outputs/`). Test PKI (private keys), kubeconfigs, database files,
executables and image archives stay out.

Reports are published, so text is edited first: the bundle and checkout
paths, the home directory, the user name and the named hosts are replaced by
placeholders, and so is any other home directory path (README.txt in the
archive lists them). On a GitHub Actions runner the runner's work, temporary
and tool directories are replaced too; its generic account name is kept. The
manifest's log digests are of the unedited logs. The archive is refused if any
of them, or a PEM private key, is left. Members are sorted with fixed times and
owners, so the same reports give the same bytes.

--part packs the same files of one job of the release workflow, edited the
same way but without README.txt, for the job that merges the jobs' bundles
(scripts/release_candidate.py --merge) and packs the archive. Each job's own
paths and host name are replaced there, so the uploaded part holds none.
"""
import argparse, getpass, gzip, io, json, os, pathlib, re, socket, tarfile

ROOT = pathlib.Path(__file__).resolve().parents[1]
# Bundle entries that are reports; everything else in a bundle stays out.
REPORTS = ['manifest.json', 'logs', 'image-server.sh', 'image-server-fips-emulated.sh', 'conformance-image', 'conformance-image-arm64',
           'oasis-case-inventory.json', 'oasis-corpus-proofs.json', 'requirement-matrix.json',
           'tls-probe-image-default', 'tls-probe-image-fips-emulated', 'security-arm64', 'java',
           'integration', 'outputs']
# Never packaged, wherever they appear.
EXCLUDED_DIRS = {'pki', 'kube-pki', 'release'}
EXCLUDED_SUFFIXES = ('.key', '.pem', '.p12', '.kubeconfig', '.tar', '.sqlite', '.sqlite-wal', '.sqlite-shm', '.lock')
PRIVATE_KEY = b'PRIVATE KEY-----'
README = """Test reports of keytend-kmip-server {version}, release run {commit}.

manifest.json lists every step of the run with its command, exit code and
log; logs/ holds the logs. Every test ran the server from the image, through
image-server.sh (and image-server-fips-emulated.sh for emulated FIPS mode). outputs/ holds step outputs written outside the
run directory, by their path in the checkout. java/ holds the Java client
suite and integration/ the integration matrix's records, when the run
included them.{ci}

To publish these reports, text was edited: {replacements}. The digests in
manifest.json are of the logs before that edit.
"""


def members(bundle):
    """(archive name, path) of every packaged file."""
    found = []
    for name in REPORTS:
        path = bundle/name
        paths = [path] if path.is_file() else sorted(p for p in path.rglob('*') if p.is_file()) if path.is_dir() else []
        for p in paths:
            rel = p.relative_to(bundle)
            if not EXCLUDED_DIRS & set(rel.parts[:-1]) and not p.name.endswith(EXCLUDED_SUFFIXES):
                found.append((rel.as_posix(), p))
    manifest = json.loads((bundle/'manifest.json').read_text())
    for phase in manifest.get('phases', {}).values():
        for step in phase.values():
            for output in step.get('outputs', {}):
                p = pathlib.Path(output)
                if p.is_absolute() and p.is_file() and not p.is_relative_to(bundle):
                    try:
                        rel = p.relative_to(ROOT)
                    except ValueError:
                        continue
                    if not p.name.endswith(EXCLUDED_SUFFIXES):
                        found.append(('outputs/'+rel.as_posix(), p))
    return sorted(dict(found).items())


# GitHub Actions runner directories (the checkout is GITHUB_WORKSPACE).
RUNNER_DIRS = {'GITHUB_WORKSPACE': '<checkout>', 'RUNNER_TEMP': '<runner-temp>', 'RUNNER_TOOL_CACHE': '<tool-cache>',
               'RUNNER_WORKSPACE': '<runner-work>', 'AGENT_TOOLSDIRECTORY': '<tool-cache>'}


def github_actions(environ=None):
    return (os.environ if environ is None else environ).get('GITHUB_ACTIONS') == 'true'


def replacements(bundle, hosts, environ=None):
    environ = os.environ if environ is None else environ
    pairs = [(str(bundle), '<bundle>'), (str(bundle.resolve()), '<bundle>'),
             (str(ROOT), '<checkout>'), (str(ROOT.resolve()), '<checkout>'),
             (str(pathlib.Path.home()), '~')]
    pairs += [(environ[name], label) for name, label in RUNNER_DIRS.items() if github_actions(environ) and environ.get(name, '').startswith('/')]
    pairs += [(h, '<host>') for h in hosts if h]
    user = getpass.getuser()
    # A runner's account is a generic name ("runner") that also occurs as an ordinary word.
    if user and not github_actions(environ):
        pairs.append((user, '<user>'))
    # Longest first, so a path is replaced before a part of it.
    return sorted({(a, b) for a, b in pairs if a}, key=lambda p: -len(p[0]))


# Any other home directory, such as a remote build host's.
HOMES = re.compile(rb'/(?:home|Users)/[^/\s"\'<>]+')
# What must not be left after the edit.
LEFT_HOME = re.compile(rb'/(?:home)/')


def edit(data, pairs):
    for old, new in pairs:
        data = data.replace(old.encode(), new.encode())
    return HOMES.sub(b'~', data)


def build(bundle, output, hosts, part=False):
    bundle = pathlib.Path(bundle)
    manifest = json.loads((bundle/'manifest.json').read_text())
    pairs = replacements(bundle, hosts)
    leaks = [old.encode() for old, _ in pairs] + [PRIVATE_KEY]
    files = []
    for name, path in members(bundle):
        data = edit(path.read_bytes(), pairs)
        left = [l.decode() for l in leaks if l in data] + (['a home directory path'] if LEFT_HOME.search(data) else [])
        if left:
            raise SystemExit(f'{name}: still contains {left}; not packaged')
        files.append((name, data))
    if not part:
        version = manifest.get('image_tag', '').rpartition(':')[2]
        ci = manifest.get('ci', {}).get('run', {})
        workflow = ('\n\nThe release workflow ran this qualification: run {} of\n{}.\n'
                    'manifest.json lists its jobs under ci.parts and the steps it does not\n'
                    'run under not_run.').format(ci.get('run_id'), ci.get('workflow_ref')) if ci else ''
        done = ['the run directory became <bundle>', 'the checkout <checkout>', 'the home directory ~', 'host names <host>']
        done.append("the runner's temporary, work and tool directories <runner-temp>,\n<runner-work> and <tool-cache>"
                    if github_actions() else 'the user name <user>')
        readme = README.format(version=version, commit=manifest.get('commit', ''), ci=workflow,
                               replacements=',\n'.join(done[:-1])+' and '+done[-1])
        files.insert(0, ('README.txt', readme.encode()))
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode='w', format=tarfile.PAX_FORMAT) as tar:
        for name, data in files:
            info = tarfile.TarInfo(name)
            info.size, info.mtime, info.mode, info.uid, info.gid, info.uname, info.gname = len(data), 0, 0o644, 0, 0, '', ''
            tar.addfile(info, io.BytesIO(data))
    output = pathlib.Path(output)
    output.parent.mkdir(parents=True, exist_ok=True)
    with open(output, 'wb') as f, gzip.GzipFile(fileobj=f, mode='wb', mtime=0, filename='') as gz:
        gz.write(raw.getvalue())
    print(json.dumps({'archive': str(output), 'files': len(files), 'bytes': output.stat().st_size}))


def main():
    a = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    a.add_argument('--bundle', required=True, type=pathlib.Path)
    a.add_argument('--output', required=True, type=pathlib.Path)
    a.add_argument('--host', action='append', default=[], help='a host name to replace (repeatable); the local host is always replaced')
    a.add_argument('--part', action='store_true', help='one workflow job\'s files, without README.txt, for the job that merges them')
    args = a.parse_args()
    build(args.bundle, args.output, [socket.gethostname(), *args.host], args.part)


if __name__ == '__main__':
    main()
