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

"""Verify the minimal UBI 9 runtime root against its pinned RPM set.

Checks the exported archive (pinned RPM inventory, file ownership, permissions
and license texts), runs `rpm -Va` from the pinned UBI builder against the image
(file digests, modes, owners and dependencies) and runs a few in-image
prerequisites. Not a vulnerability review or production approval.
"""
import argparse
import datetime
import fnmatch
import json
import posixpath
import re
import subprocess

from image_evidence import PLATFORMS, ROOT, artifacts_dir, base_images, check_platform, local_image_id, packaged_evidence
from image_rootfs import RPMDB, RPMFILE_LICENSE, RPMFILE_STATE_NORMAL, Rootfs, elf_info, rpm_packages


def dockerfile_arg(name):
    return re.search(rf'^ARG {name}="?([^"\n]+)"?$', (ROOT/'Dockerfile').read_text(), re.M).group(1)


def pins():
    """{name: version-release} from the Dockerfile's RUNTIME_PACKAGES."""
    result = {}
    for nvr in dockerfile_arg('RUNTIME_PACKAGES').split():
        name, version, release = nvr.rsplit('-', 2)
        result[name] = f'{version}-{release}'
    return result


# Unsatisfied RPM requirements reviewed as not needed at run time (rpm -Va output). The glibc
# subpackages follow the glibc pin.
GLIBC = pins()['glibc']
REVIEWED_UNSATISFIED = {
    ('glibc', f'glibc-common = {GLIBC}'): 'locale utilities, C.UTF-8 data and tzdata hook; the server calls no locale, iconv or getent utilities',
    ('glibc', f'glibc-langpack = {GLIBC}'): 'empty minimal-langpack meta package; the server does not call setlocale',
    ('openssl-libs', 'ca-certificates >= 2008-5'): 'the server never loads a system trust store; it trusts only the configured KMIP_CA',
    ('openssl-fips-provider-so', 'coreutils'): 'package-tooling requirement; fips.so links only libc and no scriptlet runs in the image',
    ('crypto-policies', '/usr/bin/bash'): 'update-crypto-policies and fips-mode-setup helper scripts; the image runs no scripts',
}
# rpm -V file differences reviewed as layout consequences of the minimal root.
REVIEWED_VERIFY = {
    ('missing', '/var/cache/bpf'): 'filesystem directory absent from the pinned ubi-micro base itself',
    ('......G..', '/var/spool/mail'): 'directory keeps numeric GID 12; the generated /etc/group lists only root and kmip, so rpm cannot resolve the group name mail',
}
# Files written by the Dockerfile or Red Hat's ubi-micro build rather than an RPM payload
# (buildinfo records the base image labels and content sets scanners use).
GENERATED = ['/var/lib/rpm/rpmdb.sqlite', '/usr/local/bin/keytend-kmip-server', '/usr/share/licenses/keytend-kmip-server/LICENSE',
    '/usr/share/licenses/keytend-kmip-server/NOTICE', '/etc/keytend-kmip-server/openssl.cnf', '/root/buildinfo/*', '/usr/share/buildinfo/*']
# The server's own OpenSSL configuration (image/openssl.cnf) replaces the RHEL system policy.
OPENSSL_CONF = '/etc/keytend-kmip-server/openssl.cnf'
TOOLS_ABSENT = ['/bin/sh', '/usr/bin/bash', '/usr/bin/cat', '/usr/bin/id', '/usr/bin/openssl', '/usr/bin/rpm',
    '/usr/bin/dnf', '/usr/bin/microdnf', '/usr/bin/getent', '/usr/bin/iconv']


def canonical(rootfs, path):
    """Resolve parent directories (for merged /usr) but keep the final component."""
    directory, name = posixpath.split(path)
    return posixpath.join(rootfs.resolve(directory), name)


def installed_versions(packages):
    return {name: f"{fields['version']}-{fields['release']}" for name, fields in packages.items()}


def static_checks(rootfs, expected, report, arch='amd64'):
    checks = report['checks']
    config = rootfs.config['config']
    assert config['User'] == '10001:10001' and config['Entrypoint'] == ['/usr/local/bin/keytend-kmip-server']
    assert config['Cmd'] == ['serve'] and config['Healthcheck']['Test'] == ['CMD', '/usr/local/bin/keytend-kmip-server', 'healthcheck']
    assert 'OPENSSL_CONF='+OPENSSL_CONF in config.get('Env', []), config.get('Env')
    assert rootfs.read(OPENSSL_CONF) == (ROOT/'image/openssl.cnf').read_bytes()
    checks.append(f'OPENSSL_CONF={OPENSSL_CONF} is set and that file matches image/openssl.cnf (no system crypto policy)')
    labels = config['Labels']
    assert labels['org.opencontainers.image.licenses'] == 'Apache-2.0' and labels['org.opencontainers.image.authors'] == 'Jeremiah Jordan'
    check_platform(rootfs.config, arch)
    micro = base_images(arch)['UBI_MICRO']
    assert re.fullmatch(r'registry\.access\.redhat\.com/ubi9/ubi-micro@sha256:[0-9a-f]{64}', micro)
    assert labels['dev.keytend.kmip-server.runtime-root.package-source'] == micro == labels['org.opencontainers.image.base.name']
    assert labels['com.redhat.license_terms'].startswith('https://www.redhat.com/')
    checks.append(f'config: linux/{arch}, UID/GID 10001, exec-form entrypoint and healthcheck, license/author labels, runtime-root and base labels match the pinned {arch} ubi-micro digest, UBI license-terms label')

    release = rootfs.read('/etc/os-release').decode()
    rhel = pins()['redhat-release'].split('-')[0]  # os-release follows the redhat-release pin
    assert 'ID="rhel"' in release and f'VERSION_ID="{rhel}"' in release, release
    packages = rpm_packages(rootfs.read(RPMDB))
    installed = installed_versions(packages)
    assert installed == expected, dict(unexpected=sorted(set(installed.items())-set(expected.items())), missing=sorted(set(expected.items())-set(installed.items())))
    rpm_arch = PLATFORMS[arch]['rpm_arch']
    assert all(fields['arch'] in (rpm_arch, 'noarch') for fields in packages.values()), {n: f['arch'] for n, f in packages.items()}
    machine, interpreter = elf_info(rootfs.read('/usr/local/bin/keytend-kmip-server'))
    assert machine == PLATFORMS[arch]['elf_machine'] and interpreter and rootfs.exists(interpreter), (machine, interpreter)
    report['server_elf'] = dict(machine=machine, interpreter=interpreter)
    report['packages'] = {name: dict(evr=fields['evr'], arch=fields['arch'], sourcerpm=fields.get('sourcerpm'), license=fields.get('license'))
        for name, fields in sorted(packages.items())}
    checks.append(f'RPM database lists exactly the {len(expected)} pinned packages at their pinned versions, all {rpm_arch} or noarch (os-release: RHEL {rhel}); the server is an ELF for {arch} using {interpreter}')

    # File digests, modes and owners are rpm -Va's (rpm_verify); this records what no package owns.
    owned, not_installed = set(), 0
    for fields in packages.values():
        for item in fields['files']:
            if item['state'] != RPMFILE_STATE_NORMAL:
                not_installed += 1  # --nodocs/--excludedocs and language exclusions
            elif item['path'] != '/':
                owned.add(canonical(rootfs, item['path']))
    generated = []
    for path, (info, _) in sorted(rootfs.entries.items()):
        if info.isdir():
            continue
        if path not in owned:
            assert any(fnmatch.fnmatch(path, pattern) for pattern in GENERATED), 'file not owned by a shipped package: '+path
            generated.append(path)
    for path, (info, _) in rootfs.entries.items():
        if info.isdir() and path not in owned:
            assert any(other.startswith(path+'/') for other in rootfs.entries) or path in ['/data', '/usr/local/bin'], 'unowned empty directory: '+path
    dangling = sorted(path for path, (info, _) in rootfs.entries.items() if info.issym() and not rootfs.exists(path))
    report['file_inventory'] = dict(entries=len(rootfs.entries), package_owned=len(owned), excluded_not_installed=not_installed,
        generated=generated, dangling_symlinks=dangling)
    checks.append(f'every non-directory entry is owned by a shipped package or an enumerated generated file; {not_installed} documentation/locale paths were never installed (--nodocs)')

    fips = packages['openssl-fips-provider-so']
    entry = next(item for item in fips['files'] if item['path'] == '/usr/lib64/ossl-modules/fips.so' and item['state'] == RPMFILE_STATE_NORMAL)
    assert rootfs.sha256(entry['path']) == entry['digest'], 'fips.so differs from its RPM digest'
    report['fips_module'] = dict(path='/usr/lib64/ossl-modules/fips.so', package=f"openssl-fips-provider-so-{fips['evr']}.{fips['arch']}",
        sourcerpm=fips.get('sourcerpm'), sha256=rootfs.sha256('/usr/lib64/ossl-modules/fips.so'))
    checks.append('/usr/lib64/ossl-modules/fips.so is installed from openssl-fips-provider-so and matches its RPM digest')

    special, sticky = [], []
    for path, (info, _) in rootfs.entries.items():
        if info.mode & 0o6000:
            assert info.isdir() and not info.mode & 0o4000, 'setuid/setgid entry: '+path
            special.append(dict(path=path, mode=oct(info.mode & 0o7777), gid=info.gid))
        if info.mode & 0o002 and not info.issym():
            assert info.isdir() and info.mode & 0o1000, 'non-sticky world-writable entry: '+path
            sticky.append(path)
    data = rootfs.entries['/data'][0]
    assert data.isdir() and (data.uid, data.gid, data.mode & 0o7777) == (10001, 10001, 0o700)
    passwd = rootfs.read('/etc/passwd').decode()
    assert passwd.splitlines() == ['root:x:0:0:root:/nonexistent:/sbin/nologin', 'kmip:x:10001:10001::/nonexistent:/sbin/nologin']
    report['setgid_directories'] = sorted(special, key=lambda item: item['path'])
    report['world_writable_sticky_directories'] = sorted(sticky)
    checks.append(f'no setuid/setgid files; {len(special)} setgid directories recorded; world-writable entries are only sticky directories {sorted(sticky)}; /data is 10001:10001 mode 0700; passwd lists only root and kmip')

    licenses = 0
    for name, fields in packages.items():
        for item in fields['files']:
            if item['flags'] & RPMFILE_LICENSE:
                assert item['state'] == 0 and rootfs.exists(item['path']), 'missing license text for '+name+': '+item['path']
                licenses += 1
    for name in ['LICENSE', 'NOTICE']:
        assert rootfs.read('/usr/share/licenses/keytend-kmip-server/'+name) == (ROOT/name).read_bytes()
    report['license_files'] = licenses
    checks.append(f'all {licenses} RPM %license texts are shipped; project LICENSE/NOTICE match the repository; UBI terms are referenced by label and /root/buildinfo')


def rpm_verify(engine, image, report, arch='amd64'):
    """rpm -Va from the pinned UBI builder against a disposable writable mount of the image."""
    builder = base_images(arch)['UBI_BUILDER']
    # A host that did not build the image (a CI job that loaded the archive) lacks the builder.
    if subprocess.run([engine, 'image', 'inspect', builder], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode:
        subprocess.run([engine, 'pull', '--quiet', '--platform', PLATFORMS[arch]['platform'], builder],
            check=True, stdout=subprocess.DEVNULL, timeout=900)
    result = subprocess.run([engine, 'run', '--rm', '--network', 'none', '--pull=never',
        '--mount', f'type=image,source={image},destination=/target,rw=true', builder, 'rpm', '--root', '/target', '-Va'],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=300)
    # rpm -V exits with a small count of failures, which the parser below judges; the engine's own
    # failures exit 125 to 127.
    assert result.returncode < 125, f'{engine} run of {builder} exited {result.returncode}: {result.stdout[-2000:]}'
    unsatisfied, files, owner = set(), set(), None
    for line in result.stdout.splitlines():
        heading = re.match(r'Unsatisfied dependencies for (.+):$', line)
        if heading:
            owner = heading.group(1)
            continue
        need = re.match(r'\t(.+) is needed by \(installed\) (\S+)$', line)
        if need:
            name = re.match(r'(.+)-[^-]+-[^-]+$', need.group(2)).group(1)
            unsatisfied.add((name, need.group(1)))
            continue
        item = re.match(r'(missing|[.SM5DLUGTP?]{9})\s+(?:[cdglr] )?\s*(/\S*)$', line)
        assert item, 'unparsed rpm -V output: '+line
        files.add((item.group(1), item.group(2)))
    assert set(unsatisfied) == set(REVIEWED_UNSATISFIED), sorted(unsatisfied)
    assert files == set(REVIEWED_VERIFY), sorted(files)
    report['rpm_verify'] = dict(builder=builder, exit_code=result.returncode,
        reviewed_unsatisfied=[dict(package=p, requires=r, reason=REVIEWED_UNSATISFIED[(p, r)]) for p, r in sorted(unsatisfied)],
        reviewed_file_differences=[dict(flags=f, path=p, reason=REVIEWED_VERIFY[(f, p)]) for f, p in sorted(files)])
    report['checks'].append(f'rpm -Va from the pinned UBI builder: file digests, sizes, modes and owners verify except {len(files)} reviewed layout differences; {len(unsatisfied)} reviewed unsatisfied requirements of erased packages')


def runtime_checks(engine, image, report, interpreter='/lib64/ld-linux-x86-64.so.2'):
    base = [engine, 'run', '--rm', '--network', 'none', '--read-only', '--cap-drop=all',
        '--security-opt=no-new-privileges', '--tmpfs', '/tmp:rw,nosuid,nodev,noexec,size=16m,mode=1777']
    def run(*args):
        return subprocess.run(base+list(args), stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=120)
    linked = run('--entrypoint', interpreter, image, '--list', '/usr/local/bin/keytend-kmip-server')
    assert linked.returncode == 0 and 'not found' not in linked.stdout, linked.stdout
    libraries = sorted(re.findall(r'=> (\S+)', linked.stdout))
    assert libraries == ['/lib64/libc.so.6', '/lib64/libcrypto.so.3', '/lib64/libgcc_s.so.1', '/lib64/libm.so.6', '/lib64/libssl.so.3', '/lib64/libz.so.1'], libraries
    report['linked_libraries'] = libraries
    assert run(image, '--help').returncode == 0
    key = run('--entrypoint', '/usr/local/bin/keytend-kmip-server', image, 'generate-master-key', '--output', '/tmp/master.key')
    assert key.returncode == 0, key.stdout
    # No shell, coreutils, OpenSSL CLI or package manager is shipped.
    for tool in TOOLS_ABSENT:
        absent = run('--entrypoint', tool, image)
        assert absent.returncode != 0, (tool, absent.stdout)
    rotation_help = run('--entrypoint', '/usr/local/bin/keytend-kmip-server', image, 'rotate-master-key', '--help')
    assert rotation_help.returncode == 0 and '--create-directory' in rotation_help.stdout, rotation_help.stdout
    report['checks'].append(f'read-only, no-network, all-capabilities-dropped container resolves every linked library, runs --help and generate-master-key, and cannot execute {", ".join(TOOLS_ABSENT)} (the rotation Job uses rotate-master-key --create-directory)')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--engine', default='podman', choices=['podman', 'docker'])
    parser.add_argument('--image', required=True)
    parser.add_argument('--arch', default='amd64', choices=sorted(PLATFORMS), help='platform of --image; reads artifacts/ or artifacts/linux-<arch>/')
    args = parser.parse_args()
    output = artifacts_dir(args.arch)/'image-hardening'
    output.mkdir(parents=True, exist_ok=True)
    path = output/'report.json'
    report = dict(status='running', started_at=datetime.datetime.now(datetime.timezone.utc).isoformat(),
        image_tag=args.image, arch=args.arch, checks=[],
        limits='Inventory, provenance-consistency and minimal runtime checks of one image. Not a vulnerability exploitability review, independent audit, signature attestation, FIPS validation or production approval.')
    path.write_text(json.dumps(report, indent=2)+'\n')
    try:
        image_id = local_image_id(args.engine, args.image)
        report.update(packaged_evidence(image_id, args.arch))
        package = json.loads((artifacts_dir(args.arch)/'image.json').read_text())
        rootfs = Rootfs(artifacts_dir(args.arch)/package['archive'])
        assert rootfs.config_id == image_id, 'archive config does not match the local image'
        static_checks(rootfs, pins(), report, args.arch)
        rpm_verify(args.engine, image_id, report, args.arch)
        runtime_checks(args.engine, args.image, report, report['server_elf']['interpreter'])
        report['status'] = 'passed'
    except BaseException as error:
        report.update(status='failed', error_type=type(error).__name__, error=str(error)[:4000])
        raise
    finally:
        report['finished_at'] = datetime.datetime.now(datetime.timezone.utc).isoformat()
        path.write_text(json.dumps(report, indent=2)+'\n')
    for check in report['checks']:
        print('PASS', check, flush=True)


if __name__ == '__main__':
    main()
