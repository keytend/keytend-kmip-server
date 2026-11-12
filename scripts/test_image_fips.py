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

"""Show that the packaged image runs the server in FIPS mode with the RHEL 9 FIPS provider.

The image sets OPENSSL_CONF to the server's own configuration (image/openssl.cnf), so
FIPS mode is the server's: `--fips`, KMIP_FIPS or a FIPS host kernel make it load the
"fips" and "base" providers itself (docs/fips.md). This test records that

- the shipped server in FIPS mode dynamically loads /usr/lib64/ossl-modules/fips.so,
  `--fips fips-check` passes and reports the provider's own name, version, build info
  and status, and the server fails closed with a corrupted module;
- a FIPS-mode server answers an approved request (Create AES-256) and refuses a
  non-approved one (Create ChaCha20) that the default-mode server answers;
- in RHEL's own system configuration with OPENSSL_FORCE_FIPS_MODE=1, the provider
  reports itself active (its power-on self-tests and integrity check passed), approved
  algorithms work, non-approved ones are refused, and a corrupted module is refused.

The shipped image has no shell or OpenSSL CLI. The CLI and a corrupted copy of fips.so
come from a separate test-only image built on top of the shipped image; the server
binary runs from the shipped image.

OPENSSL_FORCE_FIPS_MODE=1 is RHEL's test switch: libcrypto behaves as on a host whose
kernel reports /proc/sys/crypto/fips_enabled=1. The server itself reads that file, which
this host does not have, so the FIPS-mode server runs with `--fips` as well. Every FIPS
result here is therefore emulated. A real claim needs a FIPS-enabled host kernel. This
test is not a FIPS 140 validation, a CMVP certificate or a FIPS compliance claim.
"""
import argparse
import datetime
import hashlib
import json
import os
import pathlib
import re
import socket
import subprocess
import tempfile
import time
import uuid

from image_evidence import PLATFORMS, ROOT, artifacts_dir, base_images, check_platform, local_image_id, packaged_evidence
from image_rootfs import RPMDB, Rootfs, rpm_packages
import wire

FIPS_MODULE = '/usr/lib64/ossl-modules/fips.so'
PROBE_DIR = '/usr/local/libexec/fips-probe'
PROVIDER_NAME = 'Red Hat Enterprise Linux 9 - OpenSSL FIPS Provider'
FORCE = ['-e', 'OPENSSL_FORCE_FIPS_MODE=1']
# RHEL's system configuration, for the CLI checks of the provider as RHEL itself loads it.
SYSTEM_CONF = ['-e', 'OPENSSL_CONF=/etc/pki/tls/openssl.cnf']
SERVER_CONF = '/etc/keytend-kmip-server/openssl.cnf'
# CMVP certificate #4857 (FIPS 140-3, interim, active, sunset 2029-10-28) covers this module
# version; Red Hat's compliance page maps it to openssl-fips-provider-3.0.7-6.el9 for RHEL 9.8.
# https://csrc.nist.gov/projects/cryptographic-module-validation-program/certificate/4857
# https://access.redhat.com/compliance/fips
CERTIFIED_MODULE = dict(certificate='#4857', module_version='3.0.7-395c1a240fbfffd8', red_hat_package='openssl-fips-provider-3.0.7-6.el9')


def sha(path):
    with pathlib.Path(path).open('rb') as file:
        return hashlib.file_digest(file, 'sha256').hexdigest()


def providers(text):
    """Parse `openssl list -providers -verbose` into {id: {name, version, status}}."""
    result, current = {}, None
    for line in text.splitlines():
        heading = re.fullmatch(r'  (\w+)', line)
        if heading:
            current = result.setdefault(heading.group(1), {})
            continue
        field = re.fullmatch(r'    (name|version|status): (.+)', line)
        if field and current is not None:
            current[field.group(1)] = field.group(2).strip()
    return result


def build_probe(engine, image_id, openssl_version, tag, arch='amd64'):
    """Test-only image: the shipped image plus the matching RHEL openssl CLI and a corrupted fips.so copy."""
    containerfile = f'''FROM {base_images(arch)['UBI_BUILDER']} AS probe
RUN dnf install -y -q --nodocs --setopt=install_weak_deps=0 openssl-{openssl_version} && dnf clean all && \\
    mkdir -p /out/tampered && cp /usr/bin/openssl /out/openssl && cp {FIPS_MODULE} /out/tampered/fips.so && \\
    size=$(stat -c %s /out/tampered/fips.so) && printf '\\377' | dd of=/out/tampered/fips.so bs=1 seek=$((size/2)) conv=notrunc status=none && \\
    sha256sum /usr/bin/openssl {FIPS_MODULE} /out/tampered/fips.so
FROM {image_id}
COPY --from=probe /out/ {PROBE_DIR}/
'''
    with tempfile.TemporaryDirectory(prefix='keytend-fips-probe-') as directory:
        (pathlib.Path(directory)/'Containerfile').write_text(containerfile)
        build = subprocess.run([engine, 'build', '--format', 'docker', '--platform', PLATFORMS[arch]['platform'], '-t', tag, directory],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=1800)
    assert build.returncode == 0, build.stdout[-4000:]
    return containerfile, build.stdout


CHACHA20 = 28
AES = 3


def create(algorithm):
    """KMIP 1.4 Create of a 256-bit symmetric key with Encrypt and Decrypt usage."""
    attrs = [wire.enumeration(0x420028, algorithm), wire.integer(0x42002a, 256), wire.integer(0x42002c, 12)]
    return wire.request(1, [wire.enumeration(0x420057, 2), wire.structure(0x420091, *map(wire.attr, attrs))])


def result(response):
    item = wire.get(response, 0x42000f)
    fields = {tag: wire.children(item, tag) for tag in (0x42007f, 0x42007e, 0x42007d)}
    return dict(status=fields[0x42007f][0][2], reason=fields[0x42007e][0][2] if fields[0x42007e] else None,
        message=fields[0x42007d][0][2] if fields[0x42007d] else None)


def free_port():
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0))
        return sock.getsockname()[1]


def server_requests(engine, image_id, report):
    """The shipped server, default mode and forced FIPS mode (--fips), over mutual TLS."""
    observations = {}
    with tempfile.TemporaryDirectory(prefix='keytend-fips-server-') as directory:
        root = pathlib.Path(directory)
        pki = root/'pki'
        subprocess.run(['bash', str(ROOT/'scripts/dev-pki.sh'), str(pki)], check=True, stdout=subprocess.DEVNULL, timeout=300)
        userns = ['--userns', 'keep-id:uid=10001,gid=10001'] if engine == 'podman' else ['--user', f'{os.getuid()}:{os.getgid()}']
        subprocess.run([engine, 'run', '--rm', '--network', 'none', *userns, '-v', f'{pki}:/out', image_id,
            'generate-master-key', '--output', '/out/master.key'], check=True, timeout=120)
        for mode, options in [('default', []), ('fips', ['--fips'])]:
            data = root/f'data-{mode}'
            data.mkdir(mode=0o700)
            name = 'keytend-fipstest-'+uuid.uuid4().hex[:12]
            port, health = free_port(), free_port()
            command = [engine, 'run', '-d', '--name', name, *userns, '--read-only', '--cap-drop=all', '--security-opt=no-new-privileges',
                '--tmpfs', '/tmp:rw,nosuid,nodev,noexec,size=16m,mode=1777', '-v', f'{pki}:/tls:ro', '-v', f'{data}:/data',
                '-p', f'127.0.0.1:{port}:5696', '-p', f'127.0.0.1:{health}:8080', *(FORCE if mode == 'fips' else []), image_id,
                *options, 'serve', '--cert', '/tls/server.pem', '--key', '/tls/server.key', '--ca', '/tls/ca.pem',
                '--policy', '/tls/policy.json', '--master-key', '/tls/master.key', '--database', '/data/kmip.sqlite']
            subprocess.run(command, check=True, stdout=subprocess.DEVNULL, timeout=120)
            try:
                deadline = time.monotonic()+60
                while True:
                    try:
                        connection = wire.connect(pki, port)
                        break
                    except OSError:
                        if time.monotonic() > deadline:
                            raise
                        time.sleep(0.5)
                with connection:
                    answers = {name: result(wire.exchange(connection, create(algorithm))) for name, algorithm in [('create_aes_256', AES), ('create_chacha20', CHACHA20)]}
            finally:
                logs = subprocess.run([engine, 'logs', name], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True).stdout
                subprocess.run([engine, 'rm', '--force', '--time', '10', name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            started = 'FIPS mode: OpenSSL FIPS provider loaded' in logs
            logged = [json.loads(line)['fields'] for line in logs.splitlines()
                      if line.startswith('{') and 'FIPS mode: OpenSSL FIPS provider loaded' in line]
            observations[mode] = dict(answers=answers, fips_provider_logged=started,
                provider_logged={k: v for k, v in (logged[0] if logged else {}).items() if k.startswith('provider_')})
        default, fips = observations['default'], observations['fips']
        assert default['answers']['create_aes_256']['status'] == 0 and fips['answers']['create_aes_256']['status'] == 0, observations
        assert default['answers']['create_chacha20']['status'] == 0, observations
        refused = fips['answers']['create_chacha20']
        assert refused['status'] == 1 and refused['reason'] == 7 and 'FIPS mode' in (refused['message'] or ''), observations
        assert fips['fips_provider_logged'] and not default['fips_provider_logged'], observations
        provider = fips['provider_logged']
        assert provider.get('provider_name') == PROVIDER_NAME and provider.get('provider_status') == 1, observations
        assert provider.get('provider_version', '').startswith('3.0.7-') and provider.get('provider_build_info', '').startswith('3.0.7'), observations
    report['checks'].append(f"server over mutual TLS: Create AES-256 succeeds in default and forced FIPS mode; Create ChaCha20 succeeds in default mode and is refused in FIPS mode (Invalid Field, '{refused['message']}'); only the FIPS-mode server logs the provider load, with the provider's name, version, build info and status ({provider})")
    return observations


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--engine', default='podman', choices=['podman', 'docker'])
    parser.add_argument('--image', required=True)
    parser.add_argument('--keep-probe', action='store_true', help='keep the test-only probe image')
    parser.add_argument('--arch', default='amd64', choices=sorted(PLATFORMS), help='platform of --image; reads artifacts/ or artifacts/linux-<arch>/')
    args = parser.parse_args()
    output = artifacts_dir(args.arch)/'image-fips'
    output.mkdir(parents=True, exist_ok=True)
    path = output/'report.json'
    report = dict(status='running', started_at=datetime.datetime.now(datetime.timezone.utc).isoformat(),
        image_tag=args.image, arch=args.arch, checks=[],
        limits='Emulated FIPS mode: OPENSSL_FORCE_FIPS_MODE=1 plus the server flag --fips on a host whose kernel is not in FIPS mode. Shows that the shipped server loads and enforces the RHEL 9 FIPS provider and refuses a non-approved request; it is not a FIPS 140 validation, does not show the host kernel, entropy source or operating environment match a CMVP certificate, and does not show that every server service is approved.')
    path.write_text(json.dumps(report, indent=2)+'\n')
    probe = None
    try:
        image_id = local_image_id(args.engine, args.image)
        report.update(packaged_evidence(image_id, args.arch))
        package = json.loads((artifacts_dir(args.arch)/'image.json').read_text())
        rootfs = Rootfs(artifacts_dir(args.arch)/package['archive'])
        assert rootfs.config_id == image_id, 'archive config does not match the local image'
        check_platform(rootfs.config, args.arch)
        packages = rpm_packages(rootfs.read(RPMDB))
        module = packages['openssl-fips-provider-so']
        entry = next(item for item in module['files'] if item['path'] == FIPS_MODULE)
        assert rootfs.sha256(FIPS_MODULE) == entry['digest']
        assert not any(path.startswith(PROBE_DIR) for path in rootfs.entries) and not rootfs.exists('/usr/bin/openssl')
        libs = packages['openssl-libs']
        report['shipped'] = dict(fips_module=FIPS_MODULE, fips_module_sha256=entry['digest'],
            fips_packages={name: f"{packages[name]['evr']}.{packages[name]['arch']}" for name in ['openssl-fips-provider', 'openssl-fips-provider-so']},
            fips_sourcerpm=module.get('sourcerpm'), openssl_libs=f"{libs['evr']}.{libs['arch']}")
        report['checks'].append(f"shipped image installs {FIPS_MODULE} from openssl-fips-provider-so-{module['evr']} (digest matches the RPM) and contains no OpenSSL CLI or probe files")

        kernel = pathlib.Path('/proc/sys/crypto/fips_enabled')
        report['host_kernel_fips_enabled'] = kernel.read_text().strip() if kernel.exists() else 'absent'

        base = [args.engine, 'run', '--rm', '--network', 'none', '--read-only', '--cap-drop=all',
            '--security-opt=no-new-privileges', '--tmpfs', '/tmp:rw,nosuid,nodev,noexec,size=16m,mode=1777']
        def run(image, *options, command):
            result = subprocess.run(base+list(options)+[image]+list(command), stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=120)
            return dict(command=' '.join(list(options)+list(command)), exit=result.returncode, output=result.stdout[-3000:], full=result.stdout)
        observations = report['observations'] = {}

        # The server binary from the shipped image: which OpenSSL modules does the process load?
        server = ['--entrypoint', '/usr/local/bin/keytend-kmip-server']
        key = ['generate-master-key', '--output', '/tmp/master.key']
        loaded = lambda text: re.search(r'file=/usr/lib64/ossl-modules/fips\.so \[0\];\s+dynamically loaded by /lib64/libcrypto\.so\.3', text) is not None
        modules = {}
        for label, options, command in [('fips_forced', FORCE, ['--fips', *key]), ('fips', [], ['--fips', *key]),
                                        ('default', [], key), ('default_forced', FORCE, key)]:
            result = run(image_id, *server, *options, '-e', 'LD_DEBUG=files', command=command)
            assert result['exit'] == 0, result['output']
            modules[label] = dict(exit=result['exit'], fips_module_loaded=loaded(result['full']))
        assert modules['fips_forced']['fips_module_loaded'] and modules['fips']['fips_module_loaded'], modules
        assert not modules['default']['fips_module_loaded'] and not modules['default_forced']['fips_module_loaded'], modules
        observations['server_modules'] = modules
        report['checks'].append(f'server binary (shipped image, OPENSSL_CONF={SERVER_CONF}): with --fips libcrypto dynamically loads fips.so, with and without OPENSSL_FORCE_FIPS_MODE=1; without --fips it is not loaded, forced or not (FIPS mode is the server\'s decision; on a FIPS host the kernel flag enters it)')

        check = run(image_id, *server, *FORCE, command=['--fips', 'fips-check'])
        assert check['exit'] == 0, check
        status = json.loads(check['full'])
        assert status['loaded'] == ['fips', 'base'] and status['library'].startswith('OpenSSL '+libs['version']), status
        assert any('unavailable' in item for item in status['checks']) and any('known answer' in item for item in status['checks']), status
        refused = run(image_id, *server, *FORCE, command=['fips-check'])
        assert refused['exit'] != 0 and 'needs --fips' in refused['output'], refused
        # The provider's own parameters as the server reads them (OSSL_PROVIDER_get_params).
        fips_provider, base_provider = status['providers']
        module_version = packages['openssl-fips-provider-so']['version']
        assert fips_provider['id'] == 'fips' and fips_provider['name'] == PROVIDER_NAME and fips_provider['status'] == 1, status
        assert fips_provider['version'].startswith(module_version+'-') and fips_provider['build_info'].startswith(module_version), status
        assert base_provider['id'] == 'base' and base_provider['status'] == 1, status
        observations['server_fips_check'] = status
        report['checks'].append(f"forced FIPS mode: `keytend-kmip-server --fips fips-check` loads only the fips and base providers ({status['library']}); {'; '.join(status['checks'])}")
        report['checks'].append(f"forced FIPS mode: the server reports provider '{fips_provider['name']}' version {fips_provider['version']}, build info {fips_provider['build_info']}, status {fips_provider['status']} (running: its self-tests and integrity check passed at load)")
        # Recorded, not asserted: the UBI 9 repositories carry only the 3.0.7-11 rebuild (RHSA-2026:28832,
        # CVE-2026-31790), which Red Hat describes as submitted to NIST for certification.
        report['certificate'] = dict(CERTIFIED_MODULE, shipped_module_version=fips_provider['version'],
            shipped_module_is_certified_build=fips_provider['version'] == CERTIFIED_MODULE['module_version'])

        tag = f'localhost/keytend-kmip-server-fips-probe:{image_id[:12]}'
        containerfile, log = build_probe(args.engine, image_id, libs['evr'].split(':')[-1], tag, args.arch)
        probe = tag
        (output/'probe-build.log').write_text(log)
        report['probe_image'] = dict(tag=tag, image_id=local_image_id(args.engine, tag), containerfile=containerfile,
            build_log_sha256=sha(output/'probe-build.log'), note='Test-only image; never shipped or deployed.')
        cli = ['--entrypoint', PROBE_DIR+'/openssl']
        version = run(probe, *cli, command=['version'])
        assert version['exit'] == 0 and version['output'].startswith('OpenSSL '+libs['version']), version
        observations['cli_version'] = version['output'].strip()

        listing = run(probe, *cli, command=['list', '-providers', '-verbose'])
        plain = providers(listing['output'])
        assert listing['exit'] == 0 and 'fips' not in plain and plain.get('default', {}).get('status') == 'active', listing
        md5_plain = run(probe, *cli, command=['dgst', '-md5', '/etc/os-release'])
        assert md5_plain['exit'] == 0, md5_plain
        observations['default_mode'] = dict(providers=plain, md5_exit=md5_plain['exit'])
        report['checks'].append(f'default mode (image configuration {SERVER_CONF}): only the default provider is active and MD5 is available')

        listing = run(probe, *cli, *FORCE, *SYSTEM_CONF, command=['list', '-providers', '-verbose'])
        active = providers(listing['output'])
        fips = active.get('fips', {})
        # Cross-check only: RHEL's own CLI and system configuration name the same module as the server.
        assert listing['exit'] == 0 and fips.get('status') == 'active', listing
        assert (fips.get('name'), fips.get('version')) == (fips_provider['name'], fips_provider['version']), (fips, fips_provider)
        observations['forced_mode_providers'] = active
        report['checks'].append(f"forced FIPS mode, RHEL system configuration: the CLI lists the same provider and version as the server, status active")

        attempts = {
            'sha256_digest': (['dgst', '-sha256', '/etc/os-release'], True),
            'p256_keygen': (['genpkey', '-algorithm', 'EC', '-pkeyopt', 'ec_paramgen_curve:P-256', '-out', '/tmp/p256.pem'], True),
            'md5_digest': (['dgst', '-md5', '/etc/os-release'], False),
            'chacha20_cipher': (['enc', '-chacha20', '-K', '00'*32, '-iv', '00'*16, '-in', '/etc/os-release', '-out', '/dev/null'], False),
            'secp256k1_keygen': (['genpkey', '-algorithm', 'EC', '-pkeyopt', 'ec_paramgen_curve:secp256k1', '-out', '/tmp/k1.pem'], False),
            'rsa1024_keygen': (['genpkey', '-algorithm', 'RSA', '-pkeyopt', 'rsa_keygen_bits:1024', '-out', '/tmp/rsa.pem'], False),
        }
        results = {}
        for name, (command, allowed) in attempts.items():
            result = run(probe, *cli, *FORCE, *SYSTEM_CONF, command=command)
            assert (result['exit'] == 0) == allowed, (name, result)
            results[name] = dict(allowed=allowed, exit=result['exit'], output=result['output'] if not allowed else '')
        observations['forced_mode_algorithms'] = results
        report['checks'].append('forced FIPS mode, RHEL system configuration: SHA-256 and P-256 key generation succeed; MD5, ChaCha20, secp256k1 and RSA-1024 key generation are refused')

        tampered = ['-e', 'OPENSSL_MODULES='+PROBE_DIR+'/tampered']
        listing = run(probe, *cli, *FORCE, *SYSTEM_CONF, *tampered, command=['list', '-providers', '-verbose'])
        digest = run(probe, *cli, *FORCE, *SYSTEM_CONF, *tampered, command=['dgst', '-sha256', '/etc/os-release'])
        assert 'fips' not in providers(listing['output']) and digest['exit'] != 0, (listing, digest)
        observations['tampered_module'] = dict(providers=providers(listing['output']), sha256_exit=digest['exit'], sha256_output=digest['output'])
        report['checks'].append('forced FIPS mode, RHEL system configuration, one-byte-corrupted copy of fips.so: the provider does not load and even SHA-256 is refused (fails closed)')
        server_tampered = run(probe, *server, *FORCE, *tampered, command=['--fips', 'fips-check'])
        assert server_tampered['exit'] != 0 and 'cannot load the OpenSSL "fips" provider' in server_tampered['output'], server_tampered
        observations['server_tampered_module'] = dict(exit=server_tampered['exit'], output=server_tampered['output'][-1500:])
        report['checks'].append('the FIPS-mode server with the corrupted fips.so refuses to start (`--fips fips-check` fails: the provider does not load)')

        observations['server_requests'] = server_requests(args.engine, image_id, report)

        report['status'] = 'passed'
    except BaseException as error:
        report.update(status='failed', error_type=type(error).__name__, error=str(error)[:4000])
        raise
    finally:
        if probe and not args.keep_probe:
            subprocess.run([args.engine, 'rmi', probe], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        report['finished_at'] = datetime.datetime.now(datetime.timezone.utc).isoformat()
        path.write_text(json.dumps(report, indent=2)+'\n')
    for check in report['checks']:
        print('PASS', check, flush=True)
    print('host kernel fips_enabled:', report['host_kernel_fips_enabled'])
    print('certificate:', json.dumps(report.get('certificate')))


if __name__ == '__main__':
    main()
