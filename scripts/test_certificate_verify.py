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

"""Certificate subject-key verification through the unchanged released Java SDK.

JCA generates application signatures and checks positive/negative oracle results.
Disposable PKCS#8 keys are never copied to retained artifacts. This suite does
not establish PKIX trust, full Key Usage mapping or complete certificate support.
"""
import argparse
import datetime
import json
import os
import pathlib
import shutil
import subprocess
import tempfile

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import dsa, ec, rsa
from cryptography.x509.oid import NameOID
from image_evidence import source_commit, local_image_id, packaged_evidence
from https_client import HttpsServer, HttpsContainer
from test_database import ContainerServer
from test_runtime import ROOT
from keytend_kmip_release import release, sha


def fixtures(directory):
    rsa_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ec_key = ec.generate_private_key(ec.SECP256R1())
    at = datetime.datetime.now(datetime.timezone.utc)
    for i, (name, key, issuer, usage) in enumerate([
        ('rsa', rsa_key, ec_key, 'digital'),
        ('ec', ec_key, rsa_key, 'digital'),
        ('dsa', dsa.generate_private_key(key_size=2048), ec_key, 'digital'),
        ('nonrep', ec.generate_private_key(ec.SECP256R1()), rsa_key, 'nonrep'),
        ('enc', ec.generate_private_key(ec.SECP256R1()), rsa_key, 'enc'),
        ('other', ec.generate_private_key(ec.SECP256R1()), rsa_key, 'digital'),
    ]):
        cert = (x509.CertificateBuilder()
                .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)]))
                .issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'independent issuer')]))
                .public_key(key.public_key()).serial_number(i+1)
                .not_valid_before(at-datetime.timedelta(days=1))
                .not_valid_after(at+datetime.timedelta(days=1))
                .add_extension(x509.KeyUsage(digital_signature=usage == 'digital', content_commitment=usage == 'nonrep', key_encipherment=usage == 'enc', data_encipherment=False, key_agreement=False, key_cert_sign=False, crl_sign=False, encipher_only=False, decipher_only=False), critical=True)
                .sign(issuer, hashes.SHA384()))
        (directory/(name+'.der')).write_bytes(cert.public_bytes(serialization.Encoding.DER))
        private = directory/(name+'.pk8')
        private.write_bytes(key.private_bytes(serialization.Encoding.DER, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
        private.chmod(0o600)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--image')
    parser.add_argument('--engine', default='podman')
    parser.add_argument('--java', action='append', required=True)
    args = parser.parse_args()
    _, jars, artifact = release()
    binary = ROOT/'target/debug/keytend-kmip-server'
    binary_hash = sha(binary)
    config = local_image_id(args.engine, args.image) if args.image else None
    evidence = packaged_evidence(config) if config else {'runtime_binary_sha256': binary_hash, 'source_commit': source_commit()[0]}
    mode = 'image' if config else 'native'
    out = ROOT/'artifacts/certificate-verify'
    out.mkdir(parents=True, exist_ok=True)
    classes = pathlib.Path(tempfile.mkdtemp(prefix='java-certificate-verify-'+mode+'-', dir=ROOT/'.cache'))
    classpath = os.pathsep.join(map(str, [classes]+jars))
    subprocess.run(['javac', '--release', '17', '-cp', classpath, '-d', str(classes), str(ROOT/'interop/java/ServerCertificateVerify.java')], check=True)
    compiled = {str(path.relative_to(ROOT)): sha(path) for path in classes.rglob('*.class')}
    report = dict(status='running', scope='Application-signature verification using certificate subject keys; RSA, PSS, ECDSA and DSA, mixed issuer algorithms, wrong data/subject keys, malformed signature, versioned prehash/multipart, Key Usage and KMIP mask/purpose denials. Five final editions 1.2-2.1 and TLS/HTTPS TTLV/JSON/XML. Restart and clean backup restoration. No Java draft, PKIX trust, complete Key Usage mapping or full certificate-family credit.', client_artifact=artifact, **evidence, compiled_adapter_sha256=compiled, lanes=[])
    report_path = out/(mode+'.json')
    report_path.write_text(json.dumps(report, indent=2)+'\n')
    logs = []
    try:
        with tempfile.TemporaryDirectory(prefix='keytend-certificate-verify-') as directory:
            fixture_dir = pathlib.Path(directory)/'fixtures'
            fixture_dir.mkdir(mode=0o700)
            fixtures(fixture_dir)
            retained = out/(mode+'-fixtures')
            retained.mkdir(exist_ok=True)
            report['public_fixture_sha256'] = {}
            for path in fixture_dir.glob('*.der'):
                saved = retained/path.name
                shutil.copyfile(path, saved)
                report['public_fixture_sha256'][str(saved.relative_to(ROOT))] = sha(saved)
            server = HttpsContainer(directory, args.engine, args.image) if config else HttpsServer(directory)
            subprocess.run(['openssl', 'pkcs12', '-export', '-in', str(server.pki/'client.pem'), '-inkey', str(server.pki/'client.key'), '-certfile', str(server.pki/'ca.pem'), '-out', str(server.pki/'client.p12'), '-passout', 'pass:changeit'], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            manifests = [pathlib.Path(directory)/('jdk'+str(i)+'.tsv') for i in range(len(args.java))]
            try:
                server.start()
                for phase in ['create', 'restart', 'restore']:
                    if phase != 'create':
                        server.stop()
                        if phase == 'restore':
                            clean = pathlib.Path(directory)/'clean'
                            clean.mkdir(mode=0o700)
                            shutil.copyfile(backup, clean/'kmip.sqlite')
                            (clean/'kmip.sqlite').chmod(0o600)
                            server.data = clean
                        server.start()
                    for index, (java, manifest) in enumerate(zip(args.java, manifests)):
                        log = out/(mode+'-jdk'+str(index)+'-'+phase+'.log')
                        logs.append(log)
                        with log.open('w') as stream:
                            subprocess.run([java, '-cp', classpath, 'dev.keytend.kmip.interop.ServerCertificateVerify', str(server.pki), str(server.port), str(server.https), 'create' if phase == 'create' else 'verify', str(manifest), str(fixture_dir)], check=True, stdout=stream, stderr=subprocess.STDOUT, timeout=240)
                        rows = [line.split('\t') for line in log.read_text().splitlines()]
                        expected = {(code, transport) for code in [12, 13, 14, 20, 21] for transport in ['TLS', 'TTLV', 'JSON', 'XML']}
                        assert {(int(row[1]), row[2]) for row in rows} == expected and len(rows) == 20
                        assert all(row[0] == 'PASS' and len(row) == 7 for row in rows)
                        report['lanes'].append(dict(phase=phase, jdk=subprocess.check_output([java, '-version'], stderr=subprocess.STDOUT, text=True).splitlines()[0], validity_observations=sum(int(row[4]) for row in rows), nonfinal_observations=sum(int(row[5]) for row in rows), denial_observations=sum(int(row[6]) for row in rows), version_transport_pairs=20))
                    if phase == 'create':
                        if config:
                            subprocess.run(ContainerServer.base(server)+[args.image, 'backup', '--database', '/data/kmip.sqlite', '--master-key', '/tls/master.key', '--output', '/data/backup.sqlite'], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                            backup = server.data/'backup.sqlite'
                        else:
                            backup = pathlib.Path(directory)/'backup.sqlite'
                            subprocess.run([str(binary), 'backup', '--database', str(server.data/'kmip.sqlite'), '--master-key', str(server.pki/'master.key'), '--output', str(backup)], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                        report['encrypted_backup_sha256'] = sha(backup)
            finally:
                server.stop()
                if (pathlib.Path(directory)/'server.log').exists():
                    log = out/(mode+'-server.log')
                    shutil.copyfile(pathlib.Path(directory)/'server.log', log)
                    logs.append(log)
        report['status'] = 'passed'
    except Exception as error:
        report.update(status='failed', error=str(error))
        raise
    finally:
        report['log_sha256'] = {str(path.relative_to(ROOT)): sha(path) for path in logs}
        report_path.write_text(json.dumps(report, indent=2)+'\n')
    print('PASS certificate subject verification', mode, len(report['lanes']), 'JDK/recovery lanes')


if __name__ == '__main__':
    main()
