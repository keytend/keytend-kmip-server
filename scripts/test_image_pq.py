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

"""Draft 3.0 ML-DSA, SLH-DSA and ML-KEM through a built image (docs/algorithms.md#post-quantum-keys).

Starts the image twice over mutual TLS with KMIP_EXPERIMENTAL_V3=true: default
mode must list Encapsulate/Decapsulate, sign and verify with ML-DSA-65 and
SLH-DSA-SHA2-128f (a tampered signature is Invalid) and agree on an ML-KEM-768
shared secret; forced FIPS mode must hide the KEM operations and refuse ML-DSA
key generation. Containers get unique names and free ports and are removed.
"""
import argparse, json, pathlib, socket, subprocess, sys, tempfile, time, uuid
REPO = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO/'scripts'))
import wire as w

parser = argparse.ArgumentParser()
parser.add_argument('--image', required=True)
parser.add_argument('--engine', default='podman', choices=['podman'])
IMAGE = parser.parse_args().image
V = (3, 0)
FORCE = ['-e', 'OPENSSL_FORCE_FIPS_MODE=1']


def free_port():
    with socket.socket() as s:
        s.bind(('127.0.0.1', 0))
        return s.getsockname()[1]


def item(r):
    return w.get(r, 0x42000f)


def result(r):
    i = item(r)
    f = lambda t: w.children(i, t)[0][2] if w.children(i, t) else None
    return f(0x42007f), f(0x42007e), f(0x42007d)


def pair(c, alg, pmask, umask):
    r = w.exchange(c, w.request(2, [w.structure(0x420126, w.enumeration(0x420028, alg)),
                                    w.structure(0x420127, w.integer(0x42002c, pmask)),
                                    w.structure(0x420128, w.integer(0x42002c, umask))], V))
    if result(r)[0] != 0:
        return result(r)
    p = w.payload(r)
    ids = w.get(p, 0x420066)[2], w.get(p, 0x42006f)[2]
    for i in ids:
        w.payload(w.exchange(c, w.request(18, [w.uid(i, V)], V)))
    return ids


def secret(c, i):
    p = w.payload(w.exchange(c, w.request(10, [w.uid(i, V)], V)))
    return w.get(w.get(w.get(w.get(p, 0x420085), 0x420040), 0x420045), 0x420043)[2]


def probe(c, fips):
    out = {}
    q = w.payload(w.exchange(c, w.request(24, [w.enumeration(0x420074, 1)], V)))
    ops = [n[2] for n in w.children(q, 0x42005c)]
    out['query_lists_encapsulate_decapsulate'] = 65 in ops and 66 in ops
    ids = pair(c, 0x3D, 1, 2)
    if fips:
        out['create_ml_dsa_65'] = ids
        return out
    sk, pk = ids
    sig = w.get(w.payload(w.exchange(c, w.request(33, [w.uid(sk, V), w.binary(0x4200c2, b'image probe')], V))), 0x4200c3)[2]
    ok = w.get(w.payload(w.exchange(c, w.request(34, [w.uid(pk, V), w.binary(0x4200c2, b'image probe'), w.binary(0x4200c3, sig)], V))), 0x42009b)[2]
    bad = bytearray(sig); bad[5] ^= 1
    nok = w.get(w.payload(w.exchange(c, w.request(34, [w.uid(pk, V), w.binary(0x4200c2, b'image probe'), w.binary(0x4200c3, bytes(bad))], V))), 0x42009b)[2]
    out['ml_dsa_65'] = dict(signature_bytes=len(sig), valid=ok, tampered=nok)
    sk, pk = pair(c, 0x40, 1, 2)
    sig = w.get(w.payload(w.exchange(c, w.request(33, [w.uid(sk, V), w.binary(0x4200c2, b'image probe')], V))), 0x4200c3)[2]
    ok = w.get(w.payload(w.exchange(c, w.request(34, [w.uid(pk, V), w.binary(0x4200c2, b'image probe'), w.binary(0x4200c3, sig)], V))), 0x42009b)[2]
    out['slh_dsa_sha2_128f'] = dict(signature_bytes=len(sig), valid=ok)
    dk, ek = pair(c, 0x3A, 8, 4)
    p = w.payload(w.exchange(c, w.request(65, [w.uid(ek, V)], V)))
    ct = w.get(p, 0x4200c2)[2]
    s1 = secret(c, w.get(p, 0x420094)[2])
    p = w.payload(w.exchange(c, w.request(66, [w.uid(dk, V), w.binary(0x4200c2, ct)], V)))
    s2 = secret(c, w.get(p, 0x420094)[2])
    out['ml_kem_768'] = dict(ciphertext_bytes=len(ct), secret_bytes=len(s1), secrets_equal=s1 == s2)
    return out


def main():
    report = {'image': IMAGE}
    with tempfile.TemporaryDirectory(prefix='keytend-pqprobe-') as d:
        root = pathlib.Path(d); pki = root/'pki'
        subprocess.run(['bash', str(REPO/'scripts/dev-pki.sh'), str(pki)], check=True, stdout=subprocess.DEVNULL)
        userns = ['--userns', 'keep-id:uid=10001,gid=10001']
        subprocess.run(['podman', 'run', '--rm', '--network', 'none', *userns, '-v', f'{pki}:/out', IMAGE,
                        'generate-master-key', '--output', '/out/master.key'], check=True)
        for mode, options in [('default', []), ('fips', ['--fips'])]:
            data = root/f'data-{mode}'; data.mkdir(mode=0o700)
            name = 'keytend-pqprobe-'+uuid.uuid4().hex[:12]
            port, health = free_port(), free_port()
            subprocess.run(['podman', 'run', '-d', '--name', name, *userns, '--read-only', '--cap-drop=all',
                            '--security-opt=no-new-privileges', '--tmpfs', '/tmp:rw,nosuid,nodev,noexec,size=16m,mode=1777',
                            '-v', f'{pki}:/tls:ro', '-v', f'{data}:/data', '-e', 'KMIP_EXPERIMENTAL_V3=true',
                            '-p', f'127.0.0.1:{port}:5696', '-p', f'127.0.0.1:{health}:8080', *(FORCE if mode == 'fips' else []),
                            IMAGE, *options, 'serve', '--cert', '/tls/server.pem', '--key', '/tls/server.key', '--ca', '/tls/ca.pem',
                            '--policy', '/tls/policy.json', '--master-key', '/tls/master.key', '--database', '/data/kmip.sqlite'],
                           check=True, stdout=subprocess.DEVNULL)
            try:
                deadline = time.monotonic()+60
                while True:
                    try:
                        c = w.connect(pki, port); break
                    except OSError:
                        if time.monotonic() > deadline: raise
                        time.sleep(0.5)
                with c:
                    report[mode] = probe(c, mode == 'fips')
            finally:
                logs = subprocess.run(['podman', 'logs', name], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True).stdout
                subprocess.run(['podman', 'rm', '--force', '--time', '10', name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            report[mode]['fips_provider_logged'] = 'FIPS mode: OpenSSL FIPS provider loaded' in logs
    print(json.dumps(report, indent=1, default=str))
    dflt, fips = report['default'], report['fips']
    assert dflt['query_lists_encapsulate_decapsulate'] and not fips['query_lists_encapsulate_decapsulate']
    assert dflt['ml_dsa_65'] == dict(signature_bytes=3309, valid=1, tampered=2)
    assert dflt['slh_dsa_sha2_128f'] == dict(signature_bytes=17088, valid=1)
    assert dflt['ml_kem_768'] == dict(ciphertext_bytes=1088, secret_bytes=32, secrets_equal=True)
    assert fips['create_ml_dsa_65'][:2] == (1, 8) and 'FIPS mode' in fips['create_ml_dsa_65'][2]
    assert fips['fips_provider_logged'] and not dflt['fips_provider_logged']
    print('PASS')


if __name__ == '__main__':
    main()
