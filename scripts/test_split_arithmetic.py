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

"""Independent arithmetic checks, not KMIP operation or profile qualification.

This reference uses polynomial long division and explicit extension convolution,
not the server's shift/mask multiplier and Karatsuba extension formula. Python
integers independently check RustCrypto prime-field arithmetic. Only synthetic
test secrets are exchanged with the standalone Rust adapter.
"""
import argparse
import hashlib
import itertools
import json
import pathlib
import random
import subprocess

from image_evidence import source_commit
from test_runtime import ROOT


def sha(path):
    return hashlib.sha256(pathlib.Path(path).read_bytes()).hexdigest()


def gf8(a, b, polynomial):
    product = 0
    for bit in range(8):
        if b & (1 << bit):
            product ^= a << bit
    for bit in range(14, 7, -1):
        if product & (1 << bit):
            product ^= polynomial << (bit - 8)
    return product


def multiply(a, b, method, polynomial=None, prime=None):
    if method == 3:
        return (a * b) % prime
    if method == 4:
        return gf8(a, b, polynomial)
    # Convolve [constant, y] coefficients, then reduce the y^2 term
    # using y^2 = y + 0x3a. This is independent of the Rust formula.
    aa, bb = [a & 255, a >> 8], [b & 255, b >> 8]
    coefficients = [0, 0, 0]
    for i, x in enumerate(aa):
        for j, y in enumerate(bb):
            coefficients[i + j] ^= gf8(x, y, polynomial)
    coefficients[0] ^= gf8(coefficients[2], 0x3a, polynomial)
    coefficients[1] ^= coefficients[2]
    return coefficients[0] | (coefficients[1] << 8)


def power(a, exponent, mul):
    result = 1
    while exponent:
        if exponent & 1:
            result = mul(result, a)
        a = mul(a, a)
        exponent //= 2
    return result


def configuration(method, length, threshold=3, polynomial=2, prime=None):
    result = dict(method=method, parts=5, threshold=5 if method == 1 else threshold, secret_len=length)
    if method in [2, 4]:
        result['polynomial'] = polynomial
    if method == 3:
        if prime is None:
            prime = 257 if length == 1 else 65537 if length == 2 else (1 << 521) - 1
        result['prime'] = prime.to_bytes((prime.bit_length() + 7) // 8, 'big').hex()
    return result


def field(config):
    method = config['method']
    prime = int(config.get('prime', '0'), 16)
    polynomial = 283 if config.get('polynomial') == 1 else 285
    mul = lambda a, b: multiply(a, b, method, polynomial, prime)
    add = (lambda a, b: (a + b) % prime) if method == 3 else (lambda a, b: a ^ b)
    sub = (lambda a, b: (a - b) % prime) if method == 3 else add
    inverse = (lambda a: pow(a, -1, prime)) if method == 3 else (lambda a: power(a, 65534 if method == 2 else 254, mul))
    return mul, add, sub, inverse


def decode_words(value, config):
    data = bytes.fromhex(value)
    width = 2 if config['method'] == 2 else len(data) if config['method'] == 3 else 1
    return [int.from_bytes(data[i:i + width], 'big') for i in range(0, len(data), width)]


def encode_words(words, config):
    width = 2 if config['method'] == 2 else len(bytes.fromhex(config['prime'])) if config['method'] == 3 else 1
    return b''.join(w.to_bytes(width, 'big') for w in words)


def weights(shares, target, config):
    mul, _, sub, inverse = field(config)
    result = []
    for i, share in enumerate(shares):
        numerator, denominator = 1, 1
        for j, other in enumerate(shares):
            if i != j:
                numerator = mul(numerator, sub(target, other['index']))
                denominator = mul(denominator, sub(share['index'], other['index']))
        result.append(mul(numerator, inverse(denominator)))
    return result


def evaluate(shares, target, config):
    mul, add, _, _ = field(config)
    w = weights(shares, target, config)
    values = [decode_words(s['value'], config) for s in shares]
    output = []
    for column in zip(*values, strict=True):
        value = 0
        for ordinate, weight in zip(column, w, strict=True):
            value = add(value, mul(ordinate, weight))
        output.append(value)
    return encode_words(output, config)


def verify_rust_shares(shares, secret, config):
    assert [s['index'] for s in shares] == list(range(1, config['parts'] + 1))
    checks = 0
    if config['method'] == 1:
        recovered = bytearray(len(secret))
        for s in shares:
            for i, byte in enumerate(bytes.fromhex(s['value'])):
                recovered[i] ^= byte
        assert recovered == secret
        return 1
    for selected in itertools.combinations(shares, config['threshold']):
        recovered = evaluate(selected, 0, config)
        assert int.from_bytes(recovered, 'big') == int.from_bytes(secret, 'big')
        for extra in shares:
            assert evaluate(selected, extra['index'], config) == bytes.fromhex(extra['value'])
        checks += 1
    return checks


def reference_shares(secret, config, rng):
    if config['method'] == 1:
        shares = [rng.randbytes(len(secret)) for _ in range(config['parts'] - 1)]
        last = bytearray(secret)
        for s in shares:
            for i, byte in enumerate(s):
                last[i] ^= byte
        return [dict(index=i + 1, value=s.hex()) for i, s in enumerate(shares + [last])]
    raw = secret
    if config['method'] == 2 and len(raw) % 2:
        raw = b'\0' + raw
    words = decode_words(raw.hex(), config)
    mul, add, _, _ = field(config)
    order = int(config['prime'], 16) if config['method'] == 3 else 65536 if config['method'] == 2 else 256
    coefficients = [[word] + [rng.randrange(order) for _ in range(config['threshold'] - 1)] for word in words]
    shares = []
    for index in range(1, config['parts'] + 1):
        values = []
        for coefficient in coefficients:
            value = 0
            for c in reversed(coefficient):
                value = add(mul(value, index), c)
            values.append(value)
        shares.append(dict(index=index, value=encode_words(values, config).hex()))
    return shares


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--output', type=pathlib.Path, default=ROOT / 'artifacts/split-arithmetic.json')
    args = parser.parse_args()
    library = ROOT / 'target/debug/libkeytend_kmip_server.rlib'
    library_sha = sha(library)
    probe = ROOT / 'tools/split_probe.rs'
    executable = ROOT / '.cache/split-probe'
    command = ['rustc', '--edition=2024', str(probe), '-L', 'dependency=' + str(ROOT / 'target/debug/deps'),
               '--extern', 'keytend_kmip_server=' + str(library), '-o', str(executable)]
    dependencies = {}
    for name in ['serde_json', 'hex', 'zeroize', 'anyhow']:
        artifact = max((ROOT / 'target/debug/deps').glob('lib' + name + '-*.rlib'), key=lambda p: p.stat().st_mtime)
        dependencies[str(artifact.relative_to(ROOT))] = sha(artifact)
        command += ['--extern', name + '=' + str(artifact)]
    subprocess.run(command, check=True)

    def run(requests):
        result = subprocess.run([str(executable)], input=''.join(json.dumps(r) + '\n' for r in requests),
                                text=True, stdout=subprocess.PIPE, check=True, timeout=90)
        return [json.loads(line) for line in result.stdout.splitlines()]

    rng = random.Random(0x4b4d4950)  # Deterministic oracle fixtures only.
    cases = []
    for length in [1, 2, 3, 16, 31, 32, 33, 64]:
        for method, polynomial in [(1, None), (2, 1), (2, 2), (3, None), (4, 1), (4, 2)]:
            for threshold in [1, 2, 3, 5]:
                if method == 1 and threshold != 5:
                    continue
                config = configuration(method, length, threshold, polynomial)
                secret = rng.randbytes(length)
                if length % 2:
                    secret = b'\0' + secret[1:]  # Include fixed-width leading zeros.
                cases.append((config, secret))
    # Lucas-Lehmer independently proves the larger public test modulus prime.
    exponent = 1279
    prime = (1 << exponent) - 1
    ll = 4
    for _ in range(exponent - 2):
        ll = (ll * ll - 2) % prime
    assert ll == 0
    cases.append((configuration(3, 159, 3, prime=prime), rng.randbytes(159)))
    split_requests = [dict(**c, operation='split', secret=s.hex()) for c, s in cases]
    outputs = run(split_requests)
    assert len(outputs) == len(cases)
    reconstruction_checks = 0
    requests, expected = [], []
    for (config, secret), output in zip(cases, outputs, strict=True):
        assert 'error' not in output, (config, output)
        reconstruction_checks += verify_rust_shares(output['shares'], secret, config)
        shares = reference_shares(secret, config, rng)
        for selected in itertools.combinations(shares, config['threshold']):
            requests.append(dict(**config, operation='join', shares=list(reversed(selected))))
            expected.append(secret.hex())
        requests.append(dict(**config, operation='join', shares=list(reversed(shares))))
        expected.append(secret.hex())
        if config['method'] != 1 and config['threshold'] < config['parts']:
            corrupt = json.loads(json.dumps(shares))
            data = bytearray.fromhex(corrupt[-1]['value']); data[-1] ^= 1
            corrupt[-1]['value'] = data.hex()
            requests.append(dict(**config, operation='join', shares=corrupt)); expected.append(None)
        requests.append(dict(**config, operation='join', shares=shares[:config['threshold'] - 1])); expected.append(None)
        duplicate = [shares[0], shares[0]] + shares[1:]
        requests.append(dict(**config, operation='join', shares=duplicate)); expected.append(None)
    outputs = run(requests)
    assert len(outputs) == len(expected)
    for i, (output, want) in enumerate(zip(outputs, expected, strict=True)):
        if want is None:
            assert 'error' in output, ('expected rejection', i, requests[i], output)
        else:
            assert output.get('secret') == want, ('reconstruction differs', i, requests[i], output)
    report = dict(status='passed_arithmetic_backend',
                  scope='Offline arithmetic only; no KMIP object/operation, authorization, transport, persistence or database qualification.',
                  methods=['XOR', 'GF(2^8)/283', 'GF(2^8)/285', 'GF(2^16)/283', 'GF(2^16)/285', 'prime'],
                  rust_split_cases=len(cases), independent_reconstruction_checks=reconstruction_checks,
                  rust_join_cases=len(requests), expected_rejections=expected.count(None),
                  source_commit=source_commit()[0], runtime_library_sha256=library_sha,
                  probe_sha256=sha(executable), rust_dependency_sha256=dependencies)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps({k: v for k, v in report.items() if not k.endswith('sha256')}, indent=2))


if __name__ == '__main__':
    main()
