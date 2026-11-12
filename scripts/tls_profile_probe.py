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

"""Live mTLS handshake inventory of frozen native and image KMIP listeners.

Each probe is one `openssl s_client` connection with chain, hostname and client
certificate verification kept on. A handshake only counts as accepted when the
server also answers a KMIP Discover Versions request over it: in TLS 1.3 a
server rejects the client certificate after the client's Finished, so a bare
handshake can look successful. Suites, protocols and groups the pinned client
cannot offer are recorded as client-cannot-attempt before any connection and
never count as "server does not offer". Every connected probe is also bracketed
by the server's own plaintext `/connection-metrics` counters, so a rejection or
acceptance is attributed to the server only when its TLS counters agree (an
alert can be lost behind rootless port forwarding). A rejection of a suite whose
authentication type does not match the fixture's certificate is a credential
mismatch, not evidence about cipher policy. Results are observations, not profile
qualification. The server, host defaults and OpenSSL are never modified; the
only non-default client parameters are recorded per probe.

With --tls-profile the server runs under that policy (`keytend-kmip-server
tls-profiles` prints it). Probes are added for the listed suites at every
listed version and for "everything unlisted" (one connection offering every
other suite the client implements). Each fixture then gets a
policy_evaluation: every listed version, suite and group must negotiate
(given a matching credential) and everything else must be refused.

Under a Suite B policy the p256/p384 fixtures use all-ECDSA PKIs (an ECDSA CA
signing with its curve's hash, as RFC 6460 chains need) and add rows for each
TLS 1.2 signature scheme and group alone and for client certificates Suite B
must refuse; a negotiated row must use the level's suite, group and signature.
"""
import argparse, hashlib, json, os, pathlib, re, selectors, shutil, socket, subprocess, sys, tempfile, time, uuid
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import wire

ROOT = pathlib.Path(__file__).resolve().parents[1]
INVENTORY = ROOT / 'docs/specs/tls-profile-inventory.json'
DISCOVER_VERSIONS = 30
# Client-side diagnostic only: OpenSSL 3 refuses TLS 1.0/1.1 below security level 0.
LEGACY_CLIENT_CIPHER = 'DEFAULT:@SECLEVEL=0'

# TLS 1.2 suites probed: every listed KMIP suite the pinned client can name, plus
# the AEAD suites the runtime acceptor configures (mozilla_intermediate_v5).
TLS12_PROBES = [
    'TLS_RSA_WITH_AES_128_CBC_SHA256', 'TLS_RSA_WITH_AES_256_CBC_SHA256',
    'TLS_RSA_WITH_AES_128_CBC_SHA', 'TLS_RSA_WITH_AES_256_CBC_SHA',
    'TLS_DHE_RSA_WITH_AES_128_CBC_SHA', 'TLS_DHE_RSA_WITH_AES_256_CBC_SHA',
    'TLS_DHE_RSA_WITH_AES_128_CBC_SHA256', 'TLS_DHE_RSA_WITH_AES_256_CBC_SHA256',
    'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA', 'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256', 'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384',
    'TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA', 'TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256', 'TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384',
    'TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256', 'TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384',
    'TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256', 'TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384',
    'TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256', 'TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256',
    'TLS_DHE_RSA_WITH_AES_128_GCM_SHA256', 'TLS_DHE_RSA_WITH_AES_256_GCM_SHA384',
    # Listed only in 1.2-2.1 MAY lists; the pinned client is expected to lack them.
    'TLS_RSA_WITH_3DES_EDE_CBC_SHA', 'TLS_DH_RSA_WITH_AES_128_CBC_SHA', 'TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA',
    'TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256', 'TLS_DHE_DSS_WITH_AES_128_CBC_SHA', 'TLS_PSK_WITH_AES_128_CBC_SHA',
]
TLS13_PROBES = ['TLS_AES_128_GCM_SHA256', 'TLS_AES_256_GCM_SHA384', 'TLS_CHACHA20_POLY1305_SHA256',
                'TLS_AES_128_CCM_SHA256', 'TLS_AES_128_CCM_8_SHA256']
# OpenSSL group names; the 3.0 CSD02 Quantum Safe names match OpenSSL 3.5 spelling.
GROUP_PROBES = ['X25519MLKEM768', 'SecP256r1MLKEM768', 'SecP384r1MLKEM1024', 'x25519', 'secp256r1', 'secp384r1', 'ffdhe2048']
HTTPS_PROBES = ['tls1_3-default', 'tls1_3-TLS_AES_128_GCM_SHA256', 'tls1_2-TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256',
                'tls1_2-TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256', 'tls1_2-TLS_RSA_WITH_AES_128_CBC_SHA256']


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def run(args, **kw):
    return subprocess.run(args, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, **kw).stdout


def free_port():
    with socket.socket() as s:
        s.bind(('127.0.0.1', 0))
        return s.getsockname()[1]


def probes(policy=None):
    """Bounded probe list: (id, protocol flag, TLS 1.2 suite, TLS 1.3 suite, group, client identity, verify name)."""
    out = [dict(id='tls1-default', proto='tls1'), dict(id='tls1_1-default', proto='tls1_1'),
           dict(id='tls1_2-default', proto='tls1_2'), dict(id='tls1_3-default', proto='tls1_3')]
    out += [dict(id=f'tls1_2-{c}', proto='tls1_2', cipher=c) for c in TLS12_PROBES]
    out += [dict(id=f'tls1_3-{c}', proto='tls1_3', suite=c) for c in TLS13_PROBES]
    out += [dict(id=f'tls1_3-group-{g}', proto='tls1_3', group=g) for g in GROUP_PROBES]
    out += [dict(id='tls1_2-group-ffdhe2048-dhe', proto='tls1_2', cipher='TLS_DHE_RSA_WITH_AES_128_GCM_SHA256', group='ffdhe2048')]
    # Suite B (1.3/1.4 section 5.13) restricts ECDH to P-256/P-384; X25519 is recorded for contrast.
    out += [dict(id=f'tls1_2-group-{g}', proto='tls1_2', group=g) for g in ['secp256r1', 'secp384r1', 'x25519']]
    for proto in ['tls1_2', 'tls1_3']:
        out += [dict(id=f'{proto}-no-client-certificate', proto=proto, identity=None),
                dict(id=f'{proto}-foreign-ca-client', proto=proto, identity='foreign'),
                dict(id=f'{proto}-ca-valid-unlisted-client', proto=proto, identity='unlisted')]
    out += [dict(id='tls1_3-hostname-mismatch', proto='tls1_3', verify_name='wrong.invalid')]
    if policy:
        out += policy_probes(policy, {p['id'] for p in out})
    for p in out:
        p.setdefault('identity', 'client')
        p.setdefault('verify_name', 'localhost')
    return out


LEGACY_PROTOCOLS = ['tls1', 'tls1_1']
PROTO_NAMES = {'tls1': 'TLSv1.0', 'tls1_1': 'TLSv1.1', 'tls1_2': 'TLSv1.2', 'tls1_3': 'TLSv1.3'}


def policy_probes(policy, existing):
    """Probes a TLS profile policy adds: each listed suite at each listed version below TLS 1.3,
    one "every unlisted suite" offer per version, and the policy's groups."""
    out = []
    listed = [s['iana'] for s in policy['tls12_suites']]
    for proto in ['tls1', 'tls1_1', 'tls1_2']:
        for c in dict.fromkeys(listed + (TLS12_PROBES[:4] if proto in LEGACY_PROTOCOLS else [])):
            out.append(dict(id=f'{proto}-{c}', proto=proto, cipher=c))
        out.append(dict(id=f'{proto}-unlisted-all', proto=proto, unlisted=listed))
    others = [c for c in TLS13_PROBES if c not in policy['tls13_suites']]
    if others:
        out.append(dict(id='tls1_3-unlisted-all', proto='tls1_3', suites_offer=others))
    for g in policy['groups']:
        if f'tls1_3-group-{g}' not in existing:
            out.append(dict(id=f'tls1_3-group-{g}', proto='tls1_3', group=g))
    if policy.get('suite_b'):
        out += suite_b_probes(policy)
    return [p for p in out if p['id'] not in existing]


# Suite B (Profiles 1.3/1.4 section 5.13, RFC 6460 via OpenSSL's Suite B mode). The server
# signs with its certificate's key: ECDSA-256 (P-256 with SHA-256) or ECDSA-384 (P-384 with
# SHA-384). The other TLS 1.2 signature schemes are offered alone to show they are refused.
SUITE_B_SIGNATURE = {'ecdsa-p256': 'ecdsa_secp256r1_sha256', 'ecdsa-p384': 'ecdsa_secp384r1_sha384'}
SIGALG_PROBES = ['ecdsa_secp256r1_sha256', 'ecdsa_secp384r1_sha384', 'ecdsa_secp521r1_sha512', 'rsa_pss_rsae_sha256',
                 'rsa_pkcs1_sha256', 'ed25519']
# Client certificates of the Suite B PKIs (make_pki) that a Suite B policy must refuse.
SUITE_B_BAD_CLIENTS = {'client-rsa': 'RSA key', 'client-other-curve': "the other level's curve",
                       'client-wrong-hash': "signed with a hash other than its issuer curve's",
                       'client-no-digital-signature': 'key usage without digitalSignature'}
# Fixture servers whose identities come from the all-ECDSA Suite B PKIs (pki/suiteb-<curve>).
SUITE_B_SERVERS = ('p256', 'p384')


def suite_b_probes(policy):
    """Suite B rows: each signature scheme offered alone, and the policy's suite with each
    client certificate Suite B must refuse. Group rows at TLS 1.2 exist already (probes())."""
    suite = policy['tls12_suites'][0]['iana']
    # Every TLS 1.2 suite is offered, so the client can build a ClientHello for RSA schemes too.
    out = [dict(id=f'tls1_2-sigalgs-{a}', proto='tls1_2', sigalgs=a) for a in SIGALG_PROBES]
    out += [dict(id=f'tls1_2-suite-b-{c}', proto='tls1_2', cipher=suite, identity=c) for c in SUITE_B_BAD_CLIENTS]
    return out


def read_policy(binary, name, client):
    """The named policy as the runtime under test describes it (`keytend-kmip-server tls-profiles`).
    `modern` is described with OpenSSL names and colon lists; it is converted to the
    same shape as the KMIP policies (IANA suite names through the client's table)."""
    described = json.loads(run([binary, 'tls-profiles']))
    for p in described['policies']:
        if p['name'] == name:
            return dict(p, described_by_openssl=described['openssl'])
    if name == 'modern':
        m = described['modern']
        return dict(name='modern', versions=['TLSv1.2', 'TLSv1.3'], credential='any', suite_b=None, derived_from=[],
                    tls12_suites=[{'iana': client.iana[c]} for c in m['tls12_ciphers'].split(':')],
                    tls13_suites=m['tls13_suites'].split(':'), groups=m['groups'].split(':'),
                    signature_algorithms=m['signature_algorithms'].split(':'), security_level_0=False, warning=None,
                    described_by_openssl=described['openssl'])
    raise SystemExit(f'{binary} has no TLS profile {name!r}')


class Client:
    """Pinned OpenSSL command-line client; records version, binary and library hashes and config.

    With image, the client is the `openssl` command of that image (a pinned UBI image), run with
    `exec` in one long-lived container on the host network, with the temporary directory and
    `shares` mounted at the same paths; close() removes the container."""

    def __init__(self, binary=None, image=None, engine='podman', shares=()):
        self.image, self.engine, self.container = image, engine, None
        if image:
            self.container = f'keytend-tls-client-{uuid.uuid4().hex[:12]}'
            tmp = os.environ.get('TMPDIR') or '/tmp'
            volumes = [x for p in dict.fromkeys([tmp, *map(str, shares)]) for x in ('-v', f'{p}:{p}')]
            run([engine, 'run', '-d', '--rm', '--name', self.container, '--network', 'host', '--userns', 'keep-id',
                 '--user', f'{os.getuid()}:{os.getgid()}', *volumes, '--entrypoint', 'sleep', image, 'infinity'])
            self.command = [engine, 'exec', '-i', self.container, 'openssl']
            self.binary = f'{image}: openssl'
        else:
            self.binary = str(pathlib.Path(binary or shutil.which('openssl')).resolve())
            self.command = [self.binary]
        self.names = {}
        for line in run([*self.command, 'ciphers', '-stdname', 'ALL:COMPLEMENTOFALL:@SECLEVEL=0']).splitlines():
            parts = line.split()
            if len(parts) >= 3 and parts[1] == '-':
                self.names[parts[0]] = parts[2]
        self.iana = {v: k for k, v in self.names.items()}
        self.groups = set()
        try:
            self.groups = set(run([*self.command, 'list', '-tls-groups', '-tls1_3']).replace(':', ' ').split())
        except subprocess.CalledProcessError:
            pass

    def close(self):
        if self.container:
            subprocess.run([self.engine, 'rm', '-f', '-t', '0', self.container], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            self.container = None

    def identity(self):
        if self.image:
            config = run([self.engine, 'image', 'inspect', '--format', '{{.Id}}', self.image]).strip()
            m = re.search(r'OPENSSLDIR: "([^"]+)"', run([*self.command, 'version', '-d']))
            conf = f'{m.group(1)}/openssl.cnf'
            text = subprocess.run([self.engine, 'exec', self.container, 'cat', conf], stdout=subprocess.PIPE).stdout
            return {'image': self.image, 'image_id': config, 'version': run([*self.command, 'version']).strip(),
                    'openssl_conf': {'path': conf, 'source': 'OPENSSLDIR default', 'sha256': sha256(text) if text else None}}
        libs = {}
        for line in run(['ldd', self.binary]).splitlines():
            m = re.search(r'(lib(?:ssl|crypto)\.so\S*) => (\S+)', line)
            if m:
                path = pathlib.Path(m.group(2)).resolve()
                libs[m.group(1)] = {'path': str(path), 'sha256': sha256(path.read_bytes())}
        conf = os.environ.get('OPENSSL_CONF')
        if not conf:
            m = re.search(r'OPENSSLDIR: "([^"]+)"', run([*self.command, 'version', '-d']))
            conf = str(pathlib.Path(m.group(1), 'openssl.cnf'))
        conf_path = pathlib.Path(conf).resolve()
        return {'binary': self.binary, 'sha256': sha256(pathlib.Path(self.binary).read_bytes()),
                'version': run([*self.command, 'version']).strip(), 'libraries': libs,
                'openssl_conf': {'path': str(conf_path), 'source': 'OPENSSL_CONF' if os.environ.get('OPENSSL_CONF') else 'OPENSSLDIR default',
                                 'sha256': sha256(conf_path.read_bytes()) if conf_path.exists() else None}}

    def capability(self, p):
        """Return (can_attempt, diagnostic client parameters, reason) without connecting."""
        params = []
        legacy = p['proto'] in LEGACY_PROTOCOLS
        if legacy:
            params = ['-cipher', LEGACY_CLIENT_CIPHER]
            if not run([*self.command, 'ciphers', '-s', f'-{p["proto"]}', LEGACY_CLIENT_CIPHER]).strip():
                return False, params, 'client offers no suite for this protocol'
        if 'unlisted' in p:
            # Everything the client implements except the policy's suites (security level 0 so the
            # server alone decides). One refusal shows no unlisted suite is negotiable at this version.
            names = [self.names[c] for c in p['unlisted'] if c in self.names]
            params = ['-cipher', ':'.join(['ALL:COMPLEMENTOFALL'] + [f'!{n}' for n in names] + ['@SECLEVEL=0'])]
        if p.get('suites_offer'):
            params = ['-ciphersuites', ':'.join(p['suites_offer'])]
        if p.get('cipher'):
            name = self.names.get(p['cipher'])
            if not name:
                return False, params, 'suite not implemented by the pinned client'
            level = ':@SECLEVEL=0' if legacy else ''
            r = subprocess.run([*self.command, 'ciphers', '-s', '-stdname', f'-{p["proto"]}', name + level], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            if p['cipher'] not in r.stdout.split():
                return False, params, 'client would not offer this suite at this protocol version (security level, version or missing credential type)'
            if 'PSK' in p['cipher']:
                return False, params, 'PSK suite needs a pre-shared key the profile fixture does not define'
            params = ['-cipher', name + (':@SECLEVEL=0' if legacy else '')]
        if p.get('suite'):
            r = subprocess.run([*self.command, 'ciphers', '-s', '-stdname', '-tls1_3', '-ciphersuites', p['suite']], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            if r.returncode or p['suite'] not in r.stdout.split():
                return False, params, 'TLS 1.3 suite not available in the pinned client'
            params = ['-ciphersuites', p['suite']]
        if p.get('group'):
            if self.groups and p['group'] not in self.groups:
                return False, params, 'group not available in the pinned client'
            params = params + ['-groups', p['group']]
        if p.get('sigalgs'):
            params = params + ['-sigalgs', p['sigalgs']]
        return True, params, None


def parse_brief(stderr):
    """Extract `s_client -brief` connection facts."""
    facts = {}
    for line in stderr.splitlines():
        m = re.match(r'^(Protocol version|Ciphersuite|Peer certificate|Hash used|Signature type|Verification|Server Temp Key|Negotiated TLS1\.3 group|Peer Temp Key|Verified peername|Requested Signature Algorithms): (.*)$', line.strip())
        if m:
            facts[m.group(1)] = m.group(2).strip()
    return facts


def classify(stderr, response):
    """Classify one probe from client stderr and any decoded application response.

    OpenSSL prints "SSL alert number N" only for alerts received from the peer;
    alerts the client generates itself (e.g. failed server verification) lack it."""
    facts = parse_brief(stderr)
    if response is not None:
        return 'negotiated', facts, None
    received = re.search(r'alert ([a-z_ ]+):[^\n]*SSL alert number (\d+)', stderr)
    if received:
        return 'server-rejected', facts, f'{received.group(1).strip()} ({received.group(2)})'
    if re.search(r'certificate verify failed|verify error|hostname mismatch|Verification error', stderr, re.I):
        return 'client-rejected-server', facts, 'client verification of server failed'
    if re.search(r'no protocols available|no ciphers available|no cipher match|unsupported protocol|no suitable', stderr, re.I):
        return 'client-refused', facts, 'client could not build an acceptable ClientHello'
    if re.search(r'unexpected eof while reading', stderr) and not facts.get('Protocol version'):
        # Seen through rootless port forwarding: the server closed the handshake but no alert reached the client.
        return 'closed-during-handshake', facts, 'connection closed before handshake completion; no alert received'
    if re.search(r'Connection refused|connect:errno', stderr):
        return 'unreachable', facts, 'TCP connection failed'
    if facts.get('Protocol version'):
        return 'handshake-without-application-response', facts, 'handshake reported but no KMIP answer'
    return 'unclassified', facts, stderr.strip().splitlines()[-1] if stderr.strip() else 'no output'


DELTA_KEYS = ['tcp_accepted_total', 'tls_started_total', 'tls_succeeded_total', 'tls_failed_total', 'tls_timeout_total',
              'ttlv_responses_total', 'https_accepted_total', 'closed_total', 'error_total']


def server_metrics(health, timeout=2):
    """Server lifecycle counters from the plaintext health listener (no TLS connection)."""
    with socket.create_connection(('127.0.0.1', health), timeout=timeout) as c:
        c.sendall(b'GET /connection-metrics HTTP/1.1\r\nHost: localhost\r\n\r\n')
        data = b''
        while chunk := c.recv(65536):
            data += chunk
    head, _, body = data.partition(b'\r\n\r\n')
    if not head.startswith(b'HTTP/1.1 200'):
        raise OSError('connection-metrics unavailable')
    return json.loads(body)


def settled_delta(health, before, timeout=5):
    """Counter delta once the probe's connection has closed on the server, or None if it never settles."""
    until = time.monotonic() + timeout
    while True:
        after = server_metrics(health)
        if after['closed_total'] > before['closed_total'] and after['active'] == 0:
            return {k: after[k] - before[k] for k in DELTA_KEYS}
        if time.monotonic() >= until:
            return None
        time.sleep(.05)


def attribute(outcome, delta):
    """Combine the client view with the server's own counters for one connection."""
    if delta is None:
        return 'unattributed-server-did-not-settle'
    if delta['tls_started_total'] != 1 or delta['closed_total'] != 1:
        return 'unattributed-connection-count'
    ok, failed = delta['tls_succeeded_total'] == 1, delta['tls_failed_total'] == 1
    if outcome == 'negotiated':
        # The TLS counter decides; ttlv_responses_total is not raised for HTTPS answers or for the single
        # Permission Denied answer to an unlisted client (refuse_unlisted), so it is recorded, not required.
        return 'server-confirmed-negotiated' if ok and not failed else 'contradicted'
    if outcome == 'server-rejected':
        if failed:
            return 'server-confirmed-rejection'
        # TLS 1.3: the server completes its side, then refuses the client certificate or application data.
        return 'server-rejected-after-handshake' if ok and delta['ttlv_responses_total'] == 0 else 'contradicted'
    if outcome in ('closed-during-handshake', 'handshake-without-application-response', 'unclassified'):
        return 'server-recorded-tls-failure-alert-not-observed' if failed else 'unattributed'
    if outcome == 'client-rejected-server':
        return 'client-aborted-server-recorded-failure' if failed else 'unattributed'
    return 'unattributed'


def suite_credential(suite):
    """Server certificate type an IANA suite needs: rsa, ec, dsa, dh, psk, or any (TLS 1.3)."""
    if not suite.startswith('TLS_') or '_WITH_' not in suite:
        return 'any'
    kx = suite[4:suite.index('_WITH_')]
    if 'PSK' in kx:
        return 'psk'
    return {'RSA': 'rsa', 'DHE_RSA': 'rsa', 'ECDHE_RSA': 'rsa', 'ECDHE_ECDSA': 'ec', 'ECDH_ECDSA': 'ec',
            'ECDH_RSA': 'ec', 'DHE_DSS': 'dsa', 'DH_DSS': 'dh', 'DH_RSA': 'dh'}.get(kx, 'unknown')


def negotiated_group(facts):
    """Normalise the key-exchange group a client reported to an OpenSSL group name."""
    if facts.get('Negotiated TLS1.3 group'):
        return facts['Negotiated TLS1.3 group']
    key = facts.get('Peer Temp Key') or facts.get('Server Temp Key') or ''
    m = re.match(r'(X25519|X448)\b', key)
    if m:
        return m.group(1).lower()
    m = re.match(r'ECDH, (\w+),', key)
    if m:
        return {'prime256v1': 'secp256r1'}.get(m.group(1), m.group(1))
    m = re.match(r'DH, (\d+) bits', key)
    return f'ffdhe{m.group(1)}' if m and facts.get('Protocol version') == 'TLSv1.3' else (f'dh{m.group(1)}' if m else None)


def kmip_request():
    return wire.encode(wire.request(DISCOVER_VERSIONS, [], (1, 4)))


def https_request(path):
    body = kmip_request()
    head = (f'POST {path} HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/octet-stream\r\n'
            f'Content-Length: {len(body)}\r\nConnection: close\r\n\r\n').encode()
    return head + body


def complete(buffer, http):
    if http:
        end = buffer.find(b'\r\n\r\n')
        if end < 0:
            return False
        m = re.search(rb'content-length:\s*(\d+)', buffer[:end], re.I)
        return m is not None and len(buffer) >= end + 4 + int(m.group(1))
    return len(buffer) >= 8 and len(buffer) >= 8 + int.from_bytes(buffer[4:8], 'big')


def kmip_result(data, http):
    if http:
        status = data.split(b'\r\n', 1)[0].decode(errors='replace')
        data = data[data.find(b'\r\n\r\n') + 4:]
    else:
        status = None
    response = wire.decode(data)
    item = wire.get(response, 0x42000f)
    out = {'result_status': wire.get(item, 0x42007f)[2]}
    reasons = wire.children(item, 0x42007e)
    if reasons:
        out['result_reason'] = reasons[0][2]
    if status:
        out['http_status'] = status
    return out


def attempt(client, pki, port, p, params, http_path=None, timeout=10):
    """One bounded s_client connection. Returns (command, stdout bytes, stderr text, application response)."""
    args = [*client.command, 's_client', '-connect', f'127.0.0.1:{port}', '-servername', 'localhost',
            '-verify_hostname', p['verify_name'], '-verify_return_error', '-CAfile', str(pki / 'ca.pem'), '-brief',
            f'-{p["proto"]}'] + params
    if p['identity']:
        args += ['-cert', str(pki / f'{p["identity"]}.pem'), '-key', str(pki / f'{p["identity"]}.key')]
    proc = subprocess.Popen(args, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    request = https_request(http_path) if http_path else kmip_request()
    out = b''
    try:
        proc.stdin.write(request)
        proc.stdin.flush()
    except BrokenPipeError:
        pass
    sel = selectors.DefaultSelector()
    sel.register(proc.stdout, selectors.EVENT_READ)
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline and not complete(out, bool(http_path)):
        if not sel.select(max(0, deadline - time.monotonic())):
            break
        chunk = os.read(proc.stdout.fileno(), 65536)
        if not chunk:
            break
        out += chunk
    sel.close()
    try:
        proc.stdin.close()
    except BrokenPipeError:
        pass
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait()
    err = proc.stderr.read()
    proc.stdout.close()
    proc.stderr.close()
    response = None
    if complete(out, bool(http_path)):
        try:
            response = kmip_result(out, bool(http_path))
        except Exception as e:  # malformed answer is recorded, not credited
            response = None
            err = err + f'\nharness: undecodable application response: {e}'.encode()
    return args, out, err.decode(errors='replace'), response


def make_pki(directory, binary):
    """Own disposable PKI: RSA and ECDSA P-256 server identities, listed/unlisted/foreign clients."""
    d = pathlib.Path(directory)
    d.mkdir(mode=0o700, parents=True)
    def ossl(*a):
        subprocess.run(['openssl', *a], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    ca_ext = ['-addext', 'basicConstraints=critical,CA:TRUE', '-addext', 'keyUsage=critical,keyCertSign,cRLSign']
    for ca in ['ca', 'foreign-ca']:
        ossl('req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', str(d / f'{ca}.key'), '-out', str(d / f'{ca}.pem'),
             '-days', '2', '-subj', f'/CN=keytend-kmip-server-tls-probe-{ca}', *ca_ext)
    server_ext = 'basicConstraints=critical,CA:FALSE\nextendedKeyUsage=serverAuth\nsubjectAltName=DNS:localhost,IP:127.0.0.1\n'
    roles = {'server-rsa': ('rsa:2048', 'ca', server_ext + 'keyUsage=critical,digitalSignature,keyEncipherment\n'),
             'server-ecdsa': ('ec', 'ca', server_ext + 'keyUsage=critical,digitalSignature\n'),
             'client': ('rsa:2048', 'ca', None), 'unlisted': ('rsa:2048', 'ca', None), 'foreign': ('rsa:2048', 'foreign-ca', None)}
    client_ext = 'basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=clientAuth\n'
    for name, (alg, ca, ext) in roles.items():
        key = ['-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256'] if alg == 'ec' else ['-newkey', alg]
        ossl('req', '-new', *key, '-nodes', '-keyout', str(d / f'{name}.key'), '-out', str(d / f'{name}.csr'), '-subj', f'/CN={name}')
        (d / f'{name}.ext').write_text(ext or client_ext)
        ossl('x509', '-req', '-in', str(d / f'{name}.csr'), '-CA', str(d / f'{ca}.pem'), '-CAkey', str(d / f'{ca}.key'),
             '-CAcreateserial', '-out', str(d / f'{name}.pem'), '-days', '2', '-sha256', '-extfile', str(d / f'{name}.ext'))
    write_policy(d)
    subprocess.run([binary, 'generate-master-key', '--output', str(d / 'master.key')], check=True)
    for curve in SUITE_B_SERVERS:
        make_suite_b_pki(d / f'suiteb-{curve}', curve)
        shutil.copy(d / 'master.key', d / f'suiteb-{curve}' / 'master.key')
    return d


def write_policy(d):
    der = subprocess.run(['openssl', 'x509', '-in', str(d / 'client.pem'), '-outform', 'DER'], check=True, stdout=subprocess.PIPE).stdout
    (d / 'policy.json').write_text(json.dumps({'principals': {sha256(der): {'name': 'tls-probe', 'operations': list(range(1, 67))}}}, indent=2) + '\n')


# Per Suite B PKI: its curve, the hash of that curve (RFC 6460: a certificate is signed with the
# hash of its issuer's curve), the other level's curve, and a hash that does not match the curve.
SUITE_B_PKI = {'p256': ('P-256', 'sha256', 'P-384', 'sha384'), 'p384': ('P-384', 'sha384', 'P-256', 'sha256')}


def make_suite_b_pki(d, level):
    """All-ECDSA PKI for the Suite B policies: an ECDSA CA on the level's curve signing with that
    curve's hash, a server on that curve, listed/unlisted/foreign clients, and the client
    certificates Suite B must refuse (SUITE_B_BAD_CLIENTS). Never committed; generated per run."""
    curve, digest, other_curve, other_digest = SUITE_B_PKI[level]
    d.mkdir(mode=0o700)
    def ossl(*a):
        subprocess.run(['openssl', *a], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    ec = lambda c: ['-newkey', 'ec', '-pkeyopt', f'ec_paramgen_curve:{c}']
    ca_ext = ['-addext', 'basicConstraints=critical,CA:TRUE', '-addext', 'keyUsage=critical,keyCertSign,cRLSign']
    for ca in ['ca', 'foreign-ca']:
        ossl('req', '-x509', *ec(curve), '-nodes', f'-{digest}', '-keyout', str(d / f'{ca}.key'), '-out', str(d / f'{ca}.pem'),
             '-days', '2', '-subj', f'/CN=keytend-kmip-server-tls-probe-suiteb-{level}-{ca}', *ca_ext)
    server_ext = ('basicConstraints=critical,CA:FALSE\nextendedKeyUsage=serverAuth\nsubjectAltName=DNS:localhost,IP:127.0.0.1\n'
                  'keyUsage=critical,digitalSignature\n')
    client_ext = 'basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=clientAuth\n'
    roles = {f'server-{level}': (ec(curve), 'ca', digest, server_ext), 'client': (ec(curve), 'ca', digest, client_ext),
             'unlisted': (ec(curve), 'ca', digest, client_ext), 'foreign': (ec(curve), 'foreign-ca', digest, client_ext),
             'client-rsa': (['-newkey', 'rsa:2048'], 'ca', digest, client_ext),
             'client-other-curve': (ec(other_curve), 'ca', digest, client_ext),
             'client-wrong-hash': (ec(curve), 'ca', other_digest, client_ext),
             'client-no-digital-signature': (ec(curve), 'ca', digest, client_ext.replace('digitalSignature', 'keyAgreement'))}
    for name, (key, ca, md, ext) in roles.items():
        ossl('req', '-new', *key, '-nodes', '-keyout', str(d / f'{name}.key'), '-out', str(d / f'{name}.csr'), '-subj', f'/CN={name}')
        (d / f'{name}.ext').write_text(ext)
        ossl('x509', '-req', '-in', str(d / f'{name}.csr'), '-CA', str(d / f'{ca}.pem'), '-CAkey', str(d / f'{ca}.key'),
             '-CAcreateserial', '-out', str(d / f'{name}.pem'), '-days', '2', f'-{md}', '-extfile', str(d / f'{name}.ext'))
    write_policy(d)


def pki_identity(pki):
    out = {}
    names = ['ca', 'foreign-ca', 'server-rsa', 'server-ecdsa', 'client', 'unlisted', 'foreign']
    for level in SUITE_B_SERVERS:
        names += [f'suiteb-{level}/{n}' for n in ['ca', 'foreign-ca', f'server-{level}', 'client', 'unlisted', 'foreign', *SUITE_B_BAD_CLIENTS]]
    for name in names:
        text = run(['openssl', 'x509', '-in', str(pki / f'{name}.pem'), '-noout', '-subject', '-issuer', '-fingerprint', '-sha256', '-ext', 'keyUsage,extendedKeyUsage,subjectAltName'])
        pub = run(['openssl', 'x509', '-in', str(pki / f'{name}.pem'), '-noout', '-text'])
        m = re.search(r'Public Key Algorithm: (\S+)', pub)
        bits = re.search(r'Public-Key: \((\d+) bit\)', pub)
        curve = re.search(r'NIST CURVE: (\S+)', pub)
        sig = re.search(r'Signature Algorithm: (\S+)', pub)
        out[name] = {'certificate_sha256': re.search(r'Fingerprint=([0-9A-F:]+)', text).group(1).replace(':', '').lower(),
                     'subject': re.search(r'subject=(.*)', text).group(1).strip(), 'issuer': re.search(r'issuer=(.*)', text).group(1).strip(),
                     'public_key': m.group(1), 'bits': int(bits.group(1)), 'curve': curve.group(1) if curve else None,
                     'signature': sig.group(1),
                     'extensions': ' '.join(l.strip() for l in text.splitlines() if not re.match(r'(subject|issuer|sha256 Fingerprint)=', l))}
    return out


def mapped_tls_libraries(pid):
    """libssl/libcrypto files the live server process has mapped, with their on-disk hashes."""
    paths = sorted({line.split()[-1] for line in pathlib.Path(f'/proc/{pid}/maps').read_text().splitlines()
                    if re.search(r'/lib(ssl|crypto)\.so[.\d]*$', line)})
    return {'source': f'/proc/{pid}/maps', 'openssl_conf_env': os.environ.get('OPENSSL_CONF'),
            'libraries': {p: sha256(pathlib.Path(p).read_bytes()) for p in paths}}


# FIPS mode (--fips). The image fixture emulates a FIPS host: RHEL's libcrypto test switch plus
# the server flag (the server reads /proc/sys/crypto/fips_enabled, which a container cannot fake).
# A native fixture needs a FIPS provider named by KEYTEND_FIPS_OPENSSL_CONF/MODULES (scripts/fips-server.sh).
IMAGE_FIPS_ENV = ['-e', 'OPENSSL_FORCE_FIPS_MODE=1']


def native_fips_env():
    env = {'KMIP_FIPS': 'true'}
    for source, target in [('KEYTEND_FIPS_OPENSSL_CONF', 'OPENSSL_CONF'), ('KEYTEND_FIPS_OPENSSL_MODULES', 'OPENSSL_MODULES')]:
        if os.environ.get(source):
            env[target] = os.environ[source]
    return env


class Native:
    def __init__(self, binary, pki, server, root, https, tls_profile=None, fips=False):
        self.binary, self.pki, self.server, self.root = binary, pki, server, pathlib.Path(root)
        self.tls_profile = tls_profile
        self.fips = fips
        self.port, self.health = free_port(), free_port()
        self.https = free_port() if https else None
        self.data = self.root / 'data'
        self.data.mkdir(mode=0o700, parents=True)
        self.log_path = self.root / 'server.log'
        self.process = None

    def __enter__(self):
        args = [self.binary, 'serve', '--listen', f'127.0.0.1:{self.port}', '--health-listen', f'127.0.0.1:{self.health}',
                '--cert', str(self.pki / f'{self.server}.pem'), '--key', str(self.pki / f'{self.server}.key'),
                '--ca', str(self.pki / 'ca.pem'), '--policy', str(self.pki / 'policy.json'),
                '--database', str(self.data / 'kmip.sqlite'), '--master-key', str(self.pki / 'master.key')]
        if self.https:
            args += ['--https-listen', f'127.0.0.1:{self.https}']
        if self.tls_profile:
            args += ['--tls-profile', self.tls_profile]
        self.command = args
        self.log = open(self.log_path, 'ab')
        self.process = subprocess.Popen(args, stdout=self.log, stderr=self.log, env={**os.environ, **(native_fips_env() if self.fips else {})})
        try:
            wait_ready(self.health, self.port, lambda: self.process.poll() is None)
            self.tls_library = mapped_tls_libraries(self.process.pid)
        except BaseException:
            self.__exit__()
            raise
        return self

    def __exit__(self, *exc):
        if self.process and self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(timeout=25)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait()
        if hasattr(self, 'log'):
            self.log.close()
        self.closed = self.process is None or self.process.poll() is not None


class Container:
    def __init__(self, engine, image, image_id, pki, server, root, tls_profile=None, fips=False):
        self.engine, self.image, self.image_id, self.pki, self.server, self.root = engine, image, image_id, pki, server, pathlib.Path(root)
        self.tls_profile = tls_profile
        self.fips = fips
        self.port, self.health, self.https = free_port(), free_port(), None
        self.name = 'keytend-tlsprobe-' + uuid.uuid4().hex[:12]
        self.tls = self.root / 'tls'
        self.data = self.root / 'data'
        self.tls.mkdir(mode=0o700, parents=True)
        self.data.mkdir(mode=0o700)
        for src, dst in [(f'{server}.pem', 'server.pem'), (f'{server}.key', 'server.key'), ('ca.pem', 'ca.pem'), ('master.key', 'master.key'), ('policy.json', 'policy.json')]:
            shutil.copy(pki / src, self.tls / dst)
        self.log_path = self.root / 'server.log'
        self.started = False

    def exists(self):
        r = subprocess.run([self.engine, 'container', 'exists', self.name], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if r.returncode not in (0, 1):
            r.check_returncode()
        return r.returncode == 0

    def __enter__(self):
        actual = run([self.engine, 'image', 'inspect', '--format', '{{.Id}}', self.image]).strip()
        if actual != self.image_id:
            raise RuntimeError(f'image {self.image} is {actual}, expected {self.image_id}')
        userns = ['--userns', 'keep-id:uid=10001,gid=10001'] if self.engine == 'podman' else ['--user', f'{os.getuid()}:{os.getgid()}']
        # No --rm: logs, including shutdown counters, are read after stop; the owned container is then removed.
        self.command = [self.engine, 'run', '-d', '--name', self.name, *userns, '--read-only',
                        '--tmpfs', '/tmp:rw,nosuid,nodev,noexec,size=64m,mode=1777', '--cap-drop=all', '--security-opt=no-new-privileges',
                        '--pids-limit=128', '--memory=256m', '--cpus=2', '-v', f'{self.tls}:/tls:ro', '-v', f'{self.data}:/data',
                        '-p', f'127.0.0.1:{self.port}:5696', '-p', f'127.0.0.1:{self.health}:8080',
                        *(IMAGE_FIPS_ENV if self.fips else []), self.image_id, *(['--fips'] if self.fips else []),
                        'serve', '--cert', '/tls/server.pem', '--key', '/tls/server.key', '--ca', '/tls/ca.pem',
                        '--master-key', '/tls/master.key', '--policy', '/tls/policy.json', '--database', '/data/kmip.sqlite']
        if self.tls_profile:
            self.command += ['--tls-profile', self.tls_profile]
        run(self.command)
        self.started = True
        try:
            wait_ready(self.health, self.port, self.exists, timeout=30)
        except BaseException:
            self.__exit__()
            raise
        return self

    def __exit__(self, *exc):
        if self.started and self.exists():
            try:
                run([self.engine, 'stop', '--time', '20', self.name])
                logs = subprocess.run([self.engine, 'logs', self.name], stdout=subprocess.PIPE, stderr=subprocess.STDOUT).stdout
                self.log_path.write_bytes(logs)
            finally:
                run([self.engine, 'rm', '--force', self.name])
        self.closed = not self.exists()
        if not self.closed:
            raise RuntimeError('owned probe container was not removed: ' + self.name)


def wait_ready(health, port, alive, timeout=15):
    """Readiness via the plaintext health listener and a TCP connect, without TLS handshakes."""
    until = time.monotonic() + timeout
    while time.monotonic() < until:
        if not alive():
            raise RuntimeError('server exited before readiness')
        try:
            with socket.create_connection(('127.0.0.1', health), timeout=.3) as c:
                c.sendall(b'GET /readyz HTTP/1.1\r\nHost: localhost\r\n\r\n')
                if not c.recv(64).startswith(b'HTTP/1.1 200'):
                    raise OSError('not ready')
            with socket.create_connection(('127.0.0.1', port), timeout=.3):
                return
        except OSError:
            time.sleep(.1)
    raise TimeoutError('server did not become ready')


def run_fixture(client, fixture, pki, raw_dir, selected, credential):
    raw_dir.mkdir(parents=True)
    results = []
    plan = [(p, None) for p in selected]
    if fixture.https:
        by_id = {p['id']: p for p in selected}
        plan += [(dict(by_id[i], id='https-' + i), '/kmip') for i in HTTPS_PROBES]
    for p, path in plan:
        ok, params, reason = client.capability(p)
        record = {k: p.get(k) for k in ['id', 'proto', 'cipher', 'suite', 'group', 'sigalgs', 'identity', 'verify_name']}
        if 'unlisted' in p or p.get('suites_offer'):
            record['offer'] = 'every-unlisted'

        record['listener'] = 'https' if path else 'ttlv'
        record['client_parameters'] = params
        record['diagnostic_client_parameters'] = [x for x in params if 'SECLEVEL' in x]
        needs = suite_credential(p.get('cipher') or p.get('suite') or '')
        record['credential_compatible'] = needs in ('any', credential)
        if ok and p['identity'] and not (pki / f'{p["identity"]}.pem').exists():
            ok, reason = False, 'the fixture PKI has no such client identity'
        if not ok:
            record.update(outcome='client-cannot-attempt', detail=reason)
            results.append(record)
            continue
        port = fixture.https if path else fixture.port
        before = server_metrics(fixture.health)
        args, out, err, response = attempt(client, pki, port, p, params, path)
        delta = settled_delta(fixture.health, before)
        outcome, facts, detail = classify(err, response)
        raw = (f'$ {" ".join(args)}\n--- stderr ---\n{err}\n--- stdout ({len(out)} bytes) ---\n{out.hex()}\n'
               f'--- server counter delta ---\n{json.dumps(delta, sort_keys=True)}\n').encode()
        (raw_dir / f'{record["id"]}.log').write_bytes(raw)
        if facts.get('Ciphersuite'):
            facts['Ciphersuite (IANA)'] = client.iana.get(facts['Ciphersuite'], facts['Ciphersuite'])
        record.update(outcome=outcome, facts=facts, detail=detail, kmip=response, raw_sha256=sha256(raw),
                      server_delta=delta, attribution=attribute(outcome, delta),
                      negotiated_group=negotiated_group(facts) if outcome == 'negotiated' else None)
        results.append(record)
        time.sleep(.05)
    return results


def suite_sets(inventory):
    """Per edition/suite: protocols, unconditional and per-protocol conditional requirements, allowed (closed list or None)."""
    out = {}
    for edition, e in inventory['editions'].items():
        for name, s in e['suites'].items():
            proto, ciphers = s.get('protocols'), s.get('ciphers')
            if not isinstance(proto, dict) or not isinstance(ciphers, dict):
                continue
            required12 = set(ciphers.get('shall', []) + ciphers.get('server_shall', []))
            if_tls12 = set(ciphers.get('tls12_shall_if_tls12', []))
            # A MAY list given by reference (or by an unpinned external table) never closes a list.
            may = (ciphers.get('may') if isinstance(ciphers.get('may'), list) else []) + ciphers.get('tls12_may_if_tls12', [])
            tls13 = set(ciphers.get('tls13_server_shall_all', []))
            if_tls13 = set(ciphers.get('tls13_server_shall_all_if_tls13', []))
            closed = ciphers.get('closed_list') is True and not isinstance(ciphers.get('server_may'), str)
            groups = s.get('groups', {})
            out[(edition, name)] = {
                'protocols_required': sorted(set(proto.get('shall', []) + proto.get('server_shall', []))),
                'protocols_forbidden': sorted(set(proto.get('shall_not', [])) |
                    (set(['TLSv1.0','TLSv1.1','TLSv1.2','TLSv1.3']) - set(proto['only']) if proto.get('only') else set())),
                'protocols_only': proto.get('only', []),
                'modelled': s.get('modelled', not name.startswith('suite_b_')),
                'tls12_required': sorted(required12), 'tls12_required_if_tls12': sorted(if_tls12),
                'tls13_required': sorted(tls13), 'tls13_required_if_tls13': sorted(if_tls13),
                'allowed': sorted(required12 | if_tls12 | set(may) | tls13 | if_tls13) if closed else None,
                'groups_required': groups.get('server_shall_all', []),
                'groups_allowed': groups.get('server_shall_all') if groups.get('closed_list') else None}
    return out


# Attributions under which the client's view is backed by the server's own counters.
CONFIRMED = {'negotiated': {'server-confirmed-negotiated'},
             'rejected': {'server-confirmed-rejection', 'server-rejected-after-handshake',
                          'server-recorded-tls-failure-alert-not-observed'}}


def effective(r):
    """Evaluation status of one probe row. Rows without an attribution (older captures, unit rows)
    use the client view; a recorded attribution must agree with it."""
    if r['outcome'] == 'client-cannot-attempt':
        return 'untested-client-cannot-attempt'
    a = r.get('attribution')
    if r['outcome'] == 'negotiated':
        return 'negotiated' if a is None or a in CONFIRMED['negotiated'] else 'inconclusive'
    rejected = r['outcome'] == 'server-rejected' and (a is None or a in CONFIRMED['rejected'])
    rejected = rejected or a == 'server-recorded-tls-failure-alert-not-observed'
    if rejected:
        return 'server-rejected' if r.get('credential_compatible', True) else 'untested-credential-mismatch'
    return 'inconclusive'


def evaluate(inventory, results):
    """Compare observations of one fixture with each authentication suite. Pure and fail-closed:
    a requirement is only 'missing' when the client could attempt it, the fixture holds a matching
    credential and the server refused."""
    seen = [r for r in results if r['listener'] == 'ttlv' and r.get('identity') == 'client' and r.get('verify_name') == 'localhost']
    negotiated = [r for r in seen if effective(r) == 'negotiated']
    neg = {r['facts'].get('Ciphersuite (IANA)') for r in negotiated}
    neg_protocols = {('TLSv1.0' if r['facts'].get('Protocol version') == 'TLSv1' else r['facts'].get('Protocol version')) for r in negotiated}
    neg_groups = {r.get('negotiated_group') or negotiated_group(r['facts']) for r in negotiated
                  if r['facts'].get('Protocol version', 'TLSv1.3') == 'TLSv1.3'} - {None}
    def status(suite_name=None, proto=None, group=None):
        rows = [r for r in seen if (suite_name is None or r.get('cipher') == suite_name or r.get('suite') == suite_name)
                and (proto is None or (r['proto'] == proto and not r.get('cipher') and not r.get('suite') and not r.get('group')))
                and (group is None or (r.get('group') == group and r['proto'] == 'tls1_3'))]
        states = {effective(r) for r in rows}
        for st in ['negotiated', 'server-rejected']:
            if st in states:
                return st
        if len(states) == 1:
            return states.pop()
        return 'untested' if not rows else 'inconclusive'
    names = {'TLSv1.0': 'tls1', 'TLSv1.1': 'tls1_1', 'TLSv1.2': 'tls1_2', 'TLSv1.3': 'tls1_3'}
    findings = {}
    for (edition, suite), s in suite_sets(inventory).items():
        f = {'missing_required': [], 'untested_required': [], 'outside_closed_list': [], 'forbidden_protocols_accepted': [],
             'required_protocols_missing': [], 'conditions': [], 'modelled':s['modelled'],
             'scope':'protocol/cipher/group subset only; not an authentication-profile verdict'}
        for p in s['protocols_required']:
            st = 'negotiated' if p in neg_protocols else status(proto=names.get(p))
            if st != 'negotiated':
                (f['required_protocols_missing'] if st == 'server-rejected' else f['untested_required']).append(f'{p}: {st}')
        for p in s['protocols_forbidden']:
            if p in neg_protocols or (names.get(p) and status(proto=names[p]) == 'negotiated'):
                f['forbidden_protocols_accepted'].append(p)
        required = list(s['tls12_required']) + list(s['tls13_required'])
        for proto, extra in [('TLSv1.2', s['tls12_required_if_tls12']), ('TLSv1.3', s['tls13_required_if_tls13'])]:
            if extra:
                applies = proto in neg_protocols
                f['conditions'].append(f'{proto} suites {"apply: server support observed" if applies else "not applied: server support not observed"}')
                required += extra if applies else []
        for c in required:
            st = status(suite_name=c)
            if st == 'server-rejected':
                f['missing_required'].append(c)
            elif st != 'negotiated':
                f['untested_required'].append(f'{c}: {st}')
        for g in s['groups_required']:
            st = status(group=g)
            if st == 'server-rejected':
                f['missing_required'].append(g)
            elif st != 'negotiated':
                f['untested_required'].append(f'{g}: {st}')
        if s['allowed'] is not None:
            f['outside_closed_list'] = sorted(c for c in neg if c and c not in s['allowed'])
        if s['groups_allowed'] is not None:
            f['outside_closed_list'] += sorted(g for g in neg_groups if g not in s['groups_allowed'])
        f['closed_list'] = s['allowed'] is not None
        subset_conflict = bool(f['missing_required'] or f['outside_closed_list'] or f['forbidden_protocols_accepted'] or f['required_protocols_missing'])
        f['observed_subset_conflict'] = subset_conflict
        f['would_conflict_if_claimed'] = subset_conflict if f['modelled'] else None
        if not f['modelled']:
            f['unmodelled_requirements'] = ['Suite B peer credentials/RFC5759, primitive-column coherence and complete profile']
        findings[f'{edition}/{suite}'] = f
    return findings


def valid_at(suite, proto):
    """A TLS 1.0-1.2 suite with an HMAC-SHA1 CBC record layer also runs on TLS 1.0/1.1; the others need TLS 1.2."""
    return proto == 'tls1_2' or suite.endswith('_CBC_SHA')


def policy_expectation(policy, r, credential):
    """(True: must negotiate | False: must be refused | None: not a policy row, reason) for one probe row."""
    if policy.get('suite_b') and r.get('identity') in SUITE_B_BAD_CLIENTS and r.get('verify_name') == 'localhost':
        return False, f'Suite B refuses a client certificate with {SUITE_B_BAD_CLIENTS[r["identity"]]}'
    if r.get('identity') != 'client' or r.get('verify_name') != 'localhost':
        return None, 'authentication probe, evaluated per edition only'
    version = PROTO_NAMES[r['proto']]
    if version not in policy['versions']:
        return False, f'{version} is not listed'
    if r.get('offer') == 'every-unlisted':
        return False, 'only unlisted suites offered'
    listed = [s['iana'] for s in policy['tls12_suites']]
    if r.get('sigalgs'):
        expected = SUITE_B_SIGNATURE.get(policy.get('credential'))
        return (r['sigalgs'] == expected), ('the Suite B signature' if r['sigalgs'] == expected else f'only {expected} can be used')
    if r.get('cipher'):
        if r['cipher'] not in listed:
            return False, 'unlisted suite'
        if not valid_at(r['cipher'], r['proto']):
            return False, f'listed suite not defined for {version}'
        if suite_credential(r['cipher']) not in ('any', credential):
            return False, 'listed, but the fixture credential cannot serve it'
        return True, 'listed suite'
    if r.get('suite'):
        return (True, 'listed suite') if r['suite'] in policy['tls13_suites'] else (False, 'unlisted suite')
    if r.get('group'):
        if r['proto'] == 'tls1_3' or policy.get('suite_b'):
            # Suite B binds the ECDHE group to the level; no static-RSA fallback exists.
            return (True, 'listed group') if r['group'] in policy['groups'] else (False, 'unlisted group')
        return None, 'TLS 1.2 group rows depend on static-RSA fallback and the certificate curve (RFC 8422 5.3)'
    if r['proto'] == 'tls1_3':
        return bool(policy['tls13_suites']), 'listed version'
    usable = [c for c in listed if valid_at(c, r['proto']) and suite_credential(c) in ('any', credential)]
    return (True, 'listed version') if usable else (False, 'no listed suite for this version and credential')


def evaluate_policy(policy, results, credential):
    """Compare one fixture's observations with the policy the server ran. Fail-closed: a row the client
    could not attempt or the server counters do not confirm is untested, never a match."""
    out = {'policy': policy['name'], 'credential': credential, 'rows_checked': 0, 'matches': 0, 'mismatches': [],
           'untested': [], 'not_evaluated': 0, 'negotiated_outside_policy': []}
    listed = {s['iana'] for s in policy['tls12_suites']} | set(policy['tls13_suites'])
    for r in results:
        expected, reason = policy_expectation(policy, r, credential)
        if expected is None:
            out['not_evaluated'] += 1
            continue
        state = effective(r)
        observed = {'negotiated': True, 'server-rejected': False, 'untested-credential-mismatch': False}.get(state)
        key = f'{r["listener"]}:{r.get("id")}'
        if observed is None:
            out['untested'].append(f'{key}: {state}')
            continue
        out['rows_checked'] += 1
        if observed != expected:
            out['mismatches'].append(f'{key}: expected {"negotiated" if expected else "refused"} ({reason}), observed {state}')
            continue
        out['matches'] += 1
        if observed:
            facts = r.get('facts') or {}
            version = 'TLSv1.0' if facts.get('Protocol version') == 'TLSv1' else facts.get('Protocol version')
            suite = facts.get('Ciphersuite (IANA)')
            group = r.get('negotiated_group')
            if version not in policy['versions'] or suite not in listed:
                out['negotiated_outside_policy'].append(f'{key}: {version} {suite}')
            if (version == 'TLSv1.3' or policy.get('suite_b')) and policy['groups'] and group not in policy['groups']:
                out['negotiated_outside_policy'].append(f'{key}: group {group}')
            signature = SUITE_B_SIGNATURE.get(policy.get('credential')) if policy.get('suite_b') else None
            if signature and facts.get('Signature type') != signature:
                out['negotiated_outside_policy'].append(f'{key}: signature {facts.get("Signature type")}')
    out['verdict'] = ('matches-policy' if out['rows_checked'] and not out['mismatches'] and not out['negotiated_outside_policy']
                      else 'mismatch' if out['mismatches'] or out['negotiated_outside_policy'] else 'untested')
    return out


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--binary', required=True, help='keytend-kmip-server executable for tls-profiles and key generation: '
                    'a frozen native copy, or the image run as one (scripts/image_server.py)')
    ap.add_argument('--engine', default='podman')
    ap.add_argument('--image', help='image reference; probed only when given')
    ap.add_argument('--image-id', help='required image ID when --image is given')
    ap.add_argument('--output', required=True, help='new directory outside Git for PKI, raw logs and summary')
    ap.add_argument('--openssl', help='client OpenSSL binary (default: openssl on PATH)')
    ap.add_argument('--openssl-image', help='run the client OpenSSL from this image instead (its openssl command)')
    ap.add_argument('--fixtures', help='comma-separated <native|image>-<rsa|ecdsa|p256|p384> (default: rsa and ecdsa, plus p256 '
                    'and p384 under a Suite B --tls-profile). rsa/ecdsa use an RSA CA; p256/p384 use all-ECDSA Suite B PKIs')
    ap.add_argument('--image-archive', help='exported archive of --image; its TLS libraries are hashed and its config must match --image-id')
    ap.add_argument('--tls-profile', help='run every fixture under this --tls-profile policy and evaluate it (default: server default)')
    ap.add_argument('--fips', action='store_true', help='run every fixture in FIPS mode: image fixtures emulate a FIPS host '
                    '(OPENSSL_FORCE_FIPS_MODE=1 and --fips); native fixtures need KEYTEND_FIPS_OPENSSL_CONF/MODULES')
    a = ap.parse_args()
    out = pathlib.Path(a.output).resolve()
    out.mkdir(parents=True)
    binary = str(pathlib.Path(a.binary).resolve())
    client = Client(a.openssl, a.openssl_image, a.engine, shares=[out, ROOT])
    inventory = json.loads(INVENTORY.read_text())
    image_tls = None
    if a.image:
        if not a.image_id or not a.image_archive:
            raise SystemExit('--image needs --image-id and --image-archive')
        image_tls = archive_tls_identity(a.image_archive)
        if image_tls['config'].removesuffix('.json') != a.image_id:
            raise SystemExit(f'archive config {image_tls["config"]} does not match --image-id')
    policy = read_policy(binary, a.tls_profile, client) if a.tls_profile else None
    pki = make_pki(out / 'pki', binary)
    from image_evidence import source_commit
    summary = {'started': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()), 'client': client.identity(),
               'inventory_sha256': sha256(INVENTORY.read_bytes()),
               'source_commit': source_commit()[0], 'image': {'reference': a.image, 'id': a.image_id, 'archive': image_tls},
               'pki': pki_identity(pki), 'fixtures': {},
               'fips_mode': None if not a.fips else {'image': 'emulated: OPENSSL_FORCE_FIPS_MODE=1 and --fips (no FIPS host kernel)',
                                                     'native': {k: v for k, v in native_fips_env().items()}}}
    if policy:
        summary['tls_profile'] = policy
    selected = probes(policy)
    owned = []
    fixtures = a.fixtures or ','.join(f'{k}-{s}' for k in ['native', 'image']
                                      for s in ['rsa', 'ecdsa', *(SUITE_B_SERVERS if policy and policy.get('suite_b') else [])])
    # The server under test: the native executable when a native fixture runs; otherwise only the
    # image runs, and --binary (the image run as one) only lists policies and makes keys.
    if any(name.startswith('native-') for name in fixtures.split(',')):
        summary['native_binary'] = {'path': binary, 'sha256': sha256(pathlib.Path(binary).read_bytes())}
    else:
        from image_evidence import runtime_evidence
        summary.update(runtime_evidence(binary, a.image, a.engine))
    try:
        for name in fixtures.split(','):
            kind, server = name.split('-')
            root = out / 'fixtures' / name
            fixture_pki = pki / f'suiteb-{server}' if server in SUITE_B_SERVERS else pki
            if kind == 'image':
                if not a.image:
                    summary['fixtures'][name] = {'skipped': 'no --image/--image-id'}
                    continue
                fixture = Container(a.engine, a.image, a.image_id, fixture_pki, f'server-{server}', root, a.tls_profile, fips=a.fips)
            else:
                fixture = Native(binary, fixture_pki, f'server-{server}', root, https=True, tls_profile=a.tls_profile, fips=a.fips)
            owned.append(fixture)
            started = time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())
            credential = 'rsa' if server == 'rsa' else 'ec'
            try:
                fixture.__enter__()
            except (RuntimeError, TimeoutError) as e:
                # A policy whose mandatory suites the certificate cannot serve refuses to start
                # (natively the process exits; a container never becomes ready).
                log = fixture.log_path.read_bytes() if fixture.log_path.exists() else b''
                refused = isinstance(e, RuntimeError) if kind == 'native' else re.search(rb'TLS profile \S+( needs a|: server certificate)', log)
                if not policy or not refused:
                    raise
                summary['fixtures'][name] = {'kind': kind, 'server_identity': f'server-{server}', 'server_credential': credential,
                                             'started': started, 'server_refused_to_start': str(e), 'closed_after': fixture.closed,
                                             'server_log_sha256': sha256(log),
                                             'server_error': [json.loads(l).get('fields', {}).get('message', l) if l.startswith('{') else l
                                                              for l in log.decode(errors='replace').splitlines() if 'TLS profile' in l][-1:]}
                print(f'{name}: server refused to start under {policy["name"]}', flush=True)
                continue
            try:
                results = run_fixture(client, fixture, fixture_pki, root / 'raw', selected, credential)
                command = fixture.command
                tls_library = getattr(fixture, 'tls_library', None) or {'source': 'image archive', 'archive': image_tls}
            finally:
                fixture.__exit__(None, None, None)
            log = fixture.log_path.read_bytes() if fixture.log_path.exists() else b''
            counters = shutdown_counters(log)
            summary['fixtures'][name] = {'kind': kind, 'server_identity': f'server-{server}', 'server_credential': credential, 'started': started,
                                         'pki': fixture_pki.name,
                                         'command': [c if '/pki/' not in c else 'PKI/' + str(pathlib.Path(c).relative_to(pki)) for c in command],
                                         'server_tls_library': tls_library, 'container_name': getattr(fixture, 'name', None),
                                         'closed_after': fixture.closed, 'server_log_sha256': sha256(log), 'shutdown_counters': counters,
                                         # Readiness adds TCP connects without TLS handshakes, so only TLS successes are compared.
                                         'server_tls_succeeded_equals_client_negotiated': None if counters is None else
                                         counters.get('tls_succeeded_total') == count(results).get('negotiated', 0),
                                         'attributions': count(results, 'attribution'),
                                         'results': results, 'evaluation': evaluate(inventory, results)}
            if policy:
                evaluation = summary['fixtures'][name]['evaluation']
                summary['fixtures'][name]['policy_evaluation'] = evaluate_policy(policy, results, credential)
                summary['fixtures'][name]['policy_claims'] = {
                    f'{e}/{s}': evaluation.get(f'{e}/{s}', 'no protocol/cipher record (HTTPS reuses Basic)') for e, s in policy['derived_from']}
            print(f'{name}: ' + ', '.join(f'{k}={v}' for k, v in sorted(count(results).items())), flush=True)
    finally:
        client.close()
        summary['cleanup'] = cleanup_proof(a.engine, owned, out)
        summary['finished'] = time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())
        (out / 'summary.json').write_text(json.dumps(summary, indent=2, sort_keys=True) + '\n')
    print('summary', out / 'summary.json', sha256((out / 'summary.json').read_bytes()))


def cleanup_proof(engine, owned, out):
    """Owned fixtures only: native processes exited, containers removed, no other process still uses the output tree."""
    names = [f.name for f in owned if isinstance(f, Container)]
    left = [n for n in names if subprocess.run([engine, 'container', 'exists', n]).returncode == 0]
    procs = [f.process.pid for f in owned if isinstance(f, Native) and f.process and f.process.poll() is None]
    mine, pid = set(), os.getpid()
    while pid > 1:  # this harness and the shell that launched it name the output directory too
        mine.add(pid)
        pid = int(pathlib.Path(f'/proc/{pid}/stat').read_text().rsplit(')', 1)[1].split()[1])
    users = [int(p) for p in subprocess.run(['pgrep', '-f', str(out)], stdout=subprocess.PIPE, text=True).stdout.split()]
    users = [p for p in users if p not in mine]
    return {'containers': names, 'containers_remaining': left, 'native_processes_running': procs,
            'processes_referencing_output': users, 'all_removed': not left and not procs and not users}


def shutdown_counters(log):
    """Connection lifecycle counters from the server's shutdown log line, or None."""
    for line in reversed(log.decode(errors='replace').splitlines()):
        try:
            fields = json.loads(line).get('fields', {})
        except ValueError:
            continue
        if fields.get('phase') == 'shutdown' and 'counters' in fields:
            return json.loads(fields['counters'])
    return None


def count(results, key='outcome'):
    c = {}
    for r in results:
        if r.get(key) is not None:
            c[r[key]] = c.get(r[key], 0) + 1
    return c


# TLS library and OpenSSL configuration paths of the Debian 12 image and of the UBI 9 image
# (RHEL keeps the libraries in /usr/lib64, the system configuration in /etc/pki/tls and the
# server's own configuration, named by the image's OPENSSL_CONF, in /etc/keytend-kmip-server).
ARCHIVE_TLS_FILES = ['usr/lib/x86_64-linux-gnu/libssl.so.3', 'usr/lib/x86_64-linux-gnu/libcrypto.so.3', 'etc/ssl/openssl.cnf',
                     'usr/lib64/libssl.so.3', 'usr/lib64/libcrypto.so.3', 'etc/pki/tls/openssl.cnf', 'etc/keytend-kmip-server/openssl.cnf']


def archive_tls_identity(archive):
    """Hash the image's libssl/libcrypto/OpenSSL configuration files and record the package that
    ships them (dpkg libssl3 or RPM openssl-libs) by reading the docker archive in memory (no
    extraction, no container). Symlinks such as /usr/lib64/libssl.so.3 are followed."""
    import io, posixpath, tarfile
    files, links = {}, {}
    data = pathlib.Path(archive).read_bytes()
    with tarfile.open(fileobj=io.BytesIO(data)) as outer:
        manifest = json.loads(outer.extractfile('manifest.json').read())[0]
        names = set(outer.getnames())
        config = json.loads(outer.extractfile(manifest['Config']).read()) if manifest['Config'] in names else {}
        for layer in manifest['Layers']:
            with tarfile.open(fileobj=io.BytesIO(outer.extractfile(layer).read())) as inner:
                for member in inner.getmembers():
                    name = posixpath.normpath(member.name).lstrip('/')
                    if member.issym():
                        links[name] = member.linkname
                    elif member.isfile() and (name.startswith(('usr/lib', 'etc/')) or name in ('var/lib/dpkg/status', 'var/lib/rpm/rpmdb.sqlite')):
                        files[name] = inner.extractfile(member).read()
    def resolve(name, depth=0):
        parts, current = name.split('/'), ''
        for index, part in enumerate(parts):
            candidate = posixpath.join(current, part) if current else part
            if candidate in links and depth < 40:
                target = links[candidate]
                base = '' if target.startswith('/') else current
                return resolve(posixpath.normpath(posixpath.join(base, target.lstrip('/'), *parts[index+1:])).lstrip('/'), depth+1)
            current = candidate
        return current
    found = {name: files[resolve(name)] for name in ARCHIVE_TLS_FILES if resolve(name) in files}
    status = files.get('var/lib/dpkg/status', b'').decode(errors='replace')
    m = re.search(r'^Package: libssl3\n(?:[^\n]+\n)*?Version: (\S+)', status, re.M)
    rpm = None
    if 'var/lib/rpm/rpmdb.sqlite' in files:
        from image_rootfs import rpm_packages
        package = rpm_packages(files['var/lib/rpm/rpmdb.sqlite']).get('openssl-libs')
        rpm = f"{package['evr']}.{package['arch']}" if package else None
    lib = found.get('usr/lib/x86_64-linux-gnu/libcrypto.so.3') or found.get('usr/lib64/libcrypto.so.3', b'')
    v = re.search(rb'OpenSSL 3\.\d+\.\d+ [0-9]+ [A-Z][a-z]+ [0-9]{4}', lib)
    env = [e for e in (config.get('config') or {}).get('Env') or [] if e.startswith('OPENSSL_')]
    return {'archive_sha256': sha256(data), 'config': manifest['Config'], 'repo_tags': manifest.get('RepoTags'),
            'libssl3_package': m.group(1) if m else None, 'openssl_libs_rpm': rpm, 'openssl_env': env,
            'openssl_version_string': v.group(0).decode() if v else None,
            'files_sha256': {k: sha256(v) for k, v in sorted(found.items())}}


def compact(summary_path, output, archive=None):
    """Committable checkpoint: identities, per-probe observations and raw-log hashes, no PKI secrets.
    The evaluation recorded at probe time is kept; the current evaluator's reading is added beside it."""
    pathlib.Path(output).write_text(json.dumps(compact_data(summary_path, archive), indent=1, sort_keys=True) + '\n')


ROW_FORMAT = ['id', 'listener', 'outcome', 'attribution', 'Protocol version', 'Ciphersuite (IANA)', 'negotiated_group', 'raw_sha256']


def checkpoint(output, *summary_paths):
    """One committable file for several --tls-profile runs of the same binary. Per run: the compacted
    identities and rows, the policy evaluation and, per derived edition/suite, the conflict summary.
    The full per-edition evaluation is kept only for runs without a policy (the baseline)."""
    runs = {}
    for path in summary_paths:
        c = compact_data(path)
        name = (c.get('tls_profile') or {}).get('name', 'default')
        for f in c['fixtures'].values():
            if c.get('tls_profile'):
                f.pop('evaluation_recorded_at_probe_time', None)
                f.pop('evaluation_recomputed', None)
                f['policy_claims'] = {k: v if isinstance(v, str) else {x: v[x] for x in [
                    'observed_subset_conflict', 'missing_required', 'untested_required', 'outside_closed_list',
                    'forbidden_protocols_accepted', 'required_protocols_missing'] if v.get(x) or x == 'observed_subset_conflict'}
                    for k, v in (f.get('policy_claims') or {}).items()}
            f.pop('evaluation_recorded_at_probe_time', None)
            if 'results' in f:
                f['rows'] = ['|'.join(str(r.get(k) or '') for k in ROW_FORMAT) for r in f.pop('results')]
        runs[name] = c
    binaries = {c['native_binary']['sha256'] for c in runs.values() if 'native_binary' in c}
    images = sorted({(c.get('image') or {}).get('id') for c in runs.values()} - {None})
    tested = ' and '.join(x for x, present in (('native binary', binaries), ('image', images)) if present) or 'server'
    out = {'description': 'Live --tls-profile probe runs (scripts/tls_profile_probe.py). Observations of the '
                          + tested + ' only; not a profile qualification.',
           'native_binary_sha256': sorted(binaries), 'image_id': images, 'runs': runs,
           'row_format': '|'.join(ROW_FORMAT),
           'verdicts': {n: {f: (v.get('policy_evaluation') or {}).get('verdict', 'server refused to start' if 'server_refused_to_start' in v else None)
                            for f, v in c['fixtures'].items()} for n, c in runs.items()}}
    pathlib.Path(output).write_text(json.dumps(out, indent=1, sort_keys=True) + '\n')


def compact_data(summary_path, archive=None):
    summary_bytes = pathlib.Path(summary_path).read_bytes()
    s = json.loads(summary_bytes)
    inventory = json.loads(INVENTORY.read_text())
    keep = ['Protocol version', 'Ciphersuite (IANA)', 'Negotiated TLS1.3 group', 'Peer Temp Key', 'Signature type', 'Verification']
    prune = lambda e: {k: {x: y for x, y in v.items() if y is None or isinstance(y, bool) or y} for k, v in e.items()}
    out = {'summary_sha256': sha256(summary_bytes), 'started': s['started'], 'finished': s['finished'],
           'inventory_sha256': s['inventory_sha256'], 'compacted_with_inventory_sha256': sha256(INVENTORY.read_bytes()),
           'evaluation_scope':'Recomputed after the run with the current inventory; the evaluation recorded at probe time is kept separately, no new probes or profile qualification',
           'client': s['client'], **({'native_binary': {'sha256': s['native_binary']['sha256']}} if 'native_binary' in s else {}),
           'pki': {k: {x: v[x] for x in ['certificate_sha256', 'subject', 'issuer', 'public_key', 'bits', 'curve', 'signature']} for k, v in s['pki'].items()},
           'fixtures': {}}
    for k in ['source_commit', 'image', 'runtime', 'cleanup', 'tls_profile']:
        if k in s:
            out[k] = s[k]
    if archive:
        out['image_archive'] = archive_tls_identity(archive)
    for name, f in s['fixtures'].items():
        if 'results' not in f:
            out['fixtures'][name] = f
            continue
        rows = []
        for r in f['results']:
            row = {k: r.get(k) for k in ['id', 'listener', 'outcome', 'attribution', 'detail', 'kmip', 'raw_sha256', 'negotiated_group'] if r.get(k) is not None}
            if r.get('credential_compatible') is False:
                row['credential_compatible'] = False
            if r.get('server_delta'):
                row['server_delta'] = {k: v for k, v in r['server_delta'].items() if v}
            if r.get('diagnostic_client_parameters'):
                row['diagnostic_client_parameters'] = r['diagnostic_client_parameters']
            row.update({k: v for k, v in (r.get('facts') or {}).items() if k in keep})
            rows.append(row)
        tls_library = f.get('server_tls_library')
        if tls_library and tls_library.get('source') == 'image archive':
            tls_library = {'source': 'image archive', 'see': 'image.archive'}
        elif tls_library:
            tls_library = dict(tls_library, source='/proc/<server pid>/maps')
        out['fixtures'][name] = {k: v for k, v in {
            'kind': f['kind'], 'server_identity': f['server_identity'], 'server_credential': f.get('server_credential'),
            'started': f['started'], 'container_name': f.get('container_name'), 'server_tls_library': tls_library,
            'command': [c.replace(str(pathlib.Path(summary_path).resolve().parent), '$OUTPUT') for c in f['command']],
            'closed_after': f['closed_after'], 'server_log_sha256': f['server_log_sha256'],
            'shutdown_counters': f['shutdown_counters'],
            'server_tls_succeeded_equals_client_negotiated': f['server_tls_succeeded_equals_client_negotiated'],
            'outcomes': count(f['results']), 'attributions': count(f['results'], 'attribution'), 'results': rows,
            'evaluation_recorded_at_probe_time': prune(f['evaluation']),
            'policy_evaluation': f.get('policy_evaluation'), 'policy_claims': f.get('policy_claims'),
            'evaluation_recomputed': prune(evaluate(inventory, f['results']))}.items() if v is not None}
    return out


if __name__ == '__main__':
    if sys.argv[1:2] == ['compact']:
        compact(*sys.argv[2:5])
    elif sys.argv[1:2] == ['checkpoint']:
        checkpoint(*sys.argv[2:])
    else:
        main()
