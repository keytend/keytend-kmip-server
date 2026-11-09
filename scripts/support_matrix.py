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

"""Generate the tables of docs/support-matrix.md from a running server.

The operation and object rows come from the pinned specification inventories
(docs/specs/operations.json, src/wire_registry.json); whether the server
implements each one comes from its own Query Operations and Query Objects
answers in every edition (3.0 with --experimental-v3). The attribute table
lists what Get Attribute List reports for a new AES key and a new RSA private
key. Nothing is written by hand between the generated markers.

    python3 scripts/support_matrix.py [--skip-build] [--check]
"""
import argparse, json, re, subprocess, sys, tempfile
from test_runtime import ROOT, Server
from wire import *

DOC = ROOT / 'docs/support-matrix.md'
START, END = '<!-- generated:start -->', '<!-- generated:end -->'
EDITIONS = ['1.0', '1.1', '1.2', '1.3', '1.4', '2.0', '2.1', '3.0']
# Where each operation is described. Operations without a page have no handler.
PAGES = {
    'Create': 'objects.md#common-rules', 'Create Key Pair': 'algorithms.md', 'Register': 'objects.md#common-rules',
    'Re-key': 'rekey.md', 'Re-key Key Pair': 'rekey.md', 'Derive Key': 'crypto-operations.md#derive-key',
    'Certify': 'certificates.md#certify-and-re-certify', 'Re-certify': 'certificates.md#certify-and-re-certify',
    'Locate': 'locate.md', 'Check': 'lifecycle.md#check', 'Get': 'key-transfer.md#get',
    'Get Attributes': 'attributes.md#reading-attributes', 'Get Attribute List': 'attributes.md#reading-attributes', 'Add Attribute': 'attributes.md#changing-attributes',
    'Modify Attribute': 'attributes.md#changing-attributes', 'Delete Attribute': 'attributes.md#changing-attributes',
    'Set Attribute': 'attributes.md#changing-attributes', 'Adjust Attribute': 'attributes.md#adjust-attribute',
    'Obtain Lease': 'lifecycle.md#leases', 'Get Usage Allocation': 'lifecycle.md#usage-limits',
    'Activate': 'lifecycle.md#activate', 'Revoke': 'lifecycle.md#revoke', 'Destroy': 'lifecycle.md#destroy',
    'Archive': 'lifecycle.md#archive-and-recover', 'Recover': 'lifecycle.md#archive-and-recover',
    'Validate': 'certificates.md#validate', 'Query': 'messages.md#query', 'Cancel': 'messages.md#asynchronous-requests',
    'Poll': 'messages.md#asynchronous-requests', 'Notify': 'server-to-client.md', 'Put': 'server-to-client.md',
    'Discover Versions': 'messages.md#version-negotiation', 'Encrypt': 'crypto-operations.md#encrypt-and-decrypt',
    'Decrypt': 'crypto-operations.md#encrypt-and-decrypt', 'Sign': 'crypto-operations.md#sign-and-signature-verify',
    'Signature Verify': 'crypto-operations.md#sign-and-signature-verify', 'MAC': 'crypto-operations.md#mac-and-mac-verify',
    'MAC Verify': 'crypto-operations.md#mac-and-mac-verify', 'RNG Retrieve': 'crypto-operations.md#rng-retrieve-and-rng-seed',
    'RNG Seed': 'crypto-operations.md#rng-retrieve-and-rng-seed', 'Hash': 'crypto-operations.md#hash',
    'Create Split Key': 'objects.md#split-keys', 'Join Split Key': 'objects.md#split-keys',
    'Import': 'key-transfer.md#import-and-export', 'Export': 'key-transfer.md#import-and-export', 'Log': 'messages.md#log',
    'Login': 'tickets.md#login', 'Logout': 'tickets.md#logout', 'Delegated Login': 'tickets.md#delegated-login',
    'Set Endpoint Role': 'server-to-client.md#set-endpoint-role', 'PKCS#11': 'messages.md#pkcs11',
    'Interop': 'messages.md#interop-test-mode', 'Set Constraints': 'defaults-and-constraints.md#constraints',
    'Get Constraints': 'defaults-and-constraints.md#constraints', 'Set Defaults': 'defaults-and-constraints.md#set-defaults',
    'Re-Provision': 're-provision.md', 'Query Asynchronous Requests': 'messages.md#asynchronous-requests',
    'Process': 'messages.md#asynchronous-requests', 'Ping': 'messages.md#ping', 'Create Group': 'kmip-3.0.md#system-objects',
    'Obliterate': 'kmip-3.0.md#obliterate', 'Create User': 'kmip-3.0.md#system-objects',
    'Create Credential': 'kmip-3.0.md#system-objects', 'Deactivate': 'lifecycle.md#revoke',
    'Encapsulate': 'algorithms.md#post-quantum-keys', 'Decapsulate': 'algorithms.md#post-quantum-keys',
}
# Implemented, but advertised only when configured (Query lists them then).
CONFIGURED = {'Notify': 'are sent only to principals with a `client_endpoint`',
              'Put': 'are sent only to principals with a `client_endpoint`',
              'Interop': 'is offered only with `--interop-test-mode`, which KMIP forbids on a production server',
              'Re-Provision': 'is offered only with `--provisioning-ca`'}
OBJECT_PAGES = {'Certificate': 'certificates.md', 'Certificate Request': 'certificates.md#certificate-requests',
                'Symmetric Key': 'algorithms.md', 'Public Key': 'algorithms.md', 'Private Key': 'algorithms.md',
                'Secret Data': 'objects.md#secret-data', 'Opaque Object': 'objects.md#opaque-objects',
                'PGP Key': 'objects.md#pgp-keys', 'Split Key': 'objects.md#split-keys', 'Template': 'objects.md#templates-kmip-1x'}


def words(camel):
    special = {'PGPKey': 'PGP Key', 'OpaqueObject': 'Opaque Object'}
    return special.get(camel) or re.sub(r'(?<=[a-z0-9])(?=[A-Z])', ' ', camel)


def query(s, v, function):
    p = payload(exchange(s, request(24, [enumeration(0x420074, function)], v)))
    return p


def create_rsa(s, v):
    if v[0] == 1:
        common = structure(0x42001F, *map(attr, [enumeration(0x420028, 4), integer(0x42002a, 2048)]))
        private = structure(0x420065, *map(attr, [integer(0x42002c, 1)]))
        public = structure(0x42006E, *map(attr, [integer(0x42002c, 2)]))
    else:
        common = structure(0x420126, enumeration(0x420028, 4), integer(0x42002a, 2048))
        private = structure(0x420127, integer(0x42002c, 1))
        public = structure(0x420128, integer(0x42002c, 2))
    p = payload(exchange(s, request(2, [common, private, public], v)))
    return get(p, 0x420066)[2]


def attribute_names(s, v, id, tags):
    p = payload(exchange(s, request(12, [uid(id, v)], v)))
    if v[0] == 1:
        return {n[2] for n in children(p, 0x42000A)}
    names = set()
    for ref in children(p, 0x42013B):
        if ref[1] == 5:
            names.add(words(tags.get(ref[2], f'0x{ref[2]:06X}')))
        else:  # vendor attribute
            names.add('custom/vendor attribute')
    return names


def survey():
    registry = json.loads((ROOT / 'src/wire_registry.json').read_text())
    specs = json.loads((ROOT / 'docs/specs/operations.json').read_text())
    result = {'operations': {}, 'objects': {}, 'attributes': {}}
    with tempfile.TemporaryDirectory(prefix='keytend-kmip-server-matrix-') as d:
        with Server(d, draft=True) as s:
            for ed in EDITIONS:
                v = tuple(map(int, ed.split('.')))
                tags = {value: name for name, value in registry[ed]['tags'].items()}
                with s.connect() as c:
                    ops = {n[2] for n in children(query(c, v, 1), 0x42005C)}
                    objs = {n[2] for n in children(query(c, v, 2), 0x420057)}
                    key = create_key(c, v)
                    rsa = create_rsa(c, v)
                    aes_attrs = attribute_names(c, v, key, tags)
                    rsa_attrs = attribute_names(c, v, rsa, tags)
                for code, name in specs[ed].items():
                    result['operations'].setdefault(name, {'code': int(code, 16)})[ed] = int(code, 16) in ops
                for name, value in registry[ed]['enums']['ObjectType'].items():
                    if name == 'Reserved':
                        continue
                    result['objects'].setdefault(words(name), {'code': value})[ed] = value in objs
                for name in aes_attrs | rsa_attrs:
                    result['attributes'].setdefault(name, {})[ed] = ('AES' if name in aes_attrs else '') + (
                        ' RSA' if name in rsa_attrs else '')
    return result


# Each table covers one group of editions, so no table is wider than seven
# columns on GitHub. A row appears in a group when an edition there defines it.
GROUPS = [('KMIP 1.0–1.4', EDITIONS[:5]), ('KMIP 2.0, 2.1 and the 3.0 draft', EDITIONS[5:])]


def cell(value):
    return {True: 'yes', False: 'no', None: ''}[value]


def grouped(lead, align, rows):
    """Tables of rows (label cells, {edition: cell text}), one per edition group."""
    out = []
    for title, eds in GROUPS:
        out += ['', f'### {title}', '', '| ' + ' | '.join(lead + eds) + ' |',
                '|' + ''.join(f' {a} |' for a in align) + ' :---: |' * len(eds)]
        for labels, values in rows:
            if any(values.get(ed) for ed in eds):
                out.append('| ' + ' | '.join(labels + [values.get(ed) or '' for ed in eds]) + ' |')
    return out


def render(r):
    out = ['## Operations', '',
           '- `yes`: the server has a handler and lists the operation in Query.',
           '- `no`: the edition defines the operation and the server does not implement it.',
           '- `opt-in`: implemented, and listed only when configured.',
           '- Empty: the edition does not define it.',
           '- `No.`: the operation number the [policy file](configuration.md#operation-numbers) uses '
           '(the specification writes it in hex).']
    notes, rows = [], []
    for name, row in sorted(r['operations'].items(), key=lambda kv: kv[1]['code']):
        values = [row.get(ed) for ed in EDITIONS]
        if name in CONFIGURED:
            # Server-to-client delivery is configured for final editions only.
            values = [None if x is None else 'no' if name in ('Notify', 'Put') and ed == '3.0' else 'opt-in'
                      for ed, x in zip(EDITIONS, values)]
            if CONFIGURED[name] not in notes:
                notes.append(CONFIGURED[name])
        label = f'[{name}]({PAGES[name]})' if name in PAGES and any(values) else name
        cells = {ed: x if isinstance(x, str) else cell(x) for ed, x in zip(EDITIONS, values)}
        rows.append(([str(row['code']), label], cells))
    out += grouped(['No.', 'Operation'], ['---:', '---'], rows)
    names = {n: ' and '.join(k for k in CONFIGURED if CONFIGURED[k] == n) for n in notes}
    out += ['', 'Opt-in: ' + '; '.join(f'{names[n]} {n}' for n in notes) + '.']
    out += ['', '## Object types', '',
            '`yes`: listed by Query Objects in that edition. `no`: the edition defines the type and the server does '
            'not accept it. Empty: not defined.']
    rows = []
    for name, row in sorted(r['objects'].items(), key=lambda kv: kv[1]['code']):
        page = OBJECT_PAGES.get(name, 'kmip-3.0.md#system-objects' if row['code'] > 10 else '')
        label = f'[{name}]({page})' if page else name
        rows.append(([str(row['code']), label], {ed: cell(row.get(ed)) for ed in EDITIONS}))
    out += grouped(['No.', 'Object type'], ['---:', '---'], rows)
    out += ['', '## Attributes the server reports on a new key', '',
            'Get Attribute List on a newly created AES-256 key and RSA-2048 private key (`both`: both keys report it; `AES` or `RSA`: only that key does), '
            'with only '
            'algorithm, length and usage mask supplied. Client-settable attributes (Name, Object Group, Contact '
            'Information and others) appear once set; see [attributes](attributes.md).']
    rows = []
    for name in sorted(r['attributes']):
        row = r['attributes'][name]
        rows.append(([name], {ed: {'AES RSA': 'both'}.get(row.get(ed, '').strip(), row.get(ed, '').strip())
                              for ed in EDITIONS}))
    out += grouped(['Attribute'], ['---'], rows)
    return '\n'.join(out)


def main():
    a = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    a.add_argument('--skip-build', action='store_true', help='use the existing target/debug executable')
    a.add_argument('--check', action='store_true', help='fail if docs/support-matrix.md is out of date')
    args = a.parse_args()
    if not args.skip_build:
        subprocess.run(['cargo', 'build', '--locked'], cwd=ROOT, check=True)
    text = DOC.read_text()
    head, rest = text.split(START, 1)
    _, tail = rest.split(END, 1)
    new = head + START + '\n' + render(survey()) + '\n' + END + tail
    if args.check:
        if new != text:
            sys.exit('docs/support-matrix.md is out of date; run scripts/support_matrix.py')
        print('docs/support-matrix.md is up to date')
    else:
        DOC.write_text(new)
        print('wrote docs/support-matrix.md')


if __name__ == '__main__':
    main()
