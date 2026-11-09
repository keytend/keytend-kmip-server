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

"""Cross-check docs/specs/tls-profile-inventory.json against the pinned Profiles archives.

Each archive is verified against docs/specs/profiles.json before its HTML member is read in
memory. Section 3 (authentication suites) is split at each suite's opening sentence, and
the cipher-suite and key-exchange-group names in every suite are compared with the
inventory's lists for that suite. Suites that reference another suite's list contribute
only their own names. Closed-list sentences are checked where the inventory claims one.
The 1.3/1.4 TLS1.2-only sentence is also checked. Other protocol clauses, cipher
SHALL/MAY and conditional buckets, client-authenticity, ports and paraphrases are not checked mechanically;
this is a token-level aid for review, not an interpretation.
"""
import hashlib, html, io, json, pathlib, re, sys, zipfile

ROOT = pathlib.Path(__file__).resolve().parents[1]
SUITE_START = re.compile(r'This\s+authentication\s+(?:set|suite)\s+stipulates|Implementations\s+conformant\s+to\s+this\s+profile\s+SHALL\s+use\s+TLS')
SECTION_4 = re.compile(r'\n\s*4\s+(?:KMIP\s+Profiles|Conformance\s+Test\s+Cases)')
TOKEN = re.compile(r'\bTLS13-[A-Z0-9-]+[A-Z0-9]|\bTLS_[A-Z0-9_]+[A-Z0-9]|\b(?:X25519MLKEM768|SecP256r1MLKEM768|SecP384r1MLKEM1024)\b')
TLS13_SPELLING = {'TLS13-CHACHA20-POLY1305-SHA256': 'TLS_CHACHA20_POLY1305_SHA256', 'TLS13-AES-256-GCM-SHA384': 'TLS_AES_256_GCM_SHA384'}
CLOSED = re.compile(r'SHALL\s+NOT\s+support\s+any\s+(?:other\s+cipher\s+suites|cipher\s+suite\s+not\s+listed\s+above)')
CLOSED_GROUPS = re.compile(r'SHALL\s+NOT\s+support\s+any\s+key\s+exchange\s+group\s+not\s+listed\s+above')


def text_of(html_bytes):
    """Plain text of a Word-exported HTML document (tags dropped, entities decoded)."""
    head = html_bytes[:4000].lower()
    t = html_bytes.decode('utf-8' if b'charset=utf-8' in head else 'windows-1252', errors='replace')
    t = re.sub(r'(?is)<(script|style).*?</\1>', '', t)
    t = re.sub(r'(?i)<br\s*/?>|</p>|</tr>|</h\d>|</li>|</div>', '\n', t)
    t = re.sub(r'<[^>]+>', ' ', t)
    return re.sub(r'[ \t\r\xa0]+', ' ', html.unescape(t))


def pinned_text(archive, expected_sha256):
    data = pathlib.Path(archive).read_bytes()
    actual = hashlib.sha256(data).hexdigest()
    if actual != expected_sha256:
        raise ValueError(f'{archive}: sha256 {actual} does not match pin {expected_sha256}')
    with zipfile.ZipFile(io.BytesIO(data)) as z:
        members = [n for n in z.namelist() if n.endswith('.html') and '/' not in n]
        if len(members) != 1:
            raise ValueError(f'{archive}: expected one top-level HTML member, found {members}')
        body = z.read(members[0])
    return text_of(body), {'member': members[0], 'member_sha256': hashlib.sha256(body).hexdigest()}


def suite_chunks(text, count):
    starts = [m.start() for m in SUITE_START.finditer(text)]
    if len(starts) < count:
        raise ValueError(f'found {len(starts)} suite openings, inventory has {count}')
    starts = starts[:count]
    end = SECTION_4.search(text, starts[-1])
    bounds = starts + [end.start() if end else len(text)]
    return [text[a:b] for a, b in zip(bounds, bounds[1:])]


def listed(entry):
    """Every cipher-suite or group name an inventory suite entry lists explicitly."""
    names = set()
    for key in ['ciphers', 'groups']:
        block = entry.get(key)
        if isinstance(block, dict):
            for k, v in block.items():
                if isinstance(v, list) and k != 'tls13_spelling_in_source':
                    names |= set(v)
    return names


def lists_naming(entry, name):
    return sum(name in v for key in ['ciphers', 'groups'] if isinstance(entry.get(key), dict)
               for k, v in entry[key].items() if isinstance(v, list) and k != 'tls13_spelling_in_source')


def check(inventory, pins, specs):
    report = {}
    for edition, e in inventory['editions'].items():
        version = edition.split('-')[0]
        archive = pathlib.Path(specs) / f'profiles-{version}.zip'
        text, member = pinned_text(archive, pins[version])
        suites = list(e['suites'].items())
        problems = []
        for (name, entry), chunk in zip(suites, suite_chunks(text, len(suites))):
            found = [TLS13_SPELLING.get(t, t) for t in TOKEN.findall(chunk)]
            want = listed(entry)
            if set(found) != want:
                problems.append({'suite': name, 'only_in_source': sorted(set(found) - want), 'only_in_inventory': sorted(want - set(found))})
            ciphers = entry.get('ciphers')
            if isinstance(ciphers, dict) and ciphers.get('closed_list') is True and not CLOSED.search(chunk):
                problems.append({'suite': name, 'closed_list_sentence': 'absent'})
            if isinstance(ciphers, dict) and ciphers.get('closed_list') is False and CLOSED.search(chunk):
                problems.append({'suite': name, 'closed_list_sentence': 'present but inventory says open'})
            groups = entry.get('groups')
            if isinstance(groups, dict):
                if groups.get('closed_list') is True and not CLOSED_GROUPS.search(chunk):
                    problems.append({'suite': name, 'closed_group_sentence': 'absent'})
                if groups.get('closed_list') is False and CLOSED_GROUPS.search(chunk):
                    problems.append({'suite': name, 'closed_group_sentence':'present but inventory says open'})
            only = bool(re.search(r'profile\s+conforming\s+to\s+the\s+TLS\s+1\.2\s+Authentication\s+Suite\s+SHALL\s+use\s+TLS\s+version\s+1\.2', chunk))
            protocols = entry.get('protocols')
            if only != (isinstance(protocols, dict) and protocols.get('only') == ['TLSv1.2']):
                problems.append({'suite':name,'tls12_only_sentence':'source/inventory differ'})
            # A name repeated across parallel server/client lists is expected; other repeats must be noted.
            noted = ' '.join(e.get('anomalies', []))
            missing_notes = sorted({t for t in found if found.count(t) > lists_naming(entry, t) and t not in noted})
            if missing_notes:
                problems.append({'suite': name, 'unrecorded_repeats': missing_notes})
        report[edition] = {'archive_sha256': pins[version], **member, 'suites': [n for n, _ in suites], 'problems': problems,
            'mechanical_scope':{'names_and_cipher_closure':True,'group_closure_both_directions':True,'tls12_only_sentence':True,
                                'cipher_strength_and_condition_buckets':False,'other_protocol_rules':False,
                                'client_authenticity_and_ports':False},
            'qualification_credit':False}
    return report


def main():
    if len(sys.argv) != 2:
        raise SystemExit('usage: verify_tls_inventory.py SPECS_DIR (directory holding the pinned profiles-<v>.zip archives)')
    inventory = json.loads((ROOT / 'docs/specs/tls-profile-inventory.json').read_text())
    pins = {p['version']: p['sha256'] for p in json.loads((ROOT / 'docs/specs/profiles.json').read_text())}
    report = check(inventory, pins, sys.argv[1])
    print(json.dumps(report, indent=1, sort_keys=True))
    sys.exit(1 if any(r['problems'] for r in report.values()) else 0)


if __name__ == '__main__':
    main()
