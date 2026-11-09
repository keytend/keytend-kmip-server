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

"""Composite evidence for the Profiles "server conditions" clauses.

A Profiles server-conditions clause ("SHALL conform to the Baseline Server
(5.1.2)", "SHALL support the <profile> Server conditions (5.x.y)") is met when
every normative statement of the clauses it names is met. KMIP 1.3/1.4 section
12.1 says the same: a server claiming a profile "SHALL conform to all normative
statements within the clauses specified for that profile and for any subclauses
to each of those clauses". These tests check that composition against the
committed requirement matrix (docs/specs/requirement-matrix.json): every server
statement of every named clause and subclause must be clause-verified by its
own citing test, or reviewed as client, optional or non-normative. They never
check the rows they cite, so the evidence is not circular, and they fail as
soon as a constituent row reopens.

Rows are cited under the configuration of the claim they serve: a Profiles TLS
policy (`--tls-profile`), since every profile requires an authentication
suite and spec section 10 delegates channel security to the Profiles (no
profile holds under the default `modern` policy), and for the Symmetric
Key Lifecycle and Foundry profiles also `KMIP_TRIPLE_DES=enabled`. Every
2.x row that inherits the 2.x Baseline Server stays open: Interop and the
failed-Check payload are documented deviations.

Aggregate rows. "SHALL support [KMIP-SPEC]" (62cc2442524b8a8c) opens
every 6.x profile section. It is read as "speaks this edition's protocol for
the claimed profile" and cited per section (`REQ:<source>@<section>:<digest>`)
only for the claimed 1.3/1.4 server profiles, each of whose other
statements is met at that occurrence: the authentication suite, the
conditions row (which composes the Baseline Server and the profile's
conditions) and, where the profile lists any, the mandatory test cases
(scripts/test_profile_mandatory_cases.py). Profiles section 6 ("SHALL meet
all the conditions documented in one or more of the following sections") and
spec 1.3/1.4 section 12.1 (a conforming KMIP Server "meets the conditions
specified in one or more server profiles"; a claimed profile's clauses hold)
follow from the same composite. The Complete Server profiles (6.5, 6.6) are
not claimed: they need the whole specification, including table rows the
index does not hold, which no subset evidence shows.

A second test pins the non-passing mandatory test cases of the trace inventory
(docs/specs/oasis-case-inventory.json), so the claims document is revisited
when a mandatory case changes status.
"""
import json,pathlib,re,unittest
ROOT=pathlib.Path(__file__).resolve().parents[1]
MET={'clause-verified'}
NOT_SERVER={'client','optional','non-normative','test-case'}

# Profiles 1.3 / 1.4 section 5.1.2 Baseline Server: (spec section, title in the
# pinned spec index). "[KMIP-SPEC] 4" is cited for the ID Placeholder, so only
# section 4's own statements count, not the operations below it. 12.1 is the
# conformance clause itself (it requires the statements checked here).
_COMMON_1X_OBJECTS=[('2.1.1','Attribute'),('2.1.2','Credential'),('2.1.3','Key Block'),('2.1.4','Key Value'),
    ('2.1.8','Template-Attribute Structures'),('2.1.9','Extension Information')]
_COMMON_1X_OPERATIONS=[('4.9','Locate'),('4.10','Check'),('4.11','Get'),('4.12','Get Attributes'),('4.13','Get Attribute List'),
    ('4.14','Add Attribute'),('4.15','Modify Attribute'),('4.16','Delete Attribute'),('4.19','Activate'),('4.20','Revoke'),
    ('4.21','Destroy'),('4.25','Query'),('4.26','Discover Versions')]
_COMMON_1X_MESSAGES=[('6.1','Protocol Version'),('6.2','Operation'),('6.3','Maximum Response Size'),('6.4','Unique Batch Item ID'),
    ('6.5','Time Stamp'),('6.7','Asynchronous Indicator'),('6.9','Result Status'),('6.10','Result Reason'),('6.12','Batch Order Option'),
    ('6.13','Batch Error Continuation Option'),('6.14','Batch Count'),('6.15','Batch Item'),('6.17','Attestation Capable Indicator')]
_COMMON_1X_TAIL=[('7','Message Format'),('8','Authentication'),('9.1','TTLV Encoding'),('10','Transport'),('11','Error Handling')]
BASELINE_1X={
    'spec-1.3':_COMMON_1X_OBJECTS+[('3.1','Unique Identifier'),('3.2','Name'),('3.3','Object Type'),('3.4','Cryptographic Algorithm'),
        ('3.5','Cryptographic Length'),('3.6','Cryptographic Parameters'),('3.17','Digest'),('3.18.2','Default Operation Policy'),
        ('3.19','Cryptographic Usage Mask'),('3.22','State'),('3.23','Initial Date'),('3.24','Activation Date'),('3.27','Deactivation Date'),
        ('3.29','Compromise Occurrence Date'),('3.30','Compromise Date'),('3.31','Revocation Reason'),('3.38','Last Change Date')]
        +_COMMON_1X_OPERATIONS+_COMMON_1X_MESSAGES+_COMMON_1X_TAIL,
    'spec-1.4':_COMMON_1X_OBJECTS+[('2.1.19','Profile Information'),('2.1.20','Validation Information'),('2.1.21','Capability Information'),
        ('3.1','Unique Identifier'),('3.2','Name'),('3.3','Object Type'),('3.4','Cryptographic Algorithm'),('3.5','Cryptographic Length'),
        ('3.6','Cryptographic Parameters'),('3.17','Digest'),('3.19','Cryptographic Usage Mask'),('3.22','State'),('3.23','Initial Date'),
        ('3.25','Process Start Date'),('3.26','Protect Stop Date'),('3.24','Activation Date'),('3.27','Deactivation Date'),
        ('3.29','Compromise Occurrence Date'),('3.30','Compromise Date'),('3.31','Revocation Reason'),('3.33','Object Group'),
        ('3.34','Fresh'),('3.35','Link'),('3.38','Last Change Date'),('3.40','Alternative Name'),('3.41','Key Value Present'),
        ('3.42','Key Value Location'),('3.43','Original Creation Date'),('3.44','Random Number Generator'),('3.46','Description'),
        ('3.47','Comment'),('3.48','Sensitive'),('3.49','Always Sensitive'),('3.50','Extractable'),('3.51','Never Extractable')]
        +_COMMON_1X_OPERATIONS+_COMMON_1X_MESSAGES+[('6.18','Client Correlation Value'),('6.19','Server Correlation Value'),
        ('6.16','Message Extension')]+_COMMON_1X_TAIL,
}
OWN_STATEMENTS_ONLY={'4'}
BASELINE_ROW='189605f21e2b4c23'

# REQ:profiles-1.3:189605f21e2b4c23 1.3 profile server conditions start with the Baseline Server (5.1.2): every listed spec 1.3 clause and subclause is met (test_1x_baseline_server_clauses_are_met)
# REQ:profiles-1.4:189605f21e2b4c23 1.4 profile server conditions start with the Baseline Server (5.1.2): every listed spec 1.4 clause and subclause is met (test_1x_baseline_server_clauses_are_met)
# REQ:profiles-1.3:bce90de2030fdb26 1.3 Baseline Server Basic and TLS v1.2 profiles: the Baseline Server conditions (5.1.2), as above
# REQ:profiles-1.4:bce90de2030fdb26 1.4 Baseline Server Basic and TLS v1.2 profiles: the Baseline Server conditions (5.1.2), as above
#
# Profile server-conditions rows: (source, digest) -> (section, title word). The
# section's own statements must all be met; its Baseline statement is the row above.
# REQ:profiles-1.3:5f5cc6913d338583 1.3 HTTPS Server conditions (5.3.2)
# REQ:profiles-1.4:5f5cc6913d338583 1.4 HTTPS Server conditions (5.3.2)
# REQ:profiles-2.0:5f5cc6913d338583 2.0 HTTPS Server conditions (5.3.2); 5.3.2 does not include the Baseline Server
# REQ:profiles-2.1:5f5cc6913d338583 2.1 HTTPS Server conditions (5.3.2); 5.3.2 does not include the Baseline Server
# REQ:profiles-1.3:98290c1b7fc61b21 1.3 XML Server conditions (5.4.3)
# REQ:profiles-1.4:98290c1b7fc61b21 1.4 XML Server conditions (5.4.3)
# REQ:profiles-1.3:dc61a5c6ad00d896 1.3 Asymmetric Key Lifecycle Server conditions (5.8.2)
# REQ:profiles-1.4:dc61a5c6ad00d896 1.4 Asymmetric Key Lifecycle Server conditions (5.8.2)
# REQ:profiles-1.3:203b6b1cf2c1d69a 1.3 Basic Cryptographic Server conditions (5.9.4)
# REQ:profiles-1.4:203b6b1cf2c1d69a 1.4 Basic Cryptographic Server conditions (5.9.4)
# REQ:profiles-1.3:357b3fbd2f038fe2 1.3 Advanced Cryptographic Server conditions (5.9.5)
# REQ:profiles-1.4:357b3fbd2f038fe2 1.4 Advanced Cryptographic Server conditions (5.9.5)
# REQ:profiles-1.3:6f43790675b1d3b1 1.3 RNG Cryptographic Server conditions (5.9.6)
# REQ:profiles-1.4:6f43790675b1d3b1 1.4 RNG Cryptographic Server conditions (5.9.6)
# REQ:profiles-1.3:a4e9c26f29793caf 1.3 Opaque Managed Object Store Server conditions (5.10.2)
# REQ:profiles-1.4:a4e9c26f29793caf 1.4 Opaque Managed Object Store Server conditions (5.10.2)
# REQ:profiles-1.3:f2e0d457b30e2100 1.3 Storage Array with Self-Encrypting Drives Server conditions (5.11.2)
# REQ:profiles-1.4:f2e0d457b30e2100 1.4 Storage Array with Self-Encrypting Drives Server conditions (5.11.2)
# REQ:profiles-1.3:06c314726fc591b9 1.3 Tape Library Server conditions (5.12.5)
# REQ:profiles-1.4:06c314726fc591b9 1.4 Tape Library Server conditions (5.12.5)
# REQ:profiles-1.3:134ec64aa2fc2ed2 1.3 Suite B minLOS_128 Server conditions (5.13.2)
# REQ:profiles-1.4:134ec64aa2fc2ed2 1.4 Suite B minLOS_128 Server conditions (5.13.2)
# REQ:profiles-1.3:28915d7e0e74f0e5 1.3 Suite B minLOS_192 Server conditions (5.13.5)
# REQ:profiles-1.4:28915d7e0e74f0e5 1.4 Suite B minLOS_192 Server conditions (5.13.5)
# REQ:profiles-1.4:b75bf12f1a971729 1.4 AES XTS Server conditions (5.14.2)
# REQ:profiles-1.3:36502a4b401e7a15 1.3 Symmetric Key Lifecycle Server conditions (5.6.2), with KMIP_TRIPLE_DES=enabled
# REQ:profiles-1.4:36502a4b401e7a15 1.4 Symmetric Key Lifecycle Server conditions (5.6.2), with KMIP_TRIPLE_DES=enabled
# REQ:profiles-1.3:9ab79f61c1716ad3 1.3 Symmetric Key Foundry Server conditions (5.7.4), with KMIP_TRIPLE_DES=enabled
# REQ:profiles-1.4:9ab79f61c1716ad3 1.4 Symmetric Key Foundry Server conditions (5.7.4), with KMIP_TRIPLE_DES=enabled
CONDITIONS={
    '5f5cc6913d338583':('5.3.2','HTTPS Server',('profiles-1.3','profiles-1.4','profiles-2.0','profiles-2.1')),
    '98290c1b7fc61b21':('5.4.3','XML Server',('profiles-1.3','profiles-1.4')),
    'dc61a5c6ad00d896':('5.8.2','Asymmetric Key Lifecycle Server',('profiles-1.3','profiles-1.4')),
    '203b6b1cf2c1d69a':('5.9.4','Basic Cryptographic Server',('profiles-1.3','profiles-1.4')),
    '357b3fbd2f038fe2':('5.9.5','Advanced Cryptographic Server',('profiles-1.3','profiles-1.4')),
    '6f43790675b1d3b1':('5.9.6','RNG Cryptographic Server',('profiles-1.3','profiles-1.4')),
    'a4e9c26f29793caf':('5.10.2','Opaque Managed Object Store Server',('profiles-1.3','profiles-1.4')),
    'f2e0d457b30e2100':('5.11.2','Storage Array with Self-Encrypting Drives Server',('profiles-1.3','profiles-1.4')),
    '06c314726fc591b9':('5.12.5','Tape Library Server',('profiles-1.3','profiles-1.4')),
    '134ec64aa2fc2ed2':('5.13.2','Suite B minLOS_128 Server',('profiles-1.3','profiles-1.4')),
    '28915d7e0e74f0e5':('5.13.5','Suite B minLOS_192 Server',('profiles-1.3','profiles-1.4')),
    'b75bf12f1a971729':('5.14.2','AES XTS Server',('profiles-1.4',)),
    # 3DES is listed (5.6.2 algorithm encodings, 5.7.4 3DES-168 keys): claimed
    # only with KMIP_TRIPLE_DES=enabled; tests/profile_conditions.rs runs so.
    '36502a4b401e7a15':('5.6.2','Symmetric Key Lifecycle Server',('profiles-1.3','profiles-1.4')),
    '9ab79f61c1716ad3':('5.7.4','Symmetric Key Foundry Server',('profiles-1.3','profiles-1.4')),
}
# Not cited here, with the reason:
NOT_CITED={
    '1c65ba6ddcee377e':'2.x enumeration lists: cited per section in tests/profile_conditions.rs; Quantum Safe 5.16 stays open',
    '335693de5ec99a08':'Complete Server conditions (5.2): the whole specification; not claimed',
}

# Claimed 1.3/1.4 server profile sections (6.x, title in the pinned index) whose
# "SHALL support [KMIP-SPEC]" occurrence is cited per section:
# REQ:profiles-1.3@6.3:62cc2442524b8a8c 1.3 Baseline Server Basic, legacy configuration `--tls-profile kmip-1-basic` (TLS 1.0)
# REQ:profiles-1.3@6.4:62cc2442524b8a8c 1.3 Baseline Server TLS v1.2 (`kmip-1-tls12`)
# REQ:profiles-1.3@6.8:62cc2442524b8a8c 1.3 HTTPS Server, legacy (TLS 1.0, `kmip-1-basic`)
# REQ:profiles-1.3@6.10:62cc2442524b8a8c 1.3 XML Server, legacy (TLS 1.0, `kmip-1-basic`)
# REQ:profiles-1.3@6.12:62cc2442524b8a8c 1.3 JSON Server, legacy (TLS 1.0, `kmip-1-basic`)
# REQ:profiles-1.3@6.14:62cc2442524b8a8c 1.3 Symmetric Key Lifecycle Server, legacy (TLS 1.0) with KMIP_TRIPLE_DES=enabled
# REQ:profiles-1.3@6.18:62cc2442524b8a8c 1.3 Symmetric Key Foundry Server, legacy (TLS 1.0) with KMIP_TRIPLE_DES=enabled
# REQ:profiles-1.3@6.20:62cc2442524b8a8c 1.3 Asymmetric Key Lifecycle Server, legacy (TLS 1.0, `kmip-1-basic`)
# REQ:profiles-1.3@6.24:62cc2442524b8a8c 1.3 Basic Cryptographic Server, legacy (TLS 1.0); two cases pass with corrected fixtures
# REQ:profiles-1.3@6.25:62cc2442524b8a8c 1.3 Advanced Cryptographic Server, legacy (TLS 1.0, `kmip-1-basic`)
# REQ:profiles-1.3@6.26:62cc2442524b8a8c 1.3 RNG Cryptographic Server, legacy (TLS 1.0, `kmip-1-basic`)
# REQ:profiles-1.3@6.28:62cc2442524b8a8c 1.3 Opaque Managed Object Store Server, legacy (TLS 1.0, `kmip-1-basic`)
# REQ:profiles-1.3@6.30:62cc2442524b8a8c 1.3 Storage Array with Self-Encrypting Drives Server, legacy (TLS 1.0, `kmip-1-basic`)
# REQ:profiles-1.3@6.32:62cc2442524b8a8c 1.3 Tape Library Server, legacy (TLS 1.0, `kmip-1-basic`)
# REQ:profiles-1.3@6.34:62cc2442524b8a8c 1.3 Suite B minLOS_128 Server (`kmip-1-suite-b-128`)
# REQ:profiles-1.3@6.36:62cc2442524b8a8c 1.3 Suite B minLOS_192 Server (`kmip-1-suite-b-192`)
# REQ:profiles-1.4@6.3:62cc2442524b8a8c 1.4 Baseline Server Basic (`kmip-1-tls12`)
# REQ:profiles-1.4@6.4:62cc2442524b8a8c 1.4 Baseline Server TLS v1.2 (`kmip-1-tls12`)
# REQ:profiles-1.4@6.8:62cc2442524b8a8c 1.4 HTTPS Server (`kmip-1-tls12`)
# REQ:profiles-1.4@6.10:62cc2442524b8a8c 1.4 XML Server (`kmip-1-tls12`)
# REQ:profiles-1.4@6.12:62cc2442524b8a8c 1.4 JSON Server (`kmip-1-tls12`)
# REQ:profiles-1.4@6.14:62cc2442524b8a8c 1.4 Symmetric Key Lifecycle Server (`kmip-1-tls12`) with KMIP_TRIPLE_DES=enabled
# REQ:profiles-1.4@6.18:62cc2442524b8a8c 1.4 Symmetric Key Foundry Server (`kmip-1-tls12`) with KMIP_TRIPLE_DES=enabled
# REQ:profiles-1.4@6.20:62cc2442524b8a8c 1.4 Asymmetric Key Lifecycle Server (`kmip-1-tls12`)
# REQ:profiles-1.4@6.24:62cc2442524b8a8c 1.4 Basic Cryptographic Server (`kmip-1-tls12`); one case passes with its corrected fixture
# REQ:profiles-1.4@6.25:62cc2442524b8a8c 1.4 Advanced Cryptographic Server (`kmip-1-tls12`); one case passes with its corrected fixture
# REQ:profiles-1.4@6.26:62cc2442524b8a8c 1.4 RNG Cryptographic Server (`kmip-1-tls12`)
# REQ:profiles-1.4@6.28:62cc2442524b8a8c 1.4 Opaque Managed Object Store Server (`kmip-1-tls12`)
# REQ:profiles-1.4@6.30:62cc2442524b8a8c 1.4 Storage Array with Self-Encrypting Drives Server (`kmip-1-tls12`)
# REQ:profiles-1.4@6.32:62cc2442524b8a8c 1.4 Tape Library Server (`kmip-1-tls12`)
# REQ:profiles-1.4@6.34:62cc2442524b8a8c 1.4 Suite B minLOS_128 Server (`kmip-1-suite-b-128`)
# REQ:profiles-1.4@6.36:62cc2442524b8a8c 1.4 Suite B minLOS_192 Server (`kmip-1-suite-b-192`)
# REQ:profiles-1.4@6.38:62cc2442524b8a8c 1.4 AES XTS Server (`kmip-1-tls12`)
#
# The same composite (at least one claimed profile, every statement met):
# REQ:profiles-1.3:807289b6451218b2 1.3 Profiles section 6: the claimed server profiles above meet all their conditions
# REQ:profiles-1.4:807289b6451218b2 1.4 Profiles section 6: the claimed server profiles above meet all their conditions
# REQ:spec-1.3:46f8b82957f9677b spec 1.3 12.1: a conforming KMIP Server, by the claimed Profiles 1.3 server profiles above
# REQ:spec-1.4:46f8b82957f9677b spec 1.4 12.1: a conforming KMIP Server, by the claimed Profiles 1.4 server profiles above
# REQ:spec-1.3:94dd3f6a1a82fe44 spec 1.3 12.1: every claimed Profiles 1.3 server profile meets all statements of its clauses
# REQ:spec-1.4:94dd3f6a1a82fe44 spec 1.4 12.1: every claimed Profiles 1.4 server profile meets all statements of its clauses
SUPPORT_SPEC='62cc2442524b8a8c'
_CLAIMED_COMMON=[('6.3','Baseline Server Basic'),('6.4','Baseline Server TLS v1.2'),('6.8','HTTPS Server'),('6.10','XML Server'),
    ('6.12','JSON Server'),('6.14','Symmetric Key Lifecycle Server'),('6.18','Symmetric Key Foundry Server'),
    ('6.20','Asymmetric Key Lifecycle Server'),('6.24','Basic Cryptographic Server'),('6.25','Advanced Cryptographic Server'),
    ('6.26','RNG Cryptographic Server'),('6.28','Opaque Managed Object Server'),('6.30','Storage Array with Self-Encrypting Drives Server'),
    ('6.32','Tape Library Server'),('6.34','Suite B minLOS_128 Server'),('6.36','Suite B minLOS_192 Server')]
CLAIMED_1X={'profiles-1.3':_CLAIMED_COMMON,'profiles-1.4':_CLAIMED_COMMON+[('6.38','AES XTS Server')]}
NOT_CLAIMED_1X=[('6.5','Complete Server Basic'),('6.6','Complete Server TLS v1.2')]

# Non-passing mandatory cases ('-M-' in the case name under mandatory/) per
# edition, as reported by the trace inventory. CS-BC-M-4-12-3DES-13 sits in the
# 1.3 mandatory folder but is not listed in Profiles 1.3 section 5.9.7.
# CS-AC-M-3-ECC-13 (also unlisted) uses secp256k1, which needs
# KMIP_EC_CURVES=extended; the committed rc.4
# inventory predates that setting and still reports it as passed.
NON_PASSING_MANDATORY={
    '1.3':{'CS-BC-M-13-13':'passed (corrected fixture)','CS-BC-M-6-13':'passed (corrected fixture)',
           'CS-BC-M-4-12-3DES-13':'documented deviation','CS-AC-M-3-ECC-13':'ec',
           'SKFF-M-4-13':'3des','SKFF-M-8-13':'3des','SKFF-M-12-13':'3des'},
    '1.4':{'CS-AC-M-2-14':'passed (corrected fixture)','CS-BC-M-13-14':'passed (corrected fixture)',
           'SKFF-M-4-14':'3des','SKFF-M-8-14':'3des','SKFF-M-12-14':'3des'},
    '2.0':{'BL-M-2-20':'documented deviation','BL-M-3-20':'documented deviation','CS-AC-M-2-20':'passed (corrected fixture)',
           'CS-BC-M-13-20':'passed (corrected fixture)','CS-BC-M-CHACHA20POLY1305-1-20':'documented deviation',
           'PKCS11-M-1-20':'documented deviation','QS-M-1-20':'interop',
           'SKFF-M-4-20':'3des','SKFF-M-8-20':'3des','SKFF-M-12-20':'3des'},
    '2.1':{'BL-M-2-21':'documented deviation','BL-M-3-21':'documented deviation','CS-AC-M-2-21':'passed (corrected fixture)',
           'CS-BC-M-CHACHA20POLY1305-1-21':'documented deviation','PKCS11-M-1-21':'documented deviation','QS-M-1-21':'interop',
           'SKFF-M-4-21':'3des','SKFF-M-8-21':'3des','SKFF-M-12-21':'3des'},
    '3.0':{'BL-M-2-30':'documented deviation','BL-M-3-30':'documented deviation','BL-M-20-30':'documented deviation',
           'CS-AC-M-2-30':'passed (corrected fixture)','MSGENC-HTTPS-M-1-30':'interop','MSGENC-JSON-M-1-30':'interop',
           'MSGENC-XML-M-1-30':'interop','PKCS11-M-1-30':'documented deviation','QS-M-1-30':'interop',
           'SKFF-M-4-30':'3des','SKFF-M-8-30':'3des','SKFF-M-12-30':'3des'},
}
SHORT={'skipped (configuration: passes with KMIP_TRIPLE_DES=enabled)':'3des',
       'skipped (configuration: passes with KMIP_INTEROP_TEST_MODE=true (test events only; forbidden in production))':'interop',
       'skipped (configuration: passes with KMIP_EC_CURVES=extended)':'ec'}

class ProfileClaims(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.matrix=json.loads((ROOT/'docs/specs/requirement-matrix.json').read_text())
        cls.index=json.loads((ROOT/'docs/specs/requirements-index.json').read_text())

    def sections(self,key):
        return {s['id']:s for s in self.index['sources'][key]['sections']}

    def unmet(self,key,section_ids,skip=()):
        """Server statements of the given sections that are neither verified nor reviewed out of scope.

        A statement several sections share is judged at each occurrence: it is
        met in a section only if its row is verified or the matrix lists that
        section among its verified occurrences (section-scoped citations).
        """
        source=self.matrix['sources'][key];rows=source['statements'];secs=self.sections(key);bad=[]
        scoped=source.get('verified_occurrences',{})
        for sid in section_ids:
            for st in secs[sid].get('statements',[]):
                d=st.split()[0]
                if d in skip:continue
                row=rows[d];app=row[1];ev=row[2] if len(row)>2 else None
                if app in NOT_SERVER:continue
                if ev not in MET and sid not in scoped.get(d,()):bad.append((key,sid,d,app,ev))
        return bad

    def baseline_sections(self,key):
        secs=self.sections(key);out=[]
        for sid,title in BASELINE_1X[key]:
            self.assertIn(sid,secs,f'{key} {sid}')
            self.assertEqual(secs[sid]['title'],title,f'{key} {sid}')
            out.append(sid)
            if sid not in OWN_STATEMENTS_ONLY:out+=[s for s in secs if s.startswith(sid+'.')]
        return out

    def test_1x_baseline_server_clauses_are_met(self):
        for key in BASELINE_1X:
            ids=self.baseline_sections(key)
            self.assertGreater(len(ids),len(BASELINE_1X[key]),key)
            self.assertEqual(self.unmet(key,ids),[],key)

    def test_cited_server_conditions_are_met(self):
        for digest,(sid,title,sources) in CONDITIONS.items():
            for key in sources:
                sec=self.sections(key)[sid]
                self.assertEqual(sec['title'],title,f'{key} {sid}')
                self.assertTrue(any(s.split()[0]==digest for p in self.sections(key).values() for s in p.get('statements',[])),f'{key} {digest}')
                # The Baseline statement is established by test_1x_baseline_server_clauses_are_met (1.x only).
                skip={BASELINE_ROW} if key in ('profiles-1.3','profiles-1.4') else set()
                self.assertEqual(self.unmet(key,[sid],skip),[],f'{key} {sid}')
                if key in ('profiles-2.0','profiles-2.1'):
                    self.assertNotIn(BASELINE_ROW,[s.split()[0] for s in sec.get('statements',[])],f'{key} {sid}')

    def test_claimed_1x_profiles_meet_every_statement(self):
        """Aggregate rows: each claimed 1.3/1.4 server profile section holds at every statement but its own aggregate."""
        text=pathlib.Path(__file__).read_text()
        for key,claimed in CLAIMED_1X.items():
            secs=self.sections(key)
            for sid,title in claimed+NOT_CLAIMED_1X:
                self.assertTrue(secs[sid]['title'].startswith(title+' KMIP v'+key[-3:]),f'{key} {sid} {secs[sid]["title"]}')
                self.assertIn(SUPPORT_SPEC,[s.split()[0] for s in secs[sid].get('statements',[])],f'{key} {sid}')
            ids=[sid for sid,_ in claimed]
            self.assertEqual(self.unmet(key,ids,{SUPPORT_SPEC}),[],key)
            # The aggregate is cited for exactly the claimed sections, and so met there.
            cited={m.group(1) for m in re.finditer(r'REQ:'+re.escape(key)+r'@([0-9.]+):'+SUPPORT_SPEC,text)}
            self.assertEqual(cited,set(ids),key)
            self.assertEqual(self.unmet(key,ids),[],key)
            # Complete Server stays unclaimed and open.
            self.assertNotEqual(self.unmet(key,[sid for sid,_ in NOT_CLAIMED_1X]),[],key)
            # Every server profile section of the edition is either claimed or listed as not claimed.
            server=[sid for sid,s in secs.items() if sid.startswith('6.') and SUPPORT_SPEC in [x.split()[0] for x in s.get('statements',[])]
                    and 'Client' not in s['title']]
            self.assertEqual(sorted(server),sorted(ids+[sid for sid,_ in NOT_CLAIMED_1X]),key)

    def test_uncited_rows_are_not_cited_here(self):
        text=pathlib.Path(__file__).read_text()
        for digest in NOT_CITED:
            self.assertIsNone(re_cite(text,digest),digest)

    def test_non_passing_mandatory_cases_match_the_inventory(self):
        inv=json.loads((ROOT/'docs/specs/oasis-case-inventory.json').read_text())['cases']
        got={}
        for k,e in inv.items():
            v,path=k.split('|',1)
            if '/mandatory/' not in path:continue
            case=path.rsplit('/',1)[-1].removesuffix('.xml')
            if '-M-' not in case or e.get('reported')=='passed':continue
            got.setdefault(v,{})[case]=SHORT.get(e.get('reported'),e.get('reported'))
        expected=json.loads(json.dumps(NON_PASSING_MANDATORY))
        if inv['1.3|test-cases/kmip-v1.3/mandatory/CS-AC-M-3-ECC-13.xml'].get('reported')=='passed':
            del expected['1.3']['CS-AC-M-3-ECC-13']
        self.assertEqual(got,expected)

def re_cite(text,digest):
    return re.search(r'REQ:(?:[a-z]+-\d\.\d:)?'+digest,text)

if __name__=='__main__':unittest.main()
