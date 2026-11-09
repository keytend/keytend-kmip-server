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

"""Live check of the Profiles "SHALL support all of the <profile> Mandatory Test Cases" clauses.

Replays every mandatory test case of the profiles listed below against a built
binary and requires each one to pass:
- the TTLV traces through scripts/oasis_profile_replay.py (Profiles 4.1
  variations), with KMIP_TRIPLE_DES=enabled as the Symmetric Key profiles need;
- the MSGENC traces also through scripts/oasis_https_replay.py, in their own
  encodings over HTTPS/1.0 and HTTPS/1.1.

Two kinds of entry are credited in a separately labelled mode, never silently:
- CORRECTED: a case whose OASIS trace is a proven corpus defect
  (docs/specs/oasis-corpus-proofs.json) passes when its corrected fixture
  (docs/specs/oasis-corrected-fixtures.json, `--corrected-fixtures`) is
  applied; every other case of the entry must pass the published trace.
- INTEROP: the Quantum Safe Query case lists Interop, which KMIP 2.x allows
  only outside production (docs/interpretations.md#interop); these cases are
  replayed with KMIP_INTEROP_TEST_MODE=true.

Case lists are the subsection titles of each Mandatory Test Cases section of the
pinned Profiles documents. Profiles whose mandatory cases do not all pass are
not cited here. Usage:

    python3 scripts/test_profile_mandatory_cases.py [--binary target/debug/keytend-kmip-server]
"""
import argparse,json,os,pathlib,subprocess,sys,tempfile
ROOT=pathlib.Path(__file__).resolve().parents[1]

def cases(prefix,numbers,suffix):return [f'{prefix}-M-{n}-{suffix}' for n in numbers]
CORRECTED='corrected';INTEROP='interop'
def basic(suffix,gcm):return cases('CS-BC',list(range(1,15))+([f'GCM-{n}' for n in (1,2,3)] if gcm else []),suffix)
def advanced(suffix,oaep):return cases('CS-AC',list(range(1,9))+([f'OAEP-{n}' for n in range(1,11)] if oaep else []),suffix)

# Each entry: clause digest, edition, mandatory case ids.
MANDATORY=[
    # REQ:1f2b72625ac326b6 1.3 HTTPS server: its mandatory case passes over TTLV and over HTTPS
    ('1f2b72625ac326b6','1.3',cases('MSGENC-HTTPS',[1],13)),
    # REQ:f71c59939880b79d 1.3 XML server: its mandatory case passes, including XML over HTTPS
    ('f71c59939880b79d','1.3',cases('MSGENC-XML',[1],13)),
    # REQ:527ff9f67c58fce4 1.3 JSON server: its mandatory case passes, including JSON over HTTPS
    ('527ff9f67c58fce4','1.3',cases('MSGENC-JSON',[1],13)),
    # REQ:c77e2c2fe98eb5e4 1.3 Symmetric Key Lifecycle mandatory cases pass
    ('c77e2c2fe98eb5e4','1.3',cases('SKLC',[1,2,3],13)),
    # REQ:d0c86d28c04c7c2e 1.3 Basic Symmetric Key Foundry mandatory cases pass (3DES enabled)
    ('d0c86d28c04c7c2e','1.3',cases('SKFF',[1,2,3,4],13)),
    # REQ:9e3218e198105746 1.3 Advanced Symmetric Key Foundry mandatory cases pass (3DES enabled)
    ('9e3218e198105746','1.3',cases('SKFF',[9,10,11,12],13)),
    # REQ:51c23dadf11f0666 1.3 Asymmetric Key Lifecycle mandatory cases pass
    ('51c23dadf11f0666','1.3',cases('AKLC',[1,2,3],13)),
    # REQ:562b64510acb2092 1.3 RNG Cryptographic mandatory case passes
    ('562b64510acb2092','1.3',cases('CS-RNG',[1],13)),
    # REQ:507b5f36646109c7 1.3 Opaque Managed Object mandatory case passes
    ('507b5f36646109c7','1.3',cases('OMOS',[1],13)),
    # REQ:d8303666c398d613 1.3 Suite B minLOS_128 mandatory case, message part (TLS part: src/main.rs)
    ('d8303666c398d613','1.3',cases('SUITEB_128',[1],13)),
    # REQ:4e040d028568554e 1.3 Suite B minLOS_192 mandatory case, message part (TLS part: src/main.rs)
    ('4e040d028568554e','1.3',cases('SUITEB_192',[1],13)),
    # REQ:842711c35e11254c 1.3 Intermediate Symmetric Key Foundry mandatory cases pass (3DES enabled)
    ('842711c35e11254c','1.3',cases('SKFF',[5,6,7,8],13)),
    # REQ:0edffeec1fe8c9b2 1.3 Storage Array with Self-Encrypting Drives mandatory cases pass
    ('0edffeec1fe8c9b2','1.3',cases('SASED',[1,2,3],13)),
    # REQ:ae0ef0a31071adfe 1.3 Tape Library mandatory cases pass
    ('ae0ef0a31071adfe','1.3',cases('TL',[1,2,3],13)),
    # REQ:232d587ad36f6246 1.4 HTTPS server: its mandatory case passes over TTLV and over HTTPS
    ('232d587ad36f6246','1.4',cases('MSGENC-HTTPS',[1],14)),
    # REQ:cd1d609342908874 1.4 XML server: its mandatory case passes, including XML over HTTPS
    ('cd1d609342908874','1.4',cases('MSGENC-XML',[1],14)),
    # REQ:25362141b9b9b3fd 1.4 JSON server: its mandatory case passes, including JSON over HTTPS
    ('25362141b9b9b3fd','1.4',cases('MSGENC-JSON',[1],14)),
    # REQ:39e1e6586fc74a20 1.4 Symmetric Key Lifecycle mandatory cases pass
    ('39e1e6586fc74a20','1.4',cases('SKLC',[1,2,3],14)),
    # REQ:570154d8cafe916b 1.4 Basic Symmetric Key Foundry mandatory cases pass (3DES enabled)
    ('570154d8cafe916b','1.4',cases('SKFF',[1,2,3,4],14)),
    # REQ:717406f2545406b8 1.4 RNG Cryptographic mandatory case passes
    ('717406f2545406b8','1.4',cases('CS-RNG',[1],14)),
    # REQ:9db3232bacdacdbf 1.4 Opaque Managed Object mandatory case passes
    ('9db3232bacdacdbf','1.4',cases('OMOS',[1],14)),
    # REQ:fcfccce47925cd55 1.4 Suite B minLOS_128 mandatory case, message part (TLS part: src/main.rs)
    ('fcfccce47925cd55','1.4',cases('SUITEB_128',[1],14)),
    # REQ:e89c9e824244a839 1.4 Suite B minLOS_192 mandatory case, message part (TLS part: src/main.rs)
    ('e89c9e824244a839','1.4',cases('SUITEB_192',[1],14)),
    # REQ:73bf6ed8fff0babb 1.4 AES XTS mandatory cases pass
    ('73bf6ed8fff0babb','1.4',cases('AX',[1,2],14)),
    # REQ:72376bc1155915f8 1.4 Intermediate Symmetric Key Foundry mandatory cases pass (3DES enabled)
    ('72376bc1155915f8','1.4',cases('SKFF',[5,6,7,8],14)),
    # REQ:aedff99fe78adea6 1.4 Advanced Symmetric Key Foundry mandatory cases pass (3DES enabled)
    ('aedff99fe78adea6','1.4',cases('SKFF',[9,10,11,12],14)),
    # REQ:ff1b5f7dabee62f4 1.4 Asymmetric Key Lifecycle mandatory cases pass
    ('ff1b5f7dabee62f4','1.4',cases('AKLC',[1,2,3],14)),
    # REQ:2fc2dd8b5b9a28a1 1.4 Storage Array with Self-Encrypting Drives mandatory cases pass
    ('2fc2dd8b5b9a28a1','1.4',cases('SASED',[1,2,3],14)),
    # REQ:7cf1df180570bdab 1.4 Tape Library mandatory cases pass
    ('7cf1df180570bdab','1.4',cases('TL',[1,2,3],14)),
    # REQ:9eb6cbc5f39795a2 2.0 Basic Symmetric Key Foundry mandatory cases pass (3DES enabled)
    ('9eb6cbc5f39795a2','2.0',cases('SKFF',[1,2,3,4],20)),
    # REQ:01f53aa6fc2e5d14 2.0 Intermediate Symmetric Key Foundry mandatory cases pass (3DES enabled)
    ('01f53aa6fc2e5d14','2.0',cases('SKFF',[5,6,7,8],20)),
    # REQ:8696b1b7da8d5c79 2.0 RNG Cryptographic mandatory case passes
    ('8696b1b7da8d5c79','2.0',cases('CS-RNG',[1],20)),
    # REQ:038d5d57845793da 2.0 Opaque Managed Object mandatory case passes
    ('038d5d57845793da','2.0',cases('OMOS',[1],20)),
    # REQ:f8df36836c6a6703 2.0 AES XTS mandatory cases pass
    ('f8df36836c6a6703','2.0',cases('AX',[1,2],20)),
    # REQ:345a08021212d032 2.0 Symmetric Key Lifecycle mandatory cases pass
    ('345a08021212d032','2.0',cases('SKLC',[1,2,3],20)),
    # REQ:ace6f9f3594d910b 2.0 Advanced Symmetric Key Foundry mandatory cases pass (3DES enabled)
    ('ace6f9f3594d910b','2.0',cases('SKFF',[9,10,11,12],20)),
    # REQ:d6ee361dfbfc397f 2.0 Asymmetric Key Lifecycle mandatory cases pass
    ('d6ee361dfbfc397f','2.0',cases('AKLC',[1,2,3],20)),
    # REQ:427211bf06735629 2.0 Storage Array with Self-Encrypting Drives mandatory cases pass
    ('427211bf06735629','2.0',cases('SASED',[1,2,3],20)),
    # REQ:e108a688dfcfa642 2.0 Tape Library mandatory cases pass
    ('e108a688dfcfa642','2.0',cases('TL',[1,2,3],20)),
    # REQ:4aa69cfcead724b4 2.1 Basic Symmetric Key Foundry mandatory cases pass (3DES enabled)
    ('4aa69cfcead724b4','2.1',cases('SKFF',[1,2,3,4],21)),
    # REQ:18724e007bd8f59c 2.1 Intermediate Symmetric Key Foundry mandatory cases pass (3DES enabled)
    ('18724e007bd8f59c','2.1',cases('SKFF',[5,6,7,8],21)),
    # REQ:14fb1d02c938ce0f 2.1 Advanced Symmetric Key Foundry mandatory cases pass (3DES enabled)
    ('14fb1d02c938ce0f','2.1',cases('SKFF',[9,10,11,12],21)),
    # REQ:49dfd9c811bcda5f 2.1 RNG Cryptographic mandatory case passes
    ('49dfd9c811bcda5f','2.1',cases('CS-RNG',[1],21)),
    # REQ:438f0daef826fcc7 2.1 Opaque Managed Object mandatory case passes
    ('438f0daef826fcc7','2.1',cases('OMOS',[1],21)),
    # REQ:57e13a1f6889d60b 2.1 AES XTS mandatory cases pass
    ('57e13a1f6889d60b','2.1',cases('AX',[1,2],21)),
    # REQ:946bca546c890873 2.1 Symmetric Key Lifecycle mandatory cases pass
    ('946bca546c890873','2.1',cases('SKLC',[1,2,3],21)),
    # REQ:8ef2a461df574d20 2.1 Asymmetric Key Lifecycle mandatory cases pass
    ('8ef2a461df574d20','2.1',cases('AKLC',[1,2,3],21)),
    # REQ:11df870d8bc1434e 2.1 Storage Array with Self-Encrypting Drives mandatory cases pass
    ('11df870d8bc1434e','2.1',cases('SASED',[1,2,3],21)),
    # REQ:9543ed9dd29c122c 2.1 Tape Library mandatory cases pass
    ('9543ed9dd29c122c','2.1',cases('TL',[1,2,3],21)),
    # REQ:f1b9d79706e390ad 2.0 HTTPS server: its mandatory case passes over TTLV and over HTTPS
    ('f1b9d79706e390ad','2.0',cases('MSGENC-HTTPS',[1],20)),
    # REQ:c4d1794322967159 2.0 XML server: its mandatory case passes, including XML over HTTPS
    ('c4d1794322967159','2.0',cases('MSGENC-XML',[1],20)),
    # REQ:7e656dafa3327742 2.0 JSON server: its mandatory case passes, including JSON over HTTPS
    ('7e656dafa3327742','2.0',cases('MSGENC-JSON',[1],20)),
    # REQ:98a2caaa53647966 2.1 HTTPS server: its mandatory case passes over TTLV and over HTTPS
    ('98a2caaa53647966','2.1',cases('MSGENC-HTTPS',[1],21)),
    # REQ:1334bd1705a47bcb 2.1 XML server: its mandatory case passes, including XML over HTTPS
    ('1334bd1705a47bcb','2.1',cases('MSGENC-XML',[1],21)),
    # REQ:463ce5b38874c656 2.1 JSON server: its mandatory case passes, including JSON over HTTPS
    ('463ce5b38874c656','2.1',cases('MSGENC-JSON',[1],21)),
    # REQ:dfde1634e961b221 1.3 Advanced Cryptographic mandatory cases pass
    ('dfde1634e961b221','1.3',advanced(13,False)),
    # REQ:768b52028d70866a 1.3 Basic Cryptographic mandatory cases pass (CS-BC-M-6 and -13: corrected fixtures)
    ('768b52028d70866a','1.3',basic(13,False),CORRECTED),
    # REQ:c6ca6149ddc13848 1.4 Basic Cryptographic mandatory cases pass (CS-BC-M-13: corrected fixture)
    ('c6ca6149ddc13848','1.4',basic(14,True),CORRECTED),
    # REQ:86e5268b9ee1e372 1.4 Advanced Cryptographic mandatory cases pass (CS-AC-M-2: corrected fixture)
    ('86e5268b9ee1e372','1.4',advanced(14,True),CORRECTED),
    # REQ:8960b026ddebeaa1 2.0 Advanced Cryptographic mandatory cases pass (CS-AC-M-2: corrected fixture)
    ('8960b026ddebeaa1','2.0',advanced(20,True),CORRECTED),
    # REQ:bd5e390b00265f61 2.1 Advanced Cryptographic mandatory cases pass (CS-AC-M-2: corrected fixture)
    ('bd5e390b00265f61','2.1',advanced(21,True),CORRECTED),
    # REQ:f3215e67fbd808bd 2.0 Quantum Safe mandatory cases pass (interop test mode)
    ('f3215e67fbd808bd','2.0',cases('QS',[1,2],20),INTEROP),
    # REQ:096de1517bf546c6 2.1 Quantum Safe mandatory cases pass (interop test mode)
    ('096de1517bf546c6','2.1',cases('QS',[1,2],21),INTEROP),
]

def case_id(path):return path.rsplit('/',1)[-1].removesuffix('.xml')

def main():
    a=argparse.ArgumentParser(description=__doc__.splitlines()[0])
    a.add_argument('--binary',type=pathlib.Path,default=ROOT/'target/debug/keytend-kmip-server')
    args=a.parse_args()
    entries=[(e[0],e[1],e[2],e[3] if len(e)>3 else None) for e in MANDATORY]
    versions=sorted({v for _,v,_,_ in entries})
    env={**os.environ,'KMIP_TRIPLE_DES':'enabled'}
    replay=lambda out,extra,environment:subprocess.run([sys.executable,str(ROOT/'scripts/oasis_profile_replay.py'),'--binary',str(args.binary),'--output',str(out),*extra],
                       cwd=ROOT,env=environment,check=True,stdout=subprocess.DEVNULL)
    edited={e['case'] for e in json.loads((ROOT/'docs/specs/oasis-corrected-fixtures.json').read_text())['edits']}
    problems=[];credited=[]
    with tempfile.TemporaryDirectory(prefix='keytend-kmip-server-mandatory-') as d:
        ttlv=pathlib.Path(d)/'ttlv.json';https=pathlib.Path(d)/'https.json'
        corrected=pathlib.Path(d)/'corrected.json';interop=pathlib.Path(d)/'interop.json'
        replay(ttlv,['--versions',*versions],env)
        alt={}
        corrected_versions=sorted({v for _,v,_,m in entries if m==CORRECTED})
        if corrected_versions:
            replay(corrected,['--corrected-fixtures','--versions',*corrected_versions],env)
            alt[CORRECTED]={(e['version'],case_id(e['case'])):e for e in json.loads(corrected.read_text())['cases'] if e['version']+'|'+e['case'] in edited}
        interop_versions=sorted({v for _,v,_,m in entries if m==INTEROP})
        if interop_versions:
            replay(interop,['--filter','QS-M-','--versions',*interop_versions],{**env,'KMIP_INTEROP_TEST_MODE':'true'})
            alt[INTEROP]={(e['version'],case_id(e['case'])):e for e in json.loads(interop.read_text())['cases']}
        https_versions=sorted({v for _,v,c,_ in entries if any(x.startswith('MSGENC') for x in c)})
        subprocess.run([sys.executable,str(ROOT/'scripts/oasis_https_replay.py'),'--binary',str(args.binary),'--output',str(https),'--versions',*https_versions],
                       cwd=ROOT,env=env,check=True,stdout=subprocess.DEVNULL)
        status={(e['version'],case_id(e['case'])):e for e in json.loads(ttlv.read_text())['cases']}
        lanes={}
        for e in json.loads(https.read_text())['cases']:lanes.setdefault((e['version'],case_id(e['case'])),[]).append(e)
    for digest,version,ids,mode in entries:
        for cid in ids:
            e=status.get((version,cid))
            if mode and (e is None or e['status']!='passed'):
                other=alt[mode].get((version,cid))
                if other and other['status']=='passed':
                    credited.append(f'{digest} {version} {cid}: passed ({mode})');e=other
            if e is None or e['status']!='passed':
                problems.append(f'{digest} {version} {cid}: {e["status"] if e else "missing"} {(e or {}).get("detail","")[:160]}')
            if cid.startswith('MSGENC'):
                rows=lanes.get((version,cid),[])
                # Binary-port baseline plus HTTP/1.0 and 1.1 lanes (two request forms for XML/JSON).
                if len(rows)<3 or any(r['status']!='passed' for r in rows):
                    problems.append(f'{digest} {version} {cid} over HTTPS: '+'; '.join(f'{r["lane"]} {r["status"]}' for r in rows))
    for c in credited:print('CREDIT',c)
    for p in problems:print('FAIL',p)
    print(f'{len(entries)} mandatory test case clauses, {sum(len(c) for _,_,c,_ in entries)} cases, {len(credited)} credited in a labelled mode, {len(problems)} problems')
    sys.exit(1 if problems else 0)

if __name__=='__main__':main()
