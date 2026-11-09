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

"""Reproducible proofs of OASIS trace corpus defects, without the server.

Each proof reads the pinned profile archives (checksums from
docs/specs/profiles.json), recomputes the disputed value with pyca/cryptography
or inspects the trace structure, and states what it shows. The published
vectors are never modified. Output: docs/specs/oasis-corpus-proofs.json.
"""
import argparse,hashlib,json,pathlib,re,sys,xml.etree.ElementTree as ET,zipfile
from cryptography.hazmat.primitives import hashes,serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers import Cipher,algorithms,modes
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.exceptions import InvalidSignature
ROOT=pathlib.Path(__file__).resolve().parents[1]
PINS={p['version']:p['sha256'] for p in json.loads((ROOT/'docs/specs/profiles.json').read_text())}

def archive(version):
    raw=(ROOT/f'.cache/specs/profiles-{version}.zip').read_bytes()
    if hashlib.sha256(raw).hexdigest()!=PINS[version]:raise SystemExit(f'profiles-{version}.zip does not match its pin')
    return zipfile.ZipFile(ROOT/f'.cache/specs/profiles-{version}.zip')
def trace(version,case):
    z=archive(version);name=[n for n in z.namelist() if n.endswith('/'+case+'.xml')]
    if len(name)!=1:raise SystemExit(f'{version} {case}: {len(name)} archive members')
    return name[0],[m for m in ET.fromstring(z.read(name[0])) if m.tag in ('RequestMessage','ResponseMessage')]
def items(messages,op):
    out=[]
    for i,m in enumerate(messages):
        for b in m.findall('BatchItem'):
            if b.find('Operation').get('value')==op:out.append((i,m.tag,b))
    return out
def hx(e,path):
    f=e.find(path);return bytes.fromhex(f.get('value')) if f is not None and not f.get('value','').startswith('$') else None

def aes_ecb_13():
    out=[]
    for version,case in (('1.3','CS-BC-M-6-13'),('1.4','CS-BC-M-6-14')):
        name,m=trace(version,case)
        key=hx(items(m,'Register')[0][2],'.//KeyMaterial')
        req=[b for i,t,b in items(m,'Encrypt') if t=='RequestMessage'][0];resp=[b for i,t,b in items(m,'Encrypt') if t=='ResponseMessage'][0]
        data=hx(req,'RequestPayload/Data');expected=hx(resp,'ResponsePayload/Data')
        e=Cipher(algorithms.AES(key),modes.ECB()).encryptor();actual=e.update(data)+e.finalize()
        out.append({'trace':f'{version}|{name}','computed':actual.hex(),'trace_expects':expected.hex(),'agrees':actual==expected})
    assert not out[0]['agrees'] and out[1]['agrees'],out
    return {'family':'aes-ecb-sample-1.3','shows':'AES-128-ECB of the trace plaintext under the trace key differs from the 1.3 sample and equals the 1.4 sample.','evidence':out}

def pss_sample():
    out=[]
    for version,case in (('1.4','CS-AC-M-2-14'),('2.0','CS-AC-M-2-20'),('2.1','CS-AC-M-2-21'),('3.0','CS-AC-M-2-30')):
        name,m=trace(version,case)
        reg=items(m,'Register')[0][2];material=hx(reg,'.//KeyMaterial')
        try:key=serialization.load_der_public_key(material)
        except ValueError:key=serialization.load_der_public_key(spki(material))
        req=[b for i,t,b in items(m,'SignatureVerify') if t=='RequestMessage'][0]
        data=hx(req,'RequestPayload/Data');sig=hx(req,'RequestPayload/SignatureData')
        results={}
        for mgf in ('SHA1','SHA256'):
            for salt in (20,32,64,222):
                try:key.verify(sig,data,padding.PSS(padding.MGF1(getattr(hashes,mgf)()),salt),hashes.SHA256());ok=True
                except InvalidSignature:ok=False
                results[f'MGF1-{mgf} salt {salt}']=ok
        assert [k for k,v in results.items() if v]==['MGF1-SHA256 salt 222'],results
        out.append({'trace':f'{version}|{name}','verifies':results})
    return {'family':'pss-sample-contradicts-default-table','shows':'The sample PSS signature verifies only with MGF1-SHA-256 and a 222-byte salt. The Cryptographic Parameters defaults are MGF1-SHA-1 and a salt of the MGF hash block size (64 bytes); no default reading (20, 32 or 64 bytes, either MGF hash) verifies.','evidence':out}
def spki(pkcs1):
    def der(tag,body):
        n=len(body);l=bytes([n]) if n<128 else bytes([0x80|((n.bit_length()+7)//8)])+n.to_bytes((n.bit_length()+7)//8,'big')
        return bytes([tag])+l+body
    return der(0x30,der(0x30,bytes.fromhex('06092a864886f70d0101010500'))+der(0x03,b'\0'+pkcs1))

def random_iv_literal():
    out=[]
    for version,case in (('1.3','CS-BC-M-13-13'),('1.4','CS-BC-M-13-14'),('2.0','CS-BC-M-13-20'),('2.1','CS-BC-M-13-21')):
        name,m=trace(version,case);bound=set();first_use=None
        for i,msg in enumerate(m):
            for e in msg.iter():
                v=e.get('value','')
                if v=='$DATA_0':
                    if msg.tag=='ResponseMessage':bound.add(v)
                    elif v not in bound and first_use is None:first_use=i//2
        out.append({'trace':f'{version}|{name}','unbound_use_at_exchange':first_use})
    assert all(o['unbound_use_at_exchange'] is not None for o in out[:3]) and out[3]['unbound_use_at_exchange'] is None,out
    return {'family':'random-iv-literal-sample','shows':'1.3, 1.4 and 2.0 traces use $DATA_0 in a request before any response binds it (the Random IV Encrypt response is a literal); the 2.1 trace binds it.','evidence':out}

def omos_version():
    name,m=trace('1.4','OMOS-O-1-14')
    versions=[(msg.tag,int(msg.find('./*/ProtocolVersion/ProtocolVersionMinor').get('value'))) for msg in m]
    assert all(v==4 for t,v in versions if t=='RequestMessage') and [v for t,v in versions if t=='ResponseMessage'].count(3)==1,versions
    return {'family':'omos-response-version-1.4','shows':'Every request is 1.4 and one response is labelled 1.3; the 1.3 copy of the trace has the same structure.','evidence':{'trace':f'1.4|{name}','messages':versions}}

def chacha_truncated():
    name,m=trace('2.1','CS-BC-M-CHACHA20POLY1305-1-21')
    reg=items(m,'Register')[0][2];key=hx(reg,'.//KeyMaterial');found=[]
    for i,t,b in items(m,'Decrypt'):
        if t!='RequestMessage':continue
        p=b.find('RequestPayload');tag=hx(p,'AuthenticatedEncryptionTag');iv=hx(p,'IVCounterNonce');data=hx(p,'Data');aad=hx(p,'AuthenticatedEncryptionAdditionalData') or b''
        if None in (tag,iv,data):continue
        for j,t2,b2 in items(m,'Encrypt'):
            pass
        found.append({'exchange':i//2,'tag_bytes':len(tag),'tag':tag.hex()})
    full=None
    for i,t,b in items(m,'Encrypt'):
        if t=='RequestMessage':
            p=b.find('RequestPayload');iv=hx(p,'IVCounterNonce');data=hx(p,'Data');aad=hx(p,'AuthenticatedEncryptionAdditionalData') or b''
            if iv and data:full=ChaCha20Poly1305(key).encrypt(iv,data,aad or None)[-16:];break
    short=[f for f in found if f['tag_bytes']<16]
    assert full and short and all(full.hex().startswith(f['tag']) for f in short),(full,found)
    return {'family':'chacha20poly1305-truncated-tag','shows':'The truncated tags the trace expects to succeed are prefixes of the valid 16-byte RFC 8439 tag; the question is whether KMIP permits truncation, not the bytes.','evidence':{'trace':f'2.1|{name}','full_tag':full.hex(),'truncated':short}}

def spec_text(version):
    """Plain text of the pinned specification HTML (fetched and hash-checked by scripts/fetch_specs.py)."""
    from bs4 import BeautifulSoup
    html=(ROOT/f'.cache/specs/{version}.html').read_bytes()
    return BeautifulSoup(html,'html.parser').get_text(' ')

def general_failure_absent():
    out=[]
    for version in ('1.4','2.0','2.1','3.0'):
        t=re.sub(r'\s+',' ',spec_text(version))
        heading=r'\b(?:4\.\d+|6\.1\.\d+) Encrypt (?=This operation)'
        start=[x.start() for x in re.finditer(heading,t)][-1]
        end=re.compile(r'\b(?:4\.\d+|6\.1\.\d+) [A-Z][A-Za-z\- ]+? (?=This operation)').search(t,start+20).start()
        body=t[start:end]
        if version.startswith('1.'):
            # 1.x lists operation errors in a separate chapter (1.4 section 11.30).
            e=[x.start() for x in re.finditer(r'\b11\.\d+ Encrypt Error',t)][-1];body+=t[e:re.compile(r'\b11\.\d+ Decrypt').search(t,e).start()]
        table=re.search(r'Table \d+: Encrypt Errors?',body)
        out.append({'version':version,'section_chars':len(body),'errors_table':table.group(0) if table else None,'general_failure_listed':'General Failure' in body,'invalid_field_listed':'Invalid Field' in body})
    assert all(not o['general_failure_listed'] for o in out) and all(o['invalid_field_listed'] for o in out[1:]),out
    return {'family':'aead-tag-length-reason','shows':'General Failure, which the traces expect for Tag Length 1, is not listed for Encrypt in any edition. Invalid Field (the server reason) is listed in 2.0-3.0; the 1.4 Encrypt error table lists neither.','evidence':out}

def shared_digest_placeholder():
    """AKLC-O-1-30 binds one $DIGEST_VALUE to both keys of a pair."""
    name,m=trace('3.0','AKLC-O-1-30');uses=[]
    for i,msg in enumerate(m):
        if msg.tag!='ResponseMessage':continue
        uid=msg.find('.//ResponsePayload/UniqueIdentifier');digest=msg.find('.//DigestValue')
        if digest is not None and digest.get('value','').startswith('$'):uses.append({'message':i,'object':uid.get('value') if uid is not None else None,'placeholder':digest.get('value')})
    objects={u['object'] for u in uses};placeholders={u['placeholder'] for u in uses}
    assert len(objects)==2 and placeholders=={'$DIGEST_VALUE'},uses
    return {'family':'shared-digest-placeholder-3.0','shows':'One placeholder names the SHA-256 digests of both the private and the public key, which are different objects with different key material; the trace itself uses distinct placeholders for their Short Unique Identifiers.','evidence':{'trace':f'3.0|{name}','uses':uses}}

PROOFS=[shared_digest_placeholder,aes_ecb_13,pss_sample,random_iv_literal,omos_version,chacha_truncated,general_failure_absent]
def main():
    a=argparse.ArgumentParser(description=__doc__.splitlines()[0]);a.add_argument('--output',type=pathlib.Path,default=ROOT/'docs/specs/oasis-corpus-proofs.json');args=a.parse_args()
    results=[p() for p in PROOFS]
    args.output.write_text(json.dumps({'schema':1,'scope':'Server-independent proofs over the pinned profile archives; published vectors unchanged.','tool':'pyca/cryptography','proofs':results},indent=1)+'\n')
    for r in results:print('PROVEN',r['family'],'-',r['shows'][:110])
if __name__=='__main__' and '--write-fixtures' not in sys.argv:main()

# ---- separately labelled corrected fixtures (applied only with --corrected-fixtures) ----
FIXTURES=ROOT/'docs/specs/oasis-corrected-fixtures.json'
def fixture_edits(existing):
    """Edits that repair only proven corpus defects. Each names the value it replaces."""
    edits=[]
    def edit(version,case,index,path,new,family,why):
        name,m=trace(version,case);e=m[index].find(path)
        if e is None:raise SystemExit(f'{version} {case} message {index}: no {path}')
        edits.append({'case':f'{version}|{name}','message':index,'path':path,'from':e.get('value'),'to':new,'family':family,'why':why})
    name,m=trace('1.3','CS-BC-M-6-13')
    i=[i for i,t,b in items(m,'Encrypt') if t=='ResponseMessage'][0]
    key=hx(items(m,'Register')[0][2],'.//KeyMaterial');data=hx([b for j,t,b in items(m,'Encrypt') if t=='RequestMessage'][0],'RequestPayload/Data')
    e=Cipher(algorithms.AES(key),modes.ECB()).encryptor()
    correct=(e.update(data)+e.finalize()).hex();wrong=m[i].find('BatchItem/ResponsePayload/Data').get('value')
    edit('1.3','CS-BC-M-6-13',i,'BatchItem/ResponsePayload/Data',correct,'aes-ecb-sample-1.3','independently computed AES-128-ECB; equals the 1.4 sample')
    for j,t,b in items(m,'Decrypt'):
        if t=='RequestMessage' and b.find('RequestPayload/Data').get('value')==wrong:
            edit('1.3','CS-BC-M-6-13',j,'BatchItem/RequestPayload/Data',correct,'aes-ecb-sample-1.3','the Decrypt input echoes the corrected ciphertext')
    for version,case in (('1.3','CS-BC-M-13-13'),('1.4','CS-BC-M-13-14'),('2.0','CS-BC-M-13-20')):
        name,m=trace(version,case)
        i=[i for i,t,b in items(m,'Encrypt') if t=='ResponseMessage'][0]
        edit(version,case,i,'BatchItem/ResponsePayload/Data','$DATA_0','random-iv-literal-sample','bind the Random IV ciphertext as the 2.1 trace does')
        if m[i].find('BatchItem/ResponsePayload/IVCounterNonce') is not None:
            edit(version,case,i,'BatchItem/ResponsePayload/IVCounterNonce','$IV_COUNTER_NONCE','random-iv-literal-sample','bind the server-generated IV as the 2.1 trace does')
    name,m=trace('3.0','AKLC-O-1-30')
    for i,msg in enumerate(m):
        uid=msg.find('.//ResponsePayload/UniqueIdentifier')
        if msg.tag=='ResponseMessage' and uid is not None and uid.get('value')=='$UNIQUE_IDENTIFIER_1' and msg.find('.//DigestValue') is not None:
            edit('3.0','AKLC-O-1-30',i,'BatchItem/ResponsePayload/Attributes/Digest/DigestValue','$DIGEST_VALUE_1','shared-digest-placeholder-3.0','give the public key digest its own placeholder')
    name,m=trace('1.4','OMOS-O-1-14')
    i=[j for j,msg in enumerate(m) if msg.tag=='ResponseMessage' and msg.find('ResponseHeader/ProtocolVersion/ProtocolVersionMinor').get('value')=='3'][0]
    edit('1.4','OMOS-O-1-14',i,'ResponseHeader/ProtocolVersion/ProtocolVersionMinor','4','omos-response-version-1.4','the response to a 1.4 request in a 1.4 trace')
    # PSS: re-sign the Valid exchange under the 1.4+ defaults (MGF1-SHA-1, salt =
    # SHA-1 block size 64) with the sibling trace's private key. PSS is
    # randomized, so the signature is generated once and then only re-verified.
    # 1.3 is excluded: it defines no PSS defaults (an interpretation question).
    old={(x['case'],x['message'],x['path']):x['to'] for x in existing}
    for version in ('1.4','2.0','2.1','3.0'):
        sfx=version.replace('.','');_,m1=trace(version,f'CS-AC-M-1-{sfx}');name,m=trace(version,f'CS-AC-M-2-{sfx}')
        priv=serialization.load_der_private_key(hx(items(m1,'Register')[0][2],'.//KeyMaterial'),None)
        i,_,b=[x for x in items(m,'SignatureVerify') if x[1]=='RequestMessage'][0]
        data=hx(b,'RequestPayload/Data');p=padding.PSS(padding.MGF1(hashes.SHA1()),64)
        sig=old.get((f'{version}|{name}',i,'BatchItem/RequestPayload/SignatureData'))
        if sig:priv.public_key().verify(bytes.fromhex(sig),data,p,hashes.SHA256())
        else:sig=priv.sign(data,p,hashes.SHA256()).hex()
        edit(version,f'CS-AC-M-2-{sfx}',i,'BatchItem/RequestPayload/SignatureData',sig,'pss-sample-contradicts-default-table','PSS signature under the stated defaults (MGF1-SHA-1, 64-byte salt) by the sibling CS-AC-M-1 private key; later Invalid exchanges unchanged')
    return edits

def write_fixtures():
    existing=json.loads(FIXTURES.read_text())['edits'] if FIXTURES.exists() else []
    edits=fixture_edits(existing)
    FIXTURES.write_text(json.dumps({'schema':1,'label':'corrected fixture','scope':'Local corrections of proven corpus defects (docs/specs/oasis-corpus-proofs.json). Applied only by the variation harness with --corrected-fixtures and reported separately; the published vectors and their results are unchanged. Interpretation questions get no corrected fixture.','edits':edits},indent=1)+'\n')
    print(f'{len(edits)} fixture edits')
if __name__=='__main__' and '--write-fixtures' in sys.argv:write_fixtures()
