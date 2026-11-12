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

"""Inventory and replay the official KMIP 1.1/1.2 Test Cases Committee Notes.

These documents are separate from the profile ZIPs replayed by oasis_conformance.py.
Their messages are extracted from the pinned OASIS HTML at run time; the raw
documents stay in .cache and only identifiers, digests and harness rules are
committed. Results go to a separate legacy report and never change the strict
profile-trace report. Executing selected cases does not complete any profile.
"""
import argparse,copy,datetime,hashlib,html,io,json,os,pathlib,re,sys,tempfile,time,traceback,urllib.request,xml.etree.ElementTree as ET,zipfile
from wire import encode
from oasis_conformance import REG,TAGS,TYPES,Unsupported,compare,encode_xml,enum_value,preflight,normalized
import legacy_wire as W
ROOT=pathlib.Path(__file__).resolve().parents[1];CACHE=ROOT/'.cache/specs/legacy'
MANIFEST=ROOT/'docs/specs/legacy-testcases.json';LEDGER=ROOT/'docs/specs/legacy-inventory.json'
# The first legacy run (10 passed, 1 failed, 144 not executed) is historical
# evidence. Its raw report must never be overwritten as though it held new
# results.
HISTORICAL_REPORT_SHA256='b03fd622d6a0e2f2d4912b1e6251d7458fe23e085d94a96ab0bdf9311d40d9d4'
DEFAULT_OUTPUT=ROOT/'artifacts/oasis-legacy-strict.json'
TYPE_NAMES={v:k for k,v in TYPES.items()}
TAG_NAMES={}
for name,value in REG['tags'].items():TAG_NAMES.setdefault(value,name)
ID_FIELDS=['UniqueIdentifier','PrivateKeyUniqueIdentifier','PublicKeyUniqueIdentifier']
# Operations that implicitly set a new object's Unique Identifier ("When
# implicitly set", Unique Identifier attribute, section 3.1 of KMIP 1.0-1.2).
CREATING={'create','createkeypair','register','derivekey','certify','recertify','rekey','rekeykeypair'}

def cached(url,filename,sha256):
    CACHE.mkdir(parents=True,exist_ok=True);path=CACHE/filename
    raw=path.read_bytes() if path.exists() else urllib.request.urlopen(url,timeout=60).read()
    if hashlib.sha256(raw).hexdigest()!=sha256:raise RuntimeError(f'{filename}: checksum changed')
    path.write_bytes(raw);return raw
def fetch(item):
    """Return the pinned HTML member, verifying the ZIP and (when published) its OASIS manifest digests."""
    raw=cached(item['url'],item['filename'],item['sha256'])
    published=item.get('oasis_manifest')
    if published:
        listing=cached(published['url'],published['filename'],published['sha256']).decode()
        for digest,actual in [(published['zip_md5'],hashlib.md5(raw).hexdigest()),(published['zip_sha1'],hashlib.sha1(raw).hexdigest())]:
            if digest!=actual or not re.search(rf'^{digest}\s+{re.escape(item["filename"])}\s*$',listing,re.M):
                raise RuntimeError(f'{item["filename"]}: ZIP does not match the OASIS manifest digests')
    with zipfile.ZipFile(io.BytesIO(raw)) as z:
        info=z.getinfo(item['member']);member=z.read(info)
    if hashlib.sha256(member).hexdigest()!=item['member_sha256']:raise RuntimeError(f'{item["member"]}: member checksum changed')
    return member.decode(item['encoding'])

BLOCK=re.compile(r'<h([1-6])[^>]*>(.*?)</h\1>|<p class=([A-Za-z0-9]+)[^>]*>(.*?)</p>',re.S|re.I)
def text(fragment):
    # HTML whitespace (including Word's source line wrapping) is a single
    # space; non-breaking spaces are document content and are kept as spaces.
    value=re.sub(r'<[^>]+>','',fragment);value=re.sub(r'[ \t\r\n]+',' ',value)
    return html.unescape(value).replace('\xa0',' ').strip()
def blocks(document):
    for m in BLOCK.finditer(document):
        if m.group(1):yield 'h'+m.group(1),text(m.group(2))
        else:yield m.group(3),text(m.group(4))

def ttlv(raw):
    """Decode one official hex message, rejecting any length, bound, type, padding or trailing-byte defect.

    Tag-range violations are not raised here; parse_v11() records them as
    document defects so that the source fault is named rather than hidden.
    """
    if len(raw)<8:raise W.WireError('truncated TTLV')
    size=8+int.from_bytes(raw[4:8],'big')
    if raw[3]!=1 or size!=len(raw):raise W.WireError(f'TTLV length {size} does not match {len(raw)} bytes')
    return W.validate(raw,check_tags=False)
def tags(n):
    yield n[0]
    if n[1]==1:
        for c in n[2]:yield from tags(c)
# The shared registry merges tables whose names normalize alike, so several
# values carry more than one name (for example Encoding Option 1 is both
# "NoEncoding" and "Client"). Display the first registered name, which is the
# KMIP 1.x name in every legacy case; the values compared are unaffected.
ENUM_NAMES={}
for field,choices in REG['enums'].items():
    for k,v in choices.items():ENUM_NAMES.setdefault(field,{}).setdefault(v,k)
def enum_name(field,value):
    """Registry name for an enumeration, only when it round-trips through enum_value()."""
    alias={'BatchErrorContinuationOption':'BatchErrorContinuation','MaskGeneratorHashingAlgorithm':'HashingAlgorithm'}.get(field,field)
    name=ENUM_NAMES.get(normalized(alias),{}).get(value)
    try:
        if name and enum_value(field,name)==value:return name
    except Unsupported:pass
    return f'0x{value:08x}'
def to_xml(n,context=None):
    """Render decoded TTLV with the profile-trace XML conventions used by compare()."""
    name=TAG_NAMES.get(n[0])
    if name is None:raise Unsupported(f'unregistered tag 0x{n[0]:06x}','harness_limitation')
    e=ET.Element(name)
    kind=n[1];value=n[2]
    if kind!=1:e.set('type',TYPE_NAMES[kind])
    if kind==1:
        label=[c[2] for c in value if c[0]==TAGS['AttributeName']] if name=='Attribute' else []
        # A list: before Python 3.13, Element.extend takes only a sequence.
        e.extend([to_xml(c,normalized(label[0]) if label else None) for c in value])
    elif kind==5:e.set('value',enum_name(context if name=='AttributeValue' and context else name,value))
    elif kind in (4,8):e.set('value',value.hex())
    elif kind==6:e.set('value','true' if value else 'false')
    elif kind==9:e.set('value',time.strftime('%Y-%m-%dT%H:%M:%S+00:00',time.gmtime(value)))
    else:e.set('value',str(value))
    return e

LISTED_TAG=re.compile(r'Tag: [^()]*\((0x[0-9A-Fa-f]{6})\)')
def parse_v11(document):
    """KMIP Test Cases 1.1 CN01: numbered tables with a listing then hex TTLV per message."""
    cases=[];case=None;listing=[];step=None;pending=b''
    for kind,value in blocks(document):
        if kind in ('h1','h2','h3'):
            m=re.fullmatch(r'([0-9]+(?:\.[0-9]+)+)\s+Test Case: (.*)',value)
            if m:
                if pending:raise ValueError('unterminated hex message before '+value)
                case={'id':'KMIP-TC-1.1-'+m.group(1),'section':m.group(1),'title':m.group(2),'messages':[],'listing_mismatches':[],'defects':[],'prose_tags':[]};cases.append(case);step=None
            elif case is not None and re.match(r'[0-9]+\s',value):case=None
            continue
        if case is None:continue
        if kind=='TableContents':
            if re.fullmatch(r'[0-9]+',value):step=int(value);continue
            # The In:/Out: prose describes vendor tags as tag='0x......'.
            case['prose_tags']+=[t.lower() for t in re.findall(r"tag=\W?(0x[0-9A-Fa-f]{6})",value) if t.lower() not in case['prose_tags']]
        if kind not in ('KMIPCode','CodeNoLinespacing'):continue
        compact=value.replace(' ','')
        if re.fullmatch(r'(?:[0-9A-Fa-f]{2}){8,}',compact) and (pending or compact[:6].upper() in ('420078','42007B')):
            pending+=bytes.fromhex(compact)
            if 8+int.from_bytes(pending[4:8],'big')>len(pending):continue
            n=ttlv(pending);role={0x420078:'request',0x42007b:'response'}.get(n[0]);index=len(case['messages'])
            if role is None:raise ValueError(case['id']+': hex message is neither request nor response')
            listed=[int(t,16) for line in listing for t in LISTED_TAG.findall(line)]
            if listed!=list(tags(n)):case['listing_mismatches'].append(index)
            for path in W.tag_violations(n):
                tag=int(path.rsplit('/0x',1)[1],16)
                where=' in the section 9.1.3.1 (Unused) range 000000-420000' if tag<=0x420000 else ''
                prose=f'; the case prose names tag {", ".join(case["prose_tags"])}' if case['prose_tags'] else ''
                case['defects'].append(f'message {index} ({role}): tag 0x{tag:06x}{where} violates KMIP 1.1 section 9.1.1.1 (first tag byte SHALL be 42 or 54 hex), so it is neither a KMIP nor an Extensions (540000-54FFFF) tag{prose}')
            try:W.check_message(n)
            except W.WireError as e:case['defects'].append(f'message {index} ({role}): {e}')
            try:rendered=to_xml(n)
            except Unsupported as e:rendered=None;case.setdefault('blockers',[]).append(f'message {index} ({role}) not rendered: {e}')
            case['messages'].append({'role':role,'time':step,'raw':pending,'node':n,'xml':rendered,'sha256':hashlib.sha256(pending).hexdigest()});pending=b'';listing=[]
        else:listing.append(value)
    return cases

def parse_v12(document):
    """KMIP Test Cases 1.2 CN01: one numbered XML listing per case (1.0, 1.1 and 1.2 variants)."""
    cases=[];case=None
    for kind,value in blocks(document):
        if kind=='h3':
            m=re.fullmatch(r'([0-9]+\.[0-9]+\.[0-9]+) (TC-[A-Z0-9-]+) - (.*)',value)
            case={'id':m.group(2),'section':m.group(1),'title':m.group(3),'lines':[]} if m else None
            if case:cases.append(case)
            continue
        if kind.startswith('h'):case=None;continue
        if case is None or kind!='KMIPXMLCELL' or not value or re.fullmatch(r'[0-9]{4}',value):continue
        case['lines'].append(value)
    for case in cases:
        body='\n'.join('<!--'+line[1:].replace('--','- -')+'-->' if line.startswith('#') else line for line in case.pop('lines'))
        root=ET.fromstring('<Case>'+body+'</Case>',parser=ET.XMLParser(target=ET.TreeBuilder(insert_comments=True)))
        step=None;case['messages']=[];case['comments']=[];case['defects']=[]
        for e in root:
            if e.tag is ET.Comment:
                note=e.text.strip();case['comments'].append(note)
                m=re.fullmatch(r'TIME ([0-9]+)',note)
                if m:step=int(m.group(1))
                continue
            role={'RequestMessage':'request','ResponseMessage':'response'}.get(e.tag)
            if role is None:raise ValueError(case['id']+': unexpected element '+e.tag)
            case['messages'].append({'role':role,'time':step,'xml':e})
    return cases

def canonical(m):return m.get('sha256') or hashlib.sha256(ET.tostring(m['xml'],encoding='utf-8')).hexdigest()
def header_version(e):
    major=e.find('./*/ProtocolVersion/ProtocolVersionMajor');minor=e.find('./*/ProtocolVersion/ProtocolVersionMinor')
    if major is None or minor is None:return None
    return f'{int(major.get("value"),0)}.{int(minor.get("value"),0)}'
def message_version(m):
    """Published header version of one message (from the TTLV when it could not be rendered)."""
    if m['xml'] is not None:return header_version(m['xml'])
    return W.message_version(m['node']) if 'node' in m else None
def exchange_versions(case):
    """Published version per exchange: 'v' when request and response agree, else 'request/response'."""
    v=[message_version(m) for m in case['messages']]
    return [p[0] if len(set(p))==1 else '/'.join(str(x) for x in p) for p in (v[i:i+2] for i in range(0,len(v),2))]
def operations(case):
    return sorted({e.get('value') for m in case['messages'] if m['role']=='request' and m['xml'] is not None for e in m['xml'].iter('Operation')})

def document_defects(case):
    """Publication defects, recorded uniformly whether or not the case is selected."""
    defects=list(case.get('defects',[]))
    roles=[m['role'] for m in case['messages']]
    if roles!=['request','response']*(len(roles)//2):defects.append('non-alternating request/response messages')
    v=[message_version(m) for m in case['messages']]
    if len({x for x in v if x})>1:
        per=', '.join(f'{k}:{x}' for k,x in enumerate(exchange_versions(case)))
        defects.append(f'mixed_protocol_versions: published request/response versions differ across exchanges ({per}); replayed exactly as published and credited per exchange version')
    for k in range(0,len(v)-1,2):
        if v[k] and v[k+1] and v[k]!=v[k+1]:defects.append(f'exchange {k//2}: response version {v[k+1]} differs from request version {v[k]}')
    for i,m in enumerate(case['messages']):
        if m['xml'] is None or 'node' in m:continue
        # Published 1.2-note messages are checked against the same section 7 tables.
        try:W.check_message(encode_xml(m['xml'],placeholders(m['xml'])))
        except W.WireError as e:defects.append(f'message {i} ({m["role"]}): {e}')
        except Unsupported:pass
    if case.get('listing_mismatches'):defects.append('printed tag listing differs from the hex TTLV for messages '+', '.join(map(str,case['listing_mismatches'])))
    return defects

def bind_dynamic(case):
    """Return copies of a case's messages with the documented legacy dynamic-value rules applied.

    L1: the server assigns Unique Identifiers (1.1 note section 1: "Unique
    Identifiers ... in responses" change dynamically; 1.2 note section 2 uses
    symbolic identifiers for the same flow). A literal TextString identifier
    first returned by the server is bound to a stable variable and all later
    equal TextString values are replaced with it. L2: the response-header Time
    Stamp is the server's current time (KMIP 1.x spec, Time Stamp), checked as
    fresh rather than equal to the 2012 example. No other field is relaxed.
    """
    messages=[copy.deepcopy(m['xml']) for m in case['messages']];identifiers={};seen=set();rules=[]
    for m in messages:
        if m is None:continue
        for e in m.iter():
            value=e.get('value')
            if value is None or e.get('type')!='TextString':continue
            if m.tag=='ResponseMessage' and e.tag in ID_FIELDS and not value.startswith('$') and value not in seen:
                identifiers.setdefault(value,f'$LEGACY_UID_{len(identifiers)}')
            if value in identifiers:
                rules.append(('L1',e.tag,identifiers[value]));e.set('value',identifiers[value])
            elif m.tag=='RequestMessage':seen.add(value)
        stamp=m.find('./ResponseHeader/TimeStamp')
        if stamp is not None and not stamp.get('value','').startswith('$'):stamp.set('value','$NOW');rules.append(('L2','TimeStamp','$NOW'))
    return messages,rules

def placeholders(m):
    """Type-correct stand-ins for every symbol in a message, used only for offline encoding."""
    stand={1:[],2:0,3:0,4:b'',5:0,6:0,7:'x',8:b'',9:0,10:0,11:0,12:'x',13:'x',14:'x'}
    return {e.get('value'):stand.get(TYPES.get(e.get('type','Structure')),'x') for e in m.iter() if e.get('value','').startswith('$') and not e.get('value').startswith('$NOW')}

def encoding_blockers(case):
    """Encode every published request and expected response offline and name each failure exactly.

    Nothing is normalized: a published enumeration or tag spelling the
    harness registry does not define stays a blocker until a pinned primary
    source justifies an alias.
    """
    messages,_=bind_dynamic(case);found={}
    for i,(m,source) in enumerate(zip(messages,case['messages'])):
        where=f'message {i} ({source["role"]}, exchange {i//2})'
        if m is None:
            reason='; '.join(b.split(' not rendered: ',1)[1] for b in case.get('blockers',[]) if b.startswith(f'message {i} '))
            found.setdefault('not rendered: '+(reason or 'unknown'),[]).append(where);continue
        try:encode_xml(m,placeholders(m))
        except Unsupported as e:found.setdefault(str(e),[]).append(where)
    return [f'{reason} [{"; ".join(where)}]' for reason,where in found.items()]

def extension_policy(case):
    """Notes for cases whose expected result depends on an allowed Message Extension policy."""
    flags=[]
    for m in case['messages']:
        if m['role']!='request':continue
        if m['xml'] is not None:flags+=[e.get('value')=='true' for e in m['xml'].iter('CriticalityIndicator')]
        elif 'node' in m:
            def walk(n):
                if n[0]==0x420026:flags.append(bool(n[2]))
                if n[1]==1:
                    for c in n[2]:walk(c)
            walk(m['node'])
    if False in flags:
        return ['non_critical_extension_policy: the note expects the server to process the rest of the message as if the non-critical Message Extension were absent. '
                'KMIP 1.x section 6.16 makes that a MAY. The protocol-next image rejects every Message Extension with Result Reason Feature Not Supported (src/protocol.rs), '
                'which is an allowed policy that differs from the note, not a violation of a mandatory requirement']
    return []

def runs(seq):return [t for i,t in enumerate(seq) if i==0 or seq[i-1]!=t]
def shape(e,actual,path='',version=None):
    """Reject fields the server returned that the official response does not contain, and fields out of order.

    compare() checks every expected field; this adds the converse so that extra
    fields (for example an unexpected Result Reason or attribute) fail, and it
    requires the received field order to follow the official response
    (section 7 and 9.1.1.4: fields SHALL appear in the order specified;
    repeated Attribute runs stay unordered as in compare()). Only the KMIP 1.x
    rule that an omitted Attribute Index equals index 0 is applied. Extras are
    never ignored: an extra that the version's section 7 table permits as
    OPTIONAL is still a failure, labelled as a difference from the note.
    """
    path+='/'+e.tag
    if actual[1]!=1:return
    def tag_of(c):return TAGS.get(c.tag,TAGS.get(normalized(c.tag)))
    def kept(parent,children,tag_of,value_of):
        if parent!='Attribute':return children
        return [c for c in children if not (tag_of(c)==TAGS['AttributeIndex'] and value_of(c) in ('0',0))]
    want=kept(e.tag,list(e),tag_of,lambda c:c.get('value'))
    got=kept(e.tag,list(actual[2]),lambda n:n[0],lambda n:n[2])
    wanted=sorted(tag_of(c) for c in want);received=sorted(n[0] for n in got)
    if wanted!=received:
        extra=sorted({t for t in received if received.count(t)>wanted.count(t)})
        missing=sorted({t for t in wanted if wanted.count(t)>received.count(t)})
        structure={'ResponseHeader':'ResponseHeader','BatchItem':'ResponseBatchItem'}.get(e.tag)
        allowed={tag for tag,_ in W.TABLES[version][structure][1]} if structure and version in W.TABLES else None
        def label(t):
            if allowed is None:return f'0x{t:06x} (payload table legality not checked by this harness)'
            return f'0x{t:06x} ('+('permitted OPTIONAL by the section 7 table; absent from the note' if t in allowed else 'not permitted by the section 7 table')+')'
        raise AssertionError(path+' field set differs; unexpected '+(', '.join(map(label,extra)) or '(none)')+'; missing '+(', '.join(f'0x{t:06x}' for t in missing) or '(none)'))
    order=runs([tag_of(c) for c in want]);seen=runs([n[0] for n in got])
    if order!=seen:raise AssertionError(path+' field order differs from the official response; expected '+' '.join(f'0x{t:06x}' for t in order)+', received '+' '.join(f'0x{t:06x}' for t in seen))
    for tag in dict.fromkeys(n[0] for n in got if n[1]==1):
        xs=[c for c in want if tag_of(c)==tag];ys=[n for n in got if n[0]==tag]
        if tag==TAGS['Attribute']:
            # Attribute collections are unordered (as in compare()); pair by name and index.
            def key_x(c):
                index=c.find('AttributeIndex');return c.find('AttributeName').get('value'),int(index.get('value'),0) if index is not None else 0
            def key_y(n):
                index=[c for c in n[2] if c[0]==TAGS['AttributeIndex']];return [c for c in n[2] if c[0]==TAGS['AttributeName']][0][2],index[0][2] if index else 0
            ys=sorted(ys,key=lambda n:[key_x(c) for c in xs].index(key_y(n)) if key_y(n) in [key_x(c) for c in xs] else len(xs))
        for x,y in zip(xs,ys):shape(x,y,path,version)

def identifier_symbols(response):
    """Server-assigned identifier symbols in one expected response: (all, new-object)."""
    every=[];new=[]
    for item in response.findall('BatchItem'):
        op=item.find('Operation');payload=item.find('ResponsePayload')
        if payload is None:continue
        for e in payload:
            value=e.get('value','')
            if e.tag in ID_FIELDS and value.startswith('$'):
                every.append(value)
                if op is not None and normalized(op.get('value','')).lower() in CREATING:new.append(value)
    return every,new

def replay(messages,send,progress=None):
    """Run one bound case. send(request_node)->raw response bytes; returns completed exchanges.

    Each response is validated byte-for-byte (legacy_wire.validate), its
    message, header and batch-item order is checked against the section 7
    table of the published version, and it is compared strictly (compare()
    plus shape()). Distinct objects created in the case must receive nonempty,
    distinct server-assigned identifiers. The first mismatch, missing
    response or transport error fails the case and no later exchange is
    attempted, because later requests depend on earlier bindings.
    """
    if any(m is None for m in messages):raise Unsupported('case contains a message the harness cannot render','document_blocker')
    if [m.tag for m in messages]!=['RequestMessage','ResponseMessage']*(len(messages)//2) or not messages:
        raise Unsupported('case has no complete alternating request/response exchanges','document_structure')
    preflight(messages);variables={};objects={};completed=0;progress=progress if progress is not None else {}
    progress.setdefault('versions',[])
    for i in range(0,len(messages),2):
        k=i//2;expected=messages[i+1];version=header_version(expected)
        request=encode_xml(messages[i],variables)
        raw=send(request)
        if raw is None:raise AssertionError(f'exchange {k}: no response')
        try:
            response=W.validate(raw);W.check_message(response,version)
        except W.WireError as e:raise AssertionError(f'exchange {k}: malformed response: {e}') from None
        before=set(variables)
        compare(expected,response,variables);shape(expected,response,'',version)
        every,new=identifier_symbols(expected)
        for symbol in every:
            if symbol not in before and variables.get(symbol)=='':
                raise AssertionError(f'exchange {k}: server returned an empty identifier for {symbol} (Unique Identifier SHALL always have a value, KMIP 1.x section 3.1)')
        for symbol in new:
            if symbol in before or symbol in objects:continue
            clash=[s for s,v in objects.items() if v==variables[symbol]]
            if clash:raise AssertionError(f'exchange {k}: identifier {variables[symbol]!r} for new object {symbol} was already assigned to {clash[0]}; KMIP 1.x section 3.1 requires a Unique Identifier that uniquely identifies each Managed Object')
            objects[symbol]=variables[symbol]
        completed+=1;progress['completed']=completed;progress['versions'].append(version)
    return completed

def classify(case,row):
    """Return every mechanical blocker found for a case (empty when none was found).

    Every published message is encoded offline first; that is the only basis
    for saying a case has no mechanical blocker.
    """
    reasons=[]
    for defect in row.get('document_defects',[]):
        if 'section 9.1.1.1' in defect:reasons.append('document_defect: '+defect)
    reasons+=['encoding_blocker: '+b for b in encoding_blockers(case)]
    messages,_=bind_dynamic(case);ops=set(row['operations'])
    if all(m is not None for m in messages):
        try:preflight(messages)
        except Unsupported as e:reasons.append(f'{e.category}: {e}')
    header=lambda tag:any(m.find('./RequestHeader/'+tag) is not None for m in messages if m is not None and m.tag=='RequestMessage')
    if ops&{'Put','Notify'}:reasons.append('server_initiated_operation: Notify/Put are server-to-client messages; the harness has no client-side listener')
    if header('Authentication'):reasons.append('credential_fixture_required: request headers carry example Credential values that the disposable fixture does not provision')
    if ops&{'Query'}:reasons.append('server_capability_dependent: expected response enumerates the example server capabilities; no case-specific capability oracle')
    if ops&{'DiscoverVersions'}:reasons.append('server_capability_dependent: expected responses list only the example server versions; this server advertises additional versions')
    if ops&{'Poll','Cancel'}:reasons.append('asynchronous_operation_required: the case expects Pending asynchronous Locate results followed by Poll/Cancel')
    if 'Dual Client' in row['title']:reasons.append('multi_client_fixture_required: two clients sharing credentials, not yet reviewed for multi-connection replay')
    return reasons
NOT_SELECTED='not_selected: every message encodes offline and no fixture, determinism or capability blocker was found, but the case is not yet reviewed for server-policy assumptions (dates, states, defaults, policy-dependent attributes)'

def load(selection=None):
    manifest=json.loads(MANIFEST.read_text());documents={}
    for item in manifest:
        if selection and item['document'] not in selection:continue
        cases=(parse_v11 if item['format']=='hex-ttlv' else parse_v12)(fetch(item))
        documents[item['document']]=(item,cases)
    return documents

def inventory(item,cases):
    rows=[]
    for case in cases:
        roles=[m['role'] for m in case['messages']]
        row={'id':case['id'],'document':item['document'],'section':case['section'],'title':case['title'],
             'protocol_versions':sorted({v for m in case['messages'] if (v:=message_version(m))}),
             'exchange_versions':exchange_versions(case),
             'exchanges':len(roles)//2,'operations':operations(case),
             'messages':len(roles),'messages_sha256':hashlib.sha256(''.join(canonical(m) for m in case['messages']).encode()).hexdigest()}
        defects=document_defects(case)
        if defects:row['document_defects']=defects
        if case.get('listing_mismatches'):row['listing_mismatches']=case['listing_mismatches']
        notes=extension_policy(case)
        if notes:row['policy_notes']=notes
        rows.append(row)
    return rows

PINNED=['section','title','exchanges','messages','protocol_versions','exchange_versions','operations','messages_sha256','document_defects','listing_mismatches','policy_notes']
def verify(documents,ledger):
    """Fail if extracted cases, digests, defects or blockers drift from the committed ledger."""
    errors=[]
    known=set(documents)
    for row in ledger.get('cases',[]):
        if row.get('document') not in known:errors.append(f'{row.get("id", "(missing id)")}: unknown document {row.get("document")!r}')
    if set(ledger.get('documents',{}))!=known:errors.append('ledger document inventory differs from loaded pinned documents')
    for name,(item,cases) in documents.items():
        expected=ledger['documents'][name];rows=inventory(item,cases)
        if len(rows)!=expected['case_count']:errors.append(f'{name}: {len(rows)} cases extracted, ledger pins {expected["case_count"]}')
        pinned={c['id']:c for c in ledger['cases'] if c['document']==name}
        if [r['id'] for r in rows]!=[c['id'] for c in ledger['cases'] if c['document']==name]:errors.append(f'{name}: case identifiers or order differ from the ledger')
        for case,row in zip(cases,rows):
            want=pinned.get(row['id'])
            if want is None:continue
            for field in PINNED:
                if row.get(field)!=want.get(field):errors.append(f'{row["id"]}: {field} differs from the ledger')
            found=classify(case,row)
            if want.get('status')=='SELECTED':
                if found:errors.append(f'{row["id"]}: selected case has mechanical blockers {found}')
                if not want.get('rationale'):errors.append(f'{row["id"]}: selected case has no rationale')
            elif want.get('status')!='NOT EXECUTED' or want.get('blockers')!=(found or [NOT_SELECTED]):errors.append(f'{row["id"]}: blockers differ from the ledger')
    return errors

def rebuild(documents,ledger):
    """Recompute the ledger; a prior selection survives only if nothing it was reviewed against changed."""
    previous={c['id']:c for c in ledger.get('cases',[])};rows=[]
    for name,(item,cases) in documents.items():
        for case,row in zip(cases,inventory(item,cases)):
            old=previous.get(row['id']);found=classify(case,row)
            unchanged=old is not None and all(row.get(f)==old.get(f) for f in ['section','title','exchanges','messages','protocol_versions','operations','messages_sha256'])
            if old and old.get('status')=='SELECTED' and unchanged and not found:
                row.update({k:old[k] for k in ['status','rationale','triage'] if k in old})
            else:
                row.update(status='NOT EXECUTED',blockers=found or [NOT_SELECTED])
                if old and old.get('status')=='SELECTED':row['blockers'].insert(0,'reselection_required: the case changed or gained a blocker since it was selected'+('' if unchanged else ' (pinned fields or message digest differ)'))
            rows.append(row)
    return dict(ledger,documents={name:{'case_count':len(cases)} for name,(item,cases) in documents.items()},cases=rows)

SCOPE='selected official KMIP 1.1/1.2 Test Cases Committee Note exchanges over TTLV/mTLS; does not complete any legacy profile, transport or full-specification conformance'
POLICY=('strict: response bytes validated before decoding (bounds, lengths, types, tag ranges; zero padding as harness policy); '
        'message/header/batch-item order and presence checked against the version\'s section 7 tables; payload order and field set checked against the official response; '
        'distinct created objects must receive nonempty distinct identifiers; only documented legacy rules L1 (server-assigned identifiers) and L2 (response Time Stamp freshness) applied')

def write_atomic(path,document):
    path.parent.mkdir(parents=True,exist_ok=True)
    fd,tmp=tempfile.mkstemp(prefix='.'+path.name+'.',dir=path.parent)
    try:
        with os.fdopen(fd,'w') as f:f.write(json.dumps(document,indent=2)+'\n')
        os.replace(tmp,path)
    except BaseException:
        pathlib.Path(tmp).unlink(missing_ok=True);raise

def summarize(report):
    summary={s:sum(e['status']==s for e in report) for s in ['PASSED','FAILED','NOT EXECUTED']}
    # Credit is per exchange version: a 1.2 exchange inside a 1.1 case is not 1.1 evidence.
    credit={}
    for e in report:
        for v in e.get('passed_exchange_versions',[]):credit[v]=credit.get(v,0)+1
    by_version={}
    for e in report:
        if e['status']=='PASSED':
            key=e['protocol_versions'][0] if len(e.get('protocol_versions',[]))==1 else 'mixed'
            by_version[key]=by_version.get(key,0)+1
    return summary,{'passed_exchanges_by_version':dict(sorted(credit.items())),'passed_cases_by_single_version':dict(sorted(by_version.items()))}

def write(path,report,evidence,ledger,started):
    order=[c['id'] for c in ledger['cases']];report.sort(key=lambda e:order.index(e['id']))
    summary,credit=summarize(report)
    status='passed' if report and summary['PASSED']==len(report) else 'failed'
    write_atomic(path,{'status':status,'started_utc':started,'finished_utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),
        'scope':SCOPE,'comparison_policy':POLICY,
        'evidence':evidence,'summary':summary,'version_credit':credit,'cases':report})
    print(summary,credit)

def guard_output(path):
    if path.exists() and hashlib.sha256(path.read_bytes()).hexdigest()==HISTORICAL_REPORT_SHA256:
        raise SystemExit(f'{path} holds the historical legacy report; choose a new --output')

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--inventory',action='store_true',help='Rewrite the committed ledger from the pinned documents (review the diff)')
    parser.add_argument('--image',help='Packaged container image to serve')
    parser.add_argument('--engine',default='podman')
    parser.add_argument('--fixture-cli',type=pathlib.Path,help='CLI used only for fixture master-key generation, never as the server')
    parser.add_argument('--output',type=pathlib.Path,default=DEFAULT_OUTPUT)
    a=parser.parse_args();a.output=a.output.resolve()
    if a.inventory:
        documents=load();ledger=json.loads(LEDGER.read_text()) if LEDGER.exists() else {'cases':[]}
        ledger=rebuild(documents,ledger);LEDGER.write_text(json.dumps(ledger,indent=1)+'\n');print('wrote',LEDGER,len(ledger['cases']),'cases');return
    guard_output(a.output)
    started=datetime.datetime.now(datetime.timezone.utc).isoformat();report=[]
    # Replace any earlier report before anything else runs, so a stale result
    # can never be read as the outcome of this invocation.
    write_atomic(a.output,{'status':'running','started_utc':started,'scope':SCOPE,'image':a.image,'cases':[]})
    ledger=None
    try:
        documents=load();ledger=json.loads(LEDGER.read_text());errors=verify(documents,ledger)
        if errors:raise RuntimeError('ledger verification failed:\n'+'\n'.join(errors))
        selected={c['id'] for c in ledger['cases'] if c['status']=='SELECTED'}
        by_id={case['id']:(name,case) for name,(item,cases) in documents.items() for case in cases}
        for row in ledger['cases']:
            if row['id'] not in selected:report.append(entry_for(row,'NOT EXECUTED',blockers=row['blockers']))
        if not a.image:
            for row in ledger['cases']:
                if row['id'] in selected:report.append(entry_for(row,'NOT EXECUTED',blockers=['live_execution_pending: no verified image supplied']))
            write(a.output,report,None,ledger,started);return
        run_live(a,ledger,selected,by_id,report,started)
    except BaseException as e:
        # Terminal evidence for any error or cancellation; the exception still propagates.
        write_atomic(a.output,{'status':'interrupted' if isinstance(e,KeyboardInterrupt) else 'failed','started_utc':started,
            'finished_utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'scope':SCOPE,'error':f'{type(e).__name__}: {e}',
            'traceback':traceback.format_exc(limit=8),'image':a.image,'partial_cases':report})
        raise

def entry_for(row,status,**extra):
    entry={'id':row['id'],'document':row['document'],'status':status,'completed_exchanges':0,'exchanges':row['exchanges'],
           'protocol_versions':row['protocol_versions'],'exchange_versions':row['exchange_versions']}
    for field in ['document_defects','policy_notes']:
        if row.get(field):entry[field]=row[field]
    entry.update(extra);return entry

def execute(ledger,selected,by_id,report,server,directory):
    """Replay each selected case against a fresh server and database, one container at a time.

    An ordinary exception fails only its case; the server is stopped after
    every case. Cancellation (KeyboardInterrupt) is recorded on the case and
    then propagates, so main() writes the terminal report.
    """
    for row in ledger['cases']:
        if row['id'] not in selected:continue
        name,case=by_id[row['id']]
        entry=entry_for(row,'FAILED')
        server.data=pathlib.Path(directory)/'data'/re.sub('[^A-Za-z0-9.-]','_',row['id']);server.data.mkdir(parents=True,mode=0o700)
        messages,rules=bind_dynamic(case);entry['dynamic_rules']=sorted({f'{r[0]}:{r[1]}' for r in rules})
        progress={'completed':0,'versions':[]}
        try:
            server.start()
            with server.connect() as connection:
                replay(messages,lambda request:W.exchange_raw(connection,request),progress)
            entry['status']='PASSED'
        except Unsupported as e:entry.update(status='NOT EXECUTED',blockers=[f'{e.category}: {e}'])
        except Exception as e:entry.update(detail=f'{type(e).__name__}: {e}',failed_exchange=progress['completed'])
        except BaseException as e:entry.update(detail=f'interrupted: {type(e).__name__}',failed_exchange=progress['completed']);raise
        finally:
            entry['completed_exchanges']=progress['completed'];entry['passed_exchange_versions']=progress['versions']
            if entry['status']=='FAILED' and row.get('triage'):entry['triage']=row['triage']
            report.append(entry);print(entry['id'],entry['status'],entry.get('detail',''),flush=True)
            stop_preserving_exception(server,entry)

def stop_preserving_exception(server,evidence):
    pending=sys.exc_info()[1]
    try:server.stop()
    except BaseException as error:
        if pending is None:raise
        evidence['cleanup_error']=f'{type(error).__name__}: {error}'

def run_live(a,ledger,selected,by_id,report,started):
    from test_database import ContainerServer
    from image_evidence import local_image_id,packaged_evidence
    log_out=a.output.with_name(a.output.stem+'-server.log')
    log_out.unlink(missing_ok=True)  # This invocation must never cite an earlier run's log.
    evidence=packaged_evidence(local_image_id(a.engine,a.image))
    if 'archive_sha256' not in evidence:raise SystemExit('image archive could not be verified')
    if a.fixture_cli is None:raise SystemExit('--fixture-cli is required for fixture master-key generation')
    cli_sha=hashlib.sha256(a.fixture_cli.read_bytes()).hexdigest()
    evidence.update({'image':a.image,'engine':a.engine,'server':'container image only',
        'fixture_cli_sha256':cli_sha,'fixture_cli_role':'generate-master-key for disposable fixture PKI only; not a server and not runtime evidence'})
    with tempfile.TemporaryDirectory(prefix='keytend-kmip-server-legacy-') as d:
        server=ContainerServer(d,a.engine,a.image,binary=a.fixture_cli,log_path=pathlib.Path(d)/'server.log')
        try:execute(ledger,selected,by_id,report,server,d)
        finally:
            stop_preserving_exception(server,evidence)
            log=pathlib.Path(d)/'server.log'
            if log.exists():
                log_out.write_bytes(log.read_bytes())
                evidence['server_log']=str(log_out.relative_to(ROOT)) if log_out.is_relative_to(ROOT) else str(log_out)
                evidence['server_log_sha256']=hashlib.sha256(log_out.read_bytes()).hexdigest()
    write(a.output,report,evidence,ledger,started)

if __name__=='__main__':main()
