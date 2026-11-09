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

"""Strict KMIP 1.0-1.2 TTLV and message-order checks for the legacy test-case harness.

wire.decode() is a permissive test decoder shared by the frozen profile-trace
harness and is not changed. This module validates raw bytes first, so a
length, bound, type or padding defect fails the case before that decoder sees
it, and it checks the field order of the message, header and batch-item
structures against the version-specific tables in section 7 of the pinned
1.0, 1.1 and 1.2 specifications. Payload contents are not table-checked here.
"""
from wire import decode,encode,recv_exact

class WireError(ValueError):
    """A received or published message violates the TTLV encoding rules."""

# KMIP 1.x section 9.1.1.2 Table 211 / 9.1.1.3 Table 212 (1.1 numbering).
# Types 0B-0E are KMIP 2.0+ and are not legal in a 1.x message.
FIXED_LENGTH={2:4,3:8,5:4,6:8,9:8,10:4}
LEGACY_TYPES=range(1,11)
TAG_PREFIXES=(0x42,0x54)  # section 9.1.1.1: first tag byte SHALL be 42 or 54 hex

def tag_violations(n,path=''):
    """Yield every tag whose first byte is neither 42 nor 54 (section 9.1.1.1)."""
    path+=f'/0x{n[0]:06x}'
    if n[0]>>16 not in TAG_PREFIXES:yield path
    if n[1]==1:
        for c in n[2]:yield from tag_violations(c,path)

def validate(raw,check_tags=True):
    """Validate one complete TTLV item and return it decoded.

    Normative checks (1.x section 9.1.1): every item header and value lies
    inside its parent; structure lengths are exactly the sum of their padded
    children; fixed-size types have their table length; Structure and Big
    Integer lengths are multiples of eight; Booleans are 0 or 1; Text Strings
    are UTF-8; only types 01-0A occur; tags start with 42 or 54 hex.
    Harness policy (no 1.x text states the padding value; every section 9.1.2
    example uses zero bytes): padding bytes must be zero. Finally the
    permissive wire.decode() result must re-encode to exactly the same bytes.
    """
    if not isinstance(raw,(bytes,bytearray)):raise WireError(f'expected raw message bytes, received {type(raw).__name__}')
    raw=bytes(raw)
    def item(off,end,path):
        if end-off<8:raise WireError(f'{path or "/"}: truncated item header at byte {off} ({end-off} bytes left)')
        tag=int.from_bytes(raw[off:off+3],'big');kind=raw[off+3];size=int.from_bytes(raw[off+4:off+8],'big')
        path+=f'/0x{tag:06x}'
        if check_tags and tag>>16 not in TAG_PREFIXES:raise WireError(f'{path}: tag outside the 42xxxx/54xxxx ranges (section 9.1.1.1)')
        if kind not in LEGACY_TYPES:raise WireError(f'{path}: item type 0x{kind:02x} is not a KMIP 1.x type')
        if kind in FIXED_LENGTH and size!=FIXED_LENGTH[kind]:raise WireError(f'{path}: length {size} for type 0x{kind:02x}, expected {FIXED_LENGTH[kind]}')
        if kind in (1,4) and size%8:raise WireError(f'{path}: length {size} is not a multiple of eight')
        padded=size+(-size)%8;start=off+8
        if start+padded>end:raise WireError(f'{path}: value of {padded} padded bytes overruns its parent by {start+padded-end} bytes')
        value=raw[start:start+size]
        if any(raw[start+size:start+padded]):raise WireError(f'{path}: nonzero padding bytes (harness policy: padding must be zero)')
        if kind==6 and int.from_bytes(value,'big') not in (0,1):raise WireError(f'{path}: Boolean value is neither 0 nor 1')
        if kind==7:
            try:value.decode('utf-8')
            except UnicodeDecodeError as e:raise WireError(f'{path}: Text String is not UTF-8 ({e.reason})') from None
        if kind==1:
            i=start
            while i<start+size:i=item(i,start+size,path)
        return start+padded
    end=item(0,len(raw),'')
    if end!=len(raw):raise WireError(f'{len(raw)-end} trailing bytes after the message')
    n=decode(raw)
    if encode(n)!=raw:raise WireError('message does not re-encode to identical bytes')
    return n

def receive(sock,limit=1<<20):
    """Read one response message without trusting its length beyond the limit."""
    head=recv_exact(sock,8);size=int.from_bytes(head[4:8],'big')
    if head[3]!=1:raise WireError(f'response item type 0x{head[3]:02x} is not a Structure')
    if size>limit:raise WireError(f'response length {size} exceeds the {limit}-byte harness limit')
    if size%8:raise WireError(f'response length {size} is not a multiple of eight')
    return head+recv_exact(sock,size)

def exchange_raw(sock,request,limit=1<<20):
    sock.sendall(encode(request));return receive(sock,limit)

# Section 7 tables. Each entry is (tag, repeatable). Request and response
# message structures are identical in 1.0, 1.1 and 1.2; the 1.2 headers add
# the attestation and nonce fields. Protocol Version is section 6.1.
T={'ProtocolVersion':0x420069,'ProtocolVersionMajor':0x42006a,'ProtocolVersionMinor':0x42006b,'MaximumResponseSize':0x420050,
   'AsynchronousIndicator':0x420007,'AttestationCapableIndicator':0x4200d3,'AttestationType':0x4200c7,'Authentication':0x42000c,
   'BatchErrorContinuationOption':0x42000e,'BatchOrderOption':0x420010,'TimeStamp':0x420092,'Nonce':0x4200c8,'BatchCount':0x42000d,
   'Operation':0x42005c,'UniqueBatchItemID':0x420093,'RequestPayload':0x420079,'ResponsePayload':0x42007c,'MessageExtension':0x420051,
   'ResultStatus':0x42007f,'ResultReason':0x42007e,'ResultMessage':0x42007d,'AsynchronousCorrelationValue':0x420006,
   'RequestHeader':0x420077,'ResponseHeader':0x42007a,'BatchItem':0x42000f,'RequestMessage':0x420078,'ResponseMessage':0x42007b}
def table(*fields):return [(T[f.rstrip('*')],f.endswith('*')) for f in fields]
REQUIRED={'RequestHeader':['ProtocolVersion','BatchCount'],'ResponseHeader':['ProtocolVersion','TimeStamp','BatchCount'],
          'RequestBatchItem':['Operation','RequestPayload'],'ResponseBatchItem':['ResultStatus'],
          'ProtocolVersion':['ProtocolVersionMajor','ProtocolVersionMinor']}
TABLES={}
for version,numbers in {'1.0':(185,186,187,188,189,190),'1.1':(205,206,207,208,209,210),'1.2':(243,244,245,246,247,248)}.items():
    legacy_request_header=['ProtocolVersion','MaximumResponseSize','AsynchronousIndicator']+(['AttestationCapableIndicator','AttestationType*'] if version=='1.2' else [])+['Authentication','BatchErrorContinuationOption','BatchOrderOption','TimeStamp','BatchCount']
    response_header=['ProtocolVersion','TimeStamp']+(['Nonce','AttestationType*'] if version=='1.2' else [])+['BatchCount']
    TABLES[version]={
        'RequestMessage':(numbers[0],table('RequestHeader','BatchItem*')),
        'ResponseMessage':(numbers[1],table('ResponseHeader','BatchItem*')),
        'RequestHeader':(numbers[2],table(*legacy_request_header)),
        'RequestBatchItem':(numbers[3],table('Operation','UniqueBatchItemID','RequestPayload','MessageExtension')),
        'ResponseHeader':(numbers[4],table(*response_header)),
        'ResponseBatchItem':(numbers[5],table('Operation','UniqueBatchItemID','ResultStatus','ResultReason','ResultMessage','AsynchronousCorrelationValue','ResponsePayload','MessageExtension')),
        'ProtocolVersion':('6.1',table('ProtocolVersionMajor','ProtocolVersionMinor'))}

def check_structure(n,version,name,path):
    number,fields=TABLES[version][name];index={tag:i for i,(tag,_) in enumerate(fields)};last=-1;seen=set()
    label=f'KMIP {version} '+(f'section {number}' if isinstance(number,str) else f'Table {number}')
    if n[1]!=1:raise WireError(f'{path}: expected a Structure ({label})')
    for c in n[2]:
        position=index.get(c[0])
        if position is None:raise WireError(f'{path}: field 0x{c[0]:06x} is not permitted in {name} ({label})')
        if position<last:raise WireError(f'{path}: field 0x{c[0]:06x} is out of the order required by {label} (section 7: all fields SHALL appear in the order specified)')
        if position==last and not fields[position][1]:raise WireError(f'{path}: field 0x{c[0]:06x} repeated; {label} does not permit repetition')
        last=position;seen.add(c[0])
    missing=[f for f in REQUIRED.get(name,[]) if T[f] not in seen]
    if missing:raise WireError(f'{path}: {name} lacks required {", ".join(missing)} ({label})')

def message_version(n):
    for c in n[2]:
        if c[0] in (T['RequestHeader'],T['ResponseHeader']) and c[1]==1:
            for p in c[2]:
                if p[0]==T['ProtocolVersion'] and p[1]==1:
                    parts={q[0]:q[2] for q in p[2]}
                    if T['ProtocolVersionMajor'] in parts and T['ProtocolVersionMinor'] in parts:return f'{parts[T["ProtocolVersionMajor"]]}.{parts[T["ProtocolVersionMinor"]]}'
    return None

def check_message(n,version=None):
    """Check message, header, batch-item and protocol-version field order and presence."""
    role={T['RequestMessage']:'Request',T['ResponseMessage']:'Response'}.get(n[0])
    if role is None:raise WireError(f'/0x{n[0]:06x}: not a Request or Response Message')
    version=version or message_version(n)
    if version not in TABLES:raise WireError(f'message protocol version {version} has no legacy section 7 table here')
    check_structure(n,version,role+'Message','/'+role+'Message')
    if not n[2] or n[2][0][0]!=T[role+'Header']:raise WireError(f'/{role}Message: the {role} Header must come first')
    if len(n[2])<2:raise WireError(f'/{role}Message: no Batch Item')
    header=n[2][0];check_structure(header,version,role+'Header',f'/{role}Message/{role}Header')
    for c in header[2]:
        if c[0]==T['ProtocolVersion']:check_structure(c,version,'ProtocolVersion',f'/{role}Message/{role}Header/ProtocolVersion')
    for i,item in enumerate(n[2][1:]):check_structure(item,version,role+'BatchItem',f'/{role}Message/BatchItem[{i}]')
    return version
