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

"""Independent KMIP JSON/XML message codec for the HTTPS trace replay.

Written from the KMIP Profiles text (1.3/1.4 sections 5.4.1 and 5.5.1, 2.0/2.1
sections 5.4.1 and 5.5.1, 3.0 CSD02 the same sections), not from the server's
Rust encoder. Names come from the harness registry (docs/specs/registry.json),
which is generated separately from the server's wire registry.

Nodes use the scripts/wire.py form (tag, type, value) with the same Python
value types that wire.decode produces, so the variation comparator sees no
difference between a TTLV response and a JSON/XML response.

The decoder is deliberately strict about what a producer must emit:
* hex numbers begin with 0x and carry their full fixed width (5.x.1.2);
* JSON Long Integer / Date Time Extended / Big Integer Numbers with a
  magnitude of 2^52 or more are rejected (5.5.1.6.5, 5.5.1.6.6, 5.5.1.6.13);
* Date-Time values carry a time zone (2.0+ 5.4.1.6.11/5.5.1.6.11 "SHALL always
  be time zoned"; the 1.3/1.4 text has no such sentence, but an untimezoned
  value has no defined instant, so it is rejected for every edition and the
  1.x reason is reported as harness strictness);
* types are limited to each edition's list (5.x.1.4): Date Time Extended from
  2.0, Identifier/Reference/Name Reference from 3.0;
* XML Integer, Long Integer, Interval and Date Time Extended are decimal XML
  Schema values (5.4.1.6.3/5/12/13); only mask Integers take hex/symbolic
  components (5.4.1.6.4).
It accepts every form a consumer must accept: tag names or 0x tags, generic
TTLV or named XML elements, the optional KMIP namespace, an omitted Structure
type, a null JSON Structure value, enumeration names/hex/Numbers, mask
component lists, and JSON hex or dateTime Date-Time values.
"""
import json,re,xml.parsers.expat
from oasis_conformance import TAGS,ENUMS,TYPES,normalized,enum_value,Unsupported

KMIP_NS='urn:oasis:tc:kmip:xmlns'
TYPE_NAMES={v:k for k,v in TYPES.items()}
TAG_NAMES={}
for _name,_value in TAGS.items():TAG_NAMES.setdefault(_value,_name)
MASKS={'CryptographicUsageMask','StorageStatusMask'}
SAFE=1<<52

class CodecError(ValueError):
    """The text violates the profile encoding rules."""

def edition_types(version):
    """Profiles 5.4.1.4/5.5.1.4 type lists for one edition."""
    major=int(version.split('.')[0])
    names=['Structure','Integer','LongInteger','BigInteger','Enumeration','Boolean','TextString','ByteString','DateTime','Interval']
    if major>=2:names.append('DateTimeExtended')
    if major>=3:names+=['Identifier','Reference','NameReference']
    return {n:TYPES[n] for n in names}

# ---------- dates (proleptic Gregorian, no year zero in XML Schema 1.0) ----------
def _days_from_civil(y,m,d):
    y-=m<=2;era=(y if y>=0 else y-399)//400;yoe=y-era*400
    doy=(153*(m+(-3 if m>2 else 9))+2)//5+d-1;doe=yoe*365+yoe//4-yoe//100+doy
    return era*146097+doe-719468
def _civil_from_days(z):
    z+=719468;era=(z if z>=0 else z-146096)//146097;doe=z-era*146097
    yoe=(doe-doe//1460+doe//36524-doe//146096)//365;y=yoe+era*400;doy=doe-(365*yoe+yoe//4-yoe//100)
    mp=(5*doy+2)//153;d=doy-(153*mp+2)//5+1;m=mp+(3 if mp<10 else -9)
    return y+(m<=2),m,d
DATE=re.compile(r'(-?)(\d{4,})-(\d\d)-(\d\d)T(\d\d):(\d\d):(\d\d)(\.\d+)?(Z|[+-]\d\d:\d\d)?')
def parse_datetime(s,version):
    m=DATE.fullmatch(s)
    if not m:raise CodecError(f'invalid dateTime {s!r}')
    neg,year,mo,d,h,mi,sec,_fraction,tz=m.groups()
    if len(year)>4 and year[0]=='0':raise CodecError(f'invalid dateTime year {s!r}')
    year=int(year);mo,d,h,mi,sec=map(int,(mo,d,h,mi,sec))
    if year==0:raise CodecError('year 0000 is not an XML Schema 1.0 year')
    if tz is None:
        why='2.0+ section 5.x.1.6.11 requires a time zone' if not version.startswith('1.') else 'no time zone; instant undefined (1.x text has no rule; harness strictness)'
        raise CodecError(f'dateTime {s!r}: {why}')
    # XML Schema 1.0: BCE year -0001 is astronomical year 0.
    y=-year+1 if neg else year
    leap=y%4==0 and (y%100!=0 or y%400==0)
    days=[31,29 if leap else 28,31,30,31,30,31,31,30,31,30,31]
    if not 1<=mo<=12 or not 1<=d<=days[mo-1] or not (h<24 or (h==24 and mi==0 and sec==0)) or mi>59 or sec>59:raise CodecError(f'invalid dateTime field {s!r}')
    offset=0
    if tz!='Z':
        oh,om=int(tz[1:3]),int(tz[4:6])
        if oh>14 or om>59 or (oh==14 and om):raise CodecError(f'invalid time zone {s!r}')
        offset=(oh*60+om)*60*(1 if tz[0]=='+' else -1)
    # Fractional seconds are truncated (5.5.1.6.11).
    return _days_from_civil(y,mo,d)*86400+h*3600+mi*60+sec-offset
def format_datetime(t):
    days,rem=divmod(t,86400);y,m,d=_civil_from_days(days)
    year=f'{y:04d}' if y>0 else f'-{1-y:04d}'
    return f'{year}-{m:02d}-{d:02d}T{rem//3600:02d}:{rem//60%60:02d}:{rem%60:02d}+00:00'

# ---------- scalar helpers ----------
def _hex(s,digits,what):
    if not isinstance(s,str) or not re.fullmatch(r'0x[0-9a-fA-F]+',s):raise CodecError(f'{what}: expected 0x hex, got {s!r}')
    if len(s)-2!=digits:raise CodecError(f'{what}: hex {s!r} must have exactly {digits} digits (5.x.1.2 fixed width)')
    return int(s,16)
def _signed(v,bits):return v-(1<<bits) if v>=1<<(bits-1) else v
def _range(v,lo,hi,what):
    if not lo<=v<=hi:raise CodecError(f'{what}: {v} out of range')
    return v
def _hexbinary(s,what):
    if not isinstance(s,str) or not re.fullmatch(r'(?:[0-9a-fA-F]{2})*',s):raise CodecError(f'{what}: invalid hex binary {s!r}')
    return bytes.fromhex(s)
def _bigint_bytes(raw,what):
    if not raw or len(raw)%8:raise CodecError(f'{what}: Big Integer must be sign extended to a positive multiple of 8 bytes (5.x.1.2)')
    return raw
def _enum_field(name,attribute):
    return attribute if name=='AttributeValue' and attribute else name
def _enum_from_name(field,s,what):
    try:return enum_value(field,s)
    except Unsupported:raise CodecError(f'{what}: unknown enumeration name {s!r} for {field}')
def _mask(field,parts,what):
    choices=ENUMS.get(normalized(field),{});mask=0
    if not parts:raise CodecError(f'{what}: empty mask')
    for p in parts:
        if p.startswith('0x'):mask|=_hex(p,8,what)
        elif normalized(p)==p and p in choices:mask|=choices[p]
        else:raise CodecError(f'{what}: unknown mask component {p!r}')
    return mask

def resolve_tag(s,what):
    if not isinstance(s,str):raise CodecError(f'{what}: tag must be a string')
    if s.startswith('0x'):
        tag=_hex(s,6,what+' tag')
        if tag>>16 not in (0x42,0x54):raise CodecError(f'{what}: tag {s} outside KMIP and extension ranges')
        return tag
    tag=TAGS.get(s)
    if tag is None:raise CodecError(f'{what}: unknown tag name {s!r}')
    return tag

# ---------- JSON ----------
def decode_json(data,version):
    if not isinstance(data,(bytes,bytearray)):raise TypeError('bytes required')
    try:text=bytes(data).decode('utf-8')
    except UnicodeDecodeError as e:raise CodecError('JSON is not UTF-8: '+str(e))
    def pairs(items):
        keys=[k for k,_ in items]
        if len(set(keys))!=len(keys):raise CodecError('duplicate JSON property')
        return dict(items)
    def bad_float(s):raise CodecError(f'JSON fractional or exponent number {s}')
    def bad_constant(s):raise CodecError(f'JSON constant {s} is not allowed')
    try:root=json.loads(text,object_pairs_hook=pairs,parse_float=bad_float,parse_constant=bad_constant)
    except json.JSONDecodeError as e:raise CodecError('JSON syntax: '+str(e))
    types=edition_types(version)
    def item(o,path,attribute=None):
        if not isinstance(o,dict):raise CodecError(f'{path}: TTLV item must be a JSON object')
        extra=set(o)-{'tag','name','type','value'}
        if extra:raise CodecError(f'{path}: unknown properties {sorted(extra)}')
        if 'tag' not in o:raise CodecError(f'{path}: tag missing')
        tag=resolve_tag(o['tag'],path)
        if 'name' in o and o['tag'].startswith('0x') and o['name'] in TAGS and TAGS[o['name']]!=tag:raise CodecError(f'{path}: name {o["name"]!r} contradicts tag {o["tag"]}')
        kind_name=o.get('type','Structure')
        if kind_name not in types:raise CodecError(f'{path}: type {kind_name!r} is not defined for KMIP {version}')
        kind=types[kind_name];name=TAG_NAMES.get(tag,f'0x{tag:06x}');p=f'{path}/{name}'
        if 'value' not in o:raise CodecError(f'{p}: value missing')
        v=o['value']
        if kind==1:
            if v is None:return (tag,1,[])
            if not isinstance(v,list):raise CodecError(f'{p}: Structure value must be an array or null')
            attr=None
            if name=='Attribute':
                names=[c.get('value') for c in v if isinstance(c,dict) and c.get('tag') in ('AttributeName','0x42000a')]
                attr=normalized(names[0]) if names and isinstance(names[0],str) else None
            return (tag,1,[item(c,p,attr) for c in v])
        return (tag,kind,json_scalar(kind,v,_enum_field(name,attribute),p,version))
    return item(root,'')
def _number(v,what):
    if isinstance(v,bool) or not isinstance(v,int):raise CodecError(f'{what}: expected a JSON Number or hex string, got {v!r}')
    return v
def json_scalar(kind,v,field,p,version):
    if kind==2:
        if isinstance(v,str) and normalized(field) in MASKS and not re.fullmatch(r'0x[0-9a-fA-F]{8}',v):return _signed(_mask(field,v.split('|'),p),32)
        return _range(_number(v,p),-(1<<31),(1<<31)-1,p) if not isinstance(v,str) else _signed(_hex(v,8,p),32)
    if kind in (3,11):
        if isinstance(v,str):return _signed(_hex(v,16,p),64)
        v=_range(_number(v,p),-(1<<63),(1<<63)-1,p)
        if abs(v)>=SAFE:raise CodecError(f'{p}: JSON Number {v} has magnitude >= 2^52 and must be a hex string (5.5.1.6.5/13)')
        return v
    if kind==4:
        if isinstance(v,str):
            if not re.fullmatch(r'0x(?:[0-9a-fA-F]{16})+',v):raise CodecError(f'{p}: Big Integer hex must be 0x and a multiple of 8 bytes (5.5.1.6.6)')
            return bytes.fromhex(v[2:])
        v=_number(v,p)
        if abs(v)>=SAFE:raise CodecError(f'{p}: Big Integer Number magnitude >= 2^52 (5.5.1.6.6)')
        return v.to_bytes(8,'big',signed=True)
    if kind==5:
        if isinstance(v,str) and v.startswith('0x'):return _hex(v,8,p)
        if isinstance(v,str):return _enum_from_name(field,v,p)
        return _range(_number(v,p),0,(1<<32)-1,p)
    if kind==6:
        if v is True or v is False:return int(v)
        b=_hex(v,16,p)
        if b not in (0,1):raise CodecError(f'{p}: Boolean hex must be 0 or 1')
        return b
    if kind in (7,12,13,14):
        if not isinstance(v,str):raise CodecError(f'{p}: value must be a String')
        return v
    if kind==8:
        if isinstance(v,str) and v.startswith('0x'):raise CodecError(f'{p}: Byte String hex has no 0x prefix (5.5.1.6.10)')
        return _hexbinary(v,p)
    if kind==9:
        if isinstance(v,str) and v.startswith('0x'):return _signed(_hex(v,16,p),64)
        if not isinstance(v,str):raise CodecError(f'{p}: Date-Time must be a hex string or dateTime string')
        return parse_datetime(v,version)
    if kind==10:
        if isinstance(v,str):return _hex(v,8,p)
        return _range(_number(v,p),0,(1<<32)-1,p)
    raise CodecError(f'{p}: unsupported type {kind}')

# ---------- XML ----------
XSD_INT=re.compile(r'[+-]?\d+')
def _xsd_int(s,lo,hi,p):
    s=s.strip(' \t\n\r')
    if not XSD_INT.fullmatch(s):raise CodecError(f'{p}: expected a decimal XML Schema integer, got {s!r}')
    return _range(int(s),lo,hi,p)
def xml_scalar(kind,v,field,p,version,extra_masks=()):
    if kind==2:
        if (normalized(field) in MASKS or normalized(field) in extra_masks) and not XSD_INT.fullmatch(v.strip()):return _signed(_mask(field,v.split(),p),32)
        return _xsd_int(v,-(1<<31),(1<<31)-1,p)
    if kind in (3,11):return _xsd_int(v,-(1<<63),(1<<63)-1,p)
    if kind==4:return _bigint_bytes(_hexbinary(v,p),p)
    if kind==5:
        if v.startswith('0x'):return _hex(v,8,p)
        return _enum_from_name(field,v,p)
    if kind==6:
        if v not in ('true','false','1','0'):raise CodecError(f'{p}: xsd:boolean expected, got {v!r}')
        return int(v in ('true','1'))
    if kind in (7,12,13,14):return v
    if kind==8:return _hexbinary(v,p)
    if kind==9:return parse_datetime(v,version)
    if kind==10:return _xsd_int(v,0,(1<<32)-1,p)
    raise CodecError(f'{p}: unsupported type {kind}')
def decode_xml(data,version,extra_masks=()):
    """Decode a KMIP XML message. extra_masks names further Integer fields read like the two
    masks of Profiles 5.4.1.6.4 (for example a server that also writes Protection Storage Mask
    by name); the default is the Profiles list only."""
    if not isinstance(data,(bytes,bytearray)):raise TypeError('bytes required')
    types=edition_types(version)
    stack=[];root=[]
    parser=xml.parsers.expat.ParserCreate(namespace_separator=' ')
    def no_dtd(*a):raise CodecError('DTD is not permitted in a KMIP XML message')
    parser.StartDoctypeDeclHandler=no_dtd
    parser.EntityDeclHandler=no_dtd
    def start(name,attrs):
        if ' ' in name:
            ns,name=name.split(' ',1)
            if ns!=KMIP_NS:raise CodecError(f'element namespace {ns!r} is not {KMIP_NS}')
        path=stack[-1]['path'] if stack else ''
        for k in attrs:
            if k not in ('tag','name','type','value'):raise CodecError(f'{path}/{name}: unsupported attribute {k!r}')
        if name=='TTLV':
            if 'tag' not in attrs:raise CodecError(f'{path}/TTLV: tag attribute missing')
            tag=resolve_tag(attrs['tag'],path)
            if 'name' in attrs and attrs['name'] in TAGS and TAGS[attrs['name']]!=tag:raise CodecError(f'{path}: name {attrs["name"]!r} contradicts tag {attrs["tag"]}')
        else:
            if 'tag' in attrs:raise CodecError(f'{path}/{name}: named element with a tag attribute')
            tag=resolve_tag(name,path)
        kind_name=attrs.get('type','Structure')
        if kind_name not in types:raise CodecError(f'{path}/{name}: type {kind_name!r} is not defined for KMIP {version}')
        kind=types[kind_name];tname=TAG_NAMES.get(tag,f'0x{tag:06x}')
        if stack and stack[-1]['kind']!=1:raise CodecError(f'{path}: primitive item has child elements')
        if kind==1 and 'value' in attrs:raise CodecError(f'{path}/{tname}: Structure with a value attribute')
        if kind!=1 and 'value' not in attrs:raise CodecError(f'{path}/{tname}: value attribute missing')
        frame={'tag':tag,'kind':kind,'name':tname,'value':attrs.get('value'),'children':[],'path':f'{path}/{tname}'}
        (stack[-1]['children'] if stack else root).append(frame);stack.append(frame)
    def end(name):stack.pop()
    def chars(s):
        if s.strip(' \t\n\r'):raise CodecError('XML element text is not permitted; TTLV values use the value attribute')
    parser.StartElementHandler=start;parser.EndElementHandler=end;parser.CharacterDataHandler=chars
    try:parser.Parse(bytes(data),True)
    except xml.parsers.expat.ExpatError as e:raise CodecError('XML syntax: '+str(e))
    if len(root)!=1:raise CodecError('XML message must have one root element')
    def convert(f,attribute=None):
        if f['kind']==1:
            attr=None
            if f['name']=='Attribute':
                names=[c['value'] for c in f['children'] if c['name']=='AttributeName' and c['kind']==7]
                attr=normalized(names[0]) if names else None
            return (f['tag'],1,[convert(c,attr) for c in f['children']])
        return (f['tag'],f['kind'],xml_scalar(f['kind'],f['value'],_enum_field(f['name'],attribute),f['path'],version,extra_masks))
    return convert(root[0])

# ---------- encoders (requests) ----------
def _trace_literal(e):
    """Symbolic enum/mask spelling from the trace element, if it gave one."""
    if e is None:return None
    v=e.get('value','')
    if not v or v.startswith('$') or v.startswith('0x') or re.fullmatch(r'-?\d+',v):return None
    return v
def encode_json(n,form,trace=None):
    """form='normative': tag names, trace enum/mask names, fixed-width hex
    Integers, omitted Structure type, ISO dateTime (the Profiles 5.5.4 normative
    wire example style). form='numeric': 0x tags, explicit types, JSON Numbers
    for Integer/Enumeration/Interval and small Long Integers, hex Date-Time and
    hex Booleans."""
    def item(n,e):
        tag,kind,v=n
        if form=='normative':
            name=e.tag if e is not None else TAG_NAMES.get(tag)
            o={'tag':name or f'0x{tag:06x}'}
            if kind!=1:o['type']=TYPE_NAMES[kind]
        else:o={'tag':f'0x{tag:06x}','type':TYPE_NAMES[kind]}
        if kind==1:
            sub=list(e) if e is not None else [None]*len(v)
            o['value']=[item(c,s) for c,s in zip(v,sub)]
            return o
        lit=_trace_literal(e) if form=='normative' else None
        if kind==2:o['value']=('|'.join(lit.split()) if lit and normalized(TAG_NAMES.get(tag,'')) in MASKS else f'0x{v&0xffffffff:08x}') if form=='normative' else v
        elif kind in (3,11):o['value']=v if form=='numeric' and abs(v)<SAFE else f'0x{v&0xffffffffffffffff:016x}'
        elif kind==4:o['value']='0x'+v.hex()
        elif kind==5:o['value']=lit if lit else (f'0x{v:08x}' if form=='normative' else v)
        elif kind==6:o['value']=bool(v) if form=='normative' else f'0x{v:016x}'
        elif kind in (7,12,13,14):o['value']=v
        elif kind==8:o['value']=v.hex()
        elif kind==9:o['value']=format_datetime(v) if form=='normative' else f'0x{v&0xffffffffffffffff:016x}'
        elif kind==10:o['value']=f'0x{v:08x}' if form=='normative' else v
        return o
    return json.dumps(item(n,trace),ensure_ascii=False,separators=(',',':')).encode()
def _attr(s):
    return s.replace('&','&amp;').replace('<','&lt;').replace('"','&quot;').replace('>','&gt;').replace('\t','&#9;').replace('\n','&#10;').replace('\r','&#13;')
def encode_xml_text(n,form,trace=None):
    """form='normative': named elements without a namespace, trace enum/mask
    names, decimal integers (the trace files' own style). form='numeric':
    XML declaration, generic TTLV elements with 0x tags in the KMIP namespace
    and hex enumerations."""
    out=[]
    if form=='numeric':out.append('<?xml version="1.0" encoding="UTF-8"?>')
    def item(n,e,root=False):
        tag,kind,v=n
        if form=='normative':
            name=(e.tag if e is not None else TAG_NAMES.get(tag)) or None
            head=f'<{name}' if name else f'<TTLV tag="0x{tag:06x}"'
            close=f'</{name}>' if name else '</TTLV>'
            if kind!=1:head+=f' type="{TYPE_NAMES[kind]}"'
        else:
            head=f'<TTLV tag="0x{tag:06x}" type="{TYPE_NAMES[kind]}"'+(f' xmlns="{KMIP_NS}"' if root else '');close='</TTLV>'
        if kind==1:
            out.append(head+'>');sub=list(e) if e is not None else [None]*len(v)
            for c,s in zip(v,sub):item(c,s)
            out.append(close);return
        lit=_trace_literal(e) if form=='normative' else None
        if kind==2:value=lit if lit and normalized(TAG_NAMES.get(tag,'')) in MASKS else str(v)
        elif kind in (3,10,11):value=str(v)
        elif kind==4:value=v.hex()
        elif kind==5:value=lit if lit else f'0x{v:08x}'
        elif kind==6:value='true' if v else 'false'
        elif kind in (7,12,13,14):value=v
        elif kind==8:value=v.hex()
        elif kind==9:value=format_datetime(v)
        out.append(f'{head} value="{_attr(value)}"/>')
    item(n,trace,True)
    return ''.join(out).encode()
