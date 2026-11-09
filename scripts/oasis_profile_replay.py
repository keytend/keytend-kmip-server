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

"""Replay the OASIS profile traces under the Profiles section 4.1 variations.

This is a separately labelled mode. It never edits the strict report written by
oasis_conformance.py, whose comparator and fingerprint stay unchanged.

What changes relative to the strict comparator, and why:
* Only the variations listed in Profiles 4.1.1/4.1.2 are accepted, each recorded
  per case. Everything else is compared exactly, and stricter than before:
  unexpected response fields, field-order violations (KMIP 2.1 section 8: "All
  fields SHALL appear in the order specified"), malformed TTLV and reuse of one
  identifier for two created objects all fail.
* Variable output (generated key material, randomized or generated-key
  cryptographic output, RNG data, generated-object digests) is never trusted
  from the sample bytes. Each value opens an obligation that must be closed by
  an independent pyca/cryptography check or by an exact in-trace round trip. A
  case whose obligations stay open is `unverified`, not passed.
* Fixtures from docs/specs/oasis-replay-inventory.json: Interop Begin/End
  omission (Profiles 2.0+ 4.1.2), per-case client operation policies for denial
  traces, and sequenced cases sharing one store.
The production server, its RNG and its policy defaults are never modified.
"""
import argparse,collections,copy,datetime,hashlib,json,pathlib,re,subprocess,tempfile,time,xml.etree.ElementTree as ET,zipfile
from test_runtime import ROOT,Server
from wire import encode,decode,children,recv_exact,node
from oasis_conformance import TAGS,TYPES,ENUMS,Unsupported,encode_xml,enum_value,fixture_constants,normalized,shown
from image_evidence import source_commit
import oasis_validate as V
INVENTORY=ROOT/'docs/specs/oasis-replay-inventory.json'
import oasis_conformance as _strict

# Registry spellings differ in case from some traces (3.0 "UsernameAndPassword"
# versus registry "UsernameandPassword"). Accept a unique case-insensitive name
# match; the numeric value sent is the registry's. Harness spelling only.
_strict_enum_value=_strict.enum_value
HARNESS_NOTES=set()
SUPPLEMENTS={k:v for k,v in json.loads(INVENTORY.read_text())['enumeration_supplements'].items() if k!='basis'}
def _enum_value(name,value):
    try:return _strict_enum_value(name,value)
    except Unsupported:
        if normalized(name) in SUPPLEMENTS and value in SUPPLEMENTS[normalized(name)]:
            HARNESS_NOTES.add(f'enumeration {name}={value} from the inventory supplement');return SUPPLEMENTS[normalized(name)][value]
        choices=ENUMS.get(normalized(name),{});key=normalized(value).lower()
        found={v for k,v in choices.items() if k.lower()==key}
        if len(found)!=1:raise
        HARNESS_NOTES.add(f'enumeration {name}={value} matched case-insensitively (harness spelling)')
        return found.pop()
_strict.enum_value=_enum_value;enum_value=_enum_value

TAG_NAMES={}
for _name,_value in TAGS.items():TAG_NAMES.setdefault(_value,_name)
ENUM_NAMES={field:{v:k for k,v in reversed(list(values.items()))} for field,values in ENUMS.items()}
def tag_of(e):return TAGS.get(e.tag,TAGS.get(normalized(e.tag)))
def name_of(tag):return TAG_NAMES.get(tag,f'{tag:06x}')
def enum_name(field,value):return ENUM_NAMES.get(normalized(field),{}).get(value)
def val(n,tag,default=None):
    found=[c for c in n[2] if c[0]==TAGS[tag]] if n and n[1]==1 else []
    return found[0][2] if found else default
def sub(n,*path):
    for p in path:
        if n is None or n[1]!=1:return None
        found=[c for c in n[2] if c[0]==TAGS[p]];n=found[0] if found else None
    return n
def xval(e,path):
    f=e.find(path) if e is not None else None
    return f.get('value') if f is not None else None

# Profiles 4.1.1 date attributes that may vary unless fixed in the request.
# The 4.1.1 list names Protect Start Date and Process Stop Date (sic); only the
# listed names are accepted, even though the attributes are Process Start Date
# and Protect Stop Date. Those two are therefore compared exactly.
DATE_ATTRS={'ActivationDate','ArchiveDate','CompromiseDate','CompromiseOccurrenceDate','DeactivationDate','DestroyDate','InitialDate','LastChangeDate','ProtectStartDate','ProcessStopDate','ValidityDate','OriginalCreationDate'}
_INV=json.loads(INVENTORY.read_text())
ATTRIBUTE_NAMES=set(_INV['attribute_rules']['names'])
MULTI_INSTANCE=set(_INV['attribute_rules']['multi_instance'])
def attribute_ok(name):return normalized(name) in ATTRIBUTE_NAMES
ATTRIBUTE_CONTAINERS={'Attributes','CommonAttributes','PrivateKeyAttributes','PublicKeyAttributes','TemplateAttribute','CommonTemplateAttribute','PrivateKeyTemplateAttribute','PublicKeyTemplateAttribute'}
QUERY_LISTS={'Operation','ObjectType','ExtensionInformation','ApplicationNamespace'}
CREATING={'Create','CreateKeyPair','Register','Rekey','RekeyKeyPair','DeriveKey','Certify','Recertify','CreateSplitKey','JoinSplitKey','Import','ReProvision','CreateGroup'}
GENERATING={'Create','CreateKeyPair','Rekey','RekeyKeyPair','DeriveKey','CreateSplitKey','JoinSplitKey'}
ID_FIELDS={'UniqueIdentifier','PrivateKeyUniqueIdentifier','PublicKeyUniqueIdentifier'}
OUTPUT_FIELDS={'Data','SignatureData','MACData','IVCounterNonce','AuthenticatedEncryptionTag'}
EXACT_CRYPTO={'Data','ValidityIndicator','MACData','SignatureData'}

class Obligation:
    def __init__(self,kind,path,value,uid=None,expected=None,exchange=None,info=None):
        self.kind=kind;self.path=path;self.value=value;self.uid=uid;self.expected=expected;self.exchange=exchange;self.info=info or {};self.closed=None;self.roundtrip=None
    def close(self,how):
        if self.closed is None:self.closed=how
    def record(self):return {'kind':self.kind,'path':self.path,'exchange':self.exchange,'closed_by':self.closed}

class Replay:
    """State for one case (or one sequenced chain of cases)."""
    def __init__(self,version,corpus_keys):
        self.version=version;self.corpus_keys=corpus_keys
        self.vars={};self.subst={};self.generated=set();self.material={};self.params={};self.pairs={}
        self.obligations=[];self.variations=set();self.created_ids={};self.request_datetimes=set();self.rng_outputs=[]
        self.material_gets=[];self.exchange_index=0;self.formats={};self.attempted=set()

    # ---------- request side ----------
    def prepare_request(self,req):
        """Substitute server-chosen values for sample literals the trace echoes back."""
        req=copy.deepcopy(req);used={}
        for position,item in enumerate(req.findall('BatchItem')):
            for e in item.iter():
                v=e.get('value','')
                if e.get('type')=='ByteString' and v.lower() in self.subst:
                    actual=self.subst[v.lower()];e.set('value',actual.hex());used.setdefault(position,[]).append(actual)
                elif e.get('type')=='ByteString' and v in self.vars:used.setdefault(position,[]).append(self.vars[v])
        for e in req.iter():
            v=e.get('value','')
            if e.get('type')=='DateTime' and not v.startswith('$'):self.request_datetimes.add(v)
        return req,used

    # ---------- comparison ----------
    def fail(self,path,msg):raise AssertionError(path+' '+msg)
    def compare_message(self,exp,act,req_xml):
        if tag_of(exp)!=act[0]:self.fail('/'+exp.tag,'tag mismatch')
        req_items=req_xml.findall('BatchItem');exp_items=exp.findall('BatchItem')
        self.exact_items=set()
        self.structure(exp,act,'/'+exp.tag,{'container':exp.tag,'req_items':req_items,'_item_counter':[0]})
        return self.exact_items

    def permitted_extra(self,container,child,ctx):
        name=name_of(child[0]);op=ctx.get('op')
        if name=='ResultMessage':return 'Result Message may be included (4.1.1)'
        if container in ATTRIBUTE_CONTAINERS and ctx.get('response_payload'):
            # Additional attributes must be real attributes (2.x tags, or a 1.x
            # Attribute naming a defined or custom attribute).
            if name=='Attribute':return self.extra_legacy_attribute(child,ctx)
            if child[1]==1 and name not in ('Name','Link','Digest','CryptographicParameters','RandomNumberGenerator','ApplicationSpecificInformation','AlternativeName','UsageLimits','RevocationReason','CryptographicDomainParameters','X509CertificateIdentifier','X509CertificateSubject','X509CertificateIssuer','CertificateIdentifier','CertificateSubject','CertificateIssuer','KeyValueLocation','ProtectionStorageMasks','ObjectGroups'):return None
            return 'additional attribute (4.1.1)' if attribute_ok(name) else None
        if container=='ResponsePayload' and op=='GetAttributes' and name=='Attribute':return self.extra_legacy_attribute(child,ctx)
        if container=='ResponsePayload' and op=='GetAttributeList' and name in ('AttributeName','AttributeReference'):return 'additional attribute name (4.1.1)'
        if container=='ResponsePayload' and op=='Query' and name in QUERY_LISTS:return f'additional Query {name} (4.1.1)'
        if container=='ResponsePayload' and op=='Locate' and name=='LocatedItems':
            # Present without Offset Items (4.1.1), but its value must still be
            # the number of matching objects.
            found=len([c for c in ctx['actual_payload'][2] if c[0]==TAGS['UniqueIdentifier']])
            rp=ctx.get('request_payload');bounded=rp is not None and (rp.find('MaximumItems') is not None or rp.find('OffsetItems') is not None)
            if not isinstance(child[2],int) or child[2]<found or (not bounded and child[2]!=found):return None
            return 'Located Items present (4.1.1)'
        if container=='ResponsePayload' and op=='DiscoverVersions' and name=='ProtocolVersion' and ctx.get('request_payload') is not None and ctx['request_payload'].find('ProtocolVersion') is None:
            return 'additional Discover Versions protocol version (4.1.1)'
        if container in ('RandomNumberGenerator','ServerInformation'):return f'{container} contents vary (4.1.1)'
        if container=='Attribute' and name=='AttributeIndex' and ctx.get('response_payload'):
            return 'Attribute Index present (1.x section 2.1.1 index 0 may be omitted)' if child[2]==0 or self.index_shift_ok(child[2],ctx) else None
        if container in ('ResponseHeader',) and name in ('ServerCorrelationValue','ClientCorrelationValue'):return 'correlation value variable (4.1.1)'
        if name=='MessageExtension' and container in ('ResponseHeader','BatchItem') and not val(child,'CriticalityIndicator',0):return 'non-critical Message Extension (4.1.1)'
        return None

    def extra_legacy_attribute(self,child,ctx):
        n=val(child,'AttributeName')
        if not isinstance(n,str) or not (attribute_ok(n) or n[:2] in ('x-','y-')):return None
        expected=[xval(e,'AttributeName') for e in ctx.get('expected_container',[]) if e.tag=='Attribute']
        if n in expected and normalized(n) not in MULTI_INSTANCE and n[:2] not in ('x-','y-'):return None
        return 'additional attribute (4.1.1)'
    def index_shift_ok(self,index,ctx):
        """An Attribute Index may differ only when additional instances exist."""
        name=ctx.get('legacy_attribute_name');payload=ctx.get('actual_payload');expected=ctx.get('expected_payload')
        if name is None or payload is None or expected is None:return False
        actual=[c for c in payload[2] if c[0]==TAGS['Attribute'] and val(c,'AttributeName')==name]
        wanted=[e for e in expected if e.tag=='Attribute' and xval(e,'AttributeName')==name]
        indices=[val(c,'AttributeIndex',0) for c in actual]
        return len(actual)>len(wanted) and len(set(indices))==len(indices) and index<len(actual)

    def group_mode(self,container,name,ctx):
        op=ctx.get('op')
        if name=='ResultMessage':return 'optional'
        if container in ATTRIBUTE_CONTAINERS and ctx.get('response_payload'):return 'subset'
        if container=='ResponsePayload' and op=='GetAttributes' and name=='Attribute':return 'subset'
        if container=='ResponsePayload' and op=='GetAttributeList' and name in ('AttributeName','AttributeReference'):return 'subset'
        if container=='ResponsePayload' and op=='Query' and name in QUERY_LISTS:return 'subset'
        if container=='ResponsePayload' and op=='DiscoverVersions' and name=='ProtocolVersion' and ctx.get('request_payload') is not None and ctx['request_payload'].find('ProtocolVersion') is None:return 'ordered-subset'
        return 'exact'

    def structure(self,exp,act,path,ctx):
        name=exp.tag
        if act[1]!=1:self.fail(path,'type mismatch')
        rng=name=='RandomNumberGenerator' or name=='AttributeValue' and ctx.get('attribute')=='RandomNumberGenerator'
        # Profiles 1.4+ 4.1.1 let the Random Number Generator value vary (1.3 lists
        # no such variation); the 1.x attribute value is the same structure.
        if (rng and self.version!='1.3') or name=='ServerInformation':
            if act[1]!=1:self.fail(path,'type mismatch')
            self.variations.add(f'{"RandomNumberGenerator" if rng else name} contents vary (4.1.1)');return
        ctx=dict(ctx);ctx['container']=name
        if name=='BatchItem':self.batch_item_context(exp,act,ctx)
        if name=='ResponsePayload':ctx['response_payload']=True;ctx['actual_payload']=act;ctx['expected_payload']=list(exp)
        ctx['expected_container']=list(exp)
        exp_children=list(exp);exp_tags=[tag_of(c) for c in exp_children]
        if None in exp_tags:raise Unsupported('unknown expected tag in '+path)
        for a in act[2]:
            if a[0] not in exp_tags:
                why=self.permitted_extra(name,a,ctx)
                if not why:self.fail(path,f'unexpected response field {name_of(a[0])}')
                self.variations.add(why)
        # Field order: groups of expected tags must appear in the expected order
        # and must not be interleaved, except in attribute collections whose
        # order is unspecified (Profiles 4.1.2, Get Attributes).
        if name not in ATTRIBUTE_CONTAINERS:
            seen=[];prev=None
            for a in act[2]:
                if a[0] in exp_tags and a[0]!=prev:
                    if a[0] in seen:self.fail(path,f'field {name_of(a[0])} interleaved with other fields')
                    seen.append(a[0]);prev=a[0]
            order=list(dict.fromkeys(exp_tags))
            present=[t for t in order if t in seen]
            if seen!=present:self.fail(path,'fields out of order: '+', '.join(name_of(t) for t in seen))
        for tag in dict.fromkeys(exp_tags):
            exp_group=[c for c in exp_children if tag_of(c)==tag];act_group=[c for c in act[2] if c[0]==tag]
            mode=self.group_mode(name,exp_group[0].tag,ctx)
            child_name=exp_group[0].tag
            if name=='Attribute' and child_name=='AttributeIndex' and not act_group and [e.get('value') for e in exp_group]==['0']:continue
            if mode=='optional':
                if len(act_group)>len(exp_group):self.fail(path,f'{len(act_group)} {child_name} fields')
                if len(act_group)<len(exp_group):self.variations.add('Result Message omitted (4.1.1)')
                for a in act_group:
                    if a[1]!=7:self.fail(path+'/ResultMessage','type mismatch')
                if any(e.get('value')!=a[2] for e,a in zip(exp_group,act_group)):self.variations.add('Result Message wording varies (4.1.1)')
                continue
            if mode=='ordered-subset':
                # Additional entries only; the preference order is kept.
                at=0
                for e in exp_group:
                    while at<len(act_group) and not self.trial(e,act_group[at],path,ctx):at+=1
                    if at==len(act_group):self.fail(path+'/'+child_name,'expected entries missing or out of order')
                    at+=1
                if len(act_group)>len(exp_group):self.variations.add(f'additional {child_name} entries (4.1.1)')
                continue
            if mode=='subset':
                if len(act_group)<len(exp_group):
                    wanted=collections.Counter(e.get('value') or xval(e,'AttributeName') or '(structure)' for e in exp_group)
                    def label(a):
                        if isinstance(a[2],list):return '(structure)'
                        if child_name=='AttributeReference':return name_of(a[2])
                        return str(enum_name(child_name,a[2]) or a[2])
                    got=collections.Counter(normalized(label(a)).lower() for a in act_group)
                    wanted=collections.Counter(normalized(k).lower() for k in wanted.elements())
                    missing=sorted((wanted-got).elements())
                    self.fail(path,f'/{child_name}: expected at least {len(exp_group)} fields, received {len(act_group)}; missing {missing[:12]}')
                remaining=list(act_group)
                for e in exp_group:
                    for i,a in enumerate(remaining):
                        if self.trial(e,a,path,ctx):remaining.pop(i);break
                    else:
                        label=e.get('value') or xval(e,'AttributeName') or (list(e)[0].tag if len(e) else '(structure)')
                        missing=f'expected {child_name} {label} not present'
                        if child_name in ('AttributeName','AttributeReference','Operation'):
                            missing+='; received '+', '.join(str(enum_name(child_name,a[2]) or a[2]) if not isinstance(a[2],list) else '(structure)' for a in act_group)
                        self.fail(path,missing)
                if remaining:
                    if name in ATTRIBUTE_CONTAINERS and normalized(child_name) not in MULTI_INSTANCE:
                        self.fail(path+'/'+child_name,'additional instance of a single-instance attribute')
                    self.variations.add(f'additional {child_name} entries (4.1.1)')
                continue
            if len(exp_group)!=len(act_group):
                detail=f'; expected {[e.get("value") for e in exp_group]}, received {[shown(a[2]) for a in act_group]}' if exp_group[0].get('type','Structure')!='Structure' else ''
                self.fail(path+'/'+child_name,f'expected {len(exp_group)} fields, received {len(act_group)}'+detail)
            if name=='Attribute' or child_name!='Attribute':
                for e,a in zip(exp_group,act_group):self.element(e,a,path,ctx)
            else:
                # Legacy Attribute lists: unordered, matched by name/index/value.
                remaining=list(act_group)
                for e in exp_group:
                    for i,a in enumerate(remaining):
                        if self.trial(e,a,path,ctx):remaining.pop(i);break
                    else:self.fail(path+'/Attribute',f'{xval(e,"AttributeName")} not matched')

    def trial(self,e,a,path,ctx):
        saved=(copy.copy(self.vars),copy.copy(self.subst),list(self.obligations),set(self.variations),copy.copy(self.created_ids),set(self.exact_items))
        try:self.element(e,a,path,ctx);return True
        except (AssertionError,Unsupported):
            self.vars,self.subst,self.obligations,self.variations,self.created_ids,self.exact_items=saved;return False

    def batch_item_context(self,exp,act,ctx):
        op=xval(exp,'Operation');ctx['op']=op
        idx=ctx['_item_counter'];i=idx[0];idx[0]+=1;ctx['item_index']=i
        req_items=ctx['req_items'];req=req_items[i] if i<len(req_items) else None
        ctx['request_item']=req;ctx['request_payload']=req.find('RequestPayload') if req is not None else None
        uid=xval(ctx['request_payload'],'UniqueIdentifier') if ctx['request_payload'] is not None else None
        ctx['uid']=self.vars.get(uid,uid)
        wanted=exp.find('ResultStatus')
        if wanted is not None:
            got=[c for c in act[2] if c[0]==TAGS['ResultStatus']]
            if not got or got[0][2]!=enum_value('ResultStatus',wanted.get('value')):
                reason=val(act,'ResultReason');message=val(act,'ResultMessage')
                self.fail(ctx.get('path','/BatchItem'),f'ResultStatus mismatch; reason={reason}; message={message!r}')

    def element(self,e,a,path,ctx):
        tag=tag_of(e)
        if tag is None:raise Unsupported('unknown expected tag '+e.tag)
        p=path+'/'+e.tag
        if a[0]!=tag:self.fail(p,'tag mismatch')
        kind=TYPES.get(e.get('type','Structure'))
        if kind is None:raise Unsupported('unknown expected type '+str(e.get('type')))
        if kind!=a[1]:self.fail(p,'type mismatch')
        if kind==1:
            ctx=dict(ctx)
            if e.tag=='Attribute':
                n=e.find('AttributeName');ctx['attribute']=normalized(n.get('value')) if n is not None else None
                ctx['legacy_attribute_name']=n.get('value') if n is not None else None
            if e.tag in ('KeyBlock',):ctx['key_block']=a
            if e.tag=='Digest' or (e.tag=='AttributeValue' and ctx.get('attribute')=='Digest'):ctx['digest']=a
            return self.structure(e,a,p,ctx)
        self.leaf(e,a,p,ctx)

    def object_variable(self,ctx):
        uid=ctx.get('uid')
        if uid in self.generated:return 'server-generated object'
        kb=ctx.get('key_block')
        if kb is not None and sub(kb,'KeyWrappingData') is not None:
            wrap=val(sub(kb,'KeyWrappingData','EncryptionKeyInformation'),'UniqueIdentifier')
            if wrap in self.generated:return 'wrapped with a dynamic wrapping key'
            mode=val(sub(kb,'KeyWrappingData','EncryptionKeyInformation','CryptographicParameters'),'BlockCipherMode')
            if mode is not None and enum_name('BlockCipherMode',mode) in ('GCM','CBC','CTR'):return 'wrapping with variable output'
        return None

    def inherent_variable(self,ctx):
        op=ctx.get('op');req=ctx.get('request_payload');uid=ctx.get('uid')
        params=req.find('CryptographicParameters') if req is not None else None
        stored=self.params.get(uid,{})
        def pv(name):
            v=xval(params,name) if params is not None else None
            return normalized(v) if v else stored.get(name)
        pad=pv('PaddingMethod');sig=pv('DigitalSignatureAlgorithm') or '';salt=pv('SaltLength')
        alg=stored.get('CryptographicAlgorithm')
        if op=='Encrypt' and pad in ('OAEP','PKCS1v15'):return 'randomized RSA encryption padding'
        if op=='Sign' and (pad=='PSS' or sig.startswith('RSASSAPSS')) and salt!='0':return 'randomized RSA-PSS signature'
        if op=='Sign' and (alg in ('ECDSA','EC','DSA') or sig.startswith('ECDSA') or sig.startswith('DSA')):return 'randomized (EC)DSA signature'
        continuation=req is not None and req.find('CorrelationValue') is not None
        if op=='Encrypt' and not continuation and (req is None or req.find('IVCounterNonce') is None) and pv('BlockCipherMode') not in (None,'ECB'):return 'server-generated IV'
        if op=='Encrypt' and pv('RandomIV')=='true':return 'server-generated IV'
        return None

    def leaf(self,e,a,path,ctx):
        name=e.tag;value=e.get('value','');kind=a[1]
        if name in ('ServerCorrelationValue','ClientCorrelationValue') and ctx.get('container')=='ResponseHeader':
            if kind!=7 or not a[2]:self.fail(path,'must be a nonempty text value')
            if value.startswith('$'):self.vars[value]=a[2]
            if value!=a[2]:self.variations.add(f'{name} varies (4.1.1)')
            return
        if value.startswith('$'):
            relative=re.fullmatch(r'\$NOW([+-][0-9]+)?',value)
            if relative:
                if kind not in (9,11) or abs(a[2]-(int(time.time())+int(relative.group(1) or 0)))>=120:self.fail(path,'invalid timestamp')
                return
            first=value not in self.vars
            if first:self.vars[value]=a[2]
            if self.vars[value]!=a[2]:self.fail(path,f'variable {value} changed: {shown(self.vars[value])} then {shown(a[2])}')
            if first and ctx.get('response_payload') and kind in (4,8):
                # A placeholder accepts any value from the trace's point of view,
                # but the harness still verifies it like a variable literal.
                kind_name,why=self.output_kind(name,path,ctx,placeholder=True)
                if kind_name:
                    self.obligations.append(Obligation(kind_name,path,a[2],ctx.get('uid'),None,self.exchange_index,self.obligation_info(ctx,why)))
                    self.variations.add(f'{kind_name} bound to trace placeholder {value}')
            if name in ID_FIELDS and ctx.get('op') in CREATING and ctx.get('container')=='ResponsePayload':
                self.created_ids.setdefault(value,a[2])
                if ctx.get('op') in GENERATING:self.generated.add(a[2])
            if name=='UniqueIdentifier' and ctx.get('container')=='ResponsePayload':self.current_uid(ctx,a[2])
            return
        if name=='AttributeIndex' and ctx.get('container')=='Attribute' and ctx.get('response_payload') and kind==2:
            # Server-assigned index; an additional instance (4.1.1, e.g. a second
            # Digest) shifts it. The attribute name and value still match exactly.
            if encode_xml(e,self.vars)[2]!=a[2]:
                if not self.index_shift_ok(a[2],ctx):self.fail(path,f'value mismatch; expected {e.get("value")}, received {a[2]} without additional instances')
                self.variations.add('Attribute Index shifted by additional instances (4.1.1)')
            return
        if name=='TimeStamp' and kind==9:
            self.variations.add('Time Stamp varies (4.1.1)');return
        if name in DATE_ATTRS and kind==9 and value not in self.request_datetimes and ctx.get('response_payload'):
            if value and encode_xml(e,self.vars)[2]!=a[2]:self.variations.add(f'{name} varies (4.1.1)')
            return
        if name=='LinkedObjectIdentifier' and ctx.get('response_payload'):
            if kind not in (7,12):self.fail(path,'type mismatch')
            self.variations.add('Linked Object Identifier varies (4.1.1)');return
        if name=='VendorIdentification' and ctx.get('op')=='Query' and ctx.get('container')=='ResponsePayload':
            self.variations.add('Query Vendor Identification varies (4.1.1)');return
        if ctx.get('response_payload') and kind in (4,8):
            kind_name,why=self.output_kind(name,path,ctx)
            if why:
                want=encode_xml(e,self.vars)[2]
                self.subst[value.lower()]=a[2]
                self.obligations.append(Obligation(kind_name,path,a[2],ctx.get('uid'),want,self.exchange_index,self.obligation_info(ctx,why)))
                self.variations.add(f'{kind_name} varies: {why} (4.1.1)')
                return
        want=encode_xml(e,self.vars,ctx.get('attribute'))
        if want[2]!=a[2]:
            if kind==7 and isinstance(a[2],str) and a[2].endswith(want[2]) and re.search(r'[A-Z]+-[A-Z]-\d',want[2]):
                self.variations.add('test identifier carries an additional prefix (4.1.1)');return
            self.fail(path,f'value mismatch; expected {shown(want[2])}, received {shown(a[2])}')
        if name in EXACT_CRYPTO and ctx.get('op') in ('Decrypt','SignatureVerify','MACVerify','Encrypt','Sign','MAC'):self.exact_items.add(ctx.get('item_index'))
        if name=='UniqueIdentifier' and ctx.get('container')=='ResponsePayload':self.current_uid(ctx,a[2])

    def current_uid(self,ctx,uid):ctx['uid']=uid
    def obligation_info(self,ctx,why):
        return {'op':ctx.get('op'),'request_payload':ctx.get('request_payload'),'key_block':ctx.get('key_block'),'digest':ctx.get('digest'),'actual_payload':ctx.get('actual_payload'),'item':ctx.get('item_index'),'reason':why}
    def output_kind(self,name,path,ctx,placeholder=False):
        """Classify a byte-valued response field that may vary (4.1.1)."""
        kb=ctx.get('key_block')
        if kb is not None and name!='DigestValue' and path.find('/KeyValue/')>=0:
            if sub(kb,'KeyWrappingData') is not None:
                why=self.object_variable(ctx) or ('trace placeholder' if placeholder else None)
                return ('wrapped-key',why) if why else (None,None)
            why=self.object_variable(ctx) or ('trace placeholder' if placeholder else None)
            return ('key-material',why) if why else (None,None)
        if name in OUTPUT_FIELDS and ctx.get('op')=='RNGRetrieve':return 'rng','CSPRNG output'
        if name in OUTPUT_FIELDS and ctx.get('op') in ('Encrypt','Sign','MAC'):
            why='output of a server-generated key' if ctx.get('uid') in self.generated else self.inherent_variable(ctx)
            if not why and placeholder:why='trace placeholder'
            return ('crypto-output',why) if why else (None,None)
        if name=='DigestValue' and (ctx.get('uid') in self.generated or placeholder):
            return 'digest','digest of a server-generated object' if ctx.get('uid') in self.generated else 'trace placeholder'
        return None,None

    # ---------- learning about objects (from requests and actual responses) ----------
    def harvest(self,req_xml,actual,req_node):
        """Record server-generated identifiers, registered material and parameters."""
        items=list(zip(req_xml.findall('BatchItem'),[c for c in actual[2] if c[0]==TAGS['BatchItem']]))
        sent=[c for c in req_node[2] if c[0]==TAGS['BatchItem']]
        for position,(rx,ra) in enumerate(items):
            op=xval(rx,'Operation');rp=rx.find('RequestPayload');ap=sub(ra,'ResponsePayload')
            if val(ra,'ResultStatus')!=0 or ap is None:continue
            uid=val(ap,'UniqueIdentifier');priv=val(ap,'PrivateKeyUniqueIdentifier');pub=val(ap,'PublicKeyUniqueIdentifier')
            ids=[x for x in (uid,priv,pub) if x]
            if op in GENERATING:self.generated.update(ids)
            if op=='Register' and uid:self.generated.discard(uid)
            if priv and pub:self.pairs[priv]=pub;self.pairs[pub]=priv
            if op in ('Create','Register','CreateKeyPair','Rekey','DeriveKey') and rp is not None:
                for target,scope in ((uid,'Attributes'),(priv,'PrivateKeyAttributes'),(pub,'PublicKeyAttributes'),(priv,'CommonAttributes'),(pub,'CommonAttributes'),(uid,'TemplateAttribute'),(priv,'CommonTemplateAttribute'),(pub,'CommonTemplateAttribute')):
                    if not target:continue
                    st=self.params.setdefault(target,{})
                    for container in rp.iter(scope):
                        for f in container.iter():
                            if f.tag in ('CryptographicAlgorithm','CryptographicLength') and f.get('value'):st.setdefault(f.tag,normalized(f.get('value')))
                        for cp in container.iter('CryptographicParameters'):
                            for f in cp:
                                if f.get('value'):st.setdefault(f.tag,normalized(f.get('value')))
                        for at in container.iter('Attribute'):
                            n=normalized(xval(at,'AttributeName') or '')
                            if n in ('CryptographicAlgorithm','CryptographicLength'):st.setdefault(n,normalized(xval(at,'AttributeValue') or ''))
                            if n=='CryptographicParameters':
                                for f in at.find('AttributeValue') or []:
                                    if f.get('value'):st.setdefault(f.tag,normalized(f.get('value')))
                if op=='Register' and uid:
                    # Registered material, read from the request actually sent.
                    self.learn_object(uid,sub(sent[position],'RequestPayload'),'registered')
            if op=='Get' and uid:self.learn_object(uid,ap,'Get')
        self.check_pairs()

    def learn_object(self,uid,payload,source):
        if payload is None:return
        for kind in ('SymmetricKey','PrivateKey','PublicKey','SecretData'):
            obj=sub(payload,kind)
            if obj is None:continue
            kb=sub(obj,'KeyBlock')
            if kb is None or sub(kb,'KeyWrappingData') is not None:return
            fmt=enum_name('KeyFormatType',val(kb,'KeyFormatType'))
            material=val(sub(kb,'KeyValue'),'KeyMaterial')
            if not isinstance(material,bytes):return
            alg=enum_name('CryptographicAlgorithm',val(kb,'CryptographicAlgorithm'))
            self.formats[(uid,fmt)]=material
            if uid in self.material:return
            self.material[uid]={'type':kind,'format':fmt,'bytes':material,'algorithm':alg,'length':val(kb,'CryptographicLength'),'source':source}
            if alg:self.params.setdefault(uid,{}).setdefault('CryptographicAlgorithm',alg)
            if kind=='PublicKey' and fmt in ('X509','PKCS1'):
                key=self.corpus_keys.get(self.public_der(material,fmt))
                if key:self.material.setdefault('corpus:'+uid,{'type':'PrivateKey','format':'PKCS8','bytes':key,'source':'corpus'})

    @staticmethod
    def public_der(material,fmt):
        try:
            k=V.load_public(material,fmt)
            from cryptography.hazmat.primitives import serialization
            return k.public_bytes(serialization.Encoding.DER,serialization.PublicFormat.SubjectPublicKeyInfo)
        except Exception:return None

    def check_pairs(self):
        for priv,pub in list(self.pairs.items()):
            a=self.material.get(priv);b=self.material.get(pub)
            if a and b and a['type']=='PrivateKey' and b['type']=='PublicKey' and not a.get('pair_checked'):
                V.pair_check(V.load_private(a['bytes'],a['format']),V.load_public(b['bytes'],b['format']));a['pair_checked']=True
                self.variations.add('generated key pair correspondence verified independently')

    # ---------- closing obligations ----------
    def private_key(self,uid):
        for candidate in (uid,self.pairs.get(uid),'corpus:'+str(uid)):
            m=self.material.get(candidate)
            if m and m['type']=='PrivateKey':return V.load_private(m['bytes'],m['format'])
        return None
    def public_key(self,uid):
        for candidate in (uid,self.pairs.get(uid)):
            m=self.material.get(candidate)
            if m and m['type']=='PublicKey':return V.load_public(m['bytes'],m['format'])
            if m and m['type']=='PrivateKey':return V.load_private(m['bytes'],m['format']).public_key()
        return None
    def digest_spec(self,o):
        d=o.info.get('digest')
        return enum_name('HashingAlgorithm',val(d,'HashingAlgorithm')),enum_name('KeyFormatType',val(d,'KeyFormatType'))
    def needs_material(self):
        """(identifier, key format) pairs an open obligation needs and the trace has not shown."""
        out=[]
        for o in self.obligations:
            if o.closed or o.kind in ('rng','key-material'):continue
            if o.kind=='digest':
                want=[(o.uid,self.digest_spec(o)[1])]
            else:want=[(c,None) for c in (o.uid,self.pairs.get(o.uid)) if c]
            for uid,fmt in want:
                have=(uid,fmt) in self.formats if fmt else uid in self.material
                if uid in self.generated and not have and (uid,fmt) not in out and (uid,fmt) not in self.attempted:out.append((uid,fmt))
        return out

    def resolve(self,final=False):
        """Independent checks first; a round trip closes an obligation only at the
        end, and only when no independent check was possible."""
        for o in self.obligations:
            if o.closed:continue
            try:o.close(self.verify(o))
            except V.Unverifiable as e:
                o.info['unverifiable']=str(e)
                if final and o.roundtrip:o.close(o.roundtrip)

    def verify(self,o):
        info=o.info;rp=info.get('request_payload')
        if o.kind=='rng':
            length=int(xval(rp,'DataLength') or 0) if rp is not None else 0
            if len(o.value)!=length:raise AssertionError(f'RNG Retrieve returned {len(o.value)} bytes for Data Length {length}')
            if len(set(o.value))<=1 and length>1:raise AssertionError('RNG output is constant')
            if o.value in self.rng_outputs:raise AssertionError('RNG output repeated')
            self.rng_outputs.append(o.value);return f'{length} bytes as requested, non-constant, unique'
        if o.kind=='wrapped-key':return self.verify_wrapped(o)
        if o.kind=='key-material':
            kb=info['key_block'];fmt=enum_name('KeyFormatType',val(kb,'KeyFormatType'))
            m=self.material.get(o.uid) or {}
            if o.uid not in self.generated and m.get('source')=='registered':
                if self.formats.get((o.uid,fmt))==o.value:return 'equals the registered key material'
                if (o.uid,fmt) in self.formats:raise AssertionError('key material differs from the registered material')
            object_type=m.get('type') or ('SymmetricKey' if fmt in ('Raw','TransparentSymmetricKey') else None)
            if object_type is None:raise V.Unverifiable('object type unknown for key material')
            return V.key_size_check(o.value,fmt,object_type,val(kb,'CryptographicLength'),enum_name('CryptographicAlgorithm',val(kb,'CryptographicAlgorithm')))
        if o.kind=='digest':
            alg,fmt=self.digest_spec(o)
            material=self.formats.get((o.uid,fmt))
            if material is None:raise V.Unverifiable(f'key material in {fmt} not available')
            return V.digest_check(material,alg,o.value)
        if o.kind=='crypto-output':return self.verify_output(o)
        raise V.Unverifiable(o.kind)

    def verify_wrapped(self,o):
        """Unwrap under the wrapping key; length must equal the wrapped object's."""
        kb=o.info['key_block'];wd=sub(kb,'KeyWrappingData');eki=sub(wd,'EncryptionKeyInformation')
        if eki is None or sub(wd,'MACSignatureKeyInformation') is not None:raise V.Unverifiable('only encryption-key wrapping is verified')
        wrap_uid=val(eki,'UniqueIdentifier');cp=sub(eki,'CryptographicParameters')
        mode=enum_name('BlockCipherMode',val(cp,'BlockCipherMode')) if cp is not None else None
        stored=self.params.get(wrap_uid,{});mode=mode or stored.get('BlockCipherMode')
        m=self.material.get(wrap_uid)
        if not m:raise V.Unverifiable('wrapping key material not available')
        plain=V.unwrap(mode,m['bytes'],o.value,val(wd,'IVCounterNonce'))
        length=val(kb,'CryptographicLength');mine=self.formats.get((o.uid,enum_name('KeyFormatType',val(kb,'KeyFormatType'))))
        if mine is not None and plain!=mine:raise AssertionError('unwrapped key differs from the object key material')
        if mine is None and length and len(plain)*8!=length:raise AssertionError(f'unwrapped key is {len(plain)*8} bits, attribute says {length}')
        return f'unwrapped independently ({mode})'

    def operation_params(self,o):return self.param_lookup(o.uid,o.info['request_payload'])
    def param_lookup(self,uid,rp):
        """Request Cryptographic Parameters, else those stored with the object."""
        stored=self.params.get(uid,{});params=rp.find('CryptographicParameters') if rp is not None else None
        def pv(name):
            v=xval(params,name) if params is not None else None
            return normalized(v) if v else stored.get(name)
        return pv
    @staticmethod
    def label(pv):
        v=pv('PSource');return bytes.fromhex(v) if v else None
    def request_bytes(self,o,name):
        rp=o.info['request_payload'];v=xval(rp,name) if rp is not None else None
        if v is None:return None
        if v.startswith('$'):return self.vars.get(v)
        b=bytes.fromhex(v.replace(' ',''));return self.subst.get(v.lower(),b)
    def sibling_output(self,o,name):
        return val(o.info.get('actual_payload'),name)

    def verify_output(self,o):
        op=o.info['op'];pv=self.operation_params(o);uid=o.uid
        if o.path.endswith('/IVCounterNonce') or o.path.endswith('/AuthenticatedEncryptionTag'):
            data=next((x for x in self.obligations if x.exchange==o.exchange and x.info.get('actual_payload') is o.info.get('actual_payload') and x.path.endswith('/Data')),None)
            if data is not None and data.closed:return 'verified with the ciphertext it accompanies'
            raise V.Unverifiable('accompanying ciphertext not yet verified')
        if op=='Encrypt':
            plain=self.request_bytes(o,'Data');alg=pv('CryptographicAlgorithm') or (self.material.get(uid) or {}).get('algorithm')
            if alg=='RSA':
                key=self.private_key(uid)
                if key is None:raise V.Unverifiable('no private key for independent RSA decryption')
                got=V.rsa_decrypt(key,o.value,pv('PaddingMethod'),pv('HashingAlgorithm'),pv('MaskGeneratorHashingAlgorithm'),self.label(pv))
            else:
                m=self.material.get(uid)
                if not m:raise V.Unverifiable('symmetric key material not available')
                iv=self.request_bytes(o,'IVCounterNonce') or self.sibling_output(o,'IVCounterNonce')
                tag=self.sibling_output(o,'AuthenticatedEncryptionTag')
                aad=self.request_bytes(o,'AuthenticatedEncryptionAdditionalData') or b''
                mode=pv('BlockCipherMode')
                if mode is None:raise V.Unverifiable('block cipher mode not stated')
                got=V.sym_decrypt(alg or m['algorithm'],m['bytes'],mode,pv('PaddingMethod'),iv,o.value,tag,aad)
            if got!=plain:raise AssertionError('independent decryption does not return the request plaintext')
            return f'decrypted independently to the request plaintext ({alg} {pv("BlockCipherMode") or pv("PaddingMethod")})'
        if op=='Sign':
            key=self.public_key(uid)
            if key is None:raise V.Unverifiable('no public key for independent verification')
            data=self.request_bytes(o,'Data');prehashed=False
            if data is None:
                data=self.request_bytes(o,'DigestedData');prehashed=True
            sig=pv('DigitalSignatureAlgorithm') or '';hash_name=pv('HashingAlgorithm')
            for h in ('SHA1','SHA224','SHA256','SHA384','SHA512'):
                if h in sig.upper():hash_name=hash_name or h
            pad=pv('PaddingMethod') or ('PSS' if 'PSS' in sig.upper() else None)
            salt=pv('SaltLength');salt=int(salt) if salt and salt.isdigit() else None
            defaults=None
            if pad=='PSS' and salt is None and self.version!='1.3':
                # 1.4+ "if omitted, defaults to the block size of the Mask Generator
                # Hashing Algorithm"; read as its block size, its output size, or the
                # message hash output size. 1.3 defines no Salt Length.
                from cryptography.hazmat.primitives import hashes as H
                mgf=V.hash_of(pv('MaskGeneratorHashingAlgorithm') or 'SHA1');h=V.hash_of(hash_name or 'SHA256')
                defaults=sorted({mgf.block_size,mgf.digest_size,h.digest_size})
            mgf_hash=pv('MaskGeneratorHashingAlgorithm')
            if pad=='PSS' and mgf_hash is None and self.version=='1.3':
                # 1.3 has no Mask Generator field (docs/interpretations.md#pss-defaults-in-kmip-13):
                # MGF1 uses the message hash, as the CS-AC-M-2-13 signature does.
                mgf_hash=hash_name or 'SHA256'
            return V.verify_signature(key,o.value,data,pad,hash_name,mgf_hash,salt,prehashed,defaults)
        if op=='MAC':
            m=self.material.get(uid)
            if not m:raise V.Unverifiable('MAC key material not available')
            alg=pv('CryptographicAlgorithm') or m['algorithm']
            if V.mac(alg,m['bytes'],self.request_bytes(o,'Data'))!=o.value:raise AssertionError('MAC differs from the independent computation')
            return f'MAC recomputed independently ({alg})'
        raise V.Unverifiable('operation '+str(op))

# A verification Get is itself observable: KMIP clears Fresh (2.1 section 4.24)
# and this server records extraction history. It is therefore only issued when
# no later trace step reads attributes; otherwise it waits for the trace's end.
OBSERVING={'GetAttributes','GetAttributeList','Locate','Export','Check'}
def observes_attributes(later):
    return any(xval(b,'Operation') in OBSERVING for m in later if m.tag=='RequestMessage' for b in m.findall('BatchItem'))

def rederive_inputs(replay,req_xml,exp_resp,connection,version,uid_kind,notes,later=()):
    """Recompute verification inputs that the trace produced under its sample key.

    For Decrypt, Signature Verify and MAC Verify on a server-generated key, the
    trace's literal ciphertext, signature or MAC cannot match the server's key
    (Profiles 4.1.1 lets generated key material vary). The harness fetches the
    key with a labelled Get and computes the input independently from the
    trace's own expected result, which is then compared exactly.
    """
    exp_items=exp_resp.findall('BatchItem')
    for position,item in enumerate(req_xml.findall('BatchItem')):
        op=xval(item,'Operation');rp=item.find('RequestPayload')
        if op not in ('Decrypt','SignatureVerify','MACVerify') or rp is None:continue
        ref=xval(rp,'UniqueIdentifier');uid=replay.vars.get(ref,ref)
        if uid not in replay.generated:continue
        field={'Decrypt':'Data','SignatureVerify':'SignatureData','MACVerify':'MACData'}[op]
        literal=rp.find(field)
        if literal is None or literal.get('value','').startswith('$'):continue
        exp=exp_items[position] if position<len(exp_items) else None
        if exp is None or xval(exp,'ResultStatus')!='Success':continue
        for needed in (uid,replay.pairs.get(uid)):
            if needed and needed not in replay.material and (needed,None) not in replay.attempted:
                if observes_attributes(later) and not quiet_material(version):
                    raise Unsupported(f'{op} input must be re-derived under a generated key, but the Get needed for it would change attributes a later step reads','verification_would_perturb_trace')
                replay.attempted.add((needed,None));payload=material_get(connection,version,needed,uid_kind)
                replay.material_gets.append(needed)
                if payload is not None:replay.learn_object(needed,payload,'independent Get')
        pv=replay.param_lookup(uid,rp);m=replay.material.get(uid) or {}
        alg=pv('CryptographicAlgorithm') or m.get('algorithm')
        def hexval(name):
            v=xval(rp,name);return bytes.fromhex(v) if v and not v.startswith('$') else None
        try:
            if op=='Decrypt':
                plain=xval(exp,'ResponsePayload/Data')
                if plain is None or plain.startswith('$'):continue
                plain=bytes.fromhex(plain)
                if alg=='RSA':
                    key=replay.public_key(uid)
                    if key is None:raise V.Unverifiable('no public key')
                    value=V.rsa_encrypt(key,plain,pv('PaddingMethod'),pv('HashingAlgorithm'),pv('MaskGeneratorHashingAlgorithm'),Replay.label(pv))
                else:
                    if not m:raise V.Unverifiable('no key material')
                    value,tag=V.sym_encrypt(alg,m['bytes'],pv('BlockCipherMode'),pv('PaddingMethod'),hexval('IVCounterNonce'),plain,hexval('AuthenticatedEncryptionAdditionalData') or b'',len(hexval('AuthenticatedEncryptionTag') or b'')or 16)
                    if tag is not None and rp.find('AuthenticatedEncryptionTag') is not None:rp.find('AuthenticatedEncryptionTag').set('value',tag.hex())
            elif op=='SignatureVerify':
                if xval(exp,'ResponsePayload/ValidityIndicator')!='Valid':continue
                key=replay.private_key(uid) or replay.private_key(replay.pairs.get(uid))
                if key is None:raise V.Unverifiable('no private key')
                data=hexval('Data');prehashed=data is None
                if prehashed:data=hexval('DigestedData')
                sig=pv('DigitalSignatureAlgorithm') or '';hash_name=pv('HashingAlgorithm')
                for h in ('SHA1','SHA224','SHA256','SHA384','SHA512'):
                    if h in sig.upper():hash_name=hash_name or h
                pad=pv('PaddingMethod') or ('PSS' if 'PSS' in sig.upper() else None)
                salt=pv('SaltLength');salt=int(salt) if salt and salt.isdigit() else None
                value=V.sign(key,data,pad,hash_name,pv('MaskGeneratorHashingAlgorithm'),salt,prehashed)
            else:
                if xval(exp,'ResponsePayload/ValidityIndicator')!='Valid' or not m:continue
                value=V.mac(alg,m['bytes'],hexval('Data'))
        except V.Unverifiable as e:
            notes.append(f'{op} input not re-derived: {e}');continue
        literal.set('value',value.hex())
        notes.append(f'{op} {field} re-derived independently under the server-generated key (4.1.1)')

def corpus_private_keys(version_entries):
    """Index registered private keys in the version's own traces by public key.

    The OAEP encrypt traces register only the public key; the matching private
    key is registered by sibling traces. Using it decrypts the server's
    ciphertext independently of the server.
    """
    from cryptography.hazmat.primitives import serialization
    index={}
    for raw in version_entries.values():
        try:root=ET.fromstring(raw)
        except ET.ParseError:continue
        for pk in root.iter('PrivateKey'):
            m=pk.find('./KeyBlock/KeyValue/KeyMaterial');f=pk.find('./KeyBlock/KeyFormatType')
            if m is None or not m.get('value'):continue
            try:
                key=serialization.load_der_private_key(bytes.fromhex(m.get('value')),None)
                spki=key.public_key().public_bytes(serialization.Encoding.DER,serialization.PublicFormat.SubjectPublicKeyInfo)
                index[spki]=key.private_bytes(serialization.Encoding.DER,serialization.PrivateFormat.PKCS8,serialization.NoEncryption())
            except Exception:continue
    return index

def omit_interop(messages,version,inventory):
    """Drop a leading Interop Begin and trailing Interop End pair (Profiles 2.0+ 4.1.2)."""
    rule=inventory['interop_wrapper_omission']
    def is_interop(req,function):
        items=req.findall('BatchItem')
        return len(items)==1 and xval(items[0],'Operation')=='Interop' and xval(items[0],'RequestPayload/InteropFunction')==function
    done=[]
    if version in rule['versions'] and len(messages)>=2 and is_interop(messages[0],'Begin'):messages=messages[2:];done.append('Interop Begin omitted (Profiles 4.1.2)')
    if version in rule['versions'] and len(messages)>=2 and is_interop(messages[-2],'End'):messages=messages[:-2];done.append('Interop End omitted (Profiles 4.1.2)')
    return messages,done

def exchange_raw(s,n):
    s.sendall(encode(n));h=recv_exact(s,8);size=int.from_bytes(h[4:8],'big')
    if size>1024*1024:raise AssertionError('response too large for the harness')
    return h+recv_exact(s,size)

def quiet_material(version):
    """From 2.0 the verification fetch uses Export, which reads material without
    the Get-only Fresh change (2.1 section 4.24). If Export did change observable
    state, a later trace comparison would fail; it cannot cause a false pass."""
    return int(version.split('.')[0])>=2

def material_get(connection,version,uid,uid_kind,key_format=None):
    major,minor=(int(x) for x in version.split('.'))
    # Batch Count was removed in the 3.0 draft.
    header=node(TAGS['RequestHeader'],1,[node(TAGS['ProtocolVersion'],1,[node(TAGS['ProtocolVersionMajor'],2,major),node(TAGS['ProtocolVersionMinor'],2,minor)])]+([node(TAGS['BatchCount'],2,1)] if major<3 else []))
    fields=[node(TAGS['UniqueIdentifier'],uid_kind,uid)]
    if key_format:fields.append(node(TAGS['KeyFormatType'],5,ENUMS['KeyFormatType'][key_format]))
    item=node(TAGS['BatchItem'],1,[node(TAGS['Operation'],5,43 if quiet_material(version) else 10),node(TAGS['RequestPayload'],1,fields)])
    response=V.strict_decode(exchange_raw(connection,node(TAGS['RequestMessage'],1,[header,item])))
    bi=sub(response,'BatchItem')
    return sub(bi,'ResponsePayload') if val(bi,'ResultStatus')==0 else None

class ClientEndpoint:
    """Harness mTLS listener that accepts the server's Notify/Put requests.

    Profiles that list Notify and Put as server-to-client operations need a
    deployment with a client endpoint; this fixture provides one. Each request
    is decoded strictly and answered with Success for every batch item.
    """
    def __init__(self,pki):
        import socket,ssl,threading
        self.received=[];self.errors=[]
        ctx=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);ctx.minimum_version=ssl.TLSVersion.TLSv1_2
        ctx.load_cert_chain(pki/'server.pem',pki/'server.key');ctx.load_verify_locations(pki/'ca.pem');ctx.verify_mode=ssl.CERT_REQUIRED
        self.sock=socket.socket();self.sock.bind(('127.0.0.1',0));self.sock.listen(16);self.port=self.sock.getsockname()[1]
        def serve():
            while True:
                try:conn,_=self.sock.accept()
                except OSError:return
                threading.Thread(target=self.handle,args=(ctx,conn),daemon=True).start()
        threading.Thread(target=serve,daemon=True).start()
    def handle(self,ctx,conn):
        try:
            with ctx.wrap_socket(conn,server_side=True) as c:
                while True:
                    h=recv_exact(c,8);raw=h+recv_exact(c,int.from_bytes(h[4:8],'big'))
                    msg=V.strict_decode(raw);hdr=sub(msg,'RequestHeader')
                    items=[i for i in msg[2] if i[0]==TAGS['BatchItem']]
                    self.received.extend(enum_name('Operation',val(i,'Operation')) for i in items)
                    head=[node(TAGS['ProtocolVersion'],1,sub(hdr,'ProtocolVersion')[2]),node(TAGS['TimeStamp'],9,int(time.time()))]
                    if sub(hdr,'BatchCount') is not None:head.append(node(TAGS['BatchCount'],2,len(items)))
                    out=[node(TAGS['ResponseHeader'],1,head)]+[node(TAGS['BatchItem'],1,[node(TAGS['Operation'],5,val(i,'Operation')),node(TAGS['ResultStatus'],5,0)]) for i in items]
                    c.sendall(encode(node(TAGS['ResponseMessage'],1,out)))
        except (EOFError,OSError):pass
        except AssertionError as e:self.errors.append(str(e))
    def policy(self,pki,version):
        major,minor=(int(x) for x in version.split('.'))
        return {'address':f'127.0.0.1:{self.port}','server_name':'localhost','ca':str(pki/'ca.pem'),'certificate':str(pki/'server.pem'),'key':str(pki/'server.key'),
                'protocol_version':version if (major,minor)<=(2,1) else '2.1','operations':[27,28]}

def query_expects_server_to_client(messages):
    return any(e.get('value') in ('Notify','Put') for m in messages if m.tag=='ResponseMessage' for e in m.iter('Operation'))

def run_case(server,replay,version,messages,inventory,entry):
    """Execute one trace on a running server, recording progress in entry."""
    transformations=entry['transformations'];entry['completed_exchanges']=0
    messages,omitted=omit_interop(messages,version,inventory);transformations+=omitted
    if any(e.get('value')=='Interop' for m in messages if m.tag=='RequestMessage' for e in m.iter('Operation')):
        raise Unsupported('Interop used inside the test body; no permitted omission','test_only_control_operation')
    replay.vars.update(fixture_constants(messages));uid_kind=12 if version.startswith('3') else 7
    with server.connect() as connection:
        for i in range(0,len(messages),2):
            if messages[i].tag!='RequestMessage' or i+1>=len(messages) or messages[i+1].tag!='ResponseMessage':raise Unsupported('non-alternating message trace')
            replay.exchange_index=i//2;entry['failed_exchange']=i//2
            req_xml,used=replay.prepare_request(messages[i])
            later=messages[i+2:]
            notes=[];rederive_inputs(replay,req_xml,messages[i+1],connection,version,uid_kind,notes,later)
            for note in notes:replay.variations.add(note)
            req=encode_xml(req_xml,replay.vars)
            raw=exchange_raw(connection,req)
            try:actual=V.strict_decode(raw)
            except AssertionError as e:raise AssertionError('response decoding: '+str(e))
            if actual!=decode(raw):raise AssertionError('strict and lenient decoders disagree')
            replay.last_actual=actual
            exact_items=replay.compare_message(messages[i+1],actual,req_xml)
            replay.harvest(req_xml,actual,req)
            # A server value fed into a batch item whose cryptographic result the
            # trace states literally (and which matched) is a round trip. It is
            # only a fallback for when no independent check is possible.
            for item in exact_items:
                for o in replay.obligations:
                    if o.roundtrip is None and any(o.value==u for u in used.get(item,[])):o.roundtrip=f'in-trace round trip at exchange {i//2}'
            if quiet_material(version) or not observes_attributes(later):fetch_material(replay,connection,version,uid_kind)
            replay.resolve()
            entry['completed_exchanges']+=1
        # Deferred verification Gets; a destroyed object leaves its obligation open.
        fetch_material(replay,connection,version,uid_kind);replay.resolve()
    entry.pop('failed_exchange',None)

def fetch_material(replay,connection,version,uid_kind):
    for uid,fmt in replay.needs_material():
        replay.attempted.add((uid,fmt))
        payload=material_get(connection,version,uid,uid_kind,fmt)
        replay.material_gets.append(uid)
        if payload is not None:replay.learn_object(uid,payload,'independent Get')
    replay.check_pairs()

def render(n,depth=0):
    """Readable form of a decoded response, for failure diagnosis in the report."""
    tag,kind,value=n;name=name_of(tag)
    if kind==1:return '  '*depth+name+'\n'+''.join(render(c,depth+1) for c in value)
    shown_value=value.hex() if isinstance(value,bytes) else (enum_name(name,value) or value) if kind==5 else value
    return '  '*depth+f'{name}={shown_value}\n'

def finish(replay):
    """Identifier uniqueness and the open-obligation verdict."""
    seen={}
    for var,value in replay.created_ids.items():
        if value in seen:raise AssertionError(f'identifier reused: {var} and {seen[value]} both {value}')
        seen[value]=var
    replay.resolve(final=True)
    open_=[o for o in replay.obligations if not o.closed]
    return open_

def load_entries(version,flt):
    archive=ROOT/f'.cache/specs/profiles-{version}.zip'
    with zipfile.ZipFile(archive) as z:entries={n:z.read(n) for n in z.namelist() if n.endswith('.xml') and flt in n}
    for extra in json.loads((ROOT/'docs/specs/additional-traces.json').read_text()):
        name='additional/'+extra['filename']
        if extra['version']==version and flt in name:
            raw=(ROOT/'.cache/specs'/extra['filename']).read_bytes()
            if hashlib.sha256(raw).hexdigest()!=extra['sha256']:raise RuntimeError('additional trace checksum mismatch: '+name)
            entries[name]=raw
    return entries

def case_id(name):return re.sub(r'-\d\d$','',pathlib.PurePosixPath(name).stem)

def main():
    parser=argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument('--versions',nargs='+',default=['1.1','1.2','1.3','1.4','2.0','2.1','3.0'])
    parser.add_argument('--filter',default='');parser.add_argument('--binary',type=pathlib.Path,default=ROOT/'target/debug/keytend-kmip-server')
    parser.add_argument('--output',type=pathlib.Path,default=ROOT/'artifacts/oasis-profile-variations.json')
    parser.add_argument('--diagnose',action='store_true',help='Include the decoded failing response in the report')
    parser.add_argument('--corrected-fixtures',action='store_true',help='Apply docs/specs/oasis-corrected-fixtures.json (proven corpus defects only); reported as a separate mode')
    a=parser.parse_args()
    inventory=json.loads(INVENTORY.read_text())
    subprocess.run(['python3',str(ROOT/'scripts/fetch_specs.py')],check=True)
    fixtures={}
    if a.corrected_fixtures:
        for edit in json.loads((ROOT/'docs/specs/oasis-corrected-fixtures.json').read_text())['edits']:fixtures.setdefault(edit['case'],[]).append(edit)
    binary_sha=hashlib.sha256(a.binary.read_bytes()).hexdigest()
    a.output.parent.mkdir(parents=True,exist_ok=True)
    report=[]
    sequences={(v,c):seq for seq in inventory['sequences'] for v in seq['versions'] for c in seq['chain']}
    with tempfile.TemporaryDirectory(prefix='keytend-kmip-server-variations-') as d:
        server=Server(d,binary=a.binary,draft=True);base_policy=json.loads((server.pki/'policy.json').read_text())
        endpoint=None
        def configure(label,operations=None,client_endpoint=None):
            server.stop();server.data=pathlib.Path(d)/'data'/label;server.data.mkdir(parents=True,mode=0o700)
            policy=copy.deepcopy(base_policy)
            for principal in policy['principals'].values():
                # The fixture narrows only the trace client's own operation list.
                if principal['name']!='database':continue
                if operations is not None:principal['operations']=operations
                if client_endpoint:principal['client_endpoint']=client_endpoint
                principal['name']=f'oasis-{label}'
            (server.pki/'policy.json').write_text(json.dumps(policy));server.start()
        for version in a.versions:
            entries=load_entries(version,a.filter);names=sorted(entries)
            corpus_keys=corpus_private_keys(load_entries(version,''))
            legacy=inventory['legacy_archives'].get(version)
            # Only an archive without traces is delegated; a filter that matches
            # nothing in another version simply selects no case there.
            if not names and legacy and not a.filter:
                report.append({'version':version,'case':'(archive)','status':'delegated','detail':legacy['explanation']})
            done=set()
            for index,name in enumerate(names):
                if name in done:continue
                cid=case_id(name);key=(version,cid);entry={'version':version,'case':name}
                try:root=ET.fromstring(entries[name])
                except ET.ParseError as e:
                    report.append({**entry,'status':'failed','detail':'XML parse error: '+str(e)});continue
                if root.tag!='KMIP':
                    report.append({**entry,'status':'excluded_non_trace','detail':inventory['non_traces']['rule']});continue
                chain=[name]
                if key in sequences:
                    seq=sequences[key];chain=[]
                    for member in seq['chain']:
                        found=[n for n in names if case_id(n)==member and pathlib.PurePosixPath(n).parent==pathlib.PurePosixPath(name).parent]
                        chain+=found
                fixture=inventory['authorization_fixtures'].get(cid)
                wants_endpoint=query_expects_server_to_client([e for e in root if e.tag in ('RequestMessage','ResponseMessage')])
                if wants_endpoint and endpoint is None:endpoint=ClientEndpoint(server.pki)
                configure(f'{version}-{index}',fixture['client_operations'] if fixture else None,endpoint.policy(server.pki,version) if wants_endpoint else None)
                replay=Replay(version,corpus_keys);previous_ok=True
                for member in chain:
                    done.add(member);member_entry={'version':version,'case':member,'transformations':[]}
                    if fixture:member_entry['transformations'].append(fixture['label'])
                    if wants_endpoint:member_entry['transformations'].append(inventory['server_to_client_fixture']['label'])
                    if len(chain)>1:member_entry['transformations'].append('sequenced after '+', '.join(case_id(c) for c in chain[:chain.index(member)]) if chain.index(member) else 'sequence start: '+' -> '.join(case_id(c) for c in chain))
                    if not previous_ok:
                        report.append({**member_entry,'status':'unexecuted','category':'prerequisite_failed','detail':'an earlier case in its sequence did not pass'});continue
                    if member!=name:
                        replay.vars={};replay.obligations=[];replay.created_ids={};replay.subst={}
                        member_entry['transformations'].append('server-generated object set and key material carried from earlier sequence cases')
                    replay.last_actual=None
                    try:
                        messages=[e for e in ET.fromstring(entries[member]) if e.tag in ('RequestMessage','ResponseMessage')]
                        for edit in fixtures.get(f'{version}|{member}',[]):
                            target=messages[edit['message']].find(edit['path'])
                            if target is None or target.get('value')!=edit['from']:raise RuntimeError(f'corrected fixture does not match the pinned trace: {member} {edit["path"]}')
                            target.set('value',edit['to'])
                            label=f'corrected fixture ({edit["family"]}): {edit["why"]}'
                            if label not in member_entry['transformations']:member_entry['transformations'].append(label)
                        if not messages:raise Unsupported('no message trace')
                        run_case(server,replay,version,messages,inventory,member_entry)
                        open_=finish(replay)
                        member_entry['obligations']=[o.record() for o in replay.obligations]
                        if open_:
                            member_entry['status']='unverified';member_entry['detail']='; '.join(f'{o.kind} at {o.path}: {o.info.get("unverifiable","not verified")}' for o in open_)
                        else:member_entry['status']='passed'
                    except Unsupported as e:member_entry.update(status='unexecuted',detail=str(e),category=e.category)
                    except (AssertionError,ValueError,KeyError,ET.ParseError,OSError,EOFError) as e:
                        member_entry.update(status='failed',detail=str(e) or type(e).__name__,category='trace_mismatch')
                        if getattr(replay,'last_actual',None) is not None and a.diagnose:member_entry['actual_response']=render(replay.last_actual)
                    member_entry['variations']=sorted(replay.variations|HARNESS_NOTES);replay.variations=set();HARNESS_NOTES.clear()
                    if replay.material_gets:member_entry['independent_material_gets']=len(replay.material_gets);replay.material_gets=[]
                    previous_ok=member_entry['status']=='passed'
                    report.append(member_entry)
                server.stop()
            summary={s:sum(e['status']==s for e in report if e['version']==version) for s in ['passed','unverified','failed','unexecuted','excluded_non_trace','delegated']};print(version,summary,flush=True)
    summary={s:sum(e['status']==s for e in report) for s in ['passed','unverified','failed','unexecuted','excluded_non_trace','delegated']}
    a.output.write_text(json.dumps({'status':'complete','mode':'profiles-4.1-variations'+('+corrected-fixtures' if a.corrected_fixtures else ''),'conformance_credit':'none; separately labelled variation mode, the strict report is unchanged','selection':{'versions':a.versions,'filter':a.filter},'runtime_binary_sha256':binary_sha,'source_commit':source_commit()[0],'summary':summary,'cases':report},indent=2)+'\n')
    print(summary)
if __name__=='__main__':main()
