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

"""Replay official OASIS XML message traces over binary mTLS.
All cases are reported, including parser limitations and unsupported features.
This compares message semantics; it does not certify transport/profile conformance.
"""
import argparse,datetime,hashlib,json,pathlib,re,subprocess,tempfile,time,xml.etree.ElementTree as ET,zipfile
from test_runtime import ROOT,Server
from wire import *
from image_evidence import source_commit
REG=json.loads((ROOT/'docs/specs/registry.json').read_text());TAGS=REG['tags'];ENUMS=REG['enums']
def normalized(s):return re.sub('[^A-Za-z0-9]','',s)
TYPES={'Structure':1,'Integer':2,'LongInteger':3,'BigInteger':4,'Enumeration':5,'Boolean':6,'TextString':7,'ByteString':8,'DateTime':9,'Interval':10,'DateTimeExtended':11,'Identifier':12,'Reference':13,'NameReference':14}
class Unsupported(Exception):
    def __init__(self,detail,category='harness_limitation'):
        super().__init__(detail);self.category=category

def preflight(messages):
    if not messages:raise Unsupported('no message trace')
    # Interop is a test-server control operation, expressly prohibited on a
    # production server (2.1 section 6.1.26). Do not enable it in this listener
    # or silently strip controls and call the resulting trace unmodified.
    if any(e.get('value')=='Interop' for m in messages if m.tag=='RequestMessage' for e in m.iter('Operation')):
        raise Unsupported('trace requires the test-only Interop operation, prohibited on production servers; separate test fixture required','test_only_control_operation')
    created=any(e.get('value') in ['Create','CreateKeyPair'] for m in messages if m.tag=='RequestMessage' for e in m.iter('Operation'))
    fixed_generated=any(e.get('value','') and not e.get('value','').startswith('$') for m in messages if m.tag=='ResponseMessage' for tag in ['KeyMaterial','DigestValue'] for e in m.iter(tag))
    if created and fixed_generated:
        raise Unsupported('trace contains fixed key material/digests after key generation; deterministic test-only fixture required','deterministic_fixture_required')
    generated=set();placeholder=None;stored_parameters={}
    for req,resp in zip(messages[::2],messages[1::2]):
        for request_item,response_item in zip(req.findall('BatchItem'),resp.findall('BatchItem')):
            operation=request_item.find('Operation');request=request_item.find('RequestPayload');response=response_item.find('ResponsePayload')
            if operation is None or request is None or response is None:continue
            op=operation.get('value');uid=request.find('UniqueIdentifier')
            identifier=uid.get('value') if uid is not None else placeholder
            cp=request.find('CryptographicParameters')
            if cp is None:cp=stored_parameters.get(identifier)
            if cp is not None:
                padding=cp.find('PaddingMethod');signature=cp.find('DigitalSignatureAlgorithm');salt=cp.find('SaltLength')
                pad=normalized(padding.get('value','')) if padding is not None else ''
                sig=normalized(signature.get('value','')) if signature is not None else ''
                probabilistic=op=='Encrypt' and pad in ['OAEP','PKCS1v15','PKCS1V15'] or op=='Sign' and (pad=='PSS' or sig.startswith('RSASSAPSS')) and (salt is None or salt.get('value')!='0')
                output=response.find('Data' if op=='Encrypt' else 'SignatureData')
                if probabilistic and output is not None and output.get('value','') and not output.get('value').startswith('$'):
                    raise Unsupported('trace compares randomized RSA padding output with fixed sample bytes even with a registered key; deterministic test-only fixture required','deterministic_fixture_required')
            if op in ['Encrypt','Decrypt','Sign','MAC'] and identifier in generated:
                fixed=any((e:=response.find(tag)) is not None and e.get('value','') and not e.get('value').startswith('$') for tag in ['Data','SignatureData','MACData','AuthenticatedEncryptionTag'])
                if fixed:raise Unsupported('trace compares a generated key\'s cryptographic output with fixed sample bytes; deterministic test-only fixture required','deterministic_fixture_required')
            if op in ['Create','CreateKeyPair','Rekey']:
                returned=[e.get('value') for e in response if e.tag in ['UniqueIdentifier','PrivateKeyUniqueIdentifier','PublicKeyUniqueIdentifier']]
                generated.update(returned)
                if returned:placeholder=returned[0]
            elif op=='Register':
                uid=response.find('UniqueIdentifier')
                if uid is not None:
                    placeholder=uid.get('value');generated.discard(placeholder)
                    cp=request.find('./Attributes/CryptographicParameters')
                    if cp is None:
                        for attr in request.iter('Attribute'):
                            name=attr.find('AttributeName')
                            if name is not None and normalized(name.get('value',''))=='CryptographicParameters':
                                cp=attr.find('AttributeValue');break
                    if cp is not None:stored_parameters[placeholder]=cp
    for req,resp in zip(messages,messages[1:]):
        if req.tag=='RequestMessage' and resp.tag=='ResponseMessage':
            for a,b in zip(req.findall('BatchItem'),resp.findall('BatchItem')):
                op=a.find('Operation');data=b.find('./ResponsePayload/Data')
                if op is not None and op.get('value')=='RNGRetrieve' and data is not None and not data.get('value','').startswith('$'):
                    raise Unsupported('trace compares CSPRNG output with fixed sample bytes; deterministic test-only fixture required','deterministic_fixture_required')
def fixture_constants(messages):
    # CS-AC-M-6 publishes a literal known-answer MAC, then references $MAC_DATA
    # without declaring it in an expected response. Resolve only an unambiguous
    # fixed fixture value. compare() still checks the entire prior response,
    # including exact tag/type/value; no actual crypto output is accepted as an oracle.
    values={n.get('value','') for m in messages if m.tag=='ResponseMessage'
            for n in m.findall('./BatchItem/ResponsePayload/MACData')
            if n.get('type')=='ByteString' and not n.get('value','').startswith('$')}
    if len(values)==1:
        return {'$MAC_DATA':bytes.fromhex(next(iter(values)))}
    return {}

def enum_value(name,value):
    if re.fullmatch('0x[0-9a-fA-F]+',value):return int(value,16)
    if re.fullmatch('[0-9]+',value):return int(value)
    key=normalized(value)
    if name=='AttributeReference' and key in TAGS:return TAGS[key]
    # Identifier fields share the Unique Identifier enumeration table
    # (2.1 section 11.58), matching the wire registry aliases.
    name={'BatchErrorContinuationOption':'BatchErrorContinuation','MaskGeneratorHashingAlgorithm':'HashingAlgorithm','UniqueIdentifier':'UniqueIdentifierEnumerations','PrivateKeyUniqueIdentifier':'UniqueIdentifierEnumerations','PublicKeyUniqueIdentifier':'UniqueIdentifierEnumerations','LinkedObjectIdentifier':'UniqueIdentifierEnumerations'}.get(name,name)
    if name=='CryptographicAlgorithm' and value=='DES3':value='3DES';key='3DES'
    choices=ENUMS.get(normalized(name),{})
    if key in choices:return choices[key]
    raise Unsupported(f'enumeration {name}={value}')
def encode_xml(e,variables,context=None):
    name=e.tag;tag=TAGS.get(name,TAGS.get(normalized(name)))
    if tag is None:raise Unsupported('unknown tag '+name)
    kind=TYPES.get(e.get('type','Structure'))
    if kind is None:raise Unsupported('unknown type '+str(e.get('type')))
    if kind==1:
        a=e.find('AttributeName');ctx=normalized(a.get('value')) if name=='Attribute' and a is not None else None
        return node(tag,kind,[encode_xml(c,variables,ctx) for c in e])
    value=e.get('value','')
    if value.startswith('$'):
        if value.startswith('$NOW'):
            match=re.fullmatch(r'\$NOW([+-][0-9]+)?',value)
            if not match:raise Unsupported('time expression '+value)
            return node(tag,kind,int(time.time())+int(match.group(1) or 0))
        if value not in variables:raise Unsupported('unbound variable '+value)
        return node(tag,kind,variables[value])
    field=context if name=='AttributeValue' and context else name
    if kind==5:value=enum_value(field,value)
    elif kind in (2,3,10,11):
        try:value=int(value,0) if value.startswith('0x') else int(value)
        except ValueError:
            choices=ENUMS.get(field,{})
            if not choices:raise Unsupported('symbolic integer '+field+'='+value)
            mask=0
            for part in value.split():
                if normalized(part) not in choices:raise Unsupported('bitmask '+value)
                mask|=choices[normalized(part)]
            value=mask
    elif kind==6:value=int(value.lower()=='true')
    elif kind in (4,8):value=bytes.fromhex(value.replace(' ',''))
    elif kind==9:value=int(datetime.datetime.fromisoformat(value.replace('Z','+00:00')).timestamp())
    return node(tag,kind,value)
def shown(value):
    # Failure details name both sides so mismatches can be triaged from the report.
    return value.hex() if isinstance(value,bytes) else value
def compare(expected,actual,variables,context=None,path='',ignore_result_message_text=False,message_text_mismatches=None,operation=None):
    name=expected.tag;tag=TAGS.get(name,TAGS.get(normalized(name)));path+='/'+name
    if tag is None:raise Unsupported('unknown expected tag '+name)
    assert actual[0]==tag,path+' tag mismatch'
    kind=TYPES.get(expected.get('type','Structure'))
    if kind is None:raise Unsupported('unknown expected type '+str(expected.get('type')))
    assert kind==actual[1],path+' type mismatch'
    # Diagnostic mode changes only literal message wording; tag, primitive
    # type, surrounding field counts, status and reason remain exact.
    if ignore_result_message_text and name=='ResultMessage' and kind==7 and not expected.get('value','').startswith('$'):
        if expected.get('value','')!=actual[2] and message_text_mismatches is not None:message_text_mismatches.append(path)
        return
    if kind==1:
        if name=='BatchItem':
            op=expected.find('Operation');operation=op.get('value') if op is not None else None
            wanted=expected.find('ResultStatus')
            if wanted is not None:
                got=children(actual,0x42007f)
                if not got or got[0][2]!=enum_value('ResultStatus',wanted.get('value')):
                    reasons=children(actual,0x42007e);messages=children(actual,0x42007d)
                    raise AssertionError(path+' ResultStatus mismatch; reason='+str(reasons[0][2] if reasons else None)+'; message='+repr(messages[0][2] if messages else None))
        a=expected.find('AttributeName');ctx=normalized(a.get('value')) if name=='Attribute' and a is not None else None
        # Attribute collections are unordered. Match their identity (including
        # the optional index/vendor), while retaining exact counts and values.
        # Other repeated fields, including BatchItem, retain trace order.
        for child_tag in dict.fromkeys(TAGS.get(c.tag) for c in expected):
            exp=[c for c in expected if TAGS.get(c.tag)==child_tag];got=children(actual,child_tag)
            # KMIP 1.x section 2.1.1: an omitted Attribute Index SHALL be
            # assumed to be 0, so an explicit index 0 and an omitted index are equal.
            if name=='Attribute' and child_tag==TAGS['AttributeIndex'] and not got and [e.get('value') for e in exp]==['0']:continue
            if len(exp)!=len(got):
                detail=''
                if not exp[0].get('type','Structure')=='Structure':
                    detail=f'; expected {[e.get("value") for e in exp]}, received {[shown(n[2]) for n in got]}'
                raise AssertionError(path+f'/{exp[0].tag}: expected {len(exp)} fields, received {len(got)}'+detail)
            if child_tag==TAGS['Attribute']:
                def expected_key(e):
                    attribute,index,vendor=(encode_xml(c,variables)[2] if c is not None else None for c in [e.find(n) for n in ['AttributeName','AttributeIndex','VendorIdentification']])
                    return attribute,0 if index is None else index,vendor
                def actual_key(n):
                    attribute,index,vendor=(c[2] if c is not None else None for c in [next(iter(children(n,TAGS[t])),None) for t in ['AttributeName','AttributeIndex','VendorIdentification']])
                    return attribute,0 if index is None else index,vendor
                ordered=[];remaining=list(got)
                for e in exp:
                    matches=[(i,n) for i,n in enumerate(remaining) if actual_key(n)==expected_key(e)]
                    assert matches,path+'/Attribute identity missing'
                    i,n=matches[0];ordered.append(n);remaining.pop(i)
                got=ordered
            # Get Attribute List returns a list of names without a defined
            # order (1.4 table 199; 2.1 table 227). Match each name exactly once.
            if operation=='GetAttributeList' and name=='ResponsePayload' and child_tag in (TAGS['AttributeName'],TAGS['AttributeReference']):
                ordered=[];remaining=list(got)
                for e in exp:
                    for i,n in enumerate(remaining):
                        trial=dict(variables)
                        try:compare(e,n,trial,ctx,path,ignore_result_message_text,None,operation)
                        except AssertionError:continue
                        ordered.append(n);remaining.pop(i);break
                    else:raise AssertionError(path+f'/{e.tag} value missing; expected {e.get("value")}, unmatched {[shown(n[2]) for n in remaining]}')
                got=ordered
            for e,a in zip(exp,got):compare(e,a,variables,ctx,path,ignore_result_message_text,message_text_mismatches,operation)
        return
    value=expected.get('value','')
    if name=='ServerCorrelationValue':
        assert kind==7 and actual[2],path+' must be a nonempty server-generated value'
        if value.startswith('$'):variables[value]=actual[2]
        return
    if value.startswith('$'):
        relative=re.fullmatch(r'\$NOW([+-][0-9]+)?',value)
        if relative:
            assert abs(actual[2]-(int(time.time())+int(relative.group(1) or 0)))<120,path+' invalid timestamp'
            return
        if value not in variables:variables[value]=actual[2]
        assert variables[value]==actual[2],path+' variable changed';return
    want=encode_xml(expected,variables,context)
    assert want[2]==actual[2],path+f' value mismatch; expected {shown(want[2])}, received {shown(actual[2])}'

def main():
    parser=argparse.ArgumentParser();parser.add_argument('--skip-build',action='store_true',help='use the existing target/debug executable');parser.add_argument('--binary',type=pathlib.Path,help='run this executable instead of target/debug (implies --skip-build)');parser.add_argument('--versions',nargs='+',default=['1.1','1.2','1.3','1.4','2.0','2.1','3.0']);parser.add_argument('--filter',default='');parser.add_argument('--report-only',action='store_true');parser.add_argument('--output',type=pathlib.Path,default=ROOT/'artifacts/oasis.json');parser.add_argument('--ignore-result-message-text',action='store_true',help='Diagnostic only: retain types/counts/status/reasons but ignore literal Result Message wording');a=parser.parse_args()
    if a.ignore_result_message_text and a.output.resolve()==(ROOT/'artifacts/oasis.json').resolve():parser.error('diagnostic mode requires a separate --output; canonical strict results must be preserved')
    a.output.parent.mkdir(parents=True,exist_ok=True)
    a.output.write_text(json.dumps({'status':'running','selection':{'versions':a.versions,'filter':a.filter}})+'\n')
    subprocess.run(['python3',str(ROOT/'scripts/fetch_specs.py')],check=True)
    if not a.skip_build and not a.binary:subprocess.run(['cargo','build','--locked'],cwd=ROOT,check=True)
    binary=(a.binary or ROOT/'target/debug/keytend-kmip-server').resolve();binary_sha256=hashlib.sha256(binary.read_bytes()).hexdigest()
    report=[]
    with tempfile.TemporaryDirectory(prefix='keytend-kmip-server-oasis-') as d:
        server=Server(d,binary=binary,draft=True)
        for version in a.versions:
            archive=ROOT/f'.cache/specs/profiles-{version}.zip'
            with zipfile.ZipFile(archive) as z:
                entries={n:z.read(n) for n in z.namelist() if n.endswith('.xml') and a.filter in n}
            for extra in json.loads((ROOT/'docs/specs/additional-traces.json').read_text()):
                name='additional/'+extra['filename']
                if extra['version']==version and a.filter in name:
                    raw=(ROOT/'.cache/specs'/extra['filename']).read_bytes()
                    if hashlib.sha256(raw).hexdigest()!=extra['sha256']:raise RuntimeError('additional trace checksum mismatch: '+name)
                    entries[name]=raw
            names=sorted(entries)
            if not names:report.append({'version':version,'case':'(archive)','status':'unexecuted','completed_exchanges':0,'detail':'profile archive contains no XML traces; legacy test-case document coverage pending'})
            for index,name in enumerate(names):
                entry={'version':version,'case':name,'status':'unexecuted','completed_exchanges':0}
                variables={};message_text_mismatches=[];server.stop()
                # Names are server-global in CSD02. Isolate the entire store,
                # not only ownership, so independent cases cannot collide.
                server.data=pathlib.Path(d)/'data'/f'case-{len(report)}';server.data.mkdir(mode=0o700)
                # Isolate each case's ownership namespace to avoid cross-case Locate contamination.
                policy=json.loads((server.pki/'policy.json').read_text())
                for principal in policy['principals'].values():principal['name']=f'oasis-{version}-{index}'
                (server.pki/'policy.json').write_text(json.dumps(policy))
                try:
                    root=ET.fromstring(entries[name]);messages=[e for e in root if e.tag in ['RequestMessage','ResponseMessage']]
                    preflight(messages)
                    variables.update(fixture_constants(messages))
                    server.start()
                    with server.connect() as connection:
                        for i in range(0,len(messages),2):
                            if messages[i].tag!='RequestMessage' or i+1>=len(messages) or messages[i+1].tag!='ResponseMessage':raise Unsupported('non-alternating message trace')
                            req=encode_xml(messages[i],variables);entry['failed_exchange']=i//2
                            response=exchange(connection,req)
                            entry['status']='failed'
                            compare(messages[i+1],response,variables,ignore_result_message_text=a.ignore_result_message_text,message_text_mismatches=message_text_mismatches)
                            entry['completed_exchanges']+=1
                    entry['status']='passed'
                except Unsupported as e:entry['status']='unexecuted';entry['detail']=str(e);entry['category']=e.category
                except (AssertionError,ValueError,ET.ParseError,OSError,EOFError) as e:entry['status']='failed';entry['detail']=str(e);entry['category']='trace_mismatch'
                else:entry.pop('failed_exchange',None)
                finally:server.stop()
                if a.ignore_result_message_text:entry['result_message_text_mismatches']=message_text_mismatches
                report.append(entry)
            summary={s:sum(e['status']==s for e in report if e['version']==version) for s in ['passed','failed','unexecuted']};print(version,summary,flush=True)
    summary={s:sum(e['status']==s for e in report) for s in ['passed','failed','unexecuted']}
    status='passed' if report and all(e['status']=='passed' for e in report) else 'failed'
    a.output.write_text(json.dumps({'status':status,'scope':'official message traces over TTLV; transport and full profile conformance not certified','comparison_policy':'diagnostic_literal_message_text_ignored' if a.ignore_result_message_text else 'strict','diagnostic_only':a.ignore_result_message_text,'selection':{'versions':a.versions,'filter':a.filter},'source_commit':source_commit()[0],'runtime_binary_sha256':binary_sha256,'case_isolation':'independent encrypted database per case','summary':summary,'cases':report},indent=2)+'\n');print(summary)
    if not report or any(e['status']!='passed' for e in report):
        if not a.report_only:raise SystemExit(1)
if __name__=='__main__':main()
