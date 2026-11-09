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

"""Offline checks that the legacy test-case harness cannot pass a wrong server or a drifted document.

Uses the pinned OASIS documents from .cache/specs/legacy (fetched and
checksum-verified on first use) and a scripted in-process responder; no
server, container or network listener is started.

HarnessNegativeTests also load the first candidate harness from
Git commit 78ecca7 and show that each repaired negative was accepted (or
misclassified) there and is rejected now. Historical comparisons are optional when that commit is unavailable;
all current-harness rejection tests still run. Set KEYTEND_LEGACY_COMPARE_HISTORY=0
to verify the history-independent path.
"""
import copy,hashlib,importlib.util,json,os,pathlib,subprocess,sys,tempfile,time,types,unittest
import oasis_legacy as L
import legacy_wire as W
from oasis_conformance import Unsupported,encode_xml,enum_value
from wire import encode,decode

DOCUMENTS=L.load();LEDGER=json.loads(L.LEDGER.read_text())
CASES={case['id']:case for item,cases in DOCUMENTS.values() for case in cases}
ROWS={c['id']:c for c in LEDGER['cases']}
RFC3394_4_1={'kek':'000102030405060708090a0b0c0d0e0f','key':'00112233445566778899aabbccddeeff','wrapped':'1fa68b0a8112b447aef34bd8fb5a7b829d3e862371d2cfe5'}
CANDIDATE='78ecca7982f1e0ebd53955dae33a6bd4b5d659c3'

class Responder:
    """Answer each request with the official response as raw TTLV, assigning its own identifiers.

    It also requires each request to equal the official request after the
    identifiers it assigned earlier are substituted, so input binding across
    exchanges is checked as well as response comparison. tamper(i,node)
    edits the response node; raw(i,bytes) edits the encoded bytes.
    """
    def __init__(self,messages,tamper=None,raw=None,ids=None):
        self.messages=messages;self.ids={};self.index=0;self.tamper=tamper or (lambda i,n:n);self.raw=raw or (lambda i,b:b)
        self.assign=ids or (lambda symbol,n:f'server-{n}')
    def __call__(self,request):
        i=self.index;self.index+=1
        assert request==encode_xml(self.messages[2*i],self.ids),f'exchange {i}: request differs from the official request'
        expected=self.messages[2*i+1]
        for e in expected.iter():
            value=e.get('value','')
            if value.startswith('$') and not value.startswith('$NOW') and value not in self.ids:self.ids[value]=self.assign(value,len(self.ids))
        n=self.tamper(i,encode_xml(expected,self.ids))
        return None if n is None else self.raw(i,encode(n))

def replace(n,tag,value):
    if n[0]==tag:return (n[0],n[1],value)
    return (n[0],n[1],[replace(c,tag,value) for c in n[2]]) if n[1]==1 else n
def edit(n,tag,f):
    """Apply f to the child list of every structure with this tag."""
    if n[1]!=1:return n
    children=[edit(c,tag,f) for c in n[2]]
    return (n[0],n[1],f(children) if n[0]==tag else children)

class LegacyHarnessTests(unittest.TestCase):
    def test_documents_match_the_committed_ledger_and_case_counts(self):
        self.assertEqual(L.verify(DOCUMENTS,LEDGER),[])
        self.assertEqual({k:v['case_count'] for k,v in LEDGER['documents'].items()},{'KMIP Test Cases 1.1 CN01':36,'KMIP Test Cases 1.2 CN01':119})
        groups={suffix:sum(c['id'].endswith(suffix) for c in LEDGER['cases'] if c['document'].endswith('1.2 CN01')) for suffix in ['-10','-11','-12']}
        self.assertEqual(groups,{'-10':29,'-11':41,'-12':49})
        # Every case is either selected with a rationale or carries a named blocker.
        for case in LEDGER['cases']:
            self.assertTrue(case.get('rationale') if case['status']=='SELECTED' else case['status']=='NOT EXECUTED' and case['blockers'],case['id'])

    def test_wrong_case_counts_identifiers_digests_or_classification_are_rejected(self):
        for mutate in [lambda l:l['documents']['KMIP Test Cases 1.1 CN01'].update(case_count=35),
                       lambda l:l['cases'].pop(3),
                       lambda l:l['cases'][0].update(messages_sha256='0'*64),
                       lambda l:l['cases'][0].update(exchanges=3),
                       lambda l:l['cases'][40].update(protocol_versions=['1.2']),
                       lambda l:l['cases'][0].update(section='3.1.9'),
                       lambda l:l['cases'][0].update(title='Other'),
                       lambda l:l['cases'][5].update(blockers=['not_selected: x']),
                       lambda l:ROWS_IN(l)['KMIP-TC-1.1-7.1'].update(listing_mismatches=[0]),
                       lambda l:ROWS_IN(l)['KMIP-TC-1.1-7.1'].pop('document_defects'),
                       lambda l:ROWS_IN(l)['TC-141-11'].update(exchange_versions=['1.1']*7),
                       lambda l:ROWS_IN(l)['TC-71-12'].pop('policy_notes'),
                       lambda l:ROWS_IN(l)['TC-92-12'].update(status='SELECTED',rationale='x')]:
            ledger=copy.deepcopy(LEDGER);mutate(ledger)
            self.assertTrue(L.verify(DOCUMENTS,ledger))

    def test_selected_cases_replay_against_a_conforming_responder(self):
        for row in LEDGER['cases']:
            if row['status']!='SELECTED':continue
            messages,rules=L.bind_dynamic(CASES[row['id']])
            self.assertLessEqual({r[0] for r in rules},{'L1','L2'})
            progress={}
            self.assertEqual(L.replay(messages,Responder(messages),progress),row['exchanges'],row['id'])
            self.assertEqual(progress['versions'],row['exchange_versions'],row['id'])

    def test_binding_does_not_mutate_the_pinned_documents(self):
        before=L.inventory(*DOCUMENTS['KMIP Test Cases 1.1 CN01'])
        for case in DOCUMENTS['KMIP Test Cases 1.1 CN01'][1]:L.bind_dynamic(case)
        self.assertEqual(L.inventory(*DOCUMENTS['KMIP Test Cases 1.1 CN01']),before)

    def test_known_answer_is_the_full_rfc3394_vector_in_both_notes(self):
        for case in ['KMIP-TC-1.1-14.1','TC-141-11','TC-141-12']:
            messages,_=L.bind_dynamic(CASES[case])
            byte_strings=lambda i,tag:[e.get('value') for e in messages[i].iter(tag) if e.get('type')=='ByteString']
            # Register KEK (exchange 0), register the key (exchange 1), Get wrapped by the KEK (exchange 2).
            self.assertEqual(byte_strings(0,'KeyMaterial'),[RFC3394_4_1['kek']],case)
            self.assertEqual(byte_strings(2,'KeyMaterial'),[RFC3394_4_1['key']],case)
            self.assertEqual(byte_strings(5,'KeyValue'),[RFC3394_4_1['wrapped']],case)
            kek=messages[1].find('.//ResponsePayload/UniqueIdentifier').get('value');key=messages[3].find('.//ResponsePayload/UniqueIdentifier').get('value')
            self.assertEqual(messages[4].find('./BatchItem/RequestPayload/UniqueIdentifier').get('value'),key,case)
            self.assertEqual(messages[4].find('.//KeyWrappingSpecification/EncryptionKeyInformation/UniqueIdentifier').get('value'),kek,case)
            self.assertNotEqual(kek,key)
        try:from cryptography.hazmat.primitives.keywrap import aes_key_wrap
        except ImportError:self.skipTest('cryptography not installed; RFC 3394 constants checked only')
        self.assertEqual(aes_key_wrap(bytes.fromhex(RFC3394_4_1['kek']),bytes.fromhex(RFC3394_4_1['key'])).hex(),RFC3394_4_1['wrapped'])

    def failure(self,case,tamper=None,raw=None,ids=None,pattern=None):
        messages,_=L.bind_dynamic(CASES[case])
        with self.assertRaises((AssertionError,EOFError)) as caught:L.replay(messages,Responder(messages,tamper,raw,ids))
        if pattern:self.assertRegex(str(caught.exception),pattern)
        return caught.exception

    def test_tampered_wrapped_key_fails(self):
        wrapped=bytes.fromhex(RFC3394_4_1['wrapped'])
        def flip(i,n):return replace(n,0x420045,bytes([wrapped[0]^1])+wrapped[1:]) if i==2 else n
        self.failure('TC-141-12',flip);self.failure('KMIP-TC-1.1-14.1',flip)

    def test_wrong_protocol_version_fails(self):
        for case in ['TC-315-12','KMIP-TC-1.1-3.1.5','TC-315-10']:
            self.failure(case,lambda i,n:replace(n,0x42006b,4))

    def test_wrong_operation_status_or_batch_count_fails(self):
        self.failure('TC-311-12',lambda i,n:replace(n,0x42005c,3) if i==1 else n)
        self.failure('TC-311-12',lambda i,n:replace(n,0x42007f,1))
        self.failure('TC-311-12',lambda i,n:replace(n,0x42000d,2))

    def test_extra_response_fields_fail_and_are_labelled(self):
        def reason(i,n):
            header,item=n[2];return (n[0],n[1],[header,(item[0],item[1],item[2][:2]+[(0x42007e,5,1)]+item[2][2:])])
        self.failure('TC-315-12',reason,pattern='permitted OPTIONAL by the section 7 table')
        def attribute(i,n):
            header,item=n[2];payload=item[2][-1]
            extra=(payload[0],1,payload[2]+[(0x420094,7,'second')])
            return (n[0],n[1],[header,(item[0],item[1],item[2][:-1]+[extra])])
        self.failure('KMIP-TC-1.1-3.1.5',attribute,pattern='expected 1 fields, received 2')
        # A field type absent from the official payload is caught by shape(), not compare().
        def object_type(i,n):
            header,item=n[2];payload=item[2][-1]
            return (n[0],n[1],[header,(item[0],item[1],item[2][:-1]+[(payload[0],1,[(0x420057,5,7)]+payload[2])])])
        self.failure('TC-315-12',object_type,pattern='field set differs; unexpected 0x420057 \\(payload table legality not checked')
        # A header field the version's table does not define fails before comparison.
        self.failure('TC-315-12',lambda i,n:edit(n,0x42007a,lambda c:c[:1]+[(0x420007,6,1)]+c[1:]),pattern='not permitted in ResponseHeader')

    def test_missing_exchange_or_closed_connection_fails(self):
        self.failure('TC-311-11',lambda i,n:None if i==1 else n)
        def closed(i,n):
            if i==1:raise EOFError('connection closed')
            return n
        self.failure('KMIP-TC-1.1-3.1.1',closed)

    def test_identifier_binding_and_timestamp_are_enforced(self):
        # A Destroy that answers with a different identifier than Register returned.
        self.failure('TC-315-11',lambda i,n:replace(n,0x420094,'other') if i==1 else n)
        self.failure('KMIP-TC-1.1-3.1.5',lambda i,n:replace(n,0x420094,'other') if i==1 else n)
        self.failure('TC-315-12',lambda i,n:replace(n,0x420092,int(time.time())-3600))

    def test_document_hex_defects_are_rejected(self):
        raw=CASES['KMIP-TC-1.1-3.1.5']['messages'][0]['raw']
        for bad in [raw[:-8],raw+b'\0'*8,raw[:-1]+b'\1',raw[:3]+b'\2'+raw[4:]]:
            with self.assertRaises(ValueError):L.ttlv(bad)
        self.assertEqual(encode(L.ttlv(raw)),raw)

    def test_unselected_cases_keep_their_blockers(self):
        self.assertTrue(ROWS['TC-313-12']['blockers'][0].startswith('deterministic_fixture_required'))
        self.assertTrue(any(b.startswith('server_capability_dependent') for b in ROWS['KMIP-TC-1.1-16.1']['blockers']))
        self.assertTrue(ROWS['KMIP-TC-1.1-7.1']['blockers'][0].startswith('document_defect'))
        self.assertTrue(any(b.startswith('server_initiated_operation') for b in ROWS['TC-NP-2-12']['blockers']))
        messages,_=L.bind_dynamic(CASES['TC-313-12'])
        with self.assertRaises(Unsupported):L.replay(messages,Responder(messages))

def ROWS_IN(ledger):return {c['id']:c for c in ledger['cases']}

def candidate():
    """Import oasis_legacy.py as published in the first candidate commit."""
    if os.environ.get('KEYTEND_LEGACY_COMPARE_HISTORY')=='0':return None
    try:source=subprocess.run(['git','show',f'{CANDIDATE}:scripts/oasis_legacy.py'],cwd=L.ROOT,check=True,capture_output=True,text=True).stdout
    except (OSError,subprocess.CalledProcessError):return None
    module=types.ModuleType('oasis_legacy_candidate');module.__file__=str(L.ROOT/'scripts/oasis_legacy.py')
    exec(compile(source,f'{CANDIDATE[:7]}:scripts/oasis_legacy.py',"exec"),module.__dict__);return module
OLD=candidate()
OLD_DOCS=OLD.load() if OLD else None
OLD_CASES={case['id']:case for item,cases in OLD_DOCS.values() for case in cases} if OLD else {}

class HarnessNegativeTests(unittest.TestCase):
    """Each negative the first candidate harness accepted is rejected by the corrected harness."""
    def old_replay(self,case,**kw):
        # The candidate's live path decoded with the permissive wire.decode().
        messages,_=OLD.bind_dynamic(OLD_CASES[case]);responder=Responder(messages,**kw)
        def send(request):
            raw=responder(request);return None if raw is None else decode(raw)
        return OLD.replay(messages,send)
    def new_failure(self,case,pattern,**kw):
        messages,_=L.bind_dynamic(CASES[case])
        with self.assertRaisesRegex(AssertionError,pattern):L.replay(messages,Responder(messages,**kw))

    # Every case is encoded offline; exact blockers, no alias normalization.
    def test_offline_encoding_finds_blockers_the_candidate_called_not_selected(self):
        expected=sorted([f'TC-{n}-{v}' for n in ['71','72','92','93','94','134'] for v in ['10','11','12']]+[f'TC-{n}-{v}' for n in ['151','152','132','ECC-3'] for v in ['11','12']])
        self.assertEqual(len(expected),26)
        for case in expected:self.assertTrue(ROWS[case]['blockers'][0].startswith('encoding_blocker'),case)
        if OLD:
            old_rows={r['id']:r for name,(item,cases) in OLD_DOCS.items() for r in OLD.inventory(item,cases)}
            misclassified=sorted(i for i,c in OLD_CASES.items() if ROWS[i]['status']!='SELECTED' and OLD.classify(c,old_rows[i])[0].startswith('not_selected') and ROWS[i]['blockers'][0].startswith('encoding_blocker'))
            self.assertEqual(misclassified,expected)
        self.assertIn('enumeration Operation=ReKey [message 8 (request, exchange 4); message 9 (response, exchange 4)]',ROWS['TC-92-12']['blockers'][0])
        self.assertTrue(any('RevocationReasonCode=CessationOfOperation' in b for b in ROWS['TC-94-10']['blockers']))
        self.assertTrue(any('Operation=ReCertify' in b for b in ROWS['TC-134-11']['blockers']))
        self.assertTrue(any('ObjectGroupMember=GroupMemberFresh' in b for b in ROWS['TC-152-12']['blockers']))
        self.assertTrue(any('DigitalSignatureAlgorithm=ECDSAWithSHA256' in b for b in ROWS['TC-ECC-3-11']['blockers']))
        self.assertEqual(ROWS['TC-71-11']['blockers'],['encoding_blocker: unknown tag TTLV [message 0 (request, exchange 0)]'])
        # Published spellings are not silently aliased.
        for field,value in [('Operation','ReKey'),('Operation','ReCertify'),('RevocationReasonCode','CessationOfOperation'),('ObjectGroupMember','GroupMemberFresh')]:
            with self.assertRaises(Unsupported):enum_value(field,value)
        # Every remaining not_selected case really encodes.
        for i,row in ROWS.items():
            if row['status']=='SELECTED' or row['blockers'][0].startswith('not_selected'):self.assertEqual(L.encoding_blockers(CASES[i]),[],i)
        # The image's Feature Not Supported answer to a non-critical extension is a policy note, not a blocker.
        for i in ['TC-71-10','TC-71-11','TC-71-12','KMIP-TC-1.1-7.1']:
            self.assertIn('section 6.16 makes that a MAY',ROWS[i]['policy_notes'][0]);self.assertFalse(any('6.16' in b for b in ROWS[i]['blockers']))

    # Field order is checked.
    def test_wire_order_violations_fail(self):
        swaps={'BatchItem before Header':lambda i,n:(n[0],n[1],n[2][::-1]),
               'reversed header':lambda i,n:edit(n,0x42007a,lambda c:c[::-1]),
               'Result Status before Operation':lambda i,n:edit(n,0x42000f,lambda c:[c[1],c[0]]+c[2:]),
               'reversed payload':lambda i,n:edit(n,0x42007c,lambda c:c[::-1]),
               'Minor before Major':lambda i,n:edit(n,0x420069,lambda c:c[::-1])}
        for label,tamper in swaps.items():
            if OLD:self.assertEqual(self.old_replay('TC-311-12',tamper=tamper),2,label)
            self.new_failure('TC-311-12','order|must come first',tamper=tamper)
        if OLD:self.assertEqual(self.old_replay('KMIP-TC-1.1-3.1.1',tamper=swaps['reversed header']),2)
        self.new_failure('KMIP-TC-1.1-3.1.1','Table 209',tamper=swaps['reversed header'])
        self.new_failure('TC-311-10','KMIP 1.0 Table 190',tamper=swaps['Result Status before Operation'])
        self.new_failure('TC-311-12','KMIP 1.2 Table 247',tamper=swaps['reversed header'])

    # Distinct objects need nonempty, distinct server-assigned identifiers.
    def test_reused_or_empty_identifiers_fail(self):
        same=lambda symbol,n:'1';empty=lambda symbol,n:''
        for case in ['TC-141-12','KMIP-TC-1.1-14.1']:
            if OLD and case=='TC-141-12':self.assertEqual(self.old_replay(case,ids=same),7)
            self.new_failure(case,'already assigned',ids=same)
        if OLD:self.assertEqual(self.old_replay('TC-311-12',ids=empty),2)
        self.new_failure('TC-311-12','empty identifier',ids=empty)
        # One object referenced repeatedly keeps one identifier; that is not a clash.
        messages,_=L.bind_dynamic(CASES['TC-311-12'])
        self.assertEqual(L.replay(messages,Responder(messages,ids=same)),2)

    # Raw response bytes are validated before decoding.
    def test_malformed_response_bytes_fail_as_ordinary_case_failures(self):
        def padding(i,b):
            # The Time Stamp is followed by a Batch Count Integer whose last four bytes are padding.
            k=b.index(bytes.fromhex('42000d0200000004'))+15;return b[:k]+b'\x07'+b[k+1:]
        if OLD:self.assertEqual(self.old_replay('TC-311-12',raw=padding),2)
        self.new_failure('TC-311-12','nonzero padding',raw=padding)
        def overrun(i,b):
            # The Batch Item claims eight more bytes than the message contains.
            k=b.index(bytes.fromhex('42000f01'))+4;size=int.from_bytes(b[k:k+4],'big')
            return b[:k]+(size+8).to_bytes(4,'big')+b[k+4:]
        if OLD:
            try:self.old_replay('TC-311-12',raw=overrun);outcome='passed'
            except AssertionError:outcome='assertion'
            except Exception as e:outcome=type(e).__name__
            # The candidate raised IndexError, which its live loop did not catch
            # (it caught only AssertionError, ValueError, OSError and EOFError).
            self.assertEqual(outcome,'IndexError')
        self.new_failure('TC-311-12','overruns its parent',raw=overrun)
        for bad,pattern in [(lambda i,b:b[:-8],'overruns|truncated'),(lambda i,b:b[:3]+b'\x0b'+b[4:],'not a KMIP 1.x type'),
                            (lambda i,b:b.replace(bytes.fromhex('42000d0200000004'),bytes.fromhex('42000d0200000005'),1),'length 5'),
                            (lambda i,b:b+b'\0'*8,'trailing bytes')]:
            self.new_failure('TC-311-12',pattern,raw=bad)
        # Boolean and UTF-8 rules.
        with self.assertRaisesRegex(W.WireError,'Boolean'):W.validate(encode((0x420078,1,[(0x420008,6,2)])))
        with self.assertRaisesRegex(W.WireError,'UTF-8'):W.validate(bytes.fromhex('4200780100000010420094070000000280ff000000000000'))

    def test_execute_captures_ordinary_errors_per_case_and_propagates_cancellation(self):
        ledger={'cases':[ROWS['TC-311-12'],ROWS['TC-315-12']]};by_id={i:('',CASES[i]) for i in ['TC-311-12','TC-315-12']}
        class Connection:
            def __init__(self,fault):self.fault=fault
            def __enter__(self):return self
            def __exit__(self,*a):pass
            def sendall(self,data):raise self.fault
        class Server:
            def __init__(self,faults):self.faults=faults;self.stops=0;self.running=False
            def start(self):self.running=True
            def stop(self):self.stops+=1;self.running=False
            def connect(self):return Connection(self.faults.pop(0))
        with tempfile.TemporaryDirectory() as d:
            server=Server([IndexError('bad bounds'),RuntimeError('boom')]);report=[]
            L.execute(ledger,{'TC-311-12','TC-315-12'},by_id,report,server,d)
            self.assertEqual([(e['status'],e['detail']) for e in report],[('FAILED','IndexError: bad bounds'),('FAILED','RuntimeError: boom')])
            self.assertEqual(server.stops,2);self.assertFalse(server.running)
        with tempfile.TemporaryDirectory() as d:
            server=Server([KeyboardInterrupt()]);report=[]
            with self.assertRaises(KeyboardInterrupt):L.execute(ledger,{'TC-311-12'},by_id,report,server,d)
            self.assertEqual(report[0]['detail'],'interrupted: KeyboardInterrupt');self.assertEqual(server.stops,1)

    def test_reports_are_replaced_before_work_and_end_in_terminal_evidence(self):
        with tempfile.TemporaryDirectory() as d:
            output=pathlib.Path(d)/'legacy.json';output.write_text(json.dumps({'status':'passed','cases':['stale']}))
            seen=[]
            for fault,status in [(RuntimeError('cache unavailable'),'failed'),(KeyboardInterrupt(),'interrupted')]:
                def load(selection=None,fault=fault):
                    seen.append(json.loads(output.read_text())['status']);raise fault
                saved=(L.load,sys.argv);L.load=load;sys.argv=['oasis_legacy.py','--output',str(output)]
                try:
                    with self.assertRaises(type(fault)):L.main()
                finally:L.load,sys.argv=saved
                result=json.loads(output.read_text())
                self.assertEqual(result['status'],status);self.assertIn(type(fault).__name__,result['error'])
            self.assertEqual(seen,['running','running'])
            self.assertEqual([p.name for p in pathlib.Path(d).iterdir()],['legacy.json'])
            # The historical raw report is never overwritten.
            saved=(L.HISTORICAL_REPORT_SHA256,sys.argv);L.HISTORICAL_REPORT_SHA256=hashlib.sha256(output.read_bytes()).hexdigest();sys.argv=['oasis_legacy.py','--output',str(output)]
            before=output.read_bytes()
            try:
                with self.assertRaises(SystemExit):L.main()
            finally:L.HISTORICAL_REPORT_SHA256,sys.argv=saved
            self.assertEqual(output.read_bytes(),before)

    # Mixed-version cases are classified uniformly and credited per exchange.
    def test_mixed_version_cases_are_uniform_and_credited_per_exchange(self):
        old_rows={r['id']:r for name,(item,cases) in OLD_DOCS.items() for r in OLD.inventory(item,cases)} if OLD else {}
        for i in ['TC-141-11','TC-142-11','TC-NP-2-12']:
            if OLD:self.assertNotIn('defect',old_rows[i])
            self.assertTrue(ROWS[i]['document_defects'][0].startswith('mixed_protocol_versions'),i)
        self.assertEqual(ROWS['TC-141-11']['status'],'SELECTED')
        self.assertEqual(ROWS['TC-141-11']['exchange_versions'],['1.1']*5+['1.2','1.1'])
        self.assertEqual(ROWS['TC-NP-2-12']['exchange_versions'],['1.2','1.0']*4)
        messages,_=L.bind_dynamic(CASES['TC-141-11'])
        self.assertEqual(L.header_version(messages[10]),'1.2')  # sent exactly as published
        entry=L.entry_for(ROWS['TC-141-11'],'PASSED',passed_exchange_versions=ROWS['TC-141-11']['exchange_versions'])
        summary,credit=L.summarize([entry,L.entry_for(ROWS['TC-311-11'],'PASSED',passed_exchange_versions=['1.1','1.1'])])
        self.assertEqual(credit,{'passed_exchanges_by_version':{'1.1':8,'1.2':1},'passed_cases_by_single_version':{'1.1':1,'mixed':1}})

    # The 1.1 section 7.1/7.2 tag is a source fault in the unused range.
    def test_unused_range_tag_is_a_document_defect_not_a_listing_mismatch(self):
        for i in ['KMIP-TC-1.1-7.1','KMIP-TC-1.1-7.2']:
            if OLD:self.assertEqual(OLD_CASES[i]['listing_mismatches'],[0])
            self.assertEqual(CASES[i]['listing_mismatches'],[]);self.assertNotIn('listing_mismatches',ROWS[i])
            defect=ROWS[i]['document_defects'][0]
            for text in ['0x014242','(Unused) range 000000-420000','section 9.1.1.1','prose names tag 0x540001']:self.assertIn(text,defect)
            with self.assertRaisesRegex(W.WireError,'section 9.1.1.1'):W.validate(CASES[i]['messages'][0]['raw'])
            messages,_=L.bind_dynamic(CASES[i])
            with self.assertRaises(Unsupported):L.replay(messages,lambda r:self.fail('nothing may be sent'))

    # Selection drift, extended verify, display names.
    def test_selection_does_not_survive_digest_drift(self):
        ledger=copy.deepcopy(LEDGER);ROWS_IN(ledger)['TC-311-12']['messages_sha256']='0'*64
        rebuilt=ROWS_IN(L.rebuild(DOCUMENTS,ledger))['TC-311-12']
        self.assertEqual(rebuilt['status'],'NOT EXECUTED');self.assertTrue(rebuilt['blockers'][0].startswith('reselection_required'))
        self.assertEqual(L.rebuild(DOCUMENTS,copy.deepcopy(LEDGER)),LEDGER)
        # The candidate's --inventory carried the stale selection forward.
        if OLD:
            with tempfile.TemporaryDirectory() as d:
                path=pathlib.Path(d)/'ledger.json';path.write_text(json.dumps(ledger))
                saved=(OLD.LEDGER,sys.argv);OLD.LEDGER=path;sys.argv=['oasis_legacy.py','--inventory']
                try:OLD.main()
                finally:OLD.LEDGER,sys.argv=saved
                self.assertEqual(ROWS_IN(json.loads(path.read_text()))['TC-311-12']['status'],'SELECTED')
        # The candidate's verify() ignored section/title/blocker drift.
        drift=copy.deepcopy(LEDGER);ROWS_IN(drift)['TC-311-12'].update(section='9.9.9');ROWS_IN(drift)['TC-313-12'].update(blockers=['x'])
        if OLD:self.assertEqual(OLD.verify(OLD_DOCS,drift),[])
        self.assertEqual(sorted(L.verify(DOCUMENTS,drift)),['TC-311-12: section differs from the ledger','TC-313-12: blockers differ from the ledger'])

    def test_encoding_option_is_displayed_with_its_kmip_1x_name(self):
        def option(module,cases):return {e.get('value') for m in cases['KMIP-TC-1.1-14.1']['messages'] if m['xml'] is not None for e in m['xml'].iter('EncodingOption')}
        if OLD:self.assertEqual(option(OLD,OLD_CASES),{'Client'})
        self.assertEqual(option(L,CASES),{'NoEncoding'})
        self.assertEqual(enum_value('EncodingOption','NoEncoding'),enum_value('EncodingOption','Client'))  # same value; display only

class FailClosedEvidenceTests(unittest.TestCase):
    def test_unknown_document_rows_and_document_inventories_fail_closed(self):
        ledger=copy.deepcopy(LEDGER)
        ledger['cases'].append(dict(ledger['cases'][0],id='phantom',document='not pinned',status='NOT EXECUTED'))
        self.assertTrue(any('unknown document' in p for p in L.verify(DOCUMENTS,ledger)))
        ledger=copy.deepcopy(LEDGER);ledger['documents']['phantom']={'case_count':0}
        self.assertIn('ledger document inventory differs from loaded pinned documents',L.verify(DOCUMENTS,ledger))

    def run_fixture(self,root,emit_log=False):
        from unittest.mock import patch
        artifact=root/'artifacts';artifact.mkdir(exist_ok=True)
        cli=root/'fixture-cli';cli.write_bytes(b'fixture generator, never executed')
        output=artifact/'replay.json';log=artifact/'replay-server.log';log.write_text('stale log from a previous invocation')
        args=types.SimpleNamespace(engine='podman',image='fixture-image',fixture_cli=cli,output=output)
        row=ROWS['TC-311-12'];ledger={'cases':[row]};report=[]
        class Server:
            def __init__(self,directory,*args,**kw):
                if emit_log:(pathlib.Path(directory)/'server.log').write_text('new fixture log')
            def stop(self):pass
        def execute(*args):report.append(L.entry_for(row,'PASSED',completed_exchanges=2,passed_exchange_versions=['1.2','1.2']))
        with patch.object(L,'ROOT',root),patch.object(L,'execute',side_effect=execute),patch('test_database.ContainerServer',Server),patch('image_evidence.local_image_id',return_value='image-id'),patch('image_evidence.packaged_evidence',return_value={'archive_sha256':'c'*64}):
            L.run_live(args,ledger,{row['id']},{},report,'fixture-start')
        return json.loads(output.read_text()),log

    def test_a_missing_current_server_log_cannot_cite_a_stale_log(self):
        with tempfile.TemporaryDirectory() as directory:
            report,log=self.run_fixture(pathlib.Path(directory))
            self.assertFalse(log.exists());self.assertNotIn('server_log',report['evidence'])
        with tempfile.TemporaryDirectory() as directory:
            report,log=self.run_fixture(pathlib.Path(directory),emit_log=True)
            self.assertEqual(log.read_text(),'new fixture log')
            self.assertEqual(report['evidence']['server_log_sha256'],hashlib.sha256(log.read_bytes()).hexdigest())

    def test_cleanup_failure_does_not_replace_a_primary_interrupt(self):
        class Connection:
            def __enter__(self):return self
            def __exit__(self,*args):pass
            def sendall(self,data):raise KeyboardInterrupt()
        class Server:
            def start(self):pass
            def connect(self):return Connection()
            def stop(self):raise RuntimeError('owned cleanup failure')
        report=[];row=ROWS['TC-311-12']
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(KeyboardInterrupt):L.execute({'cases':[row]},{row['id']},{row['id']:('',CASES[row['id']])},report,Server(),directory)
        self.assertIn('KeyboardInterrupt',report[0]['detail'])
        self.assertEqual(report[0]['cleanup_error'],'RuntimeError: owned cleanup failure')

if __name__=='__main__':unittest.main()
