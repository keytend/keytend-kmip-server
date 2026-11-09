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

"""Offline checks for the full legacy-note replay and its committed per-case ledger.

The ledger test fails if any of the 155 cases is missing, has no status, or is
a non-pass without a known family and a reason. The replay loop is driven by an
in-process responder that answers with the official responses; no server is
started. Uses the pinned OASIS documents from .cache/specs/legacy.
"""
import copy,json,unittest,xml.etree.ElementTree as ET
import oasis_legacy_replay as R
import oasis_legacy as L
import oasis_conformance as C
from wire import encode,decode
R.install_hooks()
DOCUMENTS=L.load();CASES={case['id']:case for item,cases in DOCUMENTS.values() for case in cases}
INVENTORY=json.loads(L.LEDGER.read_text());LEDGER=R.load_ledger()
KINDS={'server_defect','server_optional_feature','server_capability_set','server_policy','note_defect','note_time_dependent','comparator_difference','not_applicable'}

class Ledger(unittest.TestCase):
    def test_every_case_is_explained(self):
        self.assertEqual(R.ledger_errors(LEDGER,INVENTORY),[])
        self.assertEqual(len(LEDGER['cases']),155)
        self.assertEqual([r['id'] for r in LEDGER['cases']],list(CASES))
    def test_family_kinds_are_known(self):
        for name,f in LEDGER['families'].items():
            if name!='untriaged':self.assertIn(f['kind'],KINDS,name)
    def test_partial_and_defect_statuses_match_their_families(self):
        for r in LEDGER['cases']:
            if r['status']=='partial':self.assertEqual(r['family'],'server_to_client_operation',r['id'])
            if r['status']=='document_defect':self.assertEqual(LEDGER['families'][r['family']]['kind'],'note_defect',r['id'])
    def test_unexplained_cases_fail_the_validator(self):
        def broken(edit):
            ledger=copy.deepcopy(LEDGER);edit(ledger);return R.ledger_errors(ledger,INVENTORY)
        failing=next(i for i,r in enumerate(LEDGER['cases']) if r['status']=='failed')
        passing=next(i for i,r in enumerate(LEDGER['cases']) if r['status']=='passed')
        self.assertTrue(broken(lambda l:l['cases'][failing].pop('family')))
        self.assertTrue(broken(lambda l:l['cases'][failing].update(reason=' ')))
        self.assertTrue(broken(lambda l:l['cases'][failing].update(family='untriaged')))
        self.assertTrue(broken(lambda l:l['cases'][failing].update(family='no-such-family')))
        self.assertTrue(broken(lambda l:l['cases'][passing].update(family='rsa_1024_refused')))
        self.assertTrue(broken(lambda l:l['cases'][passing].update(status='skipped')))
        self.assertTrue(broken(lambda l:l['cases'][passing].pop('status')))
        self.assertTrue(broken(lambda l:l['cases'].pop()))
        self.assertTrue(broken(lambda l:l['cases'][0].update(messages_sha256='0'*64)))
        self.assertTrue(broken(lambda l:l['summary'].update(passed=l['summary']['passed']+1)))
    def test_a_changed_result_becomes_untriaged(self):
        failing=next(r for r in LEDGER['cases'] if r['status']=='failed');passing=next(r for r in LEDGER['cases'] if r['status']=='passed')
        report=[{'id':failing['id'],'status':'passed'},{'id':passing['id'],'status':'failed','detail':'new failure'}]
        updated=R.update_ledger(report,LEDGER);rows={r['id']:r for r in updated['cases']}
        self.assertNotIn('family',rows[failing['id']]);self.assertEqual(rows[passing['id']]['family'],'untriaged')
        self.assertTrue(any('untriaged' in e for e in R.ledger_errors(updated,INVENTORY)))
        self.assertEqual(len(R.report_differences(report,LEDGER)),2)

class Reported(unittest.TestCase):
    """The reported status follows the family chain through the recorded evidence runs."""
    def ledger(self):
        fam=lambda ws,**kw:dict(kind='server_policy',workstream=ws,description='d',spec='s',**kw)
        return {'configurations':{'3des':{'setting':'KMIP_TRIPLE_DES=enabled'},'lease-0':{'setting':'KMIP_MAX_LEASE_SECONDS=0'}},
                'families':{'impl':fam('implementation'),'cfg':fam('configuration',configuration='3des'),'lease':fam('configuration',configuration='lease-0'),
                            'doc':fam('document'),'doc2':fam('document'),'alt':fam('alternative'),'dev':fam('deviation'),'unv':fam('unverifiable')}}
    def label(self,family,evidence=None,status='failed'):
        return R.reported({'status':status,'family':family,'evidence':evidence or {}},self.ledger())
    def test_terminal_families(self):
        self.assertEqual(self.label('impl'),'failed')
        self.assertEqual(self.label('dev'),'documented deviation')
        self.assertEqual(self.label('unv'),'skipped (unverifiable)')
        self.assertEqual(self.label('alt'),'not applicable (alternative outcome)')
        self.assertEqual(self.label('impl',status='passed'),'passed')
    def test_configuration_needs_a_passing_run(self):
        self.assertEqual(self.label('cfg'),'skipped (configuration: needs KMIP_TRIPLE_DES=enabled)')
        self.assertEqual(self.label('cfg',{'3des':{'status':'passed'}}),'skipped (configuration: passes with KMIP_TRIPLE_DES=enabled)')
        # A configured run that fails names the next blocker, which decides.
        self.assertEqual(self.label('cfg',{'3des':{'status':'failed','family':'impl'}}),'failed')
        self.assertEqual(self.label('lease',{'lease-0':{'status':'failed','family':'doc'},'lease-0+corrected':{'status':'passed'}}),
                         'skipped (configuration: passes with KMIP_MAX_LEASE_SECONDS=0 and a corrected document)')
    def test_document_needs_a_passing_correction(self):
        self.assertEqual(self.label('doc'),'document defect (no passing correction)')
        self.assertEqual(self.label('doc',{'corrected':{'status':'passed'}}),'passed (corrected document)')
        self.assertEqual(self.label('doc',{'corrected':{'status':'failed','family':'unv'}}),'skipped (unverifiable)')
        self.assertEqual(self.label('doc',{'corrected':{'status':'failed','family':'impl'}}),'failed')
        self.assertEqual(self.label('doc',{'corrected':{'status':'failed','family':'doc2'}}),'document defect (no passing correction)')
        self.assertEqual(self.label('alt',{'corrected':{'status':'passed'}}),'not applicable (alternative outcome)')
        self.assertEqual(self.label('alt',{'corrected':{'status':'failed','family':'impl'}}),'failed')
    def test_committed_rows_match_their_chain(self):
        for r in LEDGER['cases']:self.assertEqual(r['reported'],R.reported(r,LEDGER),r['id'])
        self.assertEqual(LEDGER['reported_counts'],R.reported_counts(LEDGER['cases']))
        self.assertTrue(broken_ledger(lambda l:next(r for r in l['cases'] if r['status']!='passed').update(reported='passed')))
    def test_evidence_failures_must_be_triaged(self):
        row=next(r for r in LEDGER['cases'] if r['status']=='failed')
        report={'run':'3des','status':'complete','cases':[{'id':row['id'],'status':'failed','detail':'new','failed_exchange':0}]}
        updated=R.record_evidence(LEDGER,report)
        self.assertEqual(next(r for r in updated['cases'] if r['id']==row['id'])['evidence']['3des']['family'],'untriaged')
        self.assertTrue(any('untriaged' in e or 'without a triaged family' in e for e in R.ledger_errors(updated,INVENTORY)))
        with self.assertRaises(ValueError):R.record_evidence(LEDGER,dict(report,run='default'))

def broken_ledger(edit):
    ledger=copy.deepcopy(LEDGER);edit(ledger);return R.ledger_errors(ledger,INVENTORY)

class Corrections(unittest.TestCase):
    def test_every_correction_applies_to_its_published_case(self):
        rows={r['id']:r for r in LEDGER['cases']}
        for c in R.load_corrections()['corrections']:
            corrected,labels=R.corrected_case(CASES[c['case']],[c])
            self.assertEqual(len(labels),1)
            self.assertIn(c['family'],LEDGER['families'],c['case'])
            self.assertNotEqual(rows[c['case']]['status'],'passed',c['case'])
            if c.get('fixture'):self.assertIn(c['fixture'],LEDGER['fixtures'])
            # The published case is untouched.
            self.assertIsNot(corrected['messages'][0]['xml'],CASES[c['case']]['messages'][0]['xml'])
    def test_a_stale_edit_is_refused(self):
        bad={'family':'x','why':'y','edits':[{'message':3,'path':'BatchItem/ResultReason','from':'ItemNotFound','to':'InvalidMessage'}]}
        with self.assertRaises(ValueError):R.corrected_case(CASES['KMIP-TC-1.1-17.1'],[bad])
    def test_rebase_dates_uses_each_exchanges_time_stamp(self):
        corrected,_=R.corrected_case(CASES['KMIP-TC-1.1-9.2'],[{'family':'f','why':'w','edits':[{'rebase_dates':True}]}])
        values=[e.get('value') for m in corrected['messages'] for e in m['xml'].iter() if e.get('type')=='DateTime' and e.tag!='TimeStamp']
        self.assertTrue(values and all(v.startswith('$NOW') for v in values))
        self.assertIn('$NOW+120',values)
        # The re-keyed replacement's Activation Date is "now" at its own exchange.
        self.assertIn('$NOW',values)

class Hooks(unittest.TestCase):
    def test_attribute_form_dates_vary_like_the_field_form(self):
        replay=R.Replay('1.2',{})
        e=ET.fromstring('<AttributeValue type="DateTime" value="2013-06-17T08:24:02+00:00"/>')
        ctx={'attribute':'InitialDate','response_payload':True}
        replay.leaf(e,(C.TAGS['AttributeValue'],9,1793363668),'/p',ctx)
        self.assertIn('InitialDate varies (4.1.1, 1.x Attribute form)',replay.variations)
        # A date the request supplied stays exact.
        replay.request_datetimes.add('2013-06-17T08:24:02+00:00')
        with self.assertRaises(AssertionError):replay.leaf(e,(C.TAGS['AttributeValue'],9,1793363668),'/p',{'attribute':'ActivationDate','response_payload':True})
    def test_ttlv_element_uses_its_extension_tag(self):
        e=ET.fromstring('<VendorExtension><TTLV tag="0x540001" type="TextString" value="na"/></VendorExtension>')
        self.assertEqual(R.encode_xml(e,{}),(C.TAGS['VendorExtension'],1,[(0x540001,7,'na')]))
        with self.assertRaises(C.Unsupported):R.encode_xml(ET.fromstring('<TTLV tag="0x014242" type="TextString" value="na"/>'),{})
    def test_object_group_member_and_mask_spellings(self):
        self.assertEqual(R.encode_xml(ET.fromstring('<ObjectGroupMember type="Enumeration" value="GroupMemberDefault"/>'),{})[2],2)
        self.assertEqual(R.encode_xml(ET.fromstring('<StorageStatusMask type="Integer" value="ArchivalStorage OnLineStorage"/>'),{})[2],3)
        with self.assertRaises(C.Unsupported):R.encode_xml(ET.fromstring('<StorageStatusMask type="Integer" value="OffLineStorage"/>'),{})
        with self.assertRaises(C.Unsupported):R.encode_xml(ET.fromstring('<ObjectGroupMember type="Enumeration" value="GroupMemberStale"/>'),{})
    def test_operation_spellings_are_canonical(self):
        messages,_=L.bind_dynamic(CASES['TC-91-12'])
        self.assertTrue(R.canonical_operations(messages))
        self.assertIn('Rekey',[e.get('value') for m in messages for e in m.iter('Operation')])
        bad=ET.fromstring('<RequestMessage><BatchItem><Operation type="Enumeration" value="ReKeyy"/></BatchItem></RequestMessage>')
        with self.assertRaises(C.Unsupported):R.canonical_operations([bad])

class Plans(unittest.TestCase):
    def plan(self,cid):
        messages,_=L.bind_dynamic(CASES[cid]);return R.exchange_plan(CASES[cid],messages)
    def test_dual_client_and_server_to_client_labels(self):
        self.assertEqual(set(self.plan('TC-314-12')),{'client-A','client-B'})
        self.assertEqual([k for k,p in enumerate(self.plan('TC-NP-2-12')) if p=='server-to-client'],[1,3,5,7])
        self.assertEqual(set(self.plan('KMIP-TC-1.1-3.1.1')),{'client'})
    def test_label_and_operation_must_agree(self):
        case=copy.deepcopy(CASES['TC-NP-1-12']);case['comments']=[c.replace('Server-to-Client','Client-to-Server') for c in case['comments']]
        messages,_=L.bind_dynamic(case)
        with self.assertRaises(ValueError):R.exchange_plan(case,messages)

class Responder:
    """Answer each client-to-server request with the official response, assigning its own identifiers."""
    def __init__(self,messages,plan,tamper=None,ids=None):
        self.messages=messages;self.order=[k for k,p in enumerate(plan) if p!='server-to-client'];self.ids={}
        self.tamper=tamper or (lambda k,n:n);self.assign=ids or (lambda symbol,n:f'server-{n}');self.connections=0
    def answer(self,request):
        k=self.order.pop(0);expected=self.messages[2*k+1]
        for e in expected.iter():
            value=e.get('value','')
            if value.startswith('$') and not value.startswith('$NOW') and value not in self.ids:self.ids[value]=self.assign(value,len(self.ids))
        return encode(self.tamper(k,C.encode_xml(expected,self.ids)))
class FakeConnection:
    def __init__(self,responder):self.responder=responder;self.buffer=b''
    def sendall(self,data):self.buffer+=self.responder.answer(decode(data))
    def recv(self,n):out=self.buffer[:n];self.buffer=self.buffer[n:];return out
    def close(self):pass
class FakeServer:
    def __init__(self,responder):self.responder=responder
    def connect(self):self.responder.connections+=1;return FakeConnection(self.responder)

class Loop(unittest.TestCase):
    def run_case(self,cid,**kw):
        messages,_=L.bind_dynamic(CASES[cid]);R.canonical_operations(messages);plan=R.exchange_plan(CASES[cid],messages)
        responder=Responder(messages,plan,**kw);replay=R.Replay(R.case_version(messages),{});entry={}
        R.run_case(FakeServer(responder),replay,messages,plan,entry,{});R.P.finish(replay);return entry,responder
    def test_official_responses_pass(self):
        entry,_=self.run_case('TC-311-12');self.assertEqual(entry['completed_exchanges'],2)
    def test_wrong_status_fails(self):
        def tamper(k,n):
            if k==1:
                item=[c for c in n[2] if c[0]==C.TAGS['BatchItem']][0]
                item[2][:]=[(t,ty,1) if t==C.TAGS['ResultStatus'] else (t,ty,v) for t,ty,v in item[2]]
            return n
        with self.assertRaises(AssertionError):self.run_case('TC-311-12',tamper=tamper)
    def test_reused_identifier_fails(self):
        with self.assertRaises(AssertionError):self.run_case('TC-82-12',ids=lambda symbol,n:'same')
    def test_server_to_client_exchanges_are_skipped_not_answered(self):
        entry,responder=self.run_case('TC-NP-2-12')
        self.assertEqual(entry['skipped_exchanges'],[1,3,5,7]);self.assertEqual(entry['completed_exchanges'],4);self.assertEqual(responder.order,[])
    def test_dual_client_uses_two_connections(self):
        entry,responder=self.run_case('TC-41-12')
        self.assertEqual(entry['completed_exchanges'],15);self.assertEqual(responder.connections,2)

if __name__=='__main__':unittest.main()
