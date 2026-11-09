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

"""Replay every KMIP 1.1/1.2 Test Cases Committee Note case under the Profiles 4.1 variations.

This is a separately labelled mode. The strict legacy harness
(scripts/oasis_legacy.py), its ledger docs/specs/legacy-inventory.json and its
historical reports are not changed. The messages come from the same pinned
OASIS documents through oasis_legacy.load(), and every response is compared by
the Replay comparator of scripts/oasis_profile_replay.py, imported unchanged.

Basis for applying the 4.1 variations to the 1.x notes: neither 1.x profile
document lists permitted variations, but both notes say their messages are not
the only conformant constructions (1.1 note section 1: "many values change
dynamically when running the test cases (the server-generated timestamps,
Unique Identifiers and key material in responses ...)"; 1.2 note section 2:
"not necessarily the only conformant constructions as many items within KMIP
are optional and server behavior depends on the server's policy"). Profiles
1.3+ section 4.1 is the TC's own later, explicit list of those variations; only
that list is accepted, each use recorded per case.

Added on top of the profile comparator, never relaxing it:
* response bytes pass legacy_wire.validate() and the section 7 message, header
  and batch-item tables of the exchange's published version;
* variable output (generated keys, randomized crypto, RNG) is closed only by the
  obligation mechanism of oasis_profile_replay/oasis_validate, never by copying
  sample bytes.
Harness-only hooks (spellings, the XML <TTLV> element) are scoped to this
process and listed in HOOKS; case fixtures come from the committed ledger
docs/specs/legacy-replay-ledger.json. The production server, its RNG and its
policy defaults are never modified.
"""
import argparse,copy,datetime,hashlib,json,os,pathlib,re,tempfile,time,traceback,xml.etree.ElementTree as ET
import oasis_legacy as L
import oasis_profile_replay as P
import oasis_conformance as C
import oasis_validate as V
import legacy_wire as W
from wire import node
from test_runtime import ROOT,Server
from image_evidence import source_commit

LEDGER=ROOT/'docs/specs/legacy-replay-ledger.json'
CORRECTIONS=ROOT/'docs/specs/legacy-corrected-documents.json'
DEFAULT_OUTPUT=ROOT/'artifacts/oasis-legacy-variations.json'
MODE='legacy-notes-profiles-4.1-variations'
STATUSES=['passed','unverified','failed','partial','document_defect']
# Reported status (the same vocabulary as scripts/oasis_inventory.py): "failed"
# means only that the server lacks the behavior or implements it wrongly.
WORKSTREAMS={'implementation','configuration','unverifiable','alternative','deviation','document'}


# ---------- harness hooks (this process only; shared modules are not edited) ----------
# The 1.x enumeration names below are absent from docs/specs/registry.json.
# KMIP 1.1 and 1.2 section 9.1.3.2.33 (1.2 Table 284), Object Group
# Member Enumeration: Group Member Fresh 00000001, Group Member Default 00000002.
LEGACY_ENUMS={'ObjectGroupMember':{'GroupMemberFresh':1,'GroupMemberDefault':2}}
HOOKS={
 'object_group_member':'ObjectGroupMember=GroupMemberFresh/GroupMemberDefault from KMIP 1.1/1.2 Object Group Member Enumeration table (absent from the shared registry)',
 'mask_spelling':'symbolic mask parts matched case-insensitively against the registry (published "OnLineStorage" for the 1.x "On-line storage" mask name)',
 'ttlv_element':'KMIP XML <TTLV tag= type= value=> element for an Extensions-range tag (540000-54FFFF, KMIP 1.x section 9.1.3.1) encoded with that tag',
 'attribute_dates':'a server-generated date in the 1.x Attribute form (Attribute Name "Initial Date", "Last Change Date", ...) varies exactly as the profile comparator lets the same date vary in its 2.x field form (Profiles 4.1.1); a date the request supplied stays exact',
}
NOTES=set()
_profile_enum=C.enum_value
def enum_value(name,value):
    try:return _profile_enum(name,value)
    except C.Unsupported:
        table=LEGACY_ENUMS.get(C.normalized(name),{})
        if value in table:NOTES.add(HOOKS['object_group_member']);return table[value]
        raise
_original_encode=C.encode_xml
def encode_xml(e,variables,context=None):
    if e.tag=='TTLV':
        tag=int(e.get('tag',''),16)
        if not 0x540000<=tag<=0x54ffff:raise C.Unsupported(f'<TTLV> tag 0x{tag:06x} outside the Extensions range')
        kind=C.TYPES.get(e.get('type','Structure'))
        if kind==1:return node(tag,1,[encode_xml(c,variables) for c in e])
        if kind!=7:raise C.Unsupported('<TTLV> element of type '+str(e.get('type')))
        NOTES.add(HOOKS['ttlv_element']);return node(tag,7,e.get('value',''))
    try:return _original_encode(e,variables,context)
    except C.Unsupported as error:
        if not str(error).startswith('bitmask '):raise
        field=context if e.tag=='AttributeValue' and context else e.tag
        choices=C.ENUMS.get(field,{});mask=0
        for part in e.get('value','').split():
            found={v for k,v in choices.items() if k.lower()==C.normalized(part).lower()}
            if len(found)!=1:raise
            mask|=found.pop()
        NOTES.add(HOOKS['mask_spelling'])
        return node(C.TAGS.get(e.tag,C.TAGS.get(C.normalized(e.tag))),C.TYPES[e.get('type')],mask)
def canonical_operations(messages):
    """Rewrite published Operation spellings (ReKey, ReKeyKeyPair, ReCertify) to the registry name.

    The profile comparator tracks created and generated objects by operation
    name; a published spelling it does not know would silently skip the
    identifier-uniqueness and generated-material rules for that operation.
    Only a unique case-insensitive registry match is accepted.
    """
    names={k:v for k,v in C.ENUMS['Operation'].items()};done=set()
    for m in messages:
        if m is None:continue
        for e in m.iter('Operation'):
            value=e.get('value','')
            if value in names:continue
            found=[k for k in names if k.lower()==C.normalized(value).lower()]
            if len(found)!=1:raise C.Unsupported(f'Operation={value} has no unique registry spelling')
            e.set('value',found[0]);done.add(f'Operation {value} -> {found[0]} (published spelling, unique case-insensitive registry match)')
    return sorted(done)
def install_hooks():
    C.enum_value=enum_value;P.enum_value=enum_value
    C.encode_xml=encode_xml;P.encode_xml=encode_xml

# ---------- case plans ----------
# Server-to-client operations are "only ever sent by a server to a client via
# means outside of the normal client request/response protocol, using
# information known to the server via unspecified configuration or
# administrative mechanisms" (KMIP 1.x section 5.1 Notify; 5.2 Put likewise).
SERVER_TO_CLIENT={'Notify','Put'}
def exchange_plan(case,messages):
    """Per exchange: 'client' (default connection), 'client-A'/'client-B', or 'server-to-client'."""
    labels={};time=None
    for note in case.get('comments',[]):
        m=re.fullmatch(r'TIME ([0-9]+)',note)
        if m:time=int(m.group(1));continue
        m=re.fullmatch(r'\[(Client-[AB]|Client-to-Server|Server-to-Client)\]',note)
        if m and time is not None:labels.setdefault(time,set()).add(m.group(1))
    plan=[]
    for k in range(0,len(case['messages']),2):
        found=labels.get(case['messages'][k]['time'],set())
        if len(found)>1:raise ValueError(f'{case["id"]}: exchange {k//2} has conflicting labels {sorted(found)}')
        label=found.pop() if found else None
        ops={e.get('value') for e in messages[k].iter('Operation')} if messages[k] is not None else set()
        s2c=bool(ops&SERVER_TO_CLIENT)
        if s2c!=(label=='Server-to-Client') and label is not None:raise ValueError(f'{case["id"]}: exchange {k//2} label {label} disagrees with operations {sorted(ops)}')
        plan.append('server-to-client' if s2c else {'Client-A':'client-A','Client-B':'client-B'}.get(label,'client'))
    return plan

# ---------- corrected documents ----------
def load_corrections():return json.loads(CORRECTIONS.read_text())
def parse_time(value):return int(datetime.datetime.fromisoformat(value.replace('Z','+00:00')).timestamp())
def rebase_dates(messages):
    """Rewrite every literal DateTime as $NOW plus its offset from its exchange's published Time Stamp.

    The note's dates were chosen relative to the time each exchange ran (a
    Deactivation Date two minutes ahead, a re-keyed Activation Date at the
    re-key); the 1.2 note's -11/-12 revisions express the same relations as
    $NOW offsets, which the comparator evaluates when the exchange runs.
    Header Time Stamps are left to the L2 rule. Returns the number of
    rewritten values.
    """
    count=0;stamp=None
    for k in range(0,len(messages),2):
        pair=[m for m in messages[k:k+2] if m is not None]
        found=[m.find('./ResponseHeader/TimeStamp') for m in pair if m.tag=='ResponseMessage']
        found=[f.get('value') for f in found if f is not None and not f.get('value','').startswith('$')]
        if found:stamp=parse_time(found[0])
        for m in pair:
            for e in m.iter():
                value=e.get('value','')
                if e.get('type')!='DateTime' or value.startswith('$') or e.tag=='TimeStamp':continue
                if stamp is None:raise ValueError('no published Time Stamp to rebase from')
                delta=parse_time(value)-stamp;e.set('value',f'$NOW{delta:+d}' if delta else '$NOW');count+=1
    return count
def corrected_case(case,corrections):
    """A copy of the case with its corrected-document edits applied (before the L1/L2 binding).

    Every edit must match the published message; the published case is not
    modified. Returns the copy and the transformation labels.
    """
    messages=[dict(m,xml=copy.deepcopy(m['xml'])) for m in case['messages']];labels=[]
    for c in corrections:
        for edit in c['edits']:
            where=f'{case["id"]}: corrected document'
            if edit.get('rebase_dates'):
                if not rebase_dates([m['xml'] for m in messages]):raise ValueError(f'{where}: rebase_dates changed nothing')
                continue
            if 'insert_exchange' in edit:
                # A request/response pair the note omits, on the default client connection.
                k=edit['insert_exchange']['before_message']
                if k%2 or messages[k]['role']!='request':raise ValueError(f'{where}: an exchange is inserted only before a request')
                pair=[{'role':'request','time':None,'xml':ET.fromstring(edit['insert_exchange']['request'])},
                      {'role':'response','time':None,'xml':ET.fromstring(edit['insert_exchange']['response'])}]
                messages[k:k]=pair;continue
            m=messages[edit['message']]['xml']
            if 'remove' in edit:
                parent=m.find(edit['remove']['parent'])
                found=[a for a in (parent if parent is not None else []) if a.tag=='Attribute' and a.find('AttributeName') is not None and a.find('AttributeName').get('value')==edit['remove']['attribute']]
                if len(found)!=1:raise ValueError(f'{where} expects one {edit["remove"]["attribute"]} attribute in {edit["remove"]["parent"]}')
                parent.remove(found[0]);continue
            if 'insert' in edit:
                parent=m.find(edit['insert']['parent'])
                if parent is None:raise ValueError(f'{where} parent {edit["insert"]["parent"]} absent')
                parent.insert(edit['insert']['index'],ET.fromstring(edit['insert']['element']));continue
            target=m.find(edit['path'])
            if target is None or target.get('value')!=edit['from']:raise ValueError(f'{where} does not match the published message: {edit["path"]}')
            target.set('value',edit['to'])
        labels.append(f'corrected document ({c["family"]}): {c["why"]}')
    return dict(case,messages=messages),labels

def case_version(messages):
    for m in messages:
        v=L.header_version(m) if m is not None else None
        if v:return v
    return None

class Replay(P.Replay):
    """The profile comparator plus the legacy byte and section 7 table layers."""
    def compare_message(self,exp,act,req_xml):
        try:W.check_message(act,L.header_version(exp))
        except W.WireError as e:raise AssertionError('section 7 table: '+str(e))
        return super().compare_message(exp,act,req_xml)
    def leaf(self,e,a,path,ctx):
        # The profile comparator lets a server-generated date vary when it is
        # the 2.x field <InitialDate> (DATE_ATTRS, Profiles 4.1.1) but compares
        # the 1.x <Attribute><AttributeName "Initial Date"><AttributeValue> form
        # exactly. Apply the same rule to the 1.x form; request-supplied dates,
        # symbols and every other attribute stay exact.
        value=e.get('value','')
        if e.tag=='AttributeValue' and ctx.get('attribute') in P.DATE_ATTRS and a[1]==9 and ctx.get('response_payload') and value and not value.startswith('$') and value not in self.request_datetimes:
            if C.encode_xml(e,self.vars)[2]!=a[2]:
                self.variations.add(f'{ctx["attribute"]} varies (4.1.1, 1.x Attribute form)');NOTES.add(HOOKS['attribute_dates'])
            return
        return super().leaf(e,a,path,ctx)

def password_verifier(password):
    """The server's users-file verifier form (src/credentials.rs): salt and PBKDF2-HMAC-SHA-256 output only."""
    salt=os.urandom(16)
    return {'algorithm':'PBKDF2-HMAC-SHA-256','iterations':600000,'salt':salt.hex(),'hash':hashlib.pbkdf2_hmac('sha256',password.encode(),salt,600000).hex()}

def write_credentials(server,fixture,policy):
    """Provision a fixture's header credentials for the client certificate's
    principal (--users); the server keeps only salted password verifiers. Cases without
    such a fixture run with no users file, so any header credential fails."""
    server.users=None
    credentials=fixture.get('credentials')
    if not credentials:return
    fingerprints=[f for f,principal in policy['principals'].items() if principal['name']=='database']
    users=[{'username':u['username'],'password_verifier':password_verifier(u['password'])} for u in credentials.get('users',[])]
    devices=[dict({k:v for k,v in d.items() if k!='password'},password_verifier=password_verifier(d['password'])) for d in credentials.get('devices',[])]
    server.users=server.root/'legacy-users.json'
    server.users.write_text(json.dumps({'users':{f:users for f in fingerprints},'devices':{f:devices for f in fingerprints}}))

def run_case(server,replay,messages,plan,entry,fixture):
    """Execute one case on a running server. Exchanges are compared in order and stop at the first failure."""
    entry['completed_exchanges']=0;entry['skipped_exchanges']=[]
    replay.vars.update(C.fixture_constants([m for m in messages if m is not None]))
    connections={}
    def connection(label):
        if label not in connections:connections[label]=server.connect()
        return connections[label]
    version=case_version(messages);sent={};wait=fixture.get('wait')
    try:
        for i in range(0,len(messages),2):
            k=i//2;label=plan[k]
            if label=='server-to-client':entry['skipped_exchanges'].append(k);continue
            if wait and k==wait['before_exchange']:
                # The note expects real time to pass (for example a Deactivation
                # Date of $NOW+120 taking effect); the harness waits instead of
                # editing any published date.
                # The server closes idle connections, so the wait ends with a new
                # connection under the same client certificate (same principal).
                for c in connections.values():c.close()
                connections.clear()
                time.sleep(max(0,sent[wait['after_exchange']]+wait['seconds']-time.time()))
            sent[k]=time.time()
            conn=connection(label);replay.exchange_index=k;entry['failed_exchange']=k
            expected=messages[i+1];exchange_version=L.header_version(expected) or version
            req_xml,used=replay.prepare_request(messages[i])
            later=messages[i+2:]
            notes=[];P.rederive_inputs(replay,req_xml,expected,conn,version,7,notes,later)
            for note in notes:replay.variations.add(note)
            req=encode_xml(req_xml,replay.vars)
            raw=P.exchange_raw(conn,req)
            try:W.validate(raw)
            except W.WireError as e:raise AssertionError(f'exchange {k}: malformed response: {e}')
            actual=V.strict_decode(raw);replay.last_actual=actual
            exact_items=replay.compare_message(expected,actual,req_xml)
            replay.harvest(req_xml,actual,req)
            for item in exact_items:
                for o in replay.obligations:
                    if o.roundtrip is None and any(o.value==u for u in used.get(item,[])):o.roundtrip=f'in-trace round trip at exchange {k}'
            if not P.observes_attributes(later):P.fetch_material(replay,conn,exchange_version,7)
            replay.resolve();entry['completed_exchanges']+=1
        # Deferred verification Gets go over the first client connection.
        if connections:P.fetch_material(replay,next(iter(connections.values())),version,7);replay.resolve()
        entry.pop('failed_exchange',None)
    finally:
        for c in connections.values():
            try:c.close()
            except OSError:pass

def document_defect_entry(case,row):
    defects=[d for d in row.get('document_defects',[]) if 'section 9.1.1.1' in d]
    return {'status':'document_defect','detail':'; '.join(defects)} if defects else None

def observe_published_bytes(server,case):
    """Send the first as-published request unchanged and record the server's answer.

    The defect is established offline (legacy_wire.tag_violations); this is
    only negative evidence about the request, never a pass of the case.
    """
    raw=case['messages'][0].get('raw')
    if raw is None:return None
    with server.connect() as conn:
        conn.sendall(raw)
        try:response=W.receive(conn)
        except (OSError,EOFError,W.WireError) as e:return f'no KMIP response: {type(e).__name__}: {e}'
    try:n=W.validate(response)
    except W.WireError as e:return f'malformed response: {e}'
    item=P.sub(n,'BatchItem')
    status=P.enum_name('ResultStatus',P.val(item,'ResultStatus'));reason=P.enum_name('ResultReason',P.val(item,'ResultReason'))
    return f'as-published request answered with Result Status {status}, Result Reason {reason}, Result Message {P.val(item,"ResultMessage")!r}'

# ---------- ledger ----------
def load_ledger():return json.loads(LEDGER.read_text())
def ledger_errors(ledger,inventory):
    """Every inventory case has one ledger row, a known status and, unless passed, a triaged family and reason."""
    errors=[];ids=[c['id'] for c in inventory['cases']];rows=ledger.get('cases',[])
    if [r.get('id') for r in rows]!=ids:errors.append('ledger case identifiers or order differ from docs/specs/legacy-inventory.json')
    digests={c['id']:c['messages_sha256'] for c in inventory['cases']}
    families=ledger.get('families',{})
    for r in rows:
        cid=r.get('id')
        if r.get('messages_sha256')!=digests.get(cid):errors.append(f'{cid}: message digest differs from the inventory')
        if r.get('status') not in STATUSES:errors.append(f'{cid}: unknown status {r.get("status")!r}');continue
        if r['status']=='passed':
            if r.get('family'):errors.append(f'{cid}: a passed case has a failure family')
            continue
        if r.get('family') not in families:errors.append(f'{cid}: {r["status"]} without a known family ({r.get("family")!r})')
        if not (r.get('reason') or '').strip():errors.append(f'{cid}: {r["status"]} without a reason')
        if r.get('family')=='untriaged':errors.append(f'{cid}: untriaged {r["status"]}')
        for run,ev in r.get('evidence',{}).items():
            if ev.get('status')!='passed' and ev.get('family') not in families or ev.get('family')=='untriaged':errors.append(f'{cid}: evidence run {run} ({ev.get("status")}) without a triaged family')
        if r.get('reported')!=reported(r,ledger):errors.append(f'{cid}: reported {r.get("reported")!r}, the family chain gives {reported(r,ledger)!r}')
    for name,f in families.items():
        if name=='untriaged':continue
        if not f.get('description') or not f.get('kind'):errors.append(f'family {name}: description and kind are required')
        if f.get('workstream') not in WORKSTREAMS:errors.append(f'family {name}: workstream must be one of {sorted(WORKSTREAMS)}')
        if (f.get('workstream')=='configuration')!=bool(f.get('configuration')):errors.append(f'family {name}: a configuration family names exactly one configuration')
        if f.get('configuration') and f['configuration'] not in ledger.get('configurations',{}):errors.append(f'family {name}: unknown configuration {f["configuration"]!r}')
    summary={s:sum(r.get('status')==s for r in rows) for s in STATUSES}
    if ledger.get('summary')!=summary:errors.append(f'ledger summary {ledger.get("summary")} differs from the rows {summary}')
    counts=reported_counts(rows)
    if ledger.get('reported_counts')!=counts:errors.append(f'ledger reported_counts {ledger.get("reported_counts")} differ from the rows {counts}')
    return errors

def reported(row,ledger,limit=4):
    """The reported status of one ledger row, from its family chain and recorded evidence runs.

    Mirrors scripts/oasis_inventory.py: "failed" means only that the server
    lacks the behavior or implements it wrongly. A configuration family is
    followed into the run with that setting, a document family into the run
    with corrected documents; a run that still fails names the next blocking
    family. Every terminal label therefore names the first reason the case
    does not pass by default and, when a run proves it, what makes it pass.
    """
    if row.get('status')=='passed':return 'passed'
    families=ledger['families'];evidence=row.get('evidence',{})
    family=row.get('family');names=[];corrected=False;alternative=False
    for _ in range(limit):
        f=families.get(family) or {};ws=f.get('workstream')
        if ws=='implementation' or ws is None:return 'failed'
        if ws=='unverifiable':return 'skipped (unverifiable)'
        if ws=='deviation':return 'documented deviation'
        if ws=='configuration':names.append(f['configuration'])
        elif corrected:return 'not applicable (alternative outcome)' if alternative or ws=='alternative' else 'document defect (no passing correction)'
        else:corrected=True;alternative=ws=='alternative'
        settings=' and '.join(ledger['configurations'][n]['setting'] for n in names)
        ev=evidence.get('+'.join(names+(['corrected'] if corrected else [])))
        if ev is None:
            if names and not corrected:return f'skipped (configuration: needs {settings})'
            return 'not applicable (alternative outcome)' if alternative else 'document defect (no passing correction)'
        if ev['status']=='passed':
            if names:return f'skipped (configuration: passes with {settings}'+(' and a corrected document)' if corrected else ')')
            return 'not applicable (alternative outcome)' if alternative else 'passed (corrected document)'
        family=ev.get('family')
    return 'failed'

def reported_counts(rows):
    counts={}
    for r in rows:counts[r.get('reported')]=counts.get(r.get('reported'),0)+1
    return dict(sorted(counts.items(),key=lambda kv:str(kv[0])))

def record_evidence(ledger,report):
    """Record a complete non-default run against every non-passing row it covers.

    A row keeps the family triage of an earlier record of the same run while
    the status is unchanged; a new or changed non-pass becomes untriaged.
    """
    run=report['run']
    if run=='default' or report.get('status')!='complete':raise ValueError('evidence needs a complete non-default run')
    by_id={e['id']:e for e in report['cases']};rows=[]
    for r in ledger['cases']:
        row=json.loads(json.dumps(r));e=by_id.get(r['id'])
        if e is not None and r['status']!='passed':
            old=r.get('evidence',{}).get(run,{})
            ev={'status':e['status']}
            if e['status']!='passed':
                ev['detail']=(e.get('detail') or '')[:300];ev['exchange']=e.get('failed_exchange')
                ev['family']=old.get('family') if old.get('status')==e['status'] and old.get('family') else 'untriaged'
            row.setdefault('evidence',{})[run]=ev
        rows.append(row)
    return finish_ledger(dict(ledger,cases=rows))

def finish_ledger(ledger):
    """Recompute the derived fields: reported status per row, summary and reported counts."""
    rows=[]
    for r in ledger['cases']:
        row=dict(r)
        if row.get('status')=='passed':row.pop('evidence',None)
        row['reported']=reported(row,ledger);rows.append(row)
    ledger=dict(ledger,cases=rows)
    ledger['summary']={s:sum(r['status']==s for r in rows) for s in STATUSES}
    ledger['reported_counts']=reported_counts(rows)
    return ledger

def report_differences(report,ledger):
    """Cases whose run status differs from the committed ledger."""
    want={r['id']:r['status'] for r in ledger['cases']}
    return [f'{e["id"]}: ledger {want.get(e["id"])}, run {e["status"]}' for e in report if want.get(e['id'])!=e['status']]

def update_ledger(report,ledger):
    """Statuses from a run; a triage survives only while the case keeps the same non-pass status."""
    by_id={e['id']:e for e in report};rows=[]
    for r in ledger['cases']:
        e=by_id.get(r['id']);row=dict(r)
        if e is None:rows.append(row);continue
        if e['status']=='passed':
            for k in ('family','reason','spec','exchange','observed'):row.pop(k,None)
        elif r.get('status')!=e['status'] or not r.get('family'):
            row.update(family='untriaged',reason=e.get('detail',''));row.pop('evidence',None)
        row['status']=e['status'];rows.append(row)
    return finish_ledger(dict(ledger,cases=rows))

# ---------- execution ----------
def write_atomic(path,document):
    path.parent.mkdir(parents=True,exist_ok=True)
    fd,tmp=tempfile.mkstemp(prefix='.'+path.name+'.',dir=path.parent)
    try:
        with os.fdopen(fd,'w') as f:f.write(json.dumps(document,indent=2)+'\n')
        os.replace(tmp,path)
    except BaseException:
        pathlib.Path(tmp).unlink(missing_ok=True);raise


def main():
    parser=argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument('--binary',type=pathlib.Path,default=ROOT/'target/debug/keytend-kmip-server')
    parser.add_argument('--filter',nargs='*',default=[],help='Case identifiers to run (default: all 155)')
    parser.add_argument('--output',type=pathlib.Path,default=DEFAULT_OUTPUT)
    parser.add_argument('--diagnose',action='store_true',help='Include the decoded failing response in the report')
    parser.add_argument('--update-ledger',action='store_true',help='Rewrite ledger statuses from this full run (review the diff; changed non-passes become untriaged)')
    parser.add_argument('--configuration',help='Named non-default server setting from the ledger "configurations" (reported separately)')
    parser.add_argument('--corrected-documents',action='store_true',help='Apply docs/specs/legacy-corrected-documents.json (reported separately)')
    a=parser.parse_args()
    install_hooks()
    documents=L.load();inventory=json.loads(L.LEDGER.read_text());ledger=load_ledger()
    configuration=ledger['configurations'][a.configuration] if a.configuration else {}
    stray=sorted(k for k in os.environ if k.startswith('KMIP_') and k not in configuration.get('environment',{}))
    if stray:raise SystemExit(f'server environment {stray} is not part of the selected configuration; use --configuration')
    os.environ.update(configuration.get('environment',{}))
    run_label='+'.join(([a.configuration] if a.configuration else [])+(['corrected'] if a.corrected_documents else [])) or 'default'
    if a.update_ledger and run_label!='default':raise SystemExit('--update-ledger needs a default run')
    corrections={}
    if a.corrected_documents:
        for c in load_corrections()['corrections']:corrections.setdefault(c['case'],[]).append(c)
    rows={c['id']:c for c in inventory['cases']};fixtures=ledger.get('fixtures',{});case_fixture={r['id']:r.get('fixture') for r in ledger['cases']}
    # The messages must still be the ones the strict ledger pinned.
    for name,(item,cases) in documents.items():
        for case,row in zip(cases,L.inventory(item,cases)):
            if row['messages_sha256']!=rows[row['id']]['messages_sha256']:raise SystemExit(f'{row["id"]}: messages differ from docs/specs/legacy-inventory.json')
    # Private keys registered anywhere in the notes, indexed by public key, so a
    # public-key-only case can still be checked by independent decryption.
    corpus=P.corpus_private_keys({c['id']+str(i):ET.tostring(m['xml']) for item,cases in documents.values() for c in cases for i,m in enumerate(c['messages']) if m['xml'] is not None})
    binary_sha=hashlib.sha256(a.binary.read_bytes()).hexdigest()
    started=datetime.datetime.now(datetime.timezone.utc).isoformat();report=[]
    write_atomic(a.output,{'status':'running','mode':MODE,'run':run_label,'started_utc':started,'cases':[]})
    with tempfile.TemporaryDirectory(prefix='keytend-kmip-server-legacy-variations-') as d:
        server=Server(d,binary=a.binary);base_policy=json.loads((server.pki/'policy.json').read_text())
        endpoint=P.ClientEndpoint(server.pki) if configuration.get('client_endpoint') else None
        def configure(label,fixture={},version=None):
            server.stop();server.data=pathlib.Path(d)/'data'/re.sub('[^A-Za-z0-9.-]','_',label);server.data.mkdir(parents=True,mode=0o700)
            policy=json.loads(json.dumps(base_policy))
            if fixture.get('client_identity'):
                # Deployment setting for these notes: each verified credential is
                # its own client (Profiles 1.2 section 3.1.3), not the certificate.
                for principal in policy['principals'].values():
                    if principal['name']=='database':principal['client_identity']=fixture['client_identity']
            if endpoint and version:
                for principal in policy['principals'].values():
                    if principal['name']=='database':principal['client_endpoint']=endpoint.policy(server.pki,version)
            (server.pki/'policy.json').write_text(json.dumps(policy));write_credentials(server,fixture,policy);server.start()
        try:
            for name,(item,cases) in documents.items():
                for case in cases:
                    cid=case['id']
                    if a.filter and cid not in a.filter:continue
                    row=rows[cid];entry={'id':cid,'document':name,'protocol_versions':row['protocol_versions'],'exchanges':row['exchanges'],'transformations':[]}
                    fixture=fixtures.get(case_fixture.get(cid)) or {}
                    if fixture:entry['transformations'].append(fixture['label'])
                    if configuration:entry['transformations'].append(f'configuration {a.configuration}: {configuration["label"]}')
                    defect=document_defect_entry(case,row)
                    if defect:
                        entry.update(defect);configure(cid);entry['observed']=observe_published_bytes(server,case)
                        report.append(entry);print(cid,entry['status'],entry['observed'],flush=True);continue
                    replay=Replay(None,corpus);P.HARNESS_NOTES.clear();NOTES.clear()
                    try:
                        if cid in corrections:
                            case,labels=corrected_case(case,corrections[cid]);entry['transformations']+=labels
                            override=[c['fixture'] for c in corrections[cid] if c.get('fixture')]
                            if override:fixture=fixtures[override[0]];entry['transformations'].append(fixture['label'])
                        messages,rules=L.bind_dynamic(case)
                        if rules:entry['transformations'].append('legacy dynamic-value rules '+', '.join(sorted({f'{r[0]}:{r[1]}' for r in rules})))
                        entry['transformations']+=canonical_operations(messages)
                        plan=exchange_plan(case,messages)
                        if 'client-B' in plan:entry['transformations'].append(fixtures['dual_client']['label'])
                        replay.version=case_version(messages)
                        configure(cid,fixture,replay.version)
                        run_case(server,replay,messages,plan,entry,fixture)
                        open_=P.finish(replay)
                        entry['obligations']=[o.record() for o in replay.obligations]
                        if open_:entry.update(status='unverified',detail='; '.join(f'{o.kind} at {o.path}: {o.info.get("unverifiable","not verified")}' for o in open_))
                        elif entry['skipped_exchanges']:entry.update(status='partial',detail=f'server-to-client exchanges {entry["skipped_exchanges"]} not executed; all client-to-server exchanges passed')
                        else:entry['status']='passed'
                    except C.Unsupported as e:entry.update(status='failed',detail=f'harness: {e}',category=e.category)
                    except (AssertionError,ValueError,KeyError,ET.ParseError,OSError,EOFError) as e:
                        entry.update(status='failed',detail=str(e) or type(e).__name__)
                        if getattr(replay,'last_actual',None) is not None and a.diagnose:entry['actual_response']=P.render(replay.last_actual)
                    entry['variations']=sorted(replay.variations|P.HARNESS_NOTES|NOTES)
                    if replay.material_gets:entry['independent_material_gets']=len(replay.material_gets)
                    report.append(entry);print(cid,entry['status'],entry.get('detail','')[:200],flush=True)
        except BaseException as e:
            write_atomic(a.output,{'status':'interrupted' if isinstance(e,KeyboardInterrupt) else 'failed','mode':MODE,'started_utc':started,'error':f'{type(e).__name__}: {e}','traceback':traceback.format_exc(limit=8),'partial_cases':report})
            raise
        finally:server.stop()
    summary={s:sum(e['status']==s for e in report) for s in STATUSES}
    differences=report_differences(report,ledger) if run_label=='default' else []
    write_atomic(a.output,{'status':'complete','mode':MODE,'run':run_label,
        'server_environment':configuration.get('environment',{}),'client_endpoint':bool(endpoint),
        'conformance_credit':'none; separately labelled variation mode over non-normative Committee Notes; the strict legacy report is unchanged',
        'started_utc':started,'finished_utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'selection':a.filter or 'all',
        'runtime_binary_sha256':binary_sha,'source_commit':source_commit()[0],'hooks':HOOKS,
        'summary':summary,'ledger_differences':differences,'cases':report})
    print(summary)
    for line in differences:print('ledger difference:',line)
    if a.update_ledger:
        if a.filter:raise SystemExit('--update-ledger needs a full run')
        LEDGER.write_text(json.dumps(update_ledger(report,ledger),indent=1)+'\n');print('wrote',LEDGER)

if __name__=='__main__':main()
