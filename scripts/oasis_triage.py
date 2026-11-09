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

"""Check that every non-passing strict OASIS case belongs to exactly one triage family.
The check reads a strict report and never writes it. A classification explains a
mismatch; it never changes a case status or total and never grants conformance credit.
Unclassified, overlapping, drifted or stale cases, binary changes and unverifiable
citations all fail.
"""
import argparse,collections,hashlib,html.parser,json,pathlib,re,sys,unicodedata,zipfile
ROOT=pathlib.Path(__file__).resolve().parents[1]
LEDGER=ROOT/'docs/specs/oasis-triage.json'
CLASSIFICATIONS={'missing_server_feature','server_defect','permitted_reference_choice','fixture_corpus_or_harness','dependency_determinism_interop','unresolved_spec_ambiguity'}
STATUSES={'failed','unexecuted'}
FULL_SELECTION={'versions':['1.1','1.2','1.3','1.4','2.0','2.1','3.0'],'filter':''}

def case_key(case):return case['version']+'|'+case['case']
def report_identity(report):
    return {'runtime_binary_sha256':report.get('runtime_binary_sha256'),'selection':report.get('selection')}

def validate_ledger(ledger):
    problems=[];seen={};ids=set()
    identity=ledger.get('identity')
    required={'runtime_binary_sha256','selection'}
    if not isinstance(identity,dict) or any(not identity.get(k) for k in required):
        problems.append('ledger must pin the runtime binary and selection identity')
    if ledger.get('conformance_credit')!='none':problems.append('ledger must grant no conformance credit')
    for family in ledger.get('families',[]):
        fid=family.get('id')
        if not fid or fid in ids:problems.append(f'duplicate or missing family id {fid!r}')
        ids.add(fid)
        if family.get('classification') not in CLASSIFICATIONS:problems.append(f'{fid}: unknown classification {family.get("classification")!r}')
        if family.get('status') not in STATUSES:problems.append(f'{fid}: unknown status {family.get("status")!r}')
        if not family.get('authority'):problems.append(f'{fid}: no authority cited')
        for cite in family.get('authority',[]):
            if any(not isinstance(cite.get(k),str) or not cite[k].strip() for k in ('source','ref','quote')):
                problems.append(f'{fid}: authority needs a nonempty source, reference and quote')
        if not family.get('cases'):problems.append(f'{fid}: no cases')
        try:re.compile(family.get('detail',''))
        except re.error as e:problems.append(f'{fid}: invalid detail pattern: {e}')
        for key in family.get('cases',{}):
            if key in seen:problems.append(f'{key}: listed in {seen[key]} and {fid}')
            seen[key]=fid
    return problems

def classify(report,ledger):
    """Return (assignments, problems). A case must match exactly one family by key,
    status, failed exchange and detail pattern."""
    families=ledger['families'];problems=[];assigned=collections.defaultdict(list)
    cases={case_key(c):c for c in report['cases']}
    if len(cases)!=len(report['cases']):problems.append('report contains duplicate case keys')
    for key,case in cases.items():
        listed=[f for f in families if key in f['cases']]
        if case['status']=='passed':
            for f in listed:problems.append(f'{key}: passes but is listed in {f["id"]}; remove it from the ledger')
            continue
        if not listed:problems.append(f'{key}: unclassified {case["status"]} case: {case.get("detail","")[:200]}');continue
        if len(listed)>1:problems.append(f'{key}: matches several families {[f["id"] for f in listed]}');continue
        family=listed[0];detail=case.get('detail','')
        if case['status']!=family['status']:problems.append(f'{key}: status {case["status"]} differs from {family["id"]} ({family["status"]})');continue
        if case.get('failed_exchange')!=family['cases'][key]:problems.append(f'{key}: failed exchange {case.get("failed_exchange")} differs from {family["id"]} ({family["cases"][key]})');continue
        if not re.fullmatch(family['detail'],detail):problems.append(f'{key}: detail drifted from {family["id"]}: {detail[:200]}');continue
        assigned[family['id']].append(key)
    for family in families:
        for key in family['cases']:
            if key not in cases:problems.append(f'{key}: listed in {family["id"]} but absent from the report')
    return assigned,problems

class Text(html.parser.HTMLParser):
    def __init__(self):super().__init__();self.parts=[];self.skip=0
    def handle_starttag(self,tag,attrs):
        if tag in ('script','style'):self.skip+=1
        self.parts.append(' ')
    def handle_endtag(self,tag):
        if tag in ('script','style'):self.skip-=1
        self.parts.append(' ')
    def handle_data(self,data):
        if not self.skip:self.parts.append(data)
def normalize(text):
    text=unicodedata.normalize('NFKC',text)
    for a,b in {'‘':"'",'’':"'",'“':'"','”':'"','\u2013':'-','\u2014':'-','­':''}.items():text=text.replace(a,b)
    return re.sub(r'\s+',' ',text).strip()
def source_text(source,root):
    path=root/source['file']
    data=path.read_bytes()
    if hashlib.sha256(data).hexdigest()!=source['sha256']:raise ValueError(f'{source["file"]}: SHA-256 differs from the pinned manifest')
    if source.get('member'):
        data=zipfile.ZipFile(path).read(source['member'])
        if hashlib.sha256(data).hexdigest()!=source['member_sha256']:raise ValueError(f'{source["member"]}: member SHA-256 differs')
    if not source['file'].endswith(('.html','.zip')):return normalize(data.decode('utf-8','replace'))
    try:decoded=data.decode('utf-8')
    except UnicodeDecodeError:decoded=data.decode('windows-1252')
    parser=Text();parser.feed(decoded);return normalize(''.join(parser.parts))

def verify_sources(ledger,root=ROOT):
    """Every cited quote must occur in its pinned, checksum-verified primary source."""
    problems=[];texts={}
    for sid,source in ledger['sources'].items():
        try:texts[sid]=source_text(source,root)
        except (OSError,KeyError,ValueError,zipfile.BadZipFile) as e:problems.append(f'source {sid}: {e}')
    def check(owner,cite):
        if not isinstance(cite.get('quote'),str) or not normalize(cite['quote']):problems.append(f'{owner}: empty citation quote');return
        if cite['source'] not in ledger['sources']:problems.append(f'{owner}: unknown source {cite["source"]}');return
        if cite['source'] in texts and normalize(cite['quote']) not in texts[cite['source']]:problems.append(f'{owner}: quote not found in {cite["source"]} ({cite["ref"]}): {cite["quote"][:120]}')
    for family in ledger['families']:
        for cite in family['authority']:check(family['id'],cite)
    for finding in ledger.get('findings',[]):
        for cite in finding.get('authority',[]):check(finding['id'],cite)
    return problems

def triage(report,ledger):
    problems=validate_ledger(ledger)
    if report.get('comparison_policy')!='strict' or report.get('diagnostic_only') is not False:problems.append('triage requires a strict, non-diagnostic report')
    if report.get('status') not in ('passed','failed'):problems.append(f'report status is {report.get("status")!r}; only completed strict reports can be triaged')
    if report.get('selection')!=FULL_SELECTION:problems.append(f'report selection {report.get("selection")} is not the full strict run')
    identity=report_identity(report)
    pinned=ledger.get('identity')
    for name,value in (pinned if isinstance(pinned,dict) else {}).items():
        if name in identity and identity[name]!=value:problems.append(f'report {name} differs from the triaged identity; re-triage this runtime')
    recount={s:sum(c['status']==s for c in report['cases']) for s in ('passed','failed','unexecuted')}
    if report.get('summary')!=recount:problems.append(f'report summary {report.get("summary")} disagrees with its cases {recount}')
    if recount!=ledger['expected_summary']:problems.append(f'strict totals {recount} differ from the ledger {ledger["expected_summary"]}')
    assigned,classified=classify(report,ledger) if not problems else ({},[])
    problems+=classified
    by_class=collections.Counter()
    for family in ledger['families']:by_class[family['status']+':'+family['classification']]+=len(assigned.get(family['id'],[]))
    return {'scope':'classification of strict results only; no case status or total is changed and no classification is a conformance pass',
            'strict_status':report.get('status'),'strict_summary':report.get('summary'),'conformance_credit':'none','identity':identity,
            'by_classification':dict(sorted((k,v) for k,v in by_class.items() if v)),
            'families':{f['id']:{'status':f['status'],'classification':f['classification'],'count':len(assigned.get(f['id'],[]))} for f in ledger['families']},
            'problems':problems}

def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument('report',type=pathlib.Path,nargs='?',default=ROOT/'artifacts/oasis.json')
    parser.add_argument('--ledger',type=pathlib.Path,default=LEDGER)
    parser.add_argument('--output',type=pathlib.Path)
    parser.add_argument('--verify-sources',action='store_true',help='also verify every cited quote against the pinned primary sources in .cache/specs')
    a=parser.parse_args(argv)
    if a.output and a.output.resolve()==a.report.resolve():parser.error('--output must not overwrite the strict report')
    raw=a.report.read_bytes();report=json.loads(raw);ledger=json.loads(a.ledger.read_text())
    result=triage(report,ledger);result['report']=str(a.report);result['report_sha256']=hashlib.sha256(raw).hexdigest()
    if a.verify_sources:result['problems']+=verify_sources(ledger)
    if a.output:a.output.parent.mkdir(parents=True,exist_ok=True);a.output.write_text(json.dumps(result,indent=2)+'\n')
    for name,count in result['by_classification'].items():print(f'{count:4} {name}')
    print('report',result['strict_status'],result['strict_summary'],'(unchanged; no conformance credit)')
    for problem in result['problems']:print('PROBLEM',problem,file=sys.stderr)
    return 1 if result['problems'] else 0
if __name__=='__main__':raise SystemExit(main())
