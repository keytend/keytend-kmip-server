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

"""Build the per-case OASIS inventory from a strict and a variation report.

Every one of the strict report's entries appears once, with its unchanged
strict status and its separately labelled variation result. Each non-passing
variation result must match exactly one family in
docs/specs/oasis-variation-families.json; an unexplained or doubly explained
case is an error. The output grants no conformance credit.
"""
import argparse,collections,hashlib,json,pathlib,re,sys
ROOT=pathlib.Path(__file__).resolve().parents[1]
FAMILIES=ROOT/'docs/specs/oasis-variation-families.json'

def key(e):return f"{e['version']}|{e['case']}"

# Reported status. "failed" means only that the server lacks the behavior or
# implements it wrongly. A case that needs a non-default setting, cannot be
# verified without disturbing the trace, or is a proven trace defect whose
# labelled correction passes is reported as such, never as a failure.
def family_of(families,status,detail,k):
    families=[f for f in families if f.get('mode')!='fips']
    hits=[f for f in families if f['status']==status and re.search(f['detail'],detail or '') and (not f.get('cases') or re.search(f['cases'],k))]
    return hits[0] if len(hits)==1 else None

def reported(k,ve,family,families,configured,corrected,depth=0):
    if ve['status']=='passed':return 'passed'
    if ve['status']=='excluded_non_trace':return 'excluded (not a trace)'
    if ve['status']=='delegated':return 'delegated (legacy test-case harness)'
    if family is None:return 'failed'
    ws=family['workstream']
    def follow(other,label):
        if other is None:return None
        oe=other.get(k)
        if oe is None:return None
        if oe['status']=='passed':return label
        if depth>1:return 'failed'
        nxt=family_of(families,oe['status'],oe.get('detail'),k)
        return reported(k,oe,nxt,families,configured,corrected,depth+1)
    if ws=='corpus':
        return follow(corrected,'passed (corrected fixture)') or 'corpus defect (no corrected run)'
    if ws=='alternative':return 'not applicable (alternative outcome; the server implements another listed outcome)'
    if family.get('configuration'):
        cfg=family['configuration'];other=(configured or {}).get(cfg['report'])
        return follow(other,f"skipped (configuration: passes with {cfg['setting']})") or f"skipped (configuration: needs {cfg['setting']})"
    if ws=='policy':return 'skipped (unverifiable without disturbing the trace)'
    if ws=='interpretation':return 'documented deviation'
    return 'failed'

def build(strict,variation,families,configured=None,corrected=None):
    s={key(e):e for e in strict['cases']};v={key(e):e for e in variation['cases']}
    if len(s)!=len(strict['cases']) or len(v)!=len(variation['cases']):raise SystemExit('duplicate case keys in a report')
    if set(s)!=set(v):raise SystemExit(f'reports cover different cases: {sorted(set(s)^set(v))[:5]}')
    cases={};errors=[];counts=collections.Counter()
    for k in sorted(s):
        se,ve=s[k],v[k];entry={'strict':{'status':se['status'],**({'category':se['category']} if se.get('category') else {})},'variation':{'status':ve['status']}}
        for field in ('transformations','variations'):
            if ve.get(field):entry['variation'][field]=ve[field]
        if ve['status'] not in ('passed',):
            if ve.get('detail'):entry['variation']['detail']=ve['detail'][:300]
        if ve['status'] in ('failed','unexecuted','unverified'):
            hits=[f for f in families if f.get('mode')!='fips' and f['status']==ve['status'] and re.search(f['detail'],ve.get('detail') or '') and (not f.get('cases') or re.search(f['cases'],k))]
            if len(hits)!=1:errors.append(f'{k}: {len(hits)} families match {ve.get("detail")!r}')
            else:entry['family']=hits[0]['id'];entry['workstream']=hits[0]['workstream'];counts[(hits[0]['workstream'],hits[0]['id'])]+=1
        family=next((f for f in families if f['id']==entry.get('family')),None)
        entry['reported']=reported(k,ve,family,families,configured,corrected)
        if family and family.get('configuration'):
            # Name the family that still blocks the case under its setting.
            oe=(configured or {}).get(family['configuration']['report'],{}).get(k)
            nxt=oe and oe['status']!='passed' and family_of(families,oe['status'],oe.get('detail'),k)
            if nxt:entry['configured_family']=nxt['id']
        cases[k]=entry
    return cases,errors,counts

# FIPS mode (docs/fips.md) is default mode minus non-approved services. A case
# that fails only in the FIPS-mode report must be explained by a "mode": "fips"
# family (a FIPS refusal or a Query listing without the refused services);
# anything else means FIPS mode changed an approved result, which is an error.
def fips_build(cases,variation,fips,families):
    v={key(e):e for e in variation['cases']}
    fams=[f for f in families if f.get('mode')=='fips'];errors=[];used=set()
    if set(fips)!=set(v):raise SystemExit('the FIPS report covers different cases')
    for k,entry in cases.items():
        fe=fips[k];out={'status':fe['status']}
        if fe['status']!='passed' and fe.get('detail'):out['detail']=fe['detail'][:300]
        if fe['status'] in ('passed','excluded_non_trace','delegated'):
            out['reported']=entry['reported'] if fe['status']!='passed' else 'passed'
        else:
            hits=[f for f in fams if f['status']==fe['status'] and re.search(f['detail'],fe.get('detail') or '') and (not f.get('cases') or re.search(f['cases'],k))]
            if len(hits)==1:
                out['family']=hits[0]['id'];used.add(hits[0]['id'])
                out['reported']=f"skipped (configuration: needs {hits[0]['configuration']['setting']})"
            elif len(hits)>1:errors.append(f'{k}: {len(hits)} FIPS families match')
            elif v[k]['status']=='passed':errors.append(f'{k}: passes in default mode but not in FIPS mode, and no FIPS family explains {fe.get("detail")!r}')
            elif next((f for f in families if f['id']==entry.get('family')),{}).get('fips_incompatible'):
                out['reported']='skipped (configuration: needs non-FIPS mode)'
            else:out['reported']=f"as in default mode: {entry['reported']}"
        entry['fips']=out
    return errors,used

def main():
    p=argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument('strict',type=pathlib.Path);p.add_argument('variation',type=pathlib.Path)
    p.add_argument('--output',type=pathlib.Path,default=ROOT/'docs/specs/oasis-case-inventory.json')
    p.add_argument('--configured',action='append',default=[],metavar='NAME=REPORT',help='variation report under a non-default server setting, e.g. 3des=report.json or interop=report.json; fips=report.json adds the FIPS-mode (KMIP_FIPS=true) result of each case')
    p.add_argument('--corrected',type=pathlib.Path,help='variation report with --corrected-fixtures')
    a=p.parse_args()
    load=lambda path:{key(e):e for e in json.loads(path.read_text())['cases']} if path else None
    strict=json.loads(a.strict.read_text());variation=json.loads(a.variation.read_text());families=json.loads(FAMILIES.read_text())['families']
    if strict.get('comparison_policy')!='strict':raise SystemExit('first report must be a strict report')
    if variation.get('mode')!='profiles-4.1-variations' or variation.get('status')!='complete':raise SystemExit('second report must be a complete variation report')
    configured={name:load(pathlib.Path(path)) for name,path in (c.split('=',1) for c in a.configured)}
    fips=configured.pop('fips',None)
    cases,errors,counts=build(strict,variation,families,configured,load(a.corrected))
    fips_used=set()
    if fips is not None:
        fips_errors,fips_used=fips_build(cases,variation,fips,families);errors+=fips_errors
    report_counts=collections.Counter(c['reported'] for c in cases.values())
    if errors:
        print('\n'.join(errors),file=sys.stderr);raise SystemExit(f'{len(errors)} cases are not explained by exactly one family')
    used={f for _,f in counts}|{c['configured_family'] for c in cases.values() if 'configured_family' in c}|fips_used;unused=[f['id'] for f in families if f['id'] not in used and (fips is not None or f.get('mode')!='fips')]
    out={'schema':1,'conformance_credit':'none',
         'scope':'Strict result unchanged; variation mode separately labelled (Profiles 4.1). Families name the first blocker only.',
         'strict_report':{'sha256':hashlib.sha256(a.strict.read_bytes()).hexdigest(),'runtime_binary_sha256':strict['runtime_binary_sha256'],'summary':strict['summary']},
         'variation_report':{'sha256':hashlib.sha256(a.variation.read_bytes()).hexdigest(),'runtime_binary_sha256':variation['runtime_binary_sha256'],'summary':variation['summary']},
         'reported_counts':dict(sorted(report_counts.items())),
         'family_counts':{f'{w}/{f}':n for (w,f),n in sorted(counts.items())},'unused_families':unused,'cases':cases}
    if fips is not None:
        out['fips_reported_counts']=dict(sorted(collections.Counter(c['fips']['reported'] for c in cases.values()).items()))
    a.output.write_text(json.dumps(out,indent=1)+'\n')
    print(json.dumps({'reported':dict(sorted(report_counts.items())),**({'fips_reported':out['fips_reported_counts']} if fips is not None else {}),'strict':strict['summary'],'variation':variation['summary'],'by_workstream':dict(collections.Counter(w for w,_ in counts.elements())),'unused_families':unused}))
if __name__=='__main__':main()
