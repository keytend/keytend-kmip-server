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

"""Record non-default legacy-note replay runs in the ledger and derive each case's reported status.

The default run's statuses come from
`oasis_legacy_replay.py --update-ledger`. This adds the separately labelled
runs that prove a configuration-dependent or corrected-document case (for
example `--configuration 3des` or `--corrected-documents`) as per-case
evidence, then recomputes the reported status of every row with the same
vocabulary as scripts/oasis_inventory.py. A new or changed failure in an
evidence run becomes untriaged until its family is filled in by hand; the
ledger validator in scripts/test_oasis_legacy_replay.py fails until then.

`--rerun BINARY --outdir DIR` is the release mode: it replays the default run
and every evidence run recorded in the ledger (same configuration, corrected
documents and case selection) against BINARY, writes the reports and the
derived ledger to DIR, leaves the committed ledger untouched, and exits 1 if
any case changed status or any evidence is untriaged.
"""
import argparse,hashlib,json,pathlib,subprocess,sys
import oasis_legacy_replay as R

def rerun(binary,outdir,image=None,engine='podman'):
    outdir.mkdir(parents=True,exist_ok=True)
    def replay(name,flags):
        out=outdir/f'legacy-{name}.json'
        subprocess.run([sys.executable,str(R.ROOT/'scripts/oasis_legacy_replay.py'),'--binary',str(binary),*(['--image',image,'--engine',engine] if image else []),*flags,'--output',str(out)],cwd=R.ROOT,check=False)
        return json.loads(out.read_text())
    committed=R.load_ledger()
    ledger=R.update_ledger(replay('default',[])['cases'],json.loads(json.dumps(committed)))
    for label,run in committed.get('evidence_runs',{}).items():
        flags=[]
        for part in label.split('+'):
            flags+=['--corrected-documents'] if part=='corrected' else ['--configuration',part]
        report=replay(label,flags+['--filter',*run['selection']])
        ledger=R.record_evidence(ledger,report)
        identity={'runtime':report['runtime']} if 'runtime' in report else {'runtime_binary_sha256':report['runtime_binary_sha256']}
        ledger['evidence_runs'][label]={**{k:v for k,v in run.items() if k not in ('runtime','runtime_binary_sha256')},**identity,'finished_utc':report['finished_utc'],'summary':report['summary']}
    ledger=R.finish_ledger(ledger)
    (outdir/'legacy-ledger.json').write_text(json.dumps(ledger,indent=1)+'\n')
    before={r['id']:r.get('reported') for r in committed['cases']}
    changed=[f"{r['id']}: {before.get(r['id'])} -> {r.get('reported')}" for r in ledger['cases'] if before.get(r['id'])!=r.get('reported')]
    untriaged=[f'{r["id"]} {run}' for r in ledger['cases'] for run,ev in r.get('evidence',{}).items() if ev.get('family')=='untriaged']
    print(json.dumps(ledger['reported_counts'],indent=1))
    for line in changed:print('changed:',line,file=sys.stderr)
    for line in untriaged:print('untriaged:',line,file=sys.stderr)
    return 1 if changed or untriaged else 0

def main():
    p=argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument('reports',nargs='*',type=pathlib.Path,help='complete non-default runs of scripts/oasis_legacy_replay.py')
    p.add_argument('--rerun',type=pathlib.Path,metavar='BINARY',help='release mode: replay default and recorded evidence runs against BINARY')
    p.add_argument('--outdir',type=pathlib.Path,help='output directory for --rerun')
    p.add_argument('--image',help='with --rerun: the image that BINARY runs (scripts/image_server.py), recorded as the server under test')
    p.add_argument('--engine',default='podman')
    a=p.parse_args()
    if a.rerun:
        if not a.outdir:p.error('--rerun needs --outdir')
        sys.exit(rerun(a.rerun.resolve(),a.outdir.resolve(),a.image,a.engine))
    if not a.reports:p.error('give reports or --rerun')
    ledger=R.load_ledger()
    for path in a.reports:
        report=json.loads(path.read_text())
        ledger=R.record_evidence(ledger,report)
        identity={'runtime':report['runtime']} if 'runtime' in report else {'runtime_binary_sha256':report['runtime_binary_sha256']}
        ledger.setdefault('evidence_runs',{})[report['run']]={'selection':report['selection'],**identity,
            'corrections_sha256':hashlib.sha256(R.CORRECTIONS.read_bytes()).hexdigest(),'finished_utc':report['finished_utc'],'summary':report['summary']}
    ledger=R.finish_ledger(ledger)
    R.LEDGER.write_text(json.dumps(ledger,indent=1)+'\n')
    untriaged=[f'{r["id"]} {run}' for r in ledger['cases'] for run,ev in r.get('evidence',{}).items() if ev.get('family')=='untriaged']
    print(json.dumps(ledger['reported_counts'],indent=1))
    if untriaged:print('untriaged evidence:',*untriaged,sep='\n  ',file=sys.stderr)

if __name__=='__main__':main()
