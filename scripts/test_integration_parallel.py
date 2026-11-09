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

"""Run the integration groups against one image concurrently; exit 1 if any group fails.

Each group runs its scripts in order. Database groups additionally share --db-slots
(each PBM group owns a three-member replica set), so the host is not overloaded.
"""
import argparse,concurrent.futures,datetime,hashlib,json,pathlib,shutil,subprocess,tempfile,threading
from image_evidence import ROOT,local_image_id,packaged_evidence

DB_GROUPS=frozenset({'database-baseline','pbm','pbm-compromised','pbm-destroyed',
    'pbm-missing-oplog','pbm-corrupt-oplog','pbm-interrupted','psmdb-negatives','mysql'})

# Child scripts that write fixed paths under artifacts/; their reports are copied
# into the attempt directory after the group. Other groups receive --output.
FIXED_ARTIFACTS={
    'hash':['hash-operations'],
    'base-clients':['interop*.json','interop*.log','pykmip.log','libkmip.log',
        'ovh.log','ovh-release.log','thales.log','nlnet.log'],
    'ibm-client':['ibm-client*.json'],
    'runtime':['runtime.json'],
    're-provision':['re-provision'],
    'idle-timeout':['idle-timeout.json','idle-timeout-image.json'],
    'metrics':['metrics.json','metrics-image.json'],
    'live-history':['live-history'],
    'policy-storage':['object-state','audit-checkpoint','storage-rotation'],
    'database-baseline':['database.json','database.log','database-rotation.log',
        'database-kmip.log','database-replicaset','database-outage','database-backup'],
    'contract':['catalog-probes.json'],
}

def copy_artifacts(name,destination):
    for pattern in FIXED_ARTIFACTS.get(name,[]):
        for path in (ROOT/'artifacts').glob(pattern):
            for source in (path.rglob('*') if path.is_dir() else [path]):
                if source.is_file() and source.suffix in {'.json','.log'}:
                    target=destination/source.relative_to(ROOT/'artifacts')
                    target.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(source,target)

def new_attempt(directory):
    directory.mkdir(parents=True,exist_ok=True)
    stamp=datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%SZ')
    return pathlib.Path(tempfile.mkdtemp(prefix='attempt-'+stamp+'-',dir=directory))

def now():return datetime.datetime.now(datetime.timezone.utc).isoformat()
def sha(path):return hashlib.sha256(pathlib.Path(path).read_bytes()).hexdigest()

def jobs_for(image,ibm_client_image,out):
    def cmd(script,*args):return ['python3','scripts/'+script+'.py',*args]
    def img(script,*args):return cmd(script,*args,'--image',image)
    def fixture(name):return ['--output',str(out/(name+'-fixture'))]
    return {
        'hash':[img('test_hash_operations')],
        'base-clients':[img('test_interop','--skip-build')],
        'ibm-client':[img('test_ibm_client','--client-image',ibm_client_image)],
        # Restart persistence, tenancy and hostile frames against the native executable.
        'runtime':[cmd('test_runtime','--skip-build')],
        # Re-Provision against the native executable (docs/re-provision.md).
        're-provision':[cmd('test_re_provision','--skip-build')],
        'live-history':[img('test_live_history')],
        'lease-lifecycle':[img('test_lease_lifecycle')],
        'idle-timeout':[img('test_idle_timeout')],
        'metrics':[img('test_metrics')],
        'policy-storage':[img(n) for n in ['test_object_state','test_audit_checkpoint','test_storage_rotation']],
        'database-baseline':[img(n) for n in ['test_database','test_database_replicaset','test_database_outage','test_database_backup']],
        'pbm':[img('test_database_pbm',*fixture('pbm'))],
        'pbm-compromised':[img('test_database_pbm_adverse','--scenario','compromised-key',*fixture('pbm-compromised'))],
        'pbm-destroyed':[img('test_database_pbm_adverse','--scenario','destroyed-key',*fixture('pbm-destroyed'))],
        'pbm-missing-oplog':[img('test_database_pbm_chain','--scenario','missing-oplog',*fixture('pbm-missing-oplog'))],
        'pbm-corrupt-oplog':[img('test_database_pbm_chain','--scenario','corrupt-oplog',*fixture('pbm-corrupt-oplog'))],
        'pbm-interrupted':[img('test_database_pbm_interrupt',*fixture('pbm-interrupted'))],
        'psmdb-negatives':[img('test_database_psmdb_negatives',*fixture('psmdb-negatives'))],
        'mysql':[img('test_database_mysql',*fixture('mysql'))],
        'contract':[img('test_catalog_contract')],
    }

def run_groups(jobs,out,workers,db_slots,timeout=7200):
    """Run every group; database groups also hold one of db_slots. Returns {name: result}."""
    db=threading.Semaphore(db_slots)
    def run(name,commands):
        result={'status':'running','steps':[]}
        with (db if name in DB_GROUPS else threading.Lock()):
            result['started_at']=now()
            try:
                for i,command in enumerate(commands):
                    log=out/f'{name}-{i}.log'
                    step={'command':command,'log':str(log.relative_to(out))};result['steps'].append(step)
                    try:
                        with log.open('w') as stream:step['exit_code']=subprocess.run(command,cwd=ROOT,stdout=stream,stderr=subprocess.STDOUT,timeout=timeout).returncode
                    except subprocess.TimeoutExpired:step['exit_code']=None;step['timed_out']=True
                    step['log_sha256']=sha(log)
                    if step['exit_code']!=0:raise RuntimeError(f'step {i} exit {step["exit_code"]}')
                result['status']='passed'
            except Exception as error:result.update(status='failed',error=str(error))
            try:copy_artifacts(name,out/name)
            except Exception as error:result.update(status='failed',artifact_error=str(error))
            result['finished_at']=now()
        (out/(name+'.json')).write_text(json.dumps(result,indent=2)+'\n')
        return result
    # Database groups go last, so ones waiting for a slot never hold workers the others need.
    order=sorted(jobs,key=lambda name:name in DB_GROUPS)
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
        futures={pool.submit(run,name,jobs[name]):name for name in order}
        for future in concurrent.futures.as_completed(futures):
            name=futures[future];result=future.result();print(name,result['status'],flush=True)
            yield name,result

def main(argv=None):
    p=argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument('--image',required=True)
    p.add_argument('--ibm-client-image',default='localhost/keytend-kmip-server-ibm-client:2.44.1',help='IBM consumer fixture image')
    p.add_argument('--workers',type=int,default=8)
    p.add_argument('--db-slots',type=int,default=3,help='concurrent database groups (default: 3)')
    p.add_argument('--groups',nargs='+',help='run only these groups (each run is a new attempt directory)')
    a=p.parse_args(argv)
    if not 1<=a.workers<=16:p.error('workers must be between 1 and 16')
    if not 1<=a.db_slots<=9:p.error('db-slots must be between 1 and 9')
    out=new_attempt(ROOT/'artifacts/integration-qualification')
    print('qualification attempt:',out.relative_to(ROOT),flush=True)
    commit=subprocess.check_output(['git','rev-parse','HEAD'],cwd=ROOT,text=True).strip()
    jobs=jobs_for(a.image,a.ibm_client_image,out)
    if a.groups:
        unknown=set(a.groups)-set(jobs)
        if unknown:p.error('unknown groups: '+', '.join(sorted(unknown)))
        jobs={name:commands for name,commands in jobs.items() if name in a.groups}
    report={'status':'running','started_at':now(),'commit':commit,'workers':a.workers,'db_slots':a.db_slots,
        **packaged_evidence(local_image_id('podman',a.image)),'jobs':{}}
    def save():
        temp=out/'summary.json.tmp';temp.write_text(json.dumps(report,indent=2)+'\n');temp.replace(out/'summary.json')
    save()
    for name,result in run_groups(jobs,out,a.workers,a.db_slots):report['jobs'][name]=result;save()
    report['status']='failed' if any(r['status']!='passed' for r in report['jobs'].values()) else 'passed'
    report['finished_at']=now();save()
    if report['status']!='passed':raise SystemExit(1)

if __name__=='__main__':main()
