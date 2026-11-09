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

"""Controlled storage-key cutover in the existing disposable keytend-kmip-server fixture.
Run after test_kubernetes.py. Not an automated production rotation controller.
"""
import argparse, json, pathlib, subprocess, tempfile, time, uuid
from image_evidence import packaged_evidence, normalized_id
from test_runtime import ROOT, free_port
from wire import *

def main():
    p=argparse.ArgumentParser();p.add_argument('--kubeconfig',required=True);p.add_argument('--kubectl',default='kubectl');p.add_argument('--pki',required=True);a=p.parse_args()
    k=[a.kubectl,'--kubeconfig',str(pathlib.Path(a.kubeconfig).resolve()),'-n','keytend-kmip-server'];pki=pathlib.Path(a.pki).resolve()
    def command(*args):return subprocess.check_output(k+list(args),text=True,stderr=subprocess.STDOUT)
    def apply(value):subprocess.run(k+['apply','-f','-'],input=json.dumps(value),text=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE,check=True)
    def observe(action):
        port=free_port()
        with tempfile.TemporaryFile() as log:
            forward=subprocess.Popen(k+['port-forward','pod/keytend-kmip-server-0',f'{port}:5696','--address=127.0.0.1'],stdout=log,stderr=log)
            try:
                until=time.monotonic()+15
                while time.monotonic()<until:
                    try:
                        with connect(pki,port) as c:return action(c)
                    except ConnectionRefusedError:time.sleep(.1)
                raise TimeoutError('port-forward unavailable')
            finally:forward.terminate();forward.wait(timeout=5)
    baseline=json.loads((ROOT/'artifacts/kubernetes.json').read_text());assert baseline['status']=='passed'
    evidence=packaged_evidence(baseline['tested_image_config_id'])
    initial=json.loads(command('get','statefulset','keytend-kmip-server','-o','json'))
    container=initial['spec']['template']['spec']['containers'][0];image=container['image']
    environment={e['name']:e['value'] for e in container['env']}
    assert environment['KMIP_DATABASE']=='/data/kmip.sqlite' and initial['spec']['replicas']==1
    old_volume=next(v for v in initial['spec']['template']['spec']['volumes'] if v['name']=='master');old_secret=old_volume['secret']['secretName']
    report=dict(status='running',**evidence,checks=[],limits='single-node kind PVC and Secret cutover; no production CSI, HA or power-loss qualification')
    path=ROOT/'artifacts/storage-rotation/kubernetes.json';path.parent.mkdir(exist_ok=True);path.write_text(json.dumps(report,indent=2)+'\n')
    try:
        versions=[(1,1),(1,2),(1,3),(1,4),(2,0),(2,1)]
        def prepare(c):
            rows=[]
            for version in versions:
                identifier=create_key(c,version);rows.append((version,identifier,key_value(c,identifier,version)))
            return rows
        records=observe(prepare);report['checks'].append('six final-version keys created and independently retained before cutover')
        token=uuid.uuid4().hex[:10];new_secret='keytend-kmip-server-rotated-'+token;job_name='keytend-kmip-server-rotate-'+token;directory='rotation-'+token
        with tempfile.TemporaryDirectory(prefix='keytend-kube-rotation-') as d:
            new_key=pathlib.Path(d)/'master.key'
            subprocess.run([str(ROOT/'target/debug/keytend-kmip-server'),'generate-master-key','--output',str(new_key)],stdout=subprocess.PIPE,stderr=subprocess.PIPE,check=True)
            secret=json.loads(command('create','secret','generic',new_secret,'--from-file='+str(new_key),'--dry-run=client','-o','json'));apply(secret)
        command('scale','statefulset/keytend-kmip-server','--replicas=0');command('wait','--for=delete','pod/keytend-kmip-server-0','--timeout=90s')
        security={'runAsNonRoot':True,'runAsUser':10001,'runAsGroup':10001,'fsGroup':10001,'seccompProfile':{'type':'RuntimeDefault'}}
        # One executable invocation: it creates the 0700 directory, rotates, and
        # checks that only the new key opens the copy and the source still verifies.
        job_args=['rotate-master-key','--database','/data/kmip.sqlite','--master-key','/old/master.key','--new-master-key','/new/master.key','--output',f'/data/{directory}/kmip.sqlite','--create-directory']
        apply({'apiVersion':'batch/v1','kind':'Job','metadata':{'name':job_name,'namespace':'keytend-kmip-server'},'spec':{'backoffLimit':0,'activeDeadlineSeconds':120,'template':{'spec':{'restartPolicy':'Never','automountServiceAccountToken':False,'securityContext':security,'containers':[{'name':'rotate','image':image,'imagePullPolicy':'IfNotPresent','command':['/usr/local/bin/keytend-kmip-server'],'args':job_args,'securityContext':{'allowPrivilegeEscalation':False,'readOnlyRootFilesystem':True,'capabilities':{'drop':['ALL']}},'resources':{'limits':{'cpu':'2','memory':'512Mi'}},'volumeMounts':[{'name':'scratch','mountPath':'/tmp'},{'name':'data','mountPath':'/data'},{'name':'old','mountPath':'/old','readOnly':True},{'name':'new','mountPath':'/new','readOnly':True}]}],'volumes':[{'name':'scratch','emptyDir':{'medium':'Memory','sizeLimit':'64Mi'}},{'name':'data','persistentVolumeClaim':{'claimName':'data-keytend-kmip-server-0'}},{'name':'old','secret':{'secretName':old_secret,'defaultMode':288}},{'name':'new','secret':{'secretName':new_secret,'defaultMode':288}}]}}}})
        command('wait','--for=condition=complete','job/'+job_name,'--timeout=130s')
        logs=command('logs','job/'+job_name);(ROOT/'artifacts/storage-rotation/kubernetes-job.log').write_text(logs)
        job_pod=json.loads(command('get','pods','-l','job-name='+job_name,'-o','json'))['items'][0]
        # The immutable runtime manifest used by the baseline must match the Job.
        job_image=job_pod['status']['containerStatuses'][0]['imageID'];assert normalized_id(job_image)==normalized_id(baseline['image_id'])
        report['checks'].append('nonroot Job rotated PVC snapshot, verified the new key, refused the old key, and retained the source with the old key')
        report['job_image_id']=job_image
        command('patch','statefulset','keytend-kmip-server','--type=strategic','-p',json.dumps({'spec':{'template':{'spec':{'containers':[{'name':'kmip','env':[{'name':'KMIP_DATABASE','value':f'/data/{directory}/kmip.sqlite'}]}],'volumes':[{'name':'master','secret':{'secretName':new_secret,'defaultMode':288}}]}}}}))
        command('scale','statefulset/keytend-kmip-server','--replicas=1');command('rollout','status','statefulset/keytend-kmip-server','--timeout=120s')
        def verify(c):
            for version,identifier,material in records:assert key_value(c,identifier,version)==material
        observe(verify);report['checks'].append('controlled snapshot/Secret cutover recovered exact keys on all six final requested versions')
        command('exec','keytend-kmip-server-0','--','keytend-kmip-server','check-store','--database',f'/data/{directory}/kmip.sqlite','--master-key','/master/master.key')
        command('delete','pod','keytend-kmip-server-0','--wait=true');command('rollout','status','statefulset/keytend-kmip-server','--timeout=120s');observe(verify)
        report['checks'].append('replacement pod retained new-key storage, exact key bytes and valid object/audit integrity')
        current=json.loads(command('get','pod','keytend-kmip-server-0','-o','json'));assert current['status']['containerStatuses'][0]['imageID']==baseline['image_id']
        report['status']='passed'
    except BaseException as e:report['status']='failed';report['error']=str(e);raise
    finally:path.write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps(report['checks']))
if __name__=='__main__':main()
