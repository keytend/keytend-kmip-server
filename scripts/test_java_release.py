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

"""Published keytend-kmip release suite and strict evidence collector.

Default execution fails for any applicable failed, unsupported or blocked case.
--report-only preserves those findings without treating them as qualification.
--collect-only verifies already completed reports.
"""
import argparse,collections,json,pathlib,re,subprocess,sys
from image_evidence import local_image_id,packaged_evidence
import keytend_kmip_release
from keytend_kmip_release import ROOT,release,sha

VERSIONS={'1.1','1.2','1.3','1.4','2.0','2.1'}
OPT_IN_SOAK='JAVA-06'
UPGRADE='JAVA-07'

def collect(engine,image):
    client,jars,artifact=release()
    config=local_image_id(engine,image);packaged=packaged_evidence(config)
    reports={};files={}
    paths={'catalog':'artifacts/java-catalog/summary.json',
           'https_native':'artifacts/https.json',
           'https_image':'artifacts/https-image.json',
           'wrapping_native':'artifacts/java-release-wrapping/native-summary.json',
           'wrapping_image':'artifacts/java-release-wrapping/image-summary.json',
           'contract':'artifacts/catalog-probes.json'}
    def retain(name):
        path=ROOT/name;files[name]=sha(path);return json.loads(path.read_text())
    for name,path in paths.items():
        report=retain(path);reports[name]=report
        assert report['status'] in ({'passed','incomplete'} if name=='catalog' else {'passed'}),(name,report['status'])
        if name!='contract':assert report['client_artifact']==artifact,'release artifact mismatch'
        if name in {'catalog','https_image','wrapping_image','contract'}:
            assert report['tested_image_config_id']==config and report['archive_sha256']==packaged['archive_sha256']
    # The catalog contract is the one in the signed release.
    catalog_path=keytend_kmip_release.source()/'integration/catalog/catalog.json';catalog=json.loads(catalog_path.read_text())
    # The catalog's size is the release's: one record per case and lane.
    ids={c['id'] for c in catalog['cases']};assert ids and len(ids)==len(catalog['cases'])
    assert reports['catalog']['catalog_sha256']==sha(catalog_path)
    matrix=[];tuples=set();findings=collections.defaultdict(list);opt_in=collections.defaultdict(list);no_previous=collections.defaultdict(list);coverage_findings=[]
    for lane in reports['catalog']['lanes']:
        path=lane['report'];data=retain(path);assert files[path]==lane['report_sha256']
        major=int(re.search(r'version "(\d+)',lane['jdk']).group(1))
        key=(lane['wire_version'],major);assert key not in tuples;tuples.add(key)
        assert {r['test_id'] for r in data['records']}==ids and len(data['records'])==len(ids)
        assert data['cleanup']['remaining_run_owned_ids']==[]
        control=lane['control_log'];assert sha(ROOT/control)==lane['control_log_sha256'];files[control]=lane['control_log_sha256']
        events=[json.loads(line) for line in (ROOT/control).read_text().splitlines()]
        assert sum(event['outcome']=='error' for event in events)==lane['control_failures']
        counts=dict(collections.Counter(r['outcome'] for r in data['records']))
        assert counts==lane['outcomes']
        for record in data['records']:
            assert record['image_digest']=='sha256:'+config and record['client_commit']==artifact['commit']
            assert record['wire_version']==lane['wire_version']
            if key[0]=='1.1' and record['test_id'] in {'KEY-07','KEY-08'} and record['outcome']=='NOT_APPLICABLE' and 'NoEncoding variant requires 1.2' in record['reason']:
                coverage_findings.append({'id':'JAVA-REL-005','test_id':record['test_id'],'wire_version':key[0],'jdk':major,'upstream_outcome':record['outcome']})
            # The 24-hour lane runs only on request (the release run's --soak-duration);
            # not running it is recorded apart, not as a finding.
            if record['test_id']==OPT_IN_SOAK and record['outcome']=='BLOCKED_ENV' and 'opt-in' in record['reason']:
                opt_in[(record['test_id'],record['reason'])].append({'wire_version':key[0],'jdk':major})
            # Upgrade and rollback need an earlier published SDK release; none is pinned
            # (keytend_kmip_release.PIN has no `previous`), so the case does not apply yet.
            elif record['test_id']==UPGRADE and record['outcome']=='BLOCKED_ENV' and 'previous' not in keytend_kmip_release.PIN:
                no_previous[(record['test_id'],record['reason'])].append({'wire_version':key[0],'jdk':major})
            elif record['outcome'] not in {'PASS','NOT_APPLICABLE'}:
                findings[(record['test_id'],record['outcome'],record['reason'])].append({'wire_version':key[0],'jdk':major})
        matrix.append({'wire_version':key[0],'jdk':major,'outcomes':counts,'sdk_candidate_profile_qualified':lane['qualified']})
    assert tuples=={(version,jdk) for version in VERSIONS for jdk in [17,21,25]},'expected all 18 catalog lanes'
    for name in ['https_native','https_image']:
        lanes=reports[name]['java_lanes'];assert len(lanes)==54
        actual=set()
        for lane in lanes:
            major=int(re.search(r'version "(\d+)',lane['jdk']).group(1))
            actual.add((lane['wire_version'],major,lane['encoding']))
            assert lane['status']=='passed' and lane['client_commit']==artifact['commit']
            path=lane['log'];assert sha(ROOT/path)==lane['log_sha256'];files[path]=lane['log_sha256']
        assert actual=={(version,jdk,encoding) for version in VERSIONS for jdk in [17,21,25] for encoding in ['TTLV','JSON','XML']}
    server_findings=[]
    for name in ['wrapping_native','wrapping_image']:
        actual=set()
        for lane in reports[name]['lanes']:
            major=int(re.search(r'version "(\d+)',lane['jdk']).group(1))
            data=retain(lane['report']);assert files[lane['report']]==lane['report_sha256']
            log=str(pathlib.Path(lane['report']).with_suffix('.log'));assert sha(ROOT/log)==lane['log_sha256'];files[log]=lane['log_sha256']
            for row in data['versions']:
                version=row['wire_version'];actual.add((version,major))
                assert row['no_encoding_wrap_and_independent_unwrap']
                if version.startswith('1.') and row['missing_stored_parameters_reason']!=1:
                    server_findings.append({'id':'SERVER-REL-001','runtime':name,'jdk':major,'wire_version':version,
                                            'expected_reason':1,'observed_reason':row['missing_stored_parameters_reason']})
        assert actual=={(version,jdk) for version in VERSIONS for jdk in [17,21,25]}
        if name=='wrapping_native':assert reports[name]['runtime_binary_sha256']==reports['https_native']['runtime_binary_sha256']
    assert len(reports['contract']['versions'])==6
    result={'status':'completed_with_findings' if findings or server_findings or coverage_findings else 'passed_applicable_subset',
            'client_artifact':artifact,
            **packaged,'runtime_binary_sha256':reports['https_native']['runtime_binary_sha256'],
            'catalog_observations':18*len(ids),'catalog_matrix':matrix,
            'tested_jdk_runtimes':sorted({lane['jdk'] for lane in reports['catalog']['lanes']}),
            'supplemental_sdk_wrapping_lanes':{'native':18,'container':18},'server_findings':server_findings,
            'https_lanes':{'native':54,'container':54},
            'not_applicable_no_previous_release':[{'test_id':key[0],'reason':key[1],'observations':value} for key,value in sorted(no_previous.items())],
            'opt_in_not_run':[{'test_id':key[0],'reason':key[1],'observations':value} for key,value in sorted(opt_in.items())],
            'raw_catalog_findings':[{'test_id':key[0],'upstream_outcome':key[1],'reason':key[2],'observations':value} for key,value in sorted(findings.items())],
            'reports_sha256':files,'all_applicable_catalog_cases_passed':not bool(findings),
            'client_coverage_findings':coverage_findings,'subset_gate_passed':not bool(findings or server_findings or coverage_findings),
            'limits':['Raw upstream classifications remain unchanged',
                      'Legacy Get wrapping requires reason 1; independent negative probes enforce that reason separately from positive wrapping',
                      'Controlled-peer and vendor exclusions are not server passes',
                      'No new release/image 24-hour run or previous published release qualification',
                      'Draft 3.0 client transport execution is not part of this release matrix']}
    out=ROOT/'artifacts/java-release-summary.json';out.write_text(json.dumps(result,indent=2)+'\n')
    return result

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--java',action='append');p.add_argument('--engine',default='podman');p.add_argument('--image',default='localhost/keytend-kmip-server:dev');p.add_argument('--collect-only',action='store_true');p.add_argument('--report-only',action='store_true');a=p.parse_args()
    if not a.collect_only:
        if not a.java:p.error('supply JDK 17, 21 and 25 using three --java options')
        jdks=[arg for java in a.java for arg in ['--java',java]]
        commands=[['test_java_release_fixture.py'],['test_java_catalog.py','--report-only','--engine',a.engine,'--image',a.image]+jdks,
                  ['test_https.py','--engine',a.engine,'--image',a.image]+jdks,
                  ['test_https.py']+jdks,
                  ['test_java_wrapping.py']+jdks,
                  ['test_java_wrapping.py','--engine',a.engine,'--image',a.image]+jdks,
                  ['test_catalog_contract.py','--engine',a.engine,'--image',a.image]]
        for script,*args in commands:subprocess.run([sys.executable,str(ROOT/'scripts'/script),*args],check=True,cwd=ROOT)
    result=collect(a.engine,a.image)
    print(result['status']+f": {result['catalog_observations']:,} catalog observations, 108 HTTPS lanes and 36 supplemental wrapping lanes")
    if not result['subset_gate_passed'] and not a.report_only:raise SystemExit(1)
if __name__=='__main__':main()
