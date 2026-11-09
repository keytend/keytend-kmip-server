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

"""Decode literal official XML messages; compare exact TTLV with a separate codec.

This is an offline lexical/representation corpus, not operation execution or
profile certification. Trace variables are not literal protocol encodings.
"""
import argparse,collections,hashlib,json,subprocess,xml.etree.ElementTree as ET,zipfile
from image_evidence import source_commit
from oasis_conformance import encode_xml,Unsupported
from test_runtime import sha
from test_runtime import ROOT
from wire import encode

def main():
    p=argparse.ArgumentParser();p.add_argument('--report-only',action='store_true');a=p.parse_args()
    library=ROOT/'target/debug/libkeytend_kmip_server.rlib';library_sha=sha(library)
    executable=ROOT/'.cache/encoding-corpus-probe';probe=ROOT/'tools/encoding_corpus_probe.rs'
    args=['rustc','--edition=2024',str(probe),'-L','dependency='+str(ROOT/'target/debug/deps'),'--extern','keytend_kmip_server='+str(library),'-o',str(executable)]
    dependencies={}
    for name in ['serde_json','hex']:
        artifact=max((ROOT/'target/debug/deps').glob('lib'+name+'-*.rlib'),key=lambda p:p.stat().st_mtime)
        dependencies[str(artifact.relative_to(ROOT))]=sha(artifact);args+=['--extern',name+'='+str(artifact)]
    subprocess.run(args,check=True)
    manifest=ROOT/'docs/specs/profiles.json';archives={r['version']:r for r in json.loads(manifest.read_text())};vectors=[];skipped=[];inputs={}
    for version in ['1.3','1.4','2.0','2.1','3.0']:
        path=ROOT/f'.cache/specs/profiles-{version}.zip';assert sha(path)==archives[version]['sha256'],'profile archive hash mismatch'
        inputs[version]=archives[version]
        with zipfile.ZipFile(path) as z:
            for name in z.namelist():
                if not name.endswith('.xml'):continue
                root=ET.fromstring(z.read(name))
                for i,m in enumerate(root):
                    if m.tag not in ['RequestMessage','ResponseMessage']:continue
                    identity={'version':version,'file':name,'message':i}
                    if any(e.get('value','').startswith('$') and e.get('type') not in ['TextString','Identifier','Reference','NameReference'] for e in m.iter()):
                        skipped.append({**identity,'reason':'non-literal trace variable'});continue
                    vectors.append((identity,ET.tostring(m,encoding='unicode')))
    result=subprocess.run([str(executable)],input=''.join(json.dumps(xml)+'\n' for _,xml in vectors),text=True,stdout=subprocess.PIPE,check=True)
    results=[]
    for (identity,xml),line in zip(vectors,result.stdout.splitlines(),strict=True):
        parsed=json.loads(line);record={**identity,'input_sha256':hashlib.sha256(xml.encode()).hexdigest()}
        if 'error' in parsed:record.update({'status':'rejected','error':parsed['error']})
        else:
            record.update({'status':'decoded','ttlv_sha256':hashlib.sha256(bytes.fromhex(parsed['ttlv'])).hexdigest()})
            root=ET.fromstring(xml)
            # IDs such as "$UNIQUE_IDENTIFIER" are also valid literal text.
            # Bind them to themselves for a lexical comparison, never to runtime
            # object IDs or simulated server results.
            literal_bindings={e.get('value'):e.get('value') for e in root.iter() if e.get('type') in ['TextString','Identifier','Reference','NameReference'] and e.get('value','').startswith('$')}
            try:expected=encode(encode_xml(root,literal_bindings)).hex()
            except (Unsupported,ValueError) as exc:record.update({'oracle':'unexecuted','reason':str(exc)})
            else:record['oracle']='equal' if expected==parsed['ttlv'] else 'different'
        results.append(record)
    summary={'literal_messages':len(results),'decoded':sum(r['status']=='decoded' for r in results),'rejected':sum(r['status']=='rejected' for r in results),'oracle_equal':sum(r.get('oracle')=='equal' for r in results),'oracle_different':sum(r.get('oracle')=='different' for r in results),'oracle_unexecuted':sum(r.get('oracle')=='unexecuted' for r in results),'nonliteral_unexecuted':len(skipped)}
    report={'status':'partial' if summary['rejected'] or summary['oracle_different'] else 'passed_literal_corpus','scope':'offline literal-message XML decoding and independent exact TTLV comparison; no operation execution or full conformance claim','summary':summary,'source_commit':source_commit()[0],'runtime_library_sha256':library_sha,'probe_binary_sha256':sha(executable),'rustc':subprocess.check_output(['rustc','--version'],text=True).strip(),'probe_dependency_sha256':dependencies,'archives':inputs,'messages':results,'unexecuted':skipped}
    output=ROOT/'artifacts/encoding-corpus.json';output.write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(summary,indent=2))
    if not a.report_only and report['status']=='partial':raise SystemExit(1)
if __name__=='__main__':main()
