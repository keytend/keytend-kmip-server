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

"""Observe a real missing-Final timeout on the exact packaged image."""
import argparse,json,tempfile,time
from image_evidence import local_image_id,packaged_evidence
from test_database import ContainerServer
from test_runtime import ROOT
from test_streaming import CORR,DATA,FINAL,INIT,blob,call,key
from wire import *

def main():
    p=argparse.ArgumentParser();p.add_argument('--engine',default='podman');p.add_argument('--image',default='localhost/keytend-kmip-server:dev');a=p.parse_args()
    report={'status':'RUNNING',**packaged_evidence(local_image_id(a.engine,a.image))};output=ROOT/'artifacts/stream-expiry.json'
    def save():output.write_text(json.dumps(report,indent=2)+'\n')
    save()
    try:
        with tempfile.TemporaryDirectory(prefix='keytend-expiry-') as d:
            with ContainerServer(d,a.engine,a.image) as s:
                v=(2,1);id=key(s,v,1)
                cp=structure(0x42002b,enumeration(0x420011,6),enumeration(0x42005f,1))
                initial=[uid(id,v),cp,binary(0x42003d,bytes(16)),node(INIT,6,True),binary(DATA,b'abandoned input')]
                token=blob(payload(call(s,v,31,initial)),CORR)
                hcp=structure(0x42002b,enumeration(0x420038,6));hash_init=[hcp,node(INIT,6,True),binary(DATA,b'no final')]
                hash_tokens=[blob(payload(call(s,v,39,hash_init)),CORR) for _ in range(15)]
                denied=call(s,v,39,hash_init);assert status(denied)==1 and reason(denied)==2
                started=time.monotonic()
                while time.monotonic()-started<303:
                    time.sleep(min(30,303-(time.monotonic()-started)))
                    report['elapsed_idle_seconds']=round(time.monotonic()-started,3);save()
                expired=call(s,v,31,[uid(id,v),binary(CORR,token),node(FINAL,6,True)])
                assert status(expired)==1 and reason(expired)==0x2e
                for token in hash_tokens:
                    expired=call(s,v,39,[hcp,binary(CORR,token),node(FINAL,6,True)])
                    assert status(expired)==1 and reason(expired)==0x2e
                # Expiration frees slots but never refunds committed protection use.
                denied=call(s,v,31,initial);assert status(denied)==1 and reason(denied)==12
                renewed=[blob(payload(call(s,v,39,hash_init)),CORR) for _ in range(16)]
                assert len(set(renewed))==16
                denied=call(s,v,39,hash_init);assert status(denied)==1 and reason(denied)==2
        report.update(status='passed',expired_handles=16,reallocated_slots=16,consumed_object_budget_not_refunded=True,scope='Real 303-second abandoned multipart timeout on container; absolute lifetime tested separately with deterministic clock values')
    except BaseException as error:
        report.update(status='failed',failure_type=type(error).__name__);raise
    finally:save()
    print('PASS real 303-second missing-Final expiry, 16 slots reclaimed, protection budget retained')
if __name__=='__main__':main()
