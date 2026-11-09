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

"""Live check of `--ec-curves` / KMIP_EC_CURVES.

Starts the built binary over TLS with the default, with
KMIP_EC_CURVES=extended and with the command-line option, and sends 2.1
Create Key Pair requests on P-256 (7), secp256k1 (25) and brainpoolP256r1
(61). The default `nist` creates P-256 only and answers the others with
Feature Not Supported, "Unsupported EC curve"; `extended` creates all three.
An unknown value stops startup. Usage:

    python3 scripts/test_ec_curves.py
"""
import os,subprocess,tempfile,unittest
from test_runtime import Server
from wire import enumeration,exchange,get,integer,request,status,reason,structure

ALGORITHM,DOMAIN,CURVE,USAGE=0x420028,0x420029,0x420075,0x42002c
COMMON,PRIVATE,PUBLIC,MESSAGE=0x420126,0x420127,0x420128,0x42007d
V=(2,1)

def key_pair(client,curve):
    r=exchange(client,request(2,[structure(COMMON,enumeration(ALGORITHM,6),structure(DOMAIN,enumeration(CURVE,curve))),
        structure(PRIVATE,integer(USAGE,1)),structure(PUBLIC,integer(USAGE,2))],V))
    if status(r)==0:return 'created'
    return reason(r),get(get(r,0x42000f),MESSAGE)[2]

class EcCurves(unittest.TestCase):
    def run_with(self,env=None,args=()):
        previous=os.environ.get('KMIP_EC_CURVES')
        if env is None:os.environ.pop('KMIP_EC_CURVES',None)
        else:os.environ['KMIP_EC_CURVES']=env
        try:
            with tempfile.TemporaryDirectory(prefix='keytend-ecc-') as d:
                server=Server(d);server.extra_args=list(args)
                with server,server.connect() as client:
                    return {curve:key_pair(client,curve) for curve in (7,25,61)}
        finally:
            if previous is None:os.environ.pop('KMIP_EC_CURVES',None)
            else:os.environ['KMIP_EC_CURVES']=previous

    def test_default_offers_the_nist_curves_only(self):
        for env,args in [(None,()),('nist',()),(None,('--ec-curves','nist'))]:
            self.assertEqual(self.run_with(env,args),{7:'created',25:(8,'Unsupported EC curve'),61:(8,'Unsupported EC curve')},(env,args))

    def test_extended_by_environment_and_option(self):
        for env,args in [('extended',()),(None,('--ec-curves','extended'))]:
            self.assertEqual(self.run_with(env,args),{7:'created',25:'created',61:'created'},(env,args))

    def test_unknown_value_stops_startup(self):
        with tempfile.TemporaryDirectory(prefix='keytend-ecc-') as d:
            server=Server(d)
            r=subprocess.run([server.binary,'serve','--cert','c','--key','k','--ca','a','--policy','p','--master-key','m'],
                             env={**os.environ,'KMIP_EC_CURVES':'brainpool'},capture_output=True,text=True)
            self.assertNotEqual(r.returncode,0)
            self.assertIn('extended',r.stderr)

if __name__=='__main__':unittest.main()
