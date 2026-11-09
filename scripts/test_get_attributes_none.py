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

"""Live check of `--get-attributes-none` / KMIP_GET_ATTRIBUTES_NONE.

Starts the built binary over TLS with the default, with
KMIP_GET_ATTRIBUTES_NONE=identifier-only and with the command-line option, and
sends a 2.1 Get Attributes for an attribute the key does not have. The default
answers the Unique Identifier and an empty Attributes structure (2.1 Table
224); identifier-only answers the Unique Identifier alone (2.1 section
6.1.20). An unknown value stops startup. Usage:

    python3 scripts/test_get_attributes_none.py
"""
import os,subprocess,tempfile,unittest
from test_runtime import Server
from wire import create_key,enumeration,exchange,payload,request,uid

UNIQUE_IDENTIFIER,ATTRIBUTES,ATTRIBUTE_REFERENCE,DESCRIPTION=0x420094,0x420125,0x42013b,0x4200fc
V=(2,1)

def fields(server):
    with server.connect() as client:
        key=create_key(client,V)
        p=payload(exchange(client,request(11,[uid(key,V),enumeration(ATTRIBUTE_REFERENCE,DESCRIPTION)],V)))
    return [(n[0],n[2]) for n in p[2]],key

class GetAttributesNone(unittest.TestCase):
    def run_with(self,env=None,args=()):
        previous=os.environ.get('KMIP_GET_ATTRIBUTES_NONE')
        if env is None:os.environ.pop('KMIP_GET_ATTRIBUTES_NONE',None)
        else:os.environ['KMIP_GET_ATTRIBUTES_NONE']=env
        try:
            with tempfile.TemporaryDirectory(prefix='keytend-gan-') as d:
                server=Server(d);server.extra_args=list(args)
                with server:return fields(server)
        finally:
            if previous is None:os.environ.pop('KMIP_GET_ATTRIBUTES_NONE',None)
            else:os.environ['KMIP_GET_ATTRIBUTES_NONE']=previous

    def test_default_returns_an_empty_attributes_structure(self):
        got,key=self.run_with()
        self.assertEqual(got,[(UNIQUE_IDENTIFIER,key),(ATTRIBUTES,[])])

    def test_identifier_only_by_environment_and_option(self):
        for env,args in [('identifier-only',()),(None,('--get-attributes-none','identifier-only'))]:
            got,key=self.run_with(env,args)
            self.assertEqual(got,[(UNIQUE_IDENTIFIER,key)],(env,args))

    def test_unknown_value_stops_startup(self):
        with tempfile.TemporaryDirectory(prefix='keytend-gan-') as d:
            server=Server(d)
            r=subprocess.run([server.binary,'serve','--cert','c','--key','k','--ca','a','--policy','p','--master-key','m'],
                             env={**os.environ,'KMIP_GET_ATTRIBUTES_NONE':'identifier'},capture_output=True,text=True)
            self.assertNotEqual(r.returncode,0)
            self.assertIn('identifier-only',r.stderr)

if __name__=='__main__':unittest.main()
