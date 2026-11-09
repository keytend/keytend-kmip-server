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

"""Offline tests of the independent JSON/XML codec against the Profiles' own examples."""
import json,unittest,xml.etree.ElementTree as ET
import profile_text_codec as C
from oasis_conformance import TAGS,encode_xml
from wire import request,enumeration,node

def j(o,version='2.1'):return C.decode_json(json.dumps(o).encode(),version)
def x(s,version='2.1'):return C.decode_xml(s.encode(),version)
T=TAGS

class JsonExamples(unittest.TestCase):
    """Profiles 2.1 section 5.5.1.6 examples decode to the same TTLV values."""
    def test_scalars(self):
        self.assertEqual(j({'tag':'BatchCount','type':'Integer','value':10}),(T['BatchCount'],2,10))
        self.assertEqual(j({'tag':'BatchCount','type':'Integer','value':'0x0000000A'}),(T['BatchCount'],2,10))
        self.assertEqual(j({'tag':'0x540001','type':'LongInteger','value':'0xfffffffffffffffe'}),(0x540001,3,-2))
        self.assertEqual(j({'tag':'0x540001','type':'LongInteger','value':-2}),(0x540001,3,-2))
        self.assertEqual(j({'tag':'UsageLimitsCount','type':'LongInteger','value':'0x1000000000000000'}),(T['UsageLimitsCount'],3,1<<60))
        self.assertEqual(j({'tag':'0x420057','type':'Enumeration','value':2}),(0x420057,5,2))
        self.assertEqual(j({'tag':'ObjectType','type':'Enumeration','value':'0x00000002'}),(T['ObjectType'],5,2))
        self.assertEqual(j({'tag':'ObjectType','type':'Enumeration','value':'SymmetricKey'}),(T['ObjectType'],5,2))
        self.assertEqual(j({'tag':'BatchOrderOption','type':'Boolean','value':True}),(T['BatchOrderOption'],6,1))
        self.assertEqual(j({'tag':'BatchOrderOption','type':'Boolean','value':'0x0000000000000001'}),(T['BatchOrderOption'],6,1))
        self.assertEqual(j({'tag':'AttributeName','type':'TextString','value':'Cryptographic Algorithm'})[2],'Cryptographic Algorithm')
        self.assertEqual(j({'tag':'MACSignature','type':'ByteString','value':'C50F77'})[2],bytes.fromhex('c50f77'))
        # The two 5.5.1.6.11 examples are different instants; 0x3a505520 is 10:00 UTC.
        hexdate=j({'tag':'ArchiveDate','type':'DateTime','value':'0x000000003a505520'})
        self.assertEqual(hexdate,j({'tag':'ArchiveDate','type':'DateTime','value':'2001-01-01T10:00:00Z'}))
        self.assertEqual(hexdate[2]-36000,j({'tag':'ArchiveDate','type':'DateTime','value':'2001-01-01T10:00:00+10:00'})[2])
        self.assertEqual(j({'tag':'Offset','type':'Interval','value':27}),j({'tag':'Offset','type':'Interval','value':'0x0000001b'}))
        self.assertEqual(j({'tag':'0x540001','type':'DateTimeExtended','value':2})[2],2)
        self.assertEqual(j({'tag':'0x540002','type':'BigInteger','value':0})[2],bytes(8))
        self.assertEqual(j({'tag':'0x540002','type':'BigInteger','value':'0x0000000000000000'})[2],bytes(8))
    def test_masks(self):
        want=j({'tag':'CryptographicUsageMask','type':'Integer','value':'0x0000100c'})
        self.assertEqual(want[2],0x100c)
        self.assertEqual(j({'tag':'CryptographicUsageMask','type':'Integer','value':'Encrypt|Decrypt|CertificateSign'}),want)
        self.assertEqual(j({'tag':'CryptographicUsageMask','type':'Integer','value':'CertificateSign|0x0000000c'}),want)
    def test_structures(self):
        a=j({'tag':'ProtocolVersion','type':'Structure','value':[{'tag':'ProtocolVersionMajor','type':'Integer','value':1}]})
        self.assertEqual(a,j({'tag':'ProtocolVersion','value':[{'tag':'ProtocolVersionMajor','type':'Integer','value':1}]}))
        self.assertEqual(j({'tag':'PrivateKeyTemplateAttribute','type':'Structure','value':None},'1.4'),(T['PrivateKeyTemplateAttribute'],1,[]))
    def test_normative_msgenc_wire_example_matches_the_trace(self):
        # Profiles 2.1 section 5.5.4.1, Request Time 0 (normative JSON wire encoding).
        wire='{"tag":"RequestMessage", "value":[ {"tag":"RequestHeader", "value":[ {"tag":"ProtocolVersion", "value":[ {"tag":"ProtocolVersionMajor", "type":"Integer", "value":"0x00000001"}, {"tag":"ProtocolVersionMinor", "type":"Integer", "value":"0x00000004"} ]}, {"tag":"MaximumResponseSize", "type":"Integer", "value":"0x00000100"}, {"tag":"BatchCount", "type":"Integer", "value":"0x00000001"} ]}, {"tag":"BatchItem", "value":[ {"tag":"Operation", "type":"Enumeration", "value":"Query"}, {"tag":"RequestPayload", "value":[ {"tag":"QueryFunction", "type":"Enumeration", "value":"QueryOperations"}, {"tag":"QueryFunction", "type":"Enumeration", "value":"QueryObjects"} ]} ]} ]}'
        trace=ET.fromstring('<RequestMessage><RequestHeader><ProtocolVersion><ProtocolVersionMajor type="Integer" value="1"/><ProtocolVersionMinor type="Integer" value="4"/></ProtocolVersion><MaximumResponseSize type="Integer" value="256"/><BatchCount type="Integer" value="1"/></RequestHeader><BatchItem><Operation type="Enumeration" value="Query"/><RequestPayload><QueryFunction type="Enumeration" value="QueryOperations"/><QueryFunction type="Enumeration" value="QueryObjects"/></RequestPayload></BatchItem></RequestMessage>')
        expected=encode_xml(trace,{})
        self.assertEqual(C.decode_json(wire.encode(),'1.4'),expected)
        # The normative-form encoder reproduces the same message.
        self.assertEqual(json.loads(C.encode_json(expected,'normative',trace)),json.loads(wire))

class JsonRejections(unittest.TestCase):
    def bad(self,o,version='2.1'):
        with self.assertRaises(C.CodecError):j(o,version) if not isinstance(o,bytes) else C.decode_json(o,version)
    def test_fixed_width_hex(self):
        self.bad({'tag':'BatchCount','type':'Integer','value':'0xA'})
        self.bad({'tag':'0x42000d','type':'Integer','value':1}|{'tag':'0x42d'})
        self.bad({'tag':'ObjectType','type':'Enumeration','value':'0x2'})
        self.bad({'tag':'BatchOrderOption','type':'Boolean','value':'0x01'})
        self.bad({'tag':'0x540002','type':'BigInteger','value':'0x00'})
    def test_large_numbers_must_be_hex(self):
        self.bad({'tag':'UsageLimitsCount','type':'LongInteger','value':1<<60})
        self.bad({'tag':'UsageLimitsCount','type':'LongInteger','value':1<<52})
        self.assertEqual(j({'tag':'UsageLimitsCount','type':'LongInteger','value':(1<<52)-1})[2],(1<<52)-1)
    def test_ranges_and_types(self):
        self.bad({'tag':'BatchCount','type':'Integer','value':1<<31})
        self.bad({'tag':'Offset','type':'Interval','value':-1})
        self.bad({'tag':'BatchCount','type':'Integer','value':True})
        self.bad({'tag':'BatchCount','type':'Integer','value':'10'})
        self.bad({'tag':'MACSignature','type':'ByteString','value':'0xC50F77'})
        self.bad({'tag':'MACSignature','type':'ByteString','value':'C50F7'})
        self.bad(b'{"tag":"BatchCount","type":"Integer","value":1.0}')
        self.bad(b'{"tag":"BatchCount","type":"Integer","value":NaN}')
    def test_object_shape(self):
        self.bad(b'{"tag":"BatchCount","type":"Integer","value":1,"value":2}')
        self.bad({'tag':'BatchCount','type':'Integer','value':1,'extra':1})
        self.bad({'type':'Integer','value':1})
        self.bad({'tag':'NoSuchTag','type':'Integer','value':1})
        self.bad({'tag':'0x420078','value':{}})
        self.bad({'tag':'0x42000d','name':'ObjectType','type':'Integer','value':1})
    def test_versioned_types_and_dates(self):
        self.bad({'tag':'0x540001','type':'DateTimeExtended','value':2},'1.4')
        self.bad({'tag':'UniqueIdentifier','type':'Identifier','value':'a'},'2.1')
        self.assertEqual(j({'tag':'UniqueIdentifier','type':'Identifier','value':'a'},'3.0')[1],12)
        self.bad({'tag':'ArchiveDate','type':'DateTime','value':'2001-01-01T10:00:00'})
        self.bad({'tag':'ArchiveDate','type':'DateTime','value':'2001-02-29T10:00:00Z'})
        self.bad({'tag':'ObjectType','type':'Enumeration','value':'NotAnObjectType'})

class XmlExamples(unittest.TestCase):
    """Profiles 2.1 section 5.4.1.6 examples."""
    def test_forms_and_namespace(self):
        a=x('<TTLV tag="0x420001" name="ActivationDate" type="DateTime" value="2001-01-01T10:00:00+10:00"/>')
        self.assertEqual(a,x('<TTLV tag="0x420001" type="DateTime" value="2001-01-01T10:00:00+10:00"/>'))
        self.assertEqual(a,x('<ActivationDate type="DateTime" value="2001-01-01T10:00:00+10:00"/>'))
        self.assertEqual(a,x('<ActivationDate xmlns="urn:oasis:tc:kmip:xmlns" type="DateTime" value="2001-01-01T10:00:00+10:00"/>'))
        self.assertEqual(x('<TTLV tag="0x54FFFF" name="SomeExtension" type="DateTime" value="2001-01-01T10:00:00+10:00"/>')[0],0x54ffff)
    def test_scalars(self):
        self.assertEqual(x('<BatchCount type="Integer" value="10"/>')[2],10)
        self.assertEqual(x('<UsageLimitsCount type="LongInteger" value="1152921504606846976"/>')[2],1<<60)
        self.assertEqual(x('<TTLV tag="0x540002" type="BigInteger" value="0000000000000000"/>')[2],bytes(8))
        self.assertEqual(x('<ObjectType type="Enumeration" value="0x00000002"/>'),x('<ObjectType type="Enumeration" value="SymmetricKey"/>'))
        self.assertEqual(x('<BatchOrderOption type="Boolean" value="true"/>')[2],1)
        self.assertEqual(x('<MACSignature type="ByteString" value="C50F77"/>')[2],bytes.fromhex('c50f77'))
        self.assertEqual(x('<Offset type="Interval" value="27"/>')[2],27)
        self.assertEqual(x('<TTLV tag="0x540001" type="DateTimeExtended" value="1152921504606846976"/>')[2],1<<60)
        self.assertEqual(x('<AttributeName type="TextString" value="a&amp;b&#10;c"/>')[2],'a&b\nc')
    def test_masks(self):
        want=x('<CryptographicUsageMask type="Integer" value="0x0000100c"/>')
        self.assertEqual(want[2],0x100c)
        self.assertEqual(x('<CryptographicUsageMask type="Integer" value="Encrypt Decrypt CertificateSign"/>'),want)
        self.assertEqual(x('<CryptographicUsageMask type="Integer" value="CertificateSign 0x0000000c"/>'),want)
    def test_attribute_value_context_in_any_order(self):
        for body in ('<AttributeName type="TextString" value="Object Type"/><AttributeValue type="Enumeration" value="SymmetricKey"/>',
                     '<AttributeValue type="Enumeration" value="SymmetricKey"/><AttributeName type="TextString" value="Object Type"/>'):
            values=[c for c in x(f'<Attribute>{body}</Attribute>','1.4')[2] if c[0]==T['AttributeValue']]
            self.assertEqual(values[0][2],2)

class XmlRejections(unittest.TestCase):
    def bad(self,s,version='2.1'):
        with self.assertRaises(C.CodecError):x(s,version)
    def test_rejections(self):
        self.bad('<!DOCTYPE a [<!ENTITY e "x">]><BatchCount type="Integer" value="1"/>')
        self.bad('<BatchCount xmlns="urn:example" type="Integer" value="1"/>')
        self.bad('<RequestHeader>text</RequestHeader>')
        self.bad('<BatchCount type="Integer" value="1"/><BatchCount type="Integer" value="1"/>')
        self.bad('<BatchCount type="Integer" value="0x00000001"/>')
        self.bad('<BatchCount type="Integer"/>')
        self.bad('<RequestHeader value="1"/>')
        self.bad('<BatchCount type="Integer" value="1"><BatchCount type="Integer" value="1"/></BatchCount>')
        self.bad('<BatchCount type="Integer" value="1" extra="1"/>')
        self.bad('<TTLV type="Integer" value="1"/>')
        self.bad('<BatchCount tag="0x42000d" type="Integer" value="1"/>')
        self.bad('<TTLV tag="0x540002" type="BigInteger" value="00"/>')
        self.bad('<BatchOrderOption type="Boolean" value="yes"/>')
        self.bad('<ArchiveDate type="DateTime" value="2001-01-01T10:00:00"/>')
        self.bad('<TTLV tag="0x540001" type="DateTimeExtended" value="2"/>','1.4')
        self.bad('<RequestHeader>')

class RoundTrip(unittest.TestCase):
    def test_both_forms_round_trip_every_type(self):
        msg=(T['RequestMessage'],1,[(T['BatchCount'],2,-5),(T['UsageLimitsCount'],3,1<<60),(T['UsageLimitsCount'],3,-7),(0x540002,4,bytes.fromhex('ff'*8)),
             (T['ObjectType'],5,2),(T['BatchOrderOption'],6,0),(T['AttributeName'],7,'x<"&\'\n'),(T['MACSignature'],8,b'\x00\x01'),
             (T['ArchiveDate'],9,-62135596801),(T['Offset'],10,(1<<32)-1),(0x540001,11,-(1<<62)),(T['RequestHeader'],1,[])])
        for form in ('normative','numeric'):
            self.assertEqual(C.decode_json(C.encode_json(msg,form),'2.1'),msg,form)
            self.assertEqual(C.decode_xml(C.encode_xml_text(msg,form),'2.1'),msg,form)
        q=request(24,[enumeration(T['QueryFunction'],1)],(3,0))
        self.assertEqual(C.decode_json(C.encode_json(q,'numeric'),'3.0'),q)
    def test_dates_cover_bce_and_far_future(self):
        for t in (0,-1,951782400,-62135596800,-62135596801,253402300799,253402300800,-(1<<40),1<<40):
            self.assertEqual(C.parse_datetime(C.format_datetime(t),'2.1'),t)
        self.assertEqual(C.format_datetime(-62135596801),'-0001-12-31T23:59:59+00:00')

if __name__=='__main__':unittest.main()
