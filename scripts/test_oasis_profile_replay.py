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

"""Rejection tests for the Profiles 4.1 variation comparator (no server needed)."""
import os,struct,unittest,xml.etree.ElementTree as ET
from cryptography.hazmat.primitives.asymmetric import rsa,padding
from cryptography.hazmat.primitives import hashes,serialization
import oasis_profile_replay as R
import oasis_validate as V
from wire import encode
T=R.TAGS

def n(name,kind,value):return (T[name],kind,value)
def s(name,*c):return (T[name],1,list(c))
def header(*extra):return s('ResponseHeader',s('ProtocolVersion',n('ProtocolVersionMajor',2,2),n('ProtocolVersionMinor',2,1)),n('TimeStamp',9,0),*extra,n('BatchCount',2,1))
def response(*items,head=None):return s('ResponseMessage',head or header(),*items)
def item(op,*payload,status=0,extra=()):return s('BatchItem',n('Operation',5,R.ENUMS['Operation'][op]),n('ResultStatus',5,status),*extra,*([s('ResponsePayload',*payload)] if payload is not None else []))
def xml(text):return ET.fromstring(text)
EXPECTED_HEADER='<ResponseHeader><ProtocolVersion><ProtocolVersionMajor type="Integer" value="2"/><ProtocolVersionMinor type="Integer" value="1"/></ProtocolVersion><TimeStamp type="DateTime" value="$NOW"/><BatchCount type="Integer" value="1"/></ResponseHeader>'
def expected(body):return xml(f'<ResponseMessage>{EXPECTED_HEADER}{body}</ResponseMessage>')
def request(body):return xml(f'<RequestMessage><RequestHeader/>{body}</RequestMessage>')
def now(node):
    # Replace the fixed TimeStamp with the current time for $NOW checks.
    import time
    def fix(x):
        if x[0]==T['TimeStamp']:return (x[0],x[1],int(time.time()))
        return (x[0],x[1],[fix(c) for c in x[2]]) if x[1]==1 else x
    return fix(node)

class Comparator(unittest.TestCase):
    def replay(self):return R.Replay('2.1',{})
    def run_case(self,exp,act,req='<BatchItem><Operation type="Enumeration" value="Get"/><RequestPayload/></BatchItem>'):
        r=self.replay();r.compare_message(expected(exp),now(act),request(req));return r

    def test_exact_values_and_variable_binding(self):
        r=self.run_case('<BatchItem><Operation type="Enumeration" value="Get"/><ResultStatus type="Enumeration" value="Success"/><ResponsePayload><UniqueIdentifier type="TextString" value="$UNIQUE_IDENTIFIER_0"/></ResponsePayload></BatchItem>',
            response(item('Get',n('UniqueIdentifier',7,'abc'))))
        self.assertEqual(r.vars['$UNIQUE_IDENTIFIER_0'],'abc')

    def test_unexpected_field_is_rejected(self):
        with self.assertRaisesRegex(AssertionError,'unexpected response field'):
            self.run_case('<BatchItem><Operation type="Enumeration" value="Get"/><ResultStatus type="Enumeration" value="Success"/><ResponsePayload><UniqueIdentifier type="TextString" value="$U"/></ResponsePayload></BatchItem>',
                response(item('Get',n('UniqueIdentifier',7,'abc'),n('ObjectType',5,2))))

    def test_field_order_is_enforced(self):
        exp='<BatchItem><Operation type="Enumeration" value="Get"/><ResultStatus type="Enumeration" value="Success"/><ResponsePayload><ObjectType type="Enumeration" value="SymmetricKey"/><UniqueIdentifier type="TextString" value="$U"/></ResponsePayload></BatchItem>'
        self.run_case(exp,response(item('Get',n('ObjectType',5,2),n('UniqueIdentifier',7,'abc'))))
        with self.assertRaisesRegex(AssertionError,'out of order'):
            self.run_case(exp,response(item('Get',n('UniqueIdentifier',7,'abc'),n('ObjectType',5,2))))

    def test_interleaved_repeated_fields_are_rejected(self):
        exp='<BatchItem><Operation type="Enumeration" value="Locate"/><ResultStatus type="Enumeration" value="Success"/><ResponsePayload><LocatedItems type="Integer" value="2"/><UniqueIdentifier type="TextString" value="$A"/><UniqueIdentifier type="TextString" value="$B"/></ResponsePayload></BatchItem>'
        with self.assertRaisesRegex(AssertionError,'interleaved|out of order'):
            self.run_case(exp,response(item('Locate',n('UniqueIdentifier',7,'a'),n('LocatedItems',2,2),n('UniqueIdentifier',7,'b'))))

    def test_result_message_may_vary_or_be_omitted_but_status_and_reason_are_exact(self):
        exp='<BatchItem><Operation type="Enumeration" value="Get"/><ResultStatus type="Enumeration" value="OperationFailed"/><ResultReason type="Enumeration" value="ItemNotFound"/><ResultMessage type="TextString" value="DENIED"/></BatchItem>'
        fail=lambda reason,*m:s('BatchItem',n('Operation',5,10),n('ResultStatus',5,1),n('ResultReason',5,reason),*m)
        r=self.run_case(exp,response(fail(1)))
        self.assertIn('Result Message omitted (4.1.1)',r.variations)
        r=self.run_case(exp,response(fail(1,n('ResultMessage',7,'not found'))))
        self.assertIn('Result Message wording varies (4.1.1)',r.variations)
        with self.assertRaisesRegex(AssertionError,'value mismatch'):self.run_case(exp,response(fail(12)))

    def test_query_lists_allow_additions_but_not_omissions(self):
        exp='<BatchItem><Operation type="Enumeration" value="Query"/><ResultStatus type="Enumeration" value="Success"/><ResponsePayload><Operation type="Enumeration" value="Get"/><Operation type="Enumeration" value="Poll"/></ResponsePayload></BatchItem>'
        req='<BatchItem><Operation type="Enumeration" value="Query"/><RequestPayload/></BatchItem>'
        r=self.run_case(exp,response(item('Query',n('Operation',5,10),n('Operation',5,1),n('Operation',5,26))),req)
        self.assertIn('additional Operation entries (4.1.1)',r.variations)
        with self.assertRaisesRegex(AssertionError,'missing|not present'):
            self.run_case(exp,response(item('Query',n('Operation',5,10),n('Operation',5,1),n('Operation',5,8))),req)

    def test_generated_key_material_opens_an_obligation_closed_by_size(self):
        r=self.replay();r.generated.add('k')
        exp=expected('<BatchItem><Operation type="Enumeration" value="Get"/><ResultStatus type="Enumeration" value="Success"/><ResponsePayload><ObjectType type="Enumeration" value="SymmetricKey"/><UniqueIdentifier type="TextString" value="$U"/><SymmetricKey><KeyBlock><KeyFormatType type="Enumeration" value="Raw"/><KeyValue><KeyMaterial type="ByteString" value="00112233445566778899aabbccddeeff"/></KeyValue><CryptographicAlgorithm type="Enumeration" value="AES"/><CryptographicLength type="Integer" value="128"/></KeyBlock></SymmetricKey></ResponsePayload></BatchItem>')
        def actual(material,length):
            kb=s('KeyBlock',n('KeyFormatType',5,1),s('KeyValue',n('KeyMaterial',8,material)),n('CryptographicAlgorithm',5,3),n('CryptographicLength',2,length))
            return now(response(item('Get',n('ObjectType',5,2),n('UniqueIdentifier',7,'k'),s('SymmetricKey',kb))))
        r.compare_message(exp,actual(os.urandom(16),128),request('<BatchItem><Operation type="Enumeration" value="Get"/><RequestPayload/></BatchItem>'))
        r.material['k']={'type':'SymmetricKey'};r.resolve()
        self.assertTrue(all(o.closed for o in r.obligations))
        self.assertIn('00112233445566778899aabbccddeeff',r.subst)
        bad=R.Replay('2.1',{});bad.generated.add('k');bad.material['k']={'type':'SymmetricKey'}
        bad.compare_message(exp,actual(os.urandom(8),128),request('<BatchItem><Operation type="Enumeration" value="Get"/><RequestPayload/></BatchItem>'))
        with self.assertRaisesRegex(AssertionError,'64 bits'):bad.resolve()
        # A registered (not generated) key's material is compared exactly.
        fixed=R.Replay('2.1',{})
        with self.assertRaisesRegex(AssertionError,'value mismatch'):
            fixed.compare_message(exp,actual(os.urandom(16),128),request('<BatchItem><Operation type="Enumeration" value="Get"/><RequestPayload/></BatchItem>'))

    def test_unclosed_crypto_output_is_unverified_not_passed(self):
        r=self.replay();r.generated.add('k')
        exp=expected('<BatchItem><Operation type="Enumeration" value="Encrypt"/><ResultStatus type="Enumeration" value="Success"/><ResponsePayload><UniqueIdentifier type="TextString" value="$U"/><Data type="ByteString" value="00"/></ResponsePayload></BatchItem>')
        req=request('<BatchItem><Operation type="Enumeration" value="Encrypt"/><RequestPayload><UniqueIdentifier type="TextString" value="k"/><Data type="ByteString" value="01"/></RequestPayload></BatchItem>')
        r.compare_message(exp,now(response(item('Encrypt',n('UniqueIdentifier',7,'k'),n('Data',8,b'\x99')))),req)
        self.assertEqual(len(R.finish(r)),1)

    def test_rng_output_must_match_length_and_not_repeat(self):
        r=self.replay()
        rp=xml('<RequestPayload><DataLength type="Integer" value="4"/></RequestPayload>')
        ok=R.Obligation('rng','/Data',b'\x01\x02\x03\x04',info={'request_payload':rp})
        self.assertIn('4 bytes',r.verify(ok))
        with self.assertRaisesRegex(AssertionError,'repeated'):r.verify(R.Obligation('rng','/Data',b'\x01\x02\x03\x04',info={'request_payload':rp}))
        with self.assertRaisesRegex(AssertionError,'3 bytes'):r.verify(R.Obligation('rng','/Data',b'\x01\x02\x03',info={'request_payload':rp}))

    def test_identifier_reuse_for_created_objects_fails(self):
        r=self.replay();r.created_ids={'$UNIQUE_IDENTIFIER_0':'x','$UNIQUE_IDENTIFIER_1':'x'}
        with self.assertRaisesRegex(AssertionError,'identifier reused'):R.finish(r)

class ComparisonRegressions(unittest.TestCase):
    """Regressions in message comparison found after the first version."""
    GET='<BatchItem><Operation type="Enumeration" value="Get"/><RequestPayload/></BatchItem>'
    def check(self,exp,act,req=None,replay=None):
        r=replay or R.Replay('2.1',{});r.compare_message(expected(exp),now(act),request(req or self.GET));return r
    def test_placeholder_crypto_output_opens_an_obligation(self):
        r=R.Replay('2.1',{});r.generated.add('k')
        exp='<BatchItem><Operation type="Enumeration" value="Encrypt"/><ResultStatus type="Enumeration" value="Success"/><ResponsePayload><UniqueIdentifier type="TextString" value="$U"/><Data type="ByteString" value="$DATA"/></ResponsePayload></BatchItem>'
        req='<BatchItem><Operation type="Enumeration" value="Encrypt"/><RequestPayload><UniqueIdentifier type="TextString" value="k"/><Data type="ByteString" value="01"/></RequestPayload></BatchItem>'
        self.check(exp,response(item('Encrypt',n('UniqueIdentifier',7,'k'),n('Data',8,b'\0'))),req,r)
        self.assertEqual(len(R.finish(r)),1)
    def test_placeholder_key_material_is_size_checked(self):
        r=R.Replay('2.1',{});r.generated.add('k');r.material['k']={'type':'SymmetricKey'}
        exp='<BatchItem><Operation type="Enumeration" value="Get"/><ResultStatus type="Enumeration" value="Success"/><ResponsePayload><UniqueIdentifier type="TextString" value="$U"/><SymmetricKey><KeyBlock><KeyFormatType type="Enumeration" value="Raw"/><KeyValue><KeyMaterial type="ByteString" value="$KEY_MATERIAL"/></KeyValue><CryptographicAlgorithm type="Enumeration" value="AES"/><CryptographicLength type="Integer" value="256"/></KeyBlock></SymmetricKey></ResponsePayload></BatchItem>'
        kb=s('KeyBlock',n('KeyFormatType',5,1),s('KeyValue',n('KeyMaterial',8,b'\1')),n('CryptographicAlgorithm',5,3),n('CryptographicLength',2,256))
        self.check(exp,response(item('Get',n('UniqueIdentifier',7,'k'),s('SymmetricKey',kb))),None,r)
        with self.assertRaisesRegex(AssertionError,'8 bits'):r.resolve()
    def test_wrapped_key_must_unwrap(self):
        r=R.Replay('2.1',{});r.generated.add('k');r.material['w']={'type':'SymmetricKey','bytes':bytes(16)}
        exp='<BatchItem><Operation type="Enumeration" value="Get"/><ResultStatus type="Enumeration" value="Success"/><ResponsePayload><UniqueIdentifier type="TextString" value="$U"/><SymmetricKey><KeyBlock><KeyFormatType type="Enumeration" value="Raw"/><KeyValue><KeyMaterial type="ByteString" value="00"/></KeyValue><CryptographicAlgorithm type="Enumeration" value="AES"/><CryptographicLength type="Integer" value="128"/><KeyWrappingData><WrappingMethod type="Enumeration" value="Encrypt"/><EncryptionKeyInformation><UniqueIdentifier type="TextString" value="w"/><CryptographicParameters><BlockCipherMode type="Enumeration" value="NISTKeyWrap"/></CryptographicParameters></EncryptionKeyInformation></KeyWrappingData></KeyBlock></SymmetricKey></ResponsePayload></BatchItem>'
        wd=s('KeyWrappingData',n('WrappingMethod',5,1),s('EncryptionKeyInformation',n('UniqueIdentifier',7,'w'),s('CryptographicParameters',n('BlockCipherMode',5,13))))
        kb=s('KeyBlock',n('KeyFormatType',5,1),s('KeyValue',n('KeyMaterial',8,os.urandom(16))),n('CryptographicAlgorithm',5,3),n('CryptographicLength',2,128),wd)
        self.check(exp,response(item('Get',n('UniqueIdentifier',7,'k'),s('SymmetricKey',kb))),None,r)
        with self.assertRaisesRegex(AssertionError,'does not unwrap'):r.resolve()
    def test_located_items_must_count_the_results(self):
        exp='<BatchItem><Operation type="Enumeration" value="Locate"/><ResultStatus type="Enumeration" value="Success"/><ResponsePayload><UniqueIdentifier type="TextString" value="$U"/></ResponsePayload></BatchItem>'
        req='<BatchItem><Operation type="Enumeration" value="Locate"/><RequestPayload/></BatchItem>'
        self.check(exp,response(item('Locate',n('LocatedItems',2,1),n('UniqueIdentifier',7,'a'))),req)
        with self.assertRaisesRegex(AssertionError,'unexpected response field LocatedItems'):self.check(exp,response(item('Locate',n('LocatedItems',2,999),n('UniqueIdentifier',7,'a'))),req)
    def test_additional_attributes_must_be_well_formed(self):
        exp='<BatchItem><Operation type="Enumeration" value="GetAttributes"/><ResultStatus type="Enumeration" value="Success"/><ResponsePayload><UniqueIdentifier type="TextString" value="$U"/><Attributes><CryptographicLength type="Integer" value="256"/></Attributes></ResponsePayload></BatchItem>'
        req='<BatchItem><Operation type="Enumeration" value="GetAttributes"/><RequestPayload/></BatchItem>'
        self.check(exp,response(item('GetAttributes',n('UniqueIdentifier',7,'a'),s('Attributes',n('CryptographicLength',2,256),n('State',5,1)))),req)
        with self.assertRaisesRegex(AssertionError,'single-instance'):
            self.check(exp,response(item('GetAttributes',n('UniqueIdentifier',7,'a'),s('Attributes',n('CryptographicLength',2,256),n('CryptographicLength',2,128)))),req)
        with self.assertRaisesRegex(AssertionError,'unexpected response field'):
            self.check(exp,response(item('GetAttributes',n('UniqueIdentifier',7,'a'),s('Attributes',n('CryptographicLength',2,256),n('BatchCount',7,'x')))),req)
    def test_discover_versions_keeps_preference_order(self):
        def pv(a,b):return s('ProtocolVersion',n('ProtocolVersionMajor',2,a),n('ProtocolVersionMinor',2,b))
        exp='<BatchItem><Operation type="Enumeration" value="DiscoverVersions"/><ResultStatus type="Enumeration" value="Success"/><ResponsePayload>'+''.join(f'<ProtocolVersion><ProtocolVersionMajor type="Integer" value="{a}"/><ProtocolVersionMinor type="Integer" value="{b}"/></ProtocolVersion>' for a,b in [(2,1),(2,0)])+'</ResponsePayload></BatchItem>'
        req='<BatchItem><Operation type="Enumeration" value="DiscoverVersions"/><RequestPayload/></BatchItem>'
        self.check(exp,response(item('DiscoverVersions',pv(3,0),pv(2,1),pv(2,0))),req)
        with self.assertRaisesRegex(AssertionError,'out of order'):self.check(exp,response(item('DiscoverVersions',pv(2,0),pv(2,1))),req)
    def test_unlisted_date_attributes_are_exact(self):
        exp='<BatchItem><Operation type="Enumeration" value="GetAttributes"/><ResultStatus type="Enumeration" value="Success"/><ResponsePayload><UniqueIdentifier type="TextString" value="$U"/><Attributes><ProcessStartDate type="DateTime" value="2020-01-01T00:00:00+00:00"/></Attributes></ResponsePayload></BatchItem>'
        req='<BatchItem><Operation type="Enumeration" value="GetAttributes"/><RequestPayload/></BatchItem>'
        with self.assertRaisesRegex(AssertionError,'not present'):
            self.check(exp,response(item('GetAttributes',n('UniqueIdentifier',7,'a'),s('Attributes',n('ProcessStartDate',9,5)))),req)
    def test_attribute_index_shift_needs_additional_instances(self):
        r=R.Replay('1.4',{})
        exp=('<BatchItem><Operation type="Enumeration" value="GetAttributes"/><ResultStatus type="Enumeration" value="Success"/><ResponsePayload><UniqueIdentifier type="TextString" value="$U"/>'
             '<Attribute><AttributeName type="TextString" value="Name"/><AttributeIndex type="Integer" value="0"/><AttributeValue><NameValue type="TextString" value="a"/><NameType type="Enumeration" value="UninterpretedTextString"/></AttributeValue></Attribute></ResponsePayload></BatchItem>')
        req='<BatchItem><Operation type="Enumeration" value="GetAttributes"/><RequestPayload/></BatchItem>'
        def attr(index,value):return s('Attribute',n('AttributeName',7,'Name'),n('AttributeIndex',2,index),s('AttributeValue',n('NameValue',7,value),n('NameType',5,1)))
        self.check(exp,response(item('GetAttributes',n('UniqueIdentifier',7,'u'),attr(0,'b'),attr(1,'a'))),req,r)
        with self.assertRaises(AssertionError):self.check(exp,response(item('GetAttributes',n('UniqueIdentifier',7,'u'),attr(7,'a'))),req,R.Replay('1.4',{}))
    def test_zero_length_big_integer_is_rejected(self):
        bad=T['Modulus'].to_bytes(3,'big')+bytes([4])+(0).to_bytes(4,'big')
        with self.assertRaisesRegex(AssertionError,'Big Integer'):V.strict_decode(T['ResponseMessage'].to_bytes(3,'big')+b'\x01'+len(bad).to_bytes(4,'big')+bad)

class Interop(unittest.TestCase):
    def test_only_leading_begin_and_trailing_end_are_omitted(self):
        inv={'interop_wrapper_omission':{'versions':['2.1']}}
        def pair(op,function=None):
            payload=f'<InteropFunction type="Enumeration" value="{function}"/>' if function else ''
            return [xml(f'<RequestMessage><RequestHeader/><BatchItem><Operation type="Enumeration" value="{op}"/><RequestPayload>{payload}</RequestPayload></BatchItem></RequestMessage>'),xml('<ResponseMessage/>')]
        messages=pair('Interop','Begin')+pair('Get')+pair('Interop','End')
        kept,notes=R.omit_interop(messages,'2.1',inv)
        self.assertEqual([R.xval(m.find('BatchItem'),'Operation') for m in kept[::2]],['Get'])
        self.assertEqual(len(notes),2)
        kept,notes=R.omit_interop(messages,'1.4',inv)
        self.assertEqual(len(kept),6);self.assertFalse(notes)

class VerificationGets(unittest.TestCase):
    def test_gets_wait_when_a_later_step_reads_attributes(self):
        later=[xml('<RequestMessage><RequestHeader/><BatchItem><Operation type="Enumeration" value="Destroy"/></BatchItem></RequestMessage>')]
        self.assertFalse(R.observes_attributes(later))
        later.append(xml('<RequestMessage><RequestHeader/><BatchItem><Operation type="Enumeration" value="GetAttributes"/></BatchItem></RequestMessage>'))
        self.assertTrue(R.observes_attributes(later))
    def test_rederivation_refuses_to_perturb_the_trace(self):
        r=R.Replay('2.1',{});r.generated.add('k')
        req=request('<BatchItem><Operation type="Enumeration" value="Decrypt"/><RequestPayload><UniqueIdentifier type="TextString" value="k"/><Data type="ByteString" value="00"/></RequestPayload></BatchItem>')
        exp=expected('<BatchItem><Operation type="Enumeration" value="Decrypt"/><ResultStatus type="Enumeration" value="Success"/><ResponsePayload><Data type="ByteString" value="01"/></ResponsePayload></BatchItem>')
        later=[xml('<RequestMessage><RequestHeader/><BatchItem><Operation type="Enumeration" value="GetAttributes"/></BatchItem></RequestMessage>')]
        # 1.x has only Get, which clears Fresh: re-derivation must stop.
        with self.assertRaisesRegex(R.Unsupported,'later step reads'):R.rederive_inputs(r,req,exp,None,'1.4',7,[],later)
        # From 2.0 the fetch is an Export, which is allowed here.
        self.assertTrue(R.quiet_material('2.0'));self.assertFalse(R.quiet_material('1.4'))

class StrictDecoding(unittest.TestCase):
    def good(self):return encode(s('ResponseMessage',n('BatchCount',2,1),n('ResultMessage',7,'abc')))
    def test_well_formed(self):self.assertEqual(V.strict_decode(self.good())[0],T['ResponseMessage'])
    def test_nonzero_padding(self):
        b=bytearray(self.good());b[-1]=1
        with self.assertRaisesRegex(AssertionError,'nonzero padding'):V.strict_decode(bytes(b))
    def test_wrong_integer_length(self):
        bad=T['BatchCount'].to_bytes(3,'big')+bytes([2])+(8).to_bytes(4,'big')+bytes(8)
        with self.assertRaisesRegex(AssertionError,'length'):V.strict_decode(T['ResponseMessage'].to_bytes(3,'big')+b'\x01'+len(bad).to_bytes(4,'big')+bad)
    def test_trailing_bytes_and_bad_boolean(self):
        with self.assertRaisesRegex(AssertionError,'trailing'):V.strict_decode(self.good()+bytes(8))
        b=encode(s('ResponseMessage',n('Sensitive',6,1)));b=b[:-1]+b'\x02'
        with self.assertRaisesRegex(AssertionError,'Boolean'):V.strict_decode(b)
    def test_invalid_utf8(self):
        b=bytearray(encode(s('ResponseMessage',n('ResultMessage',7,'ab'))));b[16]=0xff
        with self.assertRaisesRegex(AssertionError,'UTF-8'):V.strict_decode(bytes(b))

class Independent(unittest.TestCase):
    def test_oaep_and_pss_checks_use_kmip_defaults(self):
        key=rsa.generate_private_key(public_exponent=65537,key_size=2048)
        c=V.rsa_encrypt(key.public_key(),b'hi','OAEP','SHA256',None)
        self.assertEqual(V.rsa_decrypt(key,c,'OAEP','SHA256',None),b'hi')
        # MGF1 defaults to SHA-1 (KMIP 2.1 Cryptographic Parameters).
        sig=key.sign(b'm',padding.PSS(padding.MGF1(hashes.SHA1()),32),hashes.SHA256())
        V.verify_signature(key.public_key(),sig,b'm','PSS','SHA256')
        with self.assertRaisesRegex(AssertionError,'verifies with'):V.verify_signature(key.public_key(),sig,b'm','PSS','SHA256','SHA256')
        with self.assertRaises(AssertionError):V.verify_signature(key.public_key(),sig,b'x','PSS','SHA256')
    def test_symmetric_round_trip_and_digest(self):
        key=os.urandom(16);c,_=V.sym_encrypt('AES',key,'CBC','PKCS5',bytes(16),b'abc')
        self.assertEqual(V.sym_decrypt('AES',key,'CBC','PKCS5',bytes(16),c),b'abc')
        import hashlib
        V.digest_check(key,'SHA256',hashlib.sha256(key).digest())
        with self.assertRaises(AssertionError):V.digest_check(key,'SHA256',hashlib.sha1(key).digest())

if __name__=='__main__':unittest.main()
