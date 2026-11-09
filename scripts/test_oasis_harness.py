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

"""Protect the comparator from both false failures and false conformance passes."""
import time,unittest,xml.etree.ElementTree as ET
from oasis_conformance import compare,encode_xml,preflight,fixture_constants,Unsupported

def xml(text):return ET.fromstring(text)
def attribute(name,value):
    return f'<Attribute><AttributeName type="TextString" value="{name}"/><AttributeValue type="Integer" value="{value}"/></Attribute>'

class HarnessTests(unittest.TestCase):
    def test_mac_fixture_alias_keeps_literal_output_and_types_strict(self):
        response=xml('<ResponseMessage><BatchItem><ResponsePayload><MACData type="ByteString" value="aabb"/></ResponsePayload></BatchItem></ResponseMessage>')
        constants=fixture_constants([response]);self.assertEqual(constants,{'$MAC_DATA':b'\xaa\xbb'})
        request=xml('<MACData type="ByteString" value="$MAC_DATA"/>')
        self.assertEqual(encode_xml(request,constants),(0x4200c6,8,b'\xaa\xbb'))
        compare(response,encode_xml(response,{}),constants)
        for wrong in ['<MACData type="ByteString" value="aabc"/>','<MACData type="TextString" value="aabb"/>']:
            actual=xml('<ResponseMessage><BatchItem><ResponsePayload>'+wrong+'</ResponsePayload></BatchItem></ResponseMessage>')
            with self.assertRaises(AssertionError):compare(response,encode_xml(actual,{}),constants)
        other=xml('<ResponseMessage><BatchItem><ResponsePayload><MACData type="ByteString" value="1122"/></ResponsePayload></BatchItem></ResponseMessage>')
        self.assertEqual(fixture_constants([response,other]),{})
        with self.assertRaises(Unsupported):encode_xml(request,fixture_constants([response,other]))
        symbolic=xml('<ResponseMessage><BatchItem><ResponsePayload><MACData type="ByteString" value="$OTHER"/></ResponsePayload></BatchItem></ResponseMessage>')
        self.assertEqual(fixture_constants([symbolic]),{})

    def test_draft_identifier_types_and_prefixed_tags_are_distinct(self):
        for kind in ['Identifier','Reference','NameReference']:
            expected=xml(f'<UniqueIdentifier type="{kind}" value="key-1"/>')
            actual=encode_xml(expected,{})
            compare(expected,actual,{})
            with self.assertRaises(AssertionError):compare(expected,encode_xml(xml('<UniqueIdentifier type="TextString" value="key-1"/>'),{}),{})
        group=encode_xml(xml('<GroupLink type="NameReference" value="database"/>'),{})
        self.assertEqual(group,(0x4201b3,14,'database'))
        with self.assertRaises(Unsupported):compare(xml('<UniqueIdentifier type="FutureKind" value="key-1"/>'),(0x420094,7,'key-1'),{})
    def test_attribute_order_is_not_semantic_but_identity_and_values_are(self):
        a=attribute('Cryptographic Length',256);b=attribute('Cryptographic Usage Mask',12)
        expected=xml('<ResponsePayload>'+a+b+'</ResponsePayload>')
        compare(expected,encode_xml(xml('<ResponsePayload>'+b+a+'</ResponsePayload>'),{}),{})
        for contents in [a,a+a,a+attribute('Cryptographic Usage Mask',4)]:
            with self.assertRaises(AssertionError):compare(expected,encode_xml(xml('<ResponsePayload>'+contents+'</ResponsePayload>'),{}),{})

    def test_batch_order_and_primitive_types_are_checked(self):
        a='<BatchItem><Operation type="Enumeration" value="Create"/></BatchItem>'
        b='<BatchItem><Operation type="Enumeration" value="Get"/></BatchItem>'
        with self.assertRaises(AssertionError):compare(xml('<ResponseMessage>'+a+b+'</ResponseMessage>'),encode_xml(xml('<ResponseMessage>'+b+a+'</ResponseMessage>'),{}),{})
        with self.assertRaises(AssertionError):compare(xml('<Data type="ByteString" value="00"/>'),encode_xml(xml('<Data type="TextString" value="00"/>'),{}),{})

    def test_generated_variables_are_stable_and_relative_times_checked(self):
        expected=xml('<UniqueIdentifier type="TextString" value="$ID"/>');variables={}
        compare(expected,encode_xml(xml('<UniqueIdentifier type="TextString" value="first"/>'),{}),variables)
        with self.assertRaises(AssertionError):compare(expected,encode_xml(xml('<UniqueIdentifier type="TextString" value="second"/>'),{}),variables)
        expected=xml('<ActivationDate type="DateTime" value="$NOW-3600"/>')
        compare(expected,encode_xml(expected,{}),{})
        wrong=encode_xml(expected,{});wrong=(wrong[0],wrong[1],int(time.time()))
        with self.assertRaises(AssertionError):compare(expected,wrong,{})

    def test_production_forbidden_controls_and_fixed_random_samples_are_unexecuted(self):
        samples=[
            ('<RequestMessage><BatchItem><Operation value="Interop"/></BatchItem></RequestMessage>', 'test_only_control_operation'),
            ('<RequestMessage><BatchItem><Operation value="Create"/></BatchItem></RequestMessage><ResponseMessage><DigestValue value="00"/></ResponseMessage>', 'deterministic_fixture_required'),
            ('<RequestMessage><BatchItem><Operation value="RNGRetrieve"/></BatchItem></RequestMessage><ResponseMessage><BatchItem><ResponsePayload><Data value="00"/></ResponsePayload></BatchItem></ResponseMessage>', 'deterministic_fixture_required'),
        ]
        for sample,category in samples:
            with self.assertRaises(Unsupported) as result:preflight(list(xml('<KMIP>'+sample+'</KMIP>')))
            self.assertEqual(result.exception.category,category)

    def test_deterministic_ciphertext_is_a_fixture_constraint_for_generated_keys(self):
        encrypted='<RequestMessage><BatchItem><Operation value="Encrypt"/><RequestPayload><UniqueIdentifier value="$ID"/></RequestPayload></BatchItem></RequestMessage><ResponseMessage><BatchItem><ResponsePayload><Data value="0123"/></ResponsePayload></BatchItem></ResponseMessage>'
        for operation in ['Create','Register']:
            setup=f'<RequestMessage><BatchItem><Operation value="{operation}"/><RequestPayload/></BatchItem></RequestMessage><ResponseMessage><BatchItem><ResponsePayload><UniqueIdentifier value="$ID"/></ResponsePayload></BatchItem></ResponseMessage>'
            messages=list(xml('<KMIP>'+setup+encrypted+'</KMIP>'))
            if operation=='Create':
                with self.assertRaises(Unsupported) as result:preflight(messages)
                self.assertEqual(result.exception.category,'deterministic_fixture_required')
            else:preflight(messages)

    def test_randomized_rsa_outputs_require_fixture_even_for_registered_keys(self):
        for padding,op,output in [('OAEP','Encrypt','Data'),('PSS','Sign','SignatureData')]:
            setup=f'<RequestMessage><BatchItem><Operation value="Register"/><RequestPayload><Attributes><CryptographicParameters><PaddingMethod value="{padding}"/></CryptographicParameters></Attributes></RequestPayload></BatchItem></RequestMessage><ResponseMessage><BatchItem><ResponsePayload><UniqueIdentifier value="$ID"/></ResponsePayload></BatchItem></ResponseMessage>'
            operation=f'<RequestMessage><BatchItem><Operation value="{op}"/><RequestPayload><UniqueIdentifier value="$ID"/></RequestPayload></BatchItem></RequestMessage><ResponseMessage><BatchItem><ResponsePayload><{output} value="0123"/></ResponsePayload></BatchItem></ResponseMessage>'
            messages=list(xml('<KMIP>'+setup+operation+'</KMIP>'))
            with self.assertRaises(Unsupported) as result:preflight(messages)
            self.assertEqual(result.exception.category,'deterministic_fixture_required')
            # Known-answer decrypt/verify traces remain executable.
            inverse=operation.replace(f'value="{op}"', 'value="Decrypt"' if op=='Encrypt' else 'value="SignatureVerify"')
            preflight(list(xml('<KMIP>'+setup+inverse+'</KMIP>')))
            # A zero-salt PSS signature of a fixed key is deterministic.
            if padding=='PSS':
                setup=setup.replace('</CryptographicParameters>','<SaltLength value="0"/></CryptographicParameters>')
                preflight(list(xml('<KMIP>'+setup+operation+'</KMIP>')))

    def test_omitted_legacy_attribute_index_means_zero_but_other_indices_differ(self):
        def link(index=None):
            field='' if index is None else f'<AttributeIndex type="Integer" value="{index}"/>'
            return f'<ResponsePayload><Attribute><AttributeName type="TextString" value="Link"/>{field}<AttributeValue><LinkType type="Enumeration" value="NextLink"/><LinkedObjectIdentifier type="TextString" value="b"/></AttributeValue></Attribute></ResponsePayload>'
        for expected,actual in [(None,0),(0,None),(0,0),(None,None)]:
            compare(xml(link(expected)),encode_xml(xml(link(actual)),{}),{})
        for expected,actual in [(None,1),(1,None),(1,0),(0,1)]:
            with self.assertRaises(AssertionError):compare(xml(link(expected)),encode_xml(xml(link(actual)),{}),{})

    def test_attribute_list_names_are_unordered_but_exact(self):
        def batch(op,*names):
            refs=''.join(f'<AttributeReference type="Enumeration" value="{n}"/>' for n in names)
            return xml(f'<BatchItem><Operation type="Enumeration" value="{op}"/><ResultStatus type="Enumeration" value="Success"/><ResponsePayload>{refs}</ResponsePayload></BatchItem>')
        expected=batch('GetAttributeList','State','Name','Digest')
        compare(expected,encode_xml(batch('GetAttributeList','Digest','State','Name'),{}),{})
        for wrong in [('State','Name','Name'),('State','Name','Fresh'),('State','Name')]:
            with self.assertRaises(AssertionError):compare(expected,encode_xml(batch('GetAttributeList',*wrong),{}),{})
        # Other repeated response fields keep trace order.
        with self.assertRaises(AssertionError):compare(batch('Query','State','Name'),encode_xml(batch('Query','Name','State'),{}),{})
        legacy=xml('<BatchItem><Operation type="Enumeration" value="GetAttributeList"/><ResponsePayload><AttributeName type="TextString" value="State"/><AttributeName type="TextString" value="Name"/></ResponsePayload></BatchItem>')
        compare(legacy,encode_xml(xml('<BatchItem><Operation type="Enumeration" value="GetAttributeList"/><ResponsePayload><AttributeName type="TextString" value="Name"/><AttributeName type="TextString" value="State"/></ResponsePayload></BatchItem>'),{}),{})

    def test_identifier_placeholders_use_the_unique_identifier_enumeration(self):
        for tag in ['UniqueIdentifier','PrivateKeyUniqueIdentifier','PublicKeyUniqueIdentifier','LinkedObjectIdentifier']:
            self.assertEqual(encode_xml(xml(f'<{tag} type="Enumeration" value="IDPlaceholder"/>'),{})[1:],(5,1))
        with self.assertRaises(Unsupported):encode_xml(xml('<UniqueIdentifier type="Enumeration" value="NotAPlaceholder"/>'),{})

    def test_failures_name_expected_and_received_values(self):
        with self.assertRaises(AssertionError) as result:
            compare(xml('<Data type="ByteString" value="0a"/>'),encode_xml(xml('<Data type="ByteString" value="0b"/>'),{}),{})
        self.assertIn('expected 0a, received 0b',str(result.exception))
        expected=xml('<ResponseMessage><BatchItem><ResultStatus type="Enumeration" value="Success"/></BatchItem></ResponseMessage>')
        failed=xml('<ResponseMessage><BatchItem><ResultStatus type="Enumeration" value="OperationFailed"/><ResultReason type="Enumeration" value="PermissionDenied"/><ResultMessage type="TextString" value="no"/></BatchItem></ResponseMessage>')
        with self.assertRaises(AssertionError) as result:compare(expected,encode_xml(failed,{}),{})
        self.assertIn("reason=12; message='no'",str(result.exception))

class DiagnosticMessageTests(unittest.TestCase):
    def test_diagnostic_wording_never_relaxes_reason_type_or_cardinality(self):
        expected=xml('<BatchItem><ResultStatus type="Enumeration" value="OperationFailed"/><ResultReason type="Enumeration" value="CryptographicFailure"/><ResultMessage type="TextString" value="Bad tag"/></BatchItem>')
        different=xml('<BatchItem><ResultStatus type="Enumeration" value="OperationFailed"/><ResultReason type="Enumeration" value="CryptographicFailure"/><ResultMessage type="TextString" value="Authentication failed"/></BatchItem>')
        with self.assertRaises(AssertionError):compare(expected,encode_xml(different,{}),{})
        ignored=[]
        compare(expected,encode_xml(different,{}),{},ignore_result_message_text=True,message_text_mismatches=ignored)
        self.assertEqual(ignored,['/BatchItem/ResultMessage'])
        for changed in [
            '<BatchItem><ResultStatus type="Enumeration" value="OperationFailed"/><ResultReason type="Enumeration" value="InvalidField"/><ResultMessage type="TextString" value="Authentication failed"/></BatchItem>',
            '<BatchItem><ResultStatus type="Enumeration" value="Success"/><ResultReason type="Enumeration" value="CryptographicFailure"/><ResultMessage type="TextString" value="Authentication failed"/></BatchItem>',
            '<BatchItem><ResultStatus type="Enumeration" value="OperationFailed"/><ResultReason type="Enumeration" value="CryptographicFailure"/><ResultMessage type="ByteString" value="00"/></BatchItem>',
            '<BatchItem><ResultStatus type="Enumeration" value="OperationFailed"/><ResultReason type="Enumeration" value="CryptographicFailure"/></BatchItem>',
            '<BatchItem><ResultStatus type="Enumeration" value="OperationFailed"/><ResultReason type="Enumeration" value="CryptographicFailure"/><ResultMessage type="TextString" value="A"/><ResultMessage type="TextString" value="B"/></BatchItem>',
        ]:
            with self.assertRaises(AssertionError):compare(expected,encode_xml(xml(changed),{}),{},ignore_result_message_text=True)
        value=xml('<Data type="ByteString" value="01"/>')
        with self.assertRaises(AssertionError):compare(value,encode_xml(xml('<Data type="ByteString" value="02"/>'),{}),{},ignore_result_message_text=True)

if __name__=='__main__':unittest.main()
