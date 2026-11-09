// Copyright 2026 Jeremiah Jordan
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use keytend_kmip_server::{
    encoding::{EnumerationForm, Format, MAX_TEXT_FRAME, TextEncoding},
    tags::*,
    ttlv::{Node, Value},
};
use proptest::prelude::*;
fn same(a: &Node, b: &Node) {
    assert!(a == b, "encoded values differ")
}
#[test]
fn symbolic_fields_use_referenced_tables_and_preserve_split_html_words() {
    for (tag, name, code) in [
        (OPERATION, "Create", 1),
        (BATCH_ERROR_CONTINUATION_OPTION, "Undo", 3),
        (MASK_GENERATOR_HASHING_ALGORITHM, "SHA_256", 6),
        (MASK_GENERATOR, "MGF1", 1),
    ] {
        let xml = format!(
            "<RequestMessage><RequestHeader><ProtocolVersion><ProtocolVersionMajor type=\"Integer\" value=\"2\"/><ProtocolVersionMinor type=\"Integer\" value=\"1\"/></ProtocolVersion></RequestHeader><TTLV tag=\"0x{tag:06x}\" type=\"Enumeration\" value=\"{name}\"/></RequestMessage>"
        );
        let n = Format::Xml.decode(xml.as_bytes()).unwrap();
        assert_eq!(n.get(tag).unwrap().number().unwrap(), code);
        let json = Format::Json.encode(&n).unwrap();
        same(&Format::Json.decode(&json).unwrap(), &n);
    }
    let xml = br#"<RequestMessage><RequestHeader><ProtocolVersion><ProtocolVersionMajor type="Integer" value="1"/><ProtocolVersionMinor type="Integer" value="3"/></ProtocolVersion></RequestHeader><ObjectType type="Enumeration" value="Template"/></RequestMessage>"#;
    assert_eq!(
        Format::Xml
            .decode(xml)
            .unwrap()
            .get(OBJECT_TYPE)
            .unwrap()
            .number()
            .unwrap(),
        6
    );
    let xml = br#"<RequestMessage><RequestHeader><ProtocolVersion><ProtocolVersionMajor type="Integer" value="2"/><ProtocolVersionMinor type="Integer" value="1"/></ProtocolVersion></RequestHeader><ObjectType type="Enumeration" value="Template"/></RequestMessage>"#;
    assert!(Format::Xml.decode(xml).is_err());
}
#[test]
fn split_method_superscripts_and_draft_polynomial_table_use_their_own_names() {
    for (major, minor) in [
        (1, 0),
        (1, 1),
        (1, 2),
        (1, 3),
        (1, 4),
        (2, 0),
        (2, 1),
        (3, 0),
    ] {
        for (name, code) in [
            ("XOR", 1),
            ("PolynomialSharingGF2_16", 2),
            ("PolynomialSharingGF216", 2),
            ("PolynomialSharingPrimeField", 3),
            ("PolynomialSharingGF2_8", 4),
            ("PolynomialSharingGF28", 4),
        ] {
            let xml = format!(
                "<RequestMessage><RequestHeader><ProtocolVersion><ProtocolVersionMajor type=\"Integer\" value=\"{major}\"/><ProtocolVersionMinor type=\"Integer\" value=\"{minor}\"/></ProtocolVersion></RequestHeader><SplitKeyMethod type=\"Enumeration\" value=\"{name}\"/></RequestMessage>"
            );
            let decoded = Format::Xml.decode(xml.as_bytes());
            if code == 4 && major == 1 && minor < 2 {
                assert!(decoded.is_err());
            } else {
                assert_eq!(
                    decoded
                        .unwrap()
                        .get(SPLIT_KEY_METHOD)
                        .unwrap()
                        .number()
                        .unwrap(),
                    code
                );
            }
        }
    }
    for (tag, name, expected) in [
        ("SplitKeyPolynomial", "Polynomial_283", Some(1)),
        ("SplitKeyPolynomial", "Polynomial_285", Some(2)),
        ("State", "Polynomial_283", None),
    ] {
        let xml = format!(
            "<RequestMessage><RequestHeader><ProtocolVersion><ProtocolVersionMajor type=\"Integer\" value=\"3\"/><ProtocolVersionMinor type=\"Integer\" value=\"0\"/></ProtocolVersion></RequestHeader><{tag} type=\"Enumeration\" value=\"{name}\"/></RequestMessage>"
        );
        match expected {
            Some(code) => assert_eq!(
                Format::Xml
                    .decode(xml.as_bytes())
                    .unwrap()
                    .get(SPLIT_KEY_POLYNOMIAL)
                    .unwrap()
                    .number()
                    .unwrap(),
                code
            ),
            None => assert!(Format::Xml.decode(xml.as_bytes()).is_err()),
        }
    }
    for (tag, accepted) in [("TicketType", true), ("State", false)] {
        let xml = format!(
            "<RequestMessage><RequestHeader><ProtocolVersion><ProtocolVersionMajor type=\"Integer\" value=\"2\"/><ProtocolVersionMinor type=\"Integer\" value=\"1\"/></ProtocolVersion></RequestHeader><{tag} type=\"Enumeration\" value=\"Login\"/></RequestMessage>"
        );
        assert_eq!(Format::Xml.decode(xml.as_bytes()).is_ok(), accepted);
    }
}
#[test]
fn xml_declaration_position_and_whitespace_content_follow_xml_grammar() {
    let n = Node::structure(REQUEST_MESSAGE, vec![]);
    let xml =
        br#"<?xml version="1.0"?><TTLV tag="RequestMessage"><![CDATA[ \n ]]>&#x20;&#10;</TTLV>"#;
    // Literal backslash+n is not XML whitespace.
    assert!(Format::Xml.decode(xml).is_err());
    let xml =
        "<?xml version=\"1.0\"?><TTLV tag=\"RequestMessage\"><![CDATA[ \n ]]>&#x20;&#10;</TTLV>";
    same(&Format::Xml.decode(xml.as_bytes()).unwrap(), &n);
    for bad in [
        " <?xml version=\"1.0\"?><TTLV tag=\"RequestMessage\"/>",
        "<!--before--><?xml version=\"1.0\"?><TTLV tag=\"RequestMessage\"/>",
        "<![CDATA[ ]]><TTLV tag=\"RequestMessage\"/>",
        "&#32;<TTLV tag=\"RequestMessage\"/>",
        "<TTLV tag=\"RequestMessage\">&unknown;</TTLV>",
    ] {
        assert!(Format::Xml.decode(bad.as_bytes()).is_err());
    }
}
#[test]
fn all_ttlv_types_round_trip_through_both_profiles() {
    let n = Node::structure(
        REQUEST_MESSAGE,
        vec![
            Node::int(0x540001, i32::MIN),
            Node::long(0x540002, i64::MAX),
            Node {
                tag: 0x540003,
                value: Value::BigInteger(vec![255; 24]),
            },
            Node::enumeration(OPERATION, 0x80000001),
            Node::boolean(BATCH_ORDER_OPTION, true),
            Node::text(ATTRIBUTE_NAME, "雪<&\"'\t\n\r"),
            Node::bytes(DATA, (0..=255).collect::<Vec<_>>()),
            Node::date(TIME_STAMP, i64::MIN),
            Node::interval(0x540004, u32::MAX),
            Node {
                tag: 0x540005,
                value: Value::DateTimeExtended(i64::MIN),
            },
            Node::identifier(UNIQUE_IDENTIFIER, "u:雪"),
            Node::reference(CERTIFICATE_LINK, "literal*key"),
            Node::name_reference(PUBLIC_KEY_LINK, "database-key"),
            Node::structure(ATTRIBUTES, vec![]),
        ],
    );
    for f in [Format::Ttlv, Format::Json, Format::Xml] {
        let bytes = f.encode(&n).unwrap();
        same(&f.decode(&bytes).unwrap(), &n);
    }
}
#[test]
fn profile_numeric_spellings_and_precision_are_exact() {
    let cases = [
        ("Integer", "\"0xffffffff\"", Value::Integer(-1)),
        (
            "LongInteger",
            "\"0xfffffffffffffffe\"",
            Value::LongInteger(-2),
        ),
        (
            "BigInteger",
            "\"0x0000000000000000\"",
            Value::BigInteger(vec![0; 8]),
        ),
        ("BigInteger", "-1", Value::BigInteger(vec![255; 8])),
        ("Enumeration", "4294967295", Value::Enumeration(u32::MAX)),
        ("Boolean", "\"0x0000000000000001\"", Value::Boolean(true)),
        ("Interval", "\"0xffffffff\"", Value::Interval(u32::MAX)),
        (
            "DateTimeExtended",
            "\"0x8000000000000000\"",
            Value::DateTimeExtended(i64::MIN),
        ),
    ];
    for (kind, value, expected) in cases {
        let json = format!("{{\"tag\":\"0x540001\",\"type\":\"{kind}\",\"value\":{value}}}");
        assert!(Format::Json.decode(json.as_bytes()).unwrap().value == expected);
    }
    for value in [
        "4503599627370496",
        "-4503599627370496",
        "9007199254740993e0",
        "1.5",
        "1e999",
    ] {
        let json = format!("{{\"tag\":\"0x540001\",\"type\":\"LongInteger\",\"value\":{value}}}");
        assert!(Format::Json.decode(json.as_bytes()).is_err());
    }
    let n = Node::long(USAGE_LIMITS_COUNT, 1i64 << 60);
    let encoded = Format::Json.encode(&n).unwrap();
    assert!(
        std::str::from_utf8(&encoded)
            .unwrap()
            .contains("0x1000000000000000")
    );
}
#[test]
fn standard_names_masks_and_attribute_value_context_are_decoded() {
    for (name, value) in [("AES", 3), ("DES3", 2), ("SHA_256", 6)] {
        let tag = if name == "SHA_256" {
            "HashingAlgorithm"
        } else {
            "CryptographicAlgorithm"
        };
        let raw = format!("{{\"tag\":\"{tag}\",\"type\":\"Enumeration\",\"value\":\"{name}\"}}");
        assert!(Format::Json.decode(raw.as_bytes()).unwrap().value == Value::Enumeration(value));
    }
    let json=br#"{"tag":"Attribute","value":[{"tag":"AttributeValue","type":"Integer","value":"Encrypt|Decrypt|0x00001000"},{"tag":"AttributeName","type":"TextString","value":"Cryptographic Usage Mask"}]}"#;
    assert!(
        Format::Json
            .decode(json)
            .unwrap()
            .get(ATTRIBUTE_VALUE)
            .unwrap()
            .value
            == Value::Integer(0x100c)
    );
    let xml=br#"<Attribute><AttributeValue type="Enumeration" value="AES"/><AttributeName type="TextString" value="Cryptographic Algorithm"/></Attribute>"#;
    assert!(
        Format::Xml
            .decode(xml)
            .unwrap()
            .get(ATTRIBUTE_VALUE)
            .unwrap()
            .value
            == Value::Enumeration(3)
    );
    let xml = br#"<CryptographicUsageMask type="Integer" value="Encrypt Decrypt 0x00001000"/>"#;
    assert!(Format::Xml.decode(xml).unwrap().value == Value::Integer(0x100c));
    let json =
        br#"{"tag":"AttributeReference","type":"Enumeration","value":"CryptographicAlgorithm"}"#;
    assert!(
        Format::Json.decode(json).unwrap().value == Value::Enumeration(CRYPTOGRAPHIC_ALGORITHM)
    );
}
// REQ:10f32001e4290053 an element or object without a type is a Structure
// REQ:ad33c916ca9ce294 the type property defaults to Structure and may be omitted
// REQ:a048c4077f3677db namespaced XML uses urn:oasis:tc:kmip:xmlns (a foreign namespace is refused in the next test)
#[test]
fn empty_structures_generic_xml_namespaces_and_vendor_tags() {
    for data in [
        br#"<TTLV tag="0x540001"/>"#.as_slice(),
        br#"<x540001 type="Structure"/>"#,
        br#"<k:TTLV xmlns:k="urn:oasis:tc:kmip:xmlns" tag="0x540001"/>"#,
    ] {
        same(
            &Format::Xml.decode(data).unwrap(),
            &Node::structure(0x540001, vec![]),
        );
    }
    for data in [
        br#"{"tag":"0x540001","value":null}"#.as_slice(),
        br#"{"tag":"0x540001","name":"Extension hint","value":[]}"#,
    ] {
        same(
            &Format::Json.decode(data).unwrap(),
            &Node::structure(0x540001, vec![]),
        );
    }
}
#[test]
fn xml_attributes_escape_and_normalize_as_xml_not_as_html() {
    let n=Format::Xml.decode(b"<AttributeValue type=\"TextString\" value=\"a\tb\r\nc&#x9;d&#xA;e&#xD;f&amp;&lt;&quot;&apos;\"/>").unwrap();
    assert!(n.value == Value::TextString("a b c\td\ne\rf&<\"'".to_owned()));
    same(
        &Format::Xml
            .decode(&Format::Xml.encode(&n).unwrap())
            .unwrap(),
        &n,
    );
    let bad = Node::text(ATTRIBUTE_VALUE, "null\0byte");
    assert!(Format::Xml.encode(&bad).is_err());
    same(
        &Format::Json
            .decode(&Format::Json.encode(&bad).unwrap())
            .unwrap(),
        &bad,
    );
}
// REQ:a048c4077f3677db XML in any namespace other than urn:oasis:tc:kmip:xmlns is refused
#[test]
fn xml_dtd_entities_namespaces_malformed_and_oversized_inputs_are_rejected() {
    for xml in [
        r#"<!DOCTYPE x [<!ENTITY secret SYSTEM "file:///etc/passwd">]><AttributeValue type="TextString" value="&secret;"/>"#,
        r#"<AttributeValue type="TextString" value="&unknown;"/>"#,
        r#"<AttributeValue type="TextString" value="&#0;"/>"#,
        r#"<AttributeValue type="TextString" value="&#x1;"/>"#,
        r#"<AttributeValue type="Integer" value="1" value="2"/>"#,
        r#"<RequestMessage></ResponseMessage>"#,
        r#"<RequestMessage/><RequestMessage/>"#,
        r#"<RequestMessage xmlns="https://attacker.invalid"/>"#,
        r#"<RequestMessage>text</RequestMessage>"#,
        r#"<Data type="ByteString" value="ab c0"/>"#,
        r#"<AttributeValue type="TextString"/>"#,
        r#"<?xml version="1.1"?><RequestMessage/>"#,
        r#"<?xml version="1.0" encoding="ISO-8859-1"?><RequestMessage/>"#,
    ] {
        assert!(Format::Xml.decode(xml.as_bytes()).is_err(), "{xml}");
    }
    assert!(Format::Xml.decode(&[0xff]).is_err());
    assert!(
        Format::Json
            .decode(&vec![b' '; MAX_TEXT_FRAME + 1])
            .is_err()
    );
}
#[test]
fn json_duplicates_types_ranges_and_unknown_members_are_rejected() {
    for json in [
        r#"{"tag":"Data","tag":"Data","value":[]}"#,
        r#"{"tag":"Data","type":null,"value":[]}"#,
        r#"{"tag":"Data","name":null,"value":[]}"#,
        r#"{"tag":"Data","unexpected":1,"value":[]}"#,
        r#"{"tag":"Data","type":"Boolean","value":1}"#,
        r#"{"tag":"Data","type":"TextString","value":1}"#,
        r#"{"tag":"Data","type":"ByteString","value":"0x00"}"#,
        r#"{"tag":"Data","type":"Integer","value":2147483648}"#,
        r#"{"tag":"Data","type":"Enumeration","value":-1}"#,
        r#"{"tag":"Data","type":"Integer","value":"0x1"}"#,
        r#"{"tag":"Data","type":"BigInteger","value":"0x00"}"#,
        r#"{"tag":"Data","value":{}}"#,
        r#"{"tag":"0x42000001","value":[]}"#,
        r#"{"tag":"Data","type":"Unknown","value":0}"#,
        r#"{"tag":"Data"}"#,
    ] {
        assert!(Format::Json.decode(json.as_bytes()).is_err(), "{json}");
    }
}
#[test]
fn depth_and_node_count_limits_match_binary_limits() {
    let mut n = Node::structure(REQUEST_MESSAGE, vec![]);
    for _ in 0..33 {
        n = Node::structure(REQUEST_MESSAGE, vec![n]);
    }
    for f in [Format::Json, Format::Xml] {
        assert!(f.encode(&n).is_err());
    }
    let raw = format!(
        "{}{}{}",
        "<RequestMessage>".repeat(34),
        "",
        "</RequestMessage>".repeat(34)
    );
    assert!(Format::Xml.decode(raw.as_bytes()).is_err());
    let raw = format!(
        "<RequestMessage>{}</RequestMessage>",
        r#"<Data type="ByteString" value=""/>"#.repeat(16384)
    );
    assert!(Format::Xml.decode(raw.as_bytes()).is_err());
}
#[test]
fn requested_dates_cover_offsets_fractions_midnight_and_the_full_epoch_range() {
    for (date, seconds) in [
        ("1970-01-01T00:00:00Z", 0),
        ("2001-01-01T10:00:00+10:00", 978307200),
        ("1969-12-31T23:59:59.999Z", -1),
        ("1969-12-31T24:00:00Z", 0),
        ("0001-01-01T00:00:00Z", -62135596800),
        ("-0001-01-01T00:00:00Z", -62167219200),
        ("10000-01-01T00:00:00Z", 253402300800),
    ] {
        let raw = format!("<ActivationDate type=\"DateTime\" value=\"{date}\"/>");
        assert!(
            Format::Xml.decode(raw.as_bytes()).unwrap().value == Value::DateTime(seconds),
            "{date}"
        );
    }
    for date in [
        "2026-02-29T00:00:00Z",
        "1970-01-01T00:00:00",
        "0000-01-01T00:00:00Z",
        "1970-01-01T24:00:01Z",
        "1970-01-01T00:00:00+14:01",
        "1970-01-01T00:00:00Zjunk",
    ] {
        let raw = format!("<ActivationDate type=\"DateTime\" value=\"{date}\"/>");
        assert!(Format::Xml.decode(raw.as_bytes()).is_err(), "{date}");
    }
    for seconds in [
        i64::MIN,
        i64::MAX,
        -62167219200,
        -1,
        0,
        253402300799,
        253402300800,
    ] {
        let n = Node::date(TIME_STAMP, seconds);
        same(
            &Format::Xml
                .decode(&Format::Xml.encode(&n).unwrap())
                .unwrap(),
            &n,
        );
    }
}
proptest! {
 #[test]fn every_signed_epoch_round_trips(seconds in any::<i64>()){let n=Node::date(TIME_STAMP,seconds);prop_assert!(Format::Xml.decode(&Format::Xml.encode(&n).unwrap()).unwrap()==n);}
 #[test]fn arbitrary_bytes_round_trip(bytes in prop::collection::vec(any::<u8>(),0..4096)){let n=Node::bytes(DATA,bytes);for f in [Format::Json,Format::Xml]{prop_assert!(f.decode(&f.encode(&n).unwrap()).unwrap()==n);}}
}

#[test]
fn empty_mask_lists_are_zero_without_accepting_empty_components_or_other_integer_fields() {
    for (tag, name) in [
        (CRYPTOGRAPHIC_USAGE_MASK, "CryptographicUsageMask"),
        (STORAGE_STATUS_MASK, "StorageStatusMask"),
        (PROTECTION_STORAGE_MASK, "ProtectionStorageMask"),
    ] {
        let json = format!("{{\"tag\":\"{name}\",\"type\":\"Integer\",\"value\":\"\"}}");
        let xml = format!("<{name} type=\"Integer\" value=\"\"/>");
        for (format, data) in [
            (Format::Json, json.as_bytes()),
            (Format::Xml, xml.as_bytes()),
        ] {
            let node = format.decode(data).unwrap();
            assert!(node.value == Value::Integer(0));
            assert_eq!(node.encode(), Node::int(tag, 0).encode());
        }
    }
    assert!(
        Format::Xml
            .decode(b"<CryptographicUsageMask type=\"Integer\" value=\" &#x9;&#xA;&#xD; \"/>")
            .unwrap()
            .value
            == Value::Integer(0)
    );
    let legacy=b"<Attribute><AttributeName type=\"TextString\" value=\"Cryptographic Usage Mask\"/><AttributeValue type=\"Integer\" value=\"\"/></Attribute>";
    assert!(
        Format::Xml
            .decode(legacy)
            .unwrap()
            .required(ATTRIBUTE_VALUE)
            .unwrap()
            .value
            == Value::Integer(0)
    );
    for bad in [
        "|",
        "Encrypt|",
        "|Decrypt",
        "Encrypt||Decrypt",
        " ",
        "Unknown",
    ] {
        let value =
            serde_json::json!({"tag":"CryptographicUsageMask","type":"Integer","value":bad});
        assert!(Format::Json.decode(value.to_string().as_bytes()).is_err());
    }
    assert!(
        Format::Xml
            .decode("<CryptographicUsageMask type=\"Integer\" value=\"\u{a0}\"/>".as_bytes())
            .is_err()
    );
    for data in [b"<CryptographicLength type=\"Integer\" value=\"\"/>".as_slice(), b"<Attribute><AttributeName type=\"TextString\" value=\"Cryptographic Length\"/><AttributeValue type=\"Integer\" value=\"\"/></Attribute>".as_slice()] { assert!(Format::Xml.decode(data).is_err()); }
}
// REQ:ea885a96c212fe09 XML server: values are written and read in each type's Profiles 5.4.1.6 form
// REQ:070d715bdef02ef2 JSON server: values are written and read in each type's Profiles 5.5.1.6 form
// With the name normalization test (requirement_clauses.rs), the default-Structure,
// namespace, mask, escaping and time-zone tests in this file, this covers every rule
// of Profiles 5.4.1 and 5.5.1.
#[test]
fn xml_and_json_value_forms_follow_profiles_5_4_1_and_5_5_1() {
    let n = Node::structure(
        REQUEST_MESSAGE,
        vec![
            Node::int(BATCH_COUNT, -7),
            Node::long(USAGE_LIMITS_COUNT, 1i64 << 60),
            Node::long(0x540002, -3),
            Node {
                tag: 0x540003,
                value: Value::BigInteger(vec![0xff; 8]),
            },
            Node::enumeration(OBJECT_TYPE, 2),
            Node::boolean(BATCH_ORDER_OPTION, true),
            Node::text(ATTRIBUTE_NAME, "Object Group"),
            Node::bytes(DATA, vec![0xa0, 0x0b, 0x7c]),
            Node::date(ARCHIVE_DATE, 978_307_200),
            Node::interval(OFFSET, 31),
            Node {
                tag: 0x540005,
                value: Value::DateTimeExtended(5),
            },
            Node::structure(PROTOCOL_VERSION, vec![]),
        ],
    );
    // Encoder: hex tags (5.x.1.3), decimal xsd:int/long/unsignedInt, hexBinary
    // Big Integer and Byte String, hex Enumeration, xsd:boolean, zoned Date-Time.
    let xml = String::from_utf8(Format::Xml.encode(&n).unwrap().to_vec()).unwrap();
    for form in [
        r#"<TTLV tag="0x42000d" type="Integer" value="-7"/>"#,
        r#"<TTLV tag="0x420096" type="LongInteger" value="1152921504606846976"/>"#,
        r#"<TTLV tag="0x540003" type="BigInteger" value="ffffffffffffffff"/>"#,
        r#"<TTLV tag="0x420057" type="Enumeration" value="0x00000002"/>"#,
        r#"<TTLV tag="0x420010" type="Boolean" value="true"/>"#,
        r#"<TTLV tag="0x4200c2" type="ByteString" value="a00b7c"/>"#,
        r#"<TTLV tag="0x420005" type="DateTime" value="2001-01-01T00:00:00Z"/>"#,
        r#"<TTLV tag="0x420058" type="Interval" value="31"/>"#,
        r#"<TTLV tag="0x540005" type="DateTimeExtended" value="5"/>"#,
    ] {
        assert!(xml.contains(form), "{form}");
    }
    // JSON: Numbers below 2^52, hex strings at and above (5.5.1.6.5).
    let json = String::from_utf8(Format::Json.encode(&n).unwrap().to_vec()).unwrap();
    for form in [
        r#"{"tag":"0x42000d","type":"Integer","value":-7}"#,
        r#"{"tag":"0x420096","type":"LongInteger","value":"0x1000000000000000"}"#,
        r#"{"tag":"0x540002","type":"LongInteger","value":-3}"#,
        r#"{"tag":"0x540003","type":"BigInteger","value":"0xffffffffffffffff"}"#,
        r#"{"tag":"0x420057","type":"Enumeration","value":"0x00000002"}"#,
        r#"{"tag":"0x420010","type":"Boolean","value":true}"#,
        r#"{"tag":"0x4200c2","type":"ByteString","value":"a00b7c"}"#,
        r#"{"tag":"0x420058","type":"Interval","value":31}"#,
        r#"{"tag":"0x420069","type":"Structure","value":[]}"#,
    ] {
        assert!(json.contains(form), "{form}");
    }
    for f in [Format::Xml, Format::Json] {
        same(&f.decode(&f.encode(&n).unwrap()).unwrap(), &n);
    }
    // Decoder: every alternative form the sections allow.
    let xml_forms: &[(&str, Value)] = &[
        (
            r#"<BatchCount type="Integer" value="12"/>"#,
            Value::Integer(12),
        ),
        (
            r#"<TTLV tag="0x42000d" name="BatchCount" type="Integer" value="12"/>"#,
            Value::Integer(12),
        ),
        (
            r#"<CryptographicUsageMask type="Integer" value="0x0000000c"/>"#,
            Value::Integer(12),
        ),
        (
            r#"<CryptographicUsageMask type="Integer" value="Decrypt 0x00000004"/>"#,
            Value::Integer(12),
        ),
        (
            r#"<UsageLimitsCount type="LongInteger" value="-9"/>"#,
            Value::LongInteger(-9),
        ),
        (
            r#"<TTLV tag="0x540003" type="BigInteger" value="0000000000000001"/>"#,
            Value::BigInteger(vec![0, 0, 0, 0, 0, 0, 0, 1]),
        ),
        (
            r#"<ObjectType type="Enumeration" value="PrivateKey"/>"#,
            Value::Enumeration(4),
        ),
        (
            r#"<ObjectType type="Enumeration" value="0x00000004"/>"#,
            Value::Enumeration(4),
        ),
        (
            r#"<BatchOrderOption type="Boolean" value="false"/>"#,
            Value::Boolean(false),
        ),
        (
            r#"<Data type="ByteString" value="A00B7C"/>"#,
            Value::ByteString(vec![0xa0, 0x0b, 0x7c]),
        ),
        (
            r#"<ArchiveDate type="DateTime" value="2001-01-01T10:00:00+10:00"/>"#,
            Value::DateTime(978_307_200),
        ),
        (
            r#"<Offset type="Interval" value="31"/>"#,
            Value::Interval(31),
        ),
        (
            r#"<TTLV tag="0x540005" type="DateTimeExtended" value="5"/>"#,
            Value::DateTimeExtended(5),
        ),
    ];
    for (text, value) in xml_forms {
        assert!(
            Format::Xml.decode(text.as_bytes()).unwrap().value == *value,
            "{text}"
        );
    }
    let json_forms: &[(&str, Value)] = &[
        (
            r#"{"tag":"BatchCount","type":"Integer","value":12}"#,
            Value::Integer(12),
        ),
        (
            r#"{"tag":"BatchCount","type":"Integer","value":"0x0000000C"}"#,
            Value::Integer(12),
        ),
        (
            r#"{"tag":"CryptographicUsageMask","type":"Integer","value":"Decrypt|0x00000004"}"#,
            Value::Integer(12),
        ),
        (
            r#"{"tag":"0x540001","type":"LongInteger","value":"0xfffffffffffffffd"}"#,
            Value::LongInteger(-3),
        ),
        (
            r#"{"tag":"0x540001","type":"LongInteger","value":-3}"#,
            Value::LongInteger(-3),
        ),
        (
            r#"{"tag":"0x540001","type":"BigInteger","value":1}"#,
            Value::BigInteger(vec![0, 0, 0, 0, 0, 0, 0, 1]),
        ),
        (
            r#"{"tag":"0x540001","type":"BigInteger","value":"0x0000000000000001"}"#,
            Value::BigInteger(vec![0, 0, 0, 0, 0, 0, 0, 1]),
        ),
        (
            r#"{"tag":"0x420057","type":"Enumeration","value":4}"#,
            Value::Enumeration(4),
        ),
        (
            r#"{"tag":"ObjectType","type":"Enumeration","value":"0x00000004"}"#,
            Value::Enumeration(4),
        ),
        (
            r#"{"tag":"ObjectType","type":"Enumeration","value":"PrivateKey"}"#,
            Value::Enumeration(4),
        ),
        (
            r#"{"tag":"BatchOrderOption","type":"Boolean","value":false}"#,
            Value::Boolean(false),
        ),
        (
            r#"{"tag":"BatchOrderOption","type":"Boolean","value":"0x0000000000000000"}"#,
            Value::Boolean(false),
        ),
        (
            r#"{"tag":"Data","type":"ByteString","value":"A00B7C"}"#,
            Value::ByteString(vec![0xa0, 0x0b, 0x7c]),
        ),
        (
            r#"{"tag":"ArchiveDate","type":"DateTime","value":"0x000000003a4fc880"}"#,
            Value::DateTime(978_307_200),
        ),
        (
            r#"{"tag":"ArchiveDate","type":"DateTime","value":"2001-01-01T10:00:00+10:00"}"#,
            Value::DateTime(978_307_200),
        ),
        (
            r#"{"tag":"Offset","type":"Interval","value":31}"#,
            Value::Interval(31),
        ),
        (
            r#"{"tag":"Offset","type":"Interval","value":"0x0000001f"}"#,
            Value::Interval(31),
        ),
        (
            r#"{"tag":"0x540001","type":"DateTimeExtended","value":5}"#,
            Value::DateTimeExtended(5),
        ),
        (
            r#"{"tag":"0x540001","type":"DateTimeExtended","value":"0x0000000000000005"}"#,
            Value::DateTimeExtended(5),
        ),
    ];
    for (text, value) in json_forms {
        assert!(
            Format::Json.decode(text.as_bytes()).unwrap().value == *value,
            "{text}"
        );
    }
    // Structures: nested elements in XML; an array or null in JSON; type optional.
    let nested =
        br#"<ProtocolVersion><ProtocolVersionMajor type="Integer" value="2"/></ProtocolVersion>"#;
    let expected = Node::structure(PROTOCOL_VERSION, vec![Node::int(PROTOCOL_VERSION_MAJOR, 2)]);
    same(&Format::Xml.decode(nested).unwrap(), &expected);
    let nested = br#"{"tag":"ProtocolVersion","value":[{"tag":"ProtocolVersionMajor","type":"Integer","value":2}]}"#;
    same(&Format::Json.decode(nested).unwrap(), &expected);
    // Hex numbers need the 0x prefix and no spaces (5.x.1.2).
    for bad in [
        r#"{"tag":"BatchCount","type":"Integer","value":"0000000C"}"#,
        r#"{"tag":"BatchCount","type":"Integer","value":"0x 0000000C"}"#,
    ] {
        assert!(Format::Json.decode(bad.as_bytes()).is_err(), "{bad}");
    }
}
/// A response of `version` with standard, renamed, withdrawn, unknown and
/// extension values, so the expected JSON spellings differ per edition.
fn versioned_response(major: i32, minor: i32) -> Node {
    let mut payload = vec![
        Node::enumeration(OBJECT_TYPE, 2),
        Node::enumeration(OBJECT_TYPE, 6),
        Node::enumeration(HASHING_ALGORITHM, 0xe),
        Node::enumeration(DIGITAL_SIGNATURE_ALGORITHM, 3),
        Node::enumeration(CRYPTOGRAPHIC_ALGORITHM, 0x0000_ffff),
        Node::enumeration(CRYPTOGRAPHIC_ALGORITHM, 0x8000_0001),
        Node::int(CRYPTOGRAPHIC_USAGE_MASK, 0x0c),
        Node::text(0x540001, "extension"),
        Node::enumeration(0x540002, 1),
        Node::structure(
            ATTRIBUTE,
            vec![
                Node::text(ATTRIBUTE_NAME, "Cryptographic Algorithm"),
                Node::enumeration(ATTRIBUTE_VALUE, 3),
            ],
        ),
    ];
    if major >= 2 {
        payload.push(Node::enumeration(ATTRIBUTE_REFERENCE, STATE));
        payload.push(Node::enumeration(ATTRIBUTE_REFERENCE, 0x540001));
        payload.push(Node::enumeration(0x420171, 1));
        payload.push(Node::enumeration(RESULT_REASON, 0x4a));
    }
    Node::structure(
        RESPONSE_MESSAGE,
        vec![
            Node::structure(
                RESPONSE_HEADER,
                vec![
                    Node::structure(
                        PROTOCOL_VERSION,
                        vec![
                            Node::int(PROTOCOL_VERSION_MAJOR, major),
                            Node::int(PROTOCOL_VERSION_MINOR, minor),
                        ],
                    ),
                    Node::int(BATCH_COUNT, 1),
                ],
            ),
            Node::structure(
                BATCH_ITEM,
                vec![
                    Node::enumeration(OPERATION, 1),
                    Node::enumeration(RESULT_STATUS, 0),
                    Node::structure(RESPONSE_PAYLOAD, payload),
                ],
            ),
        ],
    )
}
// docs/interpretations.md (JSON names): Profiles 2.1 section 5.5.1.3 allows a
// tag's normalised text, 5.5.1.6.7 an enumeration's CamelCase text. With
// enumeration names selected (the default writes them in hex), responses use
// the names of their own edition and hex for anything it does not name.
#[test]
fn json_responses_name_tags_and_enumerations_in_their_own_edition() {
    let forms = TextEncoding {
        json_enumerations: EnumerationForm::Name,
        ..TextEncoding::default()
    };
    for (major, minor) in [
        (1, 0),
        (1, 1),
        (1, 2),
        (1, 3),
        (1, 4),
        (2, 0),
        (2, 1),
        (3, 0),
    ] {
        let n = versioned_response(major, minor);
        let json =
            String::from_utf8(Format::Json.encode_with(&n, &forms).unwrap().to_vec()).unwrap();
        let has = |form: &str| assert!(json.contains(form), "{major}.{minor}: {form} in {json}");
        let lacks = |form: &str| assert!(!json.contains(form), "{major}.{minor}: {form} in {json}");
        has(r#"{"tag":"ResponseMessage","type":"Structure","value":[{"tag":"ResponseHeader""#);
        has(r#"{"tag":"ProtocolVersionMajor","type":"Integer","value":"#);
        has(r#"{"tag":"Operation","type":"Enumeration","value":"Create"}"#);
        has(r#"{"tag":"ResultStatus","type":"Enumeration","value":"Success"}"#);
        has(r#"{"tag":"ObjectType","type":"Enumeration","value":"SymmetricKey"}"#);
        // Unknown and vendor enumeration values, extension tags: hex.
        has(r#"{"tag":"CryptographicAlgorithm","type":"Enumeration","value":"0x0000ffff"}"#);
        has(r#"{"tag":"CryptographicAlgorithm","type":"Enumeration","value":"0x80000001"}"#);
        has(r#"{"tag":"0x540001","type":"TextString","value":"extension"}"#);
        has(r#"{"tag":"0x540002","type":"Enumeration","value":"0x00000001"}"#);
        // Masks keep JSON Numbers by default.
        has(r#"{"tag":"CryptographicUsageMask","type":"Integer","value":12}"#);
        // A 1.x Attribute Value takes its enumeration from the Attribute Name.
        has(r#"{"tag":"AttributeValue","type":"Enumeration","value":"AES"}"#);
        let template = r#"{"tag":"ObjectType","type":"Enumeration","value":"Template"}"#;
        let reserved = r#"{"tag":"ObjectType","type":"Enumeration","value":"0x00000006"}"#;
        if major == 1 {
            has(template);
            if minor >= 1 {
                has(r#""value":"SHA_1WithRSAEncryptionPKCS_1V1_5"}"#);
            } else {
                // 1.0 defines no Digital Signature Algorithm tag.
                has(r#"{"tag":"0x4200ae","type":"Enumeration","value":"0x00000003"}"#);
            }
            if minor == 4 {
                has(r#"{"tag":"HashingAlgorithm","type":"Enumeration","value":"SHA_3_224"}"#);
            } else {
                has(r#"{"tag":"HashingAlgorithm","type":"Enumeration","value":"0x0000000e"}"#);
            }
            lacks("AttributeReference");
        } else {
            has(reserved);
            lacks("Template");
            has(r#""value":"SHA_1WithRSAEncryption"}"#);
            has(r#"{"tag":"HashingAlgorithm","type":"Enumeration","value":"SHA3_224"}"#);
            has(r#"{"tag":"AttributeReference","type":"Enumeration","value":"State"}"#);
            has(r#"{"tag":"AttributeReference","type":"Enumeration","value":"0x00540001"}"#);
            if major == 2 && minor == 1 {
                has(r#"{"tag":"RotateNameType","type":"Enumeration","value":"0x00000001"}"#);
                has(r#"{"tag":"ResultReason","type":"Enumeration","value":"UnknownObjectGroup"}"#);
            } else if major == 3 {
                // Draft 3.0 reserves both 2.1 names.
                has(r#"{"tag":"0x420171","type":"Enumeration","value":"0x00000001"}"#);
                has(r#"{"tag":"ResultReason","type":"Enumeration","value":"0x0000004a"}"#);
            }
        }
        same(&Format::Json.decode(json.as_bytes()).unwrap(), &n);
        // The previous all-hex form still decodes to the same message.
        let hex = json
            .replace(r#""tag":"ResponseMessage""#, r#""tag":"0x42007b""#)
            .replace(r#""value":"Create""#, r#""value":"0x00000001""#);
        same(&Format::Json.decode(hex.as_bytes()).unwrap(), &n);
    }
}
#[test]
fn json_messages_without_a_known_version_keep_hex_tags_and_values() {
    let mut n = versioned_response(1, 5);
    let json = String::from_utf8(Format::Json.encode(&n).unwrap().to_vec()).unwrap();
    assert!(
        json.starts_with(r#"{"tag":"0x42007b","type":"Structure""#),
        "{json}"
    );
    assert!(json.contains(r#"{"tag":"0x42005c","type":"Enumeration","value":"0x00000001"}"#));
    assert!(!json.contains("Create") && !json.contains("ResponseHeader"));
    same(&Format::Json.decode(json.as_bytes()).unwrap(), &n);
    n = Node::enumeration(OBJECT_TYPE, 2);
    let json = Format::Json.encode(&n).unwrap();
    assert_eq!(
        &json[..],
        br#"{"tag":"0x420057","type":"Enumeration","value":"0x00000002"}"#
    );
}
#[test]
fn xml_responses_keep_the_generic_hex_form() {
    // Profiles 2.1 section 5.4.1.6: the general TTLV element "allows any TTLV
    // including extensions to be encoded". The XML writer is unchanged.
    let xml = String::from_utf8(
        Format::Xml
            .encode(&versioned_response(2, 1))
            .unwrap()
            .to_vec(),
    )
    .unwrap();
    assert!(xml.contains(r#"<TTLV tag="0x42005c" type="Enumeration" value="0x00000001"/>"#));
    assert!(!xml.contains("Create"));
}
