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

//! Configurable response forms of the text encodings (docs/encodings.md,
//! docs/interpretations.md): Profiles 2.1 sections 5.4.1 (XML) and 5.5.1 (JSON). Every
//! setting value and preset round-trips through the reader in every edition;
//! values an edition does not name stay hex whatever the setting.
use clap::Parser;
use keytend_kmip_server::{
    encoding::{
        BooleanForm, DateTimeForm, EnumerationForm, Format, MaskForm, NameForm, NumberForm, Preset,
        TextEncoding, TextEncodingArgs,
    },
    tags::*,
    ttlv::Node,
};

const EDITIONS: [(i32, i32); 8] = [
    (1, 0),
    (1, 1),
    (1, 2),
    (1, 3),
    (1, 4),
    (2, 0),
    (2, 1),
    (3, 0),
];
/// 2001-01-01T00:00:00Z.
const DATE: i64 = 978_307_200;

/// A response of `major.minor` with every primitive type, masks, standard,
/// unknown and vendor enumerations, extension tags and a 1.x Attribute Value.
fn response(major: i32, minor: i32) -> Node {
    let mut payload = vec![
        Node::enumeration(OBJECT_TYPE, 2),
        Node::enumeration(OBJECT_TYPE, 0x0000_ffff),
        Node::enumeration(CRYPTOGRAPHIC_ALGORITHM, 0x8000_0001),
        Node::int(CRYPTOGRAPHIC_USAGE_MASK, 0x0c),
        Node::int(CRYPTOGRAPHIC_USAGE_MASK, 0x8000_000cu32 as i32),
        Node::int(CRYPTOGRAPHIC_USAGE_MASK, 0),
        Node::int(CRYPTOGRAPHIC_LENGTH, -1),
        Node::long(USAGE_LIMITS_COUNT, 5),
        Node::long(USAGE_LIMITS_COUNT, 1 << 60),
        Node::long(USAGE_LIMITS_COUNT, -(1 << 53)),
        Node {
            tag: 0x540003,
            value: keytend_kmip_server::ttlv::Value::BigInteger(vec![0, 0, 0, 0, 0, 0, 1, 0]),
        },
        Node {
            tag: 0x540004,
            value: keytend_kmip_server::ttlv::Value::BigInteger(vec![0xff; 16]),
        },
        Node {
            tag: 0x540005,
            value: keytend_kmip_server::ttlv::Value::BigInteger(vec![
                0x7f, 0xff, 0xff, 0xff, 0, 0, 0, 0,
            ]),
        },
        Node {
            tag: OFFSET,
            value: keytend_kmip_server::ttlv::Value::Interval(27),
        },
        Node {
            tag: 0x540006,
            value: keytend_kmip_server::ttlv::Value::DateTimeExtended(2),
        },
        Node::boolean(SENSITIVE, true),
        Node::boolean(SENSITIVE, false),
        Node::date(ACTIVATION_DATE, DATE),
        Node::date(ACTIVATION_DATE, -62_135_596_801),
        Node::bytes(DATA, vec![0xc5, 0x0f, 0x77]),
        Node::text(0x540001, "extension"),
        Node::enumeration(0x540002, 1),
        Node::structure(
            ATTRIBUTE,
            vec![
                Node::text(ATTRIBUTE_NAME, "Cryptographic Algorithm"),
                Node::enumeration(ATTRIBUTE_VALUE, 3),
            ],
        ),
        Node::structure(
            ATTRIBUTE,
            vec![
                Node::text(ATTRIBUTE_NAME, "Cryptographic Usage Mask"),
                Node::int(ATTRIBUTE_VALUE, 0x0c),
            ],
        ),
    ];
    if major >= 2 {
        payload.push(Node::enumeration(ATTRIBUTE_REFERENCE, STATE));
        payload.push(Node::enumeration(ATTRIBUTE_REFERENCE, 0x540001));
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
fn text(format: Format, n: &Node, forms: &TextEncoding) -> String {
    let bytes = format.encode_with(n, forms).unwrap();
    let text = String::from_utf8(bytes.to_vec()).unwrap();
    assert!(format.decode(text.as_bytes()).unwrap() == *n, "{text}");
    text
}
/// Every value of every setting, one setting changed at a time, and every preset.
fn variants() -> Vec<TextEncoding> {
    let mut all: Vec<TextEncoding> = [Preset::Compatible, Preset::Readable, Preset::Hex]
        .into_iter()
        .map(TextEncoding::preset)
        .collect();
    let base = TextEncoding::default();
    for form in [NameForm::Name, NameForm::Hex] {
        all.push(TextEncoding {
            json_tags: form,
            ..base
        });
        all.push(TextEncoding {
            xml_tags: form,
            ..base
        });
        all.push(TextEncoding {
            xml_enumerations: form,
            ..base
        });
    }
    for form in [
        EnumerationForm::Name,
        EnumerationForm::Hex,
        EnumerationForm::Number,
    ] {
        all.push(TextEncoding {
            json_enumerations: form,
            ..base
        });
    }
    for form in [MaskForm::Number, MaskForm::Hex, MaskForm::Names] {
        all.push(TextEncoding {
            json_masks: form,
            ..base
        });
        all.push(TextEncoding {
            xml_masks: form,
            ..base
        });
    }
    for form in [NumberForm::Number, NumberForm::Hex] {
        all.push(TextEncoding {
            json_integers: form,
            ..base
        });
        all.push(TextEncoding {
            json_long_integers: form,
            ..base
        });
        all.push(TextEncoding {
            json_big_integers: form,
            ..base
        });
        all.push(TextEncoding {
            json_intervals: form,
            ..base
        });
        all.push(TextEncoding {
            json_date_time_extended: form,
            ..base
        });
    }
    for form in [BooleanForm::Boolean, BooleanForm::Hex] {
        all.push(TextEncoding {
            json_booleans: form,
            ..base
        });
    }
    for form in [DateTimeForm::Hex, DateTimeForm::Text] {
        all.push(TextEncoding {
            json_date_times: form,
            ..base
        });
    }
    all
}

#[test]
fn every_setting_round_trips_in_every_edition() {
    for forms in variants() {
        for (major, minor) in EDITIONS.into_iter().chain([(1, 5)]) {
            let n = response(major, minor);
            text(Format::Json, &n, &forms);
            text(Format::Xml, &n, &forms);
        }
    }
}

#[test]
fn compatible_is_the_default_and_the_presets_differ_as_documented() {
    assert_eq!(
        TextEncoding::default(),
        TextEncoding::preset(Preset::Compatible)
    );
    assert_eq!(Preset::default(), Preset::Compatible);
    let c = TextEncoding::default();
    assert_eq!(
        (
            c.json_tags,
            c.json_enumerations,
            c.json_masks,
            c.json_big_integers
        ),
        (
            NameForm::Name,
            EnumerationForm::Hex,
            MaskForm::Number,
            NumberForm::Hex
        )
    );
    assert_eq!(
        (
            c.json_booleans,
            c.json_date_times,
            c.xml_tags,
            c.xml_enumerations,
            c.xml_masks
        ),
        (
            BooleanForm::Boolean,
            DateTimeForm::Hex,
            NameForm::Hex,
            NameForm::Hex,
            MaskForm::Names
        )
    );
    let r = TextEncoding::preset(Preset::Readable);
    assert_eq!(
        (
            r.json_enumerations,
            r.json_masks,
            r.json_date_times,
            r.xml_tags,
            r.xml_enumerations
        ),
        (
            EnumerationForm::Name,
            MaskForm::Names,
            DateTimeForm::Text,
            NameForm::Name,
            NameForm::Name
        )
    );
    let h = TextEncoding::preset(Preset::Hex);
    assert_eq!(
        (h.json_tags, h.json_integers, h.json_booleans, h.xml_masks),
        (
            NameForm::Hex,
            NumberForm::Hex,
            BooleanForm::Hex,
            MaskForm::Hex
        )
    );
}

#[derive(Parser)]
struct Cli {
    #[command(flatten)]
    text: TextEncodingArgs,
}
fn parse(args: &[&str]) -> Result<TextEncoding, clap::Error> {
    Cli::try_parse_from(std::iter::once("serve").chain(args.iter().copied()))
        .map(|c| c.text.resolve())
}
#[test]
fn element_options_override_the_preset_and_invalid_values_fail_at_startup() {
    assert_eq!(parse(&[]).unwrap(), TextEncoding::default());
    let r = parse(&["--text-encoding", "readable", "--json-enumerations", "hex"]).unwrap();
    assert_eq!(
        r,
        TextEncoding {
            json_enumerations: EnumerationForm::Hex,
            ..TextEncoding::preset(Preset::Readable)
        }
    );
    let h = parse(&[
        "--text-encoding",
        "hex",
        "--xml-tags",
        "name",
        "--json-date-times",
        "text",
    ])
    .unwrap();
    assert_eq!(
        (h.xml_tags, h.json_date_times, h.json_tags),
        (NameForm::Name, DateTimeForm::Text, NameForm::Hex)
    );
    for bad in [
        &["--text-encoding", "names"][..],
        &["--json-enumerations", "decimal"],
        // 5.4.1.6.7 allows only hex or text for an XML enumeration.
        &["--xml-enumerations", "number"],
        &["--json-booleans", "number"],
        &["--xml-masks", "pipe"],
    ] {
        assert!(parse(bad).is_err(), "{bad:?}");
    }
}

fn json(n: &Node, forms: TextEncoding) -> String {
    text(Format::Json, n, &forms)
}
fn xml(n: &Node, forms: TextEncoding) -> String {
    text(Format::Xml, n, &forms)
}
fn has(text: &str, form: &str) {
    assert!(text.contains(form), "{form} missing from {text}");
}
fn lacks(text: &str, form: &str) {
    assert!(!text.contains(form), "{form} present in {text}");
}

#[test]
fn json_tags_and_enumerations_follow_their_settings_with_hex_for_unnamed_values() {
    let base = TextEncoding::default();
    let n = response(2, 1);
    let named = json(&n, base);
    has(&named, r#"{"tag":"ResponseMessage","type":"Structure""#);
    // Compatible: names for tags, hex for enumeration values.
    has(
        &named,
        r#"{"tag":"ObjectType","type":"Enumeration","value":"0x00000002"}"#,
    );
    has(
        &named,
        r#"{"tag":"AttributeReference","type":"Enumeration","value":"0x0042008d"}"#,
    );
    let hex = json(
        &n,
        TextEncoding {
            json_tags: NameForm::Hex,
            ..base
        },
    );
    has(&hex, r#"{"tag":"0x42007b","type":"Structure""#);
    lacks(&hex, "ResponseMessage");
    let names = json(
        &n,
        TextEncoding {
            json_enumerations: EnumerationForm::Name,
            ..base
        },
    );
    has(
        &names,
        r#"{"tag":"ObjectType","type":"Enumeration","value":"SymmetricKey"}"#,
    );
    has(
        &names,
        r#"{"tag":"AttributeReference","type":"Enumeration","value":"State"}"#,
    );
    has(
        &names,
        r#"{"tag":"AttributeValue","type":"Enumeration","value":"AES"}"#,
    );
    let numbers = json(
        &n,
        TextEncoding {
            json_enumerations: EnumerationForm::Number,
            ..base
        },
    );
    has(
        &numbers,
        r#"{"tag":"ObjectType","type":"Enumeration","value":2}"#,
    );
    has(
        &numbers,
        r#"{"tag":"Operation","type":"Enumeration","value":1}"#,
    );
    // Unknown, vendor and extension values stay hex in every form.
    for text in [&named, &hex, &names, &numbers] {
        has(text, r#""type":"Enumeration","value":"0x0000ffff"}"#);
        has(text, r#""type":"Enumeration","value":"0x80000001"}"#);
        has(
            text,
            r#"{"tag":"0x540002","type":"Enumeration","value":"0x00000001"}"#,
        );
        has(
            text,
            r#"{"tag":"0x540001","type":"TextString","value":"extension"}"#,
        );
        has(text, r#""value":"0x00540001"}"#);
    }
    // A message without a known version names nothing.
    let unknown = json(&response(1, 5), TextEncoding::preset(Preset::Readable));
    has(&unknown, r#"{"tag":"0x42007b""#);
    lacks(&unknown, "SymmetricKey");
    lacks(&unknown, "Encrypt");
}

#[test]
fn json_numbers_masks_booleans_and_dates_follow_their_settings() {
    let base = TextEncoding::default();
    let n = response(1, 4);
    let c = json(&n, base);
    has(
        &c,
        r#"{"tag":"CryptographicUsageMask","type":"Integer","value":12}"#,
    );
    has(&c, r#"{"tag":"BatchCount","type":"Integer","value":1}"#);
    has(
        &c,
        r#"{"tag":"UsageLimitsCount","type":"LongInteger","value":5}"#,
    );
    // 2^60 and -2^53 cannot be exact JSON Numbers (5.5.1.6.5).
    has(&c, r#""value":"0x1000000000000000"}"#);
    has(&c, r#""value":"0xffe0000000000000"}"#);
    has(
        &c,
        r#"{"tag":"0x540003","type":"BigInteger","value":"0x0000000000000100"}"#,
    );
    has(&c, r#"{"tag":"Offset","type":"Interval","value":27}"#);
    has(
        &c,
        r#"{"tag":"0x540006","type":"DateTimeExtended","value":2}"#,
    );
    has(&c, r#"{"tag":"Sensitive","type":"Boolean","value":true}"#);
    has(
        &c,
        r#"{"tag":"ActivationDate","type":"DateTime","value":"0x000000003a4fc880"}"#,
    );

    let masks = json(
        &n,
        TextEncoding {
            json_masks: MaskForm::Names,
            ..base
        },
    );
    has(
        &masks,
        r#"{"tag":"CryptographicUsageMask","type":"Integer","value":"Encrypt|Decrypt"}"#,
    );
    has(&masks, r#""value":"Encrypt|Decrypt|0x80000000"}"#);
    has(
        &masks,
        r#"{"tag":"CryptographicUsageMask","type":"Integer","value":"0x00000000"}"#,
    );
    has(
        &masks,
        r#"{"tag":"AttributeValue","type":"Integer","value":"Encrypt|Decrypt"}"#,
    );
    let masks = json(
        &n,
        TextEncoding {
            json_masks: MaskForm::Hex,
            ..base
        },
    );
    has(
        &masks,
        r#"{"tag":"CryptographicUsageMask","type":"Integer","value":"0x0000000c"}"#,
    );
    has(
        &masks,
        r#"{"tag":"CryptographicUsageMask","type":"Integer","value":"0x8000000c"}"#,
    );

    let h = json(
        &n,
        TextEncoding {
            json_integers: NumberForm::Hex,
            json_long_integers: NumberForm::Hex,
            json_intervals: NumberForm::Hex,
            json_date_time_extended: NumberForm::Hex,
            json_booleans: BooleanForm::Hex,
            ..base
        },
    );
    has(
        &h,
        r#"{"tag":"BatchCount","type":"Integer","value":"0x00000001"}"#,
    );
    has(
        &h,
        r#"{"tag":"CryptographicLength","type":"Integer","value":"0xffffffff"}"#,
    );
    has(
        &h,
        r#"{"tag":"UsageLimitsCount","type":"LongInteger","value":"0x0000000000000005"}"#,
    );
    has(
        &h,
        r#"{"tag":"Offset","type":"Interval","value":"0x0000001b"}"#,
    );
    has(
        &h,
        r#"{"tag":"0x540006","type":"DateTimeExtended","value":"0x0000000000000002"}"#,
    );
    has(
        &h,
        r#"{"tag":"Sensitive","type":"Boolean","value":"0x0000000000000001"}"#,
    );
    has(
        &h,
        r#"{"tag":"Sensitive","type":"Boolean","value":"0x0000000000000000"}"#,
    );
    // Masks have their own setting.
    has(
        &h,
        r#"{"tag":"CryptographicUsageMask","type":"Integer","value":12}"#,
    );

    let big = json(
        &n,
        TextEncoding {
            json_big_integers: NumberForm::Number,
            ..base
        },
    );
    has(
        &big,
        r#"{"tag":"0x540003","type":"BigInteger","value":256}"#,
    );
    // Sixteen bytes, or eight beyond 2^52, keep hex.
    has(
        &big,
        r#"{"tag":"0x540004","type":"BigInteger","value":"0xffffffffffffffffffffffffffffffff"}"#,
    );
    has(
        &big,
        r#"{"tag":"0x540005","type":"BigInteger","value":"0x7fffffff00000000"}"#,
    );

    let dates = json(
        &n,
        TextEncoding {
            json_date_times: DateTimeForm::Text,
            ..base
        },
    );
    has(
        &dates,
        r#"{"tag":"ActivationDate","type":"DateTime","value":"2001-01-01T00:00:00Z"}"#,
    );
}

#[test]
fn xml_tags_enumerations_and_masks_follow_their_settings() {
    let base = TextEncoding::default();
    let n = response(2, 1);
    let c = xml(&n, base);
    // Compatible: the general element, hex enumerations, mask names.
    has(&c, r#"<TTLV tag="0x42007b" type="Structure">"#);
    has(
        &c,
        r#"<TTLV tag="0x420057" type="Enumeration" value="0x00000002"/>"#,
    );
    has(
        &c,
        r#"<TTLV tag="0x42002c" type="Integer" value="Encrypt Decrypt"/>"#,
    );
    let named = xml(
        &n,
        TextEncoding {
            xml_tags: NameForm::Name,
            ..base
        },
    );
    has(&named, "<ResponseMessage><ResponseHeader><ProtocolVersion>");
    has(&named, "</ResponseMessage>");
    has(
        &named,
        r#"<ObjectType type="Enumeration" value="0x00000002"/>"#,
    );
    // Extension tags keep the general element.
    has(
        &named,
        r#"<TTLV tag="0x540001" type="TextString" value="extension"/>"#,
    );
    let names = xml(
        &n,
        TextEncoding {
            xml_enumerations: NameForm::Name,
            ..base
        },
    );
    has(
        &names,
        r#"<TTLV tag="0x420057" type="Enumeration" value="SymmetricKey"/>"#,
    );
    has(
        &names,
        r#"<TTLV tag="0x42000b" type="Enumeration" value="AES"/>"#,
    );
    has(
        &names,
        r#"<TTLV tag="0x420057" type="Enumeration" value="0x0000ffff"/>"#,
    );
    has(
        &names,
        r#"<TTLV tag="0x540002" type="Enumeration" value="0x00000001"/>"#,
    );
    let hex = xml(
        &n,
        TextEncoding {
            xml_masks: MaskForm::Hex,
            ..base
        },
    );
    has(
        &hex,
        r#"<TTLV tag="0x42002c" type="Integer" value="0x0000000c"/>"#,
    );
    let number = xml(
        &n,
        TextEncoding {
            xml_masks: MaskForm::Number,
            ..base
        },
    );
    has(
        &number,
        r#"<TTLV tag="0x42002c" type="Integer" value="12"/>"#,
    );
    has(
        &number,
        r#"<TTLV tag="0x42002c" type="Integer" value="-2147483636"/>"#,
    );
    // The readable preset in 1.4: element names from that edition.
    let readable = xml(&response(1, 4), TextEncoding::preset(Preset::Readable));
    has(
        &readable,
        r#"<AttributeValue type="Enumeration" value="AES"/>"#,
    );
    has(
        &readable,
        r#"<CryptographicUsageMask type="Integer" value="Encrypt Decrypt"/>"#,
    );
    lacks(&readable, "AttributeReference");
    let unknown = xml(&response(1, 5), TextEncoding::preset(Preset::Readable));
    lacks(&unknown, "<ResponseMessage");
    lacks(&unknown, "SymmetricKey");
}

/// `response(major, minor)` with `extra` appended to its payload.
fn response_with(major: i32, minor: i32, extra: Vec<Node>) -> Node {
    let mut n = response(major, minor);
    let keytend_kmip_server::ttlv::Value::Structure(items) = &mut n.value else {
        unreachable!()
    };
    let keytend_kmip_server::ttlv::Value::Structure(batch) = &mut items[1].value else {
        unreachable!()
    };
    let keytend_kmip_server::ttlv::Value::Structure(payload) = &mut batch[2].value else {
        unreachable!()
    };
    payload.extend(extra);
    n
}

/// 2.0 Table 414, 2.1 Table 452 and 3.0 Table 563 define Endpoint Role under
/// the column heading "Encoding Option Name"; the registry gives Endpoint Role
/// its own names, and Encoding Option keeps No Encoding and TTLV Encoding.
#[test]
fn endpoint_role_values_are_named_in_2_x_and_3_0() {
    for (major, minor) in [(2, 0), (2, 1), (3, 0)] {
        let n = response_with(
            major,
            minor,
            vec![
                Node::enumeration(ENDPOINT_ROLE, 1),
                Node::enumeration(ENDPOINT_ROLE, 2),
                Node::enumeration(ENCODING_OPTION, 2),
            ],
        );
        let readable = TextEncoding::preset(Preset::Readable);
        let j = json(&n, readable);
        has(
            &j,
            r#"{"tag":"EndpointRole","type":"Enumeration","value":"Client"}"#,
        );
        has(
            &j,
            r#"{"tag":"EndpointRole","type":"Enumeration","value":"Server"}"#,
        );
        has(
            &j,
            r#"{"tag":"EncodingOption","type":"Enumeration","value":"TTLVEncoding"}"#,
        );
        let x = xml(&n, readable);
        has(&x, r#"<EndpointRole type="Enumeration" value="Client"/>"#);
        has(&x, r#"<EndpointRole type="Enumeration" value="Server"/>"#);
        has(
            &x,
            r#"<EncodingOption type="Enumeration" value="TTLVEncoding"/>"#,
        );
        // The hex preset stays hex.
        let h = xml(&n, TextEncoding::preset(Preset::Hex));
        has(
            &h,
            r#"<TTLV tag="0x420151" type="Enumeration" value="0x00000002"/>"#,
        );
        // Requests: the names decode; an Encoding Option named Client does not.
        let request = |role: &str, option: &str| {
            format!(
                r#"<RequestMessage><RequestHeader><ProtocolVersion><ProtocolVersionMajor type="Integer" value="{major}"/><ProtocolVersionMinor type="Integer" value="{minor}"/></ProtocolVersion><BatchCount type="Integer" value="1"/></RequestHeader><BatchItem><Operation type="Enumeration" value="SetEndpointRole"/><RequestPayload><EndpointRole type="Enumeration" value="{role}"/><EncodingOption type="Enumeration" value="{option}"/></RequestPayload></BatchItem></RequestMessage>"#
            )
        };
        let decoded = Format::Xml
            .decode(request("Server", "NoEncoding").as_bytes())
            .unwrap();
        fn find(n: &Node, found: &mut Vec<(u32, keytend_kmip_server::ttlv::Value)>) {
            if n.tag == ENDPOINT_ROLE || n.tag == ENCODING_OPTION {
                found.push((n.tag, n.value.clone()));
            }
            if let keytend_kmip_server::ttlv::Value::Structure(items) = &n.value {
                items.iter().for_each(|i| find(i, found));
            }
        }
        let mut found = vec![];
        find(&decoded, &mut found);
        assert!(
            found
                == [
                    (
                        ENDPOINT_ROLE,
                        keytend_kmip_server::ttlv::Value::Enumeration(2)
                    ),
                    (
                        ENCODING_OPTION,
                        keytend_kmip_server::ttlv::Value::Enumeration(1)
                    )
                ]
        );
        assert!(
            Format::Xml
                .decode(request("Server", "Client").as_bytes())
                .is_err()
        );
        assert!(
            Format::Xml
                .decode(request("NoEncoding", "NoEncoding").as_bytes())
                .is_err()
        );
    }
}

/// Profiles 2.1 section 5.4.1.6: with `--xml-tags name`, a tag the response's
/// edition does not name is written in the general form, with the optional
/// `name` attribute when another edition publishes a name for it (5.4.1.3);
/// extension tags have none. Both round-trip.
#[test]
fn xml_general_form_carries_published_names_with_the_name_tag_form() {
    let named = TextEncoding {
        xml_tags: NameForm::Name,
        ..TextEncoding::default()
    };
    // 0x420171 Rotate Name Type: named in 2.1, reserved in draft 3.0.
    let n = response_with(3, 0, vec![Node::enumeration(0x420171, 1)]);
    let x = xml(&n, named);
    has(
        &x,
        r#"<TTLV tag="0x420171" name="RotateNameType" type="Enumeration" value="0x00000001"/>"#,
    );
    has(
        &x,
        r#"<TTLV tag="0x540001" type="TextString" value="extension"/>"#,
    );
    lacks(&x, r#"tag="0x540001" name="#);
    // The 2.1 message names the tag itself, so the specific element is used.
    let x21 = xml(
        &response_with(2, 1, vec![Node::enumeration(0x420171, 1)]),
        named,
    );
    has(
        &x21,
        r#"<RotateNameType type="Enumeration" value="0x00000001"/>"#,
    );
    // The hex tag form and messages without a known version write no names.
    let hex = xml(&n, TextEncoding::default());
    has(
        &hex,
        r#"<TTLV tag="0x420171" type="Enumeration" value="0x00000001"/>"#,
    );
    lacks(&hex, " name=");
    let unknown = xml(
        &response_with(1, 5, vec![Node::enumeration(0x420171, 1)]),
        named,
    );
    lacks(&unknown, " name=");
    // A request's general element may carry any name; the tag decides.
    let request = r#"<TTLV tag="0x42007b"><TTLV tag="0x540001" name="SomeExtension" type="TextString" value="x"/></TTLV>"#;
    let decoded = Format::Xml.decode(request.as_bytes()).unwrap();
    let keytend_kmip_server::ttlv::Value::Structure(items) = &decoded.value else {
        panic!()
    };
    assert!(items[0] == Node::text(0x540001, "x"));
}

// REQ:9252afaf55688bb4 2.x masks are Integers in symbolic form in XML (default) and JSON under `--json-masks names` (named configuration; the JSON default stays numeric)
/// 2.0/2.1 section 12: "All mask values SHALL be encoded as Integers in TTLV
/// encoding and SHALL be encoded as Integers but in symbolic form in XML and
/// JSON encodings." XML writes mask names by default; JSON does with
/// `--json-masks names`. The default JSON number is the Profiles
/// 5.5.1.6.4 alternative that the Java clients and Cosmian read.
#[test]
fn masks_are_symbolic_in_xml_by_default_and_in_json_with_names() {
    for (major, minor) in [(2, 0), (2, 1), (3, 0)] {
        let n = response(major, minor);
        let default = TextEncoding::default();
        has(
            &xml(&n, default),
            r#"<TTLV tag="0x42002c" type="Integer" value="Encrypt Decrypt"/>"#,
        );
        has(
            &json(&n, default),
            r#"{"tag":"CryptographicUsageMask","type":"Integer","value":12}"#,
        );
        let names = json(
            &n,
            TextEncoding {
                json_masks: MaskForm::Names,
                ..default
            },
        );
        has(
            &names,
            r#"{"tag":"CryptographicUsageMask","type":"Integer","value":"Encrypt|Decrypt"}"#,
        );
        lacks(&names, r#""type":"Integer","value":12}"#);
    }
}
