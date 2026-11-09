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

//! Operation Policy Name `default` (1.0-1.4), metadata-only objects (Key
//! Value Present / Key Value Location, 1.2-2.1), the 1.0 Activation Date
//! rule at creation, and the 1.x X.509 Key Usage to Usage Mask mapping.
//! Asserting tests cite their clause digests as `REQ:<digest>`
//! (docs/specs/requirement-matrix.json); the paraphrases are our own words.
use keytend_kmip_server::{
    protocol::{Engine, Version},
    store::{Store, now},
    tags::*,
    ttlv::{Node, Value},
};
use openssl::{
    asn1::Asn1Time,
    bn::BigNum,
    ec::{EcGroup, EcKey},
    hash::MessageDigest,
    nid::Nid,
    pkey::PKey,
    x509::{X509, X509NameBuilder, extension::KeyUsage},
};
use tempfile::TempDir;

const LEGACY: [Version; 5] = [
    Version(1, 0),
    Version(1, 1),
    Version(1, 2),
    Version(1, 3),
    Version(1, 4),
];
/// Versions that define Key Value Present and Key Value Location.
const METADATA_ONLY: [Version; 5] = [
    Version(1, 2),
    Version(1, 3),
    Version(1, 4),
    Version(2, 0),
    Version(2, 1),
];

struct Fixture {
    _dir: TempDir,
    engine: Engine,
}
impl Fixture {
    fn new() -> Self {
        let d = tempfile::tempdir().unwrap();
        let k = d.path().join("master");
        std::fs::write(&k, [42; 32]).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&k, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        let store = Store::open(&d.path().join("keys.sqlite"), &k).unwrap();
        Self {
            _dir: d,
            engine: Engine::new(store, false),
        }
    }
    fn call_as(&mut self, owner: &str, v: Version, op: u32, fields: Vec<Node>) -> Node {
        let request = Node::structure(
            REQUEST_MESSAGE,
            vec![
                Node::structure(REQUEST_HEADER, vec![v.node(), Node::int(BATCH_COUNT, 1)]),
                Node::structure(
                    BATCH_ITEM,
                    vec![
                        Node::enumeration(OPERATION, op),
                        Node::structure(REQUEST_PAYLOAD, fields),
                    ],
                ),
            ],
        );
        let response = self.engine.process(owner, &request).unwrap();
        response.required(BATCH_ITEM).unwrap().clone()
    }
    fn call(&mut self, v: Version, op: u32, fields: Vec<Node>) -> Node {
        self.call_as("alice", v, op, fields)
    }
}

fn label(v: Version) -> String {
    format!("{}.{}", v.0, v.1)
}
/// The attribute is present with exactly this value.
fn has(attrs: &[Node], expected: Node) -> bool {
    attrs.contains(&expected)
}
fn ok(item: &Node) -> &Node {
    assert_eq!(
        item.required(RESULT_STATUS).unwrap().number().unwrap(),
        0,
        "reason {:?} {:?}",
        item.get(RESULT_REASON).map(|n| n.number()),
        item.get(RESULT_MESSAGE).map(|n| n.string())
    );
    item.required(RESPONSE_PAYLOAD).unwrap()
}
fn reason(item: &Node) -> u32 {
    assert_eq!(
        item.required(RESULT_STATUS).unwrap().number().unwrap(),
        1,
        "expected a failure"
    );
    item.required(RESULT_REASON).unwrap().number().unwrap()
}
fn id_of(item: &Node) -> String {
    ok(item)
        .required(UNIQUE_IDENTIFIER)
        .unwrap()
        .identifier_text()
        .unwrap()
        .to_owned()
}
fn uid(id: &str) -> Node {
    Node::text(UNIQUE_IDENTIFIER, id)
}
fn name_of(tag: u32) -> Option<&'static str> {
    match tag {
        CRYPTOGRAPHIC_ALGORITHM => Some("Cryptographic Algorithm"),
        CRYPTOGRAPHIC_LENGTH => Some("Cryptographic Length"),
        CRYPTOGRAPHIC_USAGE_MASK => Some("Cryptographic Usage Mask"),
        t => tag_name(t),
    }
}
fn legacy(mut value: Node) -> Node {
    let name = name_of(value.tag).unwrap();
    value.tag = ATTRIBUTE_VALUE;
    Node::structure(ATTRIBUTE, vec![Node::text(ATTRIBUTE_NAME, name), value])
}
fn container(v: Version, attrs: Vec<Node>) -> Node {
    if v.0 >= 2 {
        Node::structure(ATTRIBUTES, attrs)
    } else {
        Node::structure(TEMPLATE_ATTRIBUTE, attrs.into_iter().map(legacy).collect())
    }
}
fn aes(v: Version, extra: Vec<Node>) -> Vec<Node> {
    let mut attrs = vec![
        Node::enumeration(CRYPTOGRAPHIC_ALGORITHM, 3),
        Node::int(CRYPTOGRAPHIC_LENGTH, 128),
        Node::int(CRYPTOGRAPHIC_USAGE_MASK, 0xc),
    ];
    attrs.extend(extra);
    vec![Node::enumeration(OBJECT_TYPE, 2), container(v, attrs)]
}
/// Every attribute of an object, by tag (1.x Attribute structures decoded).
fn attributes(f: &mut Fixture, v: Version, id: &str) -> Vec<Node> {
    let item = f.call(v, 11, vec![uid(id)]);
    let payload = ok(&item);
    if v.0 >= 2 {
        return payload
            .get(ATTRIBUTES)
            .map(|n| n.children().unwrap().to_vec())
            .unwrap_or_default();
    }
    payload
        .all(ATTRIBUTE)
        .map(|a| {
            let name = a.required(ATTRIBUTE_NAME).unwrap().string().unwrap();
            let mut value = a.required(ATTRIBUTE_VALUE).unwrap().clone();
            value.tag = (0x420000..=0x420200)
                .find(|t| name_of(*t) == Some(name))
                .unwrap_or(0);
            value
        })
        .collect()
}
fn find(attrs: &[Node], tag: u32) -> Option<&Node> {
    attrs.iter().find(|a| a.tag == tag)
}
fn located(f: &mut Fixture, v: Version, filter: Node) -> Vec<String> {
    let fields = if v.0 >= 2 {
        vec![Node::structure(ATTRIBUTES, vec![filter])]
    } else {
        vec![legacy(filter)]
    };
    let item = f.call(v, 8, fields);
    ok(&item)
        .all(UNIQUE_IDENTIFIER)
        .map(|n| n.identifier_text().unwrap().to_owned())
        .collect()
}

// ---------- Operation Policy Name ----------

// REQ:6771e653034d2d1f the server implements one named policy, `default`,
// used for every object created without a policy name
#[test]
fn every_legacy_object_reports_the_default_operation_policy() {
    for v in LEGACY {
        let mut f = Fixture::new();
        let implicit = id_of(&f.call(v, 1, aes(v, vec![])));
        let explicit = id_of(&f.call(
            v,
            1,
            aes(v, vec![Node::text(OPERATION_POLICY_NAME, "default")]),
        ));
        for id in [&implicit, &explicit] {
            let attrs = attributes(&mut f, v, id);
            assert!(
                has(&attrs, Node::text(OPERATION_POLICY_NAME, "default")),
                "{}",
                label(v)
            );
        }
        let mut found = located(&mut f, v, Node::text(OPERATION_POLICY_NAME, "default"));
        found.sort();
        let mut expected = vec![implicit.clone(), explicit.clone()];
        expected.sort();
        assert_eq!(found, expected, "{}", label(v));
        // A name the server does not implement matches nothing in Locate.
        assert!(located(&mut f, v, Node::text(OPERATION_POLICY_NAME, "other")).is_empty());
    }
}
#[test]
fn unknown_operation_policies_and_client_changes_are_refused() {
    for v in LEGACY {
        let mut f = Fixture::new();
        assert_eq!(
            reason(&f.call(
                v,
                1,
                aes(v, vec![Node::text(OPERATION_POLICY_NAME, "permissive")])
            )),
            7,
            "{}",
            label(v)
        );
        assert_eq!(
            reason(&f.call(
                v,
                1,
                aes(
                    v,
                    vec![
                        Node::text(OPERATION_POLICY_NAME, "default"),
                        Node::text(OPERATION_POLICY_NAME, "default"),
                    ]
                )
            )),
            8
        );
        assert_eq!(
            reason(&f.call(v, 1, aes(v, vec![Node::int(OPERATION_POLICY_NAME, 1)]))),
            7
        );
        let id = id_of(&f.call(v, 1, aes(v, vec![])));
        // Table 73: "Modifiable by client No", "Deletable by client No".
        for (op, fields) in [
            (
                13,
                vec![
                    uid(&id),
                    legacy(Node::text(OPERATION_POLICY_NAME, "default")),
                ],
            ),
            (
                14,
                vec![
                    uid(&id),
                    legacy(Node::text(OPERATION_POLICY_NAME, "default")),
                ],
            ),
            (
                15,
                vec![
                    uid(&id),
                    Node::text(ATTRIBUTE_NAME, "Operation Policy Name"),
                ],
            ),
        ] {
            assert_eq!(reason(&f.call(v, op, fields)), 12, "{} {op}", label(v));
        }
    }
}
#[test]
fn operation_policy_name_does_not_exist_from_2_0() {
    for v in [Version(2, 0), Version(2, 1)] {
        let mut f = Fixture::new();
        let id = id_of(&f.call(v, 1, aes(v, vec![])));
        assert!(find(&attributes(&mut f, v, &id), OPERATION_POLICY_NAME).is_none());
        assert_eq!(
            reason(&f.call(
                v,
                1,
                aes(v, vec![Node::text(OPERATION_POLICY_NAME, "default")])
            )),
            8
        );
    }
    // An object created in 1.x does not carry the name into 2.x.
    let mut f = Fixture::new();
    let id = id_of(&f.call(
        Version(1, 1),
        1,
        aes(
            Version(1, 1),
            vec![Node::text(OPERATION_POLICY_NAME, "default")],
        ),
    ));
    assert!(
        find(
            &attributes(&mut f, Version(2, 1), &id),
            OPERATION_POLICY_NAME
        )
        .is_none()
    );
}
/// The documented difference from Table 75: public objects stay owner-only.
#[test]
fn the_server_default_policy_keeps_public_objects_owner_only() {
    for v in LEGACY {
        let mut f = Fixture::new();
        let item = f.call(
            v,
            2,
            vec![
                legacy_or_new(
                    v,
                    COMMON_TEMPLATE_ATTRIBUTE,
                    COMMON_ATTRIBUTES,
                    vec![
                        Node::enumeration(CRYPTOGRAPHIC_ALGORITHM, 4),
                        Node::int(CRYPTOGRAPHIC_LENGTH, 2048),
                    ],
                ),
                legacy_or_new(
                    v,
                    PRIVATE_KEY_TEMPLATE_ATTRIBUTE,
                    PRIVATE_KEY_ATTRIBUTES,
                    vec![Node::int(CRYPTOGRAPHIC_USAGE_MASK, 1)],
                ),
                legacy_or_new(
                    v,
                    PUBLIC_KEY_TEMPLATE_ATTRIBUTE,
                    PUBLIC_KEY_ATTRIBUTES,
                    vec![Node::int(CRYPTOGRAPHIC_USAGE_MASK, 2)],
                ),
            ],
        );
        let public = ok(&item)
            .required(PUBLIC_KEY_UNIQUE_IDENTIFIER)
            .unwrap()
            .identifier_text()
            .unwrap()
            .to_owned();
        assert!(has(
            &attributes(&mut f, v, &public),
            Node::text(OPERATION_POLICY_NAME, "default")
        ));
        for op in [9, 10, 11, 12] {
            assert_eq!(
                reason(&f.call_as("bob", v, op, vec![uid(&public)])),
                1,
                "{} {op}",
                label(v)
            );
        }
    }
}
fn legacy_or_new(v: Version, old: u32, new: u32, attributes: Vec<Node>) -> Node {
    let mut c = container(v, attributes);
    c.tag = if v.0 >= 2 { new } else { old };
    c
}
// ---------- Metadata-only objects ----------

fn location(value: &str) -> Node {
    Node::structure(
        KEY_VALUE_LOCATION,
        vec![
            Node::text(KEY_VALUE_LOCATION_VALUE, value),
            Node::enumeration(KEY_VALUE_LOCATION_TYPE, 1),
        ],
    )
}
fn metadata_only_block(kind_tag: u32, algorithm: Option<u32>, bits: Option<i32>) -> Node {
    let mut block = vec![Node::enumeration(KEY_FORMAT_TYPE, 1)];
    if let Some(a) = algorithm {
        block.push(Node::enumeration(CRYPTOGRAPHIC_ALGORITHM, a));
    }
    if let Some(b) = bits {
        block.push(Node::int(CRYPTOGRAPHIC_LENGTH, b));
    }
    Node::structure(kind_tag, vec![Node::structure(KEY_BLOCK, block)])
}
fn register_metadata_only(f: &mut Fixture, v: Version, extra: Vec<Node>) -> Node {
    let mut fields = aes(v, extra);
    fields.push(metadata_only_block(SYMMETRIC_KEY, Some(3), Some(128)));
    f.call(v, 3, fields)
}

// REQ:2f4e1aab2b211102 Register without a Key Value creates Key Value Present
#[test]
fn register_without_key_value_stores_a_metadata_only_object() {
    for v in METADATA_ONLY {
        let mut f = Fixture::new();
        let id = id_of(&register_metadata_only(
            &mut f,
            v,
            vec![location("HSM-12345")],
        ));
        let attrs = attributes(&mut f, v, &id);
        assert!(
            has(&attrs, Node::boolean(KEY_VALUE_PRESENT, false)),
            "{}",
            label(v)
        );
        assert!(has(&attrs, location("HSM-12345")));
        // No Digest: it would be computed over the absent Key Value.
        assert!(find(&attrs, DIGEST).is_none());
        // Get returns the Key Block as registered, without a Key Value.
        let item = f.call(v, 10, vec![uid(&id)]);
        let block = ok(&item)
            .required(SYMMETRIC_KEY)
            .unwrap()
            .required(KEY_BLOCK)
            .unwrap();
        assert!(block.get(KEY_VALUE).is_none());
        assert_eq!(
            block.required(KEY_FORMAT_TYPE).unwrap().number().unwrap(),
            1
        );
        assert_eq!(
            block
                .required(CRYPTOGRAPHIC_LENGTH)
                .unwrap()
                .number()
                .unwrap(),
            128
        );
        // A Locate on Key Value Present finds only the metadata-only object.
        let ordinary = id_of(&f.call(v, 1, aes(v, vec![])));
        assert_eq!(
            located(&mut f, v, Node::boolean(KEY_VALUE_PRESENT, false)),
            vec![id.clone()]
        );
        assert!(find(&attributes(&mut f, v, &ordinary), KEY_VALUE_PRESENT).is_none());
        // Key Value Location is client modifiable and may repeat.
        let add = if v.0 >= 2 {
            vec![
                uid(&id),
                Node::structure(NEW_ATTRIBUTE, vec![location("HSM-2")]),
            ]
        } else {
            vec![uid(&id), legacy(location("HSM-2"))]
        };
        ok(&f.call(v, 13, add));
        let count = attributes(&mut f, v, &id)
            .iter()
            .filter(|a| a.tag == KEY_VALUE_LOCATION)
            .count();
        assert_eq!(count, 2);
        // Metadata operations still work; Destroy needs no key value.
        ok(&f.call(v, 18, vec![uid(&id)]));
        for op in [9, 16, 21, 22] {
            ok(&f.call(v, op, vec![uid(&id)]));
        }
        ok(&f.call(
            v,
            19,
            vec![
                uid(&id),
                Node::structure(
                    REVOCATION_REASON,
                    vec![Node::enumeration(REVOCATION_REASON_CODE, 5)],
                ),
            ],
        ));
        ok(&f.call(v, 20, vec![uid(&id)]));
    }
}
#[test]
fn operations_that_need_the_absent_key_value_fail_with_key_value_not_present() {
    for v in METADATA_ONLY {
        let mut f = Fixture::new();
        let id = id_of(&register_metadata_only(&mut f, v, vec![]));
        ok(&f.call(v, 18, vec![uid(&id)]));
        let other = id_of(&f.call(v, 1, aes(v, vec![])));
        let cases: Vec<(u32, Vec<Node>)> = vec![
            // Get in another format, or wrapped.
            (10, vec![uid(&id), Node::enumeration(KEY_FORMAT_TYPE, 7)]),
            (
                10,
                vec![
                    uid(&other),
                    Node::structure(
                        KEY_WRAPPING_SPECIFICATION,
                        vec![
                            Node::enumeration(WRAPPING_METHOD, 1),
                            Node::structure(ENCRYPTION_KEY_INFORMATION, vec![uid(&id)]),
                        ],
                    ),
                ],
            ),
            // Encrypt / Decrypt.
            (
                31,
                vec![
                    uid(&id),
                    Node::structure(
                        CRYPTOGRAPHIC_PARAMETERS,
                        vec![
                            Node::enumeration(BLOCK_CIPHER_MODE, 1),
                            Node::enumeration(PADDING_METHOD, 3),
                        ],
                    ),
                    Node::bytes(DATA, vec![0; 16]),
                ],
            ),
            (
                32,
                vec![
                    uid(&id),
                    Node::structure(
                        CRYPTOGRAPHIC_PARAMETERS,
                        vec![
                            Node::enumeration(BLOCK_CIPHER_MODE, 1),
                            Node::enumeration(PADDING_METHOD, 3),
                        ],
                    ),
                    Node::bytes(DATA, vec![0; 16]),
                ],
            ),
            // Re-key (1.2 Table 294 lists Key Value Not Present).
            (4, vec![uid(&id)]),
        ];
        for (op, fields) in cases {
            assert_eq!(reason(&f.call(v, op, fields)), 0x13, "{} {op}", label(v));
        }
    }
}
/// An HMAC key without material must never MAC with an empty key.
#[test]
fn a_metadata_only_mac_key_cannot_compute_a_mac() {
    for v in METADATA_ONLY {
        let mut f = Fixture::new();
        let mut fields = vec![
            Node::enumeration(OBJECT_TYPE, 2),
            container(
                v,
                vec![
                    Node::enumeration(CRYPTOGRAPHIC_ALGORITHM, 8),
                    Node::int(CRYPTOGRAPHIC_LENGTH, 256),
                    Node::int(CRYPTOGRAPHIC_USAGE_MASK, 0x180),
                ],
            ),
        ];
        fields.push(metadata_only_block(SYMMETRIC_KEY, Some(8), Some(256)));
        let id = id_of(&f.call(v, 3, fields));
        ok(&f.call(v, 18, vec![uid(&id)]));
        let mac = f.call(
            v,
            35,
            vec![
                uid(&id),
                Node::structure(
                    CRYPTOGRAPHIC_PARAMETERS,
                    vec![Node::enumeration(CRYPTOGRAPHIC_ALGORITHM, 8)],
                ),
                Node::bytes(DATA, b"data".to_vec()),
            ],
        );
        assert_eq!(reason(&mac), 0x13, "{}", label(v));
    }
}
#[test]
fn metadata_only_registration_is_validated() {
    for v in METADATA_ONLY {
        let mut f = Fixture::new();
        // The client SHALL NOT specify Key Value Present.
        let mut fields = aes(v, vec![Node::boolean(KEY_VALUE_PRESENT, false)]);
        fields.push(metadata_only_block(SYMMETRIC_KEY, Some(3), Some(128)));
        assert_eq!(
            reason(&f.call(v, 3, fields)),
            if v.0 >= 2 { 0x22 } else { 12 }
        );
        // Without a Key Value the algorithm and length cannot be derived.
        let fields = vec![
            Node::enumeration(OBJECT_TYPE, 2),
            container(v, vec![Node::int(CRYPTOGRAPHIC_USAGE_MASK, 0xc)]),
            metadata_only_block(SYMMETRIC_KEY, None, None),
        ];
        // Missing Data in 1.x; 2.x tables list no Missing Data, so Invalid
        // Field.
        assert_eq!(reason(&f.call(v, 3, fields)), if v.0 >= 2 { 7 } else { 6 });
        // Key Block and attributes may not disagree.
        let mut fields = aes(v, vec![]);
        fields.push(metadata_only_block(SYMMETRIC_KEY, Some(3), Some(256)));
        assert_eq!(reason(&f.call(v, 3, fields)), 7);
        // Key Value Location only describes an absent Key Value.
        assert_eq!(reason(&f.call(v, 1, aes(v, vec![location("HSM")]))), 7);
        let ordinary = id_of(&f.call(v, 1, aes(v, vec![])));
        let add = if v.0 >= 2 {
            vec![
                uid(&ordinary),
                Node::structure(NEW_ATTRIBUTE, vec![location("HSM")]),
            ]
        } else {
            vec![uid(&ordinary), legacy(location("HSM"))]
        };
        assert_eq!(reason(&f.call(v, 13, add)), 7);
        // Unsupported location types are refused.
        let bad = Node::structure(
            KEY_VALUE_LOCATION,
            vec![
                Node::text(KEY_VALUE_LOCATION_VALUE, "x"),
                Node::enumeration(KEY_VALUE_LOCATION_TYPE, 3),
            ],
        );
        assert_eq!(reason(&register_metadata_only(&mut f, v, vec![bad])), 7);
        // Public Keys: "does not apply to [...] Public Keys" before 2.0.
        let fields = vec![
            Node::enumeration(OBJECT_TYPE, 3),
            container(v, vec![Node::int(CRYPTOGRAPHIC_USAGE_MASK, 2)]),
            Node::structure(
                PUBLIC_KEY,
                vec![Node::structure(
                    KEY_BLOCK,
                    vec![
                        Node::enumeration(KEY_FORMAT_TYPE, 5),
                        Node::enumeration(CRYPTOGRAPHIC_ALGORITHM, 4),
                        Node::int(CRYPTOGRAPHIC_LENGTH, 2048),
                    ],
                )],
            ),
        ];
        let item = f.call(v, 3, fields);
        if v.0 >= 2 {
            let id = id_of(&item);
            assert!(has(
                &attributes(&mut f, v, &id),
                Node::boolean(KEY_VALUE_PRESENT, false)
            ));
        } else {
            assert_eq!(reason(&item), 7);
        }
    }
}
#[test]
fn a_key_value_stays_required_before_1_2() {
    for v in [Version(1, 0), Version(1, 1)] {
        let mut f = Fixture::new();
        let item = register_metadata_only(&mut f, v, vec![]);
        assert_eq!(
            item.required(RESULT_STATUS).unwrap().number().unwrap(),
            1,
            "{}",
            label(v)
        );
        assert_eq!(
            reason(&register_metadata_only(&mut f, v, vec![location("x")])),
            8
        );
    }
}

// ---------- KMIP 1.0 Activation Date at creation ----------

fn activation(f: &mut Fixture, v: Version, id: &str) -> i64 {
    match find(&attributes(f, v, id), ACTIVATION_DATE).unwrap().value {
        Value::DateTime(t) => t,
        _ => panic!("Activation Date"),
    }
}
fn state(f: &mut Fixture, v: Version, id: &str) -> u32 {
    find(&attributes(f, v, id), STATE)
        .unwrap()
        .number()
        .unwrap()
}

// REQ:e9f2d165b452ab7f 1.0: a past Activation Date becomes the time the
// request was received and the object is Active
#[test]
fn a_past_activation_date_becomes_the_receipt_time_in_1_0_only() {
    let past = now() - 86_400;
    let future = now() + 86_400;
    let v = Version(1, 0);
    let mut f = Fixture::new();
    let before = now();
    let id = id_of(&f.call(v, 1, aes(v, vec![Node::date(ACTIVATION_DATE, past)])));
    let after = now();
    let date = activation(&mut f, v, &id);
    assert!((before..=after).contains(&date), "{date} {before} {after}");
    assert_eq!(state(&mut f, v, &id), 2);
    // Register follows the same rule.
    let mut fields = aes(v, vec![Node::date(ACTIVATION_DATE, past)]);
    fields.push(Node::structure(
        SYMMETRIC_KEY,
        vec![Node::structure(
            KEY_BLOCK,
            vec![
                Node::enumeration(KEY_FORMAT_TYPE, 1),
                Node::structure(KEY_VALUE, vec![Node::bytes(KEY_MATERIAL, vec![7; 16])]),
                Node::enumeration(CRYPTOGRAPHIC_ALGORITHM, 3),
                Node::int(CRYPTOGRAPHIC_LENGTH, 128),
            ],
        )],
    ));
    let id = id_of(&f.call(v, 3, fields));
    assert!(activation(&mut f, v, &id) >= before);
    // A future date is kept, and the object stays Pre-Active.
    let id = id_of(&f.call(v, 1, aes(v, vec![Node::date(ACTIVATION_DATE, future)])));
    assert_eq!(activation(&mut f, v, &id), future);
    assert_eq!(state(&mut f, v, &id), 1);
    // 1.1 and later keep "the value specified in the request".
    for v in [Version(1, 1), Version(1, 4), Version(2, 1)] {
        let id = id_of(&f.call(v, 1, aes(v, vec![Node::date(ACTIVATION_DATE, past)])));
        assert_eq!(activation(&mut f, v, &id), past, "{}", label(v));
        assert_eq!(state(&mut f, v, &id), 2);
    }
}

// ---------- X.509 Key Usage to Cryptographic Usage Mask ----------

fn certificate(usage: Option<KeyUsage>) -> X509 {
    let key = PKey::from_ec_key(
        EcKey::generate(&EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap()).unwrap(),
    )
    .unwrap();
    let mut name = X509NameBuilder::new().unwrap();
    name.append_entry_by_text("CN", "key usage").unwrap();
    let name = name.build();
    let mut b = X509::builder().unwrap();
    b.set_version(2).unwrap();
    b.set_serial_number(&BigNum::from_u32(5).unwrap().to_asn1_integer().unwrap())
        .unwrap();
    b.set_subject_name(&name).unwrap();
    b.set_issuer_name(&name).unwrap();
    b.set_pubkey(&key).unwrap();
    b.set_not_before(&Asn1Time::from_unix(now() - 10).unwrap())
        .unwrap();
    b.set_not_after(&Asn1Time::from_unix(now() + 1000).unwrap())
        .unwrap();
    if let Some(usage) = usage {
        b.append_extension(usage.build().unwrap()).unwrap();
    }
    b.sign(&key, MessageDigest::sha256()).unwrap();
    b.build()
}
fn register_certificate(f: &mut Fixture, v: Version, c: &X509, mask: Option<i32>) -> Node {
    let mut attrs = vec![
        Node::enumeration(CRYPTOGRAPHIC_ALGORITHM, 6),
        Node::int(CRYPTOGRAPHIC_LENGTH, 256),
    ];
    if v >= Version(1, 1) {
        attrs.push(Node::int(
            CERTIFICATE_LENGTH,
            c.to_der().unwrap().len() as i32,
        ));
    }
    if let Some(m) = mask {
        attrs.push(Node::int(CRYPTOGRAPHIC_USAGE_MASK, m));
    }
    f.call(
        v,
        3,
        vec![
            Node::enumeration(OBJECT_TYPE, 1),
            container(v, attrs),
            Node::structure(
                CERTIFICATE,
                vec![
                    Node::enumeration(CERTIFICATE_TYPE, 1),
                    Node::bytes(CERTIFICATE_VALUE, c.to_der().unwrap()),
                ],
            ),
        ],
    )
}
fn mask(f: &mut Fixture, v: Version, id: &str) -> u32 {
    find(&attributes(f, v, id), CRYPTOGRAPHIC_USAGE_MASK)
        .unwrap()
        .number()
        .unwrap()
}

// REQ:9447ff61353ae1ef 1.x: X.509 Key Usage maps to Cryptographic Usage Mask
// values (digitalSignature: Sign or Verify, keyEncipherment: Wrap or Unwrap
// Key, keyAgreement: Key Agreement, decipherOnly: Decrypt, ...)
#[test]
fn certificate_key_usage_maps_to_the_usage_mask_in_1_x() {
    let mut signing = KeyUsage::new();
    signing.digital_signature().key_encipherment();
    let signing = certificate(Some(signing));
    let mut agreement = KeyUsage::new();
    agreement
        .key_agreement()
        .decipher_only()
        .non_repudiation()
        .key_cert_sign()
        .crl_sign();
    let agreement = certificate(Some(agreement));
    let mut data = KeyUsage::new();
    data.data_encipherment().encipher_only();
    let data = certificate(Some(data));
    let none = certificate(None);
    for v in LEGACY {
        let mut f = Fixture::new();
        // An omitted mask is derived from the extension.
        for (c, expected) in [
            (&signing, 0x1 | 0x2 | 0x10 | 0x20),
            (&agreement, 0x800 | 0x8 | 0x400 | 0x1000 | 0x2000),
            (&data, 0x4 | 0x8),
            (&none, 0),
        ] {
            let id = id_of(&register_certificate(&mut f, v, c, None));
            assert_eq!(mask(&mut f, v, &id), expected, "{}", label(v));
        }
        // A supplied mask may not claim a mapped usage the extension lacks.
        for bad in [0x4, 0x8, 0x400, 0x800, 0x1000] {
            assert_eq!(
                reason(&register_certificate(&mut f, v, &signing, Some(bad))),
                7,
                "{} {bad:#x}",
                label(v)
            );
        }
        // A subset is accepted unchanged, and usages outside the mapping
        // (Export, MAC, Derive Key) are not governed by Key Usage.
        for good in [0x2, 0x22, 0x2 | 0x40 | 0x200] {
            let id = id_of(&register_certificate(&mut f, v, &signing, Some(good)));
            assert_eq!(mask(&mut f, v, &id), good as u32);
        }
        let id = id_of(&register_certificate(&mut f, v, &none, Some(0xc)));
        assert_eq!(mask(&mut f, v, &id), 0xc);
    }
    // 2.x has no such mapping: an omitted mask stays 0 (no use).
    for v in [Version(2, 0), Version(2, 1)] {
        let mut f = Fixture::new();
        let id = id_of(&register_certificate(&mut f, v, &signing, None));
        assert_eq!(mask(&mut f, v, &id), 0);
    }
}
