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

//! Versioned attribute projection and server defects found by the Profiles
//! 4.1 variation replay (docs/attributes.md).
use keytend_kmip_server::{
    protocol::{Engine, Version},
    store::Store,
    tags::*,
    ttlv::{Node, Value},
};

struct Fixture {
    _dir: tempfile::TempDir,
    engine: Engine,
}
impl Fixture {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let key = dir.path().join("master");
        std::fs::write(&key, [42; 32]).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        let store = Store::open(&dir.path().join("keys.sqlite"), &key).unwrap();
        Self {
            _dir: dir,
            engine: Engine::new(store, true),
        }
    }
    fn call(&mut self, v: Version, op: u32, fields: Vec<Node>) -> Node {
        let mut header = vec![v.node()];
        if v.0 < 3 {
            header.push(Node::int(BATCH_COUNT, 1));
        }
        let request = Node::structure(
            REQUEST_MESSAGE,
            vec![
                Node::structure(REQUEST_HEADER, header),
                Node::structure(
                    BATCH_ITEM,
                    vec![
                        Node::enumeration(OPERATION, op),
                        Node::structure(REQUEST_PAYLOAD, fields),
                    ],
                ),
            ],
        );
        self.engine.process("alice", &request).unwrap()
    }
    fn ok(&mut self, v: Version, op: u32, fields: Vec<Node>) -> Node {
        let response = self.call(v, op, fields);
        payload(&response).clone()
    }
    fn create_aes(&mut self, v: Version, extra: Vec<Node>) -> String {
        let mut attrs = vec![
            Node::enumeration(CRYPTOGRAPHIC_ALGORITHM, 3),
            Node::int(CRYPTOGRAPHIC_LENGTH, 256),
            Node::int(CRYPTOGRAPHIC_USAGE_MASK, 12),
        ];
        attrs.extend(extra);
        let p = self.ok(
            v,
            1,
            vec![Node::enumeration(OBJECT_TYPE, 2), container(v, attrs)],
        );
        id_of(&p)
    }
    fn register_secret(&mut self, v: Version) -> String {
        let p = self.ok(
            v,
            3,
            vec![
                Node::enumeration(OBJECT_TYPE, 7),
                container(v, vec![Node::int(CRYPTOGRAPHIC_USAGE_MASK, 0x200)]),
                Node::structure(
                    SECRET_DATA,
                    vec![
                        Node::enumeration(SECRET_DATA_TYPE, 1),
                        Node::structure(
                            KEY_BLOCK,
                            vec![
                                Node::enumeration(KEY_FORMAT_TYPE, if v.0 >= 2 { 1 } else { 2 }),
                                Node::structure(
                                    KEY_VALUE,
                                    vec![Node::bytes(KEY_MATERIAL, b"password".to_vec())],
                                ),
                            ],
                        ),
                    ],
                ),
            ],
        );
        id_of(&p)
    }
    /// Attributes returned by Get Attributes with no names, decoded to tags.
    fn attributes(&mut self, v: Version, id: &str) -> Vec<Node> {
        let p = self.ok(v, 11, vec![uid(v, id)]);
        if v.0 >= 2 {
            p.required(ATTRIBUTES).unwrap().children().unwrap().to_vec()
        } else {
            p.all(ATTRIBUTE)
                .map(|a| {
                    let name = a.required(ATTRIBUTE_NAME).unwrap().string().unwrap();
                    let mut value = a.required(ATTRIBUTE_VALUE).unwrap().clone();
                    value.tag = legacy_tag(name);
                    value
                })
                .collect()
        }
    }
}
fn payload(n: &Node) -> &Node {
    let item = n.get(BATCH_ITEM).unwrap();
    assert_eq!(
        item.required(RESULT_STATUS).unwrap().number().unwrap(),
        0,
        "reason {:?} {:?}",
        item.get(RESULT_REASON).and_then(|n| n.number().ok()),
        item.get(RESULT_MESSAGE).and_then(|n| n.string().ok())
    );
    item.required(RESPONSE_PAYLOAD).unwrap()
}
fn reason(n: &Node) -> u32 {
    n.required(BATCH_ITEM)
        .unwrap()
        .required(RESULT_REASON)
        .unwrap()
        .number()
        .unwrap()
}
fn id_of(p: &Node) -> String {
    p.required(UNIQUE_IDENTIFIER)
        .unwrap()
        .identifier_text()
        .unwrap()
        .to_owned()
}
fn uid(v: Version, id: &str) -> Node {
    if v.0 >= 3 {
        Node::identifier(UNIQUE_IDENTIFIER, id)
    } else {
        Node::text(UNIQUE_IDENTIFIER, id)
    }
}
fn legacy_name(tag: u32) -> &'static str {
    match tag {
        CRYPTOGRAPHIC_ALGORITHM => "Cryptographic Algorithm",
        CRYPTOGRAPHIC_LENGTH => "Cryptographic Length",
        CRYPTOGRAPHIC_USAGE_MASK => "Cryptographic Usage Mask",
        t => tag_name(t).unwrap(),
    }
}
fn legacy_tag(name: &str) -> u32 {
    match name {
        "Cryptographic Algorithm" => CRYPTOGRAPHIC_ALGORITHM,
        "Cryptographic Length" => CRYPTOGRAPHIC_LENGTH,
        "Cryptographic Usage Mask" => CRYPTOGRAPHIC_USAGE_MASK,
        name => (0x420001..0x420200)
            .find(|t| tag_name(*t) == Some(name))
            .unwrap_or(0),
    }
}
fn legacy(mut a: Node) -> Node {
    let name = legacy_name(a.tag);
    a.tag = ATTRIBUTE_VALUE;
    Node::structure(ATTRIBUTE, vec![Node::text(ATTRIBUTE_NAME, name), a])
}
fn container(v: Version, attrs: Vec<Node>) -> Node {
    if v.0 >= 2 {
        Node::structure(ATTRIBUTES, attrs)
    } else {
        Node::structure(TEMPLATE_ATTRIBUTE, attrs.into_iter().map(legacy).collect())
    }
}
fn locate_ids(f: &mut Fixture, v: Version, filters: Vec<Node>) -> Vec<String> {
    let fields = if v.0 >= 2 {
        vec![Node::structure(ATTRIBUTES, filters)]
    } else {
        filters.into_iter().map(legacy).collect()
    };
    f.ok(v, 8, fields)
        .all(UNIQUE_IDENTIFIER)
        .map(|n| n.identifier_text().unwrap().to_owned())
        .collect()
}
fn has(attrs: &[Node], tag: u32) -> bool {
    attrs.iter().any(|a| a.tag == tag)
}
const FINAL: [Version; 7] = [
    Version(1, 0),
    Version(1, 1),
    Version(1, 2),
    Version(1, 3),
    Version(1, 4),
    Version(2, 0),
    Version(2, 1),
];

#[test]
fn secret_data_key_block_omits_cryptographic_algorithm_and_length() {
    for v in FINAL {
        let mut f = Fixture::new();
        let id = f.register_secret(v);
        let p = f.ok(v, 10, vec![uid(v, &id)]);
        let block = p
            .required(SECRET_DATA)
            .unwrap()
            .required(KEY_BLOCK)
            .unwrap();
        assert!(block.get(CRYPTOGRAPHIC_LENGTH).is_none());
        assert!(block.get(CRYPTOGRAPHIC_ALGORITHM).is_none());
        assert!(matches!(
            &block.required(KEY_VALUE).unwrap().required(KEY_MATERIAL).unwrap().value,
            Value::ByteString(b) if b == b"password"
        ));
        // Symmetric keys keep both fields in the Key Block.
        let key = f.create_aes(v, vec![]);
        let p = f.ok(v, 10, vec![uid(v, &key)]);
        let block = p
            .required(SYMMETRIC_KEY)
            .unwrap()
            .required(KEY_BLOCK)
            .unwrap();
        assert_eq!(
            block
                .required(CRYPTOGRAPHIC_LENGTH)
                .unwrap()
                .number()
                .unwrap(),
            256
        );
        assert_eq!(
            block
                .required(CRYPTOGRAPHIC_ALGORITHM)
                .unwrap()
                .number()
                .unwrap(),
            3
        );
    }
}

#[test]
fn legacy_online_locate_omits_destroyed_objects_unless_selected() {
    for v in FINAL {
        let mut f = Fixture::new();
        let live = f.create_aes(v, vec![]);
        let dead = f.create_aes(v, vec![]);
        f.ok(v, 20, vec![uid(v, &dead)]);
        // SKFF-M-5: Locate by Unique Identifier after Destroy finds nothing.
        let by_id = Node::text(UNIQUE_IDENTIFIER, &dead);
        assert!(locate_ids(&mut f, v, vec![by_id.clone()]).is_empty());
        assert_eq!(locate_ids(&mut f, v, vec![]), [live]);
        if v.0 == 1 {
            // Explicit destroyed-state selection reaches retained metadata.
            assert_eq!(
                locate_ids(&mut f, v, vec![by_id, Node::enumeration(STATE, 5)]),
                [dead]
            );
        }
    }
}

// REQ:6bb58e268b302eae after leaving Pre-Active, Activation Date can be neither changed nor deleted
#[test]
fn activation_date_change_after_pre_active_uses_the_edition_reason() {
    for v in [
        Version(1, 0),
        Version(1, 1),
        Version(1, 2),
        Version(1, 3),
        Version(1, 4),
        Version(2, 0),
        Version(2, 1),
        Version(3, 0),
    ] {
        let mut f = Fixture::new();
        let id = f.create_aes(v, vec![]);
        f.ok(v, 18, vec![uid(v, &id)]);
        let activation = |f: &mut Fixture| {
            f.attributes(v, &id)
                .into_iter()
                .find(|a| a.tag == ACTIVATION_DATE)
                .unwrap()
        };
        let set = activation(&mut f);
        let date = Node::date(ACTIVATION_DATE, 4_000_000_000);
        let fields = if v.0 >= 2 {
            vec![uid(v, &id), Node::structure(NEW_ATTRIBUTE, vec![date])]
        } else {
            vec![uid(v, &id), legacy(date)]
        };
        let expected = if v >= Version(2, 1) { 0x43 } else { 12 };
        assert_eq!(reason(&f.call(v, 14, fields.clone())), expected);
        // Deletion is governed by "Deletable by client: No", not by state.
        let field = if v.0 >= 2 {
            Node::enumeration(ATTRIBUTE_REFERENCE, ACTIVATION_DATE)
        } else {
            Node::text(ATTRIBUTE_NAME, "Activation Date")
        };
        assert_eq!(
            reason(&f.call(v, 15, vec![uid(v, &id), field.clone()])),
            if v.0 >= 2 { 0x22 } else { 12 }
        );
        assert!(activation(&mut f) == set);
        // Still fixed once the object is Deactivated (Revoke, Cessation of Operation).
        let revocation = Node::structure(
            REVOCATION_REASON,
            vec![Node::enumeration(REVOCATION_REASON_CODE, 5)],
        );
        f.ok(v, 19, vec![uid(v, &id), revocation]);
        assert_eq!(reason(&f.call(v, 14, fields)), expected);
        assert_ne!(reason(&f.call(v, 15, vec![uid(v, &id), field])), 0);
        assert!(activation(&mut f) == set);
    }
}

// REQ:66ec0ead40e7863c 2.x the server assigns Short Unique Identifier on Create and Register and never changes or deletes it
// REQ:5911347d1a81c2a8 2.x Short Unique Identifier is the 32-byte SHA-256 of the Unique Identifier
#[test]
fn short_unique_identifier_is_projected_and_locatable_from_2_0() {
    for v in [Version(1, 4), Version(2, 0), Version(2, 1), Version(3, 0)] {
        let mut f = Fixture::new();
        let id = f.create_aes(v, vec![]);
        let attrs = f.attributes(v, &id);
        let short = attrs.iter().find(|a| a.tag == SHORT_UNIQUE_IDENTIFIER);
        if v.0 == 1 {
            assert!(short.is_none());
            continue;
        }
        let short = short.unwrap().clone();
        assert_eq!(
            short.byte_string().unwrap(),
            openssl::sha::sha256(id.as_bytes()).as_slice()
        );
        assert_eq!(
            locate_ids(&mut f, v, vec![short.clone()]),
            std::slice::from_ref(&id)
        );
        let wrong = Node::bytes(SHORT_UNIQUE_IDENTIFIER, vec![0; 31]);
        let fields = vec![Node::structure(ATTRIBUTES, vec![wrong])];
        assert_eq!(reason(&f.call(v, 8, fields)), 7);

        // Server-assigned on registration too, and never changed or deleted.
        let registered = Node::structure(
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
        );
        let r = f.ok(
            v,
            3,
            vec![
                Node::enumeration(OBJECT_TYPE, 2),
                Node::structure(ATTRIBUTES, vec![Node::int(CRYPTOGRAPHIC_USAGE_MASK, 12)]),
                registered,
            ],
        );
        let reg = id_of(&r);
        let reg_short = f.attributes(v, &reg);
        let reg_short = reg_short
            .iter()
            .find(|a| a.tag == SHORT_UNIQUE_IDENTIFIER)
            .unwrap();
        assert_eq!(
            reg_short.byte_string().unwrap(),
            openssl::sha::sha256(reg.as_bytes()).as_slice()
        );
        let other = Node::bytes(SHORT_UNIQUE_IDENTIFIER, vec![1; 32]);
        for op in [13, 14] {
            let change = vec![
                uid(v, &id),
                Node::structure(NEW_ATTRIBUTE, vec![other.clone()]),
            ];
            assert_ne!(reason(&f.call(v, op, change)), 0);
        }
        let reference = Node::enumeration(ATTRIBUTE_REFERENCE, SHORT_UNIQUE_IDENTIFIER);
        assert_ne!(reason(&f.call(v, 15, vec![uid(v, &id), reference])), 0);
        f.ok(v, 18, vec![uid(v, &id)]);
        let attrs = f.attributes(v, &id);
        assert!(
            attrs
                .iter()
                .filter(|a| a.tag == SHORT_UNIQUE_IDENTIFIER)
                .eq([&short])
        );
    }
}

fn lease_of(attrs: &[Node]) -> u32 {
    match attrs.iter().find(|a| a.tag == LEASE_TIME).unwrap().value {
        Value::Interval(seconds) => seconds,
        _ => panic!("Lease Time must be an Interval"),
    }
}

// REQ:c4e08698bf7dd571 Lease Time holds the server's maximum lease; Obtain Lease grants no more than it
#[test]
fn lease_time_is_the_configured_server_maximum_for_new_objects() {
    for v in [
        Version(1, 0),
        Version(1, 1),
        Version(1, 2),
        Version(1, 3),
        Version(1, 4),
        Version(2, 0),
        Version(2, 1),
    ] {
        let mut f = Fixture::new();
        let id = f.create_aes(v, vec![]);
        assert_eq!(lease_of(&f.attributes(v, &id)), 3600);
        f.ok(v, 18, vec![uid(v, &id)]);
        let lease = f.ok(v, 16, vec![uid(v, &id)]);
        assert!(matches!(
            lease.required(LEASE_TIME).unwrap().value,
            Value::Interval(3600)
        ));

        // A changed policy applies to later objects; stored maxima are kept.
        let previous = std::mem::replace(
            &mut f.engine,
            Engine::new(
                Store::open(
                    &f._dir.path().join("keys.sqlite"),
                    &f._dir.path().join("master"),
                )
                .unwrap(),
                true,
            )
            .with_maximum_lease(120),
        );
        drop(previous);
        assert_eq!(lease_of(&f.attributes(v, &id)), 3600);
        let short = f.create_aes(v, vec![]);
        assert_eq!(lease_of(&f.attributes(v, &short)), 120);
        f.ok(v, 18, vec![uid(v, &short)]);
        let lease = f.ok(v, 16, vec![uid(v, &short)]);
        assert!(matches!(
            lease.required(LEASE_TIME).unwrap().value,
            Value::Interval(120)
        ));
        // Check refuses a lease longer than the stored maximum.
        let check = f.call(v, 9, vec![uid(v, &short), Node::interval(LEASE_TIME, 121)]);
        assert_eq!(reason(&check), 12);
    }
}

#[test]
fn description_is_a_client_text_attribute_from_1_4() {
    for v in [
        Version(1, 3),
        Version(1, 4),
        Version(2, 0),
        Version(2, 1),
        Version(3, 0),
    ] {
        let mut f = Fixture::new();
        let id = f.create_aes(v, vec![]);
        let text = Node::text(DESCRIPTION, "backup key");
        let add = if v.0 >= 2 {
            vec![
                uid(v, &id),
                Node::structure(NEW_ATTRIBUTE, vec![text.clone()]),
            ]
        } else {
            vec![uid(v, &id), legacy(text.clone())]
        };
        if v < Version(1, 4) {
            assert_ne!(
                f.call(v, 13, add)
                    .required(BATCH_ITEM)
                    .unwrap()
                    .required(RESULT_STATUS)
                    .unwrap()
                    .number()
                    .unwrap(),
                0
            );
            assert!(!has(&f.attributes(v, &id), DESCRIPTION));
            continue;
        }
        f.ok(v, 13, add);
        let attrs = f.attributes(v, &id);
        let stored = attrs.iter().find(|a| a.tag == DESCRIPTION).unwrap();
        assert_eq!(stored.string().unwrap(), "backup key");
        // Single instance; a wrong type is refused.
        let again = if v.0 >= 2 {
            vec![
                uid(v, &id),
                Node::structure(NEW_ATTRIBUTE, vec![text.clone()]),
            ]
        } else {
            vec![uid(v, &id), legacy(text)]
        };
        assert_ne!(reason(&f.call(v, 13, again)), 0);
        let modified = Node::text(DESCRIPTION, "rotated");
        let fields = if v.0 >= 2 {
            vec![uid(v, &id), Node::structure(NEW_ATTRIBUTE, vec![modified])]
        } else {
            vec![uid(v, &id), legacy(modified)]
        };
        f.ok(v, 14, fields);
        let field = if v.0 >= 2 {
            Node::enumeration(ATTRIBUTE_REFERENCE, DESCRIPTION)
        } else {
            Node::text(ATTRIBUTE_NAME, "Description")
        };
        f.ok(v, 15, vec![uid(v, &id), field]);
        assert!(!has(&f.attributes(v, &id), DESCRIPTION));
        let wrong = if v.0 >= 2 {
            vec![
                uid(v, &id),
                Node::structure(NEW_ATTRIBUTE, vec![Node::int(DESCRIPTION, 1)]),
            ]
        } else {
            vec![uid(v, &id), legacy(Node::int(DESCRIPTION, 1))]
        };
        assert_ne!(reason(&f.call(v, 13, wrong)), 0);
    }
}

fn create_rsa_pair(f: &mut Fixture, v: Version, private_format: Option<u32>) -> (String, String) {
    let common = vec![
        Node::enumeration(CRYPTOGRAPHIC_ALGORITHM, 4),
        Node::int(CRYPTOGRAPHIC_LENGTH, 2048),
    ];
    let mut private = vec![Node::int(CRYPTOGRAPHIC_USAGE_MASK, 1)];
    private.extend(private_format.map(|f| Node::enumeration(KEY_FORMAT_TYPE, f)));
    let public = vec![Node::int(CRYPTOGRAPHIC_USAGE_MASK, 2)];
    let fields = if v.0 >= 2 {
        vec![
            Node::structure(COMMON_ATTRIBUTES, common),
            Node::structure(PRIVATE_KEY_ATTRIBUTES, private),
            Node::structure(PUBLIC_KEY_ATTRIBUTES, public),
        ]
    } else {
        let wrap =
            |tag, attrs: Vec<Node>| Node::structure(tag, attrs.into_iter().map(legacy).collect());
        vec![
            wrap(COMMON_TEMPLATE_ATTRIBUTE, common),
            wrap(PRIVATE_KEY_TEMPLATE_ATTRIBUTE, private),
            wrap(PUBLIC_KEY_TEMPLATE_ATTRIBUTE, public),
        ]
    };
    let p = f.ok(v, 2, fields);
    let id = |tag| {
        p.required(tag)
            .unwrap()
            .identifier_text()
            .unwrap()
            .to_owned()
    };
    (
        id(PRIVATE_KEY_UNIQUE_IDENTIFIER),
        id(PUBLIC_KEY_UNIQUE_IDENTIFIER),
    )
}
fn key_block(f: &mut Fixture, v: Version, id: &str, format: Option<u32>) -> (u32, Vec<u8>) {
    let mut fields = vec![uid(v, id)];
    fields.extend(format.map(|f| Node::enumeration(KEY_FORMAT_TYPE, f)));
    let p = f.ok(v, 10, fields);
    let object = p.get(PRIVATE_KEY).or_else(|| p.get(PUBLIC_KEY)).unwrap();
    let block = object.required(KEY_BLOCK).unwrap();
    (
        block.required(KEY_FORMAT_TYPE).unwrap().number().unwrap(),
        block
            .required(KEY_VALUE)
            .unwrap()
            .required(KEY_MATERIAL)
            .unwrap()
            .byte_string()
            .unwrap()
            .to_vec(),
    )
}
fn digest_formats(attrs: &[Node]) -> Vec<(u32, Vec<u8>)> {
    attrs
        .iter()
        .filter(|a| a.tag == DIGEST)
        .map(|d| {
            (
                d.get(KEY_FORMAT_TYPE).map_or(0, |n| n.number().unwrap()),
                d.required(DIGEST_VALUE)
                    .unwrap()
                    .byte_string()
                    .unwrap()
                    .to_vec(),
            )
        })
        .collect()
}

#[test]
fn generated_rsa_keys_use_the_edition_default_key_format() {
    for v in [
        Version(1, 3),
        Version(1, 4),
        Version(2, 0),
        Version(2, 1),
        Version(3, 0),
    ] {
        let mut f = Fixture::new();
        let (private, public) = create_rsa_pair(&mut f, v, None);
        // KMIP 2.0+ Table 81: RSA Private Key PKCS#1, RSA Public Key PKCS#1.
        // 1.x has no default table; generated keys stay PKCS#8 and SPKI.
        let (private_default, public_default) = if v.0 >= 2 { (3, 3) } else { (4, 5) };
        for (id, default) in [(&private, private_default), (&public, public_default)] {
            let (format, material) = key_block(&mut f, v, id, None);
            assert_eq!(format, default);
            let attrs = f.attributes(v, id);
            if v.0 >= 2 {
                let kft = attrs.iter().find(|a| a.tag == KEY_FORMAT_TYPE).unwrap();
                assert_eq!(kft.number().unwrap(), default);
            }
            // The mandatory SHA-256 digest is over the PKCS#1 encoding.
            let pkcs1 = key_block(&mut f, v, id, Some(3)).1;
            let digests = digest_formats(&attrs);
            assert!(digests.contains(&(3, openssl::sha::sha256(&pkcs1).to_vec())));
            if v.0 >= 2 {
                assert_eq!(digests.len(), 1);
                assert_eq!(material, pkcs1);
            }
        }
        let (_, der) = key_block(&mut f, v, &private, None);
        if v.0 >= 2 {
            openssl::rsa::Rsa::private_key_from_der(&der).unwrap();
            assert!(openssl::pkey::PKey::private_key_from_pkcs8(&der).is_err());
        } else {
            openssl::pkey::PKey::private_key_from_pkcs8(&der).unwrap();
        }
        // Conversions remain available in both directions.
        let (format, pkcs8) = key_block(&mut f, v, &private, Some(4));
        assert_eq!(format, 4);
        openssl::pkey::PKey::private_key_from_pkcs8(&pkcs8).unwrap();
        let (format, spki) = key_block(&mut f, v, &public, Some(5));
        assert_eq!(format, 5);
        openssl::pkey::PKey::public_key_from_der(&spki).unwrap();
        // Unsupported RSA formats are refused.
        let fields = vec![uid(v, &private), Node::enumeration(KEY_FORMAT_TYPE, 1)];
        assert_eq!(reason(&f.call(v, 10, fields)), 0x10);
    }
}

#[test]
fn requested_rsa_format_is_kept_with_an_additional_default_digest() {
    for v in [Version(2, 0), Version(2, 1)] {
        let mut f = Fixture::new();
        let (private, _) = create_rsa_pair(&mut f, v, Some(4));
        let (format, pkcs8) = key_block(&mut f, v, &private, None);
        assert_eq!(format, 4);
        let pkcs1 = key_block(&mut f, v, &private, Some(3)).1;
        let mut digests = digest_formats(&f.attributes(v, &private));
        digests.sort();
        assert_eq!(
            digests,
            [
                (3, openssl::sha::sha256(&pkcs1).to_vec()),
                (4, openssl::sha::sha256(&pkcs8).to_vec())
            ]
        );
    }
}

#[test]
fn rsa_keys_keep_their_stored_format_across_editions() {
    let mut f = Fixture::new();
    // A 1.4 key keeps PKCS#8 when read through 2.1; a 2.1 key keeps PKCS#1 in 1.4.
    let (legacy_private, _) = create_rsa_pair(&mut f, Version(1, 4), None);
    let (modern_private, _) = create_rsa_pair(&mut f, Version(2, 1), None);
    assert_eq!(key_block(&mut f, Version(2, 1), &legacy_private, None).0, 4);
    let attrs = f.attributes(Version(2, 1), &legacy_private);
    let kft = attrs.iter().find(|a| a.tag == KEY_FORMAT_TYPE).unwrap();
    assert_eq!(kft.number().unwrap(), 4);
    assert_eq!(key_block(&mut f, Version(1, 4), &modern_private, None).0, 3);
}
