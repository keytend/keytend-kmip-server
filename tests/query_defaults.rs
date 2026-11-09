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

//! Query Defaults Information (2.0 section 6.1.37, 2.1 section 6.1.40): each
//! reported default is what a factory operation really applies when the
//! attribute is omitted (docs/messages.md#query). Asserting tests cite their
//! clause digests as `REQ:<digest>` (docs/specs/requirement-matrix.json); the
//! paraphrases are our own words.
use keytend_kmip_server::{
    protocol::{Engine, Version},
    store::Store,
    tags::*,
    ttlv::{Node, Value},
};
use tempfile::TempDir;

struct Fixture {
    _dir: TempDir,
    engine: Engine,
}
impl Fixture {
    fn new(lease: u32) -> Self {
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
            engine: Engine::new(store, false).with_maximum_lease(lease),
        }
    }
    fn call(&mut self, v: Version, op: u32, fields: Vec<Node>) -> Node {
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
        let response = self.engine.process("alice", &request).unwrap();
        response.required(BATCH_ITEM).unwrap().clone()
    }
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
fn text(n: &Node, tag: u32) -> Node {
    let mut id = n.required(tag).unwrap().clone();
    id.tag = UNIQUE_IDENTIFIER;
    id
}
fn attributes(f: &mut Fixture, v: Version, id: Node) -> Vec<Node> {
    let item = f.call(v, 11, vec![id]);
    ok(&item)
        .required(ATTRIBUTES)
        .unwrap()
        .children()
        .unwrap()
        .to_vec()
}
fn certificate() -> Node {
    let key = openssl::pkey::PKey::from_ec_key(
        openssl::ec::EcKey::generate(
            &openssl::ec::EcGroup::from_curve_name(openssl::nid::Nid::X9_62_PRIME256V1).unwrap(),
        )
        .unwrap(),
    )
    .unwrap();
    let mut name = openssl::x509::X509Name::builder().unwrap();
    name.append_entry_by_text("CN", "defaults").unwrap();
    let name = name.build();
    let mut cert = openssl::x509::X509::builder().unwrap();
    cert.set_version(2).unwrap();
    cert.set_serial_number(
        &openssl::bn::BigNum::from_u32(1)
            .unwrap()
            .to_asn1_integer()
            .unwrap(),
    )
    .unwrap();
    cert.set_subject_name(&name).unwrap();
    cert.set_issuer_name(&name).unwrap();
    cert.set_pubkey(&key).unwrap();
    cert.set_not_before(&openssl::asn1::Asn1Time::days_from_now(0).unwrap())
        .unwrap();
    cert.set_not_after(&openssl::asn1::Asn1Time::days_from_now(1).unwrap())
        .unwrap();
    cert.sign(&key, openssl::hash::MessageDigest::sha256())
        .unwrap();
    Node::structure(
        CERTIFICATE,
        vec![
            Node::enumeration(CERTIFICATE_TYPE, 1),
            Node::bytes(CERTIFICATE_VALUE, cert.build().to_der().unwrap()),
        ],
    )
}

/// One new object of `kind` from the simplest factory operation, with no
/// attributes in the request; returns its attributes.
fn created(f: &mut Fixture, v: Version, kind: u32) -> Vec<Node> {
    let empty = || Node::structure(ATTRIBUTES, vec![]);
    let id = match kind {
        2 => text(
            ok(&f.call(v, 1, vec![Node::enumeration(OBJECT_TYPE, 2), empty()])),
            UNIQUE_IDENTIFIER,
        ),
        3 | 4 => {
            let item = f.call(v, 2, vec![]);
            text(
                ok(&item),
                if kind == 4 {
                    PRIVATE_KEY_UNIQUE_IDENTIFIER
                } else {
                    PUBLIC_KEY_UNIQUE_IDENTIFIER
                },
            )
        }
        _ => {
            let object = match kind {
                1 => certificate(),
                7 => Node::structure(
                    SECRET_DATA,
                    vec![
                        Node::enumeration(SECRET_DATA_TYPE, 1),
                        Node::structure(
                            KEY_BLOCK,
                            vec![
                                Node::enumeration(KEY_FORMAT_TYPE, 2),
                                Node::structure(
                                    KEY_VALUE,
                                    vec![Node::bytes(KEY_MATERIAL, b"secret".to_vec())],
                                ),
                            ],
                        ),
                    ],
                ),
                8 => Node::structure(
                    OPAQUE_OBJECT,
                    vec![
                        Node::enumeration(OPAQUE_DATA_TYPE, 0x8000_0001),
                        Node::bytes(OPAQUE_DATA_VALUE, b"opaque".to_vec()),
                    ],
                ),
                _ => unreachable!(),
            };
            text(
                ok(&f.call(
                    v,
                    3,
                    vec![Node::enumeration(OBJECT_TYPE, kind), empty(), object],
                )),
                UNIQUE_IDENTIFIER,
            )
        }
    };
    attributes(f, v, id)
}

/// Each default Query reports for `v` is applied to a new object of its
/// type created without the attribute.
fn reported_defaults_apply(f: &mut Fixture, v: Version, lease: u32) {
    let item = f.call(v, 24, vec![Node::enumeration(QUERY_FUNCTION, 13)]);
    let payload = ok(&item);
    let info = payload.required(DEFAULTS_INFORMATION).unwrap();
    assert_eq!(payload.all(DEFAULTS_INFORMATION).count(), 1);
    let entries: Vec<_> = info.all(OBJECT_DEFAULTS).cloned().collect();
    // 2.0 Table 327 requires at least one Object Defaults.
    assert!(!entries.is_empty());
    let mut kinds = vec![];
    for entry in entries {
        let kind = entry.required(OBJECT_TYPE).unwrap().number().unwrap();
        kinds.push(kind);
        let defaults = entry.required(ATTRIBUTES).unwrap().children().unwrap();
        assert!(!defaults.is_empty());
        assert!(
            defaults.contains(&Node::interval(LEASE_TIME, lease)),
            "the configured lease is reported"
        );
        let actual = created(f, v, kind);
        for d in defaults {
            assert!(
                actual.contains(d),
                "{v:?} object type {kind}: default {:x} {:?} not applied",
                d.tag,
                match &d.value {
                    Value::Enumeration(n) | Value::Interval(n) => *n as i64,
                    Value::Integer(n) => *n as i64,
                    Value::Boolean(b) => *b as i64,
                    _ => -1,
                }
            );
        }
    }
    assert_eq!(kinds, vec![1, 2, 3, 4, 7, 8]);
}

// REQ:1b580f2471aa261d 2.0/2.1 Query Defaults Information lists the defaults the server applies when the client omits them
#[test]
fn defaults_information_lists_the_defaults_factory_operations_apply() {
    for v in [Version(2, 0), Version(2, 1)] {
        for lease in [3600, 86_400] {
            let mut f = Fixture::new(lease);
            reported_defaults_apply(&mut f, v, lease);
            // With other functions, each answers once and in request order.
            let item = f.call(
                v,
                24,
                vec![
                    Node::enumeration(QUERY_FUNCTION, 13),
                    Node::enumeration(QUERY_FUNCTION, 14),
                ],
            );
            let children = ok(&item).children().unwrap();
            assert_eq!(children[0].tag, DEFAULTS_INFORMATION);
            assert_eq!(children[1].tag, PROTECTION_STORAGE_MASKS);
        }
    }
}

/// Server defaults from Set Defaults (2.1 section 6.1.53;
/// docs/defaults-and-constraints.md) are merged into the report, and the
/// report still lists only what the factory operations apply, in 2.0 too.
#[test]
fn defaults_information_includes_server_defaults() {
    let entry = |kind: u32, attrs: Vec<Node>| {
        Node::structure(
            OBJECT_DEFAULTS,
            vec![
                Node::enumeration(OBJECT_TYPE, kind),
                Node::structure(ATTRIBUTES, attrs),
            ],
        )
    };
    let mut f = Fixture::new(3600);
    let item = f.call(
        Version(2, 1),
        0x36,
        vec![Node::structure(
            DEFAULTS_INFORMATION,
            vec![
                entry(
                    2,
                    vec![
                        Node::enumeration(CRYPTOGRAPHIC_ALGORITHM, 3),
                        Node::int(CRYPTOGRAPHIC_LENGTH, 128),
                        Node::int(CRYPTOGRAPHIC_USAGE_MASK, 12),
                        Node::boolean(SENSITIVE, true),
                    ],
                ),
                entry(
                    4,
                    vec![
                        Node::enumeration(CRYPTOGRAPHIC_ALGORITHM, 4),
                        Node::int(CRYPTOGRAPHIC_LENGTH, 3072),
                        Node::int(CRYPTOGRAPHIC_USAGE_MASK, 1),
                    ],
                ),
                entry(
                    3,
                    vec![
                        Node::int(CRYPTOGRAPHIC_USAGE_MASK, 2),
                        Node::boolean(EXTRACTABLE, false),
                    ],
                ),
                entry(7, vec![Node::int(CRYPTOGRAPHIC_USAGE_MASK, 0x200)]),
                entry(1, vec![Node::boolean(SENSITIVE, true)]),
                entry(8, vec![Node::boolean(EXTRACTABLE, false)]),
            ],
        )],
    );
    ok(&item);
    for v in [Version(2, 0), Version(2, 1)] {
        reported_defaults_apply(&mut f, v, 3600);
        let item = f.call(v, 24, vec![Node::enumeration(QUERY_FUNCTION, 13)]);
        let info = ok(&item).required(DEFAULTS_INFORMATION).unwrap().clone();
        let symmetric = info
            .all(OBJECT_DEFAULTS)
            .find(|e| e.required(OBJECT_TYPE).unwrap().number().unwrap() == 2)
            .unwrap()
            .required(ATTRIBUTES)
            .unwrap()
            .clone();
        assert!(symmetric.get(CRYPTOGRAPHIC_LENGTH) == Some(&Node::int(CRYPTOGRAPHIC_LENGTH, 128)));
        assert!(symmetric.get(SENSITIVE) == Some(&Node::boolean(SENSITIVE, true)));
    }
}

/// Query Defaults Information is a 2.x function: 1.x has no such enumeration
/// value and keeps refusing it.
#[test]
fn defaults_information_is_not_a_1_x_function() {
    let mut f = Fixture::new(3600);
    for minor in 0..=4 {
        let item = f.call(
            Version(1, minor),
            24,
            vec![Node::enumeration(QUERY_FUNCTION, 13)],
        );
        assert_eq!(item.required(RESULT_STATUS).unwrap().number().unwrap(), 1);
    }
}
