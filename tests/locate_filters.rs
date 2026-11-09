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

//! Locate filters on Contact Information, Description, Comment, Digest, Key
//! Format Type, Revocation Reason, Key Value Present and Key Value Location
//! in every edition that defines them (docs/locate.md). Asserting
//! tests cite their clause digests as `REQ:<digest>`
//! (docs/specs/requirement-matrix.json); the paraphrases are our own words.
use keytend_kmip_server::{
    protocol::{Engine, Version},
    store::{Store, now},
    tags::*,
    ttlv::Node,
};
use tempfile::TempDir;

const ALL: [Version; 7] = [
    Version(1, 0),
    Version(1, 1),
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

fn label(v: Version) -> String {
    format!("{}.{}", v.0, v.1)
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
/// Every attribute of an object (1.x Attribute structures decoded).
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
fn locate_item(f: &mut Fixture, v: Version, filters: Vec<Node>) -> Node {
    let fields = if v.0 >= 2 {
        vec![Node::structure(ATTRIBUTES, filters)]
    } else {
        filters.into_iter().map(legacy).collect()
    };
    f.call(v, 8, fields)
}
/// Located identifiers, sorted.
fn located(f: &mut Fixture, v: Version, filters: Vec<Node>) -> Vec<String> {
    let item = locate_item(f, v, filters);
    let mut ids: Vec<_> = ok(&item)
        .all(UNIQUE_IDENTIFIER)
        .map(|n| n.identifier_text().unwrap().to_owned())
        .collect();
    ids.sort();
    ids
}
fn sorted(mut ids: Vec<String>) -> Vec<String> {
    ids.sort();
    ids
}
fn structure(tag: u32, fields: Vec<Node>) -> Node {
    Node::structure(tag, fields)
}

// REQ:128cdaf344413ba2 each Locate filter attribute must match: text, structure (partial fields) and multi-instance
//   filters on Contact Information, Description, Comment, Digest, Key Format Type, Revocation Reason,
//   Key Value Present and Key Value Location, in each edition that defines them
#[test]
fn descriptive_attribute_filters_match_in_every_edition() {
    for v in ALL {
        let at = label(v);
        let mut f = Fixture::new();
        let mut extra = vec![Node::text(CONTACT_INFORMATION, "ops@example.test")];
        if v >= Version(1, 4) {
            extra.push(Node::text(DESCRIPTION, "payroll key"));
            extra.push(Node::text(COMMENT, "rotated yearly"));
        }
        let a = id_of(&f.call(v, 1, aes(v, extra)));
        let b = id_of(&f.call(
            v,
            1,
            aes(
                v,
                vec![Node::text(CONTACT_INFORMATION, "other@example.test")],
            ),
        ));
        let none: Vec<String> = vec![];

        // Text Strings: equality; a filter matches only objects with that value.
        assert_eq!(
            located(
                &mut f,
                v,
                vec![Node::text(CONTACT_INFORMATION, "ops@example.test")]
            ),
            vec![a.clone()],
            "{at}"
        );
        assert_eq!(
            located(&mut f, v, vec![Node::text(CONTACT_INFORMATION, "ops")]),
            none,
            "{at}"
        );
        if v >= Version(1, 4) {
            for (tag, value) in [(DESCRIPTION, "payroll key"), (COMMENT, "rotated yearly")] {
                assert_eq!(
                    located(&mut f, v, vec![Node::text(tag, value)]),
                    vec![a.clone()],
                    "{at}"
                );
                assert_eq!(located(&mut f, v, vec![Node::text(tag, "x")]), none, "{at}");
            }
            // All filters must match.
            assert_eq!(
                located(
                    &mut f,
                    v,
                    vec![
                        Node::text(DESCRIPTION, "payroll key"),
                        Node::text(CONTACT_INFORMATION, "other@example.test"),
                    ]
                ),
                none,
                "{at}"
            );
        }

        // Digest: the whole structure, any subset of its fields, and each instance.
        let attrs = attributes(&mut f, v, &a);
        let digests: Vec<_> = attrs.iter().filter(|n| n.tag == DIGEST).cloned().collect();
        assert!(!digests.is_empty(), "{at}");
        for d in &digests {
            assert_eq!(located(&mut f, v, vec![d.clone()]), vec![a.clone()], "{at}");
            let value = d.required(DIGEST_VALUE).unwrap().clone();
            assert_eq!(
                located(&mut f, v, vec![structure(DIGEST, vec![value])]),
                vec![a.clone()],
                "{at}"
            );
        }
        // Only the hashing algorithm: both keys carry a SHA-256 Digest.
        assert_eq!(
            located(
                &mut f,
                v,
                vec![structure(
                    DIGEST,
                    vec![Node::enumeration(HASHING_ALGORITHM, 6)]
                )]
            ),
            sorted(vec![a.clone(), b.clone()]),
            "{at}"
        );
        assert_eq!(
            located(
                &mut f,
                v,
                vec![structure(
                    DIGEST,
                    vec![Node::bytes(DIGEST_VALUE, vec![0; 32])]
                )]
            ),
            none,
            "{at}"
        );
        if v >= Version(1, 1) {
            // Key Format Type is a Digest field from 1.1.
            assert_eq!(
                located(
                    &mut f,
                    v,
                    vec![structure(
                        DIGEST,
                        vec![Node::enumeration(KEY_FORMAT_TYPE, 1)]
                    )]
                ),
                sorted(vec![a.clone(), b.clone()]),
                "{at}"
            );
            assert_eq!(
                located(
                    &mut f,
                    v,
                    vec![structure(
                        DIGEST,
                        vec![Node::enumeration(KEY_FORMAT_TYPE, 7)]
                    )]
                ),
                none,
                "{at}"
            );
        }

        // Key Format Type is an attribute from 2.0.
        if v.0 >= 2 {
            assert_eq!(
                located(
                    &mut f,
                    v,
                    vec![
                        Node::enumeration(OBJECT_TYPE, 2),
                        Node::enumeration(KEY_FORMAT_TYPE, 1)
                    ]
                ),
                sorted(vec![a.clone(), b.clone()]),
                "{at}"
            );
            assert_eq!(
                located(&mut f, v, vec![Node::enumeration(KEY_FORMAT_TYPE, 7)]),
                none,
                "{at}"
            );
        }

        // Revocation Reason: Key Compromise with a message, revoked from Pre-Active.
        let mut revoke = vec![
            uid(&a),
            structure(
                REVOCATION_REASON,
                vec![
                    Node::enumeration(REVOCATION_REASON_CODE, 2),
                    Node::text(REVOCATION_MESSAGE, "laptop lost"),
                ],
            ),
        ];
        if v < Version(1, 3) {
            revoke.push(Node::date(COMPROMISE_OCCURRENCE_DATE, now() - 60));
        }
        ok(&f.call(v, 19, revoke));
        for filter in [
            structure(
                REVOCATION_REASON,
                vec![Node::enumeration(REVOCATION_REASON_CODE, 2)],
            ),
            structure(
                REVOCATION_REASON,
                vec![Node::text(REVOCATION_MESSAGE, "laptop lost")],
            ),
            structure(
                REVOCATION_REASON,
                vec![
                    Node::enumeration(REVOCATION_REASON_CODE, 2),
                    Node::text(REVOCATION_MESSAGE, "laptop lost"),
                ],
            ),
        ] {
            assert_eq!(located(&mut f, v, vec![filter]), vec![a.clone()], "{at}");
        }
        assert_eq!(
            located(
                &mut f,
                v,
                vec![structure(
                    REVOCATION_REASON,
                    vec![Node::enumeration(REVOCATION_REASON_CODE, 5)]
                )]
            ),
            none,
            "{at}"
        );

        // Key Value Present and Key Value Location (1.2 and later): a
        // metadata-only object with two Key Value Location instances.
        if v >= Version(1, 2) {
            let location = |value: &str, kind: u32| {
                structure(
                    KEY_VALUE_LOCATION,
                    vec![
                        Node::text(KEY_VALUE_LOCATION_VALUE, value),
                        Node::enumeration(KEY_VALUE_LOCATION_TYPE, kind),
                    ],
                )
            };
            let mut fields = aes(
                v,
                vec![location("hsm-1", 1), location("https://kv.example/2", 2)],
            );
            fields.push(structure(
                SYMMETRIC_KEY,
                vec![structure(
                    KEY_BLOCK,
                    vec![
                        Node::enumeration(KEY_FORMAT_TYPE, 1),
                        Node::enumeration(CRYPTOGRAPHIC_ALGORITHM, 3),
                        Node::int(CRYPTOGRAPHIC_LENGTH, 128),
                    ],
                )],
            ));
            let c = id_of(&f.call(v, 3, fields));
            assert_eq!(
                located(&mut f, v, vec![Node::boolean(KEY_VALUE_PRESENT, false)]),
                vec![c.clone()],
                "{at}"
            );
            // Set only on objects registered without a Key Value.
            assert_eq!(
                located(&mut f, v, vec![Node::boolean(KEY_VALUE_PRESENT, true)]),
                none,
                "{at}"
            );
            for filter in [
                location("hsm-1", 1),
                location("https://kv.example/2", 2),
                structure(
                    KEY_VALUE_LOCATION,
                    vec![Node::enumeration(KEY_VALUE_LOCATION_TYPE, 2)],
                ),
            ] {
                assert_eq!(located(&mut f, v, vec![filter]), vec![c.clone()], "{at}");
            }
            // Fields of one filter must match within one instance.
            assert_eq!(located(&mut f, v, vec![location("hsm-1", 2)]), none, "{at}");
        }
    }
}

// REQ:128cdaf344413ba2 a filter on an attribute the edition does not define, or of the wrong type, fails
#[test]
fn filters_outside_their_edition_or_malformed_fail() {
    for v in ALL {
        let at = label(v);
        let mut f = Fixture::new();
        let mut refused = vec![];
        if v < Version(1, 4) {
            refused.push(Node::text(DESCRIPTION, "d"));
            refused.push(Node::text(COMMENT, "c"));
        }
        if v.0 < 2 {
            refused.push(Node::enumeration(KEY_FORMAT_TYPE, 1));
        }
        if v < Version(1, 2) {
            refused.push(structure(
                KEY_VALUE_LOCATION,
                vec![Node::enumeration(KEY_VALUE_LOCATION_TYPE, 1)],
            ));
        }
        for filter in refused {
            let tag = filter.tag;
            let item = locate_item(&mut f, v, vec![filter]);
            assert_eq!(reason(&item), 7, "{at} {tag:x}");
        }
        // Wrong field types.
        for filter in [
            Node::int(CONTACT_INFORMATION, 1),
            structure(DIGEST, vec![Node::text(DIGEST_VALUE, "00")]),
            structure(
                REVOCATION_REASON,
                vec![Node::int(REVOCATION_REASON_CODE, 2)],
            ),
        ] {
            let item = locate_item(&mut f, v, vec![filter]);
            assert_eq!(reason(&item), 7, "{at}");
        }
        // 1.0 Digest has no Key Format Type field.
        if v == Version(1, 0) {
            let item = locate_item(
                &mut f,
                v,
                vec![structure(
                    DIGEST,
                    vec![Node::enumeration(KEY_FORMAT_TYPE, 1)],
                )],
            );
            // An unknown field is Invalid Field in 1.x (1.0 Table 226).
            assert_eq!(reason(&item), 7, "{at}");
        }
    }
}
