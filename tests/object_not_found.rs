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

//! The Result Reason for a Unique Identifier that names no accessible object.
//! KMIP 1.x answers Item Not Found (1). The 2.0, 2.1 and draft 3.0 error
//! tables of most operations list Object Not Found (0x37), while Adjust
//! Attribute, Certify and Create Split Key still list Item Not Found. Another
//! principal's object fails exactly like a missing one in every version.
use keytend_kmip_server::{
    protocol::{Engine, Version},
    store::Store,
    tags::*,
    ttlv::Node,
};
use tempfile::TempDir;

const VERSIONS: [Version; 4] = [Version(1, 4), Version(2, 0), Version(2, 1), Version(3, 0)];
const ITEM_NOT_FOUND: u32 = 1;
const OBJECT_NOT_FOUND: u32 = 0x37;
const WRAPPING_OBJECT_NOT_FOUND: u32 = 0x42;
const ENCRYPT_DECRYPT: i32 = 12;
const WRAP_UNWRAP: i32 = 48;

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
            engine: Engine::new(store, true),
        }
    }
    fn call(&mut self, owner: &str, v: Version, op: u32, payload: Vec<Node>) -> Node {
        // Draft 3.0 removed Batch Count.
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
                        Node::structure(REQUEST_PAYLOAD, payload),
                    ],
                ),
            ],
        );
        self.engine.process(owner, &request).unwrap()
    }
    fn create(&mut self, v: Version, mask: i32) -> String {
        let mut attrs = vec![
            Node::enumeration(CRYPTOGRAPHIC_ALGORITHM, 3),
            Node::int(CRYPTOGRAPHIC_LENGTH, 256),
            Node::int(CRYPTOGRAPHIC_USAGE_MASK, mask),
        ];
        if mask == WRAP_UNWRAP {
            // NIST Key Wrap.
            attrs.push(Node::structure(
                CRYPTOGRAPHIC_PARAMETERS,
                vec![Node::enumeration(BLOCK_CIPHER_MODE, 13)],
            ));
        }
        let r = self.call(
            "alice",
            v,
            1,
            vec![Node::enumeration(OBJECT_TYPE, 2), container(v, attrs)],
        );
        let item = r.get(BATCH_ITEM).unwrap();
        assert_eq!(
            item.required(RESULT_STATUS).unwrap().number().unwrap(),
            0,
            "reason {:?} {:?}",
            item.get(RESULT_REASON).map(|n| n.number()),
            item.get(RESULT_MESSAGE).map(|n| n.string())
        );
        item.required(RESPONSE_PAYLOAD)
            .unwrap()
            .required(UNIQUE_IDENTIFIER)
            .unwrap()
            .identifier_text()
            .unwrap()
            .to_owned()
    }
}
fn container(v: Version, attrs: Vec<Node>) -> Node {
    if v.0 >= 2 {
        return Node::structure(ATTRIBUTES, attrs);
    }
    let name = |tag| match tag {
        CRYPTOGRAPHIC_ALGORITHM => "Cryptographic Algorithm",
        CRYPTOGRAPHIC_LENGTH => "Cryptographic Length",
        CRYPTOGRAPHIC_PARAMETERS => "Cryptographic Parameters",
        _ => "Cryptographic Usage Mask",
    };
    Node::structure(
        TEMPLATE_ATTRIBUTE,
        attrs
            .into_iter()
            .map(|mut a| {
                let label = name(a.tag);
                a.tag = ATTRIBUTE_VALUE;
                Node::structure(ATTRIBUTE, vec![Node::text(ATTRIBUTE_NAME, label), a])
            })
            .collect(),
    )
}
fn uid(v: Version, id: &str) -> Node {
    if v.0 >= 3 {
        Node::identifier(UNIQUE_IDENTIFIER, id)
    } else {
        Node::text(UNIQUE_IDENTIFIER, id)
    }
}
/// Result Status, Result Reason and Result Message of the only batch item.
fn failure(r: &Node) -> (u32, u32, String) {
    let item = r.get(BATCH_ITEM).unwrap();
    (
        item.required(RESULT_STATUS).unwrap().number().unwrap(),
        item.required(RESULT_REASON).unwrap().number().unwrap(),
        item.required(RESULT_MESSAGE)
            .unwrap()
            .string()
            .unwrap()
            .to_owned(),
    )
}
fn status(r: &Node) -> u32 {
    let item = r.get(BATCH_ITEM).unwrap();
    item.required(RESULT_STATUS).unwrap().number().unwrap()
}
fn reason(r: &Node) -> u32 {
    failure(r).1
}
fn object_not_found(v: Version) -> u32 {
    if v.0 >= 2 {
        OBJECT_NOT_FOUND
    } else {
        ITEM_NOT_FOUND
    }
}
fn revocation() -> Node {
    Node::structure(
        REVOCATION_REASON,
        vec![Node::enumeration(REVOCATION_REASON_CODE, 1)],
    )
}

// Covers only the not-found row of the 2.x error tables of Activate
// (487bd4a8cb416c5f, 2.1 Table 166), Destroy (b671d7d0bc83514f, Table 210),
// Get (97ceb6b0d6644ea3, Table 222), Get Attributes (4953d329b5f770de, Table
// 225), Get Attribute List (306863620219f260, Table 228), Revoke
// (123ba3bacce17e3a, Table 297) and Encrypt (7a47dd1e74c03a07, Table 216).
// Those clauses are not cited: an archived target still answers Object
// Archived, which these tables do not list.
#[test]
fn missing_and_foreign_objects_have_the_versioned_not_found_reason() {
    let mut f = Fixture::new();
    for v in VERSIONS {
        let id = f.create(v, ENCRYPT_DECRYPT);
        let operations: Vec<(u32, Vec<Node>)> = vec![
            (10, vec![]),             // Get
            (11, vec![]),             // Get Attributes
            (12, vec![]),             // Get Attribute List
            (18, vec![]),             // Activate
            (19, vec![revocation()]), // Revoke
            (20, vec![]),             // Destroy
            (16, vec![]),             // Obtain Lease
            (
                31,
                vec![
                    Node::structure(
                        CRYPTOGRAPHIC_PARAMETERS,
                        vec![
                            Node::enumeration(BLOCK_CIPHER_MODE, 1),
                            Node::enumeration(PADDING_METHOD, 3),
                        ],
                    ),
                    Node::bytes(DATA, vec![0; 16]),
                ],
            ), // Encrypt
        ];
        for (op, extra) in operations {
            let with = |target: &str| {
                let mut p = vec![uid(v, target)];
                p.extend(extra.iter().cloned());
                p
            };
            let missing = f.call("alice", v, op, with("no-such-object"));
            assert_eq!(
                failure(&missing),
                (1, object_not_found(v), "Object not found".into()),
                "{}.{} operation {op}",
                v.0,
                v.1
            );
            // Ownership hiding: another principal's object is
            // indistinguishable from an absent one.
            let foreign = f.call("bob", v, op, with(&id));
            assert_eq!(
                failure(&foreign),
                failure(&missing),
                "{}.{} operation {op}",
                v.0,
                v.1
            );
        }
        // The owner still reaches the object.
        let r = f.call("alice", v, 10, vec![uid(v, &id)]);
        let item = r.get(BATCH_ITEM).unwrap();
        assert_eq!(item.required(RESULT_STATUS).unwrap().number().unwrap(), 0);
    }
}

// REQ:ac16bbd5d6875ff8 2.x Adjust Attribute errors list Item Not Found (2.1 Table 172)
// REQ:b1868e3012b3cc8c 2.x Create Split Key errors list Item Not Found (2.1 Table 195)
// Adjust Attribute and Create Split Key are also checked row by row in
// requirement_clauses_ops.rs. Certify (c993187a292a2d25, Table 181) is checked
// here only for its not-found row and is not cited: an archived public key
// answers Object Archived, which its table does not list.
#[test]
fn tables_that_list_item_not_found_keep_it_in_every_version() {
    let mut f = Fixture::new();
    for v in [Version(2, 0), Version(2, 1), Version(3, 0)] {
        let id = f.create(v, ENCRYPT_DECRYPT);
        let adjust = |target: &str| {
            vec![
                uid(v, target),
                Node::enumeration(ATTRIBUTE_REFERENCE, CRYPTOGRAPHIC_LENGTH),
                Node::enumeration(ADJUSTMENT_TYPE, 1),
            ]
        };
        let split = |target: &str| {
            vec![
                Node::enumeration(OBJECT_TYPE, 5),
                Node::int(SPLIT_KEY_PARTS, 3),
                Node::int(SPLIT_KEY_THRESHOLD, 3),
                Node::enumeration(SPLIT_KEY_METHOD, 1),
                Node::structure(ATTRIBUTES, vec![]),
                uid(v, target),
            ]
        };
        for (op, missing, foreign) in [
            (48, adjust("no-such-object"), adjust(&id)),
            (40, split("no-such-object"), split(&id)),
            (6, vec![uid(v, "no-such-object")], vec![uid(v, &id)]),
        ] {
            let missing = f.call("alice", v, op, missing);
            assert_eq!(
                failure(&missing),
                (1, ITEM_NOT_FOUND, "Object not found".into()),
                "{}.{} operation {op}",
                v.0,
                v.1
            );
            let foreign = f.call("bob", v, op, foreign);
            assert_eq!(
                failure(&foreign),
                failure(&missing),
                "{}.{} operation {op}",
                v.0,
                v.1
            );
        }
    }
}

// REQ:e4a8739188baf009 draft 3.0 Obliterate: later references answer Object Not Found
// REQ:7812b37184bf0b1b draft 3.0 Obliterate errors list Object Not Found (Table 376)
// The OASIS BL-M-20-30 trace shows Item Not Found after Obliterate; the draft
// text governs (docs/interpretations.md records the conflict).
#[test]
fn draft_obliterate_and_later_references_answer_object_not_found() {
    let mut f = Fixture::new();
    let v = Version(3, 0);
    let id = f.create(v, ENCRYPT_DECRYPT);
    let foreign = f.call("bob", v, 61, vec![uid(v, &id)]);
    assert_eq!(reason(&foreign), OBJECT_NOT_FOUND);
    let r = f.call("alice", v, 61, vec![uid(v, &id)]);
    let item = r.get(BATCH_ITEM).unwrap();
    assert_eq!(item.required(RESULT_STATUS).unwrap().number().unwrap(), 0);
    for op in [10, 11, 61] {
        let r = f.call("alice", v, op, vec![uid(v, &id)]);
        assert_eq!(reason(&r), OBJECT_NOT_FOUND, "operation {op}");
    }
}

// The Wrapping Object Not Found row of the 2.x Get errors (97ceb6b0d6644ea3, 2.1 Table 222);
// that clause stays uncited for the archived-object reason above.
#[test]
fn missing_and_foreign_wrapping_keys_have_the_versioned_reason() {
    let mut f = Fixture::new();
    for v in VERSIONS {
        let target = f.create(v, ENCRYPT_DECRYPT);
        let kek = f.create(v, WRAP_UNWRAP);
        let r = f.call("alice", v, 18, vec![uid(v, &kek)]);
        assert_eq!(status(&r), 0);
        let get = |kek: &str| {
            vec![
                uid(v, &target),
                Node::structure(
                    KEY_WRAPPING_SPECIFICATION,
                    vec![
                        Node::enumeration(WRAPPING_METHOD, 1),
                        Node::structure(ENCRYPTION_KEY_INFORMATION, vec![uid(v, kek)]),
                    ],
                ),
            ]
        };
        let expected = if v.0 >= 2 {
            WRAPPING_OBJECT_NOT_FOUND
        } else {
            ITEM_NOT_FOUND
        };
        let missing = f.call("alice", v, 10, get("no-such-key"));
        assert_eq!(reason(&missing), expected, "{}.{}", v.0, v.1);
        // Bob owns a target but cannot wrap with Alice's key.
        let bob_target = {
            let attrs = vec![
                Node::enumeration(CRYPTOGRAPHIC_ALGORITHM, 3),
                Node::int(CRYPTOGRAPHIC_LENGTH, 256),
                Node::int(CRYPTOGRAPHIC_USAGE_MASK, 12),
            ];
            let r = f.call(
                "bob",
                v,
                1,
                vec![Node::enumeration(OBJECT_TYPE, 2), container(v, attrs)],
            );
            r.get(BATCH_ITEM)
                .unwrap()
                .required(RESPONSE_PAYLOAD)
                .unwrap()
                .required(UNIQUE_IDENTIFIER)
                .unwrap()
                .identifier_text()
                .unwrap()
                .to_owned()
        };
        let mut foreign = get(&kek);
        foreign[0] = uid(v, &bob_target);
        let foreign = f.call("bob", v, 10, foreign);
        assert_eq!(reason(&foreign), expected, "{}.{}", v.0, v.1);
        // With its own key the owner wraps successfully.
        let own = f.call("alice", v, 10, get(&kek));
        let item = own.get(BATCH_ITEM).unwrap();
        assert_eq!(
            item.required(RESULT_STATUS).unwrap().number().unwrap(),
            0,
            "{}.{} reason {:?} {:?}",
            v.0,
            v.1,
            item.get(RESULT_REASON).map(|n| n.number()),
            item.get(RESULT_MESSAGE).map(|n| n.string())
        );
    }
}
