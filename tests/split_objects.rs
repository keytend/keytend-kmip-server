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
    encoding::Format,
    protocol::{Engine, Version},
    store::Store,
    tags::*,
    ttlv::{Node, Value},
};

struct Fixture {
    dir: tempfile::TempDir,
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
            dir,
            engine: Engine::new(store, true),
        }
    }
    fn restart(&mut self) {
        let store = Store::open(
            &self.dir.path().join("keys.sqlite"),
            &self.dir.path().join("master"),
        )
        .unwrap();
        self.engine = Engine::new(store, true);
    }
    fn call(&mut self, v: Version, owner: &str, op: u32, fields: Vec<Node>) -> Node {
        self.engine
            .process(owner, &request(v, vec![(op, fields)]))
            .unwrap()
    }
}
fn versions() -> Vec<Version> {
    Version::supported(true)
}
fn request(v: Version, items: Vec<(u32, Vec<Node>)>) -> Node {
    let mut header = vec![v.node()];
    if v.0 < 3 {
        header.push(Node::int(BATCH_COUNT, items.len() as i32));
    }
    let mut children = vec![Node::structure(REQUEST_HEADER, header)];
    children.extend(items.into_iter().enumerate().map(|(index, (op, fields))| {
        let mut item = vec![Node::enumeration(OPERATION, op)];
        if v.0 < 3 {
            item.push(Node::bytes(UNIQUE_BATCH_ITEM_ID, vec![index as u8]));
        }
        item.push(Node::structure(REQUEST_PAYLOAD, fields));
        Node::structure(BATCH_ITEM, item)
    }));
    let request = Node::structure(REQUEST_MESSAGE, children);
    // Exercise the public wire codec, including signed prime-field padding.
    Format::Ttlv
        .decode(&Format::Ttlv.encode(&request).unwrap())
        .unwrap()
}
fn id(v: Version, value: &str) -> Node {
    if v.0 >= 3 {
        Node::reference(UNIQUE_IDENTIFIER, value)
    } else {
        Node::text(UNIQUE_IDENTIFIER, value)
    }
}
fn container(v: Version, attrs: Vec<Node>) -> Node {
    if v.0 >= 2 {
        Node::structure(ATTRIBUTES, attrs)
    } else {
        Node::structure(
            TEMPLATE_ATTRIBUTE,
            attrs
                .into_iter()
                .map(|a| {
                    Node::structure(
                        ATTRIBUTE,
                        vec![
                            Node::text(ATTRIBUTE_NAME, tag_name(a.tag).unwrap()),
                            Node {
                                tag: ATTRIBUTE_VALUE,
                                value: a.value.clone(),
                            },
                        ],
                    )
                })
                .collect(),
        )
    }
}
fn payload(response: &Node) -> &Node {
    let item = response.required(BATCH_ITEM).unwrap();
    assert_eq!(
        item.required(RESULT_STATUS).unwrap().number().unwrap(),
        0,
        "reason {:?}, message {:?}",
        item.get(RESULT_REASON).map(|n| n.number().unwrap()),
        item.get(RESULT_MESSAGE).and_then(|n| n.string().ok())
    );
    item.required(RESPONSE_PAYLOAD).unwrap()
}
fn reason(response: &Node) -> u32 {
    response
        .required(BATCH_ITEM)
        .unwrap()
        .required(RESULT_REASON)
        .unwrap()
        .number()
        .unwrap()
}
fn identifier(response: &Node) -> String {
    payload(response)
        .required(UNIQUE_IDENTIFIER)
        .unwrap()
        .identifier_text()
        .unwrap()
        .to_owned()
}
fn share(v: Version, method: u32, part: i32) -> Node {
    let mut fields = vec![
        Node::int(SPLIT_KEY_PARTS, 3),
        Node::int(KEY_PART_IDENTIFIER, part),
        Node::int(SPLIT_KEY_THRESHOLD, if method == 1 { 3 } else { 2 }),
        Node::enumeration(SPLIT_KEY_METHOD, method),
    ];
    let material = if method == 3 {
        fields.push(Node {
            tag: PRIME_FIELD_SIZE,
            value: Value::BigInteger(vec![0, 0, 0, 0, 0, 0, 1, 1]),
        });
        vec![0, 254]
    } else {
        hex::decode("66c46a7754f94de420c7b1a7fff5ec56").unwrap()
    };
    let _ = v;
    fields.push(Node::structure(
        KEY_BLOCK,
        vec![
            Node::enumeration(KEY_FORMAT_TYPE, 1),
            Node::structure(KEY_VALUE, vec![Node::bytes(KEY_MATERIAL, material)]),
        ],
    ));
    Node::structure(SPLIT_KEY, fields)
}
fn registration(v: Version, method: u32, extra: Vec<Node>) -> Vec<Node> {
    let mut attrs = extra;
    if v.0 >= 3 && matches!(method, 2 | 4) {
        attrs.push(Node::enumeration(SPLIT_KEY_POLYNOMIAL, 2));
    }
    vec![
        Node::enumeration(OBJECT_TYPE, 5),
        container(v, attrs),
        share(v, method, 2),
    ]
}
fn bytes(response: &Node) -> &[u8] {
    payload(response)
        .required(SPLIT_KEY)
        .unwrap()
        .required(KEY_BLOCK)
        .unwrap()
        .required(KEY_VALUE)
        .unwrap()
        .required(KEY_MATERIAL)
        .unwrap()
        .byte_string()
        .unwrap()
}
fn fields(n: &mut Node) -> &mut Vec<Node> {
    let Value::Structure(fields) = &mut n.value else {
        panic!("not structure")
    };
    fields
}
fn set(n: &mut Node, value: Node) {
    let f = fields(n);
    f.retain(|n| n.tag != value.tag);
    f.push(value);
}

#[test]
fn registered_split_objects_round_trip_in_every_edition_and_survive_restart() {
    for v in versions() {
        for method in 1..=4 {
            let mut f = Fixture::new();
            let response = f.call(v, "alice", 3, registration(v, method, vec![]));
            if method == 4 && v < Version(1, 2) {
                assert_eq!(reason(&response), 8);
                continue;
            }
            let key = identifier(&response);
            let got = f.call(v, "alice", 10, vec![id(v, &key)]);
            assert!(payload(&got).required(SPLIT_KEY).unwrap() == &share(v, method, 2));
            assert_eq!(
                reason(&f.call(v, "bob", 10, vec![id(v, &key)])),
                not_found(v)
            );
            let stored = f.engine.store.get("alice", &key).unwrap().unwrap();
            assert!(stored.split.is_some());
            if v >= Version(1, 1) {
                assert_eq!(stored.metadata.fresh, Some(false));
            }
            f.restart();
            assert_eq!(
                f.call(v, "alice", 10, vec![id(v, &key)])
                    .required(BATCH_ITEM)
                    .unwrap()
                    .required(RESULT_STATUS)
                    .unwrap()
                    .number()
                    .unwrap(),
                0
            );
            assert_eq!(
                bytes(&got),
                bytes(&f.call(v, "alice", 10, vec![id(v, &key)]))
            );
            let query = f.call(v, "alice", 24, vec![Node::enumeration(QUERY_FUNCTION, 2)]);
            assert!(
                payload(&query)
                    .all(OBJECT_TYPE)
                    .any(|n| n.number().unwrap() == 5)
            );
            payload(&f.call(v, "alice", 20, vec![id(v, &key)]));
            // Get of a destroyed object: Object Destroyed from 2.0.
            assert_eq!(
                reason(&f.call(v, "alice", 10, vec![id(v, &key)])),
                if v.0 >= 2 { 0x36 } else { 11 }
            );
        }
    }
}

#[test]
fn split_parameters_are_strict_and_failed_registration_leaves_no_object() {
    let v = Version(2, 1);
    let mut f = Fixture::new();
    let base = share(v, 2, 2);
    let mut invalid = vec![];
    for node in [
        Node::int(SPLIT_KEY_PARTS, 0),
        Node::int(SPLIT_KEY_PARTS, 129),
        Node::int(KEY_PART_IDENTIFIER, 0),
        Node::int(KEY_PART_IDENTIFIER, 4),
        Node::int(SPLIT_KEY_THRESHOLD, 4),
        Node::int(SPLIT_KEY_METHOD, 2),
        Node::enumeration(SPLIT_KEY_METHOD, 5),
        Node::enumeration(KEY_PART_IDENTIFIER, 2),
        Node::enumeration(SECRET_DATA_TYPE, 1),
    ] {
        let mut n = base.clone();
        set(&mut n, node);
        invalid.push(n);
    }
    let mut duplicate = base.clone();
    fields(&mut duplicate).push(Node::int(SPLIT_KEY_PARTS, 3));
    invalid.push(duplicate);
    let mut missing = base.clone();
    fields(&mut missing).retain(|n| n.tag != KEY_PART_IDENTIFIER);
    invalid.push(missing);
    let mut odd = base.clone();
    let kb = fields(&mut odd)
        .iter_mut()
        .find(|n| n.tag == KEY_BLOCK)
        .unwrap();
    set(
        kb,
        Node::structure(KEY_VALUE, vec![Node::bytes(KEY_MATERIAL, vec![1; 15])]),
    );
    invalid.push(odd);
    let mut wrong_xor = base.clone();
    set(&mut wrong_xor, Node::enumeration(SPLIT_KEY_METHOD, 1));
    invalid.push(wrong_xor);
    for n in invalid {
        let response = f.call(
            v,
            "alice",
            3,
            vec![Node::enumeration(OBJECT_TYPE, 5), container(v, vec![]), n],
        );
        assert!(
            response
                .required(BATCH_ITEM)
                .unwrap()
                .get(RESULT_REASON)
                .is_some()
        );
        assert_eq!(
            f.engine.store.locate("alice", 0, 100, |_| true).unwrap().0,
            0
        );
    }
    for prime in [
        vec![0; 8],
        vec![255; 8],
        vec![0, 0, 0, 0, 0, 0, 2, 49],
        vec![0, 1, 1],
    ] {
        let mut n = share(v, 3, 2);
        set(
            &mut n,
            Node {
                tag: PRIME_FIELD_SIZE,
                value: Value::BigInteger(prime),
            },
        );
        // Invalid in-memory Big Integer widths are tested without the encoder,
        // which correctly refuses to produce a malformed wire frame itself.
        let request = Node::structure(
            REQUEST_MESSAGE,
            vec![
                Node::structure(REQUEST_HEADER, vec![v.node(), Node::int(BATCH_COUNT, 1)]),
                Node::structure(
                    BATCH_ITEM,
                    vec![
                        Node::enumeration(OPERATION, 3),
                        Node::structure(
                            REQUEST_PAYLOAD,
                            vec![Node::enumeration(OBJECT_TYPE, 5), container(v, vec![]), n],
                        ),
                    ],
                ),
            ],
        );
        let response = f.engine.process("alice", &request).unwrap();
        assert_eq!(reason(&response), 7);
    }
    let mut extra_prime = share(v, 2, 2);
    set(
        &mut extra_prime,
        Node {
            tag: PRIME_FIELD_SIZE,
            value: Value::BigInteger(vec![0, 0, 0, 0, 0, 0, 1, 1]),
        },
    );
    assert_eq!(
        reason(&f.call(
            v,
            "alice",
            3,
            vec![
                Node::enumeration(OBJECT_TYPE, 5),
                container(v, vec![]),
                extra_prime
            ]
        )),
        7
    );
    let mut out_of_field = share(v, 3, 2);
    let kb = fields(&mut out_of_field)
        .iter_mut()
        .find(|n| n.tag == KEY_BLOCK)
        .unwrap();
    set(
        kb,
        Node::structure(KEY_VALUE, vec![Node::bytes(KEY_MATERIAL, vec![1, 1])]),
    );
    assert_eq!(
        reason(&f.call(
            v,
            "alice",
            3,
            vec![
                Node::enumeration(OBJECT_TYPE, 5),
                container(v, vec![]),
                out_of_field
            ]
        )),
        7
    );
}

#[test]
fn draft_polynomial_identity_is_immutable_and_never_silently_projected_to_final_editions() {
    let mut f = Fixture::new();
    let v = Version(3, 0);
    let mut request = registration(v, 2, vec![]);
    set(&mut request[1], Node::enumeration(SPLIT_KEY_POLYNOMIAL, 1));
    let key = identifier(&f.call(v, "alice", 3, request));
    for version in [Version(1, 4), Version(2, 1)] {
        assert_eq!(
            reason(&f.call(version, "alice", 10, vec![id(version, &key)])),
            8
        );
    }
    let attrs = f.call(v, "alice", 11, vec![id(v, &key)]);
    let attrs = payload(&attrs).required(ATTRIBUTES).unwrap();
    assert_eq!(
        attrs
            .required(SPLIT_KEY_POLYNOMIAL)
            .unwrap()
            .number()
            .unwrap(),
        1
    );
    for (tag, value) in [
        (
            SPLIT_KEY_POLYNOMIAL,
            Node::enumeration(SPLIT_KEY_POLYNOMIAL, 2),
        ),
        (SPLIT_KEY_METHOD, Node::enumeration(SPLIT_KEY_METHOD, 1)),
        (SPLIT_KEY_PARTS, Node::int(SPLIT_KEY_PARTS, 4)),
        (SPLIT_KEY_THRESHOLD, Node::int(SPLIT_KEY_THRESHOLD, 1)),
    ] {
        for (op, extra) in [
            (
                13,
                vec![Node::structure(NEW_ATTRIBUTE, vec![value.clone()])],
            ),
            (49, vec![Node::structure(NEW_ATTRIBUTE, vec![value])]),
            (15, vec![Node::enumeration(ATTRIBUTE_REFERENCE, tag)]),
        ] {
            let mut request = vec![id(v, &key)];
            request.extend(extra);
            assert_eq!(reason(&f.call(v, "alice", op, request)), 0x22);
        }
    }
    let located = f.call(
        v,
        "alice",
        8,
        vec![container(
            v,
            vec![Node::enumeration(SPLIT_KEY_POLYNOMIAL, 1)],
        )],
    );
    assert!(
        payload(&located)
            .all(UNIQUE_IDENTIFIER)
            .any(|n| n.identifier_text().unwrap() == key)
    );
    let mut missing = registration(v, 2, vec![]);
    fields(&mut missing[1]).clear();
    assert_eq!(
        reason(&f.call(v, "alice", 3, missing)),
        if v.0 >= 2 { 7 } else { 6 }
    );
    let bad = registration(v, 2, vec![Node::int(SPLIT_KEY_PARTS, 4)]);
    assert_eq!(reason(&f.call(v, "alice", 3, bad)), 7);
    f.restart();
    assert_eq!(
        bytes(&f.call(v, "alice", 10, vec![id(v, &key)])),
        hex::decode("66c46a7754f94de420c7b1a7fff5ec56").unwrap()
    );
}

#[test]
fn split_share_is_never_accepted_as_a_complete_aes_or_ec_key() {
    for algorithm in [3, 4, 6, 9, 14] {
        let mut f = Fixture::new();
        let v = Version(2, 1);
        let request = registration(
            v,
            2,
            vec![
                Node::enumeration(CRYPTOGRAPHIC_ALGORITHM, algorithm),
                Node::int(CRYPTOGRAPHIC_LENGTH, 128),
                Node::int(CRYPTOGRAPHIC_USAGE_MASK, 511),
            ],
        );
        let key = identifier(&f.call(v, "alice", 3, request));
        let got = f.call(v, "alice", 10, vec![id(v, &key)]);
        assert_eq!(bytes(&got).len(), 16);
        payload(&f.call(v, "alice", 18, vec![id(v, &key)]));
        for (op, extra) in [
            (31, vec![Node::bytes(DATA, vec![0; 16])]),
            (33, vec![Node::bytes(DATA, vec![1])]),
            (35, vec![Node::bytes(DATA, vec![1])]),
            (4, vec![]),
        ] {
            let mut request = vec![id(v, &key)];
            request.extend(extra);
            assert!(
                f.call(v, "alice", op, request)
                    .required(BATCH_ITEM)
                    .unwrap()
                    .get(RESULT_REASON)
                    .is_some()
            );
        }
    }
}

#[test]
fn split_export_import_preserves_metadata_material_and_destroyed_tombstones() {
    for v in [Version(1, 4), Version(2, 0), Version(2, 1), Version(3, 0)] {
        for method in 1..=4 {
            let mut source = Fixture::new();
            let key = identifier(&source.call(v, "alice", 3, registration(v, method, vec![])));
            for destroyed in [false, true] {
                if destroyed {
                    payload(&source.call(v, "alice", 20, vec![id(v, &key)]));
                }
                let exported = source.call(v, "alice", 43, vec![id(v, &key)]);
                let mut target = Fixture::new();
                let imported = target.call(
                    v,
                    "alice",
                    42,
                    payload(&exported).children().unwrap().to_vec(),
                );
                assert_eq!(identifier(&imported), key);
                target.restart();
                let got = target.call(v, "alice", 10, vec![id(v, &key)]);
                if destroyed {
                    assert_eq!(reason(&got), if v.0 >= 2 { 0x36 } else { 11 });
                } else {
                    assert!(
                        payload(&got).required(SPLIT_KEY).unwrap()
                            == payload(&exported).required(SPLIT_KEY).unwrap()
                    );
                }
                let stored = target.engine.store.get("alice", &key).unwrap().unwrap();
                assert!(stored.split.is_some());
            }
        }
    }
}

#[test]
fn split_response_failure_and_undo_preserve_the_original_store() {
    let mut f = Fixture::new();
    let v = Version(2, 1);
    let mut req = request(
        v,
        vec![
            (3, registration(v, 2, vec![])),
            (3, registration(v, 2, vec![])),
        ],
    );
    let header = fields(&mut req)
        .iter_mut()
        .find(|n| n.tag == REQUEST_HEADER)
        .unwrap();
    fields(header).push(Node::enumeration(BATCH_ERROR_CONTINUATION_OPTION, 3));
    let items = fields(&mut req);
    let last = items.last_mut().unwrap();
    let payload = fields(last)
        .iter_mut()
        .find(|n| n.tag == REQUEST_PAYLOAD)
        .unwrap();
    let object = fields(payload)
        .iter_mut()
        .find(|n| n.tag == SPLIT_KEY)
        .unwrap();
    set(object, Node::int(KEY_PART_IDENTIFIER, 4));
    let response = f.engine.process("alice", &req).unwrap();
    assert_eq!(
        response
            .all(BATCH_ITEM)
            .next()
            .unwrap()
            .required(RESULT_STATUS)
            .unwrap()
            .number()
            .unwrap(),
        3
    );
    assert_eq!(
        f.engine.store.locate("alice", 0, 100, |_| true).unwrap().0,
        0
    );
    let key = identifier(&f.call(v, "alice", 3, registration(v, 2, vec![])));
    let mut req = request(v, vec![(10, vec![id(v, &key)])]);
    let header = fields(&mut req)
        .iter_mut()
        .find(|n| n.tag == REQUEST_HEADER)
        .unwrap();
    fields(header).push(Node::int(MAXIMUM_RESPONSE_SIZE, 256));
    let result = f.engine.process("alice", &req);
    if let Ok(response) = result {
        assert!(
            response
                .required(BATCH_ITEM)
                .unwrap()
                .get(RESULT_REASON)
                .is_some()
        );
    }
    assert_eq!(
        f.engine
            .store
            .get("alice", &key)
            .unwrap()
            .unwrap()
            .metadata
            .fresh,
        Some(true)
    );
}

fn wrapping_spec(v: Version, kek: &str) -> Node {
    Node::structure(
        KEY_WRAPPING_SPECIFICATION,
        vec![
            Node::enumeration(WRAPPING_METHOD, 1),
            Node::structure(
                ENCRYPTION_KEY_INFORMATION,
                vec![
                    id(v, kek),
                    Node::structure(
                        CRYPTOGRAPHIC_PARAMETERS,
                        vec![Node::enumeration(BLOCK_CIPHER_MODE, 12)],
                    ),
                ],
            ),
        ],
    )
}
#[test]
fn wrapped_split_registration_and_as_registered_restore_preserve_field_identity() {
    for v in versions() {
        for method in [2, 3] {
            let mut f = Fixture::new();
            let kek = identifier(&f.call(
                v,
                "alice",
                1,
                vec![
                    Node::enumeration(OBJECT_TYPE, 2),
                    container(
                        v,
                        vec![
                            Node::enumeration(CRYPTOGRAPHIC_ALGORITHM, 3),
                            Node::int(CRYPTOGRAPHIC_LENGTH, 128),
                            Node::int(CRYPTOGRAPHIC_USAGE_MASK, 48),
                            Node::structure(
                                CRYPTOGRAPHIC_PARAMETERS,
                                vec![Node::enumeration(BLOCK_CIPHER_MODE, 12)],
                            ),
                        ],
                    ),
                ],
            ));
            payload(&f.call(v, "alice", 18, vec![id(v, &kek)]));
            let protected = if v >= Version(1, 4) {
                vec![Node::boolean(SENSITIVE, true)]
            } else {
                vec![]
            };
            let key =
                identifier(&f.call(v, "alice", 3, registration(v, method, protected.clone())));
            if v >= Version(1, 4) {
                assert_eq!(reason(&f.call(v, "alice", 10, vec![id(v, &key)])), 0x16);
            }
            let wrapped = f.call(v, "alice", 10, vec![id(v, &key), wrapping_spec(v, &kek)]);
            let mut reg = registration(v, method, vec![]);
            *reg.last_mut().unwrap() = payload(&wrapped).required(SPLIT_KEY).unwrap().clone();
            let copy = identifier(&f.call(v, "alice", 3, reg));
            let clear = f.call(v, "alice", 10, vec![id(v, &copy)]);
            let expected = share(v, method, 2);
            assert!(payload(&clear).required(SPLIT_KEY).unwrap() == &expected);
            assert_eq!(
                f.engine
                    .store
                    .get("alice", &copy)
                    .unwrap()
                    .unwrap()
                    .metadata
                    .fresh,
                Some(false)
            );
            if v >= Version(1, 4) {
                let exported = f.call(v, "alice", 43, vec![id(v, &key), wrapping_spec(v, &kek)]);
                let mut imported = payload(&exported).children().unwrap().to_vec();
                imported.push(Node::boolean(REPLACE_EXISTING, true));
                if v.0 >= 2 {
                    imported.push(Node::enumeration(KEY_WRAP_TYPE, 2));
                }
                // Restore the exact owned ID; there is no secret-key or metadata
                // substitution, and the original sensitivity flags remain enforced.
                assert_eq!(identifier(&f.call(v, "alice", 42, imported)), key);
                assert!(
                    f.engine
                        .store
                        .get("alice", &key)
                        .unwrap()
                        .unwrap()
                        .material
                        .is_empty()
                );
                f.restart();
                let envelope = f.call(
                    v,
                    "alice",
                    10,
                    vec![id(v, &key), Node::enumeration(KEY_WRAP_TYPE, 2)],
                );
                assert!(
                    payload(&envelope).required(SPLIT_KEY).unwrap()
                        == payload(&exported).required(SPLIT_KEY).unwrap()
                );
                payload(&f.call(
                    v,
                    "alice",
                    19,
                    vec![
                        id(v, &kek),
                        Node::structure(
                            REVOCATION_REASON,
                            vec![Node::enumeration(REVOCATION_REASON_CODE, 1)],
                        ),
                    ],
                ));
                payload(&f.call(v, "alice", 20, vec![id(v, &kek)]));
                let envelope = f.call(
                    v,
                    "alice",
                    10,
                    vec![id(v, &key), Node::enumeration(KEY_WRAP_TYPE, 2)],
                );
                assert!(
                    payload(&envelope).required(SPLIT_KEY).unwrap()
                        == payload(&exported).required(SPLIT_KEY).unwrap()
                );
                assert_eq!(reason(&f.call(v, "alice", 10, vec![id(v, &key)])), 0x16);
                assert!(
                    f.call(v, "alice", 10, vec![id(v, &key), wrapping_spec(v, &kek)])
                        .required(BATCH_ITEM)
                        .unwrap()
                        .get(RESULT_REASON)
                        .is_some()
                );
            }
        }
    }
}

#[test]
fn split_extraction_grants_and_archive_follow_managed_object_policy() {
    use keytend_kmip_server::authorization::ObjectGrant;
    let mut f = Fixture::new();
    let v = Version(2, 1);
    let key = identifier(&f.call(v, "alice", 3, registration(v, 2, vec![])));
    let grant = ObjectGrant {
        owner: "alice".into(),
        user: None,
        device: None,
        identifier: key.clone(),
        operations: vec![10],
    };
    let request = request(v, vec![(10, vec![id(v, &key)])]);
    let got = f
        .engine
        .process_with_grants("bob", &request, Some(&[10]), std::slice::from_ref(&grant))
        .unwrap();
    assert_eq!(bytes(&got).len(), 16);
    assert_eq!(
        f.engine
            .store
            .get("alice", &key)
            .unwrap()
            .unwrap()
            .metadata
            .fresh,
        Some(false)
    );
    assert!(f.engine.store.get("bob", &key).unwrap().is_none());
    let mutate = request_for(v, 20, &key);
    assert_eq!(
        reason(
            &f.engine
                .process_with_grants("bob", &mutate, Some(&[20]), std::slice::from_ref(&grant))
                .unwrap()
        ),
        not_found(v)
    );
    payload(&f.call(v, "alice", 21, vec![id(v, &key)]));
    assert_eq!(reason(&f.call(v, "alice", 10, vec![id(v, &key)])), 13);
    f.restart();
    assert_eq!(reason(&f.call(v, "alice", 10, vec![id(v, &key)])), 13);
    payload(&f.call(v, "alice", 22, vec![id(v, &key)]));
    assert_eq!(bytes(&f.call(v, "alice", 10, vec![id(v, &key)])).len(), 16);
    let protected = identifier(&f.call(
        v,
        "alice",
        3,
        registration(v, 2, vec![Node::boolean(EXTRACTABLE, false)]),
    ));
    assert_eq!(
        reason(&f.call(v, "alice", 10, vec![id(v, &protected)])),
        0x17
    );
    f.restart();
    assert_eq!(
        reason(&f.call(v, "alice", 10, vec![id(v, &protected)])),
        0x17
    );
}
fn request_for(v: Version, op: u32, key: &str) -> Node {
    request(v, vec![(op, vec![id(v, key)])])
}

#[test]
fn chacha_split_registration_binds_share_width_to_declared_key_length() {
    for v in [Version(1, 4), Version(2, 0), Version(2, 1), Version(3, 0)] {
        for algorithm in [28, 30] {
            for method in [1, 2, 4] {
                for length in [30, 31, 32, 33, 34] {
                    let mut f = Fixture::new();
                    let mut request = registration(v, method, vec![]);
                    let object = request.iter_mut().find(|n| n.tag == SPLIT_KEY).unwrap();
                    let block = fields(object)
                        .iter_mut()
                        .find(|n| n.tag == KEY_BLOCK)
                        .unwrap();
                    set(block, Node::enumeration(CRYPTOGRAPHIC_ALGORITHM, algorithm));
                    set(block, Node::int(CRYPTOGRAPHIC_LENGTH, 256));
                    set(
                        block,
                        Node::structure(
                            KEY_VALUE,
                            vec![Node::bytes(KEY_MATERIAL, vec![7; length])],
                        ),
                    );
                    let response = f.call(v, "alice", 3, request);
                    if length == 32 {
                        let key = identifier(&response);
                        f.restart();
                        let got = f.call(v, "alice", 10, vec![id(v, &key)]);
                        assert_eq!(bytes(&got), &[7; 32]);
                    } else {
                        assert_eq!(
                            response
                                .required(BATCH_ITEM)
                                .unwrap()
                                .required(RESULT_STATUS)
                                .unwrap()
                                .number()
                                .unwrap(),
                            1,
                            "{}.{} algorithm={algorithm} method={method} length={length}",
                            v.0,
                            v.1
                        );
                        assert_eq!(reason(&response), 7);
                        assert!(f.engine.store.list("alice").unwrap().is_empty());
                    }
                }
            }
        }
    }
}

#[test]
fn chacha_split_metadata_requires_supported_edition_and_256_bit_source() {
    for v in versions() {
        for algorithm in [28, 30] {
            for bits in [0, 128, 240, 256, 264] {
                if v >= Version(1, 4) && bits == 256 {
                    continue; // Positive durability cases are exercised above.
                }
                let mut f = Fixture::new();
                let mut request = registration(v, 1, vec![]);
                let object = request.iter_mut().find(|n| n.tag == SPLIT_KEY).unwrap();
                let block = fields(object)
                    .iter_mut()
                    .find(|n| n.tag == KEY_BLOCK)
                    .unwrap();
                set(block, Node::enumeration(CRYPTOGRAPHIC_ALGORITHM, algorithm));
                set(block, Node::int(CRYPTOGRAPHIC_LENGTH, bits));
                set(
                    block,
                    Node::structure(KEY_VALUE, vec![Node::bytes(KEY_MATERIAL, vec![7; 32])]),
                );
                assert_eq!(reason(&f.call(v, "alice", 3, request)), 7);
                assert!(f.engine.store.list("alice").unwrap().is_empty());
            }
        }
    }
}

/// Item Not Found in 1.x; Object Not Found (0x37) where the 2.x and draft 3.0
/// error tables list it (see src/protocol/not_found.rs).
fn not_found(v: Version) -> u32 {
    if v.0 >= 2 { 0x37 } else { 1 }
}
