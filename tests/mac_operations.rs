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
    ttlv::Node,
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
fn cp(algorithm: u32) -> Node {
    Node::structure(
        CRYPTOGRAPHIC_PARAMETERS,
        vec![Node::enumeration(CRYPTOGRAPHIC_ALGORITHM, algorithm)],
    )
}
fn cmac_cp() -> Node {
    Node::structure(
        CRYPTOGRAPHIC_PARAMETERS,
        vec![
            Node::enumeration(CRYPTOGRAPHIC_ALGORITHM, 3),
            Node::enumeration(BLOCK_CIPHER_MODE, 7),
        ],
    )
}
fn register(f: &mut Fixture, v: Version, algorithm: u32, key: &[u8], extra: Vec<Node>) -> String {
    let mut attrs = vec![Node::int(CRYPTOGRAPHIC_USAGE_MASK, 0x38c)];
    attrs.extend(extra);
    identifier(&f.call(
        v,
        "alice",
        3,
        vec![
            Node::enumeration(OBJECT_TYPE, 2),
            container(v, attrs),
            Node::structure(
                SYMMETRIC_KEY,
                vec![Node::structure(
                    KEY_BLOCK,
                    vec![
                        Node::enumeration(KEY_FORMAT_TYPE, 1),
                        Node::enumeration(CRYPTOGRAPHIC_ALGORITHM, algorithm),
                        Node::int(CRYPTOGRAPHIC_LENGTH, (key.len() * 8) as i32),
                        Node::structure(KEY_VALUE, vec![Node::bytes(KEY_MATERIAL, key.to_vec())]),
                    ],
                )],
            ),
        ],
    ))
}
fn active(f: &mut Fixture, v: Version, identifier: &str) {
    payload(&f.call(v, "alice", 18, vec![id(v, identifier)]));
}
fn mac(
    f: &mut Fixture,
    v: Version,
    identifier: &str,
    parameters: Option<Node>,
    data: &[u8],
) -> Vec<u8> {
    let mut fields = vec![id(v, identifier), Node::bytes(DATA, data.to_vec())];
    fields.extend(parameters);
    payload(&f.call(v, "alice", 35, fields))
        .required(MAC_DATA)
        .unwrap()
        .byte_string()
        .unwrap()
        .to_vec()
}
fn stored(f: &Fixture, identifier: &str) -> keytend_kmip_server::store::Object {
    f.engine.store.get("alice", identifier).unwrap().unwrap()
}
#[test]
fn published_aes_key_with_stored_hmac_parameters_and_explicit_override() {
    let mut f = Fixture::new();
    let v = Version(2, 1);
    let key = hex::decode("0123456789abcdef0123456789abcdef").unwrap();
    let k = register(&mut f, v, 3, &key, vec![cp(9)]);
    active(&mut f, v, &k);
    let data = hex::decode("01020304050607080910111213141516").unwrap();
    let expected =
        hex::decode("c911e78196d64c30f631bb079ea37b97a95936d4da764d6a171df030c895ecf9").unwrap();
    assert_eq!(mac(&mut f, v, &k, None, &data), expected);
    let verify = f.call(
        v,
        "alice",
        36,
        vec![
            id(v, &k),
            Node::bytes(DATA, data.clone()),
            Node::bytes(MAC_DATA, expected.clone()),
        ],
    );
    assert_eq!(
        payload(&verify)
            .required(VALIDITY_INDICATOR)
            .unwrap()
            .number()
            .unwrap(),
        1
    );
    let other = mac(&mut f, v, &k, Some(cp(10)), &data);
    assert_eq!(other.len(), 48);
    assert_eq!(
        other,
        keytend_kmip_server::crypto::authentication::compute(
            keytend_kmip_server::crypto::authentication::Mechanism::Hmac(7),
            &key,
            &data
        )
        .unwrap()
    );
    let before = stored(&f, &k);
    let invalid = f.call(
        v,
        "alice",
        35,
        vec![
            id(v, &k),
            Node::structure(
                CRYPTOGRAPHIC_PARAMETERS,
                vec![
                    Node::enumeration(CRYPTOGRAPHIC_ALGORITHM, 10),
                    Node::enumeration(HASHING_ALGORITHM, 6),
                ],
            ),
            Node::bytes(DATA, data),
        ],
    );
    assert_eq!(reason(&invalid), 7);
    assert_eq!(
        serde_json::to_value(before).unwrap(),
        serde_json::to_value(stored(&f, &k)).unwrap()
    );
    assert_eq!(mac(&mut f, v, &k, None, b"again").len(), 32);
}
#[test]
fn all_hmac_key_algorithms_and_operation_selection_across_editions() {
    use keytend_kmip_server::crypto::authentication::{self, Mechanism};
    let mut f = Fixture::new();
    let key = [0x0b; 16];
    let data = b"Hi There";
    for v in [
        Version(1, 2),
        Version(1, 3),
        Version(1, 4),
        Version(2, 0),
        Version(2, 1),
        Version(3, 0),
    ] {
        let aes = register(&mut f, v, 3, &key, vec![]);
        active(&mut f, v, &aes);
        for algorithm in [7, 8, 9, 10, 11, 12, 35, 36, 37, 38] {
            if algorithm >= 35 && v < Version(1, 4) {
                assert_eq!(
                    reason(&f.call(
                        v,
                        "alice",
                        35,
                        vec![id(v, &aes), cp(algorithm), Node::bytes(DATA, data.to_vec())]
                    )),
                    7
                );
                continue;
            }
            let hash = authentication::hmac_hash(algorithm).unwrap();
            let expected = authentication::compute(Mechanism::Hmac(hash), &key, data).unwrap();
            let h = register(&mut f, v, algorithm, &key, vec![]);
            active(&mut f, v, &h);
            assert_eq!(mac(&mut f, v, &h, None, data), expected);
            assert_eq!(mac(&mut f, v, &aes, Some(cp(algorithm)), data), expected);
            assert_eq!(stored(&f, &h).algorithm, algorithm);
        }
        let tag = mac(&mut f, v, &aes, Some(cmac_cp()), data);
        assert_eq!(
            tag,
            authentication::compute(Mechanism::Cmac, &key, data).unwrap()
        );
    }
}
#[test]
fn short_and_large_hmac_keys_factories_restore_and_split_preserve_material() {
    let mut f = Fixture::new();
    let v = Version(2, 1);
    for algorithm in [7, 8, 12, 35, 36, 37, 38] {
        for length in [1, 16, 131, 1024] {
            let key = vec![0xa5; length];
            let k = register(&mut f, v, algorithm, &key, vec![]);
            active(&mut f, v, &k);
            let expected = mac(&mut f, v, &k, None, b"durable");
            let export = payload(&f.call(v, "alice", 43, vec![id(v, &k)]))
                .children()
                .unwrap()
                .to_vec();
            payload(&f.call(
                v,
                "alice",
                19,
                vec![
                    id(v, &k),
                    Node::structure(
                        REVOCATION_REASON,
                        vec![Node::enumeration(REVOCATION_REASON_CODE, 1)],
                    ),
                ],
            ));
            payload(&f.call(v, "alice", 20, vec![id(v, &k)]));
            let mut restore = export;
            restore.push(Node::boolean(REPLACE_EXISTING, true));
            payload(&f.call(v, "alice", 42, restore));
            assert_eq!(mac(&mut f, v, &k, None, b"durable"), expected);
            let share = f.call(
                v,
                "alice",
                40,
                vec![
                    id(v, &k),
                    Node::enumeration(OBJECT_TYPE, 5),
                    Node::int(SPLIT_KEY_PARTS, 2),
                    Node::int(SPLIT_KEY_THRESHOLD, 2),
                    Node::enumeration(SPLIT_KEY_METHOD, 4),
                    container(v, vec![]),
                ],
            );
            let parts = payload(&share)
                .all(UNIQUE_IDENTIFIER)
                .map(|n| n.identifier_text().unwrap().to_owned())
                .collect::<Vec<_>>();
            let mut join = vec![Node::enumeration(OBJECT_TYPE, 2)];
            join.extend(parts.iter().map(|p| id(v, p)));
            let joined = identifier(&f.call(v, "alice", 41, join));
            assert_eq!(stored(&f, &joined).material, key);
            let new = f.call(
                v,
                "alice",
                1,
                vec![
                    Node::enumeration(OBJECT_TYPE, 2),
                    container(
                        v,
                        vec![
                            Node::enumeration(CRYPTOGRAPHIC_ALGORITHM, algorithm),
                            Node::int(CRYPTOGRAPHIC_LENGTH, (length * 8) as i32),
                            Node::int(CRYPTOGRAPHIC_USAGE_MASK, 0x180),
                        ],
                    ),
                ],
            );
            let new = identifier(&new);
            active(&mut f, v, &new);
            let replacement = identifier(&f.call(v, "alice", 4, vec![id(v, &new)]));
            assert_eq!(stored(&f, &replacement).material.len(), length);
            f.restart();
            assert_eq!(mac(&mut f, v, &k, None, b"durable"), expected);
        }
    }
}
#[test]
fn multipart_hmac_cmac_copy_rollback_parameter_binding_and_invalid_verification() {
    let mut f = Fixture::new();
    let v = Version(2, 1);
    let key = [0xaa; 32];
    let k = register(&mut f, v, 3, &key, vec![]);
    active(&mut f, v, &k);
    for parameters in [
        cp(7),
        cp(8),
        cp(12),
        cp(35),
        cp(36),
        cp(37),
        cp(38),
        cmac_cp(),
    ] {
        let expected = mac(&mut f, v, &k, Some(parameters.clone()), b"initial suffix");
        let init = f.call(
            v,
            "alice",
            35,
            vec![
                id(v, &k),
                parameters.clone(),
                Node::boolean(INIT_INDICATOR, true),
                Node::bytes(DATA, b"initial ".to_vec()),
            ],
        );
        let correlation = payload(&init).required(CORRELATION_VALUE).unwrap().clone();
        assert!(payload(&init).get(MAC_DATA).is_none());
        let before = serde_json::to_value(stored(&f, &k)).unwrap();
        let bad = f.call(
            v,
            "alice",
            35,
            vec![
                id(v, &k),
                cp(10),
                correlation.clone(),
                Node::bytes(DATA, b"discarded".to_vec()),
            ],
        );
        assert_eq!(reason(&bad), 7);
        assert_eq!(before, serde_json::to_value(stored(&f, &k)).unwrap());
        let req = request(
            v,
            vec![(
                35,
                vec![
                    id(v, &k),
                    correlation.clone(),
                    Node::boolean(FINAL_INDICATOR, true),
                    Node::bytes(DATA, b"discarded".to_vec()),
                ],
            )],
        );
        let failed = f
            .engine
            .process_with_grants_checked("alice", &req, None, &[], &mut |n| {
                if n.tag == RESPONSE_PAYLOAD {
                    Err(keytend_kmip_server::protocol::Failure::new(
                        2,
                        "injected transport failure",
                    ))
                } else {
                    Ok(())
                }
            })
            .unwrap();
        assert_eq!(reason(&failed), 2);
        let final_response = f.call(
            v,
            "alice",
            35,
            vec![
                id(v, &k),
                correlation,
                Node::boolean(FINAL_INDICATOR, true),
                Node::bytes(DATA, b"suffix".to_vec()),
            ],
        );
        assert_eq!(
            payload(&final_response)
                .required(MAC_DATA)
                .unwrap()
                .byte_string()
                .unwrap(),
            expected
        );
        let init = f.call(
            v,
            "alice",
            36,
            vec![
                id(v, &k),
                parameters,
                Node::boolean(INIT_INDICATOR, true),
                Node::bytes(DATA, b"initial ".to_vec()),
                Node::bytes(MAC_DATA, vec![0; expected.len()]),
            ],
        );
        let correlation = payload(&init).required(CORRELATION_VALUE).unwrap().clone();
        assert!(payload(&init).get(VALIDITY_INDICATOR).is_none());
        let end = f.call(
            v,
            "alice",
            36,
            vec![
                id(v, &k),
                correlation,
                Node::boolean(FINAL_INDICATOR, true),
                Node::bytes(DATA, b"suffix".to_vec()),
            ],
        );
        assert_eq!(
            payload(&end)
                .required(VALIDITY_INDICATOR)
                .unwrap()
                .number()
                .unwrap(),
            2
        );
    }
}
#[test]
fn generation_budget_bad_parameters_and_lifecycle_are_enforced_for_cmac_and_hmac() {
    let mut f = Fixture::new();
    let v = Version(2, 1);
    let limits = Node::structure(
        USAGE_LIMITS,
        vec![
            Node::long(USAGE_LIMITS_TOTAL, 2),
            Node::enumeration(USAGE_LIMITS_UNIT, 2),
        ],
    );
    let k = register(&mut f, v, 3, &[1; 16], vec![limits]);
    assert!(
        f.call(
            v,
            "alice",
            35,
            vec![id(v, &k), cp(9), Node::bytes(DATA, vec![])]
        )
        .required(BATCH_ITEM)
        .unwrap()
        .get(RESULT_REASON)
        .is_some()
    );
    active(&mut f, v, &k);
    for parameters in [
        Node::structure(
            CRYPTOGRAPHIC_PARAMETERS,
            vec![
                Node::enumeration(CRYPTOGRAPHIC_ALGORITHM, 3),
                Node::enumeration(BLOCK_CIPHER_MODE, 7),
                Node::enumeration(HASHING_ALGORITHM, 6),
            ],
        ),
        Node::structure(
            CRYPTOGRAPHIC_PARAMETERS,
            vec![
                Node::enumeration(CRYPTOGRAPHIC_ALGORITHM, 9),
                Node::enumeration(BLOCK_CIPHER_MODE, 7),
            ],
        ),
    ] {
        let before = serde_json::to_value(stored(&f, &k)).unwrap();
        assert_eq!(
            reason(&f.call(
                v,
                "alice",
                35,
                vec![id(v, &k), parameters, Node::bytes(DATA, vec![])]
            )),
            7
        );
        assert_eq!(before, serde_json::to_value(stored(&f, &k)).unwrap());
    }
    assert_eq!(
        reason(&f.call(
            v,
            "bob",
            35,
            vec![id(v, &k), cp(9), Node::bytes(DATA, vec![])]
        )),
        not_found(v)
    );
    let tag = mac(&mut f, v, &k, Some(cp(9)), b"");
    mac(&mut f, v, &k, Some(cmac_cp()), b"");
    let verify = f.call(
        v,
        "alice",
        36,
        vec![
            id(v, &k),
            cp(9),
            Node::bytes(DATA, vec![]),
            Node::bytes(MAC_DATA, tag),
        ],
    );
    assert_eq!(
        payload(&verify)
            .required(VALIDITY_INDICATOR)
            .unwrap()
            .number()
            .unwrap(),
        1
    );
    assert_eq!(
        reason(&f.call(
            v,
            "alice",
            35,
            vec![id(v, &k), cp(9), Node::bytes(DATA, vec![])]
        )),
        26
    );
}
#[test]
fn hmac_derivation_and_version_gates_use_the_same_algorithm_inventory() {
    use keytend_kmip_server::crypto::authentication;
    let mut f = Fixture::new();
    let v = Version(2, 1);
    let bytes = [0xa5; 16];
    for algorithm in [7, 8, 12, 35, 36, 37, 38] {
        let source = register(&mut f, v, algorithm, &bytes, vec![]);
        active(&mut f, v, &source);
        let fields = vec![
            id(v, &source),
            Node::enumeration(OBJECT_TYPE, 2),
            Node::enumeration(DERIVATION_METHOD, 3),
            Node::structure(
                DERIVATION_PARAMETERS,
                vec![Node::bytes(DERIVATION_DATA, b"derive".to_vec())],
            ),
            container(
                v,
                vec![
                    Node::enumeration(CRYPTOGRAPHIC_ALGORITHM, 3),
                    Node::int(CRYPTOGRAPHIC_LENGTH, 128),
                    Node::int(CRYPTOGRAPHIC_USAGE_MASK, 12),
                ],
            ),
        ];
        let derived = identifier(&f.call(v, "alice", 5, fields));
        let expected = authentication::compute(
            authentication::Mechanism::Hmac(authentication::hmac_hash(algorithm).unwrap()),
            &bytes,
            b"derive",
        )
        .unwrap();
        assert_eq!(stored(&f, &derived).material, &expected[..16]);
    }
    for old in [Version(1, 0), Version(1, 1), Version(1, 2), Version(1, 3)] {
        let fields = vec![
            Node::enumeration(OBJECT_TYPE, 2),
            container(
                old,
                vec![
                    Node::enumeration(CRYPTOGRAPHIC_ALGORITHM, 35),
                    Node::int(CRYPTOGRAPHIC_LENGTH, 128),
                ],
            ),
        ];
        assert_eq!(reason(&f.call(old, "alice", 1, fields)), 7);
    }
}

/// Item Not Found in 1.x; Object Not Found (0x37) where the 2.x and draft 3.0
/// error tables list it (see src/protocol/not_found.rs).
fn not_found(v: Version) -> u32 {
    if v.0 >= 2 { 0x37 } else { 1 }
}
