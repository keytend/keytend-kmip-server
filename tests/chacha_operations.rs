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
    protocol::{Engine, Version},
    store::Store,
    tags::*,
    ttlv::Node,
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
        let engine = Engine::new(Store::open(&dir.path().join("store"), &key).unwrap(), true);
        Self { _dir: dir, engine }
    }
    fn call(&mut self, v: Version, op: u32, fields: Vec<Node>) -> Node {
        self.engine
            .process("owner", &message(v, op, fields))
            .unwrap()
    }
}
fn message(v: Version, op: u32, fields: Vec<Node>) -> Node {
    let mut header = vec![v.node()];
    if v.0 < 3 {
        header.push(Node::int(BATCH_COUNT, 1));
    }
    Node::structure(
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
    )
}
fn id(v: Version, identifier: &str) -> Node {
    if v.0 >= 3 {
        Node::reference(UNIQUE_IDENTIFIER, identifier)
    } else {
        Node::text(UNIQUE_IDENTIFIER, identifier)
    }
}
fn body(n: &Node) -> &Node {
    let item = n.required(BATCH_ITEM).unwrap();
    assert_eq!(
        item.required(RESULT_STATUS).unwrap().number().unwrap(),
        0,
        "{}",
        serde_json::to_string(n).unwrap()
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
                                value: a.value,
                            },
                        ],
                    )
                })
                .collect(),
        )
    }
}

fn register(f: &mut Fixture, v: Version, algorithm: u32, key: Vec<u8>, usage: u32) -> Node {
    f.call(
        v,
        3,
        vec![
            Node::enumeration(OBJECT_TYPE, 2),
            container(
                v,
                vec![
                    Node::int(CRYPTOGRAPHIC_USAGE_MASK, usage as i32),
                    Node::date(ACTIVATION_DATE, 0),
                    cp(algorithm),
                ],
            ),
            Node::structure(
                SYMMETRIC_KEY,
                vec![Node::structure(
                    KEY_BLOCK,
                    vec![
                        Node::enumeration(KEY_FORMAT_TYPE, 1),
                        Node::enumeration(CRYPTOGRAPHIC_ALGORITHM, algorithm),
                        Node::int(CRYPTOGRAPHIC_LENGTH, (key.len() * 8) as i32),
                        Node::structure(KEY_VALUE, vec![Node::bytes(KEY_MATERIAL, key)]),
                    ],
                )],
            ),
        ],
    )
}
fn identifier(n: &Node) -> String {
    body(n)
        .required(UNIQUE_IDENTIFIER)
        .unwrap()
        .identifier_text()
        .unwrap()
        .to_owned()
}
fn cp(algorithm: u32) -> Node {
    Node::structure(
        CRYPTOGRAPHIC_PARAMETERS,
        if algorithm == 30 {
            vec![
                Node::enumeration(BLOCK_CIPHER_MODE, 18),
                Node::int(TAG_LENGTH, 16),
            ]
        } else {
            vec![]
        },
    )
}
fn bytes(s: &str) -> Vec<u8> {
    hex::decode(s).unwrap()
}
// Published key, nonce, AAD, plaintext, ciphertext and authentication tag.
type PublishedVector = (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>);

fn vector(algorithm: u32) -> PublishedVector {
    if algorithm == 28 {
        return (
            vec![0; 32],
            vec![0; 8],
            vec![],
            vec![0; 64],
            bytes(
                "76b8e0ada0f13d90405d6ae55386bd28bdd219b8a08ded1aa836efcc8b770dc7da41597c5157488d7724e03fb8d84a376a43b8f41518a11cc387b669b2ee6586",
            ),
            vec![],
        );
    }
    (
        bytes("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f"),
        bytes("070000004041424344454647"),
        bytes("50515253c0c1c2c3c4c5c6c7"),
        bytes(
            "4c616469657320616e642047656e746c656d656e206f662074686520636c617373206f66202739393a204966204920636f756c64206f6666657220796f75206f6e6c79206f6e652074697020666f7220746865206675747572652c2073756e73637265656e20776f756c642062652069742e",
        ),
        bytes(
            "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d63dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b3692ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc3ff4def08e4b7a9de576d26586cec64b6116",
        ),
        bytes("1ae10b594f09e26a7e902ecbd0600691"),
    )
}
#[test]
fn official_vectors_across_final_editions_and_draft_one_shot_and_multipart() {
    for v in [Version(1, 4), Version(2, 0), Version(2, 1), Version(3, 0)] {
        for algorithm in [28, 30] {
            let mut f = Fixture::new();
            let (key, nonce, aad, plain, expected, tag) = vector(algorithm);
            let name = identifier(&register(&mut f, v, algorithm, key, 12));
            let mut fields = vec![
                id(v, &name),
                cp(algorithm),
                Node::bytes(IV_COUNTER_NONCE, nonce.clone()),
                Node::bytes(DATA, plain.clone()),
            ];
            if algorithm == 30 {
                fields.push(Node::bytes(
                    AUTHENTICATED_ENCRYPTION_ADDITIONAL_DATA,
                    aad.clone(),
                ));
            }
            let encrypted = f.call(v, 31, fields.clone());
            let p = body(&encrypted);
            assert_eq!(p.required(DATA).unwrap().byte_string().unwrap(), expected);
            if algorithm == 30 {
                assert_eq!(
                    p.required(AUTHENTICATED_ENCRYPTION_TAG)
                        .unwrap()
                        .byte_string()
                        .unwrap(),
                    tag
                );
            }
            fields.retain(|n| n.tag != DATA);
            fields.push(Node::bytes(DATA, expected.clone()));
            if algorithm == 30 {
                fields.push(Node::bytes(AUTHENTICATED_ENCRYPTION_TAG, tag.clone()));
            }
            assert_eq!(
                body(&f.call(v, 32, fields.clone()))
                    .required(DATA)
                    .unwrap()
                    .byte_string()
                    .unwrap(),
                plain
            );
            if algorithm == 30 {
                let bad = fields
                    .iter_mut()
                    .find(|n| n.tag == AUTHENTICATED_ENCRYPTION_TAG)
                    .unwrap();
                *bad = Node::bytes(AUTHENTICATED_ENCRYPTION_TAG, vec![0; 16]);
                assert_eq!(reason(&f.call(v, 32, fields)), 10);
            }
            // Same published bytes, different chunk boundary and immutable context snapshot path.
            let mut init = vec![
                id(v, &name),
                cp(algorithm),
                Node::bytes(IV_COUNTER_NONCE, nonce.clone()),
                Node::bytes(DATA, plain[..17].to_vec()),
                Node::boolean(INIT_INDICATOR, true),
            ];
            if algorithm == 30 {
                init.push(Node::bytes(
                    AUTHENTICATED_ENCRYPTION_ADDITIONAL_DATA,
                    aad.clone(),
                ));
            }
            let first = f.call(v, 31, init);
            let token = body(&first)
                .required(CORRELATION_VALUE)
                .unwrap()
                .byte_string()
                .unwrap()
                .to_vec();
            let prefix = body(&first)
                .get(DATA)
                .map(|n| n.byte_string().unwrap().to_vec())
                .unwrap_or_default();
            let last = f.call(
                v,
                31,
                vec![
                    id(v, &name),
                    Node::bytes(CORRELATION_VALUE, token),
                    Node::bytes(DATA, plain[17..].to_vec()),
                    Node::boolean(FINAL_INDICATOR, true),
                ],
            );
            assert_eq!(
                [
                    prefix,
                    body(&last)
                        .required(DATA)
                        .unwrap()
                        .byte_string()
                        .unwrap()
                        .to_vec()
                ]
                .concat(),
                expected
            );
            if algorithm == 30 {
                assert_eq!(
                    body(&last)
                        .required(AUTHENTICATED_ENCRYPTION_TAG)
                        .unwrap()
                        .byte_string()
                        .unwrap(),
                    tag
                );
            }
            let mut init = vec![
                id(v, &name),
                cp(algorithm),
                Node::bytes(IV_COUNTER_NONCE, nonce),
                Node::bytes(DATA, expected[..17].to_vec()),
                Node::boolean(INIT_INDICATOR, true),
            ];
            if algorithm == 30 {
                init.extend([
                    Node::bytes(AUTHENTICATED_ENCRYPTION_ADDITIONAL_DATA, aad),
                    Node::bytes(AUTHENTICATED_ENCRYPTION_TAG, tag),
                ]);
            }
            let first = f.call(v, 32, init);
            let p = body(&first);
            let token = p
                .required(CORRELATION_VALUE)
                .unwrap()
                .byte_string()
                .unwrap()
                .to_vec();
            let prefix = p
                .get(DATA)
                .map(|n| n.byte_string().unwrap().to_vec())
                .unwrap_or_default();
            if algorithm == 30 {
                assert!(prefix.is_empty());
            }
            let last = f.call(
                v,
                32,
                vec![
                    id(v, &name),
                    Node::bytes(CORRELATION_VALUE, token),
                    Node::bytes(DATA, expected[17..].to_vec()),
                    Node::boolean(FINAL_INDICATOR, true),
                ],
            );
            assert_eq!(
                [
                    prefix,
                    body(&last)
                        .required(DATA)
                        .unwrap()
                        .byte_string()
                        .unwrap()
                        .to_vec()
                ]
                .concat(),
                plain
            );
        }
    }
}
#[test]
fn legacy_and_invalid_keys_are_refused_without_registration() {
    for v in [Version(1, 1), Version(1, 2), Version(1, 3)] {
        for algorithm in [28, 30] {
            let mut f = Fixture::new();
            assert_ne!(reason(&register(&mut f, v, algorithm, vec![0; 32], 12)), 0);
            assert!(f.engine.store.list("owner").unwrap().is_empty());
        }
    }
    let mut f = Fixture::new();
    for algorithm in [28, 30] {
        for length in [16, 24, 31, 33] {
            assert_ne!(
                reason(&register(
                    &mut f,
                    Version(2, 1),
                    algorithm,
                    vec![0; length],
                    12
                )),
                0
            );
        }
    }
    assert!(f.engine.store.list("owner").unwrap().is_empty());
}

#[test]
fn random_nonce_stored_parameters_and_policy_denials() {
    for v in [Version(1, 4), Version(2, 0), Version(2, 1), Version(3, 0)] {
        for algorithm in [28, 30] {
            let mut f = Fixture::new();
            let name = identifier(&register(&mut f, v, algorithm, vec![7; 32], 4));
            let mut parameters = cp(algorithm);
            if let keytend_kmip_server::ttlv::Value::Structure(ref mut fields) = parameters.value {
                fields.push(Node::boolean(RANDOM_IV, true));
            }
            let response = f.call(
                v,
                31,
                vec![id(v, &name), parameters, Node::bytes(DATA, vec![5; 23])],
            );
            let p = body(&response);
            assert_eq!(
                p.required(IV_COUNTER_NONCE)
                    .unwrap()
                    .byte_string()
                    .unwrap()
                    .len(),
                12
            );
            assert_eq!(p.required(DATA).unwrap().byte_string().unwrap().len(), 23);
            let unauthorized = f
                .engine
                .process(
                    "foreign",
                    &message(
                        v,
                        31,
                        vec![
                            id(v, &name),
                            cp(algorithm),
                            Node::bytes(IV_COUNTER_NONCE, vec![0; 12]),
                            Node::bytes(DATA, vec![1]),
                        ],
                    ),
                )
                .unwrap();
            assert_eq!(reason(&unauthorized), not_found(v));
            let denied = f.call(
                v,
                32,
                vec![
                    id(v, &name),
                    cp(algorithm),
                    Node::bytes(IV_COUNTER_NONCE, vec![0; 12]),
                    Node::bytes(DATA, vec![1]),
                ],
            );
            assert_eq!(reason(&denied), if v.0 >= 2 { 0x29 } else { 12 });
            // Omit request parameters: use the stored instance, while an explicit
            // conflicting request must not silently merge with or replace it.
            body(&f.call(
                v,
                31,
                vec![
                    id(v, &name),
                    Node::bytes(IV_COUNTER_NONCE, vec![0; 12]),
                    Node::bytes(DATA, vec![3; 5]),
                ],
            ));
            let conflicting = Node::structure(
                CRYPTOGRAPHIC_PARAMETERS,
                vec![Node::enumeration(CRYPTOGRAPHIC_ALGORITHM, 3)],
            );
            assert_ne!(
                reason(&f.call(
                    v,
                    31,
                    vec![
                        id(v, &name),
                        conflicting,
                        Node::bytes(IV_COUNTER_NONCE, vec![0; 12]),
                        Node::bytes(DATA, vec![1])
                    ]
                )),
                0
            );
            body(&f.call(v, 21, vec![id(v, &name)]));
            assert_eq!(
                reason(&f.call(
                    v,
                    31,
                    vec![
                        id(v, &name),
                        cp(algorithm),
                        Node::bytes(IV_COUNTER_NONCE, vec![0; 12]),
                        Node::bytes(DATA, vec![1])
                    ]
                )),
                13
            );
            body(&f.call(v, 22, vec![id(v, &name)]));
            body(&f.call(
                v,
                19,
                vec![
                    id(v, &name),
                    Node::structure(
                        REVOCATION_REASON,
                        vec![Node::enumeration(REVOCATION_REASON_CODE, 1)],
                    ),
                ],
            ));
            assert_ne!(
                reason(&f.call(
                    v,
                    31,
                    vec![
                        id(v, &name),
                        cp(algorithm),
                        Node::bytes(IV_COUNTER_NONCE, vec![0; 12]),
                        Node::bytes(DATA, vec![1])
                    ]
                )),
                0
            );
        }
    }
}

#[test]
fn invalid_chacha_aead_and_counter_parameters_are_not_ignored() {
    let mut f = Fixture::new();
    let v = Version(2, 1);
    for algorithm in [28, 30] {
        let name = identifier(&register(&mut f, v, algorithm, vec![1; 32], 12));
        for field in [
            Node::int(TAG_LENGTH, 12),
            Node::int(IV_LENGTH, 128),
            Node::enumeration(PADDING_METHOD, 3),
            Node::enumeration(BLOCK_CIPHER_MODE, 1),
        ] {
            let response = f.call(
                v,
                31,
                vec![
                    id(v, &name),
                    Node::structure(CRYPTOGRAPHIC_PARAMETERS, vec![field]),
                    Node::bytes(IV_COUNTER_NONCE, vec![0; 12]),
                    Node::bytes(DATA, vec![1; 64]),
                ],
            );
            assert_ne!(reason(&response), 0);
        }
        for length in [0, 1, 7, 9, 16] {
            assert_ne!(
                reason(&f.call(
                    v,
                    31,
                    vec![
                        id(v, &name),
                        cp(algorithm),
                        Node::bytes(IV_COUNTER_NONCE, vec![0; length]),
                        Node::bytes(DATA, vec![1])
                    ]
                )),
                0
            );
        }
    }
    let raw = identifier(&register(&mut f, v, 28, vec![0; 32], 12));
    assert_eq!(
        reason(&f.call(
            v,
            31,
            vec![
                id(v, &raw),
                Node::structure(
                    CRYPTOGRAPHIC_PARAMETERS,
                    vec![Node::int(COUNTER_LENGTH, 64)]
                ),
                Node::bytes(IV_COUNTER_NONCE, vec![0; 12]),
                Node::bytes(DATA, vec![0; 64])
            ]
        )),
        7
    );
    let response = f.call(
        v,
        31,
        vec![
            id(v, &raw),
            Node::structure(
                CRYPTOGRAPHIC_PARAMETERS,
                vec![
                    Node::int(INITIAL_COUNTER_VALUE, 1),
                    Node::int(COUNTER_LENGTH, 32),
                ],
            ),
            Node::bytes(
                IV_COUNTER_NONCE,
                hex::decode("000000090000004a00000000").unwrap(),
            ),
            Node::bytes(DATA, vec![0; 64]),
        ],
    );
    // The key here is all zero; compare a separately parameterized provider
    // result only for binding of the declared wire counter, not vector credit.
    let expected = keytend_kmip_server::crypto::chacha::crypt(
        true,
        &[0; 32],
        keytend_kmip_server::crypto::chacha::Parameters {
            authenticated: false,
            initial_counter: 1,
        },
        &hex::decode("000000090000004a00000000").unwrap(),
        &[0; 64],
        &[],
        None,
    )
    .unwrap()
    .0;
    assert_eq!(
        body(&response)
            .required(DATA)
            .unwrap()
            .byte_string()
            .unwrap(),
        &*expected
    );
}

fn key_bytes(response: &Node) -> &[u8] {
    let material = body(response)
        .required(SYMMETRIC_KEY)
        .unwrap()
        .required(KEY_BLOCK)
        .unwrap()
        .required(KEY_VALUE)
        .unwrap()
        .required(KEY_MATERIAL)
        .unwrap();
    material.get(KEY).unwrap_or(material).byte_string().unwrap()
}

#[test]
fn chacha_create_rekey_derive_and_protected_registration_preserve_material() {
    for v in [Version(1, 4), Version(2, 0), Version(2, 1), Version(3, 0)] {
        for algorithm in [28, 30] {
            let mut f = Fixture::new();
            let generated = identifier(&f.call(
                v,
                1,
                vec![
                    Node::enumeration(OBJECT_TYPE, 2),
                    container(
                        v,
                        vec![
                            Node::enumeration(CRYPTOGRAPHIC_ALGORITHM, algorithm),
                            Node::int(CRYPTOGRAPHIC_LENGTH, 256),
                            Node::int(CRYPTOGRAPHIC_USAGE_MASK, 12),
                        ],
                    ),
                ],
            ));
            let original = key_bytes(&f.call(v, 10, vec![id(v, &generated)])).to_vec();
            assert_eq!(original.len(), 32);
            let replacement =
                identifier(&f.call(v, 4, vec![id(v, &generated), container(v, vec![])]));
            let replaced = key_bytes(&f.call(v, 10, vec![id(v, &replacement)])).to_vec();
            assert_eq!(replaced.len(), 32);
            assert_ne!(original, replaced);
            assert_eq!(key_bytes(&f.call(v, 10, vec![id(v, &generated)])), original);

            let password = identifier(&f.call(
                v,
                3,
                vec![
                    Node::enumeration(OBJECT_TYPE, 7),
                    container(
                        v,
                        vec![
                            Node::int(CRYPTOGRAPHIC_USAGE_MASK, 512),
                            Node::date(ACTIVATION_DATE, 0),
                        ],
                    ),
                    Node::structure(
                        SECRET_DATA,
                        vec![
                            Node::enumeration(SECRET_DATA_TYPE, 1),
                            Node::structure(
                                KEY_BLOCK,
                                vec![
                                    Node::enumeration(KEY_FORMAT_TYPE, 1),
                                    Node::structure(
                                        KEY_VALUE,
                                        vec![Node::bytes(KEY_MATERIAL, b"passwd".to_vec())],
                                    ),
                                ],
                            ),
                        ],
                    ),
                ],
            ));
            let derived = identifier(&f.call(
                v,
                5,
                vec![
                    Node::enumeration(OBJECT_TYPE, 2),
                    id(v, &password),
                    Node::enumeration(DERIVATION_METHOD, 1),
                    Node::structure(
                        DERIVATION_PARAMETERS,
                        vec![
                            Node::structure(
                                CRYPTOGRAPHIC_PARAMETERS,
                                vec![Node::enumeration(HASHING_ALGORITHM, 6)],
                            ),
                            Node::bytes(SALT, b"salt".to_vec()),
                            Node::int(ITERATION_COUNT, 1),
                        ],
                    ),
                    container(
                        v,
                        vec![
                            Node::enumeration(CRYPTOGRAPHIC_ALGORITHM, algorithm),
                            Node::int(CRYPTOGRAPHIC_LENGTH, 256),
                            Node::int(CRYPTOGRAPHIC_USAGE_MASK, 12),
                            cp(algorithm),
                        ],
                    ),
                ],
            ));
            // First 32 bytes of RFC 7914 section 11's PBKDF2-HMAC-SHA256 vector.
            let expected =
                bytes("55ac046e56e3089fec1691c22544b605f94185216dde0465e68b9d57c20dacbc");
            assert_eq!(key_bytes(&f.call(v, 10, vec![id(v, &derived)])), expected);
            assert_eq!(
                key_bytes(&f.call(
                    v,
                    10,
                    vec![id(v, &derived), Node::enumeration(KEY_FORMAT_TYPE, 7)]
                )),
                expected
            );

            let kek = identifier(&f.call(
                v,
                3,
                vec![
                    Node::enumeration(OBJECT_TYPE, 2),
                    container(
                        v,
                        vec![
                            Node::int(CRYPTOGRAPHIC_USAGE_MASK, 48),
                            Node::date(ACTIVATION_DATE, 0),
                            Node::structure(
                                CRYPTOGRAPHIC_PARAMETERS,
                                vec![Node::enumeration(BLOCK_CIPHER_MODE, 13)],
                            ),
                        ],
                    ),
                    Node::structure(
                        SYMMETRIC_KEY,
                        vec![Node::structure(
                            KEY_BLOCK,
                            vec![
                                Node::enumeration(KEY_FORMAT_TYPE, 1),
                                Node::enumeration(CRYPTOGRAPHIC_ALGORITHM, 3),
                                Node::int(CRYPTOGRAPHIC_LENGTH, 256),
                                Node::structure(
                                    KEY_VALUE,
                                    vec![Node::bytes(KEY_MATERIAL, vec![0x42; 32])],
                                ),
                            ],
                        )],
                    ),
                ],
            ));
            let wrapped = f.call(
                v,
                10,
                vec![
                    id(v, &derived),
                    Node::structure(
                        KEY_WRAPPING_SPECIFICATION,
                        vec![
                            Node::enumeration(WRAPPING_METHOD, 1),
                            Node::enumeration(ENCODING_OPTION, 1),
                            Node::structure(
                                ENCRYPTION_KEY_INFORMATION,
                                vec![
                                    id(v, &kek),
                                    Node::structure(
                                        CRYPTOGRAPHIC_PARAMETERS,
                                        vec![Node::enumeration(BLOCK_CIPHER_MODE, 13)],
                                    ),
                                ],
                            ),
                        ],
                    ),
                ],
            );
            let envelope = body(&wrapped).required(SYMMETRIC_KEY).unwrap().clone();
            let attrs = || {
                container(
                    v,
                    vec![Node::int(CRYPTOGRAPHIC_USAGE_MASK, 12), cp(algorithm)],
                )
            };
            let imported = identifier(&f.call(
                v,
                3,
                vec![Node::enumeration(OBJECT_TYPE, 2), attrs(), envelope.clone()],
            ));
            assert_eq!(key_bytes(&f.call(v, 10, vec![id(v, &imported)])), expected);

            let mut corrupted = envelope;
            let keytend_kmip_server::ttlv::Value::Structure(ref mut outer) = corrupted.value else {
                panic!("key")
            };
            let keytend_kmip_server::ttlv::Value::Structure(ref mut block) = outer[0].value else {
                panic!("block")
            };
            let value = block.iter_mut().find(|n| n.tag == KEY_VALUE).unwrap();
            let keytend_kmip_server::ttlv::Value::ByteString(ref mut ciphertext) = value.value
            else {
                panic!("ciphertext")
            };
            ciphertext[0] ^= 1;
            let before = f.engine.store.list("owner").unwrap().len();
            assert_eq!(
                reason(&f.call(
                    v,
                    3,
                    vec![Node::enumeration(OBJECT_TYPE, 2), attrs(), corrupted]
                )),
                10
            );
            assert_eq!(f.engine.store.list("owner").unwrap().len(), before);
            f.engine = Engine::new(
                Store::open(&f._dir.path().join("store"), &f._dir.path().join("master")).unwrap(),
                true,
            );
            assert_eq!(key_bytes(&f.call(v, 10, vec![id(v, &imported)])), expected);
            assert_eq!(
                key_bytes(&f.call(v, 10, vec![id(v, &replacement)])),
                replaced
            );
        }
    }
}

/// Item Not Found in 1.x; Object Not Found (0x37) where the 2.x and draft 3.0
/// error tables list it (see src/protocol/not_found.rs).
fn not_found(v: Version) -> u32 {
    if v.0 >= 2 { 0x37 } else { 1 }
}
