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

const UNRESTRICTED: u32 = 0x20_0000;
const KEY: [u8; 16] = [
    0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c,
];
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
        let engine = Engine::new(Store::open(&dir.path().join("store"), &key).unwrap(), true);
        Self { dir, engine }
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
fn register(f: &mut Fixture, v: Version, usage: u32, limits: bool) -> String {
    let mut attrs = vec![
        Node::int(CRYPTOGRAPHIC_USAGE_MASK, usage as i32),
        Node::structure(
            CRYPTOGRAPHIC_PARAMETERS,
            vec![Node::enumeration(BLOCK_CIPHER_MODE, 13)],
        ),
    ];
    if limits {
        attrs.push(Node::structure(
            USAGE_LIMITS,
            vec![
                Node::long(USAGE_LIMITS_TOTAL, 3),
                Node::enumeration(USAGE_LIMITS_UNIT, 2),
            ],
        ));
    }
    body(&f.call(
        v,
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
                        Node::enumeration(CRYPTOGRAPHIC_ALGORITHM, 3),
                        Node::int(CRYPTOGRAPHIC_LENGTH, 128),
                        Node::structure(KEY_VALUE, vec![Node::bytes(KEY_MATERIAL, KEY.to_vec())]),
                    ],
                )],
            ),
        ],
    ))
    .required(UNIQUE_IDENTIFIER)
    .unwrap()
    .identifier_text()
    .unwrap()
    .to_string()
}
fn cbc() -> Node {
    Node::structure(
        CRYPTOGRAPHIC_PARAMETERS,
        vec![
            Node::enumeration(CRYPTOGRAPHIC_ALGORITHM, 3),
            Node::enumeration(BLOCK_CIPHER_MODE, 1),
            Node::enumeration(PADDING_METHOD, 1),
        ],
    )
}
fn encrypt(f: &mut Fixture, v: Version, identifier: &str) -> Node {
    f.call(
        v,
        31,
        vec![
            id(v, identifier),
            cbc(),
            Node::bytes(IV_COUNTER_NONCE, vec![0; 16]),
            Node::bytes(DATA, vec![7; 16]),
        ],
    )
}
#[test]
fn unrestricted_is_a_versioned_permission_and_preserves_literal_metadata() {
    for v in [Version(2, 0), Version(2, 1), Version(3, 0)] {
        for mask in [UNRESTRICTED, UNRESTRICTED | 2] {
            let mut f = Fixture::new();
            let key = register(&mut f, v, mask, false);
            assert_eq!(reason(&encrypt(&mut f, v, &key)), 0x43);
            body(&f.call(v, 18, vec![id(v, &key)]));
            let request = vec![
                id(v, &key),
                Node::int(CRYPTOGRAPHIC_USAGE_MASK, 4 | 8 | 16 | 32 | 128 | 256 | 512),
            ];
            body(&f.call(v, 9, request));
            let result = encrypt(&mut f, v, &key);
            let cipher = body(&result)
                .required(DATA)
                .unwrap()
                .byte_string()
                .unwrap()
                .to_vec();
            assert_eq!(
                cipher,
                openssl::symm::encrypt(
                    openssl::symm::Cipher::aes_128_cbc(),
                    &KEY,
                    Some(&[0; 16]),
                    &[7; 16]
                )
                .unwrap()[..16]
            );
            let plain = f.call(
                v,
                32,
                vec![
                    id(v, &key),
                    cbc(),
                    Node::bytes(IV_COUNTER_NONCE, vec![0; 16]),
                    Node::bytes(DATA, cipher),
                ],
            );
            assert_eq!(
                body(&plain).required(DATA).unwrap().byte_string().unwrap(),
                [7; 16]
            );
            let cmac = Node::structure(
                CRYPTOGRAPHIC_PARAMETERS,
                vec![
                    Node::enumeration(CRYPTOGRAPHIC_ALGORITHM, 3),
                    Node::enumeration(BLOCK_CIPHER_MODE, 7),
                ],
            );
            let mac = f.call(
                v,
                35,
                vec![id(v, &key), cmac.clone(), Node::bytes(DATA, vec![])],
            );
            let mac = body(&mac)
                .required(MAC_DATA)
                .unwrap()
                .byte_string()
                .unwrap()
                .to_vec();
            assert_eq!(hex::encode(&mac), "bb1d6929e95937287fa37d129b756746");
            let verified = f.call(
                v,
                36,
                vec![
                    id(v, &key),
                    cmac,
                    Node::bytes(DATA, vec![]),
                    Node::bytes(MAC_DATA, mac),
                ],
            );
            assert_eq!(
                body(&verified)
                    .required(VALIDITY_INDICATOR)
                    .unwrap()
                    .number()
                    .unwrap(),
                1
            );
            assert_eq!(
                f.engine.store.get("owner", &key).unwrap().unwrap().usage,
                mask
            );
            let target = register(&mut f, v, 12, false);
            let wrapped = f.call(
                v,
                10,
                vec![
                    id(v, &target),
                    Node::structure(
                        KEY_WRAPPING_SPECIFICATION,
                        vec![
                            Node::enumeration(WRAPPING_METHOD, 1),
                            Node::enumeration(ENCODING_OPTION, 1),
                            Node::structure(
                                ENCRYPTION_KEY_INFORMATION,
                                vec![
                                    id(v, &key),
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
            let object = body(&wrapped).required(SYMMETRIC_KEY).unwrap();
            let value = object
                .required(KEY_BLOCK)
                .unwrap()
                .required(KEY_VALUE)
                .unwrap()
                .byte_string()
                .unwrap();
            assert_eq!(
                keytend_kmip_server::crypto::wrapping::aes(&KEY, value, false, false)
                    .unwrap()
                    .as_slice(),
                KEY
            );
            let restored = f.call(
                v,
                3,
                vec![
                    Node::enumeration(OBJECT_TYPE, 2),
                    container(v, vec![Node::int(CRYPTOGRAPHIC_USAGE_MASK, 12)]),
                    object.clone(),
                ],
            );
            let restored = body(&restored)
                .required(UNIQUE_IDENTIFIER)
                .unwrap()
                .identifier_text()
                .unwrap();
            assert_eq!(
                f.engine
                    .store
                    .get("owner", restored)
                    .unwrap()
                    .unwrap()
                    .material,
                KEY
            );
        }
        let mut f = Fixture::new();
        let registered = f.call(
            v,
            3,
            vec![
                Node::enumeration(OBJECT_TYPE, 7),
                container(
                    v,
                    vec![
                        Node::int(CRYPTOGRAPHIC_USAGE_MASK, UNRESTRICTED as i32),
                        Node::structure(
                            USAGE_LIMITS,
                            vec![
                                Node::long(USAGE_LIMITS_TOTAL, 2),
                                Node::enumeration(USAGE_LIMITS_UNIT, 2),
                            ],
                        ),
                    ],
                ),
                Node::structure(
                    SECRET_DATA,
                    vec![
                        Node::enumeration(SECRET_DATA_TYPE, 2),
                        Node::structure(
                            KEY_BLOCK,
                            vec![
                                Node::enumeration(KEY_FORMAT_TYPE, 1),
                                Node::int(CRYPTOGRAPHIC_LENGTH, 64),
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
        let source = body(&registered)
            .required(UNIQUE_IDENTIFIER)
            .unwrap()
            .identifier_text()
            .unwrap()
            .to_string();
        body(&f.call(v, 18, vec![id(v, &source)]));
        body(&f.call(
            v,
            17,
            vec![id(v, &source), Node::long(USAGE_LIMITS_COUNT, 1)],
        ));
        let fields = vec![
            id(v, &source),
            Node::enumeration(OBJECT_TYPE, 2),
            Node::enumeration(DERIVATION_METHOD, 1),
            Node::structure(
                DERIVATION_PARAMETERS,
                vec![
                    Node::structure(
                        CRYPTOGRAPHIC_PARAMETERS,
                        vec![Node::enumeration(HASHING_ALGORITHM, 6)],
                    ),
                    Node::bytes(SALT, b"12345678".to_vec()),
                    Node::int(ITERATION_COUNT, 2),
                ],
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
        let derived = f.call(v, 5, fields.clone());
        let derived = body(&derived)
            .required(UNIQUE_IDENTIFIER)
            .unwrap()
            .identifier_text()
            .unwrap();
        let mut expected = [0; 16];
        openssl::pkcs5::pbkdf2_hmac(
            b"password",
            b"12345678",
            2,
            openssl::hash::MessageDigest::sha256(),
            &mut expected,
        )
        .unwrap();
        assert_eq!(
            f.engine
                .store
                .get("owner", derived)
                .unwrap()
                .unwrap()
                .material,
            expected
        );
        assert_eq!(
            reason(&f.call(v, 5, fields)),
            0x1a,
            "Unrestricted must not bypass a password source's exhausted budget"
        );
    }
    for v in [Version(1, 1), Version(1, 2), Version(1, 3), Version(1, 4)] {
        let mut f = Fixture::new();
        let key = register(&mut f, v, UNRESTRICTED, false);
        body(&f.call(v, 18, vec![id(v, &key)]));
        assert_eq!(
            reason(&f.call(
                v,
                9,
                vec![id(v, &key), Node::int(CRYPTOGRAPHIC_USAGE_MASK, 12)]
            )),
            12
        );
        if v >= Version(1, 2) {
            assert_eq!(reason(&encrypt(&mut f, v, &key)), 12);
        }
    }
}
#[test]
fn unrestricted_does_not_override_accounting_archival_ownership_or_lifecycle() {
    for v in [Version(2, 0), Version(2, 1), Version(3, 0)] {
        let mut f = Fixture::new();
        let key = register(&mut f, v, UNRESTRICTED, true);
        body(&f.call(v, 18, vec![id(v, &key)]));
        body(&f.call(v, 17, vec![id(v, &key), Node::long(USAGE_LIMITS_COUNT, 1)]));
        let foreign = f
            .engine
            .process(
                "other",
                &message(
                    v,
                    31,
                    vec![
                        id(v, &key),
                        cbc(),
                        Node::bytes(IV_COUNTER_NONCE, vec![0; 16]),
                        Node::bytes(DATA, vec![7; 16]),
                    ],
                ),
            )
            .unwrap();
        assert_eq!(reason(&foreign), not_found(v));
        body(&f.call(v, 21, vec![id(v, &key)]));
        assert_eq!(reason(&encrypt(&mut f, v, &key)), 13);
        body(&f.call(v, 22, vec![id(v, &key)]));
        body(&encrypt(&mut f, v, &key));
        body(&encrypt(&mut f, v, &key));
        assert_eq!(reason(&encrypt(&mut f, v, &key)), 12);
        let original = f.engine.store.get("owner", &key).unwrap().unwrap();
        f.engine = Engine::new(
            Store::open(&f.dir.path().join("store"), &f.dir.path().join("master")).unwrap(),
            true,
        );
        assert_eq!(
            serde_json::to_value(f.engine.store.get("owner", &key).unwrap().unwrap()).unwrap(),
            serde_json::to_value(original).unwrap()
        );
        assert_eq!(reason(&encrypt(&mut f, v, &key)), 12);
    }
}

#[test]
fn unrestricted_multipart_retains_exact_mask_and_enforces_protection_dates() {
    for v in [Version(2, 0), Version(2, 1), Version(3, 0)] {
        let mut f = Fixture::new();
        let key = register(&mut f, v, UNRESTRICTED, false);
        body(&f.call(v, 18, vec![id(v, &key)]));
        let first = f.call(
            v,
            31,
            vec![
                id(v, &key),
                cbc(),
                Node::bytes(IV_COUNTER_NONCE, vec![0; 16]),
                Node::boolean(INIT_INDICATOR, true),
                Node::bytes(DATA, vec![7; 16]),
            ],
        );
        let token = body(&first)
            .required(CORRELATION_VALUE)
            .unwrap()
            .byte_string()
            .unwrap()
            .to_vec();
        let mut result = body(&first)
            .get(DATA)
            .map(|n| n.byte_string().unwrap().to_vec())
            .unwrap_or_default();
        let last = f.call(
            v,
            31,
            vec![
                id(v, &key),
                Node::bytes(CORRELATION_VALUE, token),
                Node::boolean(FINAL_INDICATOR, true),
                Node::bytes(DATA, vec![7; 16]),
            ],
        );
        result.extend(body(&last).required(DATA).unwrap().byte_string().unwrap());
        assert_eq!(
            result,
            openssl::symm::encrypt(
                openssl::symm::Cipher::aes_128_cbc(),
                &KEY,
                Some(&[0; 16]),
                &[7; 32]
            )
            .unwrap()[..32]
        );
        let mut stored = f.engine.store.get("owner", &key).unwrap().unwrap();
        assert_eq!(stored.usage, UNRESTRICTED);
        stored.attrs.push(Node::date(
            PROTECT_STOP_DATE,
            keytend_kmip_server::store::now() - 1,
        ));
        f.engine.store.put(&stored).unwrap();
        // Outside the date window: Wrong Key Lifecycle State from 2.1.
        assert_eq!(
            reason(&encrypt(&mut f, v, &key)),
            if v >= Version(2, 1) { 0x43 } else { 12 }
        );
        stored.attrs.retain(|a| a.tag != PROTECT_STOP_DATE);
        stored.attrs.push(Node::boolean(SENSITIVE, true));
        stored.attrs.push(Node::boolean(EXTRACTABLE, false));
        f.engine.store.put(&stored).unwrap();
        assert_eq!(reason(&f.call(v, 10, vec![id(v, &key)])), 0x16);
    }
}

#[test]
fn unrestricted_rsa_signatures_keep_public_and_private_key_roles_distinct() {
    for v in [Version(2, 0), Version(2, 1), Version(3, 0)] {
        let mut f = Fixture::new();
        let pair = f.call(
            v,
            2,
            vec![Node::structure(
                COMMON_ATTRIBUTES,
                vec![
                    Node::enumeration(CRYPTOGRAPHIC_ALGORITHM, 4),
                    Node::int(CRYPTOGRAPHIC_LENGTH, 2048),
                    Node::int(CRYPTOGRAPHIC_USAGE_MASK, UNRESTRICTED as i32),
                ],
            )],
        );
        let public = body(&pair)
            .required(PUBLIC_KEY_UNIQUE_IDENTIFIER)
            .unwrap()
            .identifier_text()
            .unwrap()
            .to_string();
        let private = body(&pair)
            .required(PRIVATE_KEY_UNIQUE_IDENTIFIER)
            .unwrap()
            .identifier_text()
            .unwrap()
            .to_string();
        for key in [&public, &private] {
            body(&f.call(v, 18, vec![id(v, key)]));
        }
        let cp = Node::structure(
            CRYPTOGRAPHIC_PARAMETERS,
            vec![
                Node::enumeration(CRYPTOGRAPHIC_ALGORITHM, 4),
                Node::enumeration(HASHING_ALGORITHM, 6),
                Node::enumeration(PADDING_METHOD, 8),
            ],
        );
        let data = b"an unrestricted RSA key still has a specific key role";
        let result = f.call(
            v,
            33,
            vec![
                id(v, &private),
                cp.clone(),
                Node::bytes(DATA, data.to_vec()),
            ],
        );
        let signature = body(&result)
            .required(SIGNATURE_DATA)
            .unwrap()
            .byte_string()
            .unwrap()
            .to_vec();
        let obj = f.engine.store.get("owner", &public).unwrap().unwrap();
        // SPKI in 1.x, PKCS#1 by default from 2.0 (KMIP 2.1 Table 81).
        let key = openssl::pkey::PKey::public_key_from_der(&obj.material)
            .or_else(|_| {
                openssl::rsa::Rsa::public_key_from_der_pkcs1(&obj.material)
                    .and_then(openssl::pkey::PKey::from_rsa)
            })
            .unwrap();
        let mut oracle =
            openssl::sign::Verifier::new(openssl::hash::MessageDigest::sha256(), &key).unwrap();
        oracle.update(data).unwrap();
        assert!(oracle.verify(&signature).unwrap());
        let result = f.call(
            v,
            34,
            vec![
                id(v, &public),
                cp.clone(),
                Node::bytes(DATA, data.to_vec()),
                Node::bytes(SIGNATURE_DATA, signature.clone()),
            ],
        );
        assert_eq!(
            body(&result)
                .required(VALIDITY_INDICATOR)
                .unwrap()
                .number()
                .unwrap(),
            1
        );
        assert_eq!(
            reason(&f.call(
                v,
                33,
                vec![id(v, &public), cp.clone(), Node::bytes(DATA, data.to_vec())]
            )),
            8
        );
        assert_eq!(
            reason(&f.call(
                v,
                34,
                vec![
                    id(v, &private),
                    cp,
                    Node::bytes(DATA, data.to_vec()),
                    Node::bytes(SIGNATURE_DATA, signature)
                ]
            )),
            8
        );
    }
}

/// Item Not Found in 1.x; Object Not Found (0x37) where the 2.x and draft 3.0
/// error tables list it (see src/protocol/not_found.rs).
fn not_found(v: Version) -> u32 {
    if v.0 >= 2 { 0x37 } else { 1 }
}
