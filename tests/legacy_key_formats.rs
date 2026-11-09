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

//! Controlled three-key 3DES and the transparent RSA/DSA key formats.
//! Expected ciphertexts and key encodings come from OpenSSL called directly
//! by the test, or from the OASIS trace values, never from the server.
use keytend_kmip_server::{
    protocol::{Engine, TripleDesPolicy, Version},
    store::Store,
    tags::*,
    ttlv::{Node, Value},
};
use openssl::{
    bn::BigNum,
    dsa::Dsa,
    hash::MessageDigest,
    pkey::PKey,
    rsa::Rsa,
    sign::Signer,
    symm::{Cipher, decrypt, encrypt},
};

const V13: Version = Version(1, 3);
const V21: Version = Version(2, 1);
const VERSIONS: [Version; 5] = [
    Version(1, 0),
    Version(1, 4),
    Version(2, 0),
    Version(2, 1),
    Version(3, 0),
];

struct Fixture {
    _dir: tempfile::TempDir,
    engine: Engine,
}
impl Fixture {
    fn new(policy: TripleDesPolicy) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let key = dir.path().join("master");
        std::fs::write(&key, [42; 32]).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        let engine = Engine::new(Store::open(&dir.path().join("store"), &key).unwrap(), true)
            .with_triple_des(policy);
        Self { _dir: dir, engine }
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
        self.engine.process("owner", &request).unwrap()
    }
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
        .unwrap_or_else(|_| panic!("expected failure: {}", serde_json::to_string(n).unwrap()))
        .number()
        .unwrap()
}
fn identifier(n: &Node) -> String {
    body(n)
        .required(UNIQUE_IDENTIFIER)
        .unwrap()
        .identifier_text()
        .unwrap()
        .to_owned()
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
fn hex(s: &str) -> Vec<u8> {
    hex::decode(s).unwrap()
}
fn big(tag: u32, magnitude: &[u8]) -> Node {
    let extra = usize::from(magnitude.first().is_none_or(|b| b & 0x80 != 0));
    let size = (magnitude.len() + extra).div_ceil(8) * 8;
    let mut bytes = vec![0; size];
    bytes[size - magnitude.len()..].copy_from_slice(magnitude);
    Node {
        tag,
        value: Value::BigInteger(bytes),
    }
}
fn key_block(format: u32, algorithm: Option<u32>, length: Option<u32>, material: Node) -> Node {
    let mut kb = vec![
        Node::enumeration(KEY_FORMAT_TYPE, format),
        Node::structure(KEY_VALUE, vec![material]),
    ];
    if let Some(a) = algorithm {
        kb.push(Node::enumeration(CRYPTOGRAPHIC_ALGORITHM, a));
    }
    if let Some(l) = length {
        kb.push(Node::int(CRYPTOGRAPHIC_LENGTH, l as i32));
    }
    Node::structure(KEY_BLOCK, kb)
}
fn register(f: &mut Fixture, v: Version, kind: u32, usage: u32, block: Node) -> Node {
    let tag = match kind {
        2 => SYMMETRIC_KEY,
        3 => PUBLIC_KEY,
        _ => PRIVATE_KEY,
    };
    f.call(
        v,
        3,
        vec![
            Node::enumeration(OBJECT_TYPE, kind),
            container(
                v,
                vec![
                    Node::int(CRYPTOGRAPHIC_USAGE_MASK, usage as i32),
                    Node::date(ACTIVATION_DATE, 0),
                ],
            ),
            Node::structure(tag, vec![block]),
        ],
    )
}
fn get(f: &mut Fixture, v: Version, uid: &str, format: Option<u32>) -> Node {
    let mut fields = vec![id(v, uid)];
    if let Some(format) = format {
        fields.push(Node::enumeration(KEY_FORMAT_TYPE, format));
    }
    f.call(v, 10, fields)
}
fn block(response: &Node) -> Node {
    let p = body(response);
    p.children()
        .unwrap()
        .iter()
        .find(|n| [SYMMETRIC_KEY, PUBLIC_KEY, PRIVATE_KEY].contains(&n.tag))
        .unwrap()
        .required(KEY_BLOCK)
        .unwrap()
        .clone()
}
fn material(response: &Node) -> Node {
    block(response)
        .required(KEY_VALUE)
        .unwrap()
        .required(KEY_MATERIAL)
        .unwrap()
        .clone()
}

// ---------------------------------------------------------------- 3DES

/// Three distinct, non-weak DES keys with odd parity.
const TDEA_KEY: &str = "0123456789abcdef23456789abcdef01456789abcdef0123";

fn create_3des(f: &mut Fixture, v: Version, length: Option<u32>) -> Node {
    let mut attrs = vec![
        Node::enumeration(CRYPTOGRAPHIC_ALGORITHM, 2),
        Node::int(CRYPTOGRAPHIC_USAGE_MASK, 12),
    ];
    if let Some(l) = length {
        attrs.push(Node::int(CRYPTOGRAPHIC_LENGTH, l as i32));
    }
    f.call(
        v,
        1,
        vec![Node::enumeration(OBJECT_TYPE, 2), container(v, attrs)],
    )
}
fn register_3des(f: &mut Fixture, v: Version, key: Vec<u8>, length: Option<u32>) -> Node {
    register(
        f,
        v,
        2,
        12,
        key_block(1, Some(2), length, Node::bytes(KEY_MATERIAL, key)),
    )
}
fn crypt(f: &mut Fixture, v: Version, op: u32, uid: &str, cp: Vec<Node>, extra: Vec<Node>) -> Node {
    let mut fields = vec![id(v, uid), Node::structure(CRYPTOGRAPHIC_PARAMETERS, cp)];
    fields.extend(extra);
    f.call(v, op, fields)
}

#[test]
fn triple_des_is_refused_unless_enabled_by_policy() {
    let mut f = Fixture::new(TripleDesPolicy::default());
    for v in VERSIONS {
        assert_eq!(reason(&create_3des(&mut f, v, Some(168))), 8);
        assert_eq!(
            reason(&register_3des(&mut f, v, hex(TDEA_KEY), Some(168))),
            8
        );
    }
    // Legacy decryption: Register and Decrypt, but no Create or Encrypt.
    let mut f = Fixture::new(TripleDesPolicy::LegacyDecrypt);
    assert_eq!(reason(&create_3des(&mut f, V21, Some(168))), 8);
    let uid = identifier(&register_3des(&mut f, V21, hex(TDEA_KEY), Some(168)));
    let iv = [9u8; 8];
    let ciphertext = encrypt(
        Cipher::des_ede3_cbc(),
        &hex(TDEA_KEY),
        Some(&iv),
        b"archived",
    )
    .unwrap();
    let cbc = vec![
        Node::enumeration(BLOCK_CIPHER_MODE, 1),
        Node::enumeration(PADDING_METHOD, 3),
    ];
    let r = crypt(
        &mut f,
        V21,
        32,
        &uid,
        cbc.clone(),
        vec![
            Node::bytes(DATA, ciphertext),
            Node::bytes(IV_COUNTER_NONCE, iv.to_vec()),
        ],
    );
    assert_eq!(
        body(&r).required(DATA).unwrap().byte_string().unwrap(),
        b"archived"
    );
    let r = crypt(
        &mut f,
        V21,
        31,
        &uid,
        cbc,
        vec![
            Node::bytes(DATA, b"new".to_vec()),
            Node::bytes(IV_COUNTER_NONCE, iv.to_vec()),
        ],
    );
    assert_eq!(reason(&r), 8);
    assert_eq!(reason(&f.call(V21, 4, vec![id(V21, &uid)])), 8);
}

#[test]
fn created_keys_are_three_key_bundles_reported_as_168_bits() {
    let mut f = Fixture::new(TripleDesPolicy::Enabled);
    for v in VERSIONS {
        for length in [None, Some(168), Some(192)] {
            let uid = identifier(&create_3des(&mut f, v, length));
            let r = get(&mut f, v, &uid, None);
            let kb = block(&r);
            let key = material(&r).byte_string().unwrap().to_vec();
            assert_eq!(key.len(), 24);
            assert!(key.iter().all(|b| b.count_ones() % 2 == 1), "odd parity");
            assert!(key[..8] != key[8..16] && key[8..16] != key[16..] && key[..8] != key[16..]);
            assert_eq!(
                kb.required(CRYPTOGRAPHIC_ALGORITHM)
                    .unwrap()
                    .number()
                    .unwrap(),
                2
            );
            assert_eq!(
                kb.required(CRYPTOGRAPHIC_LENGTH).unwrap().number().unwrap(),
                length.unwrap_or(168)
            );
        }
        // Two-key TDEA and arbitrary lengths are refused; single DES is never offered.
        for length in [112, 128, 64, 256] {
            assert_eq!(reason(&create_3des(&mut f, v, Some(length))), 7, "{length}");
        }
        let des = f.call(
            v,
            1,
            vec![
                Node::enumeration(OBJECT_TYPE, 2),
                container(
                    v,
                    vec![
                        Node::enumeration(CRYPTOGRAPHIC_ALGORITHM, 1),
                        Node::int(CRYPTOGRAPHIC_LENGTH, 56),
                        Node::int(CRYPTOGRAPHIC_USAGE_MASK, 12),
                    ],
                ),
            ],
        );
        assert_eq!(reason(&des), 7);
    }
    // Re-key replaces the material with a fresh bundle of the same length.
    let uid = identifier(&create_3des(&mut f, V21, Some(168)));
    let old = material(&get(&mut f, V21, &uid, None))
        .byte_string()
        .unwrap()
        .to_vec();
    let next = identifier(&f.call(V21, 4, vec![id(V21, &uid)]));
    let r = get(&mut f, V21, &next, None);
    assert_eq!(
        block(&r)
            .required(CRYPTOGRAPHIC_LENGTH)
            .unwrap()
            .number()
            .unwrap(),
        168
    );
    let new = material(&r).byte_string().unwrap().to_vec();
    assert_eq!(new.len(), 24);
    assert_ne!(new, old);
}

#[test]
fn registered_bundles_must_hold_three_distinct_non_weak_keys() {
    let mut f = Fixture::new(TripleDesPolicy::Enabled);
    let k = hex(TDEA_KEY);
    for v in [V13, V21, Version(3, 0)] {
        let uid = identifier(&register_3des(&mut f, v, k.clone(), Some(168)));
        let r = get(&mut f, v, &uid, None);
        assert_eq!(material(&r).byte_string().unwrap(), &k[..]);
        assert_eq!(
            block(&r)
                .required(CRYPTOGRAPHIC_LENGTH)
                .unwrap()
                .number()
                .unwrap(),
            168
        );
        // An undeclared length records 168; 192 counts the parity bits.
        let undeclared = identifier(&register_3des(&mut f, v, k.clone(), None));
        assert_eq!(
            block(&get(&mut f, v, &undeclared, None))
                .required(CRYPTOGRAPHIC_LENGTH)
                .unwrap()
                .number()
                .unwrap(),
            168
        );
        identifier(&register_3des(&mut f, v, k.clone(), Some(192)));
        for bad in [
            // CS-BC-M-4-12-3DES-13 registers all-0x01: a weak DES key, K1 = K2 = K3.
            vec![1; 24],
            [&k[..8], &k[..8], &k[16..]].concat(),
            [&k[..8], &k[8..16], &k[..8]].concat(),
            k[..16].to_vec(),
            [k.clone(), vec![1; 8]].concat(),
        ] {
            assert_eq!(reason(&register_3des(&mut f, v, bad, Some(168))), 7);
        }
        assert_eq!(reason(&register_3des(&mut f, v, k.clone(), Some(112))), 7);
        assert_eq!(reason(&register_3des(&mut f, v, k.clone(), Some(184))), 7);
    }
    // Key Block and attribute lengths must agree.
    let r = f.call(
        V21,
        3,
        vec![
            Node::enumeration(OBJECT_TYPE, 2),
            container(
                V21,
                vec![
                    Node::int(CRYPTOGRAPHIC_USAGE_MASK, 12),
                    Node::int(CRYPTOGRAPHIC_LENGTH, 192),
                ],
            ),
            Node::structure(
                SYMMETRIC_KEY,
                vec![key_block(
                    1,
                    Some(2),
                    Some(168),
                    Node::bytes(KEY_MATERIAL, k),
                )],
            ),
        ],
    );
    assert_eq!(reason(&r), 7);
}

#[test]
fn ecb_and_cbc_match_openssl_and_reject_aes_only_parameters() {
    let mut f = Fixture::new(TripleDesPolicy::Enabled);
    let k = hex(TDEA_KEY);
    for v in [V13, Version(1, 4), V21, Version(3, 0)] {
        let uid = identifier(&register_3des(&mut f, v, k.clone(), Some(168)));
        // ECB, no padding: NIST SP 800-67 Rev. 2 Appendix B example, block 1.
        let ecb = vec![
            Node::enumeration(BLOCK_CIPHER_MODE, 2),
            Node::enumeration(PADDING_METHOD, 1),
        ];
        let r = crypt(
            &mut f,
            v,
            31,
            &uid,
            ecb.clone(),
            vec![Node::bytes(DATA, b"The qufc".to_vec())],
        );
        assert_eq!(
            body(&r).required(DATA).unwrap().byte_string().unwrap(),
            hex("a826fd8ce53b855f")
        );
        // CBC with PKCS#5 padding against OpenSSL called directly.
        let iv = hex("0001020304050607");
        let plain = b"legacy payload spanning blocks".to_vec();
        let cbc = vec![
            Node::enumeration(BLOCK_CIPHER_MODE, 1),
            Node::enumeration(PADDING_METHOD, 3),
        ];
        let r = crypt(
            &mut f,
            v,
            31,
            &uid,
            cbc.clone(),
            vec![
                Node::bytes(DATA, plain.clone()),
                Node::bytes(IV_COUNTER_NONCE, iv.clone()),
            ],
        );
        let ct = body(&r)
            .required(DATA)
            .unwrap()
            .byte_string()
            .unwrap()
            .to_vec();
        assert_eq!(
            ct,
            encrypt(Cipher::des_ede3_cbc(), &k, Some(&iv), &plain).unwrap()
        );
        let r = crypt(
            &mut f,
            v,
            32,
            &uid,
            cbc.clone(),
            vec![
                Node::bytes(DATA, ct),
                Node::bytes(IV_COUNTER_NONCE, iv.clone()),
            ],
        );
        assert_eq!(
            body(&r).required(DATA).unwrap().byte_string().unwrap(),
            plain
        );
        // A server-generated IV is one 64-bit block.
        let mut random = cbc.clone();
        random.push(Node::boolean(RANDOM_IV, true));
        let r = crypt(
            &mut f,
            v,
            31,
            &uid,
            random,
            vec![Node::bytes(DATA, b"x".to_vec())],
        );
        let p = body(&r);
        let iv = p.required(IV_COUNTER_NONCE).unwrap().byte_string().unwrap();
        assert_eq!(iv.len(), 8);
        assert_eq!(
            decrypt(
                Cipher::des_ede3_cbc(),
                &k,
                Some(iv),
                p.required(DATA).unwrap().byte_string().unwrap()
            )
            .unwrap(),
            b"x"
        );
        // AES-sized IVs, AEAD modes, and IVs for ECB are refused.
        let r = crypt(
            &mut f,
            v,
            31,
            &uid,
            cbc.clone(),
            vec![
                Node::bytes(DATA, plain.clone()),
                Node::bytes(IV_COUNTER_NONCE, vec![0; 16]),
            ],
        );
        assert_eq!(reason(&r), 7);
        let r = crypt(
            &mut f,
            v,
            31,
            &uid,
            vec![Node::enumeration(BLOCK_CIPHER_MODE, 9)],
            vec![
                Node::bytes(DATA, plain.clone()),
                Node::bytes(IV_COUNTER_NONCE, vec![0; 12]),
            ],
        );
        assert_eq!(reason(&r), 8);
        let r = crypt(
            &mut f,
            v,
            31,
            &uid,
            ecb,
            vec![
                Node::bytes(DATA, b"The qufc".to_vec()),
                Node::bytes(IV_COUNTER_NONCE, iv.to_vec()),
            ],
        );
        assert_eq!(reason(&r), 7);
    }
}

// ------------------------------------------------- Transparent RSA / DSA

fn rsa_public_block(k: &Rsa<openssl::pkey::Private>) -> Node {
    key_block(
        11,
        Some(4),
        Some(k.size() * 8),
        Node::structure(
            KEY_MATERIAL,
            vec![
                big(MODULUS, &k.n().to_vec()),
                big(PUBLIC_EXPONENT, &k.e().to_vec()),
            ],
        ),
    )
}
fn rsa_private_fields(k: &Rsa<openssl::pkey::Private>) -> Vec<Node> {
    vec![
        big(MODULUS, &k.n().to_vec()),
        big(PRIVATE_EXPONENT, &k.d().to_vec()),
        big(PUBLIC_EXPONENT, &k.e().to_vec()),
        big(P, &k.p().unwrap().to_vec()),
        big(Q, &k.q().unwrap().to_vec()),
        big(PRIME_EXPONENT_P, &k.dmp1().unwrap().to_vec()),
        big(PRIME_EXPONENT_Q, &k.dmq1().unwrap().to_vec()),
        big(CRT_COEFFICIENT, &k.iqmp().unwrap().to_vec()),
    ]
}

#[test]
fn transparent_rsa_keys_register_validate_and_convert() {
    let k = Rsa::generate(2048).unwrap();
    let mut f = Fixture::new(TripleDesPolicy::default());
    for v in VERSIONS {
        // Public key: served transparently by default, and as PKCS#1 or SPKI.
        let uid = identifier(&register(&mut f, v, 3, 4, rsa_public_block(&k)));
        let r = get(&mut f, v, &uid, None);
        assert_eq!(
            block(&r)
                .required(KEY_FORMAT_TYPE)
                .unwrap()
                .number()
                .unwrap(),
            11
        );
        assert_eq!(
            block(&r)
                .required(CRYPTOGRAPHIC_LENGTH)
                .unwrap()
                .number()
                .unwrap(),
            2048
        );
        assert!(
            material(&r)
                == Node::structure(
                    KEY_MATERIAL,
                    vec![
                        big(MODULUS, &k.n().to_vec()),
                        big(PUBLIC_EXPONENT, &k.e().to_vec())
                    ]
                )
        );
        assert_eq!(
            material(&get(&mut f, v, &uid, Some(3)))
                .byte_string()
                .unwrap(),
            k.public_key_to_der_pkcs1().unwrap()
        );
        assert_eq!(
            material(&get(&mut f, v, &uid, Some(5)))
                .byte_string()
                .unwrap(),
            PKey::from_rsa(k.clone())
                .unwrap()
                .public_key_to_der()
                .unwrap()
        );
        assert_eq!(reason(&get(&mut f, v, &uid, Some(10))), 0x10);
        // Private key, all eight components.
        let full = key_block(
            10,
            Some(4),
            Some(2048),
            Node::structure(KEY_MATERIAL, rsa_private_fields(&k)),
        );
        let uid = identifier(&register(&mut f, v, 4, 8, full));
        let r = get(&mut f, v, &uid, None);
        assert!(material(&r) == Node::structure(KEY_MATERIAL, rsa_private_fields(&k)));
        assert_eq!(
            material(&get(&mut f, v, &uid, Some(3)))
                .byte_string()
                .unwrap(),
            k.private_key_to_der().unwrap()
        );
        // Modulus, Public and Private Exponent only: the factors are recovered.
        let minimal = key_block(
            10,
            None,
            None,
            Node::structure(
                KEY_MATERIAL,
                vec![
                    big(MODULUS, &k.n().to_vec()),
                    big(PRIVATE_EXPONENT, &k.d().to_vec()),
                    big(PUBLIC_EXPONENT, &k.e().to_vec()),
                ],
            ),
        );
        let uid = identifier(&register(&mut f, v, 4, 8, minimal));
        let der = material(&get(&mut f, v, &uid, Some(3)))
            .byte_string()
            .unwrap()
            .to_vec();
        let recovered = Rsa::private_key_from_der(&der).unwrap();
        assert!(recovered.check_key().unwrap());
        assert_eq!(recovered.n(), k.n());
        // A PKCS#1-registered key can be served in the transparent format.
        let uid = identifier(&register(
            &mut f,
            v,
            4,
            8,
            key_block(
                3,
                Some(4),
                Some(2048),
                Node::bytes(KEY_MATERIAL, k.private_key_to_der().unwrap()),
            ),
        ));
        assert!(
            material(&get(&mut f, v, &uid, Some(10)))
                == Node::structure(KEY_MATERIAL, rsa_private_fields(&k))
        );
    }
}

#[test]
fn transparent_rsa_rejections() {
    let k = Rsa::generate(1024).unwrap();
    let mut f = Fixture::new(TripleDesPolicy::default());
    let v = V21;
    let private =
        |fields: Vec<Node>| key_block(10, Some(4), None, Node::structure(KEY_MATERIAL, fields));
    let n = big(MODULUS, &k.n().to_vec());
    let e = big(PUBLIC_EXPONENT, &k.e().to_vec());
    // Modulus and Public Exponent alone are not a private key.
    assert_eq!(
        reason(&register(
            &mut f,
            v,
            4,
            8,
            private(vec![n.clone(), e.clone()])
        )),
        7
    );
    // A wrong CRT coefficient fails the consistency check.
    let mut fields = rsa_private_fields(&k);
    let mut bad = k.iqmp().unwrap().to_owned().unwrap();
    bad.add_word(1).unwrap();
    fields[7] = big(CRT_COEFFICIENT, &bad.to_vec());
    assert_eq!(reason(&register(&mut f, v, 4, 8, private(fields))), 7);
    // Negative Big Integers, unknown fields, wrong algorithm and length.
    let mut negative = vec![0xff; 8];
    negative.extend(k.n().to_vec());
    let neg = Node {
        tag: MODULUS,
        value: Value::BigInteger(negative),
    };
    let public = |fields: Vec<Node>, alg, len| {
        key_block(11, alg, len, Node::structure(KEY_MATERIAL, fields))
    };
    assert_eq!(
        reason(&register(
            &mut f,
            v,
            3,
            4,
            public(vec![neg, e.clone()], Some(4), None)
        )),
        7
    );
    assert_eq!(
        reason(&register(
            &mut f,
            v,
            3,
            4,
            public(vec![n.clone()], Some(4), None)
        )),
        7
    );
    assert_eq!(
        reason(&register(
            &mut f,
            v,
            3,
            4,
            public(vec![n.clone(), e.clone(), big(P, &[3])], Some(4), None)
        )),
        8
    );
    assert_eq!(
        reason(&register(
            &mut f,
            v,
            3,
            4,
            public(vec![n.clone(), e.clone()], Some(5), None)
        )),
        7
    );
    assert_eq!(
        reason(&register(
            &mut f,
            v,
            3,
            4,
            public(vec![n.clone(), e.clone()], Some(4), Some(2048))
        )),
        7
    );
    let even = BigNum::from_slice(&k.n().to_vec()).map(|mut x| {
        x.add_word(1).unwrap();
        x
    });
    assert_eq!(
        reason(&register(
            &mut f,
            v,
            3,
            4,
            public(
                vec![big(MODULUS, &even.unwrap().to_vec()), e.clone()],
                Some(4),
                None
            )
        )),
        7
    );
    // A public transparent format cannot hold a private key object.
    assert_eq!(
        reason(&register(
            &mut f,
            v,
            4,
            8,
            public(vec![n, e], Some(4), None)
        )),
        0x10
    );
}

/// The 512-bit DSA domain and keys of the OASIS BL-M-12/13 traces.
fn trace_dsa(private: bool) -> Node {
    let mut fields = vec![
        Node {
            tag: P,
            value: Value::BigInteger(hex(
                "0000000000000000fca682ce8e12caba26efccf7110e526db078b05edecbcd1eb4a208f3ae1617ae01f35b91a47e6df63413c5e12ed0899bcd132acd50d99151bdc43ee737592e17",
            )),
        },
        Node {
            tag: Q,
            value: Value::BigInteger(hex("00000000962eddcc369cba8ebb260ee6b6a126d9346e38c5")),
        },
        Node {
            tag: G,
            value: Value::BigInteger(hex(
                "678471b27a9cf44ee91a49c5147db1a9aaf244f05a434d6486931d2d14271b9e35030b71fd73da179069b32e2935630e1c2062354d0da20a6c416e50be794ca4",
            )),
        },
    ];
    fields.push(if private {
        Node {
            tag: X,
            value: Value::BigInteger(hex("00000000095411d740d2443fa3f97d1ed9a0411bb45e7131")),
        }
    } else {
        Node {
            tag: Y,
            value: Value::BigInteger(hex("0000000000000000b3cb74d988dea7160a64a4edbb7f70404fa4c08a4208c19d76357a6a9df200cce79faecb22e3419be9b01128cbd998a2d9307101705e4a952462f34728ac5fcf")),
        }
    });
    Node::structure(KEY_MATERIAL, fields)
}

#[test]
fn transparent_dsa_keys_round_trip_and_verify() {
    let mut f = Fixture::new(TripleDesPolicy::default());
    for v in VERSIONS {
        for private in [false, true] {
            let format = if private { 8 } else { 9 };
            let kind = if private { 4 } else { 3 };
            let uid = identifier(&register(
                &mut f,
                v,
                kind,
                if private { 1 } else { 2 },
                key_block(format, Some(5), Some(512), trace_dsa(private)),
            ));
            let r = get(&mut f, v, &uid, None);
            assert_eq!(
                block(&r)
                    .required(KEY_FORMAT_TYPE)
                    .unwrap()
                    .number()
                    .unwrap(),
                format
            );
            assert_eq!(
                block(&r)
                    .required(CRYPTOGRAPHIC_LENGTH)
                    .unwrap()
                    .number()
                    .unwrap(),
                512
            );
            assert!(material(&r) == trace_dsa(private));
            let der = material(&get(&mut f, v, &uid, Some(if private { 4 } else { 5 })))
                .byte_string()
                .unwrap()
                .to_vec();
            let y = if private {
                PKey::private_key_from_der(&der)
                    .unwrap()
                    .dsa()
                    .unwrap()
                    .pub_key()
                    .to_vec()
            } else {
                PKey::public_key_from_der(&der)
                    .unwrap()
                    .dsa()
                    .unwrap()
                    .pub_key()
                    .to_vec()
            };
            assert_eq!(
                y,
                trace_dsa(false)
                    .required(Y)
                    .unwrap()
                    .big_integer_magnitude()
            );
            assert_eq!(reason(&get(&mut f, v, &uid, Some(3))), 0x10);
        }
    }
    // A 2048-bit key registered transparently verifies an OpenSSL signature.
    let k = Dsa::generate(2048).unwrap();
    let public = Node::structure(
        KEY_MATERIAL,
        vec![
            big(P, &k.p().to_vec()),
            big(Q, &k.q().to_vec()),
            big(G, &k.g().to_vec()),
            big(Y, &k.pub_key().to_vec()),
        ],
    );
    let uid = identifier(&register(
        &mut f,
        V21,
        3,
        2,
        key_block(9, None, None, public),
    ));
    let mut signer = Signer::new(MessageDigest::sha256(), &PKey::from_dsa(k).unwrap()).unwrap();
    signer.update(b"signed data").unwrap();
    let signature = signer.sign_to_vec().unwrap();
    for (data, expected) in [(&b"signed data"[..], 1), (&b"other data"[..], 2)] {
        let r = f.call(
            V21,
            34,
            vec![
                id(V21, &uid),
                Node::structure(
                    CRYPTOGRAPHIC_PARAMETERS,
                    vec![
                        Node::enumeration(CRYPTOGRAPHIC_ALGORITHM, 5),
                        Node::enumeration(HASHING_ALGORITHM, 6),
                    ],
                ),
                Node::bytes(DATA, data.to_vec()),
                Node::bytes(SIGNATURE_DATA, signature.clone()),
            ],
        );
        assert_eq!(
            body(&r)
                .required(VALIDITY_INDICATOR)
                .unwrap()
                .number()
                .unwrap(),
            expected
        );
    }
}

#[test]
fn transparent_dsa_rejections() {
    let mut f = Fixture::new(TripleDesPolicy::default());
    let v = V21;
    let with = |private: bool, tag: u32, value: &[u8]| {
        let mut m = trace_dsa(private);
        if let Value::Structure(fields) = &mut m.value {
            for n in fields.iter_mut().filter(|n| n.tag == tag) {
                *n = big(tag, value);
            }
        }
        m
    };
    // Y outside the order-Q subgroup, G = 1, composite Q, X = 0 and X = Q.
    let q = trace_dsa(false)
        .required(Q)
        .unwrap()
        .big_integer_magnitude();
    for (private, tag, value) in [
        (false, Y, vec![2]),
        (false, G, vec![1]),
        (false, Q, vec![0x96, 0x2e, 0xdd, 0xcc]),
        (true, X, vec![0]),
        (true, X, q),
    ] {
        let kind = if private { 4 } else { 3 };
        let format = if private { 8 } else { 9 };
        let r = register(
            &mut f,
            v,
            kind,
            2,
            key_block(format, Some(5), None, with(private, tag, &value)),
        );
        assert_eq!(reason(&r), 7, "{tag:x}");
    }
    // Missing component, mismatched length and a DSA format on an RSA key.
    let mut missing = trace_dsa(false);
    if let Value::Structure(fields) = &mut missing.value {
        fields.retain(|n| n.tag != G);
    }
    assert_eq!(
        reason(&register(
            &mut f,
            v,
            3,
            2,
            key_block(9, Some(5), None, missing)
        )),
        7
    );
    assert_eq!(
        reason(&register(
            &mut f,
            v,
            3,
            2,
            key_block(9, Some(5), Some(1024), trace_dsa(false))
        )),
        7
    );
    assert_eq!(
        reason(&register(
            &mut f,
            v,
            3,
            2,
            key_block(9, Some(4), None, trace_dsa(false))
        )),
        7
    );
}

trait Magnitude {
    fn big_integer_magnitude(&self) -> Vec<u8>;
}
impl Magnitude for Node {
    fn big_integer_magnitude(&self) -> Vec<u8> {
        let Value::BigInteger(b) = &self.value else {
            panic!("not a Big Integer")
        };
        BigNum::from_slice(b).unwrap().to_vec()
    }
}

#[test]
fn multipart_cbc_matches_one_shot_and_honours_policy() {
    let k = hex(TDEA_KEY);
    let iv = hex("1011121314151617");
    let plain = b"multipart legacy data spanning several TDEA blocks".to_vec();
    let expected = encrypt(Cipher::des_ede3_cbc(), &k, Some(&iv), &plain).unwrap();
    let cbc = Node::structure(
        CRYPTOGRAPHIC_PARAMETERS,
        vec![
            Node::enumeration(BLOCK_CIPHER_MODE, 1),
            Node::enumeration(PADDING_METHOD, 3),
        ],
    );
    let mut f = Fixture::new(TripleDesPolicy::Enabled);
    let uid = identifier(&register_3des(&mut f, V21, k.clone(), None));
    let start = f.call(
        V21,
        31,
        vec![
            id(V21, &uid),
            cbc.clone(),
            Node::bytes(DATA, plain[..13].to_vec()),
            Node::bytes(IV_COUNTER_NONCE, iv.clone()),
            Node::boolean(INIT_INDICATOR, true),
        ],
    );
    let p = body(&start);
    let mut out = p.required(DATA).unwrap().byte_string().unwrap().to_vec();
    let token = p
        .required(CORRELATION_VALUE)
        .unwrap()
        .byte_string()
        .unwrap()
        .to_vec();
    let end = f.call(
        V21,
        31,
        vec![
            id(V21, &uid),
            cbc.clone(),
            Node::bytes(DATA, plain[13..].to_vec()),
            Node::bytes(CORRELATION_VALUE, token),
            Node::boolean(FINAL_INDICATOR, true),
        ],
    );
    out.extend(body(&end).required(DATA).unwrap().byte_string().unwrap());
    assert_eq!(out, expected);
    // Multipart encryption is refused under the legacy-decrypt policy.
    let mut f = Fixture::new(TripleDesPolicy::LegacyDecrypt);
    let uid = identifier(&register_3des(&mut f, V21, k, None));
    let r = f.call(
        V21,
        31,
        vec![
            id(V21, &uid),
            cbc,
            Node::bytes(DATA, plain),
            Node::bytes(IV_COUNTER_NONCE, iv),
            Node::boolean(INIT_INDICATOR, true),
        ],
    );
    assert_eq!(reason(&r), 8);
}
