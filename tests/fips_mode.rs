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

//! FIPS mode (docs/fips.md): every inventory row's handling in both modes.
//! Default mode keeps every service; FIPS mode refuses exactly the
//! non-approved ones with the reason the operation gives an unsupported
//! mechanism, and answers approved requests exactly as default mode does.
//! These tests run the server's policy layer with the host's default
//! provider; `fips_check_*` runs the binary against a real FIPS provider
//! when one is configured.
use keytend_kmip_server::{
    credentials::{PasswordVerifier, PolicyUser},
    protocol::{EcCurves, Engine, Version},
    store::Store,
    tags::*,
    ttlv::{Node, Value},
};
use openssl::{
    pkey::{PKey, Private},
    rsa::Rsa,
};

const V: Version = Version(2, 1);
const V14: Version = Version(1, 4);
const OK: u32 = 0;
const FEATURE_NOT_SUPPORTED: u32 = 8;
const INVALID_FIELD: u32 = 7;
const GENERAL_FAILURE: u32 = 0x100;
/// 2.x reason the RSA and derivation parameter checks use.
const UNSUPPORTED_PARAMETERS: u32 = 0x3e;

struct Server {
    _dir: tempfile::TempDir,
    e: Engine,
}
fn server(fips: bool) -> Server {
    let dir = tempfile::tempdir().unwrap();
    let key = dir.path().join("master");
    std::fs::write(&key, [9; 32]).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    let store = Store::open(&dir.path().join("keys.sqlite"), &key).unwrap();
    let e = Engine::new(store, true).with_fips(fips);
    Server { _dir: dir, e }
}
/// The same request against a default-mode and a FIPS-mode server.
struct Both {
    default: Server,
    fips: Server,
}
fn both() -> Both {
    Both {
        default: server(false),
        fips: server(true),
    }
}
fn request(v: Version, auth: Option<Node>, items: Vec<(u32, Vec<Node>)>) -> Node {
    let mut header = vec![v.node()];
    header.extend(auth);
    if v.0 < 3 {
        header.push(Node::int(BATCH_COUNT, items.len() as i32));
    }
    let mut fields = vec![Node::structure(REQUEST_HEADER, header)];
    fields.extend(items.into_iter().map(|(op, p)| {
        Node::structure(
            BATCH_ITEM,
            vec![
                Node::enumeration(OPERATION, op),
                Node::structure(REQUEST_PAYLOAD, p),
            ],
        )
    }));
    Node::structure(REQUEST_MESSAGE, fields)
}
impl Server {
    fn call_as(&mut self, v: Version, auth: Option<Node>, op: u32, p: Vec<Node>) -> Node {
        let response = self
            .e
            .process("alice", &request(v, auth, vec![(op, p)]))
            .unwrap();
        response.required(BATCH_ITEM).unwrap().clone()
    }
    fn call(&mut self, op: u32, p: Vec<Node>) -> Node {
        self.call_as(V, None, op, p)
    }
    fn ok(&mut self, op: u32, p: Vec<Node>) -> Node {
        let item = self.call(op, p);
        assert_eq!(status(&item), (OK, 0, String::new()), "{}", show(&item));
        item.required(RESPONSE_PAYLOAD).unwrap().clone()
    }
    fn id(&mut self, op: u32, p: Vec<Node>) -> String {
        self.ok(op, p)
            .required(UNIQUE_IDENTIFIER)
            .unwrap()
            .string()
            .unwrap()
            .to_owned()
    }
    /// Register or create, then Activate.
    fn key(&mut self, op: u32, p: Vec<Node>) -> String {
        let id = self.id(op, p);
        self.ok(18, vec![uid(&id)]);
        id
    }
}
/// A readable rendering for assertion messages and comparisons.
fn show(node: &Node) -> String {
    String::from_utf8(
        keytend_kmip_server::encoding::Format::Json
            .encode(node)
            .unwrap()
            .to_vec(),
    )
    .unwrap()
}
/// (Result Status, Result Reason, Result Message) of a batch item.
fn status(item: &Node) -> (u32, u32, String) {
    let number = |tag| item.get(tag).map_or(0, |n| n.number().unwrap());
    let message = item
        .get(RESULT_MESSAGE)
        .map_or(String::new(), |n| n.string().unwrap().to_owned());
    (number(RESULT_STATUS), number(RESULT_REASON), message)
}
/// FIPS mode refused the request with `reason` and said why.
fn refused(item: &Node, reason: u32) {
    let (s, r, message) = status(item);
    assert_eq!((s, r), (1, reason), "{}", show(item));
    assert!(message.contains("FIPS"), "{message}");
}
fn uid(id: &str) -> Node {
    Node::text(UNIQUE_IDENTIFIER, id)
}
fn attrs(list: Vec<Node>) -> Node {
    Node::structure(ATTRIBUTES, list)
}
fn cp(list: Vec<Node>) -> Node {
    Node::structure(CRYPTOGRAPHIC_PARAMETERS, list)
}
fn symmetric(alg: u32, material: &[u8], usage: i32) -> Vec<Node> {
    vec![
        Node::enumeration(OBJECT_TYPE, 2),
        attrs(vec![Node::int(CRYPTOGRAPHIC_USAGE_MASK, usage)]),
        Node::structure(
            SYMMETRIC_KEY,
            vec![Node::structure(
                KEY_BLOCK,
                vec![
                    Node::enumeration(KEY_FORMAT_TYPE, 1),
                    Node::structure(
                        KEY_VALUE,
                        vec![Node::bytes(KEY_MATERIAL, material.to_vec())],
                    ),
                    Node::enumeration(CRYPTOGRAPHIC_ALGORITHM, alg),
                    Node::int(CRYPTOGRAPHIC_LENGTH, (material.len() * 8) as i32),
                ],
            )],
        ),
    ]
}
fn create(alg: u32, bits: i32, usage: i32) -> Vec<Node> {
    vec![
        Node::enumeration(OBJECT_TYPE, 2),
        attrs(vec![
            Node::enumeration(CRYPTOGRAPHIC_ALGORITHM, alg),
            Node::int(CRYPTOGRAPHIC_LENGTH, bits),
            Node::int(CRYPTOGRAPHIC_USAGE_MASK, usage),
        ]),
    ]
}
/// Register an RSA private key (PKCS#8) and its public key (SPKI).
fn rsa_pair(s: &mut Server, key: &PKey<Private>) -> (String, String) {
    let bits = key.bits() as i32;
    let register = |kind: u32, tag: u32, format: u32, der: Vec<u8>, usage: i32| {
        vec![
            Node::enumeration(OBJECT_TYPE, kind),
            attrs(vec![Node::int(CRYPTOGRAPHIC_USAGE_MASK, usage)]),
            Node::structure(
                tag,
                vec![Node::structure(
                    KEY_BLOCK,
                    vec![
                        Node::enumeration(KEY_FORMAT_TYPE, format),
                        Node::structure(KEY_VALUE, vec![Node::bytes(KEY_MATERIAL, der)]),
                        Node::enumeration(CRYPTOGRAPHIC_ALGORITHM, 4),
                        Node::int(CRYPTOGRAPHIC_LENGTH, bits),
                    ],
                )],
            ),
        ]
    };
    let private = s.key(
        3,
        register(
            4,
            PRIVATE_KEY,
            4,
            key.private_key_to_pkcs8().unwrap(),
            1 | 0x20,
        ),
    );
    let public = s.key(
        3,
        register(3, PUBLIC_KEY, 5, key.public_key_to_der().unwrap(), 2 | 0x10),
    );
    (private, public)
}
/// Add an attribute to a Register/Create request's Attributes.
fn with(mut fields: Vec<Node>, attribute: Node) -> Vec<Node> {
    if let Value::Structure(list) = &mut fields[1].value {
        list.push(attribute);
    }
    fields
}
fn public_key(key: &PKey<Private>, usage: i32) -> Vec<Node> {
    vec![
        Node::enumeration(OBJECT_TYPE, 3),
        attrs(vec![Node::int(CRYPTOGRAPHIC_USAGE_MASK, usage)]),
        Node::structure(
            PUBLIC_KEY,
            vec![Node::structure(
                KEY_BLOCK,
                vec![
                    Node::enumeration(KEY_FORMAT_TYPE, 5),
                    Node::structure(
                        KEY_VALUE,
                        vec![Node::bytes(KEY_MATERIAL, key.public_key_to_der().unwrap())],
                    ),
                    Node::enumeration(CRYPTOGRAPHIC_ALGORITHM, 4),
                    Node::int(CRYPTOGRAPHIC_LENGTH, key.bits() as i32),
                ],
            )],
        ),
    ]
}
fn rsa(bits: u32) -> PKey<Private> {
    PKey::from_rsa(Rsa::generate(bits).unwrap()).unwrap()
}
fn sign(id: &str, hash: u32, padding: u32, extra: Vec<Node>) -> Vec<Node> {
    let mut params = vec![
        Node::enumeration(CRYPTOGRAPHIC_ALGORITHM, 4),
        Node::enumeration(PADDING_METHOD, padding),
        Node::enumeration(HASHING_ALGORITHM, hash),
    ];
    params.extend(extra);
    vec![uid(id), cp(params), Node::bytes(DATA, b"message".to_vec())]
}
fn verify(id: &str, hash: u32, padding: u32, extra: Vec<Node>, signature: Vec<u8>) -> Vec<Node> {
    let mut fields = sign(id, hash, padding, extra);
    fields.push(Node::bytes(SIGNATURE_DATA, signature));
    fields
}
fn validity(payload: &Node) -> u32 {
    payload
        .required(VALIDITY_INDICATOR)
        .unwrap()
        .number()
        .unwrap()
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
fn bytes(payload: &Node, tag: u32) -> Vec<u8> {
    payload
        .required(tag)
        .unwrap()
        .byte_string()
        .unwrap()
        .to_vec()
}

/// Replace values that differ between two servers by construction (object
/// identifiers, times, correlation values) so responses can be compared.
fn normalize(node: &Node, ids: &mut Vec<String>) -> Node {
    let value = match &node.value {
        Value::Structure(children) => {
            Value::Structure(children.iter().map(|c| normalize(c, ids)).collect())
        }
        Value::DateTime(_) => Value::DateTime(0),
        // A hash of the per-server Unique Identifier.
        Value::ByteString(_) if node.tag == SHORT_UNIQUE_IDENTIFIER => Value::ByteString(vec![]),
        Value::TextString(text)
            if matches!(
                node.tag,
                UNIQUE_IDENTIFIER
                    | LINKED_OBJECT_IDENTIFIER
                    | PRIVATE_KEY_UNIQUE_IDENTIFIER
                    | PUBLIC_KEY_UNIQUE_IDENTIFIER
                    | SERVER_CORRELATION_VALUE
            ) || node.tag == NAME_VALUE && text.len() == 36 =>
        {
            let index = ids.iter().position(|i| i == text).unwrap_or_else(|| {
                ids.push(text.clone());
                ids.len() - 1
            });
            Value::TextString(format!("<{index}>"))
        }
        other => other.clone(),
    };
    Node {
        tag: node.tag,
        value,
    }
}

/// REQ-free comparison: for a representative set of approved requests the
/// FIPS-mode responses equal the default-mode ones exactly, after the
/// per-server identifiers and times are normalized. Deterministic
/// mechanisms only, so every output byte is compared.
#[test]
fn approved_requests_answer_identically_in_both_modes() {
    let mut b = both();
    let rsa_key = rsa(2048);
    let aes = [0x11u8; 32];
    let hmac = [0x22u8; 32];
    let wrap_kek = [0x33u8; 16];
    let mut log: [Vec<Node>; 2] = [vec![], vec![]];
    for (index, s) in [&mut b.default, &mut b.fips].into_iter().enumerate() {
        let out = &mut log[index];
        let mut record = |item: Node| out.push(item);
        let key = s.key(3, symmetric(3, &aes, 4 | 8));
        let mac_key = s.key(3, symmetric(9, &hmac, 0x80 | 0x100));
        let kek = s.key(
            3,
            with(
                symmetric(3, &wrap_kek, 0x10 | 0x20),
                cp(vec![Node::enumeration(BLOCK_CIPHER_MODE, 13)]),
            ),
        );
        let (private, public) = rsa_pair(s, &rsa_key);
        let iv = vec![0x44; 16];
        for (mode, padding) in [(1, 3), (2, 3), (4, 1), (5, 1), (6, 1)] {
            let mut fields = vec![
                uid(&key),
                cp(vec![
                    Node::enumeration(BLOCK_CIPHER_MODE, mode),
                    Node::enumeration(PADDING_METHOD, padding),
                ]),
                Node::bytes(DATA, b"approved data 16".to_vec()),
            ];
            if mode != 2 {
                fields.push(Node::bytes(IV_COUNTER_NONCE, iv.clone()));
            }
            record(s.call(31, fields.clone()));
            let ciphertext = bytes(&s.ok(31, fields.clone()), DATA);
            fields[2] = Node::bytes(DATA, ciphertext);
            record(s.call(32, fields));
        }
        // AES-GCM decryption with a client IV, and encryption with a
        // server-generated one (round trip; the IV itself is random).
        let gcm = |extra: Vec<Node>| {
            let mut params = vec![
                Node::enumeration(BLOCK_CIPHER_MODE, 9),
                Node::int(TAG_LENGTH, 16),
            ];
            params.extend(extra);
            cp(params)
        };
        let sealed = s.ok(
            31,
            vec![
                uid(&key),
                gcm(vec![Node::boolean(RANDOM_IV, true)]),
                Node::bytes(DATA, b"gcm".to_vec()),
            ],
        );
        record(s.call(
            32,
            vec![
                uid(&key),
                gcm(vec![]),
                Node::bytes(DATA, bytes(&sealed, DATA)),
                Node::bytes(IV_COUNTER_NONCE, bytes(&sealed, IV_COUNTER_NONCE)),
                Node::bytes(
                    AUTHENTICATED_ENCRYPTION_TAG,
                    bytes(&sealed, AUTHENTICATED_ENCRYPTION_TAG),
                ),
            ],
        ));
        record(s.call(
            35,
            vec![uid(&mac_key), Node::bytes(DATA, b"mac me".to_vec())],
        ));
        for hash in [4, 6, 7, 8, 15] {
            record(s.call(
                39,
                vec![
                    cp(vec![Node::enumeration(HASHING_ALGORITHM, hash)]),
                    Node::bytes(DATA, b"abc".to_vec()),
                ],
            ));
        }
        // RSA PKCS#1 v1.5 signatures are deterministic.
        record(s.call(33, sign(&private, 6, 8, vec![])));
        let signature = bytes(&s.ok(33, sign(&private, 6, 8, vec![])), SIGNATURE_DATA);
        record(s.call(34, verify(&public, 6, 8, vec![], signature)));
        // AES key wrap of a registered key (deterministic).
        record(s.call(
            10,
            vec![
                uid(&key),
                Node::structure(
                    KEY_WRAPPING_SPECIFICATION,
                    vec![
                        Node::enumeration(WRAPPING_METHOD, 1),
                        Node::structure(ENCRYPTION_KEY_INFORMATION, vec![uid(&kek)]),
                    ],
                ),
            ],
        ));
        record(s.call(10, vec![uid(&key)]));
        record(s.call(11, vec![uid(&key)]));
        record(s.call(
            24,
            vec![
                Node::enumeration(QUERY_FUNCTION, 3),
                Node::enumeration(QUERY_FUNCTION, 8),
                Node::enumeration(QUERY_FUNCTION, 11),
            ],
        ));
        // Derive Key: PBKDF2 (salt and count at the SP 800-132 minimums)
        // and HKDF, both deterministic.
        let password = s.key(3, {
            let mut f = symmetric(9, b"a long enough password", 0x200);
            f[2] = Node::structure(
                SECRET_DATA,
                vec![
                    Node::enumeration(SECRET_DATA_TYPE, 1),
                    Node::structure(
                        KEY_BLOCK,
                        vec![
                            Node::enumeration(KEY_FORMAT_TYPE, 1),
                            Node::structure(
                                KEY_VALUE,
                                vec![Node::bytes(
                                    KEY_MATERIAL,
                                    b"a long enough password".to_vec(),
                                )],
                            ),
                        ],
                    ),
                ],
            );
            f[0] = Node::enumeration(OBJECT_TYPE, 7);
            f
        });
        let derive = |id: &str, method: u32, params: Vec<Node>| {
            vec![
                Node::enumeration(OBJECT_TYPE, 2),
                uid(id),
                Node::enumeration(DERIVATION_METHOD, method),
                Node::structure(DERIVATION_PARAMETERS, params),
                attrs(vec![
                    Node::enumeration(CRYPTOGRAPHIC_ALGORITHM, 3),
                    Node::int(CRYPTOGRAPHIC_LENGTH, 128),
                    Node::int(CRYPTOGRAPHIC_USAGE_MASK, 12),
                ]),
            ]
        };
        let derived = s.id(
            5,
            derive(
                &password,
                1,
                vec![
                    cp(vec![Node::enumeration(HASHING_ALGORITHM, 6)]),
                    Node::bytes(SALT, vec![1; 16]),
                    Node::int(ITERATION_COUNT, 1000),
                ],
            ),
        );
        record(s.call(10, vec![uid(&derived)]));
        let ikm = s.key(3, symmetric(3, &[0x55; 32], 0x200));
        let derived = s.id(
            5,
            derive(
                &ikm,
                10,
                vec![
                    cp(vec![Node::enumeration(HASHING_ALGORITHM, 6)]),
                    Node::bytes(SALT, b"salt".to_vec()),
                    Node::bytes(DERIVATION_DATA, b"info".to_vec()),
                ],
            ),
        );
        record(s.call(10, vec![uid(&derived)]));
        // Approved generation: random output, so the status and the
        // identifiers are compared.
        let created = s.call(1, create(3, 256, 12));
        record(created.clone());
        record(
            s.call(
                2,
                vec![
                    attrs(vec![
                        Node::enumeration(CRYPTOGRAPHIC_ALGORITHM, 6),
                        Node::structure(
                            CRYPTOGRAPHIC_DOMAIN_PARAMETERS,
                            vec![Node::enumeration(RECOMMENDED_CURVE, 7)],
                        ),
                    ]),
                    Node::structure(
                        PRIVATE_KEY_ATTRIBUTES,
                        vec![Node::int(CRYPTOGRAPHIC_USAGE_MASK, 1)],
                    ),
                    Node::structure(
                        PUBLIC_KEY_ATTRIBUTES,
                        vec![Node::int(CRYPTOGRAPHIC_USAGE_MASK, 2)],
                    ),
                ]
                .into_iter()
                .map(|n| {
                    if n.tag == ATTRIBUTES {
                        Node {
                            tag: COMMON_ATTRIBUTES,
                            value: n.value,
                        }
                    } else {
                        n
                    }
                })
                .collect(),
            ),
        );
    }
    let [default, fips] = log;
    assert!(default.len() > 25, "{}", default.len());
    let (mut a, mut b) = (vec![], vec![]);
    for (d, f) in default.iter().zip(&fips) {
        assert_eq!(status(d).0, OK, "{}", show(d));
        assert_eq!(show(&normalize(d, &mut a)), show(&normalize(f, &mut b)));
    }
}

/// Query in FIPS mode lists only what FIPS mode offers: no Create Split
/// Key, Join Split Key or Split Key object type, and (draft 3.0) no
/// Encapsulate or Decapsulate, which are ML-KEM only (docs/algorithms.md#post-quantum-keys).
/// Everything else is equal.
#[test]
fn query_hides_only_the_split_key_and_kem_services() {
    let mut b = both();
    for v in [V14, V, Version(3, 0)] {
        let query = vec![
            Node::enumeration(QUERY_FUNCTION, 1),
            Node::enumeration(QUERY_FUNCTION, 2),
        ];
        let d = b.default.call_as(v, None, 24, query.clone());
        let f = b.fips.call_as(v, None, 24, query);
        let values = |item: &Node, tag| -> Vec<u32> {
            item.required(RESPONSE_PAYLOAD)
                .unwrap()
                .all(tag)
                .map(|n| n.number().unwrap())
                .collect()
        };
        let mut expected = values(&d, OPERATION);
        assert!(expected.contains(&40) && expected.contains(&41));
        assert_eq!(
            expected.contains(&65) && expected.contains(&66),
            v.0 >= 3,
            "{v:?}"
        );
        expected.retain(|op| !matches!(op, 40 | 41 | 65 | 66));
        assert_eq!(values(&f, OPERATION), expected, "{v:?}");
        let mut kinds = values(&d, OBJECT_TYPE);
        assert!(kinds.contains(&5));
        kinds.retain(|k| *k != 5);
        assert_eq!(values(&f, OBJECT_TYPE), kinds);
        // The RNG and capability answers do not change.
        let other = vec![
            Node::enumeration(QUERY_FUNCTION, 8),
            Node::enumeration(QUERY_FUNCTION, 11),
        ];
        assert_eq!(
            show(
                b.default
                    .call_as(v, None, 24, other.clone())
                    .required(RESPONSE_PAYLOAD)
                    .unwrap()
            ),
            show(
                b.fips
                    .call_as(v, None, 24, other)
                    .required(RESPONSE_PAYLOAD)
                    .unwrap()
            )
        );
    }
}

#[test]
fn split_key_operations_and_objects_are_refused_in_fips_mode_only() {
    let mut b = both();
    let split = vec![
        Node::enumeration(OBJECT_TYPE, 5),
        Node::int(SPLIT_KEY_PARTS, 2),
        Node::int(SPLIT_KEY_THRESHOLD, 2),
        Node::enumeration(SPLIT_KEY_METHOD, 1),
        attrs(vec![
            Node::enumeration(CRYPTOGRAPHIC_ALGORITHM, 3),
            Node::int(CRYPTOGRAPHIC_LENGTH, 128),
            Node::int(CRYPTOGRAPHIC_USAGE_MASK, 12),
        ]),
    ];
    let d = b.default.call(40, split.clone());
    assert_eq!(status(&d).0, OK, "{}", show(&d));
    let f = b.fips.call(40, split);
    assert_eq!(status(&f).1, 5, "Operation Not Supported: {}", show(&f));
    let join = vec![Node::enumeration(OBJECT_TYPE, 2), uid("x"), uid("y")];
    assert_eq!(status(&b.fips.call(41, join)).1, 5);
    // A Split Key object cannot be registered either.
    let share = vec![
        Node::enumeration(OBJECT_TYPE, 5),
        attrs(vec![Node::int(CRYPTOGRAPHIC_USAGE_MASK, 12)]),
        Node::structure(
            SPLIT_KEY,
            vec![
                Node::int(SPLIT_KEY_PARTS, 2),
                Node::int(KEY_PART_IDENTIFIER, 1),
                Node::int(SPLIT_KEY_THRESHOLD, 2),
                Node::enumeration(SPLIT_KEY_METHOD, 1),
                Node::structure(
                    KEY_BLOCK,
                    vec![
                        Node::enumeration(KEY_FORMAT_TYPE, 1),
                        Node::structure(KEY_VALUE, vec![Node::bytes(KEY_MATERIAL, vec![1; 16])]),
                        Node::enumeration(CRYPTOGRAPHIC_ALGORITHM, 3),
                        Node::int(CRYPTOGRAPHIC_LENGTH, 128),
                    ],
                ),
            ],
        ),
    ];
    assert_eq!(status(&b.default.call(3, share.clone())).0, OK);
    refused(&b.fips.call(3, share), FEATURE_NOT_SUPPORTED);
}

/// SP 800-131A Rev. 2: ChaCha20 (and the other non-approved key labels)
/// are neither generated nor used in FIPS mode; AES is.
#[test]
fn non_approved_symmetric_algorithms_are_refused_in_fips_mode() {
    let mut b = both();
    for (alg, bits) in [(28, 256), (30, 256), (12, 256)] {
        assert_eq!(status(&b.default.call(1, create(alg, bits, 12))).0, OK);
        refused(&b.fips.call(1, create(alg, bits, 12)), INVALID_FIELD);
        // Registering is refused the same way as creating.
        refused(&b.fips.call(3, symmetric(alg, &[1; 32], 12)), INVALID_FIELD);
    }
    assert_eq!(status(&b.fips.call(1, create(3, 128, 12))).0, OK);
    // A ChaCha20 key stored before FIPS mode was turned on cannot encrypt.
    let chacha = b.default.key(3, symmetric(30, &[1; 32], 12));
    let mut fips = Server {
        _dir: b.default._dir,
        e: Engine::new(b.default.e.store, true).with_fips(true),
    };
    let encrypt = vec![
        uid(&chacha),
        cp(vec![Node::boolean(RANDOM_IV, true)]),
        Node::bytes(DATA, b"x".to_vec()),
    ];
    refused(&fips.call(31, encrypt), FEATURE_NOT_SUPPORTED);
}

/// HMAC: keys of 112 bits or more are generated and MAC; a shorter
/// registered key still verifies (legacy use). HMAC-MD5 never runs.
#[test]
fn hmac_key_length_and_md5_in_fips_mode() {
    let mut b = both();
    assert_eq!(status(&b.default.call(1, create(9, 104, 0x180))).0, OK);
    refused(&b.fips.call(1, create(9, 104, 0x180)), INVALID_FIELD);
    assert_eq!(status(&b.fips.call(1, create(9, 112, 0x180))).0, OK);
    for s in [&mut b.default, &mut b.fips] {
        let short = s.key(3, symmetric(9, &[7; 13], 0x180));
        let mac = vec![uid(&short), Node::bytes(DATA, b"m".to_vec())];
        let item = s.call(35, mac.clone());
        if s.e.fips() {
            refused(&item, FEATURE_NOT_SUPPORTED);
        } else {
            assert_eq!(status(&item).0, OK);
        }
        let expected = openssl::sign::Signer::new(
            openssl::hash::MessageDigest::sha256(),
            &PKey::hmac(&[7; 13]).unwrap(),
        )
        .unwrap()
        .sign_oneshot_to_vec(b"m")
        .unwrap();
        let mut check = mac;
        check.push(Node::bytes(MAC_DATA, expected));
        assert_eq!(validity(&s.ok(36, check)), 1);
    }
    // HMAC-MD5 selected for a stored SHA-256 key.
    let key = b.fips.key(3, symmetric(9, &[7; 32], 0x180));
    refused(
        &b.fips.call(
            35,
            vec![
                uid(&key),
                cp(vec![Node::enumeration(CRYPTOGRAPHIC_ALGORITHM, 12)]),
                Node::bytes(DATA, b"m".to_vec()),
            ],
        ),
        FEATURE_NOT_SUPPORTED,
    );
}

/// FIPS 186-5 and SP 800-131A Rev. 2: RSA signatures need 2048 bits and
/// SHA-2 to generate; 1024-bit keys and SHA-1 still verify. PSS salts
/// longer than the hash are not generated.
#[test]
fn rsa_signature_rules_in_fips_mode() {
    let mut b = both();
    let small = rsa(1024);
    let large = rsa(2048);
    for s in [&mut b.default, &mut b.fips] {
        let fips = s.e.fips();
        let (small_private, small_public) = rsa_pair(s, &small);
        let (private, public) = rsa_pair(s, &large);
        let expect = |item: &Node, ok: bool| {
            if ok {
                assert_eq!(status(item).0, OK, "{}", show(item));
            } else {
                refused(item, UNSUPPORTED_PARAMETERS);
            }
        };
        expect(&s.call(33, sign(&small_private, 6, 8, vec![])), !fips);
        expect(&s.call(33, sign(&private, 4, 8, vec![])), !fips);
        expect(&s.call(33, sign(&private, 6, 8, vec![])), true);
        // PSS: 2.1's default salt is the MGF hash block size (64 > 32).
        expect(&s.call(33, sign(&private, 6, 10, vec![])), !fips);
        expect(
            &s.call(
                33,
                sign(
                    &private,
                    6,
                    10,
                    vec![
                        Node::int(SALT_LENGTH, 32),
                        Node::enumeration(MASK_GENERATOR_HASHING_ALGORITHM, 6),
                    ],
                ),
            ),
            true,
        );
        // Verification with a 1024-bit key is legacy use and allowed. SHA-1
        // signatures are refused in FIPS mode, verification included: the
        // RHEL 9 provider refuses that digest for RSA and ECDSA signatures.
        let digest = openssl::hash::MessageDigest::sha1();
        let mut signer = openssl::sign::Signer::new(digest, &large).unwrap();
        let sha1 = signer.sign_oneshot_to_vec(b"message").unwrap();
        let item = s.call(34, verify(&public, 4, 8, vec![], sha1));
        if fips {
            refused(&item, UNSUPPORTED_PARAMETERS);
        } else {
            assert_eq!(status(&item).0, OK, "{}", show(&item));
            assert_eq!(validity(item.required(RESPONSE_PAYLOAD).unwrap()), 1);
        }
        // A SHA-1 MGF1 hash in a PSS signature still verifies (legacy use).
        let mut signer =
            openssl::sign::Signer::new(openssl::hash::MessageDigest::sha256(), &large).unwrap();
        signer
            .set_rsa_padding(openssl::rsa::Padding::PKCS1_PSS)
            .unwrap();
        signer
            .set_rsa_mgf1_md(openssl::hash::MessageDigest::sha1())
            .unwrap();
        signer
            .set_rsa_pss_saltlen(openssl::sign::RsaPssSaltlen::custom(32))
            .unwrap();
        let pss = signer.sign_oneshot_to_vec(b"message").unwrap();
        let mgf1 = vec![
            Node::int(SALT_LENGTH, 32),
            Node::enumeration(MASK_GENERATOR_HASHING_ALGORITHM, 4),
        ];
        assert_eq!(validity(&s.ok(34, verify(&public, 6, 10, mgf1, pss))), 1);
        let mut signer =
            openssl::sign::Signer::new(openssl::hash::MessageDigest::sha256(), &small).unwrap();
        let small_sig = signer.sign_oneshot_to_vec(b"message").unwrap();
        assert_eq!(
            validity(&s.ok(34, verify(&small_public, 6, 8, vec![], small_sig))),
            1
        );
        // RSA-OAEP key transport below 2048 bits is refused both ways.
        let oaep = |id: &str| {
            vec![
                uid(id),
                cp(vec![
                    Node::enumeration(CRYPTOGRAPHIC_ALGORITHM, 4),
                    Node::enumeration(PADDING_METHOD, 2),
                    Node::enumeration(HASHING_ALGORITHM, 6),
                ]),
                Node::bytes(DATA, b"secret".to_vec()),
            ]
        };
        // The public keys above were registered for Verify and Wrap only.
        let encryptor = s.key(3, public_key(&small, 4));
        expect(&s.call(31, oaep(&encryptor)), !fips);
    }
}

/// EC: P-224, P-256, P-384 and P-521 only; no ECDSA with SHA-1, neither
/// signing nor verification (the RHEL 9 provider refuses both).
#[test]
fn ec_curves_and_ecdsa_hashes_in_fips_mode() {
    let mut b = both();
    let pair = |curve: u32| {
        vec![
            Node::structure(
                COMMON_ATTRIBUTES,
                vec![
                    Node::enumeration(CRYPTOGRAPHIC_ALGORITHM, 6),
                    Node::structure(
                        CRYPTOGRAPHIC_DOMAIN_PARAMETERS,
                        vec![Node::enumeration(RECOMMENDED_CURVE, curve)],
                    ),
                ],
            ),
            Node::structure(
                PRIVATE_KEY_ATTRIBUTES,
                vec![Node::int(CRYPTOGRAPHIC_USAGE_MASK, 1)],
            ),
            Node::structure(
                PUBLIC_KEY_ATTRIBUTES,
                vec![Node::int(CRYPTOGRAPHIC_USAGE_MASK, 2)],
            ),
        ]
    };
    // secp256k1 and brainpoolP256r1: offered outside FIPS mode under the
    // default `extended`, refused with `--ec-curves nist`. FIPS mode refuses
    // them as before under either value (FIPS mode only disables).
    for curve in [25, 61] {
        assert_eq!(
            status(&b.default.call(2, pair(curve))).0,
            OK,
            "curve {curve}"
        );
        refused(&b.fips.call(2, pair(curve)), FEATURE_NOT_SUPPORTED);
        let mut nist = server(false);
        nist.e = nist.e.with_ec_curves(EcCurves::Nist);
        assert_eq!(
            status(&nist.call(2, pair(curve))),
            (1, FEATURE_NOT_SUPPORTED, "Unsupported EC curve".to_owned()),
            "curve {curve}"
        );
        let mut nist_fips = server(true);
        nist_fips.e = nist_fips.e.with_ec_curves(EcCurves::Nist);
        refused(&nist_fips.call(2, pair(curve)), FEATURE_NOT_SUPPORTED);
    }
    // P-192 is not supported in either mode (docs/interpretations.md), so
    // both answer alike, without naming FIPS mode.
    for s in [&mut b.default, &mut b.fips] {
        assert_eq!(
            status(&s.call(2, pair(1))),
            (1, FEATURE_NOT_SUPPORTED, "Unsupported EC curve".to_owned())
        );
    }
    for s in [&mut b.default, &mut b.fips] {
        let fips = s.e.fips();
        for curve in [4, 7, 10, 13] {
            assert_eq!(status(&s.call(2, pair(curve))).0, OK, "curve {curve}");
        }
        let ids = s.ok(2, pair(7));
        let private = ids
            .required(PRIVATE_KEY_UNIQUE_IDENTIFIER)
            .unwrap()
            .string()
            .unwrap()
            .to_owned();
        let public = ids
            .required(PUBLIC_KEY_UNIQUE_IDENTIFIER)
            .unwrap()
            .string()
            .unwrap()
            .to_owned();
        s.ok(18, vec![uid(&private)]);
        s.ok(18, vec![uid(&public)]);
        let ecdsa = |id: &str, hash: u32| {
            vec![
                uid(id),
                cp(vec![
                    Node::enumeration(CRYPTOGRAPHIC_ALGORITHM, 6),
                    Node::enumeration(HASHING_ALGORITHM, hash),
                ]),
                Node::bytes(DATA, b"message".to_vec()),
            ]
        };
        let item = s.call(33, ecdsa(&private, 4));
        if fips {
            refused(&item, FEATURE_NOT_SUPPORTED);
        } else {
            assert_eq!(status(&item).0, OK);
        }
        // A SHA-1 ECDSA signature made outside the server.
        let group = openssl::ec::EcGroup::from_curve_name(openssl::nid::Nid::X9_62_PRIME256V1);
        let key =
            PKey::from_ec_key(openssl::ec::EcKey::generate(&group.unwrap()).unwrap()).unwrap();
        let mut fields = public_key(&key, 2);
        if let Value::Structure(block) = &mut fields[2].value
            && let Value::Structure(items) = &mut block[0].value
        {
            items[2] = Node::enumeration(CRYPTOGRAPHIC_ALGORITHM, 6);
            items[3] = Node::int(CRYPTOGRAPHIC_LENGTH, 256);
        }
        let external = s.key(3, fields);
        let mut signer =
            openssl::sign::Signer::new(openssl::hash::MessageDigest::sha1(), &key).unwrap();
        let mut check = ecdsa(&external, 4);
        check.push(Node::bytes(
            SIGNATURE_DATA,
            signer.sign_oneshot_to_vec(b"message").unwrap(),
        ));
        let item = s.call(34, check);
        if fips {
            refused(&item, FEATURE_NOT_SUPPORTED);
        } else {
            assert_eq!(status(&item).0, OK);
            assert_eq!(validity(item.required(RESPONSE_PAYLOAD).unwrap()), 1);
        }
        for hash in [6, 7] {
            let signature = bytes(&s.ok(33, ecdsa(&private, hash)), SIGNATURE_DATA);
            let mut check = ecdsa(&public, hash);
            check.push(Node::bytes(SIGNATURE_DATA, signature));
            assert_eq!(validity(&s.ok(34, check)), 1);
        }
    }
}

/// AES-GCM: tags of 96 bits and more; FIPS mode encrypts only with an IV it
/// generates (at least 96 bits). Decryption takes the client's IV.
#[test]
fn aes_gcm_iv_and_tag_rules_in_fips_mode() {
    let mut b = both();
    for s in [&mut b.default, &mut b.fips] {
        let fips = s.e.fips();
        let key = s.key(3, symmetric(3, &[3; 16], 12));
        let gcm = |extra: Vec<Node>, more: Vec<Node>| {
            let mut params = vec![Node::enumeration(BLOCK_CIPHER_MODE, 9)];
            params.extend(extra);
            let mut fields = vec![uid(&key), cp(params), Node::bytes(DATA, b"data".to_vec())];
            fields.extend(more);
            fields
        };
        let client_iv = vec![Node::bytes(IV_COUNTER_NONCE, vec![5; 12])];
        let item = s.call(31, gcm(vec![], client_iv.clone()));
        if fips {
            refused(&item, FEATURE_NOT_SUPPORTED);
        } else {
            assert_eq!(status(&item).0, OK);
        }
        let item = s.call(
            31,
            gcm(
                vec![Node::int(TAG_LENGTH, 8), Node::boolean(RANDOM_IV, true)],
                vec![],
            ),
        );
        if fips {
            refused(&item, GENERAL_FAILURE);
        } else {
            assert_eq!(status(&item).0, OK);
        }
        let item = s.call(
            31,
            gcm(
                vec![Node::boolean(RANDOM_IV, true), Node::int(IV_LENGTH, 64)],
                vec![],
            ),
        );
        if fips {
            refused(&item, INVALID_FIELD);
        } else {
            assert_eq!(status(&item).0, OK);
        }
        let sealed = s.ok(31, gcm(vec![Node::boolean(RANDOM_IV, true)], vec![]));
        assert_eq!(bytes(&sealed, IV_COUNTER_NONCE).len(), 12);
        // Data sealed elsewhere with a client IV decrypts in both modes.
        let mut tag = vec![0; 16];
        let ciphertext = openssl::symm::encrypt_aead(
            openssl::symm::Cipher::aes_128_gcm(),
            &[3; 16],
            Some(&[5; 12]),
            b"",
            b"data",
            &mut tag,
        )
        .unwrap();
        let mut fields = gcm(vec![], client_iv.clone());
        fields[2] = Node::bytes(DATA, ciphertext);
        fields.push(Node::bytes(AUTHENTICATED_ENCRYPTION_TAG, tag));
        assert_eq!(bytes(&s.ok(32, fields), DATA), b"data");
    }
}

/// Derive Key: only PBKDF2 (password >= 8 bytes, salt >= 128 bits, count
/// >= 1000, output >= 112 bits) and HKDF (key >= 112 bits).
#[test]
fn derivation_methods_in_fips_mode() {
    let mut b = both();
    for s in [&mut b.default, &mut b.fips] {
        let fips = s.e.fips();
        let hmac = s.key(3, symmetric(9, &[8; 32], 0x200));
        let short = s.key(3, symmetric(3, &[8; 16], 0x200));
        let tiny = s.key(3, symmetric(9, &[8; 8], 0x200));
        let seven = s.key(3, symmetric(9, &[8; 7], 0x200));
        let derive = |id: &str, method: u32, params: Vec<Node>, bits: i32| {
            vec![
                Node::enumeration(OBJECT_TYPE, 2),
                uid(id),
                Node::enumeration(DERIVATION_METHOD, method),
                Node::structure(DERIVATION_PARAMETERS, params),
                attrs(vec![
                    Node::enumeration(CRYPTOGRAPHIC_ALGORITHM, 3),
                    Node::int(CRYPTOGRAPHIC_LENGTH, bits),
                    Node::int(CRYPTOGRAPHIC_USAGE_MASK, 12),
                ]),
            ]
        };
        let expect = |item: &Node, ok: bool| {
            if ok {
                assert_eq!(status(item).0, OK, "{}", show(item));
            } else {
                refused(item, UNSUPPORTED_PARAMETERS);
            }
        };
        // HMAC, HASH and SP 800-108 counter mode.
        let data = || Node::bytes(DERIVATION_DATA, vec![1; 32]);
        expect(&s.call(5, derive(&hmac, 3, vec![data()], 128)), !fips);
        expect(
            &s.call(
                5,
                derive(
                    &hmac,
                    2,
                    vec![cp(vec![Node::enumeration(HASHING_ALGORITHM, 6)])],
                    128,
                ),
            ),
            !fips,
        );
        expect(&s.call(5, derive(&hmac, 5, vec![data()], 128)), !fips);
        let pbkdf2 = |salt: usize, count: i32| {
            vec![
                cp(vec![Node::enumeration(HASHING_ALGORITHM, 6)]),
                Node::bytes(SALT, vec![1; salt]),
                Node::int(ITERATION_COUNT, count),
            ]
        };
        expect(&s.call(5, derive(&hmac, 1, pbkdf2(16, 1000), 128)), true);
        expect(&s.call(5, derive(&hmac, 1, pbkdf2(8, 1000), 128)), !fips);
        expect(&s.call(5, derive(&hmac, 1, pbkdf2(16, 999), 128)), !fips);
        // The password needs 8 bytes in FIPS mode (the RHEL 9 provider's bound).
        expect(&s.call(5, derive(&tiny, 1, pbkdf2(16, 1000), 128)), true);
        expect(&s.call(5, derive(&seven, 1, pbkdf2(16, 1000), 128)), !fips);
        let hkdf = vec![cp(vec![Node::enumeration(HASHING_ALGORITHM, 6)]), data()];
        expect(&s.call(5, derive(&short, 10, hkdf.clone(), 128)), true);
        expect(&s.call(5, derive(&tiny, 10, hkdf, 128)), !fips);
    }
}

/// Key wrapping with RSA-OAEP needs a 2048-bit key in FIPS mode; AES key
/// wrap is unchanged.
#[test]
fn rsa_key_wrapping_in_fips_mode() {
    let mut b = both();
    let small = rsa(1024);
    for s in [&mut b.default, &mut b.fips] {
        let fips = s.e.fips();
        let public = s.key(
            3,
            with(
                public_key(&small, 0x10),
                cp(vec![
                    Node::enumeration(PADDING_METHOD, 2),
                    Node::enumeration(HASHING_ALGORITHM, 6),
                ]),
            ),
        );
        let key = s.key(3, symmetric(3, &[3; 16], 12));
        let item = s.call(
            10,
            vec![
                uid(&key),
                Node::structure(
                    KEY_WRAPPING_SPECIFICATION,
                    vec![
                        Node::enumeration(WRAPPING_METHOD, 1),
                        Node::structure(ENCRYPTION_KEY_INFORMATION, vec![uid(&public)]),
                    ],
                ),
            ],
        );
        if fips {
            refused(&item, FEATURE_NOT_SUPPORTED);
        } else {
            assert_eq!(status(&item).0, OK, "{}", show(&item));
        }
    }
}

/// DSA verification (FIPS 186-5 removed DSA) is refused in FIPS mode.
#[test]
fn dsa_verification_is_refused_in_fips_mode() {
    let mut b = both();
    let dsa = PKey::from_dsa(openssl::dsa::Dsa::generate(2048).unwrap()).unwrap();
    let mut signer =
        openssl::sign::Signer::new(openssl::hash::MessageDigest::sha256(), &dsa).unwrap();
    let signature = signer.sign_oneshot_to_vec(b"message").unwrap();
    for s in [&mut b.default, &mut b.fips] {
        let fips = s.e.fips();
        let k = dsa.dsa().unwrap();
        let material = Node::structure(
            KEY_MATERIAL,
            vec![
                big(P, &k.p().to_vec()),
                big(Q, &k.q().to_vec()),
                big(G, &k.g().to_vec()),
                big(Y, &k.pub_key().to_vec()),
            ],
        );
        let register = vec![
            Node::enumeration(OBJECT_TYPE, 3),
            attrs(vec![Node::int(CRYPTOGRAPHIC_USAGE_MASK, 2)]),
            Node::structure(
                PUBLIC_KEY,
                vec![Node::structure(
                    KEY_BLOCK,
                    vec![
                        Node::enumeration(KEY_FORMAT_TYPE, 9),
                        Node::structure(KEY_VALUE, vec![material]),
                        Node::enumeration(CRYPTOGRAPHIC_ALGORITHM, 5),
                    ],
                )],
            ),
        ];
        let item = s.call(3, register);
        if fips {
            // Not even stored: DSA is not a FIPS-mode key algorithm.
            refused(&item, FEATURE_NOT_SUPPORTED);
            continue;
        }
        let id = item
            .required(RESPONSE_PAYLOAD)
            .unwrap()
            .required(UNIQUE_IDENTIFIER)
            .unwrap()
            .string()
            .unwrap()
            .to_owned();
        s.ok(18, vec![uid(&id)]);
        let check = vec![
            uid(&id),
            cp(vec![
                Node::enumeration(CRYPTOGRAPHIC_ALGORITHM, 5),
                Node::enumeration(HASHING_ALGORITHM, 6),
            ]),
            Node::bytes(DATA, b"message".to_vec()),
            Node::bytes(SIGNATURE_DATA, signature.clone()),
        ];
        assert_eq!(validity(&s.ok(34, check.clone())), 1);
        // The same stored key under a FIPS-mode server.
        let store = std::mem::replace(
            &mut s.e,
            Engine::new(
                Store::open(
                    &s._dir.path().join("other.sqlite"),
                    &s._dir.path().join("master"),
                )
                .unwrap(),
                true,
            ),
        )
        .store;
        let mut fips_engine = Engine::new(store, true).with_fips(true);
        let item = fips_engine
            .process("alice", &request(V, None, vec![(34, check)]))
            .unwrap();
        refused(item.required(BATCH_ITEM).unwrap(), FEATURE_NOT_SUPPORTED);
    }
}

/// Users-file and System credentials: PBKDF2 verifiers authenticate in
/// both modes, with passwords of at least 8 bytes in FIPS mode; a legacy
/// scrypt verifier authenticates in default mode only
/// (Authentication Not Successful in FIPS mode).
#[test]
fn legacy_scrypt_credentials_authenticate_only_outside_fips_mode() {
    let legacy: PasswordVerifier = {
        let salt = vec![9u8; 16];
        let mut hash = vec![0; 32];
        openssl::pkcs5::scrypt(b"old", &salt, 1 << 15, 8, 1, 64 << 20, &mut hash).unwrap();
        serde_json::from_value(serde_json::json!({"log_n": 15, "r": 8, "p": 1, "salt": hex::encode(&salt), "hash": hex::encode(&hash)})).unwrap()
    };
    assert!(legacy.is_legacy());
    for fips in [false, true] {
        let mut s = server(fips);
        s.e.add_policy_users(
            "alice",
            vec![
                PolicyUser {
                    username: "old".into(),
                    password_scrypt: legacy.clone(),
                    administrator: false,
                    hashed_password: None,
                    one_time_password: None,
                },
                PolicyUser {
                    username: "new".into(),
                    password_scrypt: PasswordVerifier::new(b"new password").unwrap(),
                    administrator: false,
                    hashed_password: None,
                    one_time_password: None,
                },
                PolicyUser {
                    username: "short".into(),
                    password_scrypt: PasswordVerifier::new(b"short").unwrap(),
                    administrator: false,
                    hashed_password: None,
                    one_time_password: None,
                },
            ],
        )
        .unwrap();
        let login = |user: &str, pw: &str| {
            Node::structure(
                AUTHENTICATION,
                vec![Node::structure(
                    CREDENTIAL,
                    vec![
                        Node::enumeration(CREDENTIAL_TYPE, 1),
                        Node::structure(
                            CREDENTIAL_VALUE,
                            vec![Node::text(USERNAME, user), Node::text(PASSWORD, pw)],
                        ),
                    ],
                )],
            )
        };
        let query = || vec![Node::enumeration(QUERY_FUNCTION, 3)];
        let reason = |s: &mut Server, user: &str, pw: &str| {
            let response =
                s.e.process(
                    "alice",
                    &request(V, Some(login(user, pw)), vec![(24, query())]),
                )
                .unwrap();
            match response.get(BATCH_ITEM) {
                Some(item) => status(item).1,
                None => 3,
            }
        };
        assert_eq!(reason(&mut s, "new", "new password"), 0);
        assert_eq!(reason(&mut s, "new", "bad"), 3);
        // PBKDF2 passwords under 8 bytes: refused in FIPS mode, as by the
        // RHEL 9 provider.
        assert_eq!(reason(&mut s, "short", "short"), if fips { 3 } else { 0 });
        assert_eq!(reason(&mut s, "old", "old"), if fips { 3 } else { 0 });
    }
}

/// The verifier the operator command prints is the users-file form, and
/// FIPS-mode startup refuses settings that would need non-approved services
/// before anything is loaded or read.
#[test]
fn cli_password_verifier_and_fips_startup_refusals() {
    use std::io::Write;
    use std::process::{Command, Stdio};
    let binary = env!("CARGO_BIN_EXE_keytend-kmip-server");
    let mut child = Command::new(binary)
        .arg("password-verifier")
        .env_remove("KMIP_FIPS")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(b"s3cret\n").unwrap();
    let out = child.wait_with_output().unwrap();
    assert!(out.status.success());
    let verifier: PasswordVerifier = serde_json::from_slice(&out.stdout).unwrap();
    assert!(!verifier.is_legacy());
    assert!(verifier.verify(b"s3cret"));
    let user: PolicyUser = serde_json::from_value(serde_json::json!({
        "username": "u",
        "password_verifier": serde_json::from_slice::<serde_json::Value>(&out.stdout).unwrap(),
    }))
    .unwrap();
    assert!(user.password_scrypt.verify(b"s3cret"));
    let serve = |extra: &[&str]| {
        let out = Command::new(binary)
            .args([
                "serve",
                "--fips",
                "--cert",
                "/nonexistent/c",
                "--key",
                "k",
                "--ca",
                "a",
                "--policy",
                "p",
                "--master-key",
                "m",
            ])
            .args(extra)
            .env_remove("KMIP_TRIPLE_DES")
            .env_remove("KMIP_TLS_PROFILE")
            .output()
            .unwrap();
        assert!(!out.status.success());
        String::from_utf8_lossy(&out.stderr).into_owned()
    };
    for setting in ["enabled", "legacy-decrypt"] {
        let error = serve(&["--triple-des", setting]);
        assert!(error.contains("KMIP_TRIPLE_DES=disabled"), "{error}");
    }
    for profile in [
        "mozilla-intermediate",
        "kmip-2-basic",
        "kmip-2-basic-tls12",
        "kmip-1-tls12",
        "kmip-1-basic",
        "kmip-3-quantum-safe",
    ] {
        let error = serve(&["--tls-profile", profile]);
        assert!(error.contains("approved TLS profile"), "{profile}: {error}");
    }
}

/// Loading the real provider: `fips-check` loads OpenSSL's "fips" provider
/// and proves that non-FIPS algorithms cannot be fetched. Runs against the
/// provider named by KEYTEND_TEST_FIPS_OPENSSL_CONF and
/// KEYTEND_TEST_FIPS_OPENSSL_MODULES (an `openssl fipsinstall` configuration);
/// without them it checks that the host fails closed when it has no FIPS
/// provider, or skips with a message when it has one configured globally.
#[test]
fn fips_check_loads_the_provider_or_fails_closed() {
    use std::process::Command;
    let binary = env!("CARGO_BIN_EXE_keytend-kmip-server");
    let conf = std::env::var("KEYTEND_TEST_FIPS_OPENSSL_CONF").ok();
    let modules = std::env::var("KEYTEND_TEST_FIPS_OPENSSL_MODULES").ok();
    let mut command = Command::new(binary);
    command.args(["--fips", "fips-check"]);
    if let (Some(conf), Some(modules)) = (&conf, &modules) {
        command
            .env("OPENSSL_CONF", conf)
            .env("OPENSSL_MODULES", modules);
    }
    let out = command.output().unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    if conf.is_some() && modules.is_some() {
        assert!(out.status.success(), "{stderr}");
        let status: serde_json::Value = serde_json::from_str(&stdout).unwrap();
        assert_eq!(status["loaded"], serde_json::json!(["fips", "base"]));
        assert!(status["checks"].to_string().contains("unavailable"));
        // The providers' own parameters (OSSL_PROVIDER_get_params), in load order.
        let providers = status["providers"].as_array().unwrap();
        assert_eq!(providers[0]["id"], "fips");
        assert!(
            providers[0]["name"]
                .as_str()
                .unwrap()
                .contains("FIPS Provider"),
            "{stdout}"
        );
        assert!(
            !providers[0]["version"].as_str().unwrap().is_empty(),
            "{stdout}"
        );
        assert!(providers[0]["build_info"].is_string(), "{stdout}");
        assert_eq!(providers[0]["status"], 1);
        assert_eq!(providers[1]["id"], "base");
        assert_eq!(providers[1]["name"], "OpenSSL Base Provider");
        assert_eq!(providers[1]["status"], 1);
        // A FIPS-mode server with the real provider refuses an empty TLS
        // profile list no differently; the policy tests above cover requests.
        return;
    }
    if out.status.success() {
        eprintln!(
            "SKIPPED: the host OpenSSL loads a FIPS provider globally; set KEYTEND_TEST_FIPS_OPENSSL_CONF/MODULES to test a specific one ({stdout})"
        );
        return;
    }
    eprintln!(
        "SKIPPED provider success path: no FIPS provider on this host; checking that FIPS mode fails closed"
    );
    assert!(
        stderr.contains("cannot load the OpenSSL \"fips\" provider"),
        "{stderr}"
    );
}
