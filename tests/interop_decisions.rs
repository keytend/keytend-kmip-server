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

//! Interoperability decisions (docs/interpretations.md): focused positive
//! and negative cases for each behavior the decisions changed.
use keytend_kmip_server::{
    authorization::ObjectGrant,
    encoding::Format,
    protocol::{Engine, Version},
    store::{Store, now},
    tags::*,
    ttlv::{Node, Value},
};
use tempfile::TempDir;

struct Fixture {
    _dir: TempDir,
    engine: Engine,
}
impl Fixture {
    fn new() -> Self {
        Self::with_interop(false)
    }
    fn with_interop(interop_test_mode: bool) -> Self {
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
            engine: Engine::new(store, true).with_interop_test_mode(interop_test_mode),
        }
    }
    fn call(&mut self, v: Version, owner: &str, op: u32, p: Vec<Node>) -> Node {
        self.engine.process(owner, &request(v, op, p)).unwrap()
    }
    fn granted(
        &mut self,
        v: Version,
        owner: &str,
        op: u32,
        p: Vec<Node>,
        grants: &[ObjectGrant],
    ) -> Node {
        self.engine
            .process_with_grants(owner, &request(v, op, p), None, grants)
            .unwrap()
    }
}
fn request(v: Version, op: u32, p: Vec<Node>) -> Node {
    let mut header = vec![v.node()];
    let mut item = vec![Node::enumeration(OPERATION, op)];
    if v.0 < 3 {
        header.push(Node::int(BATCH_COUNT, 1));
        item.push(Node::bytes(UNIQUE_BATCH_ITEM_ID, vec![1]));
    }
    item.push(Node::structure(REQUEST_PAYLOAD, p));
    Node::structure(
        REQUEST_MESSAGE,
        vec![
            Node::structure(REQUEST_HEADER, header),
            Node::structure(BATCH_ITEM, item),
        ],
    )
}
fn item(n: &Node) -> &Node {
    n.get(BATCH_ITEM).unwrap()
}
fn payload(n: &Node) -> &Node {
    let item = item(n);
    assert_eq!(
        item.required(RESULT_STATUS).unwrap().number().unwrap(),
        0,
        "reason {:?}",
        item.get(RESULT_REASON).map(|n| n.number().unwrap())
    );
    item.required(RESPONSE_PAYLOAD).unwrap()
}
fn reason(n: &Node) -> u32 {
    item(n).required(RESULT_REASON).unwrap().number().unwrap()
}
fn uid(v: Version, id: &str) -> Node {
    if v.0 >= 3 {
        Node::identifier(UNIQUE_IDENTIFIER, id)
    } else {
        Node::text(UNIQUE_IDENTIFIER, id)
    }
}
fn identifier(n: &Node) -> String {
    payload(n)
        .required(UNIQUE_IDENTIFIER)
        .unwrap()
        .identifier_text()
        .unwrap()
        .to_owned()
}
fn name(v: Version, value: &str) -> Node {
    if v.0 >= 3 {
        Node::text(NAME, value)
    } else {
        Node::structure(
            NAME,
            vec![
                Node::text(NAME_VALUE, value),
                Node::enumeration(NAME_TYPE, 1),
            ],
        )
    }
}
/// Attributes in the version's container (1.x Template-Attribute).
fn container(v: Version, tag: u32, attributes: Vec<Node>) -> Node {
    if v.0 >= 2 {
        return Node::structure(tag, attributes);
    }
    let legacy = match tag {
        COMMON_ATTRIBUTES => COMMON_TEMPLATE_ATTRIBUTE,
        _ => TEMPLATE_ATTRIBUTE,
    };
    Node::structure(
        legacy,
        attributes
            .into_iter()
            .map(|mut a| {
                let name = match a.tag {
                    CRYPTOGRAPHIC_ALGORITHM => "Cryptographic Algorithm",
                    CRYPTOGRAPHIC_LENGTH => "Cryptographic Length",
                    CRYPTOGRAPHIC_USAGE_MASK => "Cryptographic Usage Mask",
                    ACTIVATION_DATE => "Activation Date",
                    PROCESS_START_DATE => "Process Start Date",
                    PROTECT_STOP_DATE => "Protect Stop Date",
                    CRYPTOGRAPHIC_PARAMETERS => "Cryptographic Parameters",
                    NAME => "Name",
                    t => tag_name(t).unwrap(),
                };
                a.tag = ATTRIBUTE_VALUE;
                Node::structure(ATTRIBUTE, vec![Node::text(ATTRIBUTE_NAME, name), a])
            })
            .collect(),
    )
}
/// An Active symmetric key of `algorithm` (3 AES, 30 ChaCha20-Poly1305).
fn key(f: &mut Fixture, v: Version, owner: &str, algorithm: u32, extra: Vec<Node>) -> String {
    let mut attributes = vec![
        Node::enumeration(CRYPTOGRAPHIC_ALGORITHM, algorithm),
        Node::int(CRYPTOGRAPHIC_LENGTH, 256),
        Node::int(CRYPTOGRAPHIC_USAGE_MASK, 12),
        Node::date(ACTIVATION_DATE, now() - 60),
    ];
    attributes.extend(extra);
    identifier(&f.call(
        v,
        owner,
        1,
        vec![
            Node::enumeration(OBJECT_TYPE, 2),
            container(v, ATTRIBUTES, attributes),
        ],
    ))
}
fn parameters(fields: Vec<Node>) -> Node {
    Node::structure(CRYPTOGRAPHIC_PARAMETERS, fields)
}
fn cbc() -> Node {
    parameters(vec![
        Node::enumeration(BLOCK_CIPHER_MODE, 1),
        Node::enumeration(PADDING_METHOD, 3),
    ])
}
/// CBC without padding, so any whole-block input decrypts.
fn raw_cbc() -> Node {
    parameters(vec![
        Node::enumeration(BLOCK_CIPHER_MODE, 1),
        Node::enumeration(PADDING_METHOD, 1),
    ])
}
fn gcm(tag: i32) -> Node {
    parameters(vec![
        Node::enumeration(BLOCK_CIPHER_MODE, 9),
        Node::int(TAG_LENGTH, tag),
    ])
}
fn crypt(f: &mut Fixture, v: Version, op: u32, id: &str, cp: Node, iv: Option<usize>) -> Node {
    let mut p = vec![uid(v, id), cp, Node::bytes(DATA, vec![7; 32])];
    if let Some(len) = iv {
        p.push(Node::bytes(IV_COUNTER_NONCE, vec![1; len]));
    }
    if op == 32 && v >= Version(1, 4) && p[1].get(TAG_LENGTH).is_some() {
        p.push(Node::bytes(AUTHENTICATED_ENCRYPTION_TAG, vec![0; 16]));
    }
    f.call(v, "alice", op, p)
}
const LIFECYCLE: [Version; 6] = [
    Version(1, 2),
    Version(1, 3),
    Version(1, 4),
    Version(2, 0),
    Version(2, 1),
    Version(3, 0),
];

/// A missing required IV or nonce is Invalid Message in every version
/// (traces CS-BC-M-11/12/13), not Missing Data or Missing Initialization
/// Vector.
#[test]
fn missing_iv_is_invalid_message_in_every_version() {
    for v in LIFECYCLE {
        let mut f = Fixture::new();
        let id = key(&mut f, v, "alice", 3, vec![]);
        for op in [31, 32] {
            assert_eq!(reason(&crypt(&mut f, v, op, &id, cbc(), None)), 4, "{v:?}");
        }
        payload(&crypt(&mut f, v, 31, &id, cbc(), Some(16)));
        // A wrong IV length stays Invalid Field.
        assert_eq!(reason(&crypt(&mut f, v, 31, &id, cbc(), Some(8))), 7);
    }
    let v = Version(2, 1);
    let mut f = Fixture::new();
    let id = key(&mut f, v, "alice", 30, vec![]);
    assert_eq!(
        reason(&crypt(&mut f, v, 31, &id, parameters(vec![]), None)),
        4
    );
    payload(&crypt(&mut f, v, 31, &id, parameters(vec![]), Some(12)));
}

/// An Active key outside its Process Start / Protect Stop window is
/// Permission Denied through 2.0 and Wrong Key Lifecycle State from 2.1
/// (traces CS-AC-M-8, CS-BC-M-14).
#[test]
fn usage_window_reason_changes_at_2_1() {
    for v in LIFECYCLE {
        let expected = if v >= Version(2, 1) { 0x43 } else { 12 };
        let mut f = Fixture::new();
        let late = key(
            &mut f,
            v,
            "alice",
            3,
            vec![Node::date(PROCESS_START_DATE, now() + 300)],
        );
        // Protection is allowed before Process Start; processing is not.
        payload(&crypt(&mut f, v, 31, &late, raw_cbc(), Some(16)));
        assert_eq!(
            reason(&crypt(&mut f, v, 32, &late, raw_cbc(), Some(16))),
            expected
        );
        let stopped = key(
            &mut f,
            v,
            "alice",
            3,
            vec![Node::date(PROTECT_STOP_DATE, now() - 1)],
        );
        assert_eq!(
            reason(&crypt(&mut f, v, 31, &stopped, raw_cbc(), Some(16))),
            expected
        );
        payload(&crypt(&mut f, v, 32, &stopped, raw_cbc(), Some(16)));
    }
}

/// An unsupported AEAD Tag Length is General Failure (traces
/// CS-BC-M-GCM-1, CS-BC-M-CHACHA20POLY1305-1-30). GCM keeps its supported
/// lengths; ChaCha20-Poly1305 keeps refusing every length but 16.
#[test]
fn unsupported_tag_length_is_general_failure() {
    for v in [Version(1, 4), Version(2, 0), Version(2, 1), Version(3, 0)] {
        let mut f = Fixture::new();
        let id = key(&mut f, v, "alice", 3, vec![]);
        for tag in [1, 3, 17, 32] {
            assert_eq!(
                reason(&crypt(&mut f, v, 31, &id, gcm(tag), Some(12))),
                0x100
            );
            assert_eq!(
                reason(&crypt(&mut f, v, 32, &id, gcm(tag), Some(12))),
                0x100
            );
        }
        for tag in [12, 16] {
            payload(&crypt(&mut f, v, 31, &id, gcm(tag), Some(12)));
        }
        let chacha = key(&mut f, v, "alice", 30, vec![]);
        for tag in [1, 12, 32] {
            let cp = parameters(vec![Node::int(TAG_LENGTH, tag)]);
            assert_eq!(reason(&crypt(&mut f, v, 31, &chacha, cp, Some(12))), 0x100);
        }
        let cp = parameters(vec![Node::int(TAG_LENGTH, 16)]);
        payload(&crypt(&mut f, v, 31, &chacha, cp, Some(12)));
    }
}

fn ec_pair(f: &mut Fixture, v: Version, stored: Vec<Node>) -> (String, String) {
    let mut attributes = vec![
        Node::enumeration(CRYPTOGRAPHIC_ALGORITHM, 6),
        Node::int(CRYPTOGRAPHIC_LENGTH, 256),
        Node::int(CRYPTOGRAPHIC_USAGE_MASK, 3),
        Node::date(ACTIVATION_DATE, now() - 60),
    ];
    attributes.extend(stored);
    let r = f.call(
        v,
        "alice",
        2,
        vec![container(v, COMMON_ATTRIBUTES, attributes)],
    );
    let p = payload(&r);
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
fn validity(n: &Node) -> u32 {
    payload(n)
        .required(VALIDITY_INDICATOR)
        .unwrap()
        .number()
        .unwrap()
}

/// KMIP 1.3 ECDSA defaults to SHA-256, and Signature Verify on an EC key
/// ignores a Padding Method and an RSA algorithm, using the given hash
/// (trace CS-AC-M-3-ECC-13). 1.4 still requires a hash.
#[test]
fn ecdsa_1_3_defaults_to_sha256_and_ignores_rsa_verify_parameters() {
    let message = b"ECDSA message".to_vec();
    let v = Version(1, 3);
    let mut f = Fixture::new();
    let stored = parameters(vec![Node::enumeration(CRYPTOGRAPHIC_ALGORITHM, 6)]);
    let (private, public) = ec_pair(&mut f, v, vec![stored.clone()]);
    let r = f.call(
        v,
        "alice",
        33,
        vec![uid(v, &private), Node::bytes(DATA, message.clone())],
    );
    let signature = payload(&r)
        .required(SIGNATURE_DATA)
        .unwrap()
        .byte_string()
        .unwrap()
        .to_vec();
    let verify = |f: &mut Fixture, hash: u32| {
        f.call(
            v,
            "alice",
            34,
            vec![
                uid(v, &public),
                parameters(vec![
                    Node::enumeration(PADDING_METHOD, 10),
                    Node::enumeration(HASHING_ALGORITHM, hash),
                    Node::enumeration(CRYPTOGRAPHIC_ALGORITHM, 4),
                ]),
                Node::bytes(DATA, message.clone()),
                Node::bytes(SIGNATURE_DATA, signature.clone()),
            ],
        )
    };
    assert_eq!(validity(&verify(&mut f, 6)), 1);
    // A different hash is a failed verification, not an error.
    assert_eq!(validity(&verify(&mut f, 4)), 2);
    // Sign still refuses an RSA algorithm on an EC key.
    let r = f.call(
        v,
        "alice",
        33,
        vec![
            uid(v, &private),
            parameters(vec![Node::enumeration(CRYPTOGRAPHIC_ALGORITHM, 4)]),
            Node::bytes(DATA, message.clone()),
        ],
    );
    assert_eq!(reason(&r), 7);

    let v = Version(1, 4);
    let mut f = Fixture::new();
    let (private, public) = ec_pair(&mut f, v, vec![stored]);
    let r = f.call(
        v,
        "alice",
        33,
        vec![uid(v, &private), Node::bytes(DATA, message.clone())],
    );
    assert_eq!(reason(&r), 6);
    let r = f.call(
        v,
        "alice",
        34,
        vec![
            uid(v, &public),
            parameters(vec![
                Node::enumeration(PADDING_METHOD, 10),
                Node::enumeration(HASHING_ALGORITHM, 6),
                Node::enumeration(CRYPTOGRAPHIC_ALGORITHM, 4),
            ]),
            Node::bytes(DATA, message),
            Node::bytes(SIGNATURE_DATA, vec![0; 64]),
        ],
    );
    assert_ne!(
        item(&r).required(RESULT_STATUS).unwrap().number().unwrap(),
        0
    );
}

/// KMIP 1.3 PSS verification accepts any salt length with MGF1 over the
/// message hash.
#[test]
fn pss_1_3_verification_detects_the_salt_length() {
    use openssl::{hash::MessageDigest, rsa::Padding, sign::RsaPssSaltlen};
    let v = Version(1, 3);
    let mut f = Fixture::new();
    let r = f.call(
        v,
        "alice",
        2,
        vec![container(
            v,
            COMMON_ATTRIBUTES,
            vec![
                Node::enumeration(CRYPTOGRAPHIC_ALGORITHM, 4),
                Node::int(CRYPTOGRAPHIC_LENGTH, 2048),
                Node::int(CRYPTOGRAPHIC_USAGE_MASK, 3),
                Node::date(ACTIVATION_DATE, now() - 60),
            ],
        )],
    );
    let ids = payload(&r);
    let private = ids
        .required(PRIVATE_KEY_UNIQUE_IDENTIFIER)
        .unwrap()
        .identifier_text()
        .unwrap()
        .to_owned();
    let public = ids
        .required(PUBLIC_KEY_UNIQUE_IDENTIFIER)
        .unwrap()
        .identifier_text()
        .unwrap()
        .to_owned();
    let r = f.call(
        v,
        "alice",
        10,
        vec![uid(v, &private), Node::enumeration(KEY_FORMAT_TYPE, 4)],
    );
    let der = payload(&r)
        .required(PRIVATE_KEY)
        .unwrap()
        .required(KEY_BLOCK)
        .unwrap()
        .required(KEY_VALUE)
        .unwrap()
        .required(KEY_MATERIAL)
        .unwrap()
        .byte_string()
        .unwrap()
        .to_vec();
    let key = openssl::pkey::PKey::private_key_from_der(&der).unwrap();
    let message = b"PSS message";
    let cp = parameters(vec![
        Node::enumeration(PADDING_METHOD, 10),
        Node::enumeration(HASHING_ALGORITHM, 6),
    ]);
    for (mgf, salt, expected) in [
        (MessageDigest::sha256(), 0, 1),
        (MessageDigest::sha256(), 32, 1),
        (MessageDigest::sha256(), 222, 1),
        (MessageDigest::sha1(), 20, 2),
    ] {
        let mut signer = openssl::sign::Signer::new(MessageDigest::sha256(), &key).unwrap();
        signer.set_rsa_padding(Padding::PKCS1_PSS).unwrap();
        signer.set_rsa_mgf1_md(mgf).unwrap();
        signer
            .set_rsa_pss_saltlen(RsaPssSaltlen::custom(salt))
            .unwrap();
        signer.update(message).unwrap();
        let signature = signer.sign_to_vec().unwrap();
        let r = f.call(
            v,
            "alice",
            34,
            vec![
                uid(v, &public),
                cp.clone(),
                Node::bytes(DATA, message.to_vec()),
                Node::bytes(SIGNATURE_DATA, signature),
            ],
        );
        assert_eq!(validity(&r), expected, "salt {salt}");
    }
}

fn get_grant(owner: &str, id: &str) -> ObjectGrant {
    ObjectGrant {
        owner: owner.to_owned(),
        user: None,
        device: None,
        identifier: id.to_owned(),
        operations: vec![10],
    }
}

/// Get of a destroyed object is Object Destroyed in 2.0+ for a caller
/// that may use the object; another owner's destroyed object still looks
/// missing. 1.x is unchanged.
#[test]
fn destroyed_get_is_object_destroyed_only_for_authorized_callers() {
    for v in LIFECYCLE {
        let mut f = Fixture::new();
        let id = key(&mut f, v, "alice", 3, vec![]);
        payload(&f.call(
            v,
            "alice",
            19,
            vec![
                uid(v, &id),
                Node::structure(
                    REVOCATION_REASON,
                    vec![Node::enumeration(REVOCATION_REASON_CODE, 1)],
                ),
            ],
        ));
        payload(&f.call(v, "alice", 20, vec![uid(v, &id)]));
        let destroyed = if v.0 >= 2 { 0x36 } else { 11 };
        let missing = if v.0 >= 2 { 0x37 } else { 1 };
        assert_eq!(
            reason(&f.call(v, "alice", 10, vec![uid(v, &id)])),
            destroyed
        );
        assert_eq!(reason(&f.call(v, "bob", 10, vec![uid(v, &id)])), missing);
        assert_eq!(
            reason(&f.call(v, "bob", 10, vec![uid(v, "no-such-object")])),
            missing
        );
        let grants = [get_grant("alice", &id)];
        assert_eq!(
            reason(&f.granted(v, "bob", 10, vec![uid(v, &id)], &grants)),
            destroyed
        );
    }
}

/// 2.x Get Attributes with none of the requested attributes present
/// returns the Unique Identifier and an empty Attributes structure.
#[test]
fn get_attributes_without_matches_returns_empty_attributes() {
    for v in [Version(2, 0), Version(2, 1), Version(3, 0)] {
        let mut f = Fixture::new();
        let id = key(&mut f, v, "alice", 3, vec![]);
        let r = f.call(
            v,
            "alice",
            11,
            vec![
                uid(v, &id),
                Node::enumeration(ATTRIBUTE_REFERENCE, DESCRIPTION),
            ],
        );
        let p = payload(&r);
        let tags: Vec<u32> = p.children().unwrap().iter().map(|n| n.tag).collect();
        assert_eq!(tags, [UNIQUE_IDENTIFIER, ATTRIBUTES]);
        assert!(
            p.required(ATTRIBUTES)
                .unwrap()
                .children()
                .unwrap()
                .is_empty()
        );
    }
}

/// Names are unique per owner, and a Name Reference prefers the
/// caller's own object over granted ones.
#[test]
fn names_are_unique_per_owner_and_resolve_owner_first() {
    for v in LIFECYCLE {
        let mut f = Fixture::new();
        let alice = key(&mut f, v, "alice", 3, vec![name(v, "shared")]);
        let bob = key(&mut f, v, "bob", 3, vec![name(v, "shared")]);
        let duplicate = if v.0 >= 2 { 0x35 } else { 7 };
        for owner in ["alice", "bob"] {
            let r = f.call(
                v,
                owner,
                1,
                vec![
                    Node::enumeration(OBJECT_TYPE, 2),
                    container(
                        v,
                        ATTRIBUTES,
                        vec![
                            Node::enumeration(CRYPTOGRAPHIC_ALGORITHM, 3),
                            Node::int(CRYPTOGRAPHIC_LENGTH, 256),
                            Node::int(CRYPTOGRAPHIC_USAGE_MASK, 12),
                            name(v, "shared"),
                        ],
                    ),
                ],
            );
            assert_eq!(reason(&r), duplicate);
        }
        if v.0 < 3 {
            continue;
        }
        let by_name = || vec![Node::name_reference(UNIQUE_IDENTIFIER, "shared")];
        // Bob may read Alice's object, but his own Name wins.
        let grants = [get_grant("alice", &alice)];
        let r = f.granted(v, "bob", 10, by_name(), &grants);
        assert_eq!(identifier(&r), bob);
        // Carol owns no such Name: one granted object resolves, two are
        // ambiguous.
        let r = f.granted(v, "carol", 10, by_name(), &grants);
        assert_eq!(identifier(&r), alice);
        let both = [get_grant("alice", &alice), get_grant("bob", &bob)];
        assert_eq!(reason(&f.granted(v, "carol", 10, by_name(), &both)), 0x35);
        // An unresolved Name Reference is Object Not Found (draft 3.0 Get
        // error table), the same as an unknown Unique Identifier.
        assert_eq!(reason(&f.call(v, "carol", 10, by_name())), 0x37);
    }
}

/// Interop exists only in interop test mode, from 2.0, and is listed by
/// Query only then.
#[test]
fn interop_requires_test_mode() {
    let interop = |function: u32, id: &str| {
        vec![
            Node::enumeration(INTEROP_FUNCTION, function),
            Node::text(INTEROP_IDENTIFIER, id),
        ]
    };
    let listed = |f: &mut Fixture, v: Version| {
        payload(&f.call(v, "alice", 24, vec![Node::enumeration(QUERY_FUNCTION, 1)]))
            .all(OPERATION)
            .any(|n| n.number().unwrap() == 0x34)
    };
    let mut f = Fixture::new();
    for v in [Version(2, 0), Version(2, 1), Version(3, 0)] {
        assert!(!listed(&mut f, v));
        assert_eq!(reason(&f.call(v, "alice", 0x34, interop(1, "BL-M-1"))), 5);
    }
    let mut f = Fixture::with_interop(true);
    for v in [Version(1, 4), Version(1, 0)] {
        assert!(!listed(&mut f, v));
        assert_eq!(reason(&f.call(v, "alice", 0x34, interop(1, "BL-M-1"))), 5);
    }
    for v in [Version(2, 0), Version(2, 1), Version(3, 0)] {
        assert!(listed(&mut f, v));
        for function in [1, 2, 3] {
            let r = f.call(v, "alice", 0x34, interop(function, "BL-M-1"));
            assert!(payload(&r).children().unwrap().is_empty());
        }
        assert_eq!(reason(&f.call(v, "alice", 0x34, interop(4, "BL-M-1"))), 7);
        assert_eq!(reason(&f.call(v, "alice", 0x34, interop(1, ""))), 7);
        assert_eq!(
            reason(&f.call(
                v,
                "alice",
                0x34,
                vec![Node::enumeration(INTEROP_FUNCTION, 1)]
            )),
            7
        );
    }
    // Draft 3.0 reserves "*" for a cleanup of the caller's data, which is not
    // performed.
    assert_eq!(
        reason(&f.call(Version(3, 0), "alice", 0x34, interop(3, "*"))),
        8
    );
    payload(&f.call(Version(2, 1), "alice", 0x34, interop(3, "*")));
}

fn response(v: Version, payload: Vec<Node>) -> Node {
    Node::structure(
        RESPONSE_MESSAGE,
        vec![
            Node::structure(
                RESPONSE_HEADER,
                vec![
                    v.node(),
                    Node::date(TIME_STAMP, 0),
                    Node::int(BATCH_COUNT, 1),
                ],
            ),
            Node::structure(
                BATCH_ITEM,
                vec![
                    Node::enumeration(OPERATION, 11),
                    Node::enumeration(RESULT_STATUS, 0),
                    Node::structure(RESPONSE_PAYLOAD, payload),
                ],
            ),
        ],
    )
}
fn xml(n: &Node) -> String {
    String::from_utf8(Format::Xml.encode(n).unwrap().to_vec()).unwrap()
}

/// XML writes masks symbolically: names in bit order, unnamed bits as
/// one 0x%08X component, zero as 0x00000000. JSON keeps numbers.
#[test]
fn xml_masks_are_symbolic_and_round_trip() {
    let v = Version(2, 1);
    for (mask, text) in [
        (12, "value=\"Encrypt Decrypt\""),
        (0x1003, "value=\"Sign Verify CertificateSign\""),
        (4 | 0x4000_0000, "value=\"Encrypt 0x40000000\""),
        (0, "value=\"0x00000000\""),
        (-1, "0x"),
    ] {
        let n = response(
            v,
            vec![Node::structure(
                ATTRIBUTES,
                vec![Node::int(CRYPTOGRAPHIC_USAGE_MASK, mask)],
            )],
        );
        let encoded = xml(&n);
        assert!(encoded.contains(text), "{mask:#x}: {encoded}");
        assert!(Format::Xml.decode(encoded.as_bytes()).unwrap() == n);
        let json = String::from_utf8(Format::Json.encode(&n).unwrap().to_vec()).unwrap();
        assert!(json.contains(&format!("\"value\":{mask}")), "{json}");
    }
    let n = response(
        v,
        vec![Node::structure(
            ATTRIBUTES,
            vec![
                Node::int(STORAGE_STATUS_MASK, 3),
                Node::int(PROTECTION_STORAGE_MASK, 1),
            ],
        )],
    );
    let encoded = xml(&n);
    assert!(
        encoded.contains("value=\"OnLineStorage ArchivalStorage\""),
        "{encoded}"
    );
    assert!(Format::Xml.decode(encoded.as_bytes()).unwrap() == n);
    // 1.x: the Attribute Value of a named mask attribute.
    let v = Version(1, 4);
    let n = response(
        v,
        vec![Node::structure(
            ATTRIBUTE,
            vec![
                Node::text(ATTRIBUTE_NAME, "Cryptographic Usage Mask"),
                Node::int(ATTRIBUTE_VALUE, 3),
            ],
        )],
    );
    let encoded = xml(&n);
    assert!(encoded.contains("value=\"Sign Verify\""), "{encoded}");
    assert!(Format::Xml.decode(encoded.as_bytes()).unwrap() == n);
    // Another Integer is still decimal.
    let n = response(v, vec![Node::int(CRYPTOGRAPHIC_LENGTH, 12)]);
    assert!(xml(&n).contains("value=\"12\""));
}

/// Profiles 2.1 section 5.4.1.6.4's own example "0x0000008" decodes.
#[test]
fn mask_hex_components_accept_up_to_eight_digits() {
    let message = |mask: &str| {
        format!(
            "<RequestMessage><RequestHeader><ProtocolVersion>\
             <ProtocolVersionMajor type=\"Integer\" value=\"2\"/>\
             <ProtocolVersionMinor type=\"Integer\" value=\"1\"/></ProtocolVersion>\
             <BatchCount type=\"Integer\" value=\"1\"/></RequestHeader>\
             <CryptographicUsageMask type=\"Integer\" value=\"{mask}\"/></RequestMessage>"
        )
    };
    let decoded = |mask: &str| {
        Format::Xml
            .decode(message(mask).as_bytes())
            .map(|n| n.get(CRYPTOGRAPHIC_USAGE_MASK).unwrap().value.clone())
    };
    for (text, value) in [
        ("CertificateSign 0x00000004 0x0000008", 0x100c),
        ("CertificateSign 0x0000000c", 0x100c),
        ("0x0000100c", 0x100c),
        ("Encrypt Decrypt CertificateSign", 0x100c),
        ("0x8", 8),
    ] {
        assert!(decoded(text).unwrap() == Value::Integer(value), "{text}");
    }
    for text in ["0x000000008", "0x", "Encrypt 0xg"] {
        assert!(decoded(text).is_err(), "{text}");
    }
}
