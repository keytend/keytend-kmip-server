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

//! Server conditions of the individual Profiles 1.3, 1.4, 2.0 and 2.1 server
//! profiles (sections 5.6.2 to 5.18.4): the objects, attributes, operations,
//! enumeration values, message contents and custom or vendor attribute sizes
//! each profile lists. Every request and response passes through the TTLV
//! codec, so the checks see the bytes a client would exchange. Each asserting
//! test names the clause digests it checks as `REQ:<digest>` (see
//! docs/specs/requirement-matrix.json); the paraphrases are our own words.
//!
//! The server runs with the 3DES policy `enabled`, which the Symmetric Key
//! Lifecycle and Foundry profiles need (see docs/algorithms.md#3des).
use keytend_kmip_server::{
    encoding::Format,
    protocol::{Engine, TripleDesPolicy, Version},
    store::{Store, now},
    tags::*,
    ttlv::{self, Node, Value},
};
use openssl::{
    asn1::Asn1Time,
    bn::BigNum,
    ec::{EcGroup, EcKey},
    hash::{MessageDigest, hash},
    nid::Nid,
    pkey::{PKey, Private},
    sign::Signer,
    symm::{Cipher, Crypter, Mode},
    x509::{X509, X509NameBuilder},
};

/// Editions whose Profiles define the per-profile server conditions.
const EDITIONS: [Version; 4] = [Version(1, 3), Version(1, 4), Version(2, 0), Version(2, 1)];

// Operation codes (1.x/2.x Operation enumeration).
const CREATE: u32 = 0x01;
const CREATE_KEY_PAIR: u32 = 0x02;
const REGISTER: u32 = 0x03;
const REKEY: u32 = 0x04;
const LOCATE: u32 = 0x08;
const GET: u32 = 0x0A;
const GET_ATTRIBUTES: u32 = 0x0B;
const ACTIVATE: u32 = 0x12;
const REKEY_KEY_PAIR: u32 = 0x1D;
const ENCRYPT: u32 = 0x1F;
const DECRYPT: u32 = 0x20;
const SIGN: u32 = 0x21;
const SIGNATURE_VERIFY: u32 = 0x22;
const MAC: u32 = 0x23;
const MAC_VERIFY: u32 = 0x24;
const RNG_RETRIEVE: u32 = 0x25;
const RNG_SEED: u32 = 0x26;
const HASH: u32 = 0x27;
const PKCS_11: u32 = 0x33;

// Object Type values.
const CERTIFICATE_OBJECT: u32 = 1;
const SYMMETRIC_KEY_OBJECT: u32 = 2;
const PUBLIC_KEY_OBJECT: u32 = 3;
const PRIVATE_KEY_OBJECT: u32 = 4;
const TEMPLATE_OBJECT: u32 = 6;
const SECRET_DATA_OBJECT: u32 = 7;
const OPAQUE_OBJECT_TYPE: u32 = 8;

// Cryptographic Algorithm values.
const TDES: u32 = 2;
const AES: u32 = 3;
const RSA: u32 = 4;
const ECDSA: u32 = 6;
const HMAC_SHA256: u32 = 9;
const HMAC_SHA384: u32 = 10;
const ECDH: u32 = 14;

// Recommended Curve values.
const P_256: u32 = 7;
const P_384: u32 = 10;

struct Fixture {
    _dir: tempfile::TempDir,
    engine: Engine,
}
impl Fixture {
    fn new() -> Self {
        let d = tempfile::tempdir().unwrap();
        let k = d.path().join("master");
        std::fs::write(&k, [11; 32]).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&k, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        let store = Store::open(&d.path().join("keys.sqlite"), &k).unwrap();
        Self {
            _dir: d,
            engine: Engine::new(store, false).with_triple_des(TripleDesPolicy::Enabled),
        }
    }
    /// One request message, sent and answered as TTLV bytes.
    fn batch(&mut self, v: Version, header: Vec<Node>, items: Vec<(u32, Vec<Node>)>) -> Node {
        let mut h = vec![v.node()];
        h.extend(header);
        h.push(Node::int(BATCH_COUNT, items.len() as i32));
        let mut fields = vec![Node::structure(REQUEST_HEADER, h)];
        for (index, (op, payload)) in items.into_iter().enumerate() {
            fields.push(Node::structure(
                BATCH_ITEM,
                vec![
                    Node::enumeration(OPERATION, op),
                    Node::bytes(UNIQUE_BATCH_ITEM_ID, vec![index as u8]),
                    Node::structure(REQUEST_PAYLOAD, payload),
                ],
            ));
        }
        let wire = Node::structure(REQUEST_MESSAGE, fields).encode();
        let request = ttlv::decode(&wire).unwrap();
        let response = self.engine.process("alice", &request).unwrap();
        ttlv::decode(&response.encode()).unwrap()
    }
    /// The single batch item of a one-item request.
    fn call(&mut self, v: Version, op: u32, payload: Vec<Node>) -> Node {
        self.batch(v, vec![], vec![(op, payload)])
            .required(BATCH_ITEM)
            .unwrap()
            .clone()
    }
    /// The response payload of a request that must succeed.
    fn ok(&mut self, v: Version, op: u32, payload: Vec<Node>) -> Node {
        let item = self.call(v, op, payload);
        success(&item, v, op)
    }
}
fn success(item: &Node, v: Version, op: u32) -> Node {
    assert_eq!(
        item.required(RESULT_STATUS).unwrap().number().unwrap(),
        0,
        "{}.{} operation {op:#x}: reason {:?} {:?}",
        v.0,
        v.1,
        item.get(RESULT_REASON).map(|n| n.number().unwrap()),
        item.get(RESULT_MESSAGE)
            .map(|n| n.string().unwrap().to_owned()),
    );
    item.required(RESPONSE_PAYLOAD).unwrap().clone()
}
fn text(n: &Node, tag: u32) -> String {
    n.required(tag)
        .unwrap()
        .identifier_text()
        .unwrap()
        .to_owned()
}
fn num(n: &Node, tag: u32) -> u32 {
    n.required(tag).unwrap().number().unwrap()
}
fn bytes(n: &Node, tag: u32) -> Vec<u8> {
    n.required(tag).unwrap().byte_string().unwrap().to_vec()
}
fn uid(id: &str) -> Node {
    Node::text(UNIQUE_IDENTIFIER, id)
}

/// A standard attribute in the edition's form: the attribute itself in 2.x,
/// an Attribute structure (name and value) in 1.x.
fn attr(v: Version, a: Node) -> Node {
    if v.0 >= 2 {
        return a;
    }
    let name = tag_name(a.tag).unwrap();
    let mut value = a;
    value.tag = ATTRIBUTE_VALUE;
    Node::structure(ATTRIBUTE, vec![Node::text(ATTRIBUTE_NAME, name), value])
}
/// A client custom attribute: 1.x "x-" name, 2.x Vendor Attribute of vendor "x".
fn custom(v: Version, name: &str, value: Node) -> Node {
    let mut value = value;
    value.tag = ATTRIBUTE_VALUE;
    if v.0 >= 2 {
        Node::structure(
            ATTRIBUTE,
            vec![
                Node::text(VENDOR_IDENTIFICATION, "x"),
                Node::text(ATTRIBUTE_NAME, name),
                value,
            ],
        )
    } else {
        Node::structure(
            ATTRIBUTE,
            vec![Node::text(ATTRIBUTE_NAME, format!("x-{name}")), value],
        )
    }
}
/// Attributes as a 2.x Attributes structure or a 1.x Template-Attribute.
fn template(v: Version, attrs: Vec<Node>) -> Node {
    let custom = |a: &Node| a.tag == ATTRIBUTE;
    let fields = attrs
        .into_iter()
        .map(|a| if custom(&a) { a } else { attr(v, a) })
        .collect();
    Node::structure(
        if v.0 >= 2 {
            ATTRIBUTES
        } else {
            TEMPLATE_ATTRIBUTE
        },
        fields,
    )
}
fn common(v: Version, attrs: Vec<Node>) -> Node {
    let mut n = template(v, attrs);
    n.tag = if v.0 >= 2 {
        COMMON_ATTRIBUTES
    } else {
        COMMON_TEMPLATE_ATTRIBUTE
    };
    n
}
fn name(value: &str) -> Node {
    Node::structure(
        NAME,
        vec![
            Node::text(NAME_VALUE, value),
            Node::enumeration(NAME_TYPE, 1),
        ],
    )
}
fn alternative_name(value: &str) -> Node {
    Node::structure(
        ALTERNATIVE_NAME,
        vec![
            Node::text(ALTERNATIVE_NAME_VALUE, value),
            Node::enumeration(ALTERNATIVE_NAME_TYPE, 1),
        ],
    )
}
fn application(namespace: &str, data: &str) -> Node {
    Node::structure(
        APPLICATION_SPECIFIC_INFORMATION,
        vec![
            Node::text(APPLICATION_NAMESPACE, namespace),
            Node::text(APPLICATION_DATA, data),
        ],
    )
}

fn create(f: &mut Fixture, v: Version, alg: u32, bits: i32, mask: i32, extra: Vec<Node>) -> String {
    let mut a = vec![
        Node::enumeration(CRYPTOGRAPHIC_ALGORITHM, alg),
        Node::int(CRYPTOGRAPHIC_LENGTH, bits),
        Node::int(CRYPTOGRAPHIC_USAGE_MASK, mask),
    ];
    a.extend(extra);
    let p = f.ok(
        v,
        CREATE,
        vec![
            Node::enumeration(OBJECT_TYPE, SYMMETRIC_KEY_OBJECT),
            template(v, a),
        ],
    );
    assert_eq!(num(&p, OBJECT_TYPE), SYMMETRIC_KEY_OBJECT);
    text(&p, UNIQUE_IDENTIFIER)
}
fn pair_ids(p: &Node) -> (String, String) {
    (
        text(p, PRIVATE_KEY_UNIQUE_IDENTIFIER),
        text(p, PUBLIC_KEY_UNIQUE_IDENTIFIER),
    )
}
fn rsa_pair(f: &mut Fixture, v: Version) -> (String, String) {
    let p = f.ok(
        v,
        CREATE_KEY_PAIR,
        vec![common(
            v,
            vec![
                Node::enumeration(CRYPTOGRAPHIC_ALGORITHM, RSA),
                Node::int(CRYPTOGRAPHIC_LENGTH, 2048),
                Node::int(CRYPTOGRAPHIC_USAGE_MASK, 3),
            ],
        )],
    );
    pair_ids(&p)
}
fn ec_pair(f: &mut Fixture, v: Version, alg: u32, curve: u32, mask: i32) -> (String, String) {
    let p = f.ok(
        v,
        CREATE_KEY_PAIR,
        vec![common(
            v,
            vec![
                Node::enumeration(CRYPTOGRAPHIC_ALGORITHM, alg),
                Node::int(CRYPTOGRAPHIC_USAGE_MASK, mask),
                Node::structure(
                    CRYPTOGRAPHIC_DOMAIN_PARAMETERS,
                    vec![Node::enumeration(RECOMMENDED_CURVE, curve)],
                ),
            ],
        )],
    );
    pair_ids(&p)
}
fn register(f: &mut Fixture, v: Version, kind: u32, attrs: Vec<Node>, object: Node) -> String {
    let p = f.ok(
        v,
        REGISTER,
        vec![
            Node::enumeration(OBJECT_TYPE, kind),
            template(v, attrs),
            object,
        ],
    );
    text(&p, UNIQUE_IDENTIFIER)
}
fn secret_password(f: &mut Fixture, v: Version, extra: Vec<Node>) -> String {
    let mut a = vec![Node::int(CRYPTOGRAPHIC_USAGE_MASK, 0)];
    a.extend(extra);
    register(
        f,
        v,
        SECRET_DATA_OBJECT,
        a,
        Node::structure(
            SECRET_DATA,
            vec![
                Node::enumeration(SECRET_DATA_TYPE, 1),
                Node::structure(
                    KEY_BLOCK,
                    vec![
                        Node::enumeration(KEY_FORMAT_TYPE, 2),
                        Node::structure(
                            KEY_VALUE,
                            vec![Node::bytes(KEY_MATERIAL, b"drive password".to_vec())],
                        ),
                    ],
                ),
            ],
        ),
    )
}
fn self_signed() -> (X509, PKey<Private>) {
    let key = PKey::from_ec_key(
        EcKey::generate(&EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap()).unwrap(),
    )
    .unwrap();
    let mut subject = X509NameBuilder::new().unwrap();
    subject.append_entry_by_text("CN", "profile").unwrap();
    let subject = subject.build();
    let mut b = X509::builder().unwrap();
    b.set_version(2).unwrap();
    b.set_serial_number(&BigNum::from_u32(7).unwrap().to_asn1_integer().unwrap())
        .unwrap();
    b.set_subject_name(&subject).unwrap();
    b.set_issuer_name(&subject).unwrap();
    b.set_pubkey(&key).unwrap();
    b.set_not_before(&Asn1Time::days_from_now(0).unwrap())
        .unwrap();
    b.set_not_after(&Asn1Time::days_from_now(30).unwrap())
        .unwrap();
    b.sign(&key, MessageDigest::sha256()).unwrap();
    (b.build(), key)
}
fn register_certificate(f: &mut Fixture, v: Version) -> String {
    let der = self_signed().0.to_der().unwrap();
    register(
        f,
        v,
        CERTIFICATE_OBJECT,
        vec![
            Node::enumeration(CRYPTOGRAPHIC_ALGORITHM, ECDSA),
            Node::int(CRYPTOGRAPHIC_LENGTH, 256),
            Node::int(CRYPTOGRAPHIC_USAGE_MASK, 2),
            Node::int(CERTIFICATE_LENGTH, der.len() as i32),
        ],
        Node::structure(
            CERTIFICATE,
            vec![
                Node::enumeration(CERTIFICATE_TYPE, 1),
                Node::bytes(CERTIFICATE_VALUE, der),
            ],
        ),
    )
}
fn get(f: &mut Fixture, v: Version, id: &str, format: Option<u32>) -> Node {
    let mut p = vec![uid(id)];
    if let Some(format) = format {
        p.push(Node::enumeration(KEY_FORMAT_TYPE, format));
    }
    f.ok(v, GET, p)
}
/// Key Format Type and Key Material of a returned key object.
fn key_block(object: &Node) -> (u32, Node) {
    let block = object.required(KEY_BLOCK).unwrap();
    (
        num(block, KEY_FORMAT_TYPE),
        block
            .required(KEY_VALUE)
            .unwrap()
            .required(KEY_MATERIAL)
            .unwrap()
            .clone(),
    )
}
fn activate(f: &mut Fixture, v: Version, ids: &[&str]) {
    for id in ids {
        f.ok(v, ACTIVATE, vec![uid(id)]);
    }
}
/// Every attribute of an object as (name, value), with 2.x attributes named
/// like 1.x ones and vendor "x" attributes named "x-<name>".
fn attributes(f: &mut Fixture, v: Version, id: &str) -> Vec<(String, Node)> {
    let p = f.ok(v, GET_ATTRIBUTES, vec![uid(id)]);
    let list: Vec<Node> = if v.0 >= 2 {
        p.required(ATTRIBUTES).unwrap().children().unwrap().to_vec()
    } else {
        p.all(ATTRIBUTE).cloned().collect()
    };
    list.into_iter()
        .map(|a| {
            if a.tag == ATTRIBUTE && v.0 >= 2 {
                let vendor = a.required(VENDOR_IDENTIFICATION).unwrap().string().unwrap();
                let name = a.required(ATTRIBUTE_NAME).unwrap().string().unwrap();
                (
                    format!("{vendor}-{name}"),
                    a.required(ATTRIBUTE_VALUE).unwrap().clone(),
                )
            } else if a.tag == ATTRIBUTE {
                (
                    a.required(ATTRIBUTE_NAME)
                        .unwrap()
                        .string()
                        .unwrap()
                        .to_owned(),
                    a.required(ATTRIBUTE_VALUE).unwrap().clone(),
                )
            } else {
                let name = tag_name(a.tag).unwrap().to_owned();
                let mut value = a;
                value.tag = ATTRIBUTE_VALUE;
                (name, value)
            }
        })
        .collect()
}
/// The values of one attribute, rendered for comparison (Node has no Debug).
fn values(list: &[(String, Node)], name: &str) -> Vec<String> {
    list.iter()
        .filter(|(n, _)| n == name)
        .map(|(_, v)| serde_json::to_string(v).unwrap())
        .collect()
}
fn one(n: Node) -> Vec<String> {
    vec![serde_json::to_string(&n).unwrap()]
}
fn value_of(a: Node) -> Node {
    let mut a = a;
    a.tag = ATTRIBUTE_VALUE;
    a
}
fn locate(f: &mut Fixture, v: Version, a: Node) -> Vec<String> {
    let field = if v.0 >= 2 {
        Node::structure(ATTRIBUTES, vec![a])
    } else if a.tag == ATTRIBUTE {
        // Already a 1.x custom Attribute from `custom`.
        a
    } else {
        attr(v, a)
    };
    f.ok(v, LOCATE, vec![field])
        .all(UNIQUE_IDENTIFIER)
        .map(|n| n.identifier_text().unwrap().to_owned())
        .collect()
}

// REQ:84834a748b264268 each profile's object list (Symmetric Key, Public and Private Key, Opaque Object, Secret Data, Certificate, and the 1.3 Template) can be created or registered and returned by Get
// REQ:9caa52ee2b69721c 1.3/1.4 lifecycle, foundry, opaque and XTS profiles: Create and Register work
// REQ:9d90daeda7bdea58 1.3/1.4 self-encrypting drive profile: Register works
// REQ:a4c4ac689fd4282f 2.x lifecycle and foundry profiles: Create works
#[test]
fn profile_objects_are_created_or_registered_and_returned_in_every_profile_edition() {
    let mut f = Fixture::new();
    for v in EDITIONS {
        // Symmetric Key, by Create: AES and three-key 3DES.
        for (alg, bits, bytes) in [(AES, 256, 32), (TDES, 168, 24)] {
            let id = create(&mut f, v, alg, bits, 12, vec![]);
            let p = get(&mut f, v, &id, None);
            assert_eq!(num(&p, OBJECT_TYPE), SYMMETRIC_KEY_OBJECT);
            let (_, material) = key_block(p.required(SYMMETRIC_KEY).unwrap());
            assert_eq!(material.byte_string().unwrap().len(), bytes);
        }
        // Public Key and Private Key, by Create Key Pair: RSA and ECDSA.
        for (private, public) in [rsa_pair(&mut f, v), ec_pair(&mut f, v, ECDSA, P_256, 3)] {
            let p = get(&mut f, v, &private, None);
            assert_eq!(num(&p, OBJECT_TYPE), PRIVATE_KEY_OBJECT);
            assert!(p.get(PRIVATE_KEY).is_some());
            let p = get(&mut f, v, &public, None);
            assert_eq!(num(&p, OBJECT_TYPE), PUBLIC_KEY_OBJECT);
            assert!(p.get(PUBLIC_KEY).is_some());
        }
        // Opaque Object, by Register.
        let id = register(
            &mut f,
            v,
            OPAQUE_OBJECT_TYPE,
            vec![],
            Node::structure(
                OPAQUE_OBJECT,
                vec![
                    Node::enumeration(OPAQUE_DATA_TYPE, 0x8000_0001),
                    Node::bytes(OPAQUE_DATA_VALUE, b"opaque profile data".to_vec()),
                ],
            ),
        );
        let p = get(&mut f, v, &id, None);
        assert_eq!(num(&p, OBJECT_TYPE), OPAQUE_OBJECT_TYPE);
        let opaque = p.required(OPAQUE_OBJECT).unwrap();
        assert_eq!(num(opaque, OPAQUE_DATA_TYPE), 0x8000_0001);
        assert_eq!(bytes(opaque, OPAQUE_DATA_VALUE), b"opaque profile data");
        // Secret Data (Password), by Register.
        let id = secret_password(&mut f, v, vec![]);
        let p = get(&mut f, v, &id, None);
        assert_eq!(num(&p, OBJECT_TYPE), SECRET_DATA_OBJECT);
        let secret = p.required(SECRET_DATA).unwrap();
        assert_eq!(num(secret, SECRET_DATA_TYPE), 1);
        assert_eq!(
            key_block(secret).1.byte_string().unwrap(),
            b"drive password"
        );
        // Certificate (X.509), by Register.
        let id = register_certificate(&mut f, v);
        let p = get(&mut f, v, &id, None);
        assert_eq!(num(&p, OBJECT_TYPE), CERTIFICATE_OBJECT);
        let certificate = p.required(CERTIFICATE).unwrap();
        assert_eq!(num(certificate, CERTIFICATE_TYPE), 1);
        assert!(X509::from_der(&bytes(certificate, CERTIFICATE_VALUE)).is_ok());
        // Template: listed only by the 1.3 self-encrypting drive profile.
        if v == Version(1, 3) {
            let id = register(
                &mut f,
                v,
                TEMPLATE_OBJECT,
                vec![name("drive template")],
                Node::structure(
                    TEMPLATE,
                    vec![attr(v, Node::int(CRYPTOGRAPHIC_LENGTH, 256))],
                ),
            );
            let p = get(&mut f, v, &id, None);
            assert_eq!(num(&p, OBJECT_TYPE), TEMPLATE_OBJECT);
            assert!(p.required(TEMPLATE).unwrap().get(ATTRIBUTE).is_some());
        }
        // Negative: an object type outside the enumeration is refused.
        let item = f.call(
            v,
            REGISTER,
            vec![
                Node::enumeration(OBJECT_TYPE, 0x7f),
                template(v, vec![]),
                Node::structure(OPAQUE_OBJECT, vec![]),
            ],
        );
        assert_eq!(num(&item, RESULT_STATUS), 1);
    }
}

// REQ:3f979ab64955eb2d 1.3/1.4 profiles: the listed enumeration values (3DES, AES, RSA, ECDSA, ECDH, HMAC-SHA256/384; P-256/P-384; X.509; SHA-256/384; ECDSA with SHA-256/384; Raw, Transparent Symmetric, PKCS#1, PKCS#8, ECPrivateKey, X.509, Transparent RSA/ECDSA/ECDH/EC formats; the profile object types; Opaque Data Type; Uninterpreted Text String names) are accepted and returned
// REQ:94a93b4ed9232abc 1.3/1.4 self-encrypting drive profile: Password secret data, Secret Data (and 1.3 Template) object types and text-string names
// REQ:668c67818cb8476b 2.x self-encrypting drive profile: text-string names, Secret Data object type and Password secret data
// REQ:6137e17c2a675614 1.3/1.4 tape library profile: Alternative Name of type Uninterpreted Text String
#[test]
fn profile_enumeration_values_and_key_formats_round_trip() {
    let mut f = Fixture::new();
    for v in EDITIONS {
        // Symmetric formats: Raw and Transparent Symmetric Key, for AES and 3DES.
        for (alg, bits) in [(AES, 128), (AES, 256), (TDES, 168)] {
            let id = create(&mut f, v, alg, bits, 12, vec![]);
            let (format, raw) = key_block(
                get(&mut f, v, &id, Some(1))
                    .required(SYMMETRIC_KEY)
                    .unwrap(),
            );
            assert_eq!(format, 1);
            let (format, transparent) = key_block(
                get(&mut f, v, &id, Some(7))
                    .required(SYMMETRIC_KEY)
                    .unwrap(),
            );
            assert_eq!(format, 7);
            assert_eq!(bytes(&transparent, KEY), raw.byte_string().unwrap());
        }
        // RSA: PKCS#1, PKCS#8 and the transparent RSA formats.
        let (private, public) = rsa_pair(&mut f, v);
        for (id, kind, formats) in [
            (&private, PRIVATE_KEY, [3, 4, 10]),
            (&public, PUBLIC_KEY, [3, 5, 11]),
        ] {
            for format in formats {
                let p = get(&mut f, v, id, Some(format));
                assert_eq!(key_block(p.required(kind).unwrap()).0, format);
            }
        }
        // Negative: a symmetric format is refused for an RSA key.
        let item = f.call(
            v,
            GET,
            vec![uid(&private), Node::enumeration(KEY_FORMAT_TYPE, 7)],
        );
        assert_eq!(num(&item, RESULT_STATUS), 1);
        if v.0 == 1 {
            // Suite B: ECDSA and ECDH on P-256 and P-384, in ECPrivateKey,
            // PKCS#8, X.509 and the transparent ECDSA, ECDH and EC formats.
            for (alg, transparent) in [(ECDSA, 14), (ECDH, 16)] {
                for (curve, bits) in [(P_256, 256), (P_384, 384)] {
                    let mask = if alg == ECDSA { 3 } else { 0x800 };
                    let (private, public) = ec_pair(&mut f, v, alg, curve, mask);
                    for (id, kind, formats) in [
                        (&private, PRIVATE_KEY, [6, transparent, 20]),
                        (&public, PUBLIC_KEY, [5, transparent + 1, 21]),
                    ] {
                        for format in formats {
                            let p = get(&mut f, v, id, Some(format));
                            assert_eq!(key_block(p.required(kind).unwrap()).0, format);
                        }
                    }
                    let list = attributes(&mut f, v, &private);
                    assert_eq!(
                        values(&list, "Cryptographic Length"),
                        one(Node::int(ATTRIBUTE_VALUE, bits))
                    );
                }
            }
            // HMAC-SHA256 and HMAC-SHA384 keys.
            for (alg, bits) in [(HMAC_SHA256, 256), (HMAC_SHA384, 384)] {
                let id = create(&mut f, v, alg, bits, 0x180, vec![]);
                let list = attributes(&mut f, v, &id);
                assert_eq!(
                    values(&list, "Cryptographic Algorithm"),
                    one(Node::enumeration(ATTRIBUTE_VALUE, alg))
                );
            }
            // ECDSA with SHA-256 on P-256 and with SHA-384 on P-384, by Digital
            // Signature Algorithm and by Hashing Algorithm.
            for (curve, dsa, hashing, digest) in [
                (P_256, 14, 6, MessageDigest::sha256()),
                (P_384, 15, 7, MessageDigest::sha384()),
            ] {
                let (private, public) = ec_pair(&mut f, v, ECDSA, curve, 3);
                activate(&mut f, v, &[&private, &public]);
                for parameters in [
                    vec![Node::enumeration(DIGITAL_SIGNATURE_ALGORITHM, dsa)],
                    vec![
                        Node::enumeration(CRYPTOGRAPHIC_ALGORITHM, ECDSA),
                        Node::enumeration(HASHING_ALGORITHM, hashing),
                    ],
                ] {
                    let cp = Node::structure(CRYPTOGRAPHIC_PARAMETERS, parameters);
                    let signature = bytes(
                        &f.ok(
                            v,
                            SIGN,
                            vec![
                                uid(&private),
                                cp.clone(),
                                Node::bytes(DATA, b"suite b".to_vec()),
                            ],
                        ),
                        SIGNATURE_DATA,
                    );
                    let der = bytes(
                        get(&mut f, v, &public, Some(5))
                            .required(PUBLIC_KEY)
                            .unwrap()
                            .required(KEY_BLOCK)
                            .unwrap()
                            .required(KEY_VALUE)
                            .unwrap(),
                        KEY_MATERIAL,
                    );
                    let key = PKey::public_key_from_der(&der).unwrap();
                    let mut verifier = openssl::sign::Verifier::new(digest, &key).unwrap();
                    verifier.update(b"suite b").unwrap();
                    assert!(verifier.verify(&signature).unwrap());
                }
            }
        }
        // Certificate Type X.509 (above helper) and Opaque Data Type round trip.
        let id = register_certificate(&mut f, v);
        assert_eq!(
            num(
                get(&mut f, v, &id, None).required(CERTIFICATE).unwrap(),
                CERTIFICATE_TYPE
            ),
            1
        );
        // Password secret data with an Uninterpreted Text String name.
        let id = secret_password(&mut f, v, vec![name(&format!("drive-{}.{}", v.0, v.1))]);
        let list = attributes(&mut f, v, &id);
        assert_eq!(
            values(&list, "Name"),
            one(value_of(name(&format!("drive-{}.{}", v.0, v.1))))
        );
        assert_eq!(
            values(&list, "Object Type"),
            one(Node::enumeration(ATTRIBUTE_VALUE, SECRET_DATA_OBJECT))
        );
        assert_eq!(
            locate(&mut f, v, name(&format!("drive-{}.{}", v.0, v.1))),
            std::slice::from_ref(&id)
        );
        // Alternative Name of type Uninterpreted Text String.
        let id = create(&mut f, v, AES, 256, 12, vec![alternative_name("BARCODE01")]);
        let list = attributes(&mut f, v, &id);
        assert_eq!(
            values(&list, "Alternative Name"),
            one(value_of(alternative_name("BARCODE01")))
        );
        // Negative: a Name Type outside the enumeration is refused.
        let bad = Node::structure(
            NAME,
            vec![
                Node::text(NAME_VALUE, "bad"),
                Node::enumeration(NAME_TYPE, 0x7f),
            ],
        );
        let item = f.call(
            v,
            CREATE,
            vec![
                Node::enumeration(OBJECT_TYPE, SYMMETRIC_KEY_OBJECT),
                template(
                    v,
                    vec![
                        Node::enumeration(CRYPTOGRAPHIC_ALGORITHM, AES),
                        Node::int(CRYPTOGRAPHIC_LENGTH, 256),
                        Node::int(CRYPTOGRAPHIC_USAGE_MASK, 12),
                        bad,
                    ],
                ),
            ],
        );
        assert_eq!(num(&item, RESULT_STATUS), 1);
    }
}

// REQ:8539c442893b380f each profile's attribute list (Cryptographic Algorithm and Length, Object Type, Process Start and Protect Stop Date, Name, custom or vendor attributes, Application Specific Information, Alternative Name, and the 2.x Protection Level, Protection Period and Quantum Safe) is set, returned and searchable
// REQ:8d9fa634e236cb41 2.x lifecycle, foundry and opaque profiles: Cryptographic Algorithm and Length (168, 128, 192, 256), Object Type, Process Start Date and Protect Stop Date
// REQ:555f937ed853c279 tape library profile: Name, Cryptographic Algorithm, custom or vendor attributes, Application Specific Information and (2.x) Alternative Name
// REQ:605d36ffb8445f1a tape library: keys can be found by their Alternative Name (the cartridge barcode)
// REQ:f65d056738d70ec1 tape library ASI conditions: the client-supplied Application Specific Information is stored, returned and usable to locate the key
// REQ:dbf0e27407954836 tape library Alternative Name conditions: the client-supplied barcode Alternative Name is stored, returned and searchable
#[test]
fn profile_attributes_are_stored_returned_and_located() {
    let mut f = Fixture::new();
    for v in EDITIONS {
        let start = now() + 3600;
        let stop = start + 86_400;
        let barcode = format!("TAPE{}{}", v.0, v.1);
        let tag = |n: &str| format!("{n}-{}.{}", v.0, v.1);
        let id = create(
            &mut f,
            v,
            AES,
            256,
            12,
            vec![
                Node::date(PROCESS_START_DATE, start),
                Node::date(PROTECT_STOP_DATE, stop),
                name(&tag("tape key")),
                application("LIBRARY-LTO", &tag("kad")),
                alternative_name(&barcode),
                custom(v, "volume", Node::text(ATTRIBUTE_VALUE, "VOL001")),
            ],
        );
        let list = attributes(&mut f, v, &id);
        for (attribute, expected) in [
            (
                "Cryptographic Algorithm",
                Node::enumeration(ATTRIBUTE_VALUE, AES),
            ),
            ("Cryptographic Length", Node::int(ATTRIBUTE_VALUE, 256)),
            (
                "Object Type",
                Node::enumeration(ATTRIBUTE_VALUE, SYMMETRIC_KEY_OBJECT),
            ),
            ("Process Start Date", Node::date(ATTRIBUTE_VALUE, start)),
            ("Protect Stop Date", Node::date(ATTRIBUTE_VALUE, stop)),
            ("Name", value_of(name(&tag("tape key")))),
            (
                "Application Specific Information",
                value_of(application("LIBRARY-LTO", &tag("kad"))),
            ),
            ("Alternative Name", value_of(alternative_name(&barcode))),
            ("x-volume", Node::text(ATTRIBUTE_VALUE, "VOL001")),
        ] {
            assert_eq!(
                values(&list, attribute),
                one(expected),
                "{}.{} {attribute}",
                v.0,
                v.1
            );
        }
        for criterion in [
            name(&tag("tape key")),
            application("LIBRARY-LTO", &tag("kad")),
            alternative_name(&barcode),
        ] {
            assert_eq!(locate(&mut f, v, criterion), std::slice::from_ref(&id));
        }
        // Negative: an unknown barcode finds nothing.
        assert!(locate(&mut f, v, alternative_name("NO-SUCH-TAPE")).is_empty());
        // Cryptographic Length values of the foundry and Suite B profiles.
        for (alg, bits) in [(AES, 128), (AES, 192), (AES, 256), (TDES, 168)] {
            let id = create(&mut f, v, alg, bits, 12, vec![]);
            let list = attributes(&mut f, v, &id);
            assert_eq!(
                values(&list, "Cryptographic Length"),
                one(Node::int(ATTRIBUTE_VALUE, bits))
            );
        }
        for (curve, bits) in [(P_256, 256), (P_384, 384)] {
            let (private, _) = ec_pair(&mut f, v, ECDSA, curve, 3);
            let list = attributes(&mut f, v, &private);
            assert_eq!(
                values(&list, "Cryptographic Length"),
                one(Node::int(ATTRIBUTE_VALUE, bits))
            );
        }
        // Negative: an AES length outside 128/192/256 is refused.
        let item = f.call(
            v,
            CREATE,
            vec![
                Node::enumeration(OBJECT_TYPE, SYMMETRIC_KEY_OBJECT),
                template(
                    v,
                    vec![
                        Node::enumeration(CRYPTOGRAPHIC_ALGORITHM, AES),
                        Node::int(CRYPTOGRAPHIC_LENGTH, 100),
                        Node::int(CRYPTOGRAPHIC_USAGE_MASK, 12),
                    ],
                ),
            ],
        );
        assert_eq!(num(&item, RESULT_STATUS), 1);
        // Object Type of an opaque object.
        let id = register(
            &mut f,
            v,
            OPAQUE_OBJECT_TYPE,
            vec![],
            Node::structure(
                OPAQUE_OBJECT,
                vec![
                    Node::enumeration(OPAQUE_DATA_TYPE, 0x8000_0002),
                    Node::bytes(OPAQUE_DATA_VALUE, b"x".to_vec()),
                ],
            ),
        );
        assert_eq!(
            values(&attributes(&mut f, v, &id), "Object Type"),
            one(Node::enumeration(ATTRIBUTE_VALUE, OPAQUE_OBJECT_TYPE))
        );
        // 2.x Quantum Safe profile: Protection Level, Protection Period and
        // Quantum Safe on a qualifying 256-bit AES key.
        if v.0 >= 2 {
            let quantum = [
                Node::enumeration(PROTECTION_LEVEL, 1),
                Node {
                    tag: PROTECTION_PERIOD,
                    value: Value::Interval(31_536_000),
                },
                Node::boolean(QUANTUM_SAFE, true),
            ];
            let id = create(&mut f, v, AES, 256, 12, quantum.to_vec());
            let list = attributes(&mut f, v, &id);
            for a in quantum {
                let label = tag_name(a.tag).unwrap();
                assert_eq!(values(&list, label), one(value_of(a)), "{label}");
            }
        }
    }
}

fn aes_ecb(key: &[u8], mode: Mode, data: &[u8]) -> Vec<u8> {
    let cipher = Cipher::aes_256_ecb();
    let mut c = Crypter::new(cipher, mode, key, None).unwrap();
    c.pad(false);
    let mut out = vec![0; data.len() + cipher.block_size()];
    let n = c.update(data, &mut out).unwrap();
    let m = c.finalize(&mut out[n..]).unwrap();
    out.truncate(n + m);
    out
}
fn raw_key(f: &mut Fixture, v: Version, id: &str) -> Vec<u8> {
    key_block(get(f, v, id, Some(1)).required(SYMMETRIC_KEY).unwrap())
        .1
        .byte_string()
        .unwrap()
        .to_vec()
}

// REQ:79a69d37c358e1a7 1.3/1.4 cryptographic profiles: Encrypt, Decrypt, Sign, Signature Verify, MAC, MAC Verify, RNG Retrieve and RNG Seed work over the wire
// REQ:5d042a17930b1df6 1.3/1.4 tape and Suite B profiles: Create, Create Key Pair, Register, Re-key and Re-key Key Pair; 2.x cryptographic, opaque, drive, tape, XTS, Quantum Safe and PKCS#11 profiles: Encrypt, Decrypt, Hash, MAC, MAC Verify, RNG Retrieve, RNG Seed, Sign, Signature Verify, Register, Create, Create Key Pair, Re-key, Re-key Key Pair and PKCS#11 (Certify and Re-certify: tests/certify.rs)
// REQ:6200e5a6ae3d9db7 2.x PKCS#11 profile: C_Initialize carries encoding version 1; any other version is refused
// REQ:5424c2cc1699a0b4 2.x PKCS#11 profile: C_Initialize, C_GetInfo (CK_INFO with 8-byte CK_FLAGS) and C_Finalize use the 5.18.1 encoding
#[test]
fn profile_operations_are_answered_over_the_wire() {
    let mut f = Fixture::new();
    for v in EDITIONS {
        // Create, Register, Re-key.
        let aes = create(&mut f, v, AES, 256, 12, vec![]);
        activate(&mut f, v, &[&aes]);
        let replacement = text(&f.ok(v, REKEY, vec![uid(&aes)]), UNIQUE_IDENTIFIER);
        assert_ne!(replacement, aes);
        // Encrypt and Decrypt (AES-256 ECB, no padding), checked against OpenSSL.
        let key = raw_key(&mut f, v, &aes);
        let plain = b"sixteen byte msg".repeat(2);
        let cp = Node::structure(
            CRYPTOGRAPHIC_PARAMETERS,
            vec![
                Node::enumeration(BLOCK_CIPHER_MODE, 2),
                Node::enumeration(PADDING_METHOD, 1),
            ],
        );
        let cipher = bytes(
            &f.ok(
                v,
                ENCRYPT,
                vec![uid(&aes), cp.clone(), Node::bytes(DATA, plain.clone())],
            ),
            DATA,
        );
        assert_eq!(cipher, aes_ecb(&key, Mode::Encrypt, &plain));
        let back = bytes(
            &f.ok(
                v,
                DECRYPT,
                vec![uid(&aes), cp.clone(), Node::bytes(DATA, cipher)],
            ),
            DATA,
        );
        assert_eq!(back, plain);
        // Negative: a Pre-Active key does not encrypt.
        let idle = create(&mut f, v, AES, 256, 12, vec![]);
        let item = f.call(
            v,
            ENCRYPT,
            vec![uid(&idle), cp, Node::bytes(DATA, plain.clone())],
        );
        assert_eq!(num(&item, RESULT_STATUS), 1);
        // Sign and Signature Verify (RSA PKCS#1 v1.5 with SHA-256).
        let (private, public) = rsa_pair(&mut f, v);
        activate(&mut f, v, &[&private, &public]);
        let cp = Node::structure(
            CRYPTOGRAPHIC_PARAMETERS,
            vec![Node::enumeration(DIGITAL_SIGNATURE_ALGORITHM, 5)],
        );
        let signature = bytes(
            &f.ok(
                v,
                SIGN,
                vec![
                    uid(&private),
                    cp.clone(),
                    Node::bytes(DATA, b"tape".to_vec()),
                ],
            ),
            SIGNATURE_DATA,
        );
        for (data, valid) in [(b"tape".to_vec(), 1), (b"tamp".to_vec(), 2)] {
            let p = f.ok(
                v,
                SIGNATURE_VERIFY,
                vec![
                    uid(&public),
                    cp.clone(),
                    Node::bytes(DATA, data),
                    Node::bytes(SIGNATURE_DATA, signature.clone()),
                ],
            );
            assert_eq!(num(&p, VALIDITY_INDICATOR), valid);
        }
        // MAC and MAC Verify (HMAC-SHA256), checked against OpenSSL.
        let hmac = create(&mut f, v, HMAC_SHA256, 256, 0x180, vec![]);
        activate(&mut f, v, &[&hmac]);
        let mac = bytes(
            &f.ok(
                v,
                MAC,
                vec![uid(&hmac), Node::bytes(DATA, b"block".to_vec())],
            ),
            MAC_DATA,
        );
        let k = PKey::hmac(&raw_key(&mut f, v, &hmac)).unwrap();
        let mut signer = Signer::new(MessageDigest::sha256(), &k).unwrap();
        signer.update(b"block").unwrap();
        assert_eq!(mac, signer.sign_to_vec().unwrap());
        for (data, valid) in [(b"block".to_vec(), 1), (b"black".to_vec(), 2)] {
            let p = f.ok(
                v,
                MAC_VERIFY,
                vec![
                    uid(&hmac),
                    Node::bytes(DATA, data),
                    Node::bytes(MAC_DATA, mac.clone()),
                ],
            );
            assert_eq!(num(&p, VALIDITY_INDICATOR), valid);
        }
        // RNG Retrieve and RNG Seed.
        let random = bytes(
            &f.ok(v, RNG_RETRIEVE, vec![Node::int(DATA_LENGTH, 48)]),
            DATA,
        );
        assert_eq!(random.len(), 48);
        let seeded = f.ok(v, RNG_SEED, vec![Node::bytes(DATA, vec![9; 32])]);
        assert!(seeded.get(DATA_LENGTH).is_some());
        // Create Key Pair, Register, Re-key Key Pair (EC, as in Suite B).
        let (private, _) = ec_pair(&mut f, v, ECDSA, P_256, 3);
        let p = f.ok(
            v,
            REKEY_KEY_PAIR,
            vec![Node::text(PRIVATE_KEY_UNIQUE_IDENTIFIER, &private)],
        );
        let (new_private, _) = pair_ids(&p);
        assert_ne!(new_private, private);
        register_certificate(&mut f, v);
        if v.0 >= 2 {
            // Hash (SHA-256), checked against OpenSSL.
            let digest = bytes(
                &f.ok(
                    v,
                    HASH,
                    vec![
                        Node::structure(
                            CRYPTOGRAPHIC_PARAMETERS,
                            vec![Node::enumeration(HASHING_ALGORITHM, 6)],
                        ),
                        Node::bytes(DATA, b"hash me".to_vec()),
                    ],
                ),
                DATA,
            );
            assert_eq!(
                digest,
                hash(MessageDigest::sha256(), b"hash me").unwrap().to_vec()
            );
            // PKCS#11: C_Initialize (encoding version 1), C_GetInfo, C_Finalize.
            let refused = f.call(
                v,
                PKCS_11,
                vec![
                    Node::enumeration(PKCS_11_FUNCTION, 1),
                    Node::bytes(PKCS_11_INPUT_PARAMETERS, vec![2]),
                ],
            );
            assert_eq!(num(&refused, RESULT_STATUS), 1);
            let p = f.ok(
                v,
                PKCS_11,
                vec![
                    Node::enumeration(PKCS_11_FUNCTION, 1),
                    Node::bytes(PKCS_11_INPUT_PARAMETERS, vec![1]),
                ],
            );
            assert_eq!(num(&p, PKCS_11_RETURN_CODE), 0);
            let library = bytes(&p, CORRELATION_VALUE);
            let p = f.ok(
                v,
                PKCS_11,
                vec![
                    Node::enumeration(PKCS_11_FUNCTION, 3),
                    Node::bytes(CORRELATION_VALUE, library.clone()),
                ],
            );
            assert_eq!(num(&p, PKCS_11_RETURN_CODE), 0);
            let info = bytes(&p, PKCS_11_OUTPUT_PARAMETERS);
            // CK_VERSION(2) + manufacturerID[32] + CK_FLAGS(8) + description[32] + CK_VERSION(2).
            assert_eq!(info.len(), 76);
            assert_eq!(info[..2], [3, 0]);
            assert_eq!(info[34..42], [0; 8]);
            let p = f.ok(
                v,
                PKCS_11,
                vec![
                    Node::enumeration(PKCS_11_FUNCTION, 2),
                    Node::bytes(CORRELATION_VALUE, library),
                ],
            );
            assert_eq!(num(&p, PKCS_11_RETURN_CODE), 0);
        }
    }
}

// REQ:8fbb72a80b036dd3 1.3/1.4 drive and tape profiles: custom attributes of type Text String, Integer and Date-Time
// REQ:27860018a5974a94 2.x drive profile: vendor attributes of type Text String
// REQ:57b716bc5a0f30a7 2.x tape profile: vendor attributes of type Date-Time, Integer and Text String
// REQ:ee78994060209cb3 1.3 drive profile: custom attribute and Name values of at least 64 characters
// REQ:ba8ca2a9c9d62073 1.3 drive profile: at least 10 custom attributes per object
// REQ:5ec95e8e60da995a 1.3/1.4 drive and tape profiles: custom attribute names of at least 64 characters
// REQ:342e6fcd45715733 1.3/1.4 tape profile: custom attribute and Name values of at least 255 characters
// REQ:b1e2a8242ce54bce 1.3/1.4 tape profile: at least 30 custom attributes per object
// REQ:7fb20ae667e7f062 1.4 drive profile: custom attribute and Name values of at least 128 characters
// REQ:a509177eac13dce8 1.4 drive profile: at least 20 custom attributes per object
// REQ:58a0804e12dc908b 1.4 drive profile: custom attribute names of at least 128 characters
// REQ:a55655af72dad86b 2.x drive profile: vendor attribute and Name values of at least 128 characters
// REQ:45b177ba23bc8302 2.x drive profile: at least 20 vendor attributes per object
// REQ:7a49d00eba97ace5 2.x drive profile: vendor attribute names of at least 128 characters
// REQ:7952a38f16099cc4 2.x tape profile: vendor attribute and Name values of at least 255 characters
// REQ:11ea396becf9f0c8 2.x tape profile: at least 30 vendor attributes per object
// REQ:70867960aa113000 2.x tape profile: vendor attribute names of at least 64 characters
#[test]
fn custom_and_vendor_attributes_meet_the_profile_sizes_and_types() {
    let mut f = Fixture::new();
    for v in EDITIONS {
        // 128-character attribute names (126 after the 1.x "x-" prefix, so the
        // full 1.x name is 128 characters too) and 255-character values.
        let long_name = |i: usize| {
            let stem = format!("{i:03}-");
            let width = if v.0 >= 2 { 128 } else { 126 };
            format!("{stem}{}", "n".repeat(width - stem.len()))
        };
        // Values are 255 characters and unique per edition.
        let long_value = |i: usize| format!("{i:03}{}.{}{}", v.0, v.1, "v".repeat(249));
        let long_name_value = |object: usize| format!("{object}{}.{}{}", v.0, v.1, "N".repeat(251));
        let when = now() - 60;
        let typed = |i: usize| match i % 3 {
            0 => Node::text(ATTRIBUTE_VALUE, long_value(i)),
            1 => Node::int(ATTRIBUTE_VALUE, i as i32),
            _ => Node::date(ATTRIBUTE_VALUE, when + i as i64),
        };
        let extra = |object: usize| {
            let mut extra = vec![name(&long_name_value(object))];
            extra.extend((0..30).map(|i| custom(v, &long_name(i), typed(i))));
            extra
        };
        assert_eq!(long_value(0).len(), 255);
        assert_eq!(long_name_value(0).len(), 255);
        let ids = [
            create(&mut f, v, AES, 256, 12, extra(0)),
            secret_password(&mut f, v, extra(1)),
        ];
        for (object, id) in ids.iter().enumerate() {
            let list = attributes(&mut f, v, id);
            assert_eq!(
                values(&list, "Name"),
                one(value_of(name(&long_name_value(object))))
            );
            let customs = list.iter().filter(|(n, _)| n.starts_with("x-")).count();
            assert_eq!(customs, 30, "{}.{}", v.0, v.1);
            for i in 0..30 {
                let key = format!("x-{}", long_name(i));
                if v.0 == 1 {
                    assert_eq!(key.len(), 128);
                }
                assert_eq!(values(&list, &key), one(typed(i)), "{key}");
            }
        }
        let mut found = locate(&mut f, v, custom(v, &long_name(0), typed(0)));
        found.sort();
        let mut expected = ids.to_vec();
        expected.sort();
        assert_eq!(found, expected);
    }
}

// REQ:933016ef60221c72 1.3/1.4 tape profile: Batch Order Option True and Batch Counts from 1 to 32
// REQ:e36915a3ecdc5aa8 2.x tape profile: Batch Count 1 to 32 and Batch Order Option True
#[test]
fn ordered_batches_of_one_to_thirty_two_items_run_in_order() {
    let mut f = Fixture::new();
    for v in EDITIONS {
        for count in [1usize, 2, 16, 32] {
            let items: Vec<_> = (0..count)
                .map(|i| {
                    (
                        CREATE,
                        vec![
                            Node::enumeration(OBJECT_TYPE, SYMMETRIC_KEY_OBJECT),
                            template(
                                v,
                                vec![
                                    Node::enumeration(CRYPTOGRAPHIC_ALGORITHM, AES),
                                    Node::int(CRYPTOGRAPHIC_LENGTH, 256),
                                    Node::int(CRYPTOGRAPHIC_USAGE_MASK, 12),
                                    name(&format!("batch {}.{} {count} {i}", v.0, v.1)),
                                ],
                            ),
                        ],
                    )
                })
                .collect();
            let r = f.batch(v, vec![Node::boolean(BATCH_ORDER_OPTION, true)], items);
            let header = r.required(RESPONSE_HEADER).unwrap();
            assert_eq!(num(header, BATCH_COUNT) as usize, count);
            let answered: Vec<_> = r.all(BATCH_ITEM).collect();
            assert_eq!(answered.len(), count);
            for (i, item) in answered.into_iter().enumerate() {
                assert_eq!(bytes(item, UNIQUE_BATCH_ITEM_ID), [i as u8]);
                let id = text(&success(item, v, CREATE), UNIQUE_IDENTIFIER);
                let list = attributes(&mut f, v, &id);
                assert_eq!(
                    values(&list, "Name"),
                    one(value_of(name(&format!(
                        "batch {}.{} {count} {i}",
                        v.0, v.1
                    ))))
                );
            }
        }
        // Negative: a Batch Count that disagrees with the items is refused.
        let mut r = f.batch(v, vec![], vec![(0x18, vec![])]);
        assert_eq!(num(r.required(BATCH_ITEM).unwrap(), RESULT_STATUS), 0);
        let wire = Node::structure(
            REQUEST_MESSAGE,
            vec![
                Node::structure(REQUEST_HEADER, vec![v.node(), Node::int(BATCH_COUNT, 2)]),
                Node::structure(
                    BATCH_ITEM,
                    vec![
                        Node::enumeration(OPERATION, 0x18),
                        Node::structure(REQUEST_PAYLOAD, vec![]),
                    ],
                ),
            ],
        );
        r = f.engine.process("alice", &wire).unwrap();
        assert_eq!(num(r.required(BATCH_ITEM).unwrap(), RESULT_STATUS), 1);
    }
}

/// The per-edition tag and enumeration names generated from the pinned
/// specification tables (scripts/generate_wire_registry.py).
fn wire_registry() -> serde_json::Value {
    serde_json::from_str(include_str!("../src/wire_registry.json")).unwrap()
}
fn message_text(format: Format, v: &str, field: &str) -> String {
    let (major, minor) = v.split_once('.').unwrap();
    match format {
        Format::Xml => format!(
            "<RequestMessage><RequestHeader><ProtocolVersion>\
             <ProtocolVersionMajor type=\"Integer\" value=\"{major}\"/>\
             <ProtocolVersionMinor type=\"Integer\" value=\"{minor}\"/>\
             </ProtocolVersion></RequestHeader>{field}</RequestMessage>"
        ),
        _ => format!(
            "{{\"tag\":\"RequestMessage\",\"value\":[{{\"tag\":\"RequestHeader\",\"value\":[\
             {{\"tag\":\"ProtocolVersion\",\"value\":[\
             {{\"tag\":\"ProtocolVersionMajor\",\"type\":\"Integer\",\"value\":{major}}},\
             {{\"tag\":\"ProtocolVersionMinor\",\"type\":\"Integer\",\"value\":{minor}}}]}}]}},{field}]}}"
        ),
    }
}
fn field_text(format: Format, tag: &str, kind: &str, value: &str) -> String {
    match format {
        Format::Xml => format!("<{tag} type=\"{kind}\" value=\"{value}\"/>"),
        _ => format!("{{\"tag\":\"{tag}\",\"type\":\"{kind}\",\"value\":\"{value}\"}}"),
    }
}

// REQ:974edca9343e0692 XML server: every tag and enumeration name of the edition's specification maps to and from XML
// REQ:e5d9ebc259b2fc38 JSON server: every tag and enumeration name of the edition's specification maps to and from JSON
#[test]
fn every_specification_tag_and_enumeration_maps_to_and_from_xml_and_json() {
    let registry = wire_registry();
    for v in ["1.3", "1.4", "2.0", "2.1"] {
        let edition = &registry[v];
        let tags = edition["tags"].as_object().unwrap();
        let mut enumerations = 0;
        for format in [Format::Xml, Format::Json] {
            for (name, number) in tags {
                let number = number.as_u64().unwrap() as u32;
                let text = message_text(format, v, &field_text(format, name, "TextString", "t"));
                let decoded = format
                    .decode(text.as_bytes())
                    .unwrap_or_else(|e| panic!("{v} {name}: {e}"));
                let field = decoded.children().unwrap()[1].clone();
                assert_eq!(field.tag, number, "{v} tag {name}");
                // The server's own rendering decodes back to the same node.
                let back = format.decode(&format.encode(&field).unwrap()).unwrap();
                assert!(back == field, "{v} tag {name}");
            }
            for (family, names) in edition["enums"].as_object().unwrap() {
                // Mask families are Integers, written as mask lists, not Enumerations.
                if family.ends_with("Mask") || family.ends_with("Masks") {
                    continue;
                }
                // Tables titled differently from the tag they serve; Item Type
                // is the TTLV type byte and Batch Error Continuation duplicates
                // the Batch Error Continuation Option table.
                let tag_name = match family.as_str() {
                    "ItemType" | "BatchErrorContinuation" => continue,
                    "RecommendedCurveEnumeration" => "RecommendedCurve",
                    "DestroyActionType" => "DestroyAction",
                    "ObjectGroupMemberOption" => "ObjectGroupMember",
                    "NISTKeyTypeEnumeration" => "NISTKeyType",
                    "ProfileNameType" | "Profile" => "ProfileName",
                    "UniqueIdentifierEnumerations" => "UniqueIdentifier",
                    other => other,
                };
                let tag = tags
                    .get(tag_name)
                    .and_then(|t| t.as_u64())
                    .unwrap_or_else(|| panic!("{v}: no tag for enumeration table {family}"));
                let family = tag_name;
                for (name, value) in names.as_object().unwrap() {
                    let value = value.as_u64().unwrap() as u32;
                    let text =
                        message_text(format, v, &field_text(format, family, "Enumeration", name));
                    let decoded = format
                        .decode(text.as_bytes())
                        .unwrap_or_else(|e| panic!("{v} {family}.{name}: {e}"));
                    let field = decoded.children().unwrap()[1].clone();
                    assert_eq!(field.tag, tag as u32);
                    assert!(
                        field.value == Value::Enumeration(value),
                        "{v} {family}.{name}"
                    );
                    let back = format.decode(&format.encode(&field).unwrap()).unwrap();
                    assert!(back == field, "{v} {family}.{name}");
                    enumerations += 1;
                }
            }
            // Negative: a name outside the registry is refused.
            for field in [
                field_text(format, "NoSuchKmipTag", "TextString", "t"),
                field_text(
                    format,
                    "CryptographicAlgorithm",
                    "Enumeration",
                    "NoSuchAlgorithm",
                ),
            ] {
                assert!(
                    format
                        .decode(message_text(format, v, &field).as_bytes())
                        .is_err()
                );
            }
        }
        assert!(
            tags.len() > 200 && enumerations > 400,
            "{v}: {} tags, {enumerations} values",
            tags.len()
        );
    }
}

// Profiles 2.0/2.1 "SHALL support the following Enumerations" is one sentence
// (digest 1c65ba6ddcee377e) under seven profiles, each with its own list, so
// each list is cited for its own section (docs/specs/requirement-matrix.json).
// Quantum Safe (5.16) is not cited: McEliece-6960119, McEliece-8192128 and
// SPHINCS-256 are not implemented, and that profile is not claimed.
// REQ:profiles-2.0@5.6.2:1c65ba6ddcee377e Symmetric Key Lifecycle: 3DES and AES, Symmetric Key, Raw and Transparent Symmetric Key (3DES under KMIP_TRIPLE_DES=enabled)
// REQ:profiles-2.1@5.6.2:1c65ba6ddcee377e Symmetric Key Lifecycle: as 2.0 (3DES under KMIP_TRIPLE_DES=enabled)
// REQ:profiles-2.0@5.7.4:1c65ba6ddcee377e Symmetric Key Foundry: 3DES and AES, Raw and Transparent Symmetric Key (3DES under KMIP_TRIPLE_DES=enabled)
// REQ:profiles-2.1@5.7.4:1c65ba6ddcee377e Symmetric Key Foundry: as 2.0 (3DES under KMIP_TRIPLE_DES=enabled)
// REQ:profiles-2.0@5.8.2:1c65ba6ddcee377e Asymmetric Key Lifecycle: RSA, PKCS#1, PKCS#8, Transparent RSA Public/Private Key, Public and Private Key
// REQ:profiles-2.1@5.8.2:1c65ba6ddcee377e Asymmetric Key Lifecycle: as 2.0
// REQ:profiles-2.0@5.10.2:1c65ba6ddcee377e Opaque Managed Object Store: Opaque Data Type and Opaque Object
// REQ:profiles-2.1@5.10.2:1c65ba6ddcee377e Opaque Managed Object Store: as 2.0
// REQ:profiles-2.0@5.12.5:1c65ba6ddcee377e Tape Library Server: Uninterpreted Text String Alternative and Name types, AES, 256, Raw, Symmetric Key
// REQ:profiles-2.1@5.12.5:1c65ba6ddcee377e Tape Library Server: as 2.0
// REQ:profiles-2.0@5.13.2:1c65ba6ddcee377e AES XTS Server: AES, Raw and Transparent Symmetric Key, Symmetric Key
// REQ:profiles-2.1@5.13.2:1c65ba6ddcee377e AES XTS Server: as 2.0
#[test]
fn two_x_enumeration_lists_hold_for_each_profile() {
    let mut f = Fixture::new();
    for v in [Version(2, 0), Version(2, 1)] {
        // Symmetric profiles: 3DES and AES, Raw and Transparent Symmetric Key.
        for (alg, bits) in [(TDES, 168), (AES, 128), (AES, 256)] {
            let id = create(&mut f, v, alg, bits, 12, vec![]);
            for format in [1, 7] {
                let p = get(&mut f, v, &id, Some(format));
                assert_eq!(num(&p, OBJECT_TYPE), SYMMETRIC_KEY_OBJECT);
                assert_eq!(key_block(p.required(SYMMETRIC_KEY).unwrap()).0, format);
            }
            let list = attributes(&mut f, v, &id);
            assert_eq!(
                values(&list, "Cryptographic Algorithm"),
                one(Node::enumeration(ATTRIBUTE_VALUE, alg))
            );
            assert_eq!(
                values(&list, "Cryptographic Length"),
                one(Node::int(ATTRIBUTE_VALUE, bits))
            );
            // Negative: an asymmetric format for a symmetric key.
            let item = f.call(
                v,
                GET,
                vec![uid(&id), Node::enumeration(KEY_FORMAT_TYPE, 3)],
            );
            assert_eq!(num(&item, RESULT_STATUS), 1);
        }
        // Asymmetric Key Lifecycle: RSA in PKCS#1, PKCS#8 and transparent forms.
        let (private, public) = rsa_pair(&mut f, v);
        for (id, kind, object, formats) in [
            (&private, PRIVATE_KEY, PRIVATE_KEY_OBJECT, [3, 4, 10]),
            (&public, PUBLIC_KEY, PUBLIC_KEY_OBJECT, [3, 5, 11]),
        ] {
            for format in formats {
                let p = get(&mut f, v, id, Some(format));
                assert_eq!(num(&p, OBJECT_TYPE), object);
                assert_eq!(key_block(p.required(kind).unwrap()).0, format);
            }
            let list = attributes(&mut f, v, id);
            assert_eq!(
                values(&list, "Cryptographic Algorithm"),
                one(Node::enumeration(ATTRIBUTE_VALUE, RSA))
            );
        }
        // Opaque Managed Object Store: Opaque Data Type and Opaque Object.
        let id = register(
            &mut f,
            v,
            OPAQUE_OBJECT_TYPE,
            vec![],
            Node::structure(
                OPAQUE_OBJECT,
                vec![
                    Node::enumeration(OPAQUE_DATA_TYPE, 0x8000_0002),
                    Node::bytes(OPAQUE_DATA_VALUE, b"2.x opaque".to_vec()),
                ],
            ),
        );
        let p = get(&mut f, v, &id, None);
        assert_eq!(num(&p, OBJECT_TYPE), OPAQUE_OBJECT_TYPE);
        assert_eq!(
            num(p.required(OPAQUE_OBJECT).unwrap(), OPAQUE_DATA_TYPE),
            0x8000_0002
        );
        // Tape Library: AES-256 Raw keys with Uninterpreted Text String Name
        // and Alternative Name values.
        let label = format!("tape-{}.{}", v.0, v.1);
        let barcode = format!("BARCODE{}{}", v.0, v.1);
        let id = create(
            &mut f,
            v,
            AES,
            256,
            12,
            vec![name(&label), alternative_name(&barcode)],
        );
        let p = get(&mut f, v, &id, Some(1));
        assert_eq!(key_block(p.required(SYMMETRIC_KEY).unwrap()).0, 1);
        let list = attributes(&mut f, v, &id);
        assert_eq!(values(&list, "Name"), one(value_of(name(&label))));
        assert_eq!(
            values(&list, "Alternative Name"),
            one(value_of(alternative_name(&barcode)))
        );
        assert_eq!(locate(&mut f, v, alternative_name(&barcode)), [id]);
    }
}
