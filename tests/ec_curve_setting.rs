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

//! `--ec-curves nist|extended`
//! (docs/interpretations.md#supported-elliptic-curves), per edition.
//! `nist` offers P-224, P-256, P-384 and P-521; `extended` (default) adds
//! secp256k1 (25) and brainpoolP256r1 through brainpoolP512t1 (61-68). Under
//! `nist` every operation that needs an extended curve fails with Feature Not
//! Supported, "Unsupported EC curve" (1.0-1.4 section 6.10; 2.x section 11),
//! and keys stored on them stay retrievable as stored but unusable.
use keytend_kmip_server::{
    protocol::{EcCurves, Engine, Version},
    store::Store,
    tags::*,
    ttlv::{Node, Value},
};
use openssl::{
    ec::{EcGroup, EcKey},
    hash::MessageDigest,
    nid::Nid,
    pkey::{PKey, Private},
    x509::{X509, X509NameBuilder, X509Req},
};

const NIST: [u32; 4] = [4, 7, 10, 13];
const EXTENDED: [u32; 9] = [25, 61, 62, 63, 64, 65, 66, 67, 68];
const FEATURE_NOT_SUPPORTED: u32 = 8;
const CREATE_KEY_PAIR: u32 = 2;
const REGISTER: u32 = 3;
const GET: u32 = 10;
const GET_ATTRIBUTES: u32 = 11;
const ACTIVATE: u32 = 18;
const VALIDATE: u32 = 23;
const RE_KEY_KEY_PAIR: u32 = 29;
const SIGN: u32 = 33;
const SIGNATURE_VERIFY: u32 = 34;
/// Editions with curves above 15 (1.2 added them) and the KMIP 3.0 draft.
const EDITIONS: [Version; 6] = [
    Version(1, 2),
    Version(1, 3),
    Version(1, 4),
    Version(2, 0),
    Version(2, 1),
    Version(3, 0),
];

struct Server {
    dir: tempfile::TempDir,
    e: Option<Engine>,
}
fn server(curves: EcCurves) -> Server {
    let dir = tempfile::tempdir().unwrap();
    let key = dir.path().join("master");
    std::fs::write(&key, [9; 32]).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    let store = Store::open(&dir.path().join("keys.sqlite"), &key).unwrap();
    Server {
        e: Some(Engine::new(store, true).with_ec_curves(curves)),
        dir,
    }
}
impl Server {
    /// Restart on the same store with another setting.
    fn restart(&mut self, curves: EcCurves) {
        let store = self.e.take().unwrap().store;
        self.e = Some(Engine::new(store, true).with_ec_curves(curves));
    }
    fn call(&mut self, v: Version, op: u32, payload: Vec<Node>) -> Node {
        let mut header = vec![v.node()];
        if v.0 < 3 {
            header.push(Node::int(BATCH_COUNT, 1));
        }
        let message = Node::structure(
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
        let response = self.e.as_mut().unwrap().process("alice", &message).unwrap();
        response.required(BATCH_ITEM).unwrap().clone()
    }
    fn ok(&mut self, v: Version, op: u32, payload: Vec<Node>) -> Node {
        let item = self.call(v, op, payload);
        assert_eq!(status(&item).0, 0, "{v:?} op {op}: {:?}", status(&item));
        item.required(RESPONSE_PAYLOAD).unwrap().clone()
    }
}
/// (Result Status, Result Reason, Result Message).
fn status(item: &Node) -> (u32, u32, String) {
    let number = |tag| item.get(tag).map_or(0, |n| n.number().unwrap());
    let message = item
        .get(RESULT_MESSAGE)
        .map_or(String::new(), |n| n.string().unwrap().to_owned());
    (number(RESULT_STATUS), number(RESULT_REASON), message)
}
fn unsupported(item: &Node, what: &str) {
    assert_eq!(
        status(item),
        (1, FEATURE_NOT_SUPPORTED, "Unsupported EC curve".to_owned()),
        "{what}"
    );
}
fn text(n: &Node, tag: u32) -> String {
    n.required(tag)
        .unwrap()
        .identifier_text()
        .unwrap()
        .to_owned()
}
fn uid(v: Version, id: &str) -> Node {
    if v.0 >= 3 {
        Node::identifier(UNIQUE_IDENTIFIER, id)
    } else {
        Node::text(UNIQUE_IDENTIFIER, id)
    }
}
/// Re-key Key Pair of a private key (draft 3.0 names it Unique Identifier).
fn rekey_pair(v: Version, id: &str) -> Vec<Node> {
    if v.0 >= 3 {
        vec![uid(v, id)]
    } else {
        vec![Node::text(PRIVATE_KEY_UNIQUE_IDENTIFIER, id)]
    }
}
fn name_of(tag: u32) -> &'static str {
    match tag {
        CRYPTOGRAPHIC_ALGORITHM => "Cryptographic Algorithm",
        CRYPTOGRAPHIC_USAGE_MASK => "Cryptographic Usage Mask",
        CRYPTOGRAPHIC_DOMAIN_PARAMETERS => "Cryptographic Domain Parameters",
        _ => unreachable!(),
    }
}
/// Attributes in the edition's container: 1.x Template-Attribute of
/// Attribute structures, 2.x/3.0 Attributes.
fn container(v: Version, one: u32, two: u32, attrs: Vec<Node>) -> Node {
    if v.0 >= 2 {
        return Node::structure(two, attrs);
    }
    Node::structure(
        one,
        attrs
            .into_iter()
            .map(|a| {
                let name = name_of(a.tag);
                let mut value = a;
                value.tag = ATTRIBUTE_VALUE;
                Node::structure(ATTRIBUTE, vec![Node::text(ATTRIBUTE_NAME, name), value])
            })
            .collect(),
    )
}
fn usage(mask: i32) -> Node {
    Node::int(CRYPTOGRAPHIC_USAGE_MASK, mask)
}
/// Create Key Pair, ECDSA on `curve`.
fn key_pair(v: Version, curve: u32) -> Vec<Node> {
    vec![
        container(
            v,
            COMMON_TEMPLATE_ATTRIBUTE,
            COMMON_ATTRIBUTES,
            vec![
                Node::enumeration(CRYPTOGRAPHIC_ALGORITHM, 6),
                Node::structure(
                    CRYPTOGRAPHIC_DOMAIN_PARAMETERS,
                    vec![Node::enumeration(RECOMMENDED_CURVE, curve)],
                ),
            ],
        ),
        container(
            v,
            PRIVATE_KEY_TEMPLATE_ATTRIBUTE,
            PRIVATE_KEY_ATTRIBUTES,
            vec![usage(1)],
        ),
        container(
            v,
            PUBLIC_KEY_TEMPLATE_ATTRIBUTE,
            PUBLIC_KEY_ATTRIBUTES,
            vec![usage(2)],
        ),
    ]
}
/// Register an ECDSA key: `kind` 3 public or 4 private, `material` in `format`.
fn register_key(v: Version, kind: u32, format: u32, material: Node) -> Vec<Node> {
    vec![
        Node::enumeration(OBJECT_TYPE, kind),
        container(
            v,
            TEMPLATE_ATTRIBUTE,
            ATTRIBUTES,
            vec![usage(if kind == 4 { 1 } else { 2 })],
        ),
        Node::structure(
            if kind == 4 { PRIVATE_KEY } else { PUBLIC_KEY },
            vec![Node::structure(
                KEY_BLOCK,
                vec![
                    Node::enumeration(KEY_FORMAT_TYPE, format),
                    Node::structure(KEY_VALUE, vec![material]),
                    Node::enumeration(CRYPTOGRAPHIC_ALGORITHM, 6),
                ],
            )],
        ),
    ]
}
fn certificate(der: Vec<u8>) -> Node {
    Node::structure(
        CERTIFICATE,
        vec![
            Node::enumeration(CERTIFICATE_TYPE, 1),
            Node::bytes(CERTIFICATE_VALUE, der),
        ],
    )
}
fn register_certificate(v: Version, der: Vec<u8>) -> Vec<Node> {
    vec![
        Node::enumeration(OBJECT_TYPE, 1),
        container(v, TEMPLATE_ATTRIBUTE, ATTRIBUTES, vec![]),
        certificate(der),
    ]
}
fn ecdsa() -> Node {
    Node::structure(
        CRYPTOGRAPHIC_PARAMETERS,
        vec![
            Node::enumeration(CRYPTOGRAPHIC_ALGORITHM, 6),
            Node::enumeration(HASHING_ALGORITHM, 6),
        ],
    )
}
fn sign(v: Version, id: &str) -> Vec<Node> {
    vec![uid(v, id), ecdsa(), Node::bytes(DATA, b"message".to_vec())]
}
fn verify(v: Version, id: &str, signature: Vec<u8>) -> Vec<Node> {
    vec![
        uid(v, id),
        ecdsa(),
        Node::bytes(DATA, b"message".to_vec()),
        Node::bytes(SIGNATURE_DATA, signature),
    ]
}
fn get(v: Version, id: &str, format: Option<u32>) -> Vec<Node> {
    let mut p = vec![uid(v, id)];
    if let Some(f) = format {
        p.push(Node::enumeration(KEY_FORMAT_TYPE, f));
    }
    p
}
/// The Key Material of a Get response.
fn material(payload: &Node) -> Node {
    let object = payload
        .get(PRIVATE_KEY)
        .or_else(|| payload.get(PUBLIC_KEY))
        .unwrap();
    object
        .required(KEY_BLOCK)
        .unwrap()
        .required(KEY_VALUE)
        .unwrap()
        .required(KEY_MATERIAL)
        .unwrap()
        .clone()
}
fn nid(curve: u32) -> Nid {
    match curve {
        7 => Nid::X9_62_PRIME256V1,
        25 => Nid::SECP256K1,
        61 => Nid::BRAINPOOL_P256R1,
        63 => Nid::BRAINPOOL_P320R1,
        65 => Nid::BRAINPOOL_P384R1,
        67 => Nid::BRAINPOOL_P512R1,
        _ => unreachable!(),
    }
}
fn ec_key(curve: u32) -> PKey<Private> {
    PKey::from_ec_key(EcKey::generate(&EcGroup::from_curve_name(nid(curve)).unwrap()).unwrap())
        .unwrap()
}
fn self_signed(key: &PKey<Private>) -> Vec<u8> {
    let mut name = X509NameBuilder::new().unwrap();
    name.append_entry_by_text("CN", "curve").unwrap();
    let name = name.build();
    let mut b = X509::builder().unwrap();
    b.set_version(2).unwrap();
    b.set_subject_name(&name).unwrap();
    b.set_issuer_name(&name).unwrap();
    b.set_pubkey(key).unwrap();
    b.set_not_before(&openssl::asn1::Asn1Time::days_from_now(0).unwrap())
        .unwrap();
    b.set_not_after(&openssl::asn1::Asn1Time::days_from_now(30).unwrap())
        .unwrap();
    b.sign(key, MessageDigest::sha256()).unwrap();
    b.build().to_der().unwrap()
}
fn request(key: &PKey<Private>) -> Vec<u8> {
    let mut name = X509NameBuilder::new().unwrap();
    name.append_entry_by_text("CN", "curve").unwrap();
    let mut b = X509Req::builder().unwrap();
    b.set_subject_name(&name.build()).unwrap();
    b.set_pubkey(key).unwrap();
    b.sign(key, MessageDigest::sha256()).unwrap();
    b.build().to_der().unwrap()
}

/// The default is `extended`.
#[test]
fn the_default_is_extended() {
    let store_dir = tempfile::tempdir().unwrap();
    let key = store_dir.path().join("master");
    std::fs::write(&key, [9; 32]).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    let store = Store::open(&store_dir.path().join("keys.sqlite"), &key).unwrap();
    assert_eq!(Engine::new(store, true).ec_curves(), EcCurves::Extended);
    assert_eq!(EcCurves::default(), EcCurves::Extended);
}

/// Create Key Pair: the NIST curves under both values, the extended curves
/// only under `extended`, in every edition with curves above 15. KMIP 1.0
/// and 1.1 list only curves 1-15 and refuse the rest under both values.
#[test]
fn create_key_pair_follows_the_setting_in_every_edition() {
    for curves in [EcCurves::Nist, EcCurves::Extended] {
        let mut s = server(curves);
        for v in EDITIONS {
            for curve in NIST.into_iter().chain(EXTENDED) {
                let what = format!("{curves:?} {v:?} curve {curve}");
                let item = s.call(v, CREATE_KEY_PAIR, key_pair(v, curve));
                if curves == EcCurves::Extended || NIST.contains(&curve) {
                    assert_eq!(status(&item).0, 0, "{what}: {:?}", status(&item));
                } else {
                    unsupported(&item, &what);
                }
            }
        }
        for v in [Version(1, 0), Version(1, 1)] {
            assert_eq!(
                status(&s.call(v, CREATE_KEY_PAIR, key_pair(v, 25))),
                (
                    1,
                    FEATURE_NOT_SUPPORTED,
                    "Curve requires KMIP 1.2".to_owned()
                ),
                "{curves:?} {v:?}"
            );
            assert_eq!(
                status(&s.call(v, CREATE_KEY_PAIR, key_pair(v, 7))).0,
                0,
                "{curves:?} {v:?}"
            );
        }
    }
}

/// Register of DER (PKCS#8, SEC 1, SubjectPublicKeyInfo) and transparent
/// keys, X.509 certificates and (2.x/3.0) PKCS#10 Certificate Requests, and
/// Validate of a certificate: extended curves only under `extended`.
#[test]
fn register_and_validate_follow_the_setting_in_every_edition() {
    for curves in [EcCurves::Nist, EcCurves::Extended] {
        let mut s = server(curves);
        for v in EDITIONS {
            for curve in [7, 25, 61, 63, 65, 67] {
                let what = format!("{curves:?} {v:?} curve {curve}");
                let accepted = curves == EcCurves::Extended || curve == 7;
                let expect = |item: &Node, what: &str| {
                    if accepted {
                        assert_eq!(status(item).0, 0, "{what}: {:?}", status(item));
                    } else {
                        unsupported(item, what);
                    }
                };
                let key = ec_key(curve);
                let ec = key.ec_key().unwrap();
                for (kind, format, der) in [
                    (4, 4, key.private_key_to_pkcs8().unwrap()),
                    (4, 6, ec.private_key_to_der().unwrap()),
                    (3, 5, key.public_key_to_der().unwrap()),
                ] {
                    let material = Node::bytes(KEY_MATERIAL, der);
                    expect(
                        &s.call(v, REGISTER, register_key(v, kind, format, material)),
                        &format!("{what} format {format}"),
                    );
                }
                if v >= Version(1, 3) {
                    // Transparent EC Public Key (21), the curve named in the material.
                    let mut ctx = openssl::bn::BigNumContext::new().unwrap();
                    let q = ec
                        .public_key()
                        .to_bytes(
                            ec.group(),
                            openssl::ec::PointConversionForm::UNCOMPRESSED,
                            &mut ctx,
                        )
                        .unwrap();
                    let point = Node::structure(
                        KEY_MATERIAL,
                        vec![
                            Node::enumeration(RECOMMENDED_CURVE, curve),
                            Node::bytes(Q_STRING, q),
                        ],
                    );
                    expect(
                        &s.call(v, REGISTER, register_key(v, 3, 21, point)),
                        &format!("{what} transparent"),
                    );
                }
                let cert = self_signed(&key);
                expect(
                    &s.call(v, REGISTER, register_certificate(v, cert.clone())),
                    &format!("{what} certificate"),
                );
                if v.0 >= 2 {
                    let validate = s.call(v, VALIDATE, vec![certificate(cert)]);
                    if accepted {
                        // Self-signed and not trusted: answered, not refused.
                        assert_eq!(status(&validate).0, 0, "{what}: {:?}", status(&validate));
                    } else {
                        unsupported(&validate, &format!("{what} validate"));
                    }
                    let csr = vec![
                        Node::enumeration(OBJECT_TYPE, 10),
                        Node::structure(ATTRIBUTES, vec![]),
                        Node::structure(
                            CERTIFICATE_REQUEST,
                            vec![
                                Node::enumeration(CERTIFICATE_REQUEST_TYPE, 2),
                                Node::bytes(CERTIFICATE_REQUEST_VALUE, request(&key)),
                            ],
                        ),
                    ];
                    expect(&s.call(v, REGISTER, csr), &format!("{what} request"));
                }
            }
        }
    }
}

/// Keys created under `extended` stay retrievable as stored after a restart
/// with `nist` (Get without a format, Get Attributes), but cannot sign,
/// verify, convert or be re-keyed; restarting with `extended` again makes
/// them usable.
#[test]
fn keys_on_extended_curves_stay_retrievable_but_unusable_under_nist() {
    for v in EDITIONS {
        for curve in [25, 61, 68] {
            let what = format!("{v:?} curve {curve}");
            let mut s = server(EcCurves::Extended);
            let pair = s.ok(v, CREATE_KEY_PAIR, key_pair(v, curve));
            let private = text(&pair, PRIVATE_KEY_UNIQUE_IDENTIFIER);
            let public = text(&pair, PUBLIC_KEY_UNIQUE_IDENTIFIER);
            s.ok(v, ACTIVATE, vec![uid(v, &private)]);
            s.ok(v, ACTIVATE, vec![uid(v, &public)]);
            let signature = s.ok(v, SIGN, sign(v, &private));
            let signature = signature
                .required(SIGNATURE_DATA)
                .unwrap()
                .byte_string()
                .unwrap()
                .to_vec();
            let stored_private = material(&s.ok(v, GET, get(v, &private, None)));
            let stored_public = material(&s.ok(v, GET, get(v, &public, None)));

            s.restart(EcCurves::Nist);
            assert!(
                material(&s.ok(v, GET, get(v, &private, None))) == stored_private,
                "{what}"
            );
            assert!(
                material(&s.ok(v, GET, get(v, &public, None))) == stored_public,
                "{what}"
            );
            s.ok(v, GET_ATTRIBUTES, vec![uid(v, &private)]);
            unsupported(&s.call(v, SIGN, sign(v, &private)), &format!("{what} sign"));
            unsupported(
                &s.call(v, SIGNATURE_VERIFY, verify(v, &public, signature.clone())),
                &format!("{what} verify"),
            );
            // Conversions: PKCS#8 (4) and SEC 1 (6) of the private key and
            // SubjectPublicKeyInfo (5) and a compressed point of the public
            // key. Created keys are stored in the edition's transparent
            // format (1.2: 14/15, 1.3+: 20/21), which Get returns as stored.
            for (id, format) in [(&private, 4), (&private, 6), (&public, 5)] {
                unsupported(
                    &s.call(v, GET, get(v, id, Some(format))),
                    &format!("{what} get format {format}"),
                );
            }
            let mut compressed = get(v, &public, None);
            compressed.push(Node::enumeration(KEY_COMPRESSION_TYPE, 2));
            unsupported(
                &s.call(v, GET, compressed.clone()),
                &format!("{what} get compressed"),
            );
            unsupported(
                &s.call(v, RE_KEY_KEY_PAIR, rekey_pair(v, &private)),
                &format!("{what} re-key key pair"),
            );

            // Create Split Key of the private key (2.x): its shares carry
            // a portable DER form, a conversion of the stored key.
            let split = |v: Version| {
                vec![
                    Node::enumeration(OBJECT_TYPE, 5),
                    Node::int(SPLIT_KEY_PARTS, 2),
                    Node::int(SPLIT_KEY_THRESHOLD, 2),
                    Node::enumeration(SPLIT_KEY_METHOD, 1),
                    Node::structure(ATTRIBUTES, vec![]),
                    uid(v, &private),
                ]
            };
            if v.0 == 2 {
                unsupported(&s.call(v, 40, split(v)), &format!("{what} split"));
            }

            s.restart(EcCurves::Extended);
            if v.0 == 2 {
                let item = s.call(v, 40, split(v));
                assert_eq!(status(&item).0, 0, "{what} split: {:?}", status(&item));
            }
            let valid = s.ok(v, SIGNATURE_VERIFY, verify(v, &public, signature));
            assert_eq!(
                valid
                    .required(VALIDITY_INDICATOR)
                    .unwrap()
                    .number()
                    .unwrap(),
                1,
                "{what}: Valid"
            );
            s.ok(v, SIGN, sign(v, &private));
            s.ok(v, GET, get(v, &private, Some(6)));
            s.ok(v, GET, compressed);
            let rekey = s.call(v, RE_KEY_KEY_PAIR, rekey_pair(v, &private));
            assert_eq!(status(&rekey).0, 0, "{what}: {:?}", status(&rekey));
            drop(s.dir);
        }
    }
}

/// The setting never adds curves to FIPS mode, and never removes the NIST
/// curves or the KMIP 1.0/1.1 version check. Under the default and an
/// explicit `extended`, FIPS mode also refuses certificates and certificate
/// requests on secp256k1 and brainpoolP256r1, as under `nist`.
#[test]
fn fips_mode_keeps_the_nist_curves_under_both_values() {
    // `EcCurves::default()` is what `Engine::new` uses (the_default_is_extended).
    for curves in [EcCurves::default(), EcCurves::Nist, EcCurves::Extended] {
        let mut s = server(curves);
        let engine = s.e.take().unwrap().with_fips(true);
        assert_eq!(engine.curve_set(), EcCurves::Nist, "{curves:?}");
        s.e = Some(engine);
        for v in [Version(1, 4), Version(2, 1), Version(3, 0)] {
            for curve in NIST {
                let item = s.call(v, CREATE_KEY_PAIR, key_pair(v, curve));
                assert_eq!(status(&item).0, 0, "{curves:?} {v:?} curve {curve}");
            }
            for curve in EXTENDED {
                let (result, reason, message) =
                    status(&s.call(v, CREATE_KEY_PAIR, key_pair(v, curve)));
                assert_eq!((result, reason), (1, FEATURE_NOT_SUPPORTED));
                // FIPS mode answers alike under both values.
                assert_eq!(message, "EC curve is not available in FIPS mode");
            }
            for curve in [7, 25, 61] {
                let what = format!("{curves:?} {v:?} curve {curve}");
                let key = ec_key(curve);
                let cert = self_signed(&key);
                let mut items = vec![(
                    s.call(v, REGISTER, register_certificate(v, cert.clone())),
                    "certificate",
                )];
                // Validate and Certificate Request objects are 2.0 and later.
                if v.0 >= 2 {
                    items.push((s.call(v, VALIDATE, vec![certificate(cert)]), "validate"));
                    let csr = vec![
                        Node::enumeration(OBJECT_TYPE, 10),
                        Node::structure(ATTRIBUTES, vec![]),
                        Node::structure(
                            CERTIFICATE_REQUEST,
                            vec![
                                Node::enumeration(CERTIFICATE_REQUEST_TYPE, 2),
                                Node::bytes(CERTIFICATE_REQUEST_VALUE, request(&key)),
                            ],
                        ),
                    ];
                    items.push((s.call(v, REGISTER, csr), "request"));
                }
                for (item, op) in &items {
                    if curve == 7 {
                        assert_eq!(status(item).0, 0, "{what} {op}: {:?}", status(item));
                    } else {
                        unsupported(item, &format!("{what} {op}"));
                    }
                }
            }
        }
    }
}

/// Re-key Key Pair keeps the curve, including brainpoolP320 and P512, whose
/// lengths have no default curve; Create Key Pair accepts their length with
/// the curve named, and still refuses a length without one.
#[test]
fn re_key_key_pair_keeps_every_extended_curve() {
    let mut s = server(EcCurves::Extended);
    for v in [Version(1, 2), Version(2, 1), Version(3, 0)] {
        for (curve, bits) in [(25, 256), (63, 320), (64, 320), (67, 512), (68, 512)] {
            let mut request = key_pair(v, curve);
            if v.0 >= 2
                && let Value::Structure(common) = &mut request[0].value
            {
                common.push(Node::int(CRYPTOGRAPHIC_LENGTH, bits));
            }
            let pair = s.ok(v, CREATE_KEY_PAIR, request);
            let private = text(&pair, PRIVATE_KEY_UNIQUE_IDENTIFIER);
            let rekey = s.ok(v, RE_KEY_KEY_PAIR, rekey_pair(v, &private));
            let replacement = text(&rekey, PRIVATE_KEY_UNIQUE_IDENTIFIER);
            let transparent = if v >= Version(1, 3) { 20 } else { 14 };
            let m = material(&s.ok(v, GET, get(v, &replacement, Some(transparent))));
            assert!(
                matches!(m.required(RECOMMENDED_CURVE).unwrap().value, Value::Enumeration(c) if c == curve),
                "{v:?} curve {curve}"
            );
        }
        let mut no_curve = key_pair(v, 7);
        if v.0 >= 2 {
            if let Value::Structure(common) = &mut no_curve[0].value {
                common.retain(|a| a.tag != CRYPTOGRAPHIC_DOMAIN_PARAMETERS);
                common.push(Node::int(CRYPTOGRAPHIC_LENGTH, 320));
            }
            assert_eq!(
                status(&s.call(v, CREATE_KEY_PAIR, no_curve)),
                (1, 7, "EC curve is required for this length".to_owned())
            );
        }
    }
}

#[test]
fn transparent_material_names_the_curve() {
    let mut s = server(EcCurves::Extended);
    let v = Version(2, 1);
    let pair = s.ok(v, CREATE_KEY_PAIR, key_pair(v, 61));
    let public = text(&pair, PUBLIC_KEY_UNIQUE_IDENTIFIER);
    let m = material(&s.ok(v, GET, get(v, &public, Some(21))));
    assert!(matches!(
        m.required(RECOMMENDED_CURVE).unwrap().value,
        Value::Enumeration(61)
    ));
}
