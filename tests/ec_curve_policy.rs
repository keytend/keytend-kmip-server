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

//! The server implements 13 KMIP Recommended Curves on every OpenSSL build
//! (docs/interpretations.md#supported-elliptic-curves): P-224, P-256, P-384,
//! P-521, secp256k1 and brainpoolP256-512 r1/t1. `--ec-curves nist` offers
//! the P curves only, `extended` (default) all 13 (tests/ec_curve_setting.rs).
//! FIPS mode keeps only the P curves. Every request that needs another KMIP
//! curve fails with Feature Not Supported, "Unsupported EC curve", decided by the
//! server before OpenSSL is asked.
use keytend_kmip_server::{
    protocol::{EcCurves, Engine, Version},
    store::Store,
    tags::*,
    ttlv::{Node, Value},
};

const SUPPORTED: [u32; 13] = [4, 7, 10, 13, 25, 61, 62, 63, 64, 65, 66, 67, 68];
const FIPS_CURVES: [u32; 4] = [4, 7, 10, 13];
/// P-192, sect163k1, secp160r1 and brainpoolP224r1.
const REMOVED: [u32; 4] = [1, 2, 21, 59];
const FEATURE_NOT_SUPPORTED: u32 = 8;

struct Server {
    _dir: tempfile::TempDir,
    e: Engine,
}
fn server(fips: bool) -> Server {
    server_with(fips, EcCurves::Extended)
}
fn server_with(fips: bool, curves: EcCurves) -> Server {
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
        e: Engine::new(store, true)
            .with_fips(fips)
            .with_ec_curves(curves),
        _dir: dir,
    }
}
impl Server {
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
        let response = self.e.process("alice", &message).unwrap();
        response.required(BATCH_ITEM).unwrap().clone()
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
// REQ:5ee0c67131c6b1d9 Feature not supported: an optional feature in the request is not supported
fn unsupported(item: &Node, what: &str) {
    assert_eq!(
        status(item),
        (1, FEATURE_NOT_SUPPORTED, "Unsupported EC curve".to_owned()),
        "{what}"
    );
}
fn fixtures() -> Vec<(u32, serde_json::Value)> {
    let data: serde_json::Value =
        serde_json::from_str(include_str!("ec-removed-curves.json")).unwrap();
    data["curves"]
        .as_object()
        .unwrap()
        .values()
        .map(|f| (f["curve"].as_u64().unwrap() as u32, f.clone()))
        .collect()
}
fn bytes(fixture: &serde_json::Value, field: &str) -> Vec<u8> {
    hex::decode(fixture[field].as_str().unwrap()).unwrap()
}
/// 2.x Create Key Pair, ECDSA on `curve`.
fn key_pair(curve: u32) -> Vec<Node> {
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
}
/// Register an EC key (2.x): `kind` 3 public or 4 private, with key material
/// in `format`.
fn register_key(kind: u32, format: u32, material: Node) -> Vec<Node> {
    vec![
        Node::enumeration(OBJECT_TYPE, kind),
        Node::structure(
            ATTRIBUTES,
            vec![Node::int(
                CRYPTOGRAPHIC_USAGE_MASK,
                if kind == 4 { 1 } else { 2 },
            )],
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

#[test]
fn create_key_pair_offers_exactly_the_supported_curves() {
    for curves in [EcCurves::Nist, EcCurves::Extended] {
        for fips in [false, true] {
            let mut s = server_with(fips, curves);
            for curve in 1..=68 {
                let item = s.call(Version(2, 1), 2, key_pair(curve));
                let (result, reason, message) = status(&item);
                let what = format!("curve {curve} fips {fips} {curves:?}");
                if FIPS_CURVES.contains(&curve)
                    || !fips && curves == EcCurves::Extended && SUPPORTED.contains(&curve)
                {
                    assert_eq!(result, 0, "{what}: {message}");
                } else if SUPPORTED.contains(&curve) && fips {
                    // FIPS mode answers alike under both values.
                    assert_eq!((result, reason), (1, FEATURE_NOT_SUPPORTED), "{what}");
                    assert!(message.contains("FIPS mode"), "{message}");
                } else {
                    unsupported(&item, &what);
                }
            }
            // The same in KMIP 3.0 (1.x uses template attributes and reaches the
            // same check, `ec::curve`).
            unsupported(&s.call(Version(3, 0), 2, key_pair(1)), "3.0 P-192");
        }
    }
}

#[test]
fn register_refuses_removed_curves_in_every_key_format_and_in_certificates() {
    for (fips, curves) in [
        (false, EcCurves::Nist),
        (false, EcCurves::Extended),
        (true, EcCurves::Nist),
        (true, EcCurves::Extended),
    ] {
        let mut s = server_with(fips, curves);
        for (curve, fixture) in fixtures() {
            assert!(REMOVED.contains(&curve));
            let what = format!("curve {curve} fips {fips} {curves:?}");
            // DER: SubjectPublicKeyInfo (5), PKCS#8 (4) and SEC 1 (6).
            for (kind, format, field) in [(3, 5, "spki"), (4, 4, "pkcs8"), (4, 6, "sec1")] {
                let material = Node::bytes(KEY_MATERIAL, bytes(&fixture, field));
                unsupported(
                    &s.call(Version(2, 1), 3, register_key(kind, format, material)),
                    &what,
                );
            }
            // Transparent EC public key (format 21): the curve is named in the material.
            let point = Node::structure(
                KEY_MATERIAL,
                vec![
                    Node::enumeration(RECOMMENDED_CURVE, curve),
                    Node::bytes(Q_STRING, vec![4; 49]),
                ],
            );
            unsupported(&s.call(Version(2, 1), 3, register_key(3, 21, point)), &what);
            // X.509 certificate with a subject key on the curve.
            let certificate = vec![
                Node::enumeration(OBJECT_TYPE, 1),
                Node::structure(ATTRIBUTES, vec![]),
                Node::structure(
                    CERTIFICATE,
                    vec![
                        Node::enumeration(CERTIFICATE_TYPE, 1),
                        Node::bytes(CERTIFICATE_VALUE, bytes(&fixture, "certificate")),
                    ],
                ),
            ];
            unsupported(&s.call(Version(2, 1), 3, certificate), &what);
            // Validate with the certificate inline.
            let validate = vec![Node::structure(
                CERTIFICATE,
                vec![
                    Node::enumeration(CERTIFICATE_TYPE, 1),
                    Node::bytes(CERTIFICATE_VALUE, bytes(&fixture, "certificate")),
                ],
            )];
            unsupported(&s.call(Version(2, 1), 23, validate), &what);
        }
    }
}

/// With `--ec-curves extended` all 13 curves create and sign
/// (tests/ec_curve_setting.rs covers both values per edition).
#[test]
fn supported_curves_still_register_and_sign() {
    let mut s = server(false);
    for curve in SUPPORTED {
        let item = s.call(Version(2, 1), 2, key_pair(curve));
        assert_eq!(status(&item).0, 0, "curve {curve}");
        let payload = item.required(RESPONSE_PAYLOAD).unwrap();
        let private = payload
            .required(PRIVATE_KEY_UNIQUE_IDENTIFIER)
            .unwrap()
            .string()
            .unwrap()
            .to_owned();
        s.call(
            Version(2, 1),
            18,
            vec![Node::text(UNIQUE_IDENTIFIER, &private)],
        );
        let sign = s.call(
            Version(2, 1),
            33,
            vec![
                Node::text(UNIQUE_IDENTIFIER, &private),
                Node::structure(
                    CRYPTOGRAPHIC_PARAMETERS,
                    vec![
                        Node::enumeration(CRYPTOGRAPHIC_ALGORITHM, 6),
                        Node::enumeration(HASHING_ALGORITHM, 6),
                    ],
                ),
                Node::bytes(DATA, b"message".to_vec()),
            ],
        );
        assert_eq!(status(&sign).0, 0, "curve {curve}: {:?}", status(&sign));
        assert!(matches!(
            sign.required(RESPONSE_PAYLOAD)
                .unwrap()
                .required(SIGNATURE_DATA)
                .unwrap()
                .value,
            Value::ByteString(_)
        ));
    }
}

/// DER TLV with a definite length.
fn tlv(tag: u8, contents: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    match contents.len() {
        n @ 0..=127 => out.push(n as u8),
        n @ 128..=255 => out.extend([0x81, n as u8]),
        n => out.extend([0x82, (n >> 8) as u8, n as u8]),
    }
    out.extend(contents);
    out
}
/// PKCS#8 PrivateKeyInfo around a fixture's SEC 1 key (the fixture's
/// `pkcs8` field holds the SEC 1 encoding too), with the SubjectPublicKeyInfo's
/// AlgorithmIdentifier.
fn pkcs8(fixture: &serde_json::Value) -> Vec<u8> {
    let spki = bytes(fixture, "spki");
    // SEQUENCE { AlgorithmIdentifier, BIT STRING }: the first inner element.
    let header = if spki[1] & 0x80 != 0 {
        2 + (spki[1] & 0x7f) as usize
    } else {
        2
    };
    let algorithm = &spki[header..header + 2 + spki[header + 1] as usize];
    let mut info = vec![0x02, 0x01, 0x00];
    info.extend(algorithm);
    info.extend(tlv(0x04, &bytes(fixture, "sec1")));
    tlv(0x30, &info)
}
/// Keys stored on curves no longer offered are returned as stored
/// (read from the DER without OpenSSL) but cannot sign, convert or be
/// re-keyed. The fixtures replace the material of a stored P-256 pair.
#[test]
fn keys_on_removed_curves_are_returned_as_stored_only() {
    for (curve, fixture) in fixtures() {
        let mut s = server(false);
        let v = Version(2, 1);
        let item = s.call(v, 2, key_pair(7));
        let payload = item.required(RESPONSE_PAYLOAD).unwrap();
        let id = |tag| payload.required(tag).unwrap().string().unwrap().to_owned();
        let (private, public) = (
            id(PRIVATE_KEY_UNIQUE_IDENTIFIER),
            id(PUBLIC_KEY_UNIQUE_IDENTIFIER),
        );
        for (uid, material, format) in [
            (&private, pkcs8(&fixture), 20),
            (&public, bytes(&fixture, "spki"), 21),
        ] {
            let mut obj = s.e.store.get("alice", uid).unwrap().unwrap();
            assert_eq!(obj.format, format);
            obj.material = material;
            s.e.store.put(&obj).unwrap();
        }
        let what = format!("curve {curve}");
        let get = |id: &str, format: Option<u32>| {
            let mut p = vec![Node::text(UNIQUE_IDENTIFIER, id)];
            p.extend(format.map(|f| Node::enumeration(KEY_FORMAT_TYPE, f)));
            p
        };
        let material = |item: &Node| {
            assert_eq!(status(item).0, 0, "{what}: {:?}", status(item));
            let p = item.required(RESPONSE_PAYLOAD).unwrap();
            p.get(PRIVATE_KEY)
                .or_else(|| p.get(PUBLIC_KEY))
                .unwrap()
                .required(KEY_BLOCK)
                .unwrap()
                .required(KEY_VALUE)
                .unwrap()
                .required(KEY_MATERIAL)
                .unwrap()
                .clone()
        };
        // Transparent, as stored: the curve and D or Q from the DER.
        for uid in [&private, &public] {
            let m = material(&s.call(v, 10, get(uid, None)));
            assert!(
                matches!(m.required(RECOMMENDED_CURVE).unwrap().value, Value::Enumeration(c) if c == curve),
                "{what}"
            );
        }
        let q = material(&s.call(v, 10, get(&public, None)));
        let spki = bytes(&fixture, "spki");
        let point = q.required(Q_STRING).unwrap().byte_string().unwrap();
        assert!(spki.ends_with(point), "{what}");
        // Conversions, signing and re-keying are refused.
        unsupported(&s.call(v, 10, get(&private, Some(4))), &what);
        unsupported(&s.call(v, 10, get(&public, Some(5))), &what);
        let sign = vec![
            Node::text(UNIQUE_IDENTIFIER, &private),
            Node::structure(
                CRYPTOGRAPHIC_PARAMETERS,
                vec![
                    Node::enumeration(CRYPTOGRAPHIC_ALGORITHM, 6),
                    Node::enumeration(HASHING_ALGORITHM, 6),
                ],
            ),
            Node::bytes(DATA, b"message".to_vec()),
        ];
        s.call(v, 18, vec![Node::text(UNIQUE_IDENTIFIER, &private)]);
        unsupported(&s.call(v, 33, sign), &what);
        // Re-key Key Pair is refused (its pair check runs before the curve
        // check, so the reason is not asserted here).
        let rekey = s.call(
            v,
            29,
            vec![Node::text(PRIVATE_KEY_UNIQUE_IDENTIFIER, &private)],
        );
        assert_eq!(status(&rekey).0, 1, "{what}");
        // A DER-stored key is returned byte for byte.
        let mut obj = s.e.store.get("alice", &private).unwrap().unwrap();
        obj.format = 4;
        s.e.store.put(&obj).unwrap();
        let m = material(&s.call(v, 10, get(&private, None)));
        assert!(m.byte_string().unwrap() == pkcs8(&fixture), "{what}");
        // FIPS mode refuses even the stored form, as before.
        let mut fips = Server {
            e: Engine::new(s.e.store, true).with_fips(true),
            _dir: s._dir,
        };
        unsupported(&fips.call(v, 10, get(&private, None)), &what);
    }
}
