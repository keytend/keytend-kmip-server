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
    dir: tempfile::TempDir,
    engine: Engine,
}
impl Fixture {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let key = dir.path().join("master");
        std::fs::write(&key, [31; 32]).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        let engine = Engine::new(
            Store::open(&dir.path().join("keys.sqlite"), &key).unwrap(),
            true,
        );
        Self { dir, engine }
    }
    fn restart(&mut self) {
        self.engine = Engine::new(
            Store::open(
                &self.dir.path().join("keys.sqlite"),
                &self.dir.path().join("master"),
            )
            .unwrap(),
            true,
        );
    }
    fn call(&mut self, v: Version, op: u32, fields: Vec<Node>) -> Node {
        let mut header = vec![v.node()];
        let mut item = vec![
            Node::enumeration(OPERATION, op),
            Node::structure(REQUEST_PAYLOAD, fields),
        ];
        if v.0 < 3 {
            header.push(Node::int(BATCH_COUNT, 1));
            item.push(Node::bytes(UNIQUE_BATCH_ITEM_ID, vec![1]));
        }
        self.engine
            .process(
                "alice",
                &Node::structure(
                    REQUEST_MESSAGE,
                    vec![
                        Node::structure(REQUEST_HEADER, header),
                        Node::structure(BATCH_ITEM, item),
                    ],
                ),
            )
            .unwrap()
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
fn id(n: &Node) -> String {
    body(n)
        .required(UNIQUE_IDENTIFIER)
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
fn editions() -> [Version; 7] {
    [
        Version(1, 1),
        Version(1, 2),
        Version(1, 3),
        Version(1, 4),
        Version(2, 0),
        Version(2, 1),
        Version(3, 0),
    ]
}
fn fixture(name: &str) -> Vec<u8> {
    let d: serde_json::Value = serde_json::from_str(include_str!("fixtures/openpgp.json")).unwrap();
    let value = d[name].as_str().unwrap().as_bytes().to_vec();
    if name != "v3_public" {
        return value;
    }
    // Reuse the pre-existing V3 RSA key, adding its required public identity.
    // This does not generate new deprecated V3 key material or a signature.
    let mut raw = binary(&value);
    let identity = b"Existing V3 fixture";
    raw.extend([0xcd, identity.len() as u8]);
    raw.extend(identity);
    let encoded = openssl::base64::encode_block(&raw);
    format!(
        "-----BEGIN PGP PUBLIC KEY BLOCK-----\n\n{}\n-----END PGP PUBLIC KEY BLOCK-----\n",
        encoded
    )
    .into_bytes()
}
fn binary(data: &[u8]) -> Vec<u8> {
    let text = std::str::from_utf8(data).unwrap();
    let mut started = false;
    let mut encoded = String::new();
    for line in text.lines() {
        if line.is_empty() {
            started = true;
            continue;
        }
        if started && !line.starts_with('=') && !line.starts_with("-----") {
            encoded.push_str(line);
        }
    }
    openssl::base64::decode_block(&encoded).unwrap()
}
fn object(kind: u32, data: &[u8]) -> Node {
    Node::structure(
        CERTIFICATE,
        vec![
            Node::enumeration(CERTIFICATE_TYPE, kind),
            Node::bytes(CERTIFICATE_VALUE, data.to_vec()),
        ],
    )
}
fn attrs(v: Version, values: Vec<Node>) -> Node {
    if v.0 >= 2 {
        return Node::structure(ATTRIBUTES, values);
    }
    Node::structure(
        TEMPLATE_ATTRIBUTE,
        values
            .into_iter()
            .map(|mut value| {
                let name = match value.tag {
                    CRYPTOGRAPHIC_ALGORITHM => "Cryptographic Algorithm",
                    CRYPTOGRAPHIC_LENGTH => "Cryptographic Length",
                    CRYPTOGRAPHIC_USAGE_MASK => "Cryptographic Usage Mask",
                    CERTIFICATE_LENGTH => "Certificate Length",
                    CERTIFICATE_TYPE => "Certificate Type",
                    DIGITAL_SIGNATURE_ALGORITHM => "Digital Signature Algorithm",
                    _ => panic!("attribute"),
                };
                value.tag = ATTRIBUTE_VALUE;
                Node::structure(ATTRIBUTE, vec![Node::text(ATTRIBUTE_NAME, name), value])
            })
            .collect(),
    )
}
fn register(f: &mut Fixture, v: Version, data: &[u8], mut supplied: Vec<Node>) -> Node {
    let mut values = vec![
        Node::enumeration(CRYPTOGRAPHIC_ALGORITHM, 4),
        Node::int(CRYPTOGRAPHIC_LENGTH, 2048),
        Node::int(CRYPTOGRAPHIC_USAGE_MASK, 0),
        Node::int(CERTIFICATE_LENGTH, data.len() as i32),
    ];
    for value in supplied.drain(..) {
        values.retain(|a| a.tag != value.tag);
        values.push(value);
    }
    f.call(
        v,
        3,
        vec![
            Node::enumeration(OBJECT_TYPE, 1),
            attrs(v, values),
            object(2, data),
        ],
    )
}
fn check(f: &mut Fixture, v: Version, key: &str, data: &[u8]) {
    let reply = f.call(v, 10, vec![uid(v, key)]);
    let cert = body(&reply).required(CERTIFICATE).unwrap();
    assert_eq!(
        cert.required(CERTIFICATE_TYPE).unwrap().number().unwrap(),
        2
    );
    assert_eq!(
        cert.required(CERTIFICATE_VALUE)
            .unwrap()
            .byte_string()
            .unwrap(),
        data
    );
    let stored = f.engine.store.get("alice", key).unwrap().unwrap();
    assert_eq!(stored.certificate_type, 2);
    assert_eq!(stored.bits, 2048);
    assert_eq!(stored.algorithm, 4);
    assert!(
        stored
            .attrs
            .iter()
            .any(|a| a.tag == CERTIFICATE_LENGTH && a.number().unwrap() == data.len() as u32)
    );
}
fn signatures(f: &mut Fixture, v: Version, key: &str) -> Vec<u32> {
    let selector = if v.0 == 1 {
        Node::text(ATTRIBUTE_NAME, "Digital Signature Algorithm")
    } else {
        Node::enumeration(ATTRIBUTE_REFERENCE, DIGITAL_SIGNATURE_ALGORITHM)
    };
    let response = f.call(v, 11, vec![uid(v, key), selector]);
    let p = body(&response);
    if v.0 == 1 {
        p.all(ATTRIBUTE)
            .enumerate()
            .map(|(i, a)| {
                assert_eq!(
                    a.required(ATTRIBUTE_INDEX).unwrap().number().unwrap(),
                    i as u32
                );
                a.required(ATTRIBUTE_VALUE).unwrap().number().unwrap()
            })
            .collect()
    } else {
        p.required(ATTRIBUTES)
            .unwrap()
            .all(DIGITAL_SIGNATURE_ALGORITHM)
            .map(|a| a.number().unwrap())
            .collect()
    }
}
#[test]
fn all_final_editions_and_draft_preserve_public_certificate_type_and_metadata() {
    for v in editions() {
        for name in ["v3_public", "v4_public"] {
            let mut f = Fixture::new();
            let data = fixture(name);
            let extra = if name == "v3_public" {
                vec![Node::enumeration(DIGITAL_SIGNATURE_ALGORITHM, 7)]
            } else {
                vec![]
            };
            let key = id(&register(&mut f, v, &data, extra));
            check(&mut f, v, &key, &data);
            assert_eq!(signatures(&mut f, v, &key), vec![7]);
            f.restart();
            check(&mut f, v, &key, &data);
            let bytes = binary(&data);
            let copy = id(&register(
                &mut f,
                v,
                &bytes,
                if name == "v3_public" {
                    vec![Node::enumeration(DIGITAL_SIGNATURE_ALGORITHM, 7)]
                } else {
                    vec![]
                },
            ));
            check(&mut f, v, &copy, &bytes);
        }
    }
}
#[test]
fn complete_packet_stream_is_checked_and_secret_material_never_becomes_a_certificate() {
    let data = fixture("v4_public");
    let raw = binary(&data);
    let mut secret_suffix = raw.clone();
    secret_suffix.extend([0xc5, 1, 4]);
    let mut garbage_suffix = raw.clone();
    garbage_suffix.push(0);
    let mut truncated = raw.clone();
    truncated.pop();
    let mut second = raw.clone();
    second.extend_from_slice(&raw);
    let mut armor_suffix = data.clone();
    armor_suffix.extend_from_slice(b"not armor");
    for bad in [
        fixture("v4_private"),
        secret_suffix,
        garbage_suffix,
        truncated,
        second,
        armor_suffix,
        vec![],
        vec![0xc6, 1, 4],
    ] {
        assert!(keytend_kmip_server::crypto::pgp_certificate::inspect(&bad).is_err());
        let mut f = Fixture::new();
        assert_eq!(reason(&register(&mut f, Version(2, 1), &bad, vec![])), 7);
        assert!(f.engine.store.list("alice").unwrap().is_empty());
    }
    let mut bad_crc = data.clone();
    let index = bad_crc.windows(2).rposition(|w| w == b"\n=").unwrap() + 2;
    bad_crc[index] = if bad_crc[index] == b'A' { b'B' } else { b'A' };
    assert!(keytend_kmip_server::crypto::pgp_certificate::inspect(&bad_crc).is_err());
}
#[test]
fn signature_instances_are_derived_readonly_and_object_specific() {
    let data = multiple_fixture();
    for v in editions() {
        let mut f = Fixture::new();
        let key = id(&register(&mut f, v, &data, vec![]));
        assert_eq!(signatures(&mut f, v, &key), vec![7, 5]);
        let stored = f.engine.store.get("alice", &key).unwrap().unwrap();
        assert_eq!(stored.certificate_type, 2);
        let deletion = if v.0 == 1 {
            vec![
                uid(v, &key),
                Node::text(ATTRIBUTE_NAME, "Digital Signature Algorithm"),
                Node::int(ATTRIBUTE_INDEX, 1),
            ]
        } else {
            vec![
                uid(v, &key),
                Node::enumeration(ATTRIBUTE_REFERENCE, DIGITAL_SIGNATURE_ALGORITHM),
            ]
        };
        assert_eq!(
            reason(&f.call(v, 15, deletion)),
            if v.0 >= 2 { 0x22 } else { 12 }
        );
    }
}
fn split(f: &mut Fixture, v: Version, key: &str) -> Vec<String> {
    body(&f.call(
        v,
        40,
        vec![
            Node::enumeration(OBJECT_TYPE, 5),
            uid(v, key),
            Node::int(SPLIT_KEY_PARTS, 3),
            Node::int(SPLIT_KEY_THRESHOLD, 2),
            Node::enumeration(SPLIT_KEY_METHOD, 4),
            attrs(
                v,
                if v.0 >= 3 {
                    vec![Node::enumeration(SPLIT_KEY_POLYNOMIAL, 2)]
                } else {
                    vec![]
                },
            ),
        ],
    ))
    .all(UNIQUE_IDENTIFIER)
    .map(|n| n.identifier_text().unwrap().to_owned())
    .collect()
}
fn join(f: &mut Fixture, v: Version, parts: &[String]) -> Node {
    f.call(
        v,
        41,
        vec![
            Node::enumeration(OBJECT_TYPE, 1),
            uid(v, &parts[2]),
            uid(v, &parts[0]),
            attrs(v, vec![]),
        ],
    )
}
#[test]
fn certificate_type_and_signatures_survive_local_and_external_shares_and_backup() {
    let data = fixture("v4_public");
    for v in editions().into_iter().filter(|v| *v >= Version(1, 2)) {
        let mut f = Fixture::new();
        let key = id(&register(&mut f, v, &data, vec![]));
        let parts = split(&mut f, v, &key);
        f.restart();
        let joined = id(&join(&mut f, v, &parts));
        check(&mut f, v, &joined, &data);
        assert_eq!(signatures(&mut f, v, &joined), vec![7]);
        for part in &parts {
            let stored = f.engine.store.get("alice", part).unwrap().unwrap();
            assert!(!stored.attrs.iter().any(|a| matches!(
                a.tag,
                CERTIFICATE_TYPE | CERTIFICATE_LENGTH | DIGITAL_SIGNATURE_ALGORITHM
            )));
            assert_eq!(
                stored
                    .split
                    .as_ref()
                    .unwrap()
                    .source
                    .as_ref()
                    .unwrap()
                    .certificate_type,
                2
            );
        }
        let copies = parts
            .iter()
            .map(|part| {
                let response = f.call(v, 10, vec![uid(v, part)]);
                let obj = body(&response).required(SPLIT_KEY).unwrap().clone();
                id(&f.call(
                    v,
                    3,
                    vec![
                        Node::enumeration(OBJECT_TYPE, 5),
                        attrs(
                            v,
                            if v.0 >= 3 {
                                vec![Node::enumeration(SPLIT_KEY_POLYNOMIAL, 2)]
                            } else {
                                vec![]
                            },
                        ),
                        obj,
                    ],
                ))
            })
            .collect::<Vec<_>>();
        let external = id(&join(&mut f, v, &copies));
        check(&mut f, v, &external, &data);
        assert_eq!(signatures(&mut f, v, &external), vec![7]);
        let backup = f.dir.path().join("backup");
        f.engine.store.backup(&backup).unwrap();
        let clean = f.dir.path().join("clean");
        std::fs::create_dir(&clean).unwrap();
        std::fs::copy(backup, clean.join("keys")).unwrap();
        f.engine = Engine::new(
            Store::open(&clean.join("keys"), &f.dir.path().join("master")).unwrap(),
            true,
        );
        let restored = id(&join(&mut f, v, &parts));
        check(&mut f, v, &restored, &data);
    }
}
#[test]
fn live_and_destroyed_import_preserve_type_and_multiple_signature_metadata() {
    for v in [Version(1, 4), Version(2, 0), Version(2, 1), Version(3, 0)] {
        let mut f = Fixture::new();
        let data = multiple_fixture();
        let key = id(&register(&mut f, v, &data, vec![]));
        let exported = body(&f.call(v, 43, vec![uid(v, &key)]))
            .children()
            .unwrap()
            .to_vec();
        f.call(v, 20, vec![uid(v, &key)]);
        let mut fields = exported;
        fields.push(Node::boolean(REPLACE_EXISTING, true));
        body(&f.call(v, 42, fields));
        check(&mut f, v, &key, &data);
        body(&f.call(v, 20, vec![uid(v, &key)]));
        let mut destroyed = body(&f.call(v, 43, vec![uid(v, &key)]))
            .children()
            .unwrap()
            .to_vec();
        let cert = destroyed.iter().find(|a| a.tag == CERTIFICATE).unwrap();
        assert_eq!(
            cert.required(CERTIFICATE_TYPE).unwrap().number().unwrap(),
            2
        );
        assert!(cert.get(CERTIFICATE_VALUE).is_none());
        destroyed.push(Node::boolean(REPLACE_EXISTING, true));
        body(&f.call(v, 42, destroyed));
        assert_eq!(
            f.engine
                .store
                .get("alice", &key)
                .unwrap()
                .unwrap()
                .certificate_type,
            2
        );
        assert_eq!(signatures(&mut f, v, &key), vec![7, 5]);
    }
}
#[test]
fn conflicting_material_metadata_is_rejected_before_commit() {
    for v in editions() {
        for wrong in [
            Node::enumeration(CERTIFICATE_TYPE, 1),
            Node::int(CERTIFICATE_LENGTH, 1),
            Node::int(CRYPTOGRAPHIC_LENGTH, 1024),
            Node::enumeration(CRYPTOGRAPHIC_ALGORITHM, 5),
            Node::enumeration(DIGITAL_SIGNATURE_ALGORITHM, 5),
        ] {
            let mut f = Fixture::new();
            assert_eq!(
                reason(&register(&mut f, v, &fixture("v4_public"), vec![wrong])),
                7
            );
            assert!(f.engine.store.list("alice").unwrap().is_empty());
        }
    }
}

fn multiple_fixture() -> Vec<u8> {
    // Framing-only extra certification, not a cryptographically valid signature.
    let mut data = binary(&fixture("v4_public"));
    let signature = [4, 0x13, 1, 8, 0, 0, 0, 0, 0, 0, 0, 1, 1];
    data.extend([0xc2, signature.len() as u8]);
    data.extend(signature);
    data
}

#[test]
fn real_dsa_and_three_nist_ec_certificates_match_gnupg_metadata() {
    let fixtures: serde_json::Value =
        serde_json::from_str(include_str!("fixtures/pgp-certificates.json")).unwrap();
    for (name, fixture) in fixtures["fixtures"].as_object().unwrap() {
        let data = fixture["armored"].as_str().unwrap().as_bytes();
        let algorithm = fixture["algorithm"].as_u64().unwrap() as u32;
        let bits = fixture["bits"].as_u64().unwrap() as u32;
        let expected = fixture["signature_algorithms"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_u64().unwrap() as u32)
            .collect::<Vec<_>>();
        assert!(fixture["generator_verified_signatures"].as_u64().unwrap() >= 1);
        let inspected = keytend_kmip_server::crypto::pgp_certificate::inspect(data)
            .unwrap_or_else(|error| panic!("{name}: {error}"));
        assert_eq!(inspected.algorithm, Some(algorithm));
        assert_eq!(inspected.bits, Some(bits));
        assert_eq!(inspected.signatures, expected);
        assert!(!inspected.unknown_signatures);
        for v in editions() {
            let mut f = Fixture::new();
            let key = id(&register(
                &mut f,
                v,
                data,
                vec![
                    Node::enumeration(CRYPTOGRAPHIC_ALGORITHM, algorithm),
                    Node::int(CRYPTOGRAPHIC_LENGTH, bits as i32),
                ],
            ));
            assert_eq!(signatures(&mut f, v, &key), expected);
            let result = f.call(v, 10, vec![uid(v, &key)]);
            let value = body(&result).required(CERTIFICATE).unwrap();
            assert_eq!(
                value.required(CERTIFICATE_TYPE).unwrap().number().unwrap(),
                2
            );
            assert_eq!(
                value
                    .required(CERTIFICATE_VALUE)
                    .unwrap()
                    .byte_string()
                    .unwrap(),
                data
            );
            assert_eq!(reason(&f.call(v, 23, vec![uid(v, &key)])), 8);
        }
    }
}
