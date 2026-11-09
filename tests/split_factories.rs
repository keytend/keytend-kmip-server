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
    ttlv::{Node, Value},
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
fn versions() -> Vec<Version> {
    Version::supported(true)
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

fn source(f: &mut Fixture, v: Version) -> String {
    let attrs = vec![
        Node::int(CRYPTOGRAPHIC_USAGE_MASK, 12),
        Node::structure(
            USAGE_LIMITS,
            vec![
                Node::long(USAGE_LIMITS_TOTAL, 2),
                Node::enumeration(USAGE_LIMITS_UNIT, 2),
            ],
        ),
    ];
    let object = Node::structure(
        SYMMETRIC_KEY,
        vec![Node::structure(
            KEY_BLOCK,
            vec![
                Node::enumeration(KEY_FORMAT_TYPE, 1),
                Node::structure(
                    KEY_VALUE,
                    vec![Node::bytes(KEY_MATERIAL, (1u8..=16).collect::<Vec<_>>())],
                ),
                Node::enumeration(CRYPTOGRAPHIC_ALGORITHM, 3),
                Node::int(CRYPTOGRAPHIC_LENGTH, 128),
            ],
        )],
    );
    identifier(&f.call(
        v,
        "alice",
        3,
        vec![
            Node::enumeration(OBJECT_TYPE, 2),
            container(v, attrs),
            object,
        ],
    ))
}
fn create_fields(v: Version, method: u32, source: Option<&str>) -> Vec<Node> {
    let mut attrs = vec![];
    if v.0 >= 3 && [2, 4].contains(&method) {
        attrs.push(Node::enumeration(SPLIT_KEY_POLYNOMIAL, 2));
    }
    let mut fields = vec![
        Node::enumeration(OBJECT_TYPE, 5),
        Node::int(SPLIT_KEY_PARTS, 3),
        Node::int(SPLIT_KEY_THRESHOLD, if method == 1 { 3 } else { 2 }),
        Node::enumeration(SPLIT_KEY_METHOD, method),
        container(v, attrs),
    ];
    if let Some(source) = source {
        fields.push(id(v, source));
    }
    fields
}
fn ids(response: &Node) -> Vec<String> {
    payload(response)
        .all(UNIQUE_IDENTIFIER)
        .map(|n| n.identifier_text().unwrap().to_owned())
        .collect()
}
fn count(f: &Fixture, key: &str) -> i64 {
    let object = f.engine.store.get("alice", key).unwrap().unwrap();
    match object
        .attrs
        .iter()
        .find(|a| a.tag == USAGE_LIMITS)
        .unwrap()
        .required(USAGE_LIMITS_COUNT)
        .unwrap()
        .value
    {
        Value::LongInteger(n) => n,
        _ => panic!("not a count"),
    }
}
#[test]
fn split_join_all_methods_preserve_source_and_initialize_new_object_lifetimes() {
    for v in versions().into_iter().filter(|v| *v >= Version(1, 2)) {
        for method in 1..=4 {
            let mut f = Fixture::new();
            let original = source(&mut f, v);
            payload(&f.call(v, "alice", 10, vec![id(v, &original)]));
            payload(&f.call(v, "alice", 18, vec![id(v, &original)]));
            payload(&f.call(
                v,
                "alice",
                17,
                vec![id(v, &original), Node::long(USAGE_LIMITS_COUNT, 2)],
            ));
            assert_eq!(count(&f, &original), 0);
            let created = f.call(v, "alice", 40, create_fields(v, method, Some(&original)));
            let parts = ids(&created);
            assert_eq!(parts.len(), 3);
            assert_eq!(
                payload(&created).get(OBJECT_TYPE).is_some(),
                v == Version(1, 2)
            );
            for (index, part) in parts.iter().enumerate() {
                let object = f.engine.store.get("alice", part).unwrap().unwrap();
                assert_eq!(object.split.as_ref().unwrap().part, index as u32 + 1);
                assert_eq!(object.bits, 128);
                assert_eq!(object.metadata.fresh, Some(true));
                assert_eq!(count(&f, part), 2);
            }
            f.restart();
            let mut join = vec![
                Node::enumeration(OBJECT_TYPE, 2),
                id(v, &parts[2]),
                id(v, &parts[0]),
            ];
            if method == 1 {
                join.push(id(v, &parts[1]));
            }
            let response = f.call(v, "alice", 41, join);
            let joined = identifier(&response);
            assert_eq!(
                payload(&response).get(OBJECT_TYPE).is_some(),
                v == Version(1, 2)
            );
            assert_ne!(joined, original);
            assert_eq!(count(&f, &joined), 2);
            assert_eq!(count(&f, &original), 0);
            assert_eq!(
                f.engine
                    .store
                    .get("alice", &joined)
                    .unwrap()
                    .unwrap()
                    .metadata
                    .fresh,
                Some(true)
            );
            assert_eq!(
                f.engine
                    .store
                    .get("alice", &original)
                    .unwrap()
                    .unwrap()
                    .metadata
                    .fresh,
                Some(false)
            );
            let got = f.call(v, "alice", 10, vec![id(v, &joined)]);
            assert_eq!(
                payload(&got)
                    .required(SYMMETRIC_KEY)
                    .unwrap()
                    .required(KEY_BLOCK)
                    .unwrap()
                    .required(KEY_VALUE)
                    .unwrap()
                    .required(KEY_MATERIAL)
                    .unwrap()
                    .byte_string()
                    .unwrap(),
                (1u8..=16).collect::<Vec<_>>()
            );
            assert_eq!(
                reason(&f.call(
                    v,
                    "bob",
                    41,
                    vec![
                        Node::enumeration(OBJECT_TYPE, 2),
                        id(v, &parts[0]),
                        id(v, &parts[1]),
                        id(v, &parts[2])
                    ]
                )),
                not_found(v)
            );
        }
    }
}
#[test]
fn new_source_creation_and_parameter_failures_are_atomic() {
    let v = Version(2, 1);
    let mut f = Fixture::new();
    let mut invalid = create_fields(v, 4, None);
    invalid.retain(|n| n.tag != ATTRIBUTES);
    invalid.push(container(
        v,
        vec![Node::enumeration(CRYPTOGRAPHIC_ALGORITHM, 0)],
    ));
    assert_eq!(reason(&f.call(v, "alice", 40, invalid)), 7);
    assert!(f.engine.store.list("alice").unwrap().is_empty());
    let parts = ids(&f.call(v, "alice", 40, create_fields(v, 4, None)));
    let first = f.engine.store.get("alice", &parts[0]).unwrap().unwrap();
    assert_eq!(first.algorithm, 3);
    assert_eq!(first.bits, 256);
    let before = serde_json::to_value(f.engine.store.list("alice").unwrap()).unwrap();
    assert_eq!(
        reason(&f.call(
            v,
            "alice",
            41,
            vec![Node::enumeration(OBJECT_TYPE, 2), id(v, &parts[0])]
        )),
        7
    );
    assert_eq!(
        reason(&f.call(
            v,
            "alice",
            41,
            vec![
                Node::enumeration(OBJECT_TYPE, 2),
                id(v, &parts[0]),
                id(v, &parts[0])
            ]
        )),
        7
    );
    assert_eq!(
        serde_json::to_value(f.engine.store.list("alice").unwrap()).unwrap(),
        before
    );
    let joined = identifier(&f.call(
        v,
        "alice",
        41,
        vec![
            Node::enumeration(OBJECT_TYPE, 2),
            id(v, &parts[2]),
            id(v, &parts[0]),
        ],
    ));
    assert_eq!(
        f.engine
            .store
            .get("alice", &joined)
            .unwrap()
            .unwrap()
            .material
            .len(),
        32
    );
}

fn register_object(
    f: &mut Fixture,
    v: Version,
    kind: u32,
    object: Node,
    mut attrs: Vec<Node>,
) -> String {
    if kind == 1 {
        let der = object
            .required(CERTIFICATE_VALUE)
            .unwrap()
            .byte_string()
            .unwrap();
        let metadata = keytend_kmip_server::crypto::certificate::inspect(der).unwrap();
        for a in [
            Node::enumeration(CRYPTOGRAPHIC_ALGORITHM, metadata.algorithm),
            Node::int(CRYPTOGRAPHIC_LENGTH, metadata.bits as i32),
            Node::int(CERTIFICATE_LENGTH, metadata.length as i32),
            Node::int(CRYPTOGRAPHIC_USAGE_MASK, 0),
        ] {
            if !attrs.iter().any(|old| old.tag == a.tag) {
                attrs.push(a);
            }
        }
    }
    identifier(&f.call(
        v,
        "alice",
        3,
        vec![
            Node::enumeration(OBJECT_TYPE, kind),
            container(v, attrs),
            object,
        ],
    ))
}
fn block_object(
    tag: u32,
    format: u32,
    material: Node,
    algorithm: u32,
    bits: u32,
    secret_type: u32,
) -> Node {
    let mut block = vec![
        Node::enumeration(KEY_FORMAT_TYPE, format),
        Node::structure(KEY_VALUE, vec![material]),
    ];
    if algorithm != 0 {
        block.push(Node::enumeration(CRYPTOGRAPHIC_ALGORITHM, algorithm));
    }
    if bits != 0 {
        block.push(Node::int(CRYPTOGRAPHIC_LENGTH, bits as i32));
    }
    let mut fields = vec![];
    if tag == SECRET_DATA {
        fields.push(Node::enumeration(SECRET_DATA_TYPE, secret_type));
    }
    fields.push(Node::structure(KEY_BLOCK, block));
    Node::structure(tag, fields)
}
fn join_fields(v: Version, kind: u32, parts: &[String], method: u32) -> Vec<Node> {
    let mut fields = vec![
        Node::enumeration(OBJECT_TYPE, kind),
        id(v, &parts[2]),
        id(v, &parts[0]),
    ];
    if method == 1 {
        fields.push(id(v, &parts[1]));
    }
    fields
}
fn copied_parts(f: &mut Fixture, v: Version, parts: &[String]) -> Vec<String> {
    parts
        .iter()
        .map(|part| {
            let response = f.call(v, "alice", 10, vec![id(v, part)]);
            let object = payload(&response).required(SPLIT_KEY).unwrap().clone();
            let mut attrs = vec![];
            if v.0 >= 3 {
                let original = f.engine.store.get("alice", part).unwrap().unwrap();
                if let Some(poly) = original.split.as_ref().unwrap().polynomial {
                    attrs.push(Node::enumeration(SPLIT_KEY_POLYNOMIAL, poly));
                }
            }
            let id = register_object(f, v, 5, object, attrs);
            assert!(
                f.engine
                    .store
                    .get("alice", &id)
                    .unwrap()
                    .unwrap()
                    .split
                    .as_ref()
                    .unwrap()
                    .source
                    .is_none()
            );
            id
        })
        .collect()
}
fn crypto_identity(object: &keytend_kmip_server::store::Object) -> Vec<u8> {
    if object.object_type == 4 {
        openssl::pkey::PKey::private_key_from_der(&object.material)
            .unwrap()
            .private_key_to_pkcs8()
            .unwrap()
    } else if object.object_type == 3 {
        openssl::pkey::PKey::public_key_from_der(&object.material)
            .or_else(|_| {
                openssl::rsa::Rsa::public_key_from_der_pkcs1(&object.material)
                    .and_then(openssl::pkey::PKey::from_rsa)
            })
            .unwrap()
            .public_key_to_der()
            .unwrap()
    } else {
        object.material.clone()
    }
}
fn certificate(key: &openssl::pkey::PKey<openssl::pkey::Private>) -> Node {
    let mut name = openssl::x509::X509Name::builder().unwrap();
    name.append_entry_by_text("CN", "split-factory-fixture")
        .unwrap();
    let name = name.build();
    let mut cert = openssl::x509::X509::builder().unwrap();
    cert.set_version(2).unwrap();
    cert.set_serial_number(
        &openssl::bn::BigNum::from_u32(1)
            .unwrap()
            .to_asn1_integer()
            .unwrap(),
    )
    .unwrap();
    cert.set_subject_name(&name).unwrap();
    cert.set_issuer_name(&name).unwrap();
    cert.set_pubkey(key).unwrap();
    cert.set_not_before(&openssl::asn1::Asn1Time::days_from_now(0).unwrap())
        .unwrap();
    cert.set_not_after(&openssl::asn1::Asn1Time::days_from_now(1).unwrap())
        .unwrap();
    cert.sign(key, openssl::hash::MessageDigest::sha256())
        .unwrap();
    Node::structure(
        CERTIFICATE,
        vec![
            Node::enumeration(CERTIFICATE_TYPE, 1),
            Node::bytes(CERTIFICATE_VALUE, cert.build().to_der().unwrap()),
        ],
    )
}
#[test]
fn local_and_external_reconstruction_cover_supported_object_types_and_formats() {
    let rsa = openssl::pkey::PKey::from_rsa(openssl::rsa::Rsa::generate(2048).unwrap()).unwrap();
    let ec = keytend_kmip_server::crypto::ec::generate(7).unwrap();
    let ec_der = ec.private_key_to_pkcs8().unwrap();
    let ec_public = ec.public_key_to_der().unwrap();
    for v in versions().into_iter().filter(|v| *v >= Version(1, 2)) {
        let mut objects = vec![
            (1, certificate(&rsa)),
            (
                2,
                block_object(
                    SYMMETRIC_KEY,
                    1,
                    Node::bytes(KEY_MATERIAL, vec![0; 16]),
                    3,
                    128,
                    2,
                ),
            ),
            (
                2,
                block_object(
                    SYMMETRIC_KEY,
                    7,
                    Node::structure(KEY_MATERIAL, vec![Node::bytes(KEY, vec![3; 16])]),
                    3,
                    128,
                    2,
                ),
            ),
            (
                7,
                block_object(
                    SECRET_DATA,
                    1,
                    Node::bytes(KEY_MATERIAL, vec![0, 0, 1, 2, 3, 4, 5]),
                    0,
                    56,
                    1,
                ),
            ),
            (
                7,
                block_object(
                    SECRET_DATA,
                    2,
                    Node::bytes(KEY_MATERIAL, vec![0, 0, 0, 8, 9]),
                    0,
                    40,
                    2,
                ),
            ),
            (
                8,
                Node::structure(
                    OPAQUE_OBJECT,
                    vec![
                        Node::enumeration(OPAQUE_DATA_TYPE, 0x80000000),
                        Node::bytes(OPAQUE_DATA_VALUE, vec![0, 0, 2, 3, 4, 5, 6]),
                    ],
                ),
            ),
            (
                3,
                block_object(
                    PUBLIC_KEY,
                    3,
                    Node::bytes(
                        KEY_MATERIAL,
                        rsa.rsa().unwrap().public_key_to_der_pkcs1().unwrap(),
                    ),
                    4,
                    2048,
                    2,
                ),
            ),
            (
                3,
                block_object(
                    PUBLIC_KEY,
                    5,
                    Node::bytes(KEY_MATERIAL, rsa.public_key_to_der().unwrap()),
                    4,
                    2048,
                    2,
                ),
            ),
            (
                4,
                block_object(
                    PRIVATE_KEY,
                    3,
                    Node::bytes(
                        KEY_MATERIAL,
                        rsa.rsa().unwrap().private_key_to_der().unwrap(),
                    ),
                    4,
                    2048,
                    2,
                ),
            ),
            (
                4,
                block_object(
                    PRIVATE_KEY,
                    4,
                    Node::bytes(KEY_MATERIAL, rsa.private_key_to_pkcs8().unwrap()),
                    4,
                    2048,
                    2,
                ),
            ),
            (
                3,
                block_object(
                    PUBLIC_KEY,
                    5,
                    Node::bytes(KEY_MATERIAL, ec_public.clone()),
                    6,
                    256,
                    2,
                ),
            ),
            (
                4,
                block_object(
                    PRIVATE_KEY,
                    4,
                    Node::bytes(KEY_MATERIAL, ec_der.clone()),
                    6,
                    256,
                    2,
                ),
            ),
            (
                4,
                block_object(
                    PRIVATE_KEY,
                    6,
                    Node::bytes(
                        KEY_MATERIAL,
                        ec.ec_key().unwrap().private_key_to_der().unwrap(),
                    ),
                    6,
                    256,
                    2,
                ),
            ),
        ];
        let d = keytend_kmip_server::crypto::ec::scalar(&ec_der).unwrap();
        let size = (d.len() + usize::from(d[0] & 128 != 0)).next_multiple_of(8);
        let mut scalar = vec![0; size];
        scalar[size - d.len()..].copy_from_slice(&d);
        let private_material = Node::structure(
            KEY_MATERIAL,
            vec![
                Node::enumeration(RECOMMENDED_CURVE, 7),
                Node {
                    tag: D,
                    value: Value::BigInteger(scalar),
                },
            ],
        );
        let public_material = Node::structure(
            KEY_MATERIAL,
            vec![
                Node::enumeration(RECOMMENDED_CURVE, 7),
                Node::bytes(
                    Q_STRING,
                    keytend_kmip_server::crypto::ec::point(&ec_public, 1).unwrap(),
                ),
            ],
        );
        let (private_format, public_format) = if v >= Version(1, 3) {
            (20, 21)
        } else {
            (14, 15)
        };
        objects.push((
            4,
            block_object(PRIVATE_KEY, private_format, private_material, 6, 256, 2),
        ));
        objects.push((
            3,
            block_object(PUBLIC_KEY, public_format, public_material, 6, 256, 2),
        ));
        for (kind, object) in objects {
            for method in 1..=4 {
                let mut f = Fixture::new();
                let original = register_object(&mut f, v, kind, object.clone(), vec![]);
                let expected = f.engine.store.get("alice", &original).unwrap().unwrap();
                let identity = crypto_identity(&expected);
                let parts = ids(&f.call(v, "alice", 40, create_fields(v, method, Some(&original))));
                f.restart();
                let joined =
                    identifier(&f.call(v, "alice", 41, join_fields(v, kind, &parts, method)));
                let result = f.engine.store.get("alice", &joined).unwrap().unwrap();
                assert!(
                    crypto_identity(&result) == identity,
                    "local reconstruction changed material; {}.{} kind {kind} method {method}",
                    v.0,
                    v.1
                );
                assert_eq!(result.format, expected.format);
                assert_eq!(result.secret_type, expected.secret_type);
                let external = copied_parts(&mut f, v, &parts);
                let mut fields = join_fields(v, kind, &external, method);
                if kind == 7 {
                    fields.push(Node::enumeration(SECRET_DATA_TYPE, expected.secret_type));
                }
                if kind == 8 && [2, 3].contains(&method) {
                    // Field padding cannot convey an opaque object's original length.
                    // Never silently return a different value for an ambiguous import.
                    let count = f.engine.store.list("alice").unwrap().len();
                    assert_eq!(
                        reason(&f.call(v, "alice", 41, fields.clone())),
                        if v.0 >= 2 { 7 } else { 6 }
                    );
                    assert_eq!(f.engine.store.list("alice").unwrap().len(), count);
                    continue;
                }
                let joined = identifier(&f.call(v, "alice", 41, fields));
                let result = f.engine.store.get("alice", &joined).unwrap().unwrap();
                assert!(
                    crypto_identity(&result) == identity,
                    "external reconstruction changed material; {}.{} kind {kind} method {method}",
                    v.0,
                    v.1
                );
                assert_eq!(result.secret_type, expected.secret_type);
            }
        }
    }
}
#[test]
fn published_external_gf8_quorums_and_all_extra_shares_are_checked() {
    // OASIS TC-SJ-3-12, retained unchanged in OVH kmip-go at 525ef10d1246.
    let values = [
        "66C46A7754F94DE420C7B1A7FFF5EC56",
        "CF93D1E2A7E593CD5B8D6247F4E5D49C",
        "A855B891F61AD9217240D8EC061E37DA",
        "803DBAD55CDD329FAD19D99AE2C5A415",
    ];
    for v in versions().into_iter().filter(|v| *v >= Version(1, 2)) {
        let mut f = Fixture::new();
        let mut parts = vec![];
        for (index, value) in values.iter().enumerate() {
            let object = Node::structure(
                SPLIT_KEY,
                vec![
                    Node::int(SPLIT_KEY_PARTS, 4),
                    Node::int(KEY_PART_IDENTIFIER, index as i32 + 1),
                    Node::int(SPLIT_KEY_THRESHOLD, 2),
                    Node::enumeration(SPLIT_KEY_METHOD, 4),
                    Node::structure(
                        KEY_BLOCK,
                        vec![
                            Node::enumeration(KEY_FORMAT_TYPE, 1),
                            Node::structure(
                                KEY_VALUE,
                                vec![Node::bytes(KEY_MATERIAL, hex::decode(value).unwrap())],
                            ),
                            Node::enumeration(CRYPTOGRAPHIC_ALGORITHM, 3),
                            Node::int(CRYPTOGRAPHIC_LENGTH, 128),
                        ],
                    ),
                ],
            );
            let attrs = if v.0 >= 3 {
                vec![Node::enumeration(SPLIT_KEY_POLYNOMIAL, 2)]
            } else {
                vec![]
            };
            parts.push(register_object(&mut f, v, 5, object, attrs));
        }
        for a in 0..4 {
            for b in a + 1..4 {
                let joined = identifier(&f.call(
                    v,
                    "alice",
                    41,
                    vec![
                        Node::enumeration(OBJECT_TYPE, 2),
                        id(v, &parts[a]),
                        id(v, &parts[b]),
                    ],
                ));
                assert!(
                    f.engine
                        .store
                        .get("alice", &joined)
                        .unwrap()
                        .unwrap()
                        .material
                        == (1u8..=16).collect::<Vec<_>>()
                );
            }
        }
        let mut join = vec![Node::enumeration(OBJECT_TYPE, 2)];
        join.extend(parts.iter().map(|p| id(v, p)));
        identifier(&f.call(v, "alice", 41, join.clone()));
        let mut damaged = f.engine.store.get("alice", &parts[3]).unwrap().unwrap();
        damaged.material[4] ^= 1;
        f.engine.store.put(&damaged).unwrap();
        let before = serde_json::to_value(f.engine.store.list("alice").unwrap()).unwrap();
        assert_eq!(reason(&f.call(v, "alice", 41, join)), 10);
        assert_eq!(
            serde_json::to_value(f.engine.store.list("alice").unwrap()).unwrap(),
            before
        );
    }
}
#[test]
fn join_enforces_strictest_share_policy_and_legacy_calls_do_not_remove_it() {
    let mut f = Fixture::new();
    let v = Version(2, 1);
    let original = source(&mut f, v);
    let parts = ids(&f.call(v, "alice", 40, create_fields(v, 4, Some(&original))));
    let mut restricted = f.engine.store.get("alice", &parts[1]).unwrap().unwrap();
    restricted
        .attrs
        .retain(|a| ![SENSITIVE, EXTRACTABLE].contains(&a.tag));
    restricted.attrs.extend([
        Node::boolean(SENSITIVE, true),
        Node::boolean(EXTRACTABLE, false),
    ]);
    f.engine.store.put(&restricted).unwrap();
    for version in [Version(1, 2), v] {
        let fields = vec![
            Node::enumeration(OBJECT_TYPE, 2),
            id(version, &parts[0]),
            id(version, &parts[1]),
        ];
        let joined = identifier(&f.call(version, "alice", 41, fields.clone()));
        let object = f.engine.store.get("alice", &joined).unwrap().unwrap();
        assert!(
            object
                .attrs
                .iter()
                .any(|a| a.tag == SENSITIVE && a.flag().unwrap())
        );
        assert!(
            object
                .attrs
                .iter()
                .any(|a| a.tag == EXTRACTABLE && !a.flag().unwrap())
        );
        assert_eq!(object.metadata.always_sensitive, Some(true));
        assert_eq!(object.metadata.never_extractable, Some(true));
        assert!(
            f.call(version, "alice", 10, vec![id(version, &joined)])
                .required(BATCH_ITEM)
                .unwrap()
                .get(RESPONSE_PAYLOAD)
                .is_none()
        );
        if version >= Version(1, 4) {
            let mut weaken = fields;
            weaken.push(container(version, vec![Node::boolean(SENSITIVE, false)]));
            assert_eq!(reason(&f.call(version, "alice", 41, weaken)), 12);
        }
    }
}
#[test]
fn duplicate_factory_containers_are_not_normalized_away() {
    let mut f = Fixture::new();
    let v = Version(2, 1);
    let mut fields = create_fields(v, 4, None);
    fields.push(container(v, vec![]));
    assert_eq!(reason(&f.call(v, "alice", 40, fields)), 7);
    assert!(f.engine.store.list("alice").unwrap().is_empty());
}

fn header_field(request: &mut Node, node: Node) {
    if let Value::Structure(items) = &mut request.value
        && let Value::Structure(fields) = &mut items
            .iter_mut()
            .find(|n| n.tag == REQUEST_HEADER)
            .unwrap()
            .value
    {
        fields.push(node);
    } else {
        panic!("invalid test request");
    }
}
fn snapshot(f: &Fixture) -> serde_json::Value {
    serde_json::to_value(f.engine.store.list("alice").unwrap()).unwrap()
}
#[test]
fn factory_failures_roll_back_inserts_audit_undo_and_response_limits() {
    for v in [Version(1, 2), Version(2, 1), Version(3, 0)] {
        let mut f = Fixture::new();
        let original = source(&mut f, v);
        let before = snapshot(&f);
        let conn = rusqlite::Connection::open(f.dir.path().join("keys.sqlite")).unwrap();
        conn.execute_batch("CREATE TRIGGER reject_second_share BEFORE INSERT ON objects WHEN (SELECT COUNT(*) FROM objects)>1 BEGIN SELECT RAISE(ABORT,'injected second share failure'); END").unwrap();
        assert_eq!(
            reason(&f.call(v, "alice", 40, create_fields(v, 4, Some(&original)))),
            0x100
        );
        conn.execute_batch("DROP TRIGGER reject_second_share")
            .unwrap();
        assert!(snapshot(&f) == before);
        conn.execute_batch("CREATE TRIGGER reject_factory_audit BEFORE INSERT ON audit WHEN NEW.operation=40 BEGIN SELECT RAISE(FAIL,'injected factory audit failure'); END").unwrap();
        assert_eq!(
            reason(&f.call(v, "alice", 40, create_fields(v, 4, Some(&original)))),
            0x100
        );
        conn.execute_batch("DROP TRIGGER reject_factory_audit")
            .unwrap();
        assert!(snapshot(&f) == before);
        let mut limited = request(v, vec![(40, create_fields(v, 4, Some(&original)))]);
        header_field(&mut limited, Node::int(MAXIMUM_RESPONSE_SIZE, 256));
        if let Ok(response) = f.engine.process("alice", &limited) {
            assert_ne!(
                response
                    .required(BATCH_ITEM)
                    .unwrap()
                    .required(RESULT_STATUS)
                    .unwrap()
                    .number()
                    .unwrap(),
                0
            );
        }
        assert!(snapshot(&f) == before);
        let mut undo = request(
            v,
            vec![
                (40, create_fields(v, 4, Some(&original))),
                (10, vec![id(v, "missing")]),
            ],
        );
        header_field(
            &mut undo,
            Node::enumeration(BATCH_ERROR_CONTINUATION_OPTION, 3),
        );
        let response = f.engine.process("alice", &undo).unwrap();
        assert_eq!(
            response
                .get(BATCH_ITEM)
                .unwrap()
                .required(RESULT_STATUS)
                .unwrap()
                .number()
                .unwrap(),
            3
        );
        assert!(snapshot(&f) == before);
        f.restart();
        assert!(snapshot(&f) == before);
        let parts = ids(&f.call(v, "alice", 40, create_fields(v, 4, Some(&original))));
        let before = snapshot(&f);
        conn.execute_batch("CREATE TRIGGER reject_join_audit BEFORE INSERT ON audit WHEN NEW.operation=41 BEGIN SELECT RAISE(FAIL,'injected join audit failure'); END").unwrap();
        assert_eq!(
            reason(&f.call(v, "alice", 41, join_fields(v, 2, &parts, 4))),
            0x100
        );
        conn.execute_batch("DROP TRIGGER reject_join_audit")
            .unwrap();
        assert!(snapshot(&f) == before);
        f.engine.store.verify_audit().unwrap();
    }
}
#[test]
fn mixed_families_duplicate_part_indices_and_corrupt_quorums_are_rejected() {
    let v = Version(2, 1);
    let mut f = Fixture::new();
    let original = source(&mut f, v);
    let a = ids(&f.call(v, "alice", 40, create_fields(v, 4, Some(&original))));
    let b = ids(&f.call(v, "alice", 40, create_fields(v, 4, Some(&original))));
    let before = snapshot(&f);
    assert_eq!(
        reason(&f.call(
            v,
            "alice",
            41,
            vec![
                Node::enumeration(OBJECT_TYPE, 2),
                id(v, &a[0]),
                id(v, &b[1])
            ]
        )),
        7
    );
    assert!(snapshot(&f) == before);
    let mut changed = f.engine.store.get("alice", &a[1]).unwrap().unwrap();
    let saved = changed.clone();
    changed.split.as_mut().unwrap().part = 1;
    f.engine.store.put(&changed).unwrap();
    let before = snapshot(&f);
    assert_eq!(
        reason(&f.call(
            v,
            "alice",
            41,
            vec![
                Node::enumeration(OBJECT_TYPE, 2),
                id(v, &a[0]),
                id(v, &a[1])
            ]
        )),
        10
    );
    assert!(snapshot(&f) == before);
    changed = saved;
    changed.material[0] ^= 1;
    f.engine.store.put(&changed).unwrap();
    let before = snapshot(&f);
    assert_eq!(
        reason(&f.call(
            v,
            "alice",
            41,
            vec![
                Node::enumeration(OBJECT_TYPE, 2),
                id(v, &a[0]),
                id(v, &a[1])
            ]
        )),
        10
    );
    assert!(snapshot(&f) == before);
}
#[test]
fn nested_local_shares_restore_inner_metadata_and_material() {
    for v in [Version(1, 2), Version(2, 1), Version(3, 0)] {
        let mut f = Fixture::new();
        let original = source(&mut f, v);
        let inner = ids(&f.call(v, "alice", 40, create_fields(v, 4, Some(&original))));
        let saved = f.engine.store.get("alice", &inner[0]).unwrap().unwrap();
        for method in 1..=4 {
            let outer = ids(&f.call(v, "alice", 40, create_fields(v, method, Some(&inner[0]))));
            f.restart();
            let restored = identifier(&f.call(v, "alice", 41, join_fields(v, 5, &outer, method)));
            let result = f.engine.store.get("alice", &restored).unwrap().unwrap();
            assert!(result.material == saved.material);
            assert!(
                serde_json::to_value(&result.split).unwrap()
                    == serde_json::to_value(&saved.split).unwrap()
            );
            let result = identifier(&f.call(
                v,
                "alice",
                41,
                vec![
                    Node::enumeration(OBJECT_TYPE, 2),
                    id(v, &restored),
                    id(v, &inner[1]),
                ],
            ));
            assert!(
                f.engine
                    .store
                    .get("alice", &result)
                    .unwrap()
                    .unwrap()
                    .material
                    == (1u8..=16).collect::<Vec<_>>()
            );
        }
    }
}
#[test]
fn generated_rsa_ec_and_threshold_one_share_factories() {
    for v in [Version(1, 2), Version(2, 1), Version(3, 0)] {
        for (algorithm, bits, kind) in [(4, 2048, 4), (6, 256, 4)] {
            let mut f = Fixture::new();
            let mut fields = create_fields(v, 4, None);
            fields.retain(|n| {
                ![ATTRIBUTES, TEMPLATE_ATTRIBUTE, SPLIT_KEY_THRESHOLD].contains(&n.tag)
            });
            fields.push(Node::int(SPLIT_KEY_THRESHOLD, 1));
            let mut attrs = vec![Node::int(CRYPTOGRAPHIC_LENGTH, bits)];
            attrs.push(Node::enumeration(CRYPTOGRAPHIC_ALGORITHM, algorithm));
            if algorithm == 6 {
                attrs.push(Node::structure(
                    CRYPTOGRAPHIC_DOMAIN_PARAMETERS,
                    vec![Node::enumeration(RECOMMENDED_CURVE, 7)],
                ));
            }
            if v.0 >= 3 {
                attrs.push(Node::enumeration(SPLIT_KEY_POLYNOMIAL, 1));
            }
            fields.push(container(v, attrs));
            let parts = ids(&f.call(v, "alice", 40, fields));
            let mut previous = None;
            for part in parts {
                let result = identifier(&f.call(
                    v,
                    "alice",
                    41,
                    vec![Node::enumeration(OBJECT_TYPE, kind), id(v, &part)],
                ));
                let object = f.engine.store.get("alice", &result).unwrap().unwrap();
                assert_eq!(object.bits, bits as u32);
                let identity = crypto_identity(&object);
                if let Some(previous) = previous {
                    assert!(identity == previous);
                }
                previous = Some(identity);
            }
        }
    }
}
#[test]
fn create_split_alias_aggregates_parts_and_versioned_placeholder_names_part_one() {
    for v in [Version(1, 2), Version(1, 3), Version(2, 1), Version(3, 0)] {
        let mut f = Fixture::new();
        let get = if v.0 >= 3 {
            vec![Node::enumeration(UNIQUE_IDENTIFIER, 1)]
        } else {
            vec![]
        };
        let mut items = vec![(40, create_fields(v, 4, None)), (10, get)];
        if v.0 >= 2 {
            items.push((
                41,
                vec![
                    Node::enumeration(OBJECT_TYPE, 2),
                    Node::enumeration(UNIQUE_IDENTIFIER, 7),
                ],
            ));
        }
        let response = f.engine.process("alice", &request(v, items)).unwrap();
        let results = response.all(BATCH_ITEM).collect::<Vec<_>>();
        let first = results[0]
            .required(RESPONSE_PAYLOAD)
            .unwrap()
            .get(UNIQUE_IDENTIFIER)
            .unwrap()
            .identifier_text()
            .unwrap();
        assert_eq!(
            results[1]
                .required(RESULT_STATUS)
                .unwrap()
                .number()
                .unwrap(),
            0,
            "version {}.{} reason {:?} message {:?}",
            v.0,
            v.1,
            results[1].get(RESULT_REASON).and_then(|n| n.number().ok()),
            results[1].get(RESULT_MESSAGE).and_then(|n| n.string().ok())
        );
        assert_eq!(
            results[1]
                .required(RESPONSE_PAYLOAD)
                .unwrap()
                .required(UNIQUE_IDENTIFIER)
                .unwrap()
                .identifier_text()
                .unwrap(),
            first
        );
        if v.0 >= 2 {
            assert_eq!(
                results[2]
                    .required(RESULT_STATUS)
                    .unwrap()
                    .number()
                    .unwrap(),
                0
            );
        }
        // Source omission must generate a new key even with a nonempty placeholder.
        let response = f
            .engine
            .process(
                "alice",
                &request(
                    v,
                    vec![
                        (40, create_fields(v, 4, None)),
                        (40, create_fields(v, 4, None)),
                    ],
                ),
            )
            .unwrap();
        let results = response.all(BATCH_ITEM).collect::<Vec<_>>();
        for result in results {
            assert_eq!(result.required(RESULT_STATUS).unwrap().number().unwrap(), 0);
        }
        assert_eq!(
            f.engine
                .store
                .list("alice")
                .unwrap()
                .iter()
                .filter(|o| o.object_type == 5)
                .count(),
            9
        );
    }
}

#[test]
fn factory_resource_limits_are_item_failures_with_durable_continuation_outcomes() {
    for v in [
        Version(1, 2),
        Version(1, 4),
        Version(2, 0),
        Version(2, 1),
        Version(3, 0),
    ] {
        let mut f = Fixture::new();
        let expected = if v.0 >= 2 { 0x3a } else { 0x100 };
        let mut fields = create_fields(v, 3, None);
        fields.retain(|n| ![SPLIT_KEY_PARTS, SPLIT_KEY_THRESHOLD].contains(&n.tag));
        fields.extend([
            Node::int(SPLIT_KEY_PARTS, 128),
            Node::int(SPLIT_KEY_THRESHOLD, 128),
        ]);
        let mut prime = vec![0xff; 4096];
        prime[0] = 0x7f;
        fields.push(Node {
            tag: PRIME_FIELD_SIZE,
            value: Value::BigInteger(prime),
        });
        assert_eq!(
            reason(&f.call(v, "alice", 40, fields)),
            if v.0 >= 2 { 0x3a } else { 2 }
        );
        assert!(f.engine.store.list("alice").unwrap().is_empty());
        for (count, parts) in [(5, 3), (3, 43)] {
            for continuation in [1, 2, 3] {
                let before = f.engine.store.list("alice").unwrap().len();
                let mut entries: Vec<_> = (0..count)
                    .map(|_| {
                        let mut fields = create_fields(v, 4, None);
                        fields.retain(|n| n.tag != SPLIT_KEY_PARTS);
                        fields.push(Node::int(SPLIT_KEY_PARTS, parts));
                        (40, fields)
                    })
                    .collect();
                entries.push((24, vec![Node::enumeration(QUERY_FUNCTION, 1)]));
                let mut request = request(v, entries);
                header_field(
                    &mut request,
                    Node::enumeration(BATCH_ERROR_CONTINUATION_OPTION, continuation),
                );
                let response = f.engine.process("alice", &request).unwrap();
                let items: Vec<_> = response.all(BATCH_ITEM).collect();
                assert_eq!(items.len(), count + usize::from(continuation == 1));
                for item in &items[..count - 1] {
                    assert_eq!(
                        item.required(RESULT_STATUS).unwrap().number().unwrap(),
                        if continuation == 3 { 3 } else { 0 }
                    );
                }
                assert_eq!(
                    items[count - 1]
                        .required(OPERATION)
                        .unwrap()
                        .number()
                        .unwrap(),
                    40
                );
                assert_eq!(
                    items[count - 1]
                        .required(RESULT_REASON)
                        .unwrap()
                        .number()
                        .unwrap(),
                    expected
                );
                if v.0 < 3 {
                    assert_eq!(
                        items[count - 1]
                            .required(UNIQUE_BATCH_ITEM_ID)
                            .unwrap()
                            .byte_string()
                            .unwrap(),
                        &[(count - 1) as u8]
                    );
                }
                f.restart();
                assert_eq!(
                    f.engine.store.list("alice").unwrap().len(),
                    before
                        + if continuation == 3 {
                            0
                        } else {
                            (count - 1) * parts as usize
                        }
                );
                f.engine.store.verify_audit().unwrap();
                let db = rusqlite::Connection::open(f.dir.path().join("keys.sqlite")).unwrap();
                let statuses: Vec<u32> = db
                    .prepare("SELECT status FROM audit ORDER BY seq DESC LIMIT ?")
                    .unwrap()
                    .query_map([items.len() as i64], |r| r.get(0))
                    .unwrap()
                    .map(Result::unwrap)
                    .collect();
                let expected: Vec<_> = items
                    .iter()
                    .rev()
                    .map(|i| i.required(RESULT_STATUS).unwrap().number().unwrap())
                    .collect();
                assert_eq!(statuses, expected);
            }
        }
    }
}

#[test]
fn transport_response_guard_rejects_factory_success_before_committing() {
    let v = Version(2, 1);
    let mut f = Fixture::new();
    let original = source(&mut f, v);
    for op in [40, 41] {
        let fields = if op == 40 {
            create_fields(v, 4, Some(&original))
        } else {
            let parts = ids(&f.call(v, "alice", 40, create_fields(v, 4, Some(&original))));
            join_fields(v, 2, &parts, 4)
        };
        let before = snapshot(&f);
        let mut rejected = false;
        let result = f
            .engine
            .process_with_grants_checked(
                "alice",
                &request(v, vec![(op, fields)]),
                None,
                &[],
                &mut |node| {
                    if node.tag == RESPONSE_PAYLOAD {
                        rejected = true;
                        return Err(keytend_kmip_server::protocol::Failure::new(
                            2,
                            "injected transport representation failure",
                        ));
                    }
                    Ok(())
                },
            )
            .unwrap();
        assert!(rejected);
        assert_eq!(reason(&result), 2);
        assert!(snapshot(&f) == before);
        f.restart();
        assert!(snapshot(&f) == before);
        f.engine.store.verify_audit().unwrap();
    }
}
#[test]
fn factory_ownership_certificate_policy_and_archival_are_enforced() {
    let v = Version(2, 1);
    let mut f = Fixture::new();
    let original = source(&mut f, v);
    let parts = ids(&f.call(v, "alice", 40, create_fields(v, 4, Some(&original))));
    let grants = [original.clone(), parts[0].clone(), parts[2].clone()]
        .into_iter()
        .map(
            |identifier| keytend_kmip_server::authorization::ObjectGrant {
                owner: "alice".into(),
                user: None,
                device: None,
                identifier,
                operations: vec![10],
            },
        )
        .collect::<Vec<_>>();
    for (op, fields) in [
        (40, create_fields(v, 4, Some(&original))),
        (41, join_fields(v, 2, &parts, 4)),
    ] {
        let before = snapshot(&f);
        let denied = f
            .engine
            .process_with_grants(
                "bob",
                &request(v, vec![(op, fields.clone())]),
                Some(&[10, 40, 41]),
                &grants,
            )
            .unwrap();
        // 2.1 Table 195 Create Split Key lists Item Not Found; Table 246
        // Join Split Key lists Object Not Found.
        assert_eq!(reason(&denied), if op == 40 { 1 } else { 0x37 });
        let denied = f
            .engine
            .process_authorized("alice", &request(v, vec![(op, fields)]), Some(&[10]))
            .unwrap();
        assert_eq!(reason(&denied), 12);
        assert!(snapshot(&f) == before);
    }
    for (op, key, fields) in [
        (40, original.clone(), create_fields(v, 4, Some(&original))),
        (41, parts[0].clone(), join_fields(v, 2, &parts, 4)),
    ] {
        payload(&f.call(v, "alice", 21, vec![id(v, &key)]));
        let before = snapshot(&f);
        assert_eq!(reason(&f.call(v, "alice", op, fields.clone())), 13);
        assert!(snapshot(&f) == before);
        payload(&f.call(v, "alice", 22, vec![id(v, &key)]));
        payload(&f.call(v, "alice", 20, vec![id(v, &key)]));
        let before = snapshot(&f);
        assert_eq!(reason(&f.call(v, "alice", op, fields)), 12);
        assert!(snapshot(&f) == before);
    }
}

#[test]
fn chacha_split_join_all_methods_preserve_exact_key_across_restart() {
    for v in [Version(1, 4), Version(2, 0), Version(2, 1), Version(3, 0)] {
        for algorithm in [28, 30] {
            let mut f = Fixture::new();
            let expected = (0u8..32).collect::<Vec<_>>();
            let key = identifier(&f.call(
                v,
                "alice",
                3,
                vec![
                    Node::enumeration(OBJECT_TYPE, 2),
                    container(v, vec![Node::int(CRYPTOGRAPHIC_USAGE_MASK, 12)]),
                    Node::structure(
                        SYMMETRIC_KEY,
                        vec![Node::structure(
                            KEY_BLOCK,
                            vec![
                                Node::enumeration(KEY_FORMAT_TYPE, 1),
                                Node::enumeration(CRYPTOGRAPHIC_ALGORITHM, algorithm),
                                Node::int(CRYPTOGRAPHIC_LENGTH, 256),
                                Node::structure(
                                    KEY_VALUE,
                                    vec![Node::bytes(KEY_MATERIAL, expected.clone())],
                                ),
                            ],
                        )],
                    ),
                ],
            ));
            for method in 1..=4 {
                let parts = ids(&f.call(v, "alice", 40, create_fields(v, method, Some(&key))));
                assert_eq!(parts.len(), 3);
                f.restart();
                let mut request = vec![Node::enumeration(OBJECT_TYPE, 2), container(v, vec![])];
                request.extend(
                    parts
                        .iter()
                        .take(if method == 1 { 3 } else { 2 })
                        .map(|part| id(v, part)),
                );
                let joined = identifier(&f.call(v, "alice", 41, request));
                f.restart();
                let got = f.call(v, "alice", 10, vec![id(v, &joined)]);
                let block = payload(&got)
                    .required(SYMMETRIC_KEY)
                    .unwrap()
                    .required(KEY_BLOCK)
                    .unwrap();
                assert_eq!(
                    block
                        .required(CRYPTOGRAPHIC_ALGORITHM)
                        .unwrap()
                        .number()
                        .unwrap(),
                    algorithm
                );
                assert_eq!(
                    block
                        .required(CRYPTOGRAPHIC_LENGTH)
                        .unwrap()
                        .number()
                        .unwrap(),
                    256
                );
                assert_eq!(
                    block
                        .required(KEY_VALUE)
                        .unwrap()
                        .required(KEY_MATERIAL)
                        .unwrap()
                        .byte_string()
                        .unwrap(),
                    expected
                );
            }
        }
    }
}

#[test]
fn alternative_names_follow_split_and_join_factory_attributes() {
    for v in versions().into_iter().filter(|v| *v >= Version(1, 2)) {
        let mut f = Fixture::new();
        let original = source(&mut f, v);
        let alias = Node::structure(
            ALTERNATIVE_NAME,
            vec![
                Node::text(ALTERNATIVE_NAME_VALUE, "shared by source, shares and join"),
                Node::enumeration(ALTERNATIVE_NAME_TYPE, 3),
            ],
        );
        let input = if v.0 == 1 {
            Node::structure(
                ATTRIBUTE,
                vec![
                    Node::text(ATTRIBUTE_NAME, "Alternative Name"),
                    Node {
                        tag: ATTRIBUTE_VALUE,
                        value: alias.value.clone(),
                    },
                ],
            )
        } else {
            Node::structure(NEW_ATTRIBUTE, vec![alias.clone()])
        };
        payload(&f.call(v, "alice", 13, vec![id(v, &original), input]));
        let created = f.call(v, "alice", 40, create_fields(v, 1, Some(&original)));
        let parts = ids(&created);
        f.restart();
        let joined = identifier(&f.call(v, "alice", 41, join_fields(v, 2, &parts, 1)));
        for key in parts.iter().chain([&joined, &original]) {
            let object = f.engine.store.get("alice", key).unwrap().unwrap();
            assert!(
                object
                    .attrs
                    .iter()
                    .filter(|a| a.tag == ALTERNATIVE_NAME)
                    .eq([&alias])
            );
        }
        f.engine.store.verify_audit().unwrap();
    }
}

/// Item Not Found in 1.x; Object Not Found (0x37) where the 2.x and draft 3.0
/// error tables list it (see src/protocol/not_found.rs).
fn not_found(v: Version) -> u32 {
    if v.0 >= 2 { 0x37 } else { 1 }
}
