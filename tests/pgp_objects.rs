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

fn versions() -> Vec<Version> {
    Version::supported(true)
        .into_iter()
        .filter(|v| *v >= Version(1, 2))
        .collect()
}
fn material(name: &str) -> Vec<u8> {
    let data: serde_json::Value =
        serde_json::from_str(include_str!("fixtures/openpgp.json")).unwrap();
    data[name].as_str().unwrap().as_bytes().to_vec()
}
fn object(version: u32, format: u32, bytes: &[u8]) -> Node {
    Node::structure(
        PGP_KEY,
        vec![
            Node::int(PGP_KEY_VERSION, version as i32),
            Node::structure(
                KEY_BLOCK,
                vec![
                    Node::enumeration(KEY_FORMAT_TYPE, format),
                    Node::structure(KEY_VALUE, vec![Node::bytes(KEY_MATERIAL, bytes.to_vec())]),
                    Node::enumeration(CRYPTOGRAPHIC_ALGORITHM, 4),
                    Node::int(CRYPTOGRAPHIC_LENGTH, 2048),
                ],
            ),
        ],
    )
}
fn register(f: &mut Fixture, v: Version, obj: Node, mut attrs: Vec<Node>) -> Node {
    if !attrs.iter().any(|a| a.tag == CRYPTOGRAPHIC_USAGE_MASK) {
        attrs.push(Node::int(CRYPTOGRAPHIC_USAGE_MASK, 0));
    }
    if !attrs.iter().any(|a| a.tag == DIGITAL_SIGNATURE_ALGORITHM) {
        attrs.push(Node::enumeration(DIGITAL_SIGNATURE_ALGORITHM, 7));
    }
    f.call(
        v,
        "alice",
        3,
        vec![Node::enumeration(OBJECT_TYPE, 9), container(v, attrs), obj],
    )
}
fn get(f: &mut Fixture, v: Version, key: &str, format: u32) -> Node {
    payload(&f.call(
        v,
        "alice",
        10,
        vec![id(v, key), Node::enumeration(KEY_FORMAT_TYPE, format)],
    ))
    .required(PGP_KEY)
    .unwrap()
    .clone()
}
fn clear_bytes(obj: &Node) -> &[u8] {
    obj.required(KEY_BLOCK)
        .unwrap()
        .required(KEY_VALUE)
        .unwrap()
        .required(KEY_MATERIAL)
        .unwrap()
        .byte_string()
        .unwrap()
}
fn assert_pgp(obj: &Node, version: u32, format: u32, bytes: &[u8]) {
    assert!(obj.required(PGP_KEY_VERSION).unwrap().value == Value::Integer(version as i32));
    let block = obj.required(KEY_BLOCK).unwrap();
    assert!(block.required(KEY_FORMAT_TYPE).unwrap().value == Value::Enumeration(format));
    assert_eq!(
        block
            .required(CRYPTOGRAPHIC_ALGORITHM)
            .unwrap()
            .number()
            .unwrap(),
        4
    );
    assert_eq!(
        block
            .required(CRYPTOGRAPHIC_LENGTH)
            .unwrap()
            .number()
            .unwrap(),
        2048
    );
    assert_eq!(clear_bytes(obj), bytes);
}
#[test]
fn real_public_private_and_v3_containers_survive_format_conversion_and_restart() {
    let mut f = Fixture::new();
    for v in versions() {
        for (name, pgp) in [("v3_public", 3), ("v4_public", 4), ("v4_private", 4)] {
            let bytes = material(name);
            for format in [1, 2] {
                let key = identifier(&register(&mut f, v, object(pgp, format, &bytes), vec![]));
                for requested in [1, 2] {
                    assert_pgp(&get(&mut f, v, &key, requested), pgp, requested, &bytes);
                }
                let saved = f.engine.store.get("alice", &key).unwrap().unwrap();
                assert_eq!(saved.pgp_version, pgp);
                assert_eq!(saved.bits, 2048);
                let digest = saved
                    .attrs
                    .iter()
                    .find(|a| {
                        a.tag == DIGEST
                            && a.required(KEY_FORMAT_TYPE).unwrap().number().unwrap() == 1
                    })
                    .unwrap();
                assert_eq!(
                    digest.required(KEY_FORMAT_TYPE).unwrap().number().unwrap(),
                    1
                );
                assert_eq!(
                    digest
                        .required(DIGEST_VALUE)
                        .unwrap()
                        .byte_string()
                        .unwrap(),
                    openssl::sha::sha256(&bytes)
                );
                f.restart();
                assert_pgp(&get(&mut f, v, &key, format), pgp, format, &bytes);
                assert_eq!(
                    reason(&f.call(v, "bob", 10, vec![id(v, &key)])),
                    not_found(v)
                );
            }
        }
    }
    f.engine.store.verify_audit().unwrap();
}
#[test]
fn availability_and_required_field_types_are_versioned() {
    let mut f = Fixture::new();
    let bytes = material("v4_public");
    let key = identifier(&register(
        &mut f,
        Version(2, 1),
        object(4, 1, &bytes),
        vec![],
    ));
    for v in Version::supported(true) {
        let query = f.call(v, "alice", 24, vec![Node::enumeration(QUERY_FUNCTION, 2)]);
        let offered = payload(&query)
            .all(OBJECT_TYPE)
            .any(|n| n.number().unwrap() == 9);
        assert_eq!(offered, v >= Version(1, 2));
        if v < Version(1, 2) {
            assert_eq!(
                reason(&register(&mut f, v, object(4, 1, &bytes), vec![])),
                8
            );
            for op in [10, 11] {
                assert_eq!(reason(&f.call(v, "alice", op, vec![id(v, &key)])), 8);
            }
            continue;
        }
        for (bad, expected) in [
            (Some(Node::enumeration(PGP_KEY_VERSION, 4)), 7),
            (Some(Node::int(PGP_KEY_VERSION, 5)), 8),
            (Some(Node::int(PGP_KEY_VERSION, -1)), 8),
            (None, 7),
        ] {
            let mut obj = object(4, 1, &bytes);
            let Value::Structure(fields) = &mut obj.value else {
                unreachable!()
            };
            fields.retain(|n| n.tag != PGP_KEY_VERSION);
            if let Some(bad) = bad {
                fields.insert(0, bad);
            }
            assert_eq!(reason(&register(&mut f, v, obj, vec![])), expected);
        }
        let mut obj = object(4, 1, &bytes);
        let Value::Structure(fields) = &mut obj.value else {
            unreachable!()
        };
        fields.push(Node::int(PGP_KEY_VERSION, 3));
        // A field given twice is Invalid Message in 1.x (1.4 Table 327).
        assert_eq!(
            reason(&register(&mut f, v, obj, vec![])),
            if v.0 == 1 { 4 } else { 7 }
        );
        assert_eq!(
            reason(&register(&mut f, v, object(4, 3, &bytes), vec![])),
            0x10
        );
        assert_eq!(
            reason(&register(
                &mut f,
                v,
                object(4, 1, &bytes),
                vec![
                    Node::enumeration(CRYPTOGRAPHIC_ALGORITHM, 4),
                    Node::int(CRYPTOGRAPHIC_LENGTH, 1024)
                ]
            )),
            7
        );
    }
}
fn export(f: &mut Fixture, v: Version, key: &str, extra: Vec<Node>) -> Vec<Node> {
    let mut fields = vec![id(v, key)];
    fields.extend(extra);
    payload(&f.call(v, "alice", 43, fields))
        .children()
        .unwrap()
        .to_vec()
}
fn restore(f: &mut Fixture, v: Version, mut fields: Vec<Node>) -> Node {
    fields.push(Node::boolean(REPLACE_EXISTING, true));
    f.call(v, "alice", 42, fields)
}
#[test]
fn live_and_destroyed_export_import_preserve_version_and_digest() {
    let mut f = Fixture::new();
    for v in versions().into_iter().filter(|v| *v >= Version(1, 4)) {
        for (name, pgp) in [("v3_public", 3), ("v4_private", 4)] {
            let bytes = material(name);
            let key = identifier(&register(&mut f, v, object(pgp, 2, &bytes), vec![]));
            let live = export(&mut f, v, &key, vec![]);
            payload(&f.call(v, "alice", 20, vec![id(v, &key)]));
            let destroyed = export(&mut f, v, &key, vec![]);
            let tombstone = destroyed.iter().find(|n| n.tag == PGP_KEY).unwrap();
            assert_eq!(
                tombstone
                    .required(PGP_KEY_VERSION)
                    .unwrap()
                    .number()
                    .unwrap(),
                pgp
            );
            assert!(
                tombstone
                    .required(KEY_BLOCK)
                    .unwrap()
                    .get(KEY_VALUE)
                    .is_none()
            );
            payload(&restore(&mut f, v, live.clone()));
            assert_pgp(&get(&mut f, v, &key, 1), pgp, 1, &bytes);
            let mut invalid = live.clone();
            let obj = invalid.iter_mut().find(|n| n.tag == PGP_KEY).unwrap();
            let Value::Structure(fields) = &mut obj.value else {
                unreachable!()
            };
            fields.retain(|n| n.tag != PGP_KEY_VERSION);
            assert_eq!(reason(&restore(&mut f, v, invalid)), 7);
            assert_pgp(&get(&mut f, v, &key, 2), pgp, 2, &bytes);
            payload(&restore(&mut f, v, destroyed));
            // Get of a destroyed object: Object Destroyed from 2.0.
            assert_eq!(
                reason(&f.call(v, "alice", 10, vec![id(v, &key)])),
                if v.0 >= 2 { 0x36 } else { 11 }
            );
            f.restart();
            assert_eq!(
                f.engine
                    .store
                    .get("alice", &key)
                    .unwrap()
                    .unwrap()
                    .pgp_version,
                pgp
            );
        }
    }
}
fn kek(f: &mut Fixture, v: Version) -> String {
    let mut obj = object(4, 1, &[0x72; 32]);
    obj.tag = SYMMETRIC_KEY;
    let Value::Structure(fields) = &mut obj.value else {
        unreachable!()
    };
    fields.retain(|n| n.tag != PGP_KEY_VERSION);
    let block = fields.iter_mut().find(|n| n.tag == KEY_BLOCK).unwrap();
    let Value::Structure(fields) = &mut block.value else {
        unreachable!()
    };
    for node in fields {
        if node.tag == CRYPTOGRAPHIC_ALGORITHM {
            *node = Node::enumeration(CRYPTOGRAPHIC_ALGORITHM, 3);
        }
        if node.tag == CRYPTOGRAPHIC_LENGTH {
            *node = Node::int(CRYPTOGRAPHIC_LENGTH, 256);
        }
    }
    let key = identifier(&f.call(
        v,
        "alice",
        3,
        vec![
            Node::enumeration(OBJECT_TYPE, 2),
            container(
                v,
                vec![
                    Node::int(CRYPTOGRAPHIC_USAGE_MASK, 48),
                    Node::structure(
                        CRYPTOGRAPHIC_PARAMETERS,
                        vec![Node::enumeration(BLOCK_CIPHER_MODE, 12)],
                    ),
                ],
            ),
            obj,
        ],
    ));
    payload(&f.call(v, "alice", 18, vec![id(v, &key)]));
    key
}
fn wrapping(v: Version, key: &str, encoding: u32) -> Node {
    Node::structure(
        KEY_WRAPPING_SPECIFICATION,
        vec![
            Node::enumeration(WRAPPING_METHOD, 1),
            Node::structure(ENCRYPTION_KEY_INFORMATION, vec![id(v, key)]),
            Node::enumeration(ENCODING_OPTION, encoding),
        ],
    )
}
#[test]
fn kwp_wrapped_register_and_import_materialize_exact_pgp_container() {
    let mut f = Fixture::new();
    for v in versions() {
        let wrapping_key = kek(&mut f, v);
        for pgp in [3, 4] {
            let bytes = material(if pgp == 3 { "v3_public" } else { "v4_private" });
            let key = identifier(&register(&mut f, v, object(pgp, 2, &bytes), vec![]));
            for encoding in [1, 2] {
                let response = f.call(
                    v,
                    "alice",
                    10,
                    vec![id(v, &key), wrapping(v, &wrapping_key, encoding)],
                );
                let wrapped = payload(&response).required(PGP_KEY).unwrap().clone();
                assert_eq!(
                    wrapped.required(PGP_KEY_VERSION).unwrap().number().unwrap(),
                    pgp
                );
                assert!(matches!(
                    wrapped
                        .required(KEY_BLOCK)
                        .unwrap()
                        .required(KEY_VALUE)
                        .unwrap()
                        .value,
                    Value::ByteString(_)
                ));
                let imported = identifier(&register(&mut f, v, wrapped, vec![]));
                assert_pgp(&get(&mut f, v, &imported, 1), pgp, 1, &bytes);
                f.restart();
                assert_pgp(&get(&mut f, v, &imported, 2), pgp, 2, &bytes);
                if v >= Version(1, 4) {
                    let mut fields =
                        export(&mut f, v, &key, vec![wrapping(v, &wrapping_key, encoding)]);
                    fields.push(Node::enumeration(KEY_WRAP_TYPE, 2));
                    payload(&restore(&mut f, v, fields));
                    assert!(
                        f.engine
                            .store
                            .get("alice", &key)
                            .unwrap()
                            .unwrap()
                            .wrapped
                            .is_some()
                    );
                    f.restart();
                    assert_pgp(&get(&mut f, v, &key, 1), pgp, 1, &bytes);
                }
            }
        }
    }
}
fn split(f: &mut Fixture, v: Version, key: &str, method: u32) -> Vec<String> {
    let attrs = if v.0 >= 3 && [2, 4].contains(&method) {
        vec![Node::enumeration(SPLIT_KEY_POLYNOMIAL, 2)]
    } else {
        vec![]
    };
    payload(&f.call(
        v,
        "alice",
        40,
        vec![
            Node::enumeration(OBJECT_TYPE, 5),
            id(v, key),
            Node::int(SPLIT_KEY_PARTS, 3),
            Node::int(SPLIT_KEY_THRESHOLD, if method == 1 { 3 } else { 2 }),
            Node::enumeration(SPLIT_KEY_METHOD, method),
            container(v, attrs),
        ],
    ))
    .all(UNIQUE_IDENTIFIER)
    .map(|n| n.identifier_text().unwrap().to_owned())
    .collect()
}
fn join(f: &mut Fixture, v: Version, parts: &[String]) -> Node {
    let mut fields = vec![
        Node::enumeration(OBJECT_TYPE, 9),
        container(
            v,
            vec![
                Node::int(CRYPTOGRAPHIC_USAGE_MASK, 0),
                Node::enumeration(DIGITAL_SIGNATURE_ALGORITHM, 7),
            ],
        ),
    ];
    fields.extend(parts.iter().rev().map(|part| id(v, part)));
    f.call(v, "alice", 41, fields)
}
fn copy_parts(f: &mut Fixture, v: Version, parts: &[String]) -> Vec<String> {
    parts
        .iter()
        .map(|part| {
            let response = f.call(v, "alice", 10, vec![id(v, part)]);
            let obj = payload(&response).required(SPLIT_KEY).unwrap().clone();
            let original = f.engine.store.get("alice", part).unwrap().unwrap();
            let attrs = if v.0 >= 3 {
                original
                    .split
                    .as_ref()
                    .unwrap()
                    .polynomial
                    .map(|n| vec![Node::enumeration(SPLIT_KEY_POLYNOMIAL, n)])
                    .unwrap_or_default()
            } else {
                vec![]
            };
            let key = identifier(&f.call(
                v,
                "alice",
                3,
                vec![Node::enumeration(OBJECT_TYPE, 5), container(v, attrs), obj],
            ));
            assert!(
                f.engine
                    .store
                    .get("alice", &key)
                    .unwrap()
                    .unwrap()
                    .split
                    .as_ref()
                    .unwrap()
                    .source
                    .is_none()
            );
            key
        })
        .collect()
}
#[test]
fn local_and_external_split_reconstruction_preserve_v3_v4_and_blob_bytes() {
    let mut f = Fixture::new();
    for v in versions() {
        for (name, pgp) in [("v3_public", 3), ("v4_public", 4)] {
            let bytes = material(name);
            for method in 1..=4 {
                let key = identifier(&register(&mut f, v, object(pgp, 1, &bytes), vec![]));
                let parts = split(&mut f, v, &key, method);
                f.restart();
                let joined = identifier(&join(&mut f, v, &parts));
                assert_pgp(&get(&mut f, v, &joined, 1), pgp, 1, &bytes);
                let copied = copy_parts(&mut f, v, &parts);
                let joined = identifier(&join(&mut f, v, &copied));
                assert_pgp(&get(&mut f, v, &joined, 1), pgp, 1, &bytes);
            }
        }
    }
}
#[test]
fn opaque_treatment_does_not_invent_external_reconstruction_metadata() {
    let mut f = Fixture::new();
    let v = Version(2, 1);
    // PGP-aware clients own content processing. A local roundtrip preserves the
    // declared version even when this server cannot inspect the opaque content.
    let bytes = b"client-owned opaque content";
    let key = identifier(&register(&mut f, v, object(3, 2, bytes), vec![]));
    let parts = split(&mut f, v, &key, 4);
    let joined = identifier(&join(&mut f, v, &parts));
    assert_pgp(&get(&mut f, v, &joined, 2), 3, 2, bytes);
    let copied = copy_parts(&mut f, v, &parts);
    assert_eq!(reason(&join(&mut f, v, &copied)), 7);
}

#[test]
fn protected_transfer_rejects_tampering_and_respects_extraction_and_archive_policy() {
    let mut f = Fixture::new();
    let v = Version(2, 1);
    let bytes = material("v4_private");
    let wrapping_key = kek(&mut f, v);
    let key = identifier(&register(&mut f, v, object(4, 1, &bytes), vec![]));
    let response = f.call(
        v,
        "alice",
        10,
        vec![id(v, &key), wrapping(v, &wrapping_key, 2)],
    );
    let mut damaged = payload(&response).required(PGP_KEY).unwrap().clone();
    let Value::Structure(fields) = &mut damaged.value else {
        unreachable!()
    };
    let block = fields.iter_mut().find(|n| n.tag == KEY_BLOCK).unwrap();
    let Value::Structure(fields) = &mut block.value else {
        unreachable!()
    };
    let value = fields.iter_mut().find(|n| n.tag == KEY_VALUE).unwrap();
    let Value::ByteString(data) = &mut value.value else {
        unreachable!()
    };
    data[0] ^= 0x80;
    let before = f.engine.store.list("alice").unwrap().len();
    assert_eq!(reason(&register(&mut f, v, damaged, vec![])), 10);
    assert_eq!(f.engine.store.list("alice").unwrap().len(), before);
    let sensitive = identifier(&register(
        &mut f,
        v,
        object(4, 1, &bytes),
        vec![Node::boolean(SENSITIVE, true)],
    ));
    assert_eq!(
        reason(&f.call(v, "alice", 10, vec![id(v, &sensitive)])),
        0x16
    );
    payload(&f.call(
        v,
        "alice",
        10,
        vec![id(v, &sensitive), wrapping(v, &wrapping_key, 2)],
    ));
    let nonextractable = identifier(&register(
        &mut f,
        v,
        object(4, 1, &bytes),
        vec![Node::boolean(EXTRACTABLE, false)],
    ));
    assert_eq!(
        reason(&f.call(
            v,
            "alice",
            10,
            vec![id(v, &nonextractable), wrapping(v, &wrapping_key, 2)]
        )),
        0x17
    );
    payload(&f.call(v, "alice", 21, vec![id(v, &key)]));
    assert_eq!(reason(&f.call(v, "alice", 10, vec![id(v, &key)])), 13);
    payload(&f.call(v, "alice", 22, vec![id(v, &key)]));
    assert_pgp(&get(&mut f, v, &key, 1), 4, 1, &bytes);
    f.engine.store.verify_audit().unwrap();
}

#[test]
fn failed_commit_leaves_no_object_and_clean_backup_retains_container_and_local_shares() {
    let mut f = Fixture::new();
    let v = Version(2, 1);
    let bytes = material("v3_public");
    let db = rusqlite::Connection::open(f.dir.path().join("keys.sqlite")).unwrap();
    db.execute_batch("CREATE TRIGGER fail_pgp_audit BEFORE INSERT ON audit WHEN NEW.operation=3 BEGIN SELECT RAISE(FAIL,'PGP audit test failure'); END").unwrap();
    let response = register(&mut f, v, object(3, 2, &bytes), vec![]);
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
    assert!(f.engine.store.list("alice").unwrap().is_empty());
    db.execute_batch("DROP TRIGGER fail_pgp_audit").unwrap();
    let req = request(
        v,
        vec![(
            3,
            vec![
                Node::enumeration(OBJECT_TYPE, 9),
                container(
                    v,
                    vec![
                        Node::int(CRYPTOGRAPHIC_USAGE_MASK, 0),
                        Node::enumeration(DIGITAL_SIGNATURE_ALGORITHM, 7),
                    ],
                ),
                object(3, 2, &bytes),
            ],
        )],
    );
    let response = f
        .engine
        .process_with_grants_checked("alice", &req, None, &[], &mut |n| {
            if n.tag == RESPONSE_PAYLOAD {
                Err(keytend_kmip_server::protocol::Failure::new(
                    2,
                    "PGP response test failure",
                ))
            } else {
                Ok(())
            }
        })
        .unwrap();
    assert_eq!(reason(&response), 2);
    assert!(f.engine.store.list("alice").unwrap().is_empty());
    let key = identifier(&register(&mut f, v, object(3, 2, &bytes), vec![]));
    let parts = split(&mut f, v, &key, 4);
    let backup = f.dir.path().join("backup.sqlite");
    f.engine.store.backup(&backup).unwrap();
    let raw = std::fs::read(&backup).unwrap();
    assert!(!raw.windows(bytes.len()).any(|w| w == bytes));
    let directory = f.dir.path().join("clean");
    std::fs::create_dir(&directory).unwrap();
    let restored = directory.join("keys.sqlite");
    std::fs::copy(backup, &restored).unwrap();
    f.engine = Engine::new(
        Store::open(&restored, &f.dir.path().join("master")).unwrap(),
        true,
    );
    assert_pgp(&get(&mut f, v, &key, 1), 3, 1, &bytes);
    let joined = identifier(&join(&mut f, v, &parts));
    assert_pgp(&get(&mut f, v, &joined, 2), 3, 2, &bytes);
    f.engine.store.verify_audit().unwrap();
}

fn signature_values(f: &mut Fixture, v: Version, key: &str) -> Vec<u32> {
    let selector = if v.0 == 1 {
        Node::text(ATTRIBUTE_NAME, "Digital Signature Algorithm")
    } else {
        Node::enumeration(ATTRIBUTE_REFERENCE, DIGITAL_SIGNATURE_ALGORITHM)
    };
    let response = f.call(v, "alice", 11, vec![id(v, key), selector]);
    let p = payload(&response);
    if v.0 == 1 {
        p.all(ATTRIBUTE)
            .enumerate()
            .map(|(index, a)| {
                assert_eq!(
                    a.required(ATTRIBUTE_INDEX).unwrap().number().unwrap(),
                    index as u32
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
fn declared() -> Vec<Node> {
    vec![
        Node::int(CRYPTOGRAPHIC_USAGE_MASK, 0),
        Node::enumeration(DIGITAL_SIGNATURE_ALGORITHM, 7),
    ]
}
fn raw_register(f: &mut Fixture, v: Version, obj: Node, attrs: Vec<Node>) -> Node {
    f.call(
        v,
        "alice",
        3,
        vec![Node::enumeration(OBJECT_TYPE, 9), container(v, attrs), obj],
    )
}
#[test]
fn mandatory_metadata_omissions_types_and_pairing_fail_before_insert() {
    let mut f = Fixture::new();
    let bytes = material("v4_public");
    for v in versions() {
        for removed in [CRYPTOGRAPHIC_ALGORITHM, CRYPTOGRAPHIC_LENGTH] {
            let mut obj = object(4, 1, &bytes);
            let Value::Structure(fields) = &mut obj.value else {
                unreachable!()
            };
            let block = fields.iter_mut().find(|a| a.tag == KEY_BLOCK).unwrap();
            let Value::Structure(fields) = &mut block.value else {
                unreachable!()
            };
            fields.retain(|a| a.tag != removed);
            assert_eq!(
                reason(&raw_register(&mut f, v, obj, declared())),
                if v.0 >= 2 { 7 } else { 6 }
            );
        }
        for removed in [CRYPTOGRAPHIC_USAGE_MASK, DIGITAL_SIGNATURE_ALGORITHM] {
            let mut attrs = declared();
            attrs.retain(|a| a.tag != removed);
            assert_eq!(
                reason(&raw_register(&mut f, v, object(4, 1, &bytes), attrs)),
                if v.0 >= 2 { 7 } else { 6 }
            );
        }
        for one in [
            Node::enumeration(CRYPTOGRAPHIC_ALGORITHM, 4),
            Node::int(CRYPTOGRAPHIC_LENGTH, 2048),
        ] {
            let mut attrs = declared();
            attrs.push(one);
            assert_eq!(
                reason(&raw_register(&mut f, v, object(4, 1, &bytes), attrs)),
                if v.0 >= 2 { 7 } else { 6 }
            );
        }
        let cases = vec![
            vec![
                Node::int(CRYPTOGRAPHIC_ALGORITHM, 4),
                Node::int(CRYPTOGRAPHIC_LENGTH, 2048),
            ],
            vec![
                Node::enumeration(CRYPTOGRAPHIC_ALGORITHM, 4),
                Node::enumeration(CRYPTOGRAPHIC_LENGTH, 2048),
            ],
            vec![Node::enumeration(CRYPTOGRAPHIC_USAGE_MASK, 0)],
            vec![Node::int(DIGITAL_SIGNATURE_ALGORITHM, 7)],
            vec![Node::enumeration(DIGITAL_SIGNATURE_ALGORITHM, 0)],
            vec![Node::enumeration(DIGITAL_SIGNATURE_ALGORITHM, 20)],
        ];
        for values in cases {
            let mut attrs = declared();
            attrs.retain(|a| !values.iter().any(|value| value.tag == a.tag));
            attrs.extend(values);
            assert_eq!(
                reason(&raw_register(&mut f, v, object(4, 1, &bytes), attrs)),
                7
            );
        }
    }
    assert!(f.engine.store.list("alice").unwrap().is_empty());
}
#[test]
fn signature_metadata_is_versioned_readonly_indexed_and_searchable() {
    let mut f = Fixture::new();
    let bytes = material("v4_public");
    for v in versions() {
        let key = identifier(&register(
            &mut f,
            v,
            object(4, 1, &bytes),
            vec![
                Node::enumeration(DIGITAL_SIGNATURE_ALGORITHM, 7),
                Node::enumeration(DIGITAL_SIGNATURE_ALGORITHM, 16),
            ],
        ));
        assert_eq!(signature_values(&mut f, v, &key), vec![7, 16]);
        for op in [13, 14, 15, 49]
            .into_iter()
            .filter(|op| v.0 >= 2 || *op != 49)
        {
            let fields = if v.0 == 1 {
                if op == 15 {
                    vec![
                        id(v, &key),
                        Node::text(ATTRIBUTE_NAME, "Digital Signature Algorithm"),
                        Node::int(ATTRIBUTE_INDEX, 1),
                    ]
                } else {
                    vec![
                        id(v, &key),
                        Node::structure(
                            ATTRIBUTE,
                            vec![
                                Node::text(ATTRIBUTE_NAME, "Digital Signature Algorithm"),
                                Node::enumeration(ATTRIBUTE_VALUE, 5),
                            ],
                        ),
                    ]
                }
            } else if op == 15 {
                vec![
                    id(v, &key),
                    Node::enumeration(ATTRIBUTE_REFERENCE, DIGITAL_SIGNATURE_ALGORITHM),
                ]
            } else {
                vec![
                    id(v, &key),
                    Node::structure(
                        NEW_ATTRIBUTE,
                        vec![Node::enumeration(DIGITAL_SIGNATURE_ALGORITHM, 5)],
                    ),
                ]
            };
            assert_eq!(
                reason(&f.call(v, "alice", op, fields)),
                if v.0 >= 2 { 0x22 } else { 12 }
            );
        }
        let filter = if v.0 == 1 {
            vec![Node::structure(
                ATTRIBUTE,
                vec![
                    Node::text(ATTRIBUTE_NAME, "Digital Signature Algorithm"),
                    Node::enumeration(ATTRIBUTE_VALUE, 16),
                ],
            )]
        } else {
            vec![Node::structure(
                ATTRIBUTES,
                vec![Node::enumeration(DIGITAL_SIGNATURE_ALGORITHM, 16)],
            )]
        };
        let response = f.call(v, "alice", 8, filter);
        assert!(
            payload(&response)
                .all(UNIQUE_IDENTIFIER)
                .any(|a| a.identifier_text().unwrap() == key)
        );
        let future = raw_register(
            &mut f,
            v,
            object(4, 1, &bytes),
            vec![
                Node::int(CRYPTOGRAPHIC_USAGE_MASK, 0),
                Node::enumeration(DIGITAL_SIGNATURE_ALGORITHM, 17),
            ],
        );
        if v < Version(1, 4) {
            assert_eq!(reason(&future), 7);
        } else {
            let future_id = identifier(&future);
            assert_eq!(
                reason(&f.call(
                    Version(1, 2),
                    "alice",
                    11,
                    vec![
                        id(Version(1, 2), &future_id),
                        Node::text(ATTRIBUTE_NAME, "Digital Signature Algorithm")
                    ]
                )),
                8
            );
            payload(&f.call(
                Version(1, 2),
                "alice",
                11,
                vec![
                    id(Version(1, 2), &future_id),
                    Node::text(ATTRIBUTE_NAME, "Cryptographic Length"),
                ],
            ));
        }
        let extension = identifier(&register(
            &mut f,
            v,
            object(4, 1, &bytes),
            vec![Node::enumeration(DIGITAL_SIGNATURE_ALGORITHM, 0x8fffffff)],
        ));
        f.restart();
        assert_eq!(signature_values(&mut f, v, &extension), vec![0x8fffffff]);
        assert_eq!(signature_values(&mut f, v, &key), vec![7, 16]);
    }
}
#[test]
fn local_share_signature_provenance_is_not_an_attribute_of_the_shares() {
    let mut f = Fixture::new();
    let bytes = material("v4_public");
    for v in versions() {
        let key = identifier(&register(
            &mut f,
            v,
            object(4, 1, &bytes),
            vec![
                Node::enumeration(DIGITAL_SIGNATURE_ALGORITHM, 7),
                Node::enumeration(DIGITAL_SIGNATURE_ALGORITHM, 16),
            ],
        ));
        let parts = split(&mut f, v, &key, 4);
        for part in &parts {
            let saved = f.engine.store.get("alice", part).unwrap().unwrap();
            assert!(
                !saved
                    .attrs
                    .iter()
                    .any(|a| a.tag == DIGITAL_SIGNATURE_ALGORITHM)
            );
            assert_eq!(
                saved
                    .split
                    .as_ref()
                    .unwrap()
                    .source
                    .as_ref()
                    .unwrap()
                    .pgp_signatures,
                vec![7, 16]
            );
        }
        payload(&f.call(v, "alice", 20, vec![id(v, &key)]));
        f.restart();
        let joined = identifier(&f.call(
            v,
            "alice",
            41,
            vec![
                Node::enumeration(OBJECT_TYPE, 9),
                id(v, &parts[2]),
                id(v, &parts[0]),
            ],
        ));
        assert_eq!(signature_values(&mut f, v, &joined), vec![7, 16]);
        let copied = copy_parts(&mut f, v, &parts);
        let missing = f.call(
            v,
            "alice",
            41,
            vec![
                Node::enumeration(OBJECT_TYPE, 9),
                id(v, &copied[0]),
                id(v, &copied[2]),
            ],
        );
        assert_eq!(reason(&missing), if v.0 >= 2 { 7 } else { 6 });
        let external = identifier(&f.call(
            v,
            "alice",
            41,
            vec![
                Node::enumeration(OBJECT_TYPE, 9),
                id(v, &copied[0]),
                id(v, &copied[2]),
                container(
                    v,
                    vec![
                        Node::enumeration(DIGITAL_SIGNATURE_ALGORITHM, 7),
                        Node::enumeration(DIGITAL_SIGNATURE_ALGORITHM, 16),
                    ],
                ),
            ],
        ));
        assert_eq!(signature_values(&mut f, v, &external), vec![7, 16]);
    }
}

/// Item Not Found in 1.x; Object Not Found (0x37) where the 2.x and draft 3.0
/// error tables list it (see src/protocol/not_found.rs).
fn not_found(v: Version) -> u32 {
    if v.0 >= 2 { 0x37 } else { 1 }
}
