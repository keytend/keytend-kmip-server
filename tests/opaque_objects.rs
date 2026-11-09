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
fn register(f: &mut Fixture, v: Version, kind: u32, data: &[u8]) -> String {
    identifier(&f.call(
        v,
        "alice",
        3,
        vec![
            Node::enumeration(OBJECT_TYPE, 8),
            container(v, vec![]),
            Node::structure(
                OPAQUE_OBJECT,
                vec![
                    Node::enumeration(OPAQUE_DATA_TYPE, kind),
                    Node::bytes(OPAQUE_DATA_VALUE, data.to_vec()),
                ],
            ),
        ],
    ))
}
fn get(f: &mut Fixture, v: Version, key: &str) -> Node {
    payload(&f.call(v, "alice", 10, vec![id(v, key)]))
        .required(OPAQUE_OBJECT)
        .unwrap()
        .clone()
}
fn stored(f: &Fixture, key: &str) -> keytend_kmip_server::store::Object {
    f.engine.store.get("alice", key).unwrap().unwrap()
}
#[test]
fn all_editions_preserve_opaque_extension_types_empty_values_and_versioned_attribute() {
    let mut f = Fixture::new();
    for v in [
        Version(1, 0),
        Version(1, 1),
        Version(1, 2),
        Version(1, 3),
        Version(1, 4),
        Version(2, 0),
        Version(2, 1),
        Version(3, 0),
    ] {
        for typ in [0x80000000, 0x80000001, 0x80012345, 0x8fffffff] {
            for data in [vec![], vec![0, 1, 255], vec![0xaa; 65536]] {
                let key = register(&mut f, v, typ, &data);
                assert_eq!(stored(&f, &key).opaque_type, typ);
                let object = get(&mut f, v, &key);
                assert!(
                    object.required(OPAQUE_DATA_TYPE).unwrap()
                        == &Node::enumeration(OPAQUE_DATA_TYPE, typ)
                );
                assert_eq!(
                    object
                        .required(OPAQUE_DATA_VALUE)
                        .unwrap()
                        .byte_string()
                        .unwrap(),
                    data
                );
                let attrs = f.call(v, "alice", 11, vec![id(v, &key)]);
                if v.0 >= 2 {
                    assert_eq!(
                        payload(&attrs)
                            .required(ATTRIBUTES)
                            .unwrap()
                            .required(OPAQUE_DATA_TYPE)
                            .unwrap()
                            .number()
                            .unwrap(),
                        typ
                    );
                } else {
                    assert!(
                        !payload(&attrs).all(ATTRIBUTE).any(|a| a
                            .required(ATTRIBUTE_NAME)
                            .unwrap()
                            .string()
                            .unwrap()
                            == "Opaque Data Type")
                    );
                }
                f.restart();
                assert!(get(&mut f, v, &key) == object);
            }
        }
    }
}
#[test]
fn malformed_reserved_missing_types_and_nonbytes_fail_without_persistence() {
    let mut f = Fixture::new();
    let v = Version(2, 1);
    for fields in [
        vec![
            Node::enumeration(OPAQUE_DATA_TYPE, 0x7fffffff),
            Node::bytes(OPAQUE_DATA_VALUE, vec![1]),
        ],
        vec![
            Node::enumeration(OPAQUE_DATA_TYPE, 0x90000000),
            Node::bytes(OPAQUE_DATA_VALUE, vec![1]),
        ],
        vec![
            Node::int(OPAQUE_DATA_TYPE, -2147483647),
            Node::bytes(OPAQUE_DATA_VALUE, vec![1]),
        ],
        vec![Node::bytes(OPAQUE_DATA_VALUE, vec![1])],
        vec![
            Node::enumeration(OPAQUE_DATA_TYPE, 0x80000001),
            Node::text(OPAQUE_DATA_VALUE, "data"),
        ],
    ] {
        let r = f.call(
            v,
            "alice",
            3,
            vec![
                Node::enumeration(OBJECT_TYPE, 8),
                container(v, vec![]),
                Node::structure(OPAQUE_OBJECT, fields),
            ],
        );
        assert_ne!(
            r.required(BATCH_ITEM)
                .unwrap()
                .required(RESULT_STATUS)
                .unwrap()
                .number()
                .unwrap(),
            0
        );
        assert!(f.engine.store.list("alice").unwrap().is_empty());
    }
}
#[test]
fn opaque_type_is_intrinsic_immutable_and_locate_matches_exact_type() {
    let mut f = Fixture::new();
    let v = Version(2, 1);
    let a = register(&mut f, v, 0x80000001, b"first");
    let b = register(&mut f, v, 0x80000002, b"second");
    let response = f.call(
        v,
        "alice",
        8,
        vec![Node::structure(
            ATTRIBUTES,
            vec![Node::enumeration(OPAQUE_DATA_TYPE, 0x80000001)],
        )],
    );
    assert_eq!(
        payload(&response)
            .all(UNIQUE_IDENTIFIER)
            .map(|n| n.identifier_text().unwrap())
            .collect::<Vec<_>>(),
        vec![a.as_str()]
    );
    for op in [13, 14, 15, 49] {
        let fields = if op == 15 {
            vec![
                id(v, &a),
                Node::enumeration(ATTRIBUTE_REFERENCE, OPAQUE_DATA_TYPE),
            ]
        } else {
            vec![
                id(v, &a),
                Node::structure(
                    NEW_ATTRIBUTE,
                    vec![Node::enumeration(OPAQUE_DATA_TYPE, 0x80000002)],
                ),
            ]
        };
        assert_eq!(reason(&f.call(v, "alice", op, fields)), 0x22);
        assert_eq!(stored(&f, &a).opaque_type, 0x80000001);
    }
    let bad = f.call(
        v,
        "alice",
        3,
        vec![
            Node::enumeration(OBJECT_TYPE, 8),
            container(v, vec![Node::enumeration(OPAQUE_DATA_TYPE, 0x80000001)]),
            Node::structure(
                OPAQUE_OBJECT,
                vec![
                    Node::enumeration(OPAQUE_DATA_TYPE, 0x80000001),
                    Node::bytes(OPAQUE_DATA_VALUE, b"x".to_vec()),
                ],
            ),
        ],
    );
    assert_eq!(reason(&bad), 0x22);
    assert_eq!(reason(&f.call(v, "bob", 10, vec![id(v, &b)])), not_found(v));
}
#[test]
fn opaque_import_export_live_empty_destroyed_and_mismatched_intrinsic_type() {
    let mut f = Fixture::new();
    let v = Version(2, 1);
    for data in [vec![], b"restored opaque".to_vec()] {
        let key = register(&mut f, v, 0x80001234, &data);
        let exported = payload(&f.call(v, "alice", 43, vec![id(v, &key)]))
            .children()
            .unwrap()
            .to_vec();
        payload(&f.call(v, "alice", 20, vec![id(v, &key)]));
        let mut fields = exported.clone();
        fields.push(Node::boolean(REPLACE_EXISTING, true));
        payload(&f.call(v, "alice", 42, fields));
        assert_eq!(
            get(&mut f, v, &key)
                .required(OPAQUE_DATA_VALUE)
                .unwrap()
                .byte_string()
                .unwrap(),
            data
        );
        let before = serde_json::to_value(stored(&f, &key)).unwrap();
        let mut corrupt = exported.clone();
        corrupt.push(Node::boolean(REPLACE_EXISTING, true));
        let attrs = corrupt.iter_mut().find(|n| n.tag == ATTRIBUTES).unwrap();
        let keytend_kmip_server::ttlv::Value::Structure(attrs) = &mut attrs.value else {
            panic!()
        };
        let digest = attrs.iter_mut().find(|n| n.tag == DIGEST).unwrap();
        let keytend_kmip_server::ttlv::Value::Structure(fields) = &mut digest.value else {
            panic!()
        };
        *fields.iter_mut().find(|n| n.tag == DIGEST_VALUE).unwrap() =
            Node::bytes(DIGEST_VALUE, vec![0; 32]);
        assert_eq!(reason(&f.call(v, "alice", 42, corrupt)), 7);
        assert_eq!(before, serde_json::to_value(stored(&f, &key)).unwrap());
        let mut bad = exported;
        bad.push(Node::boolean(REPLACE_EXISTING, true));
        for node in &mut bad {
            if node.tag == ATTRIBUTES {
                let keytend_kmip_server::ttlv::Value::Structure(attrs) = &mut node.value else {
                    panic!()
                };
                for a in attrs {
                    if a.tag == OPAQUE_DATA_TYPE {
                        *a = Node::enumeration(OPAQUE_DATA_TYPE, 0x80000000);
                    }
                }
            }
        }
        assert_eq!(reason(&f.call(v, "alice", 42, bad)), 7);
        assert_eq!(stored(&f, &key).opaque_type, 0x80001234);
        payload(&f.call(v, "alice", 20, vec![id(v, &key)]));
        let tombstone = f.call(v, "alice", 43, vec![id(v, &key)]);
        let object = payload(&tombstone).required(OPAQUE_OBJECT).unwrap();
        assert_eq!(
            object.required(OPAQUE_DATA_TYPE).unwrap().number().unwrap(),
            0x80001234
        );
        assert!(object.get(OPAQUE_DATA_VALUE).is_none());
        let mut fields = payload(&tombstone).children().unwrap().to_vec();
        fields.push(Node::boolean(REPLACE_EXISTING, true));
        payload(&f.call(v, "alice", 42, fields));
        assert_eq!(stored(&f, &key).opaque_type, 0x80001234);
    }
}
#[test]
fn opaque_split_source_type_survives_join_restart_and_old_record_defaults() {
    let mut f = Fixture::new();
    let v = Version(2, 1);
    let key = register(&mut f, v, 0x80000001, b"opaque to split");
    let parts = f.call(
        v,
        "alice",
        40,
        vec![
            id(v, &key),
            Node::enumeration(OBJECT_TYPE, 5),
            Node::int(SPLIT_KEY_PARTS, 3),
            Node::int(SPLIT_KEY_THRESHOLD, 2),
            Node::enumeration(SPLIT_KEY_METHOD, 4),
            container(v, vec![]),
        ],
    );
    let ids = payload(&parts)
        .all(UNIQUE_IDENTIFIER)
        .map(|n| n.identifier_text().unwrap().to_owned())
        .collect::<Vec<_>>();
    f.restart();
    let joined = identifier(&f.call(
        v,
        "alice",
        41,
        vec![
            Node::enumeration(OBJECT_TYPE, 8),
            id(v, &ids[0]),
            id(v, &ids[2]),
        ],
    ));
    assert_eq!(stored(&f, &joined).opaque_type, 0x80000001);
    assert_eq!(
        get(&mut f, v, &joined)
            .required(OPAQUE_DATA_VALUE)
            .unwrap()
            .byte_string()
            .unwrap(),
        b"opaque to split"
    );
    let object = stored(&f, &joined);
    let mut raw = serde_json::to_value(&object).unwrap();
    raw.as_object_mut().unwrap().remove("opaque_type");
    let old: keytend_kmip_server::store::Object = serde_json::from_value(raw).unwrap();
    assert_eq!(old.opaque_type, 0x80000000);
}
#[test]
fn opaque_register_rollback_and_backup_preserve_intrinsic_type() {
    let mut f = Fixture::new();
    let v = Version(2, 1);
    let fields = vec![
        Node::enumeration(OBJECT_TYPE, 8),
        container(v, vec![]),
        Node::structure(
            OPAQUE_OBJECT,
            vec![
                Node::enumeration(OPAQUE_DATA_TYPE, 0x8ffffffe),
                Node::bytes(OPAQUE_DATA_VALUE, vec![]),
            ],
        ),
    ];
    let db = rusqlite::Connection::open(f.dir.path().join("keys.sqlite")).unwrap();
    db.execute_batch("CREATE TRIGGER fail_opaque_audit BEFORE INSERT ON audit WHEN NEW.operation=3 BEGIN SELECT RAISE(FAIL,'opaque audit test failure'); END").unwrap();
    let failed = f.call(v, "alice", 3, fields.clone());
    assert_ne!(
        failed
            .required(BATCH_ITEM)
            .unwrap()
            .required(RESULT_STATUS)
            .unwrap()
            .number()
            .unwrap(),
        0
    );
    assert!(f.engine.store.list("alice").unwrap().is_empty());
    db.execute_batch("DROP TRIGGER fail_opaque_audit").unwrap();
    let req = request(v, vec![(3, fields.clone())]);
    let failed = f
        .engine
        .process_with_grants_checked("alice", &req, None, &[], &mut |n| {
            if n.tag == RESPONSE_PAYLOAD {
                Err(keytend_kmip_server::protocol::Failure::new(
                    2,
                    "opaque response test failure",
                ))
            } else {
                Ok(())
            }
        })
        .unwrap();
    assert_eq!(reason(&failed), 2);
    assert!(f.engine.store.list("alice").unwrap().is_empty());
    let key = identifier(&f.call(v, "alice", 3, fields));
    let backup = f.dir.path().join("opaque-backup.sqlite");
    f.engine.store.backup(&backup).unwrap();
    let restored = f.dir.path().join("opaque-restored.sqlite");
    std::fs::copy(backup, &restored).unwrap();
    f.engine = Engine::new(
        Store::open(&restored, &f.dir.path().join("master")).unwrap(),
        true,
    );
    let object = get(&mut f, v, &key);
    assert_eq!(
        object.required(OPAQUE_DATA_TYPE).unwrap().number().unwrap(),
        0x8ffffffe
    );
    assert!(
        object
            .required(OPAQUE_DATA_VALUE)
            .unwrap()
            .byte_string()
            .unwrap()
            .is_empty()
    );
    f.engine.store.verify_audit().unwrap();
}

/// Item Not Found in 1.x; Object Not Found (0x37) where the 2.x and draft 3.0
/// error tables list it (see src/protocol/not_found.rs).
fn not_found(v: Version) -> u32 {
    if v.0 >= 2 { 0x37 } else { 1 }
}
