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

fn masks(tag: u32, values: &[i32]) -> Node {
    Node::structure(
        tag,
        values
            .iter()
            .map(|n| Node::int(PROTECTION_STORAGE_MASK, *n))
            .collect(),
    )
}
fn create(v: Version) -> Vec<Node> {
    vec![
        Node::enumeration(OBJECT_TYPE, 2),
        container(
            v,
            vec![
                Node::enumeration(CRYPTOGRAPHIC_ALGORITHM, 3),
                Node::int(CRYPTOGRAPHIC_LENGTH, 128),
                Node::int(CRYPTOGRAPHIC_USAGE_MASK, 12),
            ],
        ),
    ]
}
fn metadata(f: &mut Fixture, v: Version, key: &str) -> u32 {
    let response = f.call(
        v,
        "alice",
        11,
        vec![
            id(v, key),
            Node::enumeration(ATTRIBUTE_REFERENCE, PROTECTION_STORAGE_MASK),
        ],
    );
    payload(&response)
        .required(ATTRIBUTES)
        .unwrap()
        .required(PROTECTION_STORAGE_MASK)
        .unwrap()
        .number()
        .unwrap()
}
fn snapshot(f: &Fixture) -> serde_json::Value {
    serde_json::to_value(f.engine.store.list("alice").unwrap()).unwrap()
}
#[test]
fn select_whole_alternatives_store_readonly_metadata_and_hide_it_from_legacy() {
    for v in [Version(2, 0), Version(2, 1), Version(3, 0)] {
        let mut f = Fixture::new();
        let query = f.call(v, "alice", 24, vec![Node::enumeration(QUERY_FUNCTION, 14)]);
        assert!(
            payload(&query)
                .required(PROTECTION_STORAGE_MASKS)
                .unwrap()
                .children()
                .unwrap()
                == [Node::int(PROTECTION_STORAGE_MASK, 1)]
        );
        for (values, expected) in [
            (None, 1),
            (Some(vec![1]), 1),
            (Some(vec![2, 3, 1]), 1),
            (Some(vec![0, 1]), 0),
            (Some(vec![0]), 0),
        ] {
            let mut fields = create(v);
            if let Some(values) = values {
                fields.push(masks(PROTECTION_STORAGE_MASKS, &values));
            }
            let key = identifier(&f.call(v, "alice", 1, fields));
            assert_eq!(metadata(&mut f, v, &key), expected);
            assert_eq!(
                f.engine
                    .store
                    .get("alice", &key)
                    .unwrap()
                    .unwrap()
                    .protection_mask,
                expected
            );
            f.restart();
            assert_eq!(metadata(&mut f, v, &key), expected);
            let old = f.call(Version(1, 4), "alice", 11, vec![id(Version(1, 4), &key)]);
            assert!(
                payload(&old).all(ATTRIBUTE).all(|a| a
                    .required(ATTRIBUTE_NAME)
                    .unwrap()
                    .string()
                    .unwrap()
                    != "Protection Storage Mask")
            );
            for op in [13, 14, 15, 49] {
                let mut fields = vec![id(v, &key)];
                if op == 15 {
                    fields.push(Node::enumeration(
                        ATTRIBUTE_REFERENCE,
                        PROTECTION_STORAGE_MASK,
                    ));
                } else {
                    fields.push(Node::structure(
                        NEW_ATTRIBUTE,
                        vec![Node::int(PROTECTION_STORAGE_MASK, 2)],
                    ));
                }
                let before = snapshot(&f);
                assert_eq!(reason(&f.call(v, "alice", op, fields)), 0x22);
                assert!(snapshot(&f) == before);
            }
        }
        for selected in [0, 1] {
            let located = f.call(
                v,
                "alice",
                8,
                vec![container(
                    v,
                    vec![Node::int(PROTECTION_STORAGE_MASK, selected)],
                )],
            );
            let located = payload(&located)
                .all(UNIQUE_IDENTIFIER)
                .map(|n| n.identifier_text().unwrap().to_owned())
                .collect::<Vec<_>>();
            assert!(!located.is_empty());
            for key in located {
                assert_eq!(metadata(&mut f, v, &key), selected as u32);
            }
        }
    }
}
#[test]
fn malformed_and_unavailable_mask_selections_are_atomic_and_versioned() {
    for v in [Version(2, 0), Version(2, 1), Version(3, 0)] {
        let mut f = Fixture::new();
        for values in [vec![], vec![2], vec![3], vec![128, 4096], vec![-1]] {
            let mut fields = create(v);
            fields.push(masks(PROTECTION_STORAGE_MASKS, &values));
            assert_eq!(reason(&f.call(v, "alice", 1, fields)), 0x44);
            assert!(f.engine.store.list("alice").unwrap().is_empty());
        }
        let invalid = [
            Node::int(PROTECTION_STORAGE_MASKS, 1),
            Node::structure(
                PROTECTION_STORAGE_MASKS,
                vec![Node::enumeration(PROTECTION_STORAGE_MASK, 1)],
            ),
            Node::structure(
                PROTECTION_STORAGE_MASKS,
                vec![
                    Node::int(PROTECTION_STORAGE_MASK, 1),
                    Node::text(DATA, "invalid after an acceptable choice"),
                ],
            ),
        ];
        for node in invalid {
            let mut fields = create(v);
            fields.push(node);
            assert_eq!(reason(&f.call(v, "alice", 1, fields)), 7);
        }
        let mut fields = create(v);
        fields.extend([
            masks(PROTECTION_STORAGE_MASKS, &[1]),
            masks(PROTECTION_STORAGE_MASKS, &[0]),
        ]);
        assert_eq!(reason(&f.call(v, "alice", 1, fields)), 7);
        let mut fields = create(v);
        fields.push(masks(PROTECTION_STORAGE_MASKS, &[1; 65]));
        let many = identifier(&f.call(v, "alice", 1, fields));
        assert_eq!(metadata(&mut f, v, &many), 1);
        // No extra arbitrary alternative-count limit; frame/codec limits bound input.
        payload(&f.call(v, "alice", 20, vec![id(v, &many)]));
        let mut fields = create(v);
        fields[1] = container(v, vec![Node::int(PROTECTION_STORAGE_MASK, 1)]);
        assert_eq!(reason(&f.call(v, "alice", 1, fields)), 0x22);
        assert_eq!(f.engine.store.list("alice").unwrap().len(), 1);
    }
    for v in [
        Version(1, 0),
        Version(1, 1),
        Version(1, 2),
        Version(1, 3),
        Version(1, 4),
    ] {
        let mut f = Fixture::new();
        let mut fields = create(v);
        fields.push(masks(PROTECTION_STORAGE_MASKS, &[1]));
        assert_eq!(reason(&f.call(v, "alice", 1, fields)), 7);
        let mut fields = create(v);
        fields[1] = container(v, vec![Node::int(PROTECTION_STORAGE_MASK, 1)]);
        assert_eq!(reason(&f.call(v, "alice", 1, fields)), 7);
        let key = identifier(&f.call(v, "alice", 1, create(v)));
        assert_eq!(metadata(&mut f, Version(2, 1), &key), 1);
    }
}
#[test]
fn pair_masks_apply_common_and_role_constraints_with_specific_failure_reasons() {
    for v in [Version(2, 0), Version(2, 1), Version(3, 0)] {
        let mut f = Fixture::new();
        for (tag, expected) in [
            (COMMON_PROTECTION_STORAGE_MASKS, 0x48),
            (PRIVATE_PROTECTION_STORAGE_MASKS, 0x48),
            (PUBLIC_PROTECTION_STORAGE_MASKS, 0x49),
        ] {
            assert_eq!(
                reason(&f.call(v, "alice", 2, vec![masks(tag, &[2])])),
                expected
            );
            assert!(f.engine.store.list("alice").unwrap().is_empty());
        }
        let response = f.call(
            v,
            "alice",
            2,
            vec![
                masks(COMMON_PROTECTION_STORAGE_MASKS, &[0]),
                masks(PRIVATE_PROTECTION_STORAGE_MASKS, &[2, 1]),
                masks(PUBLIC_PROTECTION_STORAGE_MASKS, &[0]),
            ],
        );
        let private = payload(&response)
            .required(PRIVATE_KEY_UNIQUE_IDENTIFIER)
            .unwrap()
            .identifier_text()
            .unwrap()
            .to_owned();
        let public = payload(&response)
            .required(PUBLIC_KEY_UNIQUE_IDENTIFIER)
            .unwrap()
            .identifier_text()
            .unwrap()
            .to_owned();
        assert_eq!(metadata(&mut f, v, &private), 1);
        assert_eq!(metadata(&mut f, v, &public), 0);
        let before = snapshot(&f);
        let private_tag = if v.0 >= 3 {
            UNIQUE_IDENTIFIER
        } else {
            PRIVATE_KEY_UNIQUE_IDENTIFIER
        };
        let mut key = id(v, &private);
        key.tag = private_tag;
        assert_eq!(
            reason(&f.call(
                v,
                "alice",
                29,
                vec![key.clone(), masks(PUBLIC_PROTECTION_STORAGE_MASKS, &[2])]
            )),
            0x49
        );
        assert!(snapshot(&f) == before);
        let replaced = f.call(
            v,
            "alice",
            29,
            vec![
                key,
                masks(PRIVATE_PROTECTION_STORAGE_MASKS, &[0]),
                masks(PUBLIC_PROTECTION_STORAGE_MASKS, &[1]),
            ],
        );
        let new_private = payload(&replaced)
            .required(PRIVATE_KEY_UNIQUE_IDENTIFIER)
            .unwrap()
            .identifier_text()
            .unwrap()
            .to_owned();
        let new_public = payload(&replaced)
            .required(PUBLIC_KEY_UNIQUE_IDENTIFIER)
            .unwrap()
            .identifier_text()
            .unwrap()
            .to_owned();
        assert_eq!(metadata(&mut f, v, &new_private), 0);
        assert_eq!(metadata(&mut f, v, &new_public), 1);
        assert_eq!(metadata(&mut f, v, &private), 1);
        assert_eq!(metadata(&mut f, v, &public), 0);
        f.restart();
        assert_eq!(metadata(&mut f, v, &new_private), 0);
        assert_eq!(metadata(&mut f, v, &new_public), 1);
    }
}

fn registration(v: Version) -> Vec<Node> {
    vec![
        Node::enumeration(OBJECT_TYPE, 2),
        container(v, vec![Node::int(CRYPTOGRAPHIC_USAGE_MASK, 524)]),
        Node::structure(
            SYMMETRIC_KEY,
            vec![Node::structure(
                KEY_BLOCK,
                vec![
                    Node::enumeration(KEY_FORMAT_TYPE, 1),
                    Node::structure(KEY_VALUE, vec![Node::bytes(KEY_MATERIAL, vec![7; 16])]),
                    Node::enumeration(CRYPTOGRAPHIC_ALGORITHM, 3),
                    Node::int(CRYPTOGRAPHIC_LENGTH, 128),
                ],
            )],
        ),
    ]
}
fn split_fields(v: Version, source: &str, selection: i32) -> Vec<Node> {
    let attrs = if v.0 >= 3 {
        vec![Node::enumeration(SPLIT_KEY_POLYNOMIAL, 2)]
    } else {
        vec![]
    };
    vec![
        Node::enumeration(OBJECT_TYPE, 5),
        id(v, source),
        Node::int(SPLIT_KEY_PARTS, 3),
        Node::int(SPLIT_KEY_THRESHOLD, 2),
        Node::enumeration(SPLIT_KEY_METHOD, 4),
        container(v, attrs),
        masks(PROTECTION_STORAGE_MASKS, &[selection]),
    ]
}
fn export_fields(f: &mut Fixture, v: Version, key: &str) -> Vec<Node> {
    payload(&f.call(v, "alice", 43, vec![id(v, key)]))
        .children()
        .unwrap()
        .to_vec()
}
fn import_mask(fields: &mut [Node], value: i32) {
    let attrs = fields.iter_mut().find(|n| n.tag == ATTRIBUTES).unwrap();
    if let keytend_kmip_server::ttlv::Value::Structure(values) = &mut attrs.value {
        values.retain(|n| n.tag != PROTECTION_STORAGE_MASK);
        values.push(Node::int(PROTECTION_STORAGE_MASK, value));
    }
}
#[test]
fn register_split_join_and_rekey_select_storage_for_each_new_object() {
    for v in [Version(2, 0), Version(2, 1), Version(3, 0)] {
        let mut f = Fixture::new();
        let mut fields = registration(v);
        fields.push(masks(PROTECTION_STORAGE_MASKS, &[0]));
        let source = identifier(&f.call(v, "alice", 3, fields));
        assert_eq!(metadata(&mut f, v, &source), 0);
        let before = snapshot(&f);
        assert_eq!(
            reason(&f.call(v, "alice", 40, split_fields(v, &source, 2))),
            0x44
        );
        assert!(snapshot(&f) == before);
        let response = f.call(v, "alice", 40, split_fields(v, &source, 1));
        let parts = payload(&response)
            .all(UNIQUE_IDENTIFIER)
            .map(|n| n.identifier_text().unwrap().to_owned())
            .collect::<Vec<_>>();
        assert_eq!(parts.len(), 3);
        for part in &parts {
            assert_eq!(metadata(&mut f, v, part), 1);
        }
        let mut join = vec![
            Node::enumeration(OBJECT_TYPE, 2),
            id(v, &parts[0]),
            id(v, &parts[2]),
            masks(PROTECTION_STORAGE_MASKS, &[2]),
        ];
        let before = snapshot(&f);
        assert_eq!(reason(&f.call(v, "alice", 41, join.clone())), 0x44);
        assert!(snapshot(&f) == before);
        *join.last_mut().unwrap() = masks(PROTECTION_STORAGE_MASKS, &[0]);
        let joined = identifier(&f.call(v, "alice", 41, join));
        assert_eq!(metadata(&mut f, v, &joined), 0);
        assert!(
            f.engine
                .store
                .get("alice", &joined)
                .unwrap()
                .unwrap()
                .material
                == vec![7; 16]
        );
        let before = snapshot(&f);
        assert_eq!(
            reason(&f.call(
                v,
                "alice",
                4,
                vec![id(v, &source), masks(PROTECTION_STORAGE_MASKS, &[2])]
            )),
            0x44
        );
        assert!(snapshot(&f) == before);
        let replacement = identifier(&f.call(
            v,
            "alice",
            4,
            vec![id(v, &source), masks(PROTECTION_STORAGE_MASKS, &[1])],
        ));
        assert_eq!(metadata(&mut f, v, &replacement), 1);
        assert_eq!(metadata(&mut f, v, &source), 0);
        f.restart();
        assert_eq!(metadata(&mut f, v, &joined), 0);
        assert_eq!(metadata(&mut f, v, &replacement), 1);
        for part in &parts {
            assert_eq!(metadata(&mut f, v, part), 1);
        }
    }
}
#[test]
fn import_checks_storage_even_for_destroyed_objects_and_preserves_restore_values() {
    for v in [Version(2, 0), Version(2, 1), Version(3, 0)] {
        let mut origin = Fixture::new();
        let mut fields = registration(v);
        fields.push(masks(PROTECTION_STORAGE_MASKS, &[0]));
        let key = identifier(&origin.call(v, "alice", 3, fields));
        let exported = export_fields(&mut origin, v, &key);
        for destroyed in [false, true] {
            let fields = if destroyed {
                payload(&origin.call(v, "alice", 20, vec![id(v, &key)]));
                export_fields(&mut origin, v, &key)
            } else {
                exported.clone()
            };
            let mut target = Fixture::new();
            let mut invalid = fields.clone();
            import_mask(&mut invalid, 2);
            assert_eq!(reason(&target.call(v, "alice", 42, invalid)), 0x44);
            assert!(target.engine.store.list("alice").unwrap().is_empty());
            let imported = identifier(&target.call(v, "alice", 42, fields.clone()));
            assert_eq!(metadata(&mut target, v, &imported), 0);
            target.restart();
            assert_eq!(metadata(&mut target, v, &imported), 0);
            let mut incompatible = fields.clone();
            incompatible.push(Node::boolean(REPLACE_EXISTING, true));
            incompatible.push(masks(PROTECTION_STORAGE_MASKS, &[1]));
            let before = snapshot(&target);
            assert_eq!(reason(&target.call(v, "alice", 42, incompatible)), 0x44);
            assert!(snapshot(&target) == before);
            let mut replace = fields.clone();
            replace.push(Node::boolean(REPLACE_EXISTING, true));
            replace.push(masks(PROTECTION_STORAGE_MASKS, &[1, 0]));
            identifier(&target.call(v, "alice", 42, replace));
            assert_eq!(metadata(&mut target, v, &imported), 0);
            let before = snapshot(&target);
            let mut replace = fields.clone();
            replace.push(Node::boolean(REPLACE_EXISTING, true));
            replace.push(masks(PROTECTION_STORAGE_MASKS, &[2]));
            assert_eq!(reason(&target.call(v, "alice", 42, replace)), 0x44);
            assert!(snapshot(&target) == before);
        }
    }
}
#[test]
fn derive_storage_failures_do_not_consume_source_limits_or_create_history() {
    let v = Version(2, 1);
    let mut f = Fixture::new();
    let mut fields = registration(v);
    fields[1] = container(
        v,
        vec![
            Node::int(CRYPTOGRAPHIC_USAGE_MASK, 512),
            Node::structure(
                USAGE_LIMITS,
                vec![
                    Node::long(USAGE_LIMITS_TOTAL, 1),
                    Node::enumeration(USAGE_LIMITS_UNIT, 2),
                ],
            ),
        ],
    );
    fields[2] = Node::structure(
        SYMMETRIC_KEY,
        vec![Node::structure(
            KEY_BLOCK,
            vec![
                Node::enumeration(KEY_FORMAT_TYPE, 1),
                Node::structure(KEY_VALUE, vec![Node::bytes(KEY_MATERIAL, vec![7; 16])]),
                Node::enumeration(CRYPTOGRAPHIC_ALGORITHM, 9),
                Node::int(CRYPTOGRAPHIC_LENGTH, 128),
            ],
        )],
    );
    let source = identifier(&f.call(v, "alice", 3, fields));
    payload(&f.call(v, "alice", 18, vec![id(v, &source)]));
    let mut derive = vec![
        Node::enumeration(OBJECT_TYPE, 2),
        id(v, &source),
        Node::enumeration(DERIVATION_METHOD, 3),
        Node::structure(
            DERIVATION_PARAMETERS,
            vec![
                Node::structure(
                    CRYPTOGRAPHIC_PARAMETERS,
                    vec![Node::enumeration(HASHING_ALGORITHM, 6)],
                ),
                Node::bytes(DERIVATION_DATA, b"storage".to_vec()),
            ],
        ),
        container(
            v,
            vec![
                Node::enumeration(CRYPTOGRAPHIC_ALGORITHM, 3),
                Node::int(CRYPTOGRAPHIC_LENGTH, 128),
            ],
        ),
        masks(PROTECTION_STORAGE_MASKS, &[2]),
    ];
    let before = snapshot(&f);
    assert_eq!(reason(&f.call(v, "alice", 5, derive.clone())), 8);
    assert!(snapshot(&f) == before);
    *derive.last_mut().unwrap() = masks(PROTECTION_STORAGE_MASKS, &[0]);
    let derived = identifier(&f.call(v, "alice", 5, derive));
    assert_eq!(metadata(&mut f, v, &derived), 0);
    let object = f.engine.store.get("alice", &source).unwrap().unwrap();
    assert!(matches!(
        object
            .attrs
            .iter()
            .find(|a| a.tag == USAGE_LIMITS)
            .unwrap()
            .required(USAGE_LIMITS_COUNT)
            .unwrap()
            .value,
        keytend_kmip_server::ttlv::Value::LongInteger(0)
    ));
}

fn header_field(node: &mut Node, field: Node) {
    if let keytend_kmip_server::ttlv::Value::Structure(items) = &mut node.value
        && let keytend_kmip_server::ttlv::Value::Structure(fields) = &mut items[0].value
    {
        fields.push(field);
    } else {
        panic!("invalid fixture header");
    }
}
#[test]
fn late_failures_undo_and_backup_restore_preserve_selected_storage() {
    let v = Version(2, 1);
    let mut f = Fixture::new();
    let conn = rusqlite::Connection::open(f.dir.path().join("keys.sqlite")).unwrap();
    conn.execute_batch("CREATE TRIGGER reject_protection_audit BEFORE INSERT ON audit WHEN NEW.operation=1 BEGIN SELECT RAISE(FAIL,'injected protection audit failure'); END").unwrap();
    let mut fields = create(v);
    fields.push(masks(PROTECTION_STORAGE_MASKS, &[0]));
    assert_eq!(reason(&f.call(v, "alice", 1, fields.clone())), 0x100);
    assert!(f.engine.store.list("alice").unwrap().is_empty());
    conn.execute_batch("DROP TRIGGER reject_protection_audit")
        .unwrap();
    let mut undo = request(v, vec![(1, fields.clone()), (10, vec![id(v, "missing")])]);
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
    assert!(f.engine.store.list("alice").unwrap().is_empty());
    let response = f
        .engine
        .process_with_grants_checked(
            "alice",
            &request(v, vec![(1, fields.clone())]),
            None,
            &[],
            &mut |n| {
                if n.tag == RESPONSE_PAYLOAD {
                    Err(keytend_kmip_server::protocol::Failure::new(
                        2,
                        "injected wire encoding failure",
                    ))
                } else {
                    Ok(())
                }
            },
        )
        .unwrap();
    assert_eq!(reason(&response), 2);
    assert!(f.engine.store.list("alice").unwrap().is_empty());
    let key = identifier(&f.call(v, "alice", 1, fields));
    assert_eq!(metadata(&mut f, v, &key), 0);
    let backup = f.dir.path().join("backup.sqlite");
    f.engine.store.backup(&backup).unwrap();
    let restored = f.dir.path().join("restored.sqlite");
    std::fs::copy(backup, &restored).unwrap();
    f.engine = Engine::new(
        Store::open(&restored, &f.dir.path().join("master")).unwrap(),
        true,
    );
    assert_eq!(metadata(&mut f, v, &key), 0);
    f.engine.store.verify_audit().unwrap();
}
#[test]
fn old_encrypted_record_shape_defaults_to_software_without_changing_other_fields() {
    let v = Version(2, 1);
    let mut f = Fixture::new();
    let key = identifier(&f.call(v, "alice", 1, create(v)));
    let object = f.engine.store.get("alice", &key).unwrap().unwrap();
    let mut raw = serde_json::to_value(&object).unwrap();
    raw.as_object_mut().unwrap().remove("protection_mask");
    let restored: keytend_kmip_server::store::Object = serde_json::from_value(raw).unwrap();
    assert_eq!(restored.protection_mask, 1);
    assert!(restored.material == object.material);
    assert_eq!(restored.id, object.id);
    assert!(restored.attrs == object.attrs);
}

#[test]
fn wrapped_import_preserves_authenticated_mask_and_internal_validation_cannot_reset_it() {
    let v = Version(2, 1);
    let mut source = Fixture::new();
    let cp = Node::structure(
        CRYPTOGRAPHIC_PARAMETERS,
        vec![Node::enumeration(BLOCK_CIPHER_MODE, 12)],
    );
    let mut fields = registration(v);
    fields[1] = container(v, vec![Node::int(CRYPTOGRAPHIC_USAGE_MASK, 48), cp.clone()]);
    let kek = identifier(&source.call(v, "alice", 3, fields));
    payload(&source.call(v, "alice", 18, vec![id(v, &kek)]));
    let kek_export = export_fields(&mut source, v, &kek);
    let mut fields = registration(v);
    fields.push(masks(PROTECTION_STORAGE_MASKS, &[0]));
    let key = identifier(&source.call(v, "alice", 3, fields));
    let spec = Node::structure(
        KEY_WRAPPING_SPECIFICATION,
        vec![
            Node::enumeration(WRAPPING_METHOD, 1),
            Node::structure(ENCRYPTION_KEY_INFORMATION, vec![id(v, &kek), cp]),
            Node::enumeration(ENCODING_OPTION, 2),
            Node::text(ATTRIBUTE_NAME, "Protection Storage Mask"),
        ],
    );
    let response = source.call(v, "alice", 43, vec![id(v, &key), spec]);
    let exported = payload(&response).children().unwrap().to_vec();
    let mut target = Fixture::new();
    identifier(&target.call(v, "alice", 42, kek_export));
    let mut deferred = exported;
    deferred.push(Node::enumeration(KEY_WRAP_TYPE, 2));
    let mut invalid = deferred.clone();
    invalid.push(masks(PROTECTION_STORAGE_MASKS, &[1]));
    let before = snapshot(&target);
    assert_eq!(reason(&target.call(v, "alice", 42, invalid)), 0x44);
    assert!(snapshot(&target) == before);
    deferred.push(masks(PROTECTION_STORAGE_MASKS, &[1, 0]));
    let imported = identifier(&target.call(v, "alice", 42, deferred));
    assert_eq!(metadata(&mut target, v, &imported), 0);
    target.restart();
    payload(&target.call(
        v,
        "alice",
        10,
        vec![id(v, &imported), Node::enumeration(KEY_WRAP_TYPE, 2)],
    ));
    let got = target.call(v, "alice", 10, vec![id(v, &imported)]);
    assert!(
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
            .unwrap()
            == [7; 16]
    );
    assert_eq!(metadata(&mut target, v, &imported), 0);
    target.restart();
    assert_eq!(metadata(&mut target, v, &imported), 0);
}
