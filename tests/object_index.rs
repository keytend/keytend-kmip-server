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

//! The in-memory object index and the decrypted-object cache: Locate by Name
//! or Link and the Name uniqueness check give the same answers as a full
//! scan, across writes, rollbacks, restarts and versions.
use keytend_kmip_server::{
    protocol::{Engine, Version},
    store::{CacheLimits, Store},
    tags::*,
    ttlv::Node,
};
use std::path::Path;

const V21: Version = Version(2, 1);

fn store(dir: &Path, cache: bool) -> Store {
    let master = dir.join("master");
    if !master.exists() {
        std::fs::write(&master, [7; 32]).unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&master, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    let store = Store::open(&dir.join("store"), &master).unwrap();
    if cache {
        store.set_object_cache(CacheLimits {
            max_bytes: 1 << 20,
            idle: std::time::Duration::from_secs(600),
        });
    }
    store
}
fn message(v: Version, undo: bool, items: Vec<(u32, Vec<Node>)>) -> Node {
    let mut header = vec![v.node()];
    if v.0 < 3 {
        header.push(Node::int(BATCH_COUNT, items.len() as i32));
    }
    if undo {
        header.push(Node::enumeration(BATCH_ERROR_CONTINUATION_OPTION, 3));
    }
    let many = items.len() > 1;
    let mut fields = vec![Node::structure(REQUEST_HEADER, header)];
    for (i, (op, p)) in items.into_iter().enumerate() {
        let mut item = vec![Node::enumeration(OPERATION, op)];
        if many {
            item.push(Node::bytes(UNIQUE_BATCH_ITEM_ID, vec![i as u8]));
        }
        item.push(Node::structure(REQUEST_PAYLOAD, p));
        fields.push(Node::structure(BATCH_ITEM, item));
    }
    Node::structure(REQUEST_MESSAGE, fields)
}
fn ok(e: &mut Engine, v: Version, op: u32, p: Vec<Node>) -> Node {
    let r = e
        .process("alice", &message(v, false, vec![(op, p)]))
        .unwrap();
    let item = r.get(BATCH_ITEM).unwrap().clone();
    assert_eq!(
        item.required(RESULT_STATUS).unwrap().number().unwrap(),
        0,
        "{}",
        serde_json::to_string(&item).unwrap()
    );
    item.required(RESPONSE_PAYLOAD).unwrap().clone()
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
fn create(e: &mut Engine, value: &str) -> String {
    let p = ok(
        e,
        V21,
        1,
        vec![
            Node::enumeration(OBJECT_TYPE, 2),
            Node::structure(
                ATTRIBUTES,
                vec![
                    Node::enumeration(CRYPTOGRAPHIC_ALGORITHM, 3),
                    Node::int(CRYPTOGRAPHIC_LENGTH, 128),
                    Node::int(CRYPTOGRAPHIC_USAGE_MASK, 12),
                    name(V21, value),
                ],
            ),
        ],
    );
    p.required(UNIQUE_IDENTIFIER)
        .unwrap()
        .identifier_text()
        .unwrap()
        .to_owned()
}
fn located(e: &mut Engine, v: Version, filter: Node) -> Vec<String> {
    located_with(e, v, filter, vec![])
}
fn located_with(e: &mut Engine, v: Version, filter: Node, extra: Vec<Node>) -> Vec<String> {
    let mut payload = extra;
    if v.0 == 1 {
        // 1.x: Attribute structures named by text.
        let name = tag_name(filter.tag).unwrap();
        let mut value = filter;
        value.tag = ATTRIBUTE_VALUE;
        payload.push(Node::structure(
            ATTRIBUTE,
            vec![Node::text(ATTRIBUTE_NAME, name), value],
        ));
    } else {
        payload.push(Node::structure(ATTRIBUTES, vec![filter]));
    }
    let p = ok(e, v, 8, payload);
    let mut ids: Vec<String> = p
        .all(UNIQUE_IDENTIFIER)
        .map(|n| n.identifier_text().unwrap().to_owned())
        .collect();
    ids.sort();
    ids
}
fn uid(v: Version, id: &str) -> Node {
    if v.0 >= 3 {
        Node::identifier(UNIQUE_IDENTIFIER, id)
    } else {
        Node::text(UNIQUE_IDENTIFIER, id)
    }
}

#[test]
fn locate_by_name_follows_writes_rollbacks_and_restarts() {
    for cache in [false, true] {
        let dir = tempfile::tempdir().unwrap();
        let mut e = Engine::new(store(dir.path(), cache), false);
        let a = create(&mut e, "alpha");
        let b = create(&mut e, "beta");
        assert_eq!(located(&mut e, V21, name(V21, "alpha")), vec![a.clone()]);
        // Rename: the old Name no longer finds it.
        ok(
            &mut e,
            V21,
            15,
            vec![
                uid(V21, &a),
                Node::structure(CURRENT_ATTRIBUTE, vec![name(V21, "alpha")]),
            ],
        );
        ok(
            &mut e,
            V21,
            13,
            vec![
                uid(V21, &a),
                Node::structure(NEW_ATTRIBUTE, vec![name(V21, "gamma")]),
            ],
        );
        assert!(located(&mut e, V21, name(V21, "alpha")).is_empty());
        assert_eq!(located(&mut e, V21, name(V21, "gamma")), vec![a.clone()]);
        // An Undo batch: the added Name is rolled back with the failed item.
        let r = e
            .process(
                "alice",
                &message(
                    V21,
                    true,
                    vec![
                        (
                            13,
                            vec![
                                uid(V21, &b),
                                Node::structure(NEW_ATTRIBUTE, vec![name(V21, "delta")]),
                            ],
                        ),
                        (10, vec![uid(V21, "missing")]),
                    ],
                ),
            )
            .unwrap();
        assert!(
            r.all(BATCH_ITEM)
                .any(|i| i.required(RESULT_STATUS).unwrap().number().unwrap() != 0)
        );
        assert!(
            located(&mut e, V21, name(V21, "delta")).is_empty(),
            "cache {cache}"
        );
        assert_eq!(located(&mut e, V21, name(V21, "beta")), vec![b.clone()]);
        // The rolled-back Name is free; a taken one is refused (Non-Unique Name).
        let c = create(&mut e, "delta");
        let r = e
            .process(
                "alice",
                &message(
                    V21,
                    false,
                    vec![(
                        13,
                        vec![
                            uid(V21, &c),
                            Node::structure(NEW_ATTRIBUTE, vec![name(V21, "beta")]),
                        ],
                    )],
                ),
            )
            .unwrap();
        assert_eq!(
            r.get(BATCH_ITEM)
                .unwrap()
                .required(RESULT_REASON)
                .unwrap()
                .number()
                .unwrap(),
            0x35
        );
        // Another owner's object of the same Name is not visible.
        let r = e
            .process(
                "bob",
                &message(
                    V21,
                    false,
                    vec![(
                        8,
                        vec![Node::structure(ATTRIBUTES, vec![name(V21, "beta")])],
                    )],
                ),
            )
            .unwrap();
        assert!(
            r.get(BATCH_ITEM)
                .unwrap()
                .required(RESPONSE_PAYLOAD)
                .unwrap()
                .get(UNIQUE_IDENTIFIER)
                .is_none()
        );
        // A restart rebuilds the index from the store.
        drop(e);
        let mut e = Engine::new(store(dir.path(), cache), false);
        assert_eq!(located(&mut e, V21, name(V21, "gamma")), vec![a.clone()]);
        assert_eq!(located(&mut e, V21, name(V21, "delta")), vec![c.clone()]);
        // A destroyed object keeps its Name: excluded by the default Storage
        // Status Mask, found when the mask includes destroyed objects.
        ok(&mut e, V21, 20, vec![uid(V21, &b)]);
        assert!(located(&mut e, V21, name(V21, "beta")).is_empty());
        assert_eq!(
            located_with(
                &mut e,
                V21,
                name(V21, "beta"),
                vec![Node::int(STORAGE_STATUS_MASK, 1 | 4)]
            ),
            vec![b.clone()]
        );
    }
}

#[test]
fn locate_by_link_finds_the_same_objects_in_every_version() {
    for cache in [false, true] {
        let dir = tempfile::tempdir().unwrap();
        let mut e = Engine::new(store(dir.path(), cache), true);
        let p = ok(
            &mut e,
            V21,
            2,
            vec![
                Node::structure(
                    COMMON_ATTRIBUTES,
                    vec![
                        Node::enumeration(CRYPTOGRAPHIC_ALGORITHM, 4),
                        Node::int(CRYPTOGRAPHIC_LENGTH, 2048),
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
            ],
        );
        let public = p
            .required(PUBLIC_KEY_UNIQUE_IDENTIFIER)
            .unwrap()
            .identifier_text()
            .unwrap()
            .to_owned();
        let private = p
            .required(PRIVATE_KEY_UNIQUE_IDENTIFIER)
            .unwrap()
            .identifier_text()
            .unwrap()
            .to_owned();
        let link = |v: Version| {
            if v.0 >= 3 {
                Node::reference(PRIVATE_KEY_LINK, &private)
            } else {
                Node::structure(
                    LINK,
                    vec![
                        Node::enumeration(LINK_TYPE, 0x103),
                        Node::text(LINKED_OBJECT_IDENTIFIER, &private),
                    ],
                )
            }
        };
        for v in [Version(1, 4), V21, Version(3, 0)] {
            assert_eq!(
                located(&mut e, v, link(v)),
                vec![public.clone()],
                "{v:?} cache {cache}"
            );
        }
        // A filter the index does not hold still scans.
        assert_eq!(
            located(&mut e, V21, Node::enumeration(OBJECT_TYPE, 3)),
            vec![public.clone()]
        );
    }
}

fn state(e: &mut Engine, id: &str) -> u32 {
    let p = ok(
        e,
        V21,
        11,
        vec![uid(V21, id), Node::enumeration(ATTRIBUTE_REFERENCE, STATE)],
    );
    p.required(ATTRIBUTES)
        .unwrap()
        .required(STATE)
        .unwrap()
        .number()
        .unwrap()
}

// Read after write with the cache on: each lifecycle change is seen by the
// next request, and so is a write through another handle on the same file,
// which bypasses this process entirely (`serve` itself holds the store's
// writer lock, so no second server can share it).
#[test]
fn the_cache_never_serves_a_stale_object() {
    let dir = tempfile::tempdir().unwrap();
    let mut e = Engine::new(store(dir.path(), true), false);
    let id = create(&mut e, "epsilon");
    assert_eq!(state(&mut e, &id), 1);
    ok(&mut e, V21, 18, vec![uid(V21, &id)]);
    assert_eq!(state(&mut e, &id), 2);
    ok(
        &mut e,
        V21,
        19,
        vec![
            uid(V21, &id),
            Node::structure(
                REVOCATION_REASON,
                vec![Node::enumeration(REVOCATION_REASON_CODE, 5)],
            ),
        ],
    );
    assert_eq!(state(&mut e, &id), 3);
    ok(&mut e, V21, 20, vec![uid(V21, &id)]);
    assert_eq!(state(&mut e, &id), 5);

    // Another handle renames an object the first has cached.
    let other = create(&mut e, "zeta");
    assert_eq!(located(&mut e, V21, name(V21, "zeta")), vec![other.clone()]);
    let second = store(dir.path(), false);
    let mut obj = second.get("alice", &other).unwrap().unwrap();
    obj.attrs.retain(|a| a.tag != NAME);
    obj.attrs.push(name(V21, "eta"));
    second.begin().unwrap();
    second.put(&obj).unwrap();
    second.commit().unwrap();
    let seen = e.store.get("alice", &other).unwrap().unwrap();
    assert!(seen.attrs.iter().any(|a| a == &name(V21, "eta")));
    // The old Name no longer matches: the full filter runs on the current
    // record. (A new Name written by another process is not in this
    // process's index; the writer lock rules that case out for `serve`.)
    assert!(located(&mut e, V21, name(V21, "zeta")).is_empty());
}
