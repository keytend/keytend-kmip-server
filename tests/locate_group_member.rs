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

//! Locate with Object Group Member (1.1+ section 4.9, 2.x section 6.1.27).
use keytend_kmip_server::{
    protocol::{Engine, Version},
    store::Store,
    tags::*,
    ttlv::Node,
};

struct Fixture {
    _dir: tempfile::TempDir,
    engine: Engine,
}
impl Fixture {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let key = dir.path().join("master");
        std::fs::write(&key, [5; 32]).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        let store = Store::open(&dir.path().join("keys.sqlite"), &key).unwrap();
        Self {
            engine: Engine::new(store, false),
            _dir: dir,
        }
    }
    fn call(&mut self, v: Version, op: u32, payload: Vec<Node>) -> Node {
        let request = Node::structure(
            REQUEST_MESSAGE,
            vec![
                Node::structure(REQUEST_HEADER, vec![v.node(), Node::int(BATCH_COUNT, 1)]),
                Node::structure(
                    BATCH_ITEM,
                    vec![
                        Node::enumeration(OPERATION, op),
                        Node::structure(REQUEST_PAYLOAD, payload),
                    ],
                ),
            ],
        );
        let response = self.engine.process("alice", &request).unwrap();
        response.required(BATCH_ITEM).unwrap().clone()
    }
}
fn reason(item: &Node) -> Option<u32> {
    item.get(RESULT_REASON).map(|n| n.number().unwrap())
}
fn ids(item: &Node) -> Vec<String> {
    assert_eq!(reason(item), None);
    item.required(RESPONSE_PAYLOAD)
        .unwrap()
        .all(UNIQUE_IDENTIFIER)
        .map(|n| n.identifier_text().unwrap().to_owned())
        .collect()
}
fn group(v: Version, name: &str) -> Node {
    if v.0 == 1 {
        Node::structure(
            ATTRIBUTE,
            vec![
                Node::text(ATTRIBUTE_NAME, "Object Group"),
                Node::text(ATTRIBUTE_VALUE, name),
            ],
        )
    } else {
        Node::text(OBJECT_GROUP, name)
    }
}
fn create(f: &mut Fixture, v: Version, name: &str) -> String {
    let attrs = if v.0 == 1 {
        let a = |n: &str, value: Node| {
            Node::structure(ATTRIBUTE, vec![Node::text(ATTRIBUTE_NAME, n), value])
        };
        Node::structure(
            TEMPLATE_ATTRIBUTE,
            vec![
                a(
                    "Cryptographic Algorithm",
                    Node::enumeration(ATTRIBUTE_VALUE, 3),
                ),
                a("Cryptographic Length", Node::int(ATTRIBUTE_VALUE, 128)),
                a("Cryptographic Usage Mask", Node::int(ATTRIBUTE_VALUE, 12)),
                group(v, name),
            ],
        )
    } else {
        Node::structure(
            ATTRIBUTES,
            vec![
                Node::enumeration(CRYPTOGRAPHIC_ALGORITHM, 3),
                Node::int(CRYPTOGRAPHIC_LENGTH, 128),
                Node::int(CRYPTOGRAPHIC_USAGE_MASK, 12),
                group(v, name),
            ],
        )
    };
    let r = f.call(v, 1, vec![Node::enumeration(OBJECT_TYPE, 2), attrs]);
    ids(&r).remove(0)
}
fn locate(v: Version, member: u32, max: Option<i32>, name: Option<&str>) -> Vec<Node> {
    let mut p = vec![];
    p.extend(max.map(|m| Node::int(MAXIMUM_ITEMS, m)));
    p.push(Node::enumeration(OBJECT_GROUP_MEMBER, member));
    if let Some(name) = name {
        p.push(if v.0 == 1 {
            group(v, name)
        } else {
            Node::structure(ATTRIBUTES, vec![group(v, name)])
        });
    }
    p
}
fn get(f: &mut Fixture, v: Version, id: &str) {
    let r = f.call(v, 10, vec![Node::text(UNIQUE_IDENTIFIER, id)]);
    assert_eq!(reason(&r), None);
}

// REQ:def908bf1380ab20 Group Member Fresh returns only fresh objects of the requested group
// REQ:d7930c0ff5004be4 2.x Group Member Fresh returns only fresh objects of the requested group
#[test]
fn group_member_fresh_returns_unserved_members_of_the_group() {
    for v in [
        Version(1, 1),
        Version(1, 2),
        Version(1, 4),
        Version(2, 0),
        Version(2, 1),
    ] {
        let mut f = Fixture::new();
        let a = create(&mut f, v, "pool");
        let b = create(&mut f, v, "pool");
        create(&mut f, v, "other");
        let all = ids(&f.call(v, 8, locate(v, 1, None, Some("pool"))));
        // 2.0+ section 6.1.27 orders several results newest first; 1.x
        // leaves the order open and the server hands out the oldest first.
        if v.0 == 1 {
            assert_eq!(all, vec![a.clone(), b.clone()]);
        } else {
            assert_eq!(all, vec![b.clone(), a.clone()]);
        }
        let first = ids(&f.call(v, 8, locate(v, 1, Some(1), Some("pool"))));
        assert_eq!(first, vec![if v.0 == 1 { a.clone() } else { b.clone() }]);
        // Serving the object (Get) makes it no longer fresh.
        get(&mut f, v, &first[0]);
        let next = ids(&f.call(v, 8, locate(v, 1, Some(1), Some("pool"))));
        assert_eq!(next, vec![if v.0 == 1 { b.clone() } else { a.clone() }]);
        get(&mut f, v, &next[0]);
        // No fresh member is left, and none is generated on the fly.
        assert!(ids(&f.call(v, 8, locate(v, 1, Some(1), Some("pool")))).is_empty());
    }
}

#[test]
fn group_member_default_rotates_through_the_group() {
    for v in [Version(1, 1), Version(1, 3), Version(2, 1)] {
        let mut f = Fixture::new();
        let members = [
            create(&mut f, v, "rr"),
            create(&mut f, v, "rr"),
            create(&mut f, v, "rr"),
        ];
        create(&mut f, v, "other");
        for round in 0..7 {
            let found = ids(&f.call(v, 8, locate(v, 2, Some(1), Some("rr"))));
            assert_eq!(found, vec![members[round % 3].clone()], "round {round}");
        }
        // Without a limit it still names one default object.
        assert_eq!(ids(&f.call(v, 8, locate(v, 2, None, Some("rr")))).len(), 1);
        assert!(ids(&f.call(v, 8, locate(v, 2, None, Some("empty")))).is_empty());
        if v.0 >= 2 {
            let mut p = locate(v, 2, None, Some("rr"));
            p.push(Node::int(OFFSET_ITEMS, 1));
            assert_eq!(reason(&f.call(v, 8, p)), Some(7));
        }
    }
}

#[test]
fn group_member_is_versioned_and_validated() {
    let mut f = Fixture::new();
    // Object Group Member was added in KMIP 1.1.
    let v10 = Version(1, 0);
    assert_eq!(
        reason(&f.call(v10, 8, locate(v10, 1, None, Some("g")))),
        // An unknown field is Invalid Field in 1.x (1.0 Table 226).
        Some(7)
    );
    for v in [Version(1, 1), Version(2, 1)] {
        // The text defines the flag together with an Object Group only.
        assert_eq!(reason(&f.call(v, 8, locate(v, 1, None, None))), Some(7));
        assert_eq!(
            reason(&f.call(v, 8, locate(v, 3, None, Some("g")))),
            Some(7)
        );
        let mut twice = locate(v, 1, None, Some("g"));
        twice.push(Node::enumeration(OBJECT_GROUP_MEMBER, 2));
        assert_eq!(reason(&f.call(v, 8, twice)), Some(7));
        let mut integer = locate(v, 1, None, Some("g"));
        integer[0] = Node::int(OBJECT_GROUP_MEMBER, 1);
        assert_eq!(reason(&f.call(v, 8, integer)), Some(7));
    }
}
