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

//! KMIP 2.1 Set Constraints (6.1.52) and Get Constraints (6.1.22): one
//! server-wide set, always read as 2.1, enforced on the objects that 2.1 and
//! 3.0 requests create, alongside the draft 3.0 per-owner sets
//! (tests/constraints.rs). Also the backup and master-key rotation round trip
//! of the server defaults and constraints records. The reading is in
//! docs/defaults-and-constraints.md.
use keytend_kmip_server::{
    protocol::{Engine, Version},
    store::Store,
    tags::*,
    ttlv::Node,
};
use std::path::Path;

const V14: Version = Version(1, 4);
const V20: Version = Version(2, 0);
const V21: Version = Version(2, 1);
const V3: Version = Version(3, 0);
const CREATE: u32 = 1;
const GET: u32 = 10;
const SET_DEFAULTS: u32 = 0x36;
const SET_CONSTRAINTS: u32 = 0x37;
const GET_CONSTRAINTS: u32 = 0x38;
const CONSTRAINT_VIOLATION: u32 = 0x4b;
const GENERAL_FAILURE: u32 = 0x100;
const SERVER_OWNER: &str = "\0server\0constraints";
const SERVER_ID: &str = "constraints\0\0server";

struct Fixture {
    engine: Engine,
    directory: tempfile::TempDir,
}
fn master(directory: &Path) -> std::path::PathBuf {
    let master = directory.join("master");
    if !master.exists() {
        key(&master, [8; 32]);
    }
    master
}
fn key(path: &Path, bytes: [u8; 32]) {
    std::fs::write(path, bytes).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
}
fn open(directory: &Path) -> Engine {
    Engine::new(
        Store::open(&directory.join("store.sqlite"), &master(directory)).unwrap(),
        true,
    )
}
impl Fixture {
    fn new() -> Self {
        let directory = tempfile::tempdir().unwrap();
        Self {
            engine: open(directory.path()),
            directory,
        }
    }
    fn send(
        &mut self,
        owner: &str,
        v: Version,
        header: Vec<Node>,
        items: Vec<(u32, Vec<Node>)>,
    ) -> Vec<Node> {
        let mut fields = vec![v.node()];
        fields.extend(header);
        if v.0 < 3 {
            fields.push(Node::int(BATCH_COUNT, items.len() as i32));
        }
        let mut message = vec![Node::structure(REQUEST_HEADER, fields)];
        let many = items.len() > 1;
        for (index, (op, payload)) in items.into_iter().enumerate() {
            let mut item = vec![Node::enumeration(OPERATION, op)];
            if many && v.0 < 3 {
                item.push(Node::bytes(UNIQUE_BATCH_ITEM_ID, vec![index as u8]));
            }
            item.push(Node::structure(REQUEST_PAYLOAD, payload));
            message.push(Node::structure(BATCH_ITEM, item));
        }
        self.engine
            .process(owner, &Node::structure(REQUEST_MESSAGE, message))
            .unwrap()
            .all(BATCH_ITEM)
            .cloned()
            .collect()
    }
    fn call(&mut self, owner: &str, v: Version, op: u32, payload: Vec<Node>) -> Node {
        self.send(owner, v, vec![], vec![(op, payload)]).remove(0)
    }
    fn set(&mut self, owner: &str, v: Version, constraints: Vec<Node>) -> Node {
        self.call(
            owner,
            v,
            SET_CONSTRAINTS,
            vec![Node::structure(CONSTRAINTS, constraints)],
        )
    }
    fn get(&mut self, owner: &str, v: Version) -> Vec<Node> {
        let r = self.call(owner, v, GET_CONSTRAINTS, vec![]);
        assert_eq!(status(&r), 0, "{}", describe(&r));
        r.required(RESPONSE_PAYLOAD)
            .unwrap()
            .required(CONSTRAINTS)
            .unwrap()
            .all(CONSTRAINT)
            .cloned()
            .collect()
    }
    fn create(&mut self, owner: &str, v: Version, bits: i32, extra: Vec<Node>) -> Node {
        self.call(owner, v, CREATE, aes(v, bits, extra))
    }
    fn objects(&self, owner: &str) -> usize {
        self.engine.store.list(owner).unwrap().len()
    }
}
fn status(item: &Node) -> u32 {
    item.required(RESULT_STATUS).unwrap().number().unwrap()
}
fn reason(item: &Node) -> u32 {
    item.get(RESULT_REASON).map_or(0, |n| n.number().unwrap())
}
fn describe(item: &Node) -> String {
    format!(
        "status {} reason {:#x} {:?}",
        status(item),
        reason(item),
        item.get(RESULT_MESSAGE)
            .map(|n| n.string().unwrap().to_owned())
    )
}
fn constraint(types: Option<Vec<u32>>, attributes: Vec<Node>) -> Node {
    let mut fields = vec![];
    if let Some(types) = types {
        fields.push(Node::structure(
            OBJECT_TYPES,
            types
                .into_iter()
                .map(|t| Node::enumeration(OBJECT_TYPE, t))
                .collect(),
        ));
    }
    fields.push(Node::structure(ATTRIBUTES, attributes));
    Node::structure(CONSTRAINT, fields)
}
/// A symmetric key Create; 1.x attributes go in a Template-Attribute.
fn aes(v: Version, bits: i32, extra: Vec<Node>) -> Vec<Node> {
    let mut attrs = vec![
        Node::enumeration(CRYPTOGRAPHIC_ALGORITHM, 3),
        Node::int(CRYPTOGRAPHIC_LENGTH, bits),
        Node::int(CRYPTOGRAPHIC_USAGE_MASK, 12),
    ];
    attrs.extend(extra);
    let container = if v.0 >= 2 {
        Node::structure(ATTRIBUTES, attrs)
    } else {
        Node::structure(
            TEMPLATE_ATTRIBUTE,
            attrs
                .into_iter()
                .map(|a| {
                    let name = match a.tag {
                        CRYPTOGRAPHIC_ALGORITHM => "Cryptographic Algorithm",
                        CRYPTOGRAPHIC_LENGTH => "Cryptographic Length",
                        _ => "Cryptographic Usage Mask",
                    };
                    let mut value = a;
                    value.tag = ATTRIBUTE_VALUE;
                    Node::structure(ATTRIBUTE, vec![Node::text(ATTRIBUTE_NAME, name), value])
                })
                .collect(),
        )
    };
    vec![Node::enumeration(OBJECT_TYPE, 2), container]
}
fn name21(value: &str) -> Node {
    Node::structure(
        NAME,
        vec![
            Node::text(NAME_VALUE, value),
            Node::enumeration(NAME_TYPE, 1),
        ],
    )
}
fn length256() -> Node {
    constraint(Some(vec![2]), vec![Node::int(CRYPTOGRAPHIC_LENGTH, 256)])
}

#[test]
fn server_constraints_apply_to_2_1_and_3_0_creations_of_every_principal() {
    let mut f = Fixture::new();
    assert!(f.get("alice", V21).is_empty());
    let r = f.set("alice", V21, vec![length256()]);
    assert_eq!(status(&r), 0, "{}", describe(&r));
    assert!(
        r.required(RESPONSE_PAYLOAD)
            .unwrap()
            .children()
            .unwrap()
            .is_empty()
    );
    // Every principal sees and is bound by the server set.
    let stored = f.get("bob", V21);
    assert_eq!(stored.len(), 1);
    assert!(stored[0] == length256());
    for v in [V21, V3] {
        let r = f.create("bob", v, 128, vec![]);
        assert_eq!((status(&r), reason(&r)), (1, CONSTRAINT_VIOLATION), "{v:?}");
        assert_eq!(status(&f.create("bob", v, 256, vec![])), 0, "{v:?}");
    }
    assert_eq!(f.objects("bob"), 2);
    // 1.x and 2.0 creations are not constrained.
    for v in [V14, V20] {
        assert_eq!(status(&f.create("bob", v, 128, vec![])), 0, "{v:?}");
    }
    // 3.0 Get Constraints returns the owner's set only.
    assert!(f.get("bob", V3).is_empty());
    // A 3.0 owner set applies on top of the server set in 3.0 only.
    let r = f.set(
        "bob",
        V3,
        vec![constraint(None, vec![Node::text(COMMENT, "approved")])],
    );
    assert_eq!(status(&r), 0, "{}", describe(&r));
    let r = f.create("bob", V3, 256, vec![]);
    assert_eq!(reason(&r), CONSTRAINT_VIOLATION);
    let r = f.create("bob", V3, 128, vec![Node::text(COMMENT, "approved")]);
    assert_eq!(reason(&r), CONSTRAINT_VIOLATION);
    assert_eq!(
        status(&f.create("bob", V3, 256, vec![Node::text(COMMENT, "approved")])),
        0
    );
    assert_eq!(status(&f.create("bob", V21, 256, vec![])), 0);
    // Under Continue only the violating item fails, and leaves nothing.
    let before = f.objects("carol");
    let r = f.send(
        "carol",
        V21,
        vec![Node::enumeration(BATCH_ERROR_CONTINUATION_OPTION, 1)],
        vec![
            (CREATE, aes(V21, 192, vec![])),
            (CREATE, aes(V21, 256, vec![])),
        ],
    );
    assert_eq!(r.iter().map(status).collect::<Vec<_>>(), [1, 0]);
    assert_eq!(f.objects("carol"), before + 1);
    // An empty Constraints structure removes the server set.
    assert_eq!(status(&f.set("carol", V21, vec![])), 0);
    assert!(f.get("alice", V21).is_empty());
    assert_eq!(status(&f.create("bob", V21, 128, vec![])), 0);
    f.engine.store.verify_audit().unwrap();
}

/// The server record is always decoded as 2.1: a 2.1 Name
/// constraint holds for a 3.0 Create, whose Name is a Text String.
#[test]
fn a_2_1_name_constraint_is_evaluated_as_2_1_in_3_0() {
    let mut f = Fixture::new();
    let r = f.set(
        "alice",
        V21,
        vec![constraint(Some(vec![2]), vec![name21("approved")])],
    );
    assert_eq!(status(&r), 0, "{}", describe(&r));
    // Get Constraints in 2.1 returns the 2.1 Name structure.
    let stored = f.get("alice", V21);
    assert!(
        stored[0]
            .required(ATTRIBUTES)
            .unwrap()
            .required(NAME)
            .unwrap()
            == &name21("approved")
    );
    let r = f.create("bob", V3, 256, vec![Node::text(NAME, "approved")]);
    assert_eq!(status(&r), 0, "{}", describe(&r));
    let r = f.create("carol", V3, 256, vec![Node::text(NAME, "other")]);
    assert_eq!(reason(&r), CONSTRAINT_VIOLATION);
    let r = f.create("carol", V21, 256, vec![name21("approved")]);
    assert_eq!(status(&r), 0, "{}", describe(&r));
    let r = f.create("dave", V21, 256, vec![]);
    assert_eq!(reason(&r), CONSTRAINT_VIOLATION);
}

// REQ:6faa26c9707e7abf 2.1 Get Constraints reasons come from its error table
// REQ:3ad54238b5ed3c4d 2.1 Set Constraints reasons come from its error table
#[test]
fn groups_are_not_supported_in_server_constraints() {
    let mut f = Fixture::new();
    let groups = Node::structure(
        CONSTRAINT,
        vec![
            Node::structure(OBJECT_GROUPS, vec![Node::text(OBJECT_GROUP, "g")]),
            Node::structure(ATTRIBUTES, vec![Node::int(CRYPTOGRAPHIC_LENGTH, 256)]),
        ],
    );
    let cases: Vec<(Node, u32)> = vec![
        (groups, 8),
        (constraint(None, vec![Node::text(OBJECT_GROUP, "g")]), 8),
        (constraint(None, vec![Node::text(GROUP_LINK, "g")]), 8),
        // The 3.0 rules otherwise apply.
        (constraint(Some(vec![2]), vec![]), 7),
        (
            constraint(Some(vec![0x0b]), vec![Node::int(CRYPTOGRAPHIC_LENGTH, 256)]),
            0x30,
        ),
    ];
    for (index, (c, expected)) in cases.into_iter().enumerate() {
        let r = f.set("alice", V21, vec![c]);
        assert_eq!(
            (status(&r), reason(&r)),
            (1, expected),
            "case {index}: {}",
            describe(&r)
        );
    }
    // Constraints is required, and Get Constraints takes no fields.
    assert_eq!(reason(&f.call("alice", V21, SET_CONSTRAINTS, vec![])), 7);
    let r = f.call(
        "alice",
        V21,
        GET_CONSTRAINTS,
        vec![Node::int(CRYPTOGRAPHIC_LENGTH, 1)],
    );
    assert_eq!(status(&r), 1);
    assert!(f.get("alice", V21).is_empty());
    // 2.0 does not define the operations.
    for op in [SET_CONSTRAINTS, GET_CONSTRAINTS] {
        assert_eq!(reason(&f.call("alice", V20, op, vec![])), 5);
    }
}

#[test]
fn server_constraints_follow_undo_and_survive_restart() {
    let mut f = Fixture::new();
    let r = f.send(
        "alice",
        V21,
        vec![Node::enumeration(BATCH_ERROR_CONTINUATION_OPTION, 3)],
        vec![
            (
                SET_CONSTRAINTS,
                vec![Node::structure(CONSTRAINTS, vec![length256()])],
            ),
            (GET, vec![Node::text(UNIQUE_IDENTIFIER, "missing")]),
        ],
    );
    assert_eq!(r.iter().map(status).collect::<Vec<_>>(), [3, 1]);
    assert!(f.get("alice", V21).is_empty());
    assert_eq!(status(&f.set("alice", V21, vec![length256()])), 0);
    let directory = f.directory.path().to_owned();
    f.engine = open(&directory);
    assert!(f.get("bob", V21)[0] == length256());
    assert_eq!(
        reason(&f.create("bob", V3, 128, vec![])),
        CONSTRAINT_VIOLATION
    );
    f.engine.store.verify_integrity().unwrap();
}

/// A server record that cannot be read fails creations closed, and an empty
/// Set Constraints recovers.
#[test]
fn a_corrupt_server_record_fails_creations_closed() {
    let mut f = Fixture::new();
    assert_eq!(status(&f.set("alice", V21, vec![length256()])), 0);
    assert!(f.engine.check_server_records().is_ok());
    let mut record = f
        .engine
        .store
        .get(SERVER_OWNER, SERVER_ID)
        .unwrap()
        .unwrap();
    record.material = b"not TTLV".to_vec();
    f.engine.store.put(&record).unwrap();
    assert!(f.engine.check_server_records().is_err());
    for v in [V21, V3] {
        let r = f.create("bob", v, 256, vec![]);
        assert_eq!((status(&r), reason(&r)), (1, GENERAL_FAILURE), "{v:?}");
    }
    assert_eq!(f.objects("bob"), 0);
    assert_eq!(status(&f.create("bob", V20, 256, vec![])), 0);
    assert_eq!(status(&f.set("alice", V21, vec![])), 0);
    assert!(f.engine.check_server_records().is_ok());
    assert_eq!(status(&f.create("bob", V21, 128, vec![])), 0);
}

/// Both server records are ordinary sealed objects: a backup and a
/// master-key rotation carry them.
#[test]
fn server_records_survive_backup_and_rotation() {
    let mut f = Fixture::new();
    assert_eq!(status(&f.set("alice", V21, vec![length256()])), 0);
    let r = f.call(
        "alice",
        V21,
        SET_DEFAULTS,
        vec![Node::structure(
            DEFAULTS_INFORMATION,
            vec![Node::structure(
                OBJECT_DEFAULTS,
                vec![
                    Node::enumeration(OBJECT_TYPE, 2),
                    Node::structure(ATTRIBUTES, vec![Node::boolean(SENSITIVE, true)]),
                ],
            )],
        )],
    );
    assert_eq!(status(&r), 0, "{}", describe(&r));
    let dir = f.directory.path().to_owned();
    let backup = dir.join("backup.sqlite");
    f.engine.store.backup(&backup).unwrap();
    let next = dir.join("next.key");
    key(&next, [9; 32]);
    let rotated = dir.join("rotated.sqlite");
    f.engine.store.rotate_master_key(&next, &rotated).unwrap();
    for (database, master) in [(backup, master(&dir)), (rotated, next)] {
        let store = Store::open(&database, &master).unwrap();
        store.verify_integrity().unwrap();
        let mut restored = Fixture {
            engine: Engine::new(store, true),
            directory: tempfile::tempdir().unwrap(),
        };
        assert!(restored.get("bob", V21)[0] == length256());
        assert_eq!(
            reason(&restored.create("bob", V21, 128, vec![])),
            CONSTRAINT_VIOLATION
        );
        let r = restored.create("bob", V21, 256, vec![]);
        assert_eq!(status(&r), 0, "{}", describe(&r));
        let id = r
            .required(RESPONSE_PAYLOAD)
            .unwrap()
            .required(UNIQUE_IDENTIFIER)
            .unwrap()
            .identifier_text()
            .unwrap()
            .to_owned();
        let r = restored.call("bob", V21, 11, vec![Node::text(UNIQUE_IDENTIFIER, id)]);
        let sensitive = r
            .required(RESPONSE_PAYLOAD)
            .unwrap()
            .required(ATTRIBUTES)
            .unwrap()
            .required(SENSITIVE)
            .unwrap()
            .clone();
        assert!(sensitive == Node::boolean(SENSITIVE, true));
    }
}
