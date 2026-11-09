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

// Draft 3.0 (CSD02) Set Constraints (6.1.59) and Get Constraints (6.1.28):
// storage, validation, scoping and enforcement on object creation with
// Constraint Violation (0x4B). The enforcement reading of the Constraint
// structure (table 466) is documented in src/protocol/constraints.rs.

use keytend_kmip_server::{
    protocol::{Engine, Version},
    store::Store,
    tags::*,
    ttlv::{Node, Value},
};
use std::path::PathBuf;

const V3: Version = Version(3, 0);
const V21: Version = Version(2, 1);
const CREATE: u32 = 1;
const REGISTER: u32 = 3;
const REKEY: u32 = 4;
const GET: u32 = 10;
const SET_CONSTRAINTS: u32 = 0x37;
const GET_CONSTRAINTS: u32 = 0x38;
const CONSTRAINT_VIOLATION: u32 = 0x4b;

struct Fixture {
    engine: Engine,
    directory: tempfile::TempDir,
}
fn open(directory: &std::path::Path) -> Engine {
    let master: PathBuf = directory.join("master");
    if !master.exists() {
        std::fs::write(&master, [5; 32]).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&master, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
    }
    Engine::new(
        Store::open(&directory.join("store.sqlite"), &master).unwrap(),
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
        for (index, (op, payload)) in items.into_iter().enumerate() {
            let mut item = vec![Node::enumeration(OPERATION, op)];
            if v.0 < 3 {
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
    fn call(&mut self, owner: &str, op: u32, payload: Vec<Node>) -> Node {
        self.send(owner, V3, vec![], vec![(op, payload)]).remove(0)
    }
    fn set(&mut self, owner: &str, constraints: Vec<Node>) -> Node {
        self.call(
            owner,
            SET_CONSTRAINTS,
            vec![Node::structure(CONSTRAINTS, constraints)],
        )
    }
    fn get(&mut self, owner: &str) -> Vec<Node> {
        let r = self.call(owner, GET_CONSTRAINTS, vec![]);
        assert_eq!(status(&r), 0);
        r.required(RESPONSE_PAYLOAD)
            .unwrap()
            .required(CONSTRAINTS)
            .unwrap()
            .all(CONSTRAINT)
            .cloned()
            .collect()
    }
    fn objects(&self, owner: &str) -> usize {
        self.engine.store.list(owner).unwrap().len()
    }
}
fn status(item: &Node) -> u32 {
    item.required(RESULT_STATUS).unwrap().number().unwrap()
}
fn reason(item: &Node) -> u32 {
    item.required(RESULT_REASON).unwrap().number().unwrap()
}
fn constraint(types: Option<Vec<u32>>, groups: Option<Vec<Node>>, attributes: Vec<Node>) -> Node {
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
    if let Some(groups) = groups {
        fields.push(Node::structure(OBJECT_GROUPS, groups));
    }
    fields.push(Node::structure(ATTRIBUTES, attributes));
    Node::structure(CONSTRAINT, fields)
}
fn aes(bits: i32, mask: i32, extra: Vec<Node>) -> Vec<Node> {
    let mut attrs = vec![
        Node::enumeration(CRYPTOGRAPHIC_ALGORITHM, 3),
        Node::int(CRYPTOGRAPHIC_LENGTH, bits),
        Node::int(CRYPTOGRAPHIC_USAGE_MASK, mask),
    ];
    attrs.extend(extra);
    vec![
        Node::enumeration(OBJECT_TYPE, 2),
        Node::structure(ATTRIBUTES, attrs),
    ]
}
fn secret_data() -> Vec<Node> {
    vec![
        Node::enumeration(OBJECT_TYPE, 7),
        Node::structure(ATTRIBUTES, vec![Node::int(CRYPTOGRAPHIC_USAGE_MASK, 0)]),
        Node::structure(
            SECRET_DATA,
            vec![
                Node::enumeration(SECRET_DATA_TYPE, 2),
                Node::structure(
                    KEY_BLOCK,
                    vec![
                        Node::enumeration(KEY_FORMAT_TYPE, 2),
                        Node::structure(KEY_VALUE, vec![Node::bytes(KEY_MATERIAL, vec![1; 16])]),
                    ],
                ),
            ],
        ),
    ]
}
fn uid(item: &Node) -> String {
    item.required(RESPONSE_PAYLOAD)
        .unwrap()
        .required(UNIQUE_IDENTIFIER)
        .unwrap()
        .identifier_text()
        .unwrap()
        .to_owned()
}

// REQ:6faa26c9707e7abf Get Constraints reasons come from its error table
// REQ:3ad54238b5ed3c4d Set Constraints reasons come from its error table
#[test]
fn constraints_are_stored_returned_and_enforced_on_create() {
    let mut f = Fixture::new();
    assert!(f.get("alice").is_empty());
    let length = constraint(
        Some(vec![2]),
        None,
        vec![Node::int(CRYPTOGRAPHIC_LENGTH, 256)],
    );
    let r = f.set("alice", vec![length.clone()]);
    assert_eq!(status(&r), 0);
    assert!(
        r.required(RESPONSE_PAYLOAD)
            .unwrap()
            .children()
            .unwrap()
            .is_empty()
    );
    let stored = f.get("alice");
    assert_eq!(stored.len(), 1);
    assert!(
        stored[0] == length,
        "Get Constraints returns the set as given"
    );
    // AES-128 violates; nothing is created.
    let r = f.call("alice", CREATE, aes(128, 12, vec![]));
    assert_eq!((status(&r), reason(&r)), (1, CONSTRAINT_VIOLATION));
    assert_eq!(f.objects("alice"), 0);
    // AES-256 satisfies it.
    let r = f.call("alice", CREATE, aes(256, 12, vec![]));
    assert_eq!(status(&r), 0);
    // Another object type is outside the constraint.
    assert_eq!(status(&f.call("alice", REGISTER, secret_data())), 0);
    assert_eq!(f.objects("alice"), 2);
    // Under Continue the violating item alone fails and leaves nothing.
    let r = f.send(
        "alice",
        V3,
        vec![Node::enumeration(BATCH_ERROR_CONTINUATION_OPTION, 1)],
        vec![
            (CREATE, aes(192, 12, vec![])),
            (CREATE, aes(256, 12, vec![])),
        ],
    );
    assert_eq!(r.iter().map(status).collect::<Vec<_>>(), [1, 0]);
    assert_eq!(f.objects("alice"), 3);
    // Another principal is not constrained and sees no constraints.
    assert!(f.get("bob").is_empty());
    assert_eq!(status(&f.call("bob", CREATE, aes(128, 12, vec![]))), 0);
    // An empty set removes the constraints.
    assert_eq!(status(&f.set("alice", vec![])), 0);
    assert!(f.get("alice").is_empty());
    assert_eq!(status(&f.call("alice", CREATE, aes(128, 12, vec![]))), 0);
    f.engine.store.verify_audit().unwrap();
}

#[test]
fn usage_masks_groups_and_names_follow_the_locate_matching_rule() {
    let mut f = Fixture::new();
    let finance = Node::name_reference(GROUP_LINK, "finance");
    let r = f.set(
        "alice",
        vec![
            // Every symmetric key must allow Encrypt (mask bit 4).
            constraint(
                Some(vec![2]),
                None,
                vec![Node::int(CRYPTOGRAPHIC_USAGE_MASK, 4)],
            ),
            // Objects in the finance group must carry this Name.
            constraint(
                None,
                Some(vec![finance.clone()]),
                vec![Node::text(NAME, "fin-key")],
            ),
        ],
    );
    assert_eq!(status(&r), 0, "reason {}", reason(&r));
    // Encrypt|Decrypt contains Encrypt; Decrypt alone does not.
    assert_eq!(status(&f.call("alice", CREATE, aes(256, 12, vec![]))), 0);
    let r = f.call("alice", CREATE, aes(256, 8, vec![]));
    assert_eq!(reason(&r), CONSTRAINT_VIOLATION);
    // Group members need the Name; non-members do not.
    let r = f.call("alice", CREATE, aes(256, 4, vec![finance.clone()]));
    assert_eq!(reason(&r), CONSTRAINT_VIOLATION);
    let r = f.call(
        "alice",
        CREATE,
        aes(256, 4, vec![finance.clone(), Node::text(NAME, "fin-key")]),
    );
    assert_eq!(
        status(&r),
        0,
        "reason {}",
        r.get(RESULT_REASON).map_or(0, |n| n.number().unwrap())
    );
    let r = f.call(
        "alice",
        CREATE,
        aes(256, 4, vec![Node::name_reference(GROUP_LINK, "hr")]),
    );
    assert_eq!(status(&r), 0);
    // The draft 3.0 Name form is returned.
    let stored = f.get("alice");
    let name = stored[1]
        .required(ATTRIBUTES)
        .unwrap()
        .required(NAME)
        .unwrap();
    assert!(matches!(&name.value, Value::TextString(n) if n == "fin-key"));
}

#[test]
fn rekey_is_checked_but_existing_objects_are_not() {
    let mut f = Fixture::new();
    let id = uid(&f.call("alice", CREATE, aes(256, 12, vec![])));
    let r = f.set(
        "alice",
        vec![constraint(
            Some(vec![2]),
            None,
            vec![Node::text(COMMENT, "approved")],
        )],
    );
    assert_eq!(status(&r), 0);
    // The existing key stays usable.
    let r = f.call(
        "alice",
        GET,
        vec![Node::identifier(UNIQUE_IDENTIFIER, &*id)],
    );
    assert_eq!(status(&r), 0);
    // Its replacement is a new object and must satisfy the constraint.
    let r = f.call(
        "alice",
        REKEY,
        vec![Node::identifier(UNIQUE_IDENTIFIER, &*id)],
    );
    assert_eq!((status(&r), reason(&r)), (1, CONSTRAINT_VIOLATION));
    assert_eq!(f.objects("alice"), 1);
}

#[test]
fn set_constraints_follows_undo_and_survives_restart() {
    let mut f = Fixture::new();
    let length = constraint(None, None, vec![Node::int(CRYPTOGRAPHIC_LENGTH, 256)]);
    let r = f.send(
        "alice",
        V3,
        vec![Node::enumeration(BATCH_ERROR_CONTINUATION_OPTION, 3)],
        vec![
            (
                SET_CONSTRAINTS,
                vec![Node::structure(CONSTRAINTS, vec![length.clone()])],
            ),
            (GET, vec![Node::identifier(UNIQUE_IDENTIFIER, "missing")]),
        ],
    );
    assert_eq!(r.iter().map(status).collect::<Vec<_>>(), [3, 1]);
    assert!(f.get("alice").is_empty());
    // A constraint set earlier in a batch applies to later items.
    let r = f.send(
        "alice",
        V3,
        vec![],
        vec![
            (
                SET_CONSTRAINTS,
                vec![Node::structure(CONSTRAINTS, vec![length.clone()])],
            ),
            (CREATE, aes(128, 12, vec![])),
        ],
    );
    assert_eq!(r.iter().map(status).collect::<Vec<_>>(), [0, 1]);
    // The set is stored encrypted with the objects and reloads.
    let directory = f.directory.path().to_owned();
    f.engine = open(&directory);
    let stored = f.get("alice");
    assert_eq!(stored.len(), 1);
    assert!(stored[0] == length);
    assert_eq!(
        reason(&f.call("alice", CREATE, aes(128, 12, vec![]))),
        CONSTRAINT_VIOLATION
    );
    // The record is not a managed object of the principal.
    assert_eq!(f.objects("alice"), 0);
    f.engine.store.verify_integrity().unwrap();
}

#[test]
fn malformed_constraints_are_refused() {
    let mut f = Fixture::new();
    let length = || Node::int(CRYPTOGRAPHIC_LENGTH, 256);
    // Constraints is required.
    assert_eq!(reason(&f.call("alice", SET_CONSTRAINTS, vec![])), 7);
    let cases: Vec<(Node, u32)> = vec![
        // A constraint without Attributes would restrict nothing.
        (constraint(Some(vec![2]), None, vec![]), 7),
        (
            Node::structure(
                CONSTRAINT,
                vec![Node::structure(
                    OBJECT_TYPES,
                    vec![Node::enumeration(OBJECT_TYPE, 2)],
                )],
            ),
            7,
        ),
        // System Object types (User) are not constrained: Invalid Object Type.
        (constraint(Some(vec![0x0b]), None, vec![length()]), 0x30),
        (constraint(Some(vec![6]), None, vec![length()]), 0x30),
        (constraint(Some(vec![]), None, vec![length()]), 7),
        // Object Groups holds Group Link values only.
        (
            constraint(
                None,
                Some(vec![Node::text(OBJECT_GROUP, "g")]),
                vec![length()],
            ),
            7,
        ),
        (
            constraint(
                None,
                Some(vec![Node::name_reference(GROUP_LINK, "")]),
                vec![length()],
            ),
            7,
        ),
        // Attributes follow the creation rules: Always Sensitive is
        // read-only, single-valued attributes appear once, and a Constraint
        // has no other fields.
        (
            constraint(None, None, vec![Node::boolean(ALWAYS_SENSITIVE, true)]),
            u32::MAX,
        ),
        (constraint(None, None, vec![length(), length()]), u32::MAX),
        (
            Node::structure(
                CONSTRAINT,
                vec![
                    Node::structure(ATTRIBUTES, vec![length()]),
                    Node::int(CRYPTOGRAPHIC_LENGTH, 1),
                ],
            ),
            u32::MAX,
        ),
    ];
    for (index, (c, expected)) in cases.into_iter().enumerate() {
        let r = f.set("alice", vec![c]);
        assert_eq!(status(&r), 1, "case {index}");
        if expected != u32::MAX {
            assert_eq!(reason(&r), expected, "case {index}");
        }
    }
    // Server bound on the number of constraints.
    let many = (0..33)
        .map(|_| constraint(None, None, vec![length()]))
        .collect::<Vec<_>>();
    assert_eq!(reason(&f.set("alice", many)), 0x3a);
    // A failed Set leaves the previous set in place.
    assert!(f.get("alice").is_empty());
    // Get Constraints takes no fields.
    let r = f.call(
        "alice",
        GET_CONSTRAINTS,
        vec![Node::int(CRYPTOGRAPHIC_LENGTH, 1)],
    );
    assert_eq!(status(&r), 1);
    // KMIP 2.1 defines both operations for one server-wide set
    // (tests/server_constraints.rs); the owner's 3.0 set is not part of it.
    let r = f
        .send("alice", V21, vec![], vec![(SET_CONSTRAINTS, vec![])])
        .remove(0);
    assert_eq!(reason(&r), 7);
    let r = f
        .send("alice", V21, vec![], vec![(GET_CONSTRAINTS, vec![])])
        .remove(0);
    assert_eq!(status(&r), 0);
}
