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

//! Draft 3.0 Locate by Name: the request carries Name as a Text String
//! (draft 3.0 section 4.40) and must match the object's stored Name. A Name
//! Reference that names no object of the caller fails with Object Not Found.
use keytend_kmip_server::{
    protocol::{Engine, Version},
    store::Store,
    tags::*,
    ttlv::Node,
};

const V3: Version = Version(3, 0);

fn engine(directory: &std::path::Path) -> Engine {
    let master = directory.join("master");
    std::fs::write(&master, [7; 32]).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&master, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    Engine::new(
        Store::open(&directory.join("store.sqlite"), &master).unwrap(),
        true,
    )
}
fn send(engine: &mut Engine, owner: &str, op: u32, payload: Vec<Node>) -> Node {
    let request = Node::structure(
        REQUEST_MESSAGE,
        vec![
            Node::structure(REQUEST_HEADER, vec![V3.node()]),
            Node::structure(
                BATCH_ITEM,
                vec![
                    Node::enumeration(OPERATION, op),
                    Node::structure(REQUEST_PAYLOAD, payload),
                ],
            ),
        ],
    );
    let response = engine.process(owner, &request).unwrap();
    response.required(BATCH_ITEM).unwrap().clone()
}
fn call(engine: &mut Engine, owner: &str, op: u32, payload: Vec<Node>) -> Node {
    let item = send(engine, owner, op, payload);
    assert_eq!(
        item.required(RESULT_STATUS).unwrap().number().unwrap(),
        0,
        "{:?}",
        item.get(RESULT_MESSAGE).map(|n| n.string())
    );
    item.required(RESPONSE_PAYLOAD).unwrap().clone()
}
fn create(engine: &mut Engine, owner: &str, name: &str) -> String {
    let payload = call(
        engine,
        owner,
        1,
        vec![
            Node::enumeration(OBJECT_TYPE, 2),
            Node::structure(
                ATTRIBUTES,
                vec![
                    Node::enumeration(CRYPTOGRAPHIC_ALGORITHM, 3),
                    Node::int(CRYPTOGRAPHIC_LENGTH, 128),
                    Node::int(CRYPTOGRAPHIC_USAGE_MASK, 0xc),
                    Node::text(NAME, name),
                ],
            ),
        ],
    );
    payload
        .required(UNIQUE_IDENTIFIER)
        .unwrap()
        .identifier_text()
        .unwrap()
        .to_owned()
}
fn locate(engine: &mut Engine, owner: &str, name: &str) -> Vec<String> {
    let payload = call(
        engine,
        owner,
        8,
        vec![Node::structure(ATTRIBUTES, vec![Node::text(NAME, name)])],
    );
    payload
        .all(UNIQUE_IDENTIFIER)
        .map(|n| n.identifier_text().unwrap().to_owned())
        .collect()
}

#[test]
fn draft_3_locate_matches_text_names() {
    let directory = tempfile::tempdir().unwrap();
    let mut engine = engine(directory.path());
    let first = create(&mut engine, "alice", "first-key");
    let second = create(&mut engine, "alice", "second-key");
    assert_eq!(locate(&mut engine, "alice", "first-key"), vec![first]);
    assert_eq!(locate(&mut engine, "alice", "second-key"), vec![second]);
    assert!(locate(&mut engine, "alice", "missing-key").is_empty());
    // Names are owner-scoped: another owner sees nothing.
    assert!(locate(&mut engine, "bob", "first-key").is_empty());
}

#[test]
fn draft_3_unresolved_name_reference_is_object_not_found() {
    let directory = tempfile::tempdir().unwrap();
    let mut engine = engine(directory.path());
    create(&mut engine, "alice", "alice-key");
    for (owner, name) in [("alice", "missing-key"), ("bob", "alice-key")] {
        let item = send(
            &mut engine,
            owner,
            10,
            vec![Node::name_reference(UNIQUE_IDENTIFIER, name)],
        );
        assert_eq!(item.required(RESULT_STATUS).unwrap().number().unwrap(), 1);
        assert_eq!(
            item.required(RESULT_REASON).unwrap().number().unwrap(),
            0x37,
            "{owner}/{name}"
        );
    }
}
