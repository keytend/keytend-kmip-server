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

//! Client-to-server Set Endpoint Role (2.0 6.1.48, 2.1 6.1.54, draft 3.0
//! 6.1.61): which roles are accepted, on which channels, and Query.
use keytend_kmip_server::{
    protocol::{
        Engine, ROLE_CLIENT, ROLE_SERVER, SET_ENDPOINT_ROLE, ServerToClient, Subscription, Version,
        reversal_accepted,
    },
    store::Store,
    tags::*,
    ttlv::Node,
};
use std::collections::HashMap;

struct Fixture {
    _dir: tempfile::TempDir,
    engine: Engine,
}
/// `subscribed`: alice's client endpoint uses this version.
fn fixture(subscribed: Option<Version>) -> Fixture {
    let dir = tempfile::tempdir().unwrap();
    let key = dir.path().join("master");
    std::fs::write(&key, [3; 32]).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    let store = Store::open(&dir.path().join("keys.sqlite"), &key).unwrap();
    let mut engine = Engine::new(store, true);
    if let Some(version) = subscribed {
        let subscriptions = HashMap::from([(
            "alice".to_owned(),
            Subscription {
                version,
                notify: true,
                put: true,
            },
        )]);
        engine = engine
            .with_server_to_client(ServerToClient::new(subscriptions, Box::new(|_| true)).unwrap());
    }
    Fixture { _dir: dir, engine }
}
fn request(v: Version, items: Vec<(u32, Vec<Node>)>, continuation: Option<u32>) -> Node {
    let mut header = vec![v.node()];
    if let Some(c) = continuation {
        header.push(Node::enumeration(BATCH_ERROR_CONTINUATION_OPTION, c));
    }
    if v.0 < 3 {
        header.push(Node::int(BATCH_COUNT, items.len() as i32));
    }
    let mut fields = vec![Node::structure(REQUEST_HEADER, header)];
    for (i, (op, payload)) in items.into_iter().enumerate() {
        let mut item = vec![Node::enumeration(OPERATION, op)];
        if v.0 < 3 {
            item.push(Node::bytes(UNIQUE_BATCH_ITEM_ID, vec![i as u8]));
        }
        item.push(Node::structure(REQUEST_PAYLOAD, payload));
        fields.push(Node::structure(BATCH_ITEM, item));
    }
    Node::structure(REQUEST_MESSAGE, fields)
}
fn role(value: u32) -> Vec<Node> {
    vec![Node::enumeration(ENDPOINT_ROLE, value)]
}
fn set_role(v: Version, payload: Vec<Node>) -> Node {
    request(v, vec![(SET_ENDPOINT_ROLE, payload)], None)
}
/// Result Reason of the first item, or its accepted Endpoint Role.
fn result(response: &Node) -> Result<u32, u32> {
    let item = response.required(BATCH_ITEM).unwrap();
    match item.required(RESULT_STATUS).unwrap().number().unwrap() {
        0 => Ok(item
            .required(RESPONSE_PAYLOAD)
            .unwrap()
            .required(ENDPOINT_ROLE)
            .unwrap()
            .number()
            .unwrap()),
        _ => Err(item.required(RESULT_REASON).unwrap().number().unwrap()),
    }
}
const V2: [Version; 3] = [Version(2, 0), Version(2, 1), Version(3, 0)];

#[test]
fn the_server_role_is_accepted_in_every_version_that_defines_the_operation() {
    let mut f = fixture(None);
    for v in V2 {
        let r = f
            .engine
            .process("alice", &set_role(v, role(ROLE_SERVER)))
            .unwrap();
        assert_eq!(result(&r), Ok(ROLE_SERVER), "{}.{}", v.0, v.1);
        assert!(!reversal_accepted(&r));
    }
    // 1.x defines no Set Endpoint Role (1.4 table 255 ends at Export).
    for v in [Version(1, 0), Version(1, 4)] {
        let r = f
            .engine
            .process("alice", &set_role(v, role(ROLE_SERVER)))
            .unwrap();
        assert_eq!(result(&r), Err(5));
    }
}

#[test]
fn query_lists_set_endpoint_role_from_2_0() {
    let mut f = fixture(None);
    for (v, listed) in [
        (Version(1, 4), false),
        (Version(2, 0), true),
        (Version(2, 1), true),
        (Version(3, 0), true),
    ] {
        let r = f
            .engine
            .process(
                "alice",
                &request(
                    v,
                    vec![(24, vec![Node::enumeration(QUERY_FUNCTION, 1)])],
                    None,
                ),
            )
            .unwrap();
        let ops = r
            .required(BATCH_ITEM)
            .unwrap()
            .required(RESPONSE_PAYLOAD)
            .unwrap()
            .all(OPERATION)
            .map(|n| n.number().unwrap())
            .collect::<Vec<_>>();
        assert_eq!(ops.contains(&SET_ENDPOINT_ROLE), listed);
        // Interop (0x34) is never offered.
        assert!(!ops.contains(&0x34));
    }
}

#[test]
fn the_client_role_needs_a_reversible_channel_and_a_matching_client_endpoint() {
    let v = Version(2, 1);
    // No client endpoint: nothing could use the reversed channel.
    let mut f = fixture(None);
    let r = f
        .engine
        .process_reversible("alice", &set_role(v, role(ROLE_CLIENT)), None, &[])
        .unwrap();
    assert_eq!(result(&r), Err(12));
    let mut f = fixture(Some(v));
    // Another principal has none either.
    let r = f
        .engine
        .process_reversible("bob", &set_role(v, role(ROLE_CLIENT)), None, &[])
        .unwrap();
    assert_eq!(result(&r), Err(12));
    // An HTTP exchange or a deferred batch cannot be reversed.
    let r = f
        .engine
        .process("alice", &set_role(v, role(ROLE_CLIENT)))
        .unwrap();
    assert_eq!(result(&r), Err(8));
    assert!(!reversal_accepted(&r));
    // Another protocol version than the endpoint's, including draft 3.0.
    for other in [Version(2, 0), Version(3, 0)] {
        let r = f
            .engine
            .process_reversible("alice", &set_role(other, role(ROLE_CLIENT)), None, &[])
            .unwrap();
        assert_eq!(result(&r), Err(8));
    }
    let r = f
        .engine
        .process_reversible("alice", &set_role(v, role(ROLE_CLIENT)), None, &[])
        .unwrap();
    assert_eq!(result(&r), Ok(ROLE_CLIENT));
    assert!(reversal_accepted(&r));
    // The certificate policy still decides whether the operation is allowed.
    let r = f
        .engine
        .process_reversible("alice", &set_role(v, role(ROLE_CLIENT)), Some(&[24]), &[])
        .unwrap();
    assert_eq!(result(&r), Err(12));
    assert!(!reversal_accepted(&r));
}

#[test]
fn invalid_payloads_are_refused() {
    let mut f = fixture(Some(Version(2, 1)));
    let v = Version(2, 1);
    for (payload, reason) in [
        (vec![], 7),
        (role(3), 7),
        (vec![Node::int(ENDPOINT_ROLE, 1)], 7),
        (
            vec![
                Node::enumeration(ENDPOINT_ROLE, 2),
                Node::enumeration(ENDPOINT_ROLE, 2),
            ],
            7,
        ),
        (
            vec![
                Node::enumeration(ENDPOINT_ROLE, 2),
                Node::text(UNIQUE_IDENTIFIER, "x"),
            ],
            8,
        ),
    ] {
        let r = f
            .engine
            .process_reversible("alice", &set_role(v, payload), None, &[])
            .unwrap();
        assert_eq!(result(&r), Err(reason));
    }
}

#[test]
fn only_a_committed_batch_reverses_the_channel_and_the_last_role_wins() {
    let mut f = fixture(Some(Version(2, 1)));
    let v = Version(2, 1);
    let missing = vec![Node::text(UNIQUE_IDENTIFIER, "missing")];
    // Undo: a later failure undoes the accepted role.
    let r = f
        .engine
        .process_reversible(
            "alice",
            &request(
                v,
                vec![
                    (SET_ENDPOINT_ROLE, role(ROLE_CLIENT)),
                    (10, missing.clone()),
                ],
                Some(3),
            ),
            None,
            &[],
        )
        .unwrap();
    assert!(!reversal_accepted(&r));
    // Continue: the accepted role stands.
    let r = f
        .engine
        .process_reversible(
            "alice",
            &request(
                v,
                vec![(SET_ENDPOINT_ROLE, role(ROLE_CLIENT)), (10, missing)],
                Some(1),
            ),
            None,
            &[],
        )
        .unwrap();
    assert!(reversal_accepted(&r));
    // A later Server role in the same batch applies to subsequent messages.
    let r = f
        .engine
        .process_reversible(
            "alice",
            &request(
                v,
                vec![
                    (SET_ENDPOINT_ROLE, role(ROLE_CLIENT)),
                    (SET_ENDPOINT_ROLE, role(ROLE_SERVER)),
                ],
                None,
            ),
            None,
            &[],
        )
        .unwrap();
    assert!(!reversal_accepted(&r));
}
