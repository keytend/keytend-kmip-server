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

// Draft 3.0 (CSD02) asynchronous processing: Asynchronous Indicator
// Mandatory/Optional/Prohibited, Poll of a request item that expanded into
// several results (section 11.60), Cancel, Process, Query Asynchronous
// Requests, identity and version scoping. The 2.x rules are in
// tests/asynchronous.rs.

use keytend_kmip_server::{
    credentials::{PasswordVerifier, PolicyUser},
    protocol::{Engine, Version},
    store::Store,
    tags::*,
    ttlv::{Node, Value},
};

const V3: Version = Version(3, 0);
const V21: Version = Version(2, 1);
const CREATE: u32 = 1;
const CREATE_KEY_PAIR: u32 = 2;
const LOCATE: u32 = 8;
const GET: u32 = 10;
const QUERY: u32 = 24;
const CANCEL: u32 = 25;
const POLL: u32 = 26;
const QUERY_ASYNC: u32 = 57;
const PROCESS: u32 = 58;
const MANDATORY: u32 = 1;
const OPTIONAL: u32 = 2;
const PROHIBITED: u32 = 3;
/// Unique Identifier Enumeration Locate (draft 3.0 table 607).
const LOCATE_RESULTS: u32 = 11;

struct Fixture {
    engine: Engine,
    _directory: tempfile::TempDir,
}
impl Fixture {
    fn new() -> Self {
        let directory = tempfile::tempdir().unwrap();
        let master = directory.path().join("master");
        std::fs::write(&master, [9; 32]).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&master, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        let store = Store::open(&directory.path().join("store.sqlite"), &master).unwrap();
        Self {
            engine: Engine::new(store, true),
            _directory: directory,
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
    fn one(&mut self, owner: &str, v: Version, op: u32, payload: Vec<Node>) -> Node {
        self.send(owner, v, vec![], vec![(op, payload)])
            .into_iter()
            .next()
            .unwrap()
    }
    fn poll(&mut self, owner: &str, v: Version, value: &[u8]) -> Vec<Node> {
        self.send(owner, v, vec![], vec![(POLL, acv(value))])
    }
}
fn indicator(mode: u32) -> Vec<Node> {
    vec![Node::enumeration(ASYNCHRONOUS_INDICATOR, mode)]
}
fn status(item: &Node) -> u32 {
    item.required(RESULT_STATUS).unwrap().number().unwrap()
}
fn reason(item: &Node) -> u32 {
    item.required(RESULT_REASON).unwrap().number().unwrap()
}
fn operation(item: &Node) -> u32 {
    item.required(OPERATION).unwrap().number().unwrap()
}
fn correlation(item: &Node) -> Vec<u8> {
    item.required(ASYNCHRONOUS_CORRELATION_VALUE)
        .unwrap()
        .byte_string()
        .unwrap()
        .to_vec()
}
fn acv(value: &[u8]) -> Vec<Node> {
    vec![Node::bytes(ASYNCHRONOUS_CORRELATION_VALUE, value.to_vec())]
}
fn aes() -> Vec<Node> {
    vec![
        Node::enumeration(OBJECT_TYPE, 2),
        Node::structure(
            ATTRIBUTES,
            vec![
                Node::enumeration(CRYPTOGRAPHIC_ALGORITHM, 3),
                Node::int(CRYPTOGRAPHIC_LENGTH, 256),
                Node::int(CRYPTOGRAPHIC_USAGE_MASK, 12),
            ],
        ),
    ]
}
fn locate_all() -> Vec<Node> {
    vec![Node::structure(
        ATTRIBUTES,
        vec![Node::enumeration(OBJECT_TYPE, 2)],
    )]
}
fn get_located() -> Vec<Node> {
    vec![Node::enumeration(UNIQUE_IDENTIFIER, LOCATE_RESULTS)]
}
fn identifier(item: &Node) -> String {
    item.required(RESPONSE_PAYLOAD)
        .unwrap()
        .required(UNIQUE_IDENTIFIER)
        .unwrap()
        .identifier_text()
        .unwrap()
        .to_owned()
}
fn cancellation(item: &Node) -> u32 {
    item.required(RESPONSE_PAYLOAD)
        .unwrap()
        .required(CANCELLATION_RESULT)
        .unwrap()
        .number()
        .unwrap()
}
fn listed(item: &Node) -> Vec<Node> {
    item.required(RESPONSE_PAYLOAD)
        .unwrap()
        .all(ASYNCHRONOUS_REQUEST)
        .cloned()
        .collect()
}

// REQ:ec42c0df7db06381 Mandatory: every batch item is deferred with its own correlation value
// REQ:50e0e097d2d7aaf4 an incomplete operation polls with no payload and Pending
// REQ:bb13b6343c6f5fb8 a completed operation polls with its payload
#[test]
fn draft_mandatory_defers_every_item_and_poll_returns_each_result() {
    let mut f = Fixture::new();
    let pending = f.send(
        "alice",
        V3,
        indicator(MANDATORY),
        vec![(CREATE, aes()), (QUERY, vec![])],
    );
    assert_eq!(pending.len(), 2);
    let mut values = vec![];
    for (item, op) in pending.iter().zip([CREATE, QUERY]) {
        assert_eq!(status(item), 2);
        assert_eq!(operation(item), op);
        // Draft 3.0 removed the Unique Batch Item ID.
        assert!(item.get(UNIQUE_BATCH_ITEM_ID).is_none());
        assert!(item.get(RESPONSE_PAYLOAD).is_none());
        values.push(correlation(item));
    }
    assert_ne!(values[0], values[1]);
    assert_eq!(values[0].len(), 16);
    assert!(f.engine.store.list("alice").unwrap().is_empty());
    let early = f.poll("alice", V3, &values[0]);
    assert_eq!(early.len(), 1);
    assert_eq!(status(&early[0]), 2);
    assert_eq!(correlation(&early[0]), values[0]);
    assert!(early[0].get(RESPONSE_PAYLOAD).is_none());
    assert!(f.engine.run_asynchronous());
    assert_eq!(f.engine.store.list("alice").unwrap().len(), 1);
    let created = f.poll("alice", V3, &values[0]);
    assert_eq!(created.len(), 1);
    assert_eq!((status(&created[0]), operation(&created[0])), (0, POLL));
    // The stored result keeps the draft 3.0 Identifier encoding.
    assert!(matches!(
        created[0]
            .required(RESPONSE_PAYLOAD)
            .unwrap()
            .required(UNIQUE_IDENTIFIER)
            .unwrap()
            .value,
        Value::Identifier(_)
    ));
    let query = f.poll("alice", V3, &values[1]);
    assert_eq!((status(&query[0]), operation(&query[0])), (0, POLL));
    // Without the indicator, or with Prohibited, nothing is deferred.
    for header in [vec![], indicator(PROHIBITED)] {
        let r = f.send("alice", V3, header, vec![(CREATE, aes())]);
        assert_eq!(status(&r[0]), 0);
        assert!(r[0].get(ASYNCHRONOUS_CORRELATION_VALUE).is_none());
    }
    // An unknown Asynchronous Indicator value.
    let r = f.send("alice", V3, indicator(7), vec![(QUERY, vec![])]);
    assert_eq!(reason(&r[0]), 7);
}

// REQ:893468adfeef4819 Poll answers as the synchronous response would: an expanded item yields every result
#[test]
fn poll_of_an_expanded_item_returns_every_result_in_order() {
    for v in [V3, V21] {
        let mut f = Fixture::new();
        f.send("alice", v, vec![], vec![(CREATE, aes()), (CREATE, aes())]);
        let identifier_of = |n: &Node| identifier(n);
        // Synchronously, Get with the Locate enumeration repeats per object.
        let sync = f.send(
            "alice",
            v,
            vec![],
            vec![(LOCATE, locate_all()), (GET, get_located())],
        );
        assert_eq!(sync.len(), 3, "{v:?}");
        let expected = sync[1..].iter().map(identifier_of).collect::<Vec<_>>();
        let pending = f.send(
            "alice",
            v,
            indicator(MANDATORY),
            vec![(LOCATE, locate_all()), (GET, get_located())],
        );
        assert_eq!(pending.len(), 2, "one correlation value per request item");
        let get = correlation(&pending[1]);
        // Still pending: one Pending item.
        assert_eq!(
            f.poll("alice", v, &get)
                .iter()
                .map(status)
                .collect::<Vec<_>>(),
            [2]
        );
        assert!(f.engine.run_asynchronous());
        for _ in 0..2 {
            let results = f.poll("alice", v, &get);
            assert_eq!(results.len(), 2, "{v:?}");
            for item in &results {
                assert_eq!((status(item), operation(item)), (0, POLL));
                if v.0 < 3 {
                    assert_eq!(
                        item.required(UNIQUE_BATCH_ITEM_ID)
                            .unwrap()
                            .byte_string()
                            .unwrap(),
                        [0]
                    );
                }
            }
            assert_eq!(
                results.iter().map(identifier_of).collect::<Vec<_>>(),
                expected
            );
        }
        // Both results succeeded.
        assert_eq!(cancellation(&f.one("alice", v, CANCEL, acv(&get))), 3);
        let located = f.poll("alice", v, &correlation(&pending[0]));
        assert_eq!(located.len(), 1);
        // A Poll after a Poll in one batch: each item expands on its own.
        let both = f.send(
            "alice",
            v,
            vec![],
            vec![(POLL, acv(&get)), (POLL, acv(&correlation(&pending[0])))],
        );
        assert_eq!(both.iter().map(status).collect::<Vec<_>>(), [0, 0, 0]);
    }
}

#[test]
fn a_failed_expanded_result_fails_the_poll_item_under_stop() {
    let mut f = Fixture::new();
    f.send("alice", V3, vec![], vec![(CREATE, aes())]);
    let pending = f.send(
        "alice",
        V3,
        indicator(MANDATORY),
        vec![(LOCATE, locate_all()), (GET, get_located())],
    );
    f.engine.run_asynchronous();
    // A Get of a missing object fails when the batch runs.
    let failing = f.send(
        "alice",
        V3,
        indicator(MANDATORY),
        vec![(GET, vec![Node::identifier(UNIQUE_IDENTIFIER, "missing")])],
    );
    f.engine.run_asynchronous();
    let value = correlation(&failing[0]);
    assert_eq!(cancellation(&f.one("alice", V3, CANCEL, acv(&value))), 4);
    // Stop (the default): the failed Poll item ends the batch.
    let r = f.send(
        "alice",
        V3,
        vec![],
        vec![(POLL, acv(&value)), (POLL, acv(&correlation(&pending[1])))],
    );
    assert_eq!(r.iter().map(status).collect::<Vec<_>>(), [1]);
    // The stored failure: Object Not Found (draft 3.0 table 595).
    assert_eq!(reason(&r[0]), 0x37);
}

// REQ:b042961d23273925 Optional: the server chooses per request
#[test]
fn draft_optional_defers_only_key_pair_generation() {
    let mut f = Fixture::new();
    let r = f.send("alice", V3, indicator(OPTIONAL), vec![(CREATE, aes())]);
    assert_eq!(status(&r[0]), 0);
    let r = f.send(
        "alice",
        V3,
        indicator(OPTIONAL),
        vec![(CREATE_KEY_PAIR, vec![Node::text(UNIQUE_IDENTIFIER, "bad")])],
    );
    assert_eq!(status(&r[0]), 2);
    assert!(f.engine.run_asynchronous());
    let polled = f.poll("alice", V3, &correlation(&r[0]));
    assert_eq!(status(&polled[0]), 1);
}

// REQ:4dd4359dc48be99e Poll (and Cancel, Process, Query Asynchronous Requests) are never asynchronous
#[test]
fn draft_mandatory_refuses_synchronous_only_operations() {
    let mut f = Fixture::new();
    for op in [POLL, CANCEL, PROCESS, QUERY_ASYNC] {
        let r = f.send(
            "alice",
            V3,
            indicator(MANDATORY),
            vec![(QUERY, vec![]), (op, acv(&[1]))],
        );
        assert_eq!(r.len(), 1);
        assert_eq!(reason(&r[0]), 7, "operation {op}");
    }
    // Login is bound to the requesting TLS connection (the ticket records
    // the certificate that obtained it), so it is never deferred either.
    let r = f.send(
        "alice",
        V3,
        indicator(MANDATORY),
        vec![(QUERY, vec![]), (45, vec![])],
    );
    assert_eq!(r.len(), 1);
    assert_eq!(reason(&r[0]), 7, "Login");
    assert!(!f.engine.asynchronous_pending());
}

// REQ:1aa732ed98225ee6 after Process the next Poll is not Pending
// REQ:d1a606c22b3d2fab REQ:d61437b8f380d28b REQ:b579ba3a70e8c2fe Query Asynchronous Requests filters
#[test]
fn draft_cancel_process_and_query_asynchronous_requests() {
    let mut f = Fixture::new();
    let r = f.send(
        "alice",
        V3,
        indicator(MANDATORY),
        vec![(CREATE, aes()), (QUERY, vec![])],
    );
    let values = r.iter().map(correlation).collect::<Vec<_>>();
    let all = listed(&f.one("alice", V3, QUERY_ASYNC, vec![]));
    assert_eq!(all.len(), 2);
    for request in &all {
        assert_eq!(
            request
                .required(PROCESSING_STAGE)
                .unwrap()
                .number()
                .unwrap(),
            1
        );
        assert!(matches!(
            request.required(SUBMISSION_DATE).unwrap().value,
            Value::DateTimeExtended(_)
        ));
    }
    let creates = listed(&f.one(
        "alice",
        V3,
        QUERY_ASYNC,
        vec![Node::structure(
            OPERATIONS,
            vec![Node::enumeration(OPERATION, CREATE)],
        )],
    ));
    assert_eq!(creates.len(), 1);
    assert_eq!(correlation(&creates[0]), values[0]);
    let by_value = listed(&f.one(
        "alice",
        V3,
        QUERY_ASYNC,
        vec![Node::structure(
            ASYNCHRONOUS_CORRELATION_VALUES,
            vec![Node::bytes(
                ASYNCHRONOUS_CORRELATION_VALUE,
                values[1].clone(),
            )],
        )],
    ));
    assert_eq!(by_value.len(), 1);
    assert_eq!(correlation(&by_value[0]), values[1]);
    // Cancel the Query before the batch runs; Process the Create.
    assert_eq!(
        cancellation(&f.one("alice", V3, CANCEL, acv(&values[1]))),
        1
    );
    assert_eq!(status(&f.one("alice", V3, PROCESS, acv(&values[0]))), 0);
    assert!(!f.engine.asynchronous_pending());
    assert_eq!(status(&f.poll("alice", V3, &values[0])[0]), 0);
    let canceled = f.poll("alice", V3, &values[1]);
    // Operation Canceled By Requester.
    assert_eq!((status(&canceled[0]), reason(&canceled[0])), (1, 9));
    // Both results were obtained.
    assert!(listed(&f.one("alice", V3, QUERY_ASYNC, vec![])).is_empty());
    // Malformed filters.
    let bad = f.one(
        "alice",
        V3,
        QUERY_ASYNC,
        vec![Node::structure(
            OPERATIONS,
            vec![Node::int(QUERY_FUNCTION, 1)],
        )],
    );
    assert_eq!(status(&bad), 1);
}

#[test]
fn draft_correlation_values_are_identity_and_version_scoped() {
    let mut f = Fixture::new();
    let r = f.send("alice", V3, indicator(MANDATORY), vec![(CREATE, aes())]);
    let value = correlation(&r[0]);
    // Invalid Asynchronous Correlation Value (draft 3.0 table 386).
    let other = f.poll("bob", V3, &value);
    assert_eq!((status(&other[0]), reason(&other[0])), (1, 0x2b));
    assert_eq!(reason(&f.one("bob", V3, PROCESS, acv(&value))), 0x2b);
    // Cancellation Result Unavailable for an unknown value.
    assert_eq!(cancellation(&f.one("bob", V3, CANCEL, acv(&value))), 5);
    assert!(listed(&f.one("bob", V3, QUERY_ASYNC, vec![])).is_empty());
    // The same principal under 2.1 does not see the draft request.
    assert_eq!(reason(&f.poll("alice", V21, &value)[0]), 0x2b);
    assert!(listed(&f.one("alice", V21, QUERY_ASYNC, vec![])).is_empty());
    // A client cannot select a stored result index itself.
    let forged = f.one(
        "alice",
        V3,
        POLL,
        vec![
            Node::bytes(ASYNCHRONOUS_CORRELATION_VALUE, value.clone()),
            Node::int(0x54ff_ff01, 0),
        ],
    );
    assert_eq!(status(&forged), 1);
    assert_eq!(status(&f.poll("alice", V3, &value)[0]), 2);
}

fn password(name: &str) -> Node {
    Node::structure(
        AUTHENTICATION,
        vec![Node::structure(
            CREDENTIAL,
            vec![
                Node::enumeration(CREDENTIAL_TYPE, 1),
                Node::structure(
                    CREDENTIAL_VALUE,
                    vec![
                        Node::text(USERNAME, name),
                        Node::text(PASSWORD, name.to_lowercase()),
                    ],
                ),
            ],
        )],
    )
}

#[test]
fn under_credential_identity_only_the_submitting_user_sees_its_request() {
    let mut f = Fixture::new();
    let user = |name: &str| PolicyUser {
        username: name.into(),
        password_scrypt: PasswordVerifier::new(name.to_lowercase().as_bytes()).unwrap(),
        administrator: false,
        hashed_password: None,
        one_time_password: None,
    };
    f.engine
        .add_policy_users("alice", vec![user("Fred"), user("Barney")])
        .unwrap();
    f.engine.use_credential_identity("alice");
    let r = f.send(
        "alice",
        V3,
        vec![indicator(MANDATORY).remove(0), password("Fred")],
        vec![(CREATE, aes())],
    );
    let value = correlation(&r[0]);
    // The queued message keeps no password; the verified user runs it.
    assert!(f.engine.run_asynchronous());
    assert_eq!(f.engine.store.list("alice\0user\0Fred").unwrap().len(), 1);
    assert!(f.engine.store.list("alice").unwrap().is_empty());
    let fred = f.send(
        "alice",
        V3,
        vec![password("Fred")],
        vec![(POLL, acv(&value))],
    );
    assert_eq!(status(&fred[0]), 0);
    let barney = f.send(
        "alice",
        V3,
        vec![password("Barney")],
        vec![(POLL, acv(&value))],
    );
    assert_eq!(reason(&barney[0]), 0x2b);
    // The certificate principal without credentials is another identity.
    assert_eq!(reason(&f.poll("alice", V3, &value)[0]), 0x2b);
}

#[test]
fn draft_query_advertises_asynchronous_operations_and_capability() {
    let mut f = Fixture::new();
    let r = f.one(
        "alice",
        V3,
        QUERY,
        vec![
            Node::enumeration(QUERY_FUNCTION, 1),
            Node::enumeration(QUERY_FUNCTION, 11),
        ],
    );
    let payload = r.required(RESPONSE_PAYLOAD).unwrap();
    let ops = payload
        .all(OPERATION)
        .map(|n| n.number().unwrap())
        .collect::<Vec<_>>();
    for op in [CANCEL, POLL, QUERY_ASYNC, PROCESS, 0x37, 0x38] {
        assert!(ops.contains(&op), "operation {op:#x}");
    }
    assert!(
        payload
            .required(CAPABILITY_INFORMATION)
            .unwrap()
            .required(ASYNCHRONOUS_CAPABILITY)
            .unwrap()
            .flag()
            .unwrap()
    );
    // Set Defaults, Set Constraints and Get Constraints are 2.1 operations.
    let r = f.one(
        "alice",
        V21,
        QUERY,
        vec![Node::enumeration(QUERY_FUNCTION, 1)],
    );
    let ops = r
        .required(RESPONSE_PAYLOAD)
        .unwrap()
        .all(OPERATION)
        .map(|n| n.number().unwrap())
        .collect::<Vec<_>>();
    assert!(ops.contains(&0x36) && ops.contains(&0x37) && ops.contains(&0x38));
}
