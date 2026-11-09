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

// Asynchronous processing: Operation Pending, Poll, Cancel, Process, Query
// Asynchronous Requests, owner scoping, queue limits, batch semantics of a
// deferred message, and the truthful Query capability.

use keytend_kmip_server::{
    protocol::{Engine, Version},
    store::Store,
    tags::*,
    ttlv::Node,
};

const CREATE: u32 = 1;
const CREATE_KEY_PAIR: u32 = 2;
const GET: u32 = 10;
const QUERY: u32 = 24;
const CANCEL: u32 = 25;
const POLL: u32 = 26;
const QUERY_ASYNC: u32 = 57;
const PROCESS: u32 = 58;
const MANDATORY: u32 = 1;
const OPTIONAL: u32 = 2;

struct Fixture {
    engine: Engine,
    _directory: tempfile::TempDir,
}
impl Fixture {
    fn new() -> Self {
        let directory = tempfile::tempdir().unwrap();
        let master = directory.path().join("master");
        std::fs::write(&master, [7; 32]).unwrap();
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
    ) -> Node {
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
    }
    fn one(&mut self, owner: &str, v: Version, op: u32, payload: Vec<Node>) -> Node {
        let r = self.send(owner, v, vec![], vec![(op, payload)]);
        r.all(BATCH_ITEM).next().unwrap().clone()
    }
}
fn indicator(v: Version, mode: u32) -> Vec<Node> {
    vec![if v.0 == 1 {
        Node::boolean(ASYNCHRONOUS_INDICATOR, mode == OPTIONAL)
    } else {
        Node::enumeration(ASYNCHRONOUS_INDICATOR, mode)
    }]
}
fn items(r: &Node) -> Vec<Node> {
    r.all(BATCH_ITEM).cloned().collect()
}
fn status(item: &Node) -> u32 {
    item.required(RESULT_STATUS).unwrap().number().unwrap()
}
fn reason(item: &Node) -> u32 {
    item.required(RESULT_REASON).unwrap().number().unwrap()
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
fn aes(v: Version) -> Vec<Node> {
    let attrs = vec![
        Node::enumeration(CRYPTOGRAPHIC_ALGORITHM, 3),
        Node::int(CRYPTOGRAPHIC_LENGTH, 256),
        Node::int(CRYPTOGRAPHIC_USAGE_MASK, 12),
    ];
    let container = if v.0 >= 2 {
        Node::structure(ATTRIBUTES, attrs)
    } else {
        Node::structure(
            TEMPLATE_ATTRIBUTE,
            attrs
                .into_iter()
                .zip([
                    "Cryptographic Algorithm",
                    "Cryptographic Length",
                    "Cryptographic Usage Mask",
                ])
                .map(|(mut a, name)| {
                    a.tag = ATTRIBUTE_VALUE;
                    Node::structure(ATTRIBUTE, vec![Node::text(ATTRIBUTE_NAME, name), a])
                })
                .collect(),
        )
    };
    vec![Node::enumeration(OBJECT_TYPE, 2), container]
}
/// A Create Key Pair payload that fails when executed.
fn bad_pair() -> Vec<Node> {
    vec![Node::text(UNIQUE_IDENTIFIER, "not a Create Key Pair field")]
}
fn cancellation(item: &Node) -> u32 {
    item.required(RESPONSE_PAYLOAD)
        .unwrap()
        .required(CANCELLATION_RESULT)
        .unwrap()
        .number()
        .unwrap()
}

#[test]
fn mandatory_create_is_pending_until_run_and_poll_returns_the_result() {
    for v in [Version(2, 0), Version(2, 1)] {
        let mut f = Fixture::new();
        let r = f.send("alice", v, indicator(v, MANDATORY), vec![(CREATE, aes(v))]);
        let item = &items(&r)[0];
        assert_eq!(status(item), 2);
        assert_eq!(item.required(OPERATION).unwrap().number().unwrap(), CREATE);
        assert!(item.get(RESPONSE_PAYLOAD).is_none());
        let value = correlation(item);
        assert_eq!(value.len(), 16);
        // Nothing runs before the queue does.
        assert!(f.engine.store.list("alice").unwrap().is_empty());
        let pending = f.one("alice", v, POLL, acv(&value));
        assert_eq!(status(&pending), 2);
        assert_eq!(correlation(&pending), value);
        assert!(pending.get(RESPONSE_PAYLOAD).is_none());
        assert!(f.engine.asynchronous_pending());
        assert!(f.engine.run_asynchronous());
        assert!(!f.engine.asynchronous_pending());
        assert_eq!(f.engine.store.list("alice").unwrap().len(), 1);
        for _ in 0..2 {
            let done = f.one("alice", v, POLL, acv(&value));
            assert_eq!(status(&done), 0);
            assert_eq!(done.required(OPERATION).unwrap().number().unwrap(), POLL);
            assert!(done.get(ASYNCHRONOUS_CORRELATION_VALUE).is_none());
            let payload = done.required(RESPONSE_PAYLOAD).unwrap();
            assert_eq!(payload.required(OBJECT_TYPE).unwrap().number().unwrap(), 2);
            assert!(payload.get(UNIQUE_IDENTIFIER).is_some());
        }
        assert_eq!(cancellation(&f.one("alice", v, CANCEL, acv(&value))), 3);
        f.engine.store.verify_audit().unwrap();
    }
}

// REQ:ec42c0df7db06381 2.0/2.1 Mandatory: every batch item is deferred, each with its own correlation value
#[test]
fn mandatory_defers_every_batch_item_with_its_own_correlation_value() {
    for v in [Version(2, 0), Version(2, 1)] {
        let mut f = Fixture::new();
        // Query is not long-running: Allowed would run it synchronously, but
        // Mandatory defers it as well.
        let r = f.send(
            "alice",
            v,
            indicator(v, MANDATORY),
            vec![(CREATE, aes(v)), (QUERY, vec![]), (CREATE, aes(v))],
        );
        let all = items(&r);
        assert_eq!(all.len(), 3);
        let mut values = vec![];
        for (index, item) in all.iter().enumerate() {
            assert_eq!(status(item), 2, "{v:?} item {index} is Operation Pending");
            assert!(item.get(RESPONSE_PAYLOAD).is_none());
            assert_eq!(
                item.required(UNIQUE_BATCH_ITEM_ID)
                    .unwrap()
                    .byte_string()
                    .unwrap(),
                [index as u8]
            );
            values.push(correlation(item));
        }
        values.sort();
        values.dedup();
        assert_eq!(values.len(), 3, "distinct correlation values");
        assert!(f.engine.store.list("alice").unwrap().is_empty());
        assert!(f.engine.run_asynchronous());
        assert_eq!(f.engine.store.list("alice").unwrap().len(), 2);
        for value in &values {
            assert_eq!(status(&f.one("alice", v, POLL, acv(value))), 0);
        }
        // Without the indicator the same batch runs synchronously.
        let r = f.send("alice", v, vec![], vec![(CREATE, aes(v)), (QUERY, vec![])]);
        assert!(items(&r).iter().all(|item| status(item) == 0));
    }
}

#[test]
fn cancel_before_execution_prevents_the_operation() {
    let v = Version(2, 1);
    let mut f = Fixture::new();
    let r = f.send("alice", v, indicator(v, MANDATORY), vec![(CREATE, aes(v))]);
    let value = correlation(&items(&r)[0]);
    let canceled = f.one("alice", v, CANCEL, acv(&value));
    assert_eq!(status(&canceled), 0);
    assert_eq!(
        canceled
            .required(RESPONSE_PAYLOAD)
            .unwrap()
            .required(ASYNCHRONOUS_CORRELATION_VALUE)
            .unwrap()
            .byte_string()
            .unwrap(),
        value
    );
    assert_eq!(cancellation(&canceled), 1);
    assert!(f.engine.run_asynchronous());
    assert!(f.engine.store.list("alice").unwrap().is_empty());
    let polled = f.one("alice", v, POLL, acv(&value));
    assert_eq!(status(&polled), 1);
    // Operation Canceled By Requester.
    assert_eq!(reason(&polled), 9);
    assert_eq!(cancellation(&f.one("alice", v, CANCEL, acv(&value))), 1);
}

#[test]
fn correlation_values_are_owner_and_version_scoped() {
    let v = Version(2, 1);
    let mut f = Fixture::new();
    let r = f.send("alice", v, indicator(v, MANDATORY), vec![(CREATE, aes(v))]);
    let value = correlation(&items(&r)[0]);
    // Another principal learns nothing and cannot cancel.
    let polled = f.one("bob", v, POLL, acv(&value));
    assert_eq!((status(&polled), reason(&polled)), (1, 0x2b));
    assert_eq!(cancellation(&f.one("bob", v, CANCEL, acv(&value))), 5);
    let processed = f.one("bob", v, PROCESS, acv(&value));
    assert_eq!(reason(&processed), 0x2b);
    // The same principal under another protocol version.
    let other = f.one("alice", Version(2, 0), POLL, acv(&value));
    assert_eq!(reason(&other), 0x2b);
    // KMIP 1.4 table 352: Item Not Found.
    let legacy = f.one("alice", Version(1, 4), POLL, acv(&[1, 2, 3]));
    assert_eq!(reason(&legacy), 1);
    assert_eq!(
        cancellation(&f.one("alice", Version(1, 4), CANCEL, acv(&[1, 2, 3]))),
        5
    );
    // A malformed Poll payload.
    assert_eq!(reason(&f.one("alice", v, POLL, vec![])), 7);
    assert_eq!(
        reason(&f.one(
            "alice",
            v,
            POLL,
            vec![Node::text(ASYNCHRONOUS_CORRELATION_VALUE, "x")]
        )),
        7
    );
    // Still pending for its owner.
    assert_eq!(status(&f.one("alice", v, POLL, acv(&value))), 2);
}

#[test]
fn optional_and_one_x_true_defer_only_key_pair_generation() {
    for v in [Version(1, 4), Version(2, 1)] {
        let mut f = Fixture::new();
        let r = f.send("alice", v, indicator(v, OPTIONAL), vec![(CREATE, aes(v))]);
        assert_eq!(status(&items(&r)[0]), 0);
        assert!(items(&r)[0].get(ASYNCHRONOUS_CORRELATION_VALUE).is_none());
        // A key pair batch is deferred; this one is malformed and fails when run.
        let r = f.send(
            "alice",
            v,
            indicator(v, OPTIONAL),
            vec![(CREATE, aes(v)), (CREATE_KEY_PAIR, bad_pair())],
        );
        let pending = items(&r);
        assert_eq!(pending.iter().map(status).collect::<Vec<_>>(), [2, 2]);
        assert_eq!(f.engine.store.list("alice").unwrap().len(), 1);
        assert!(f.engine.run_asynchronous());
        // Default Stop: the Create ran, the key pair item failed.
        assert_eq!(f.engine.store.list("alice").unwrap().len(), 2);
        let first = f.one("alice", v, POLL, acv(&correlation(&pending[0])));
        assert_eq!(status(&first), 0);
        let second = f.one("alice", v, POLL, acv(&correlation(&pending[1])));
        assert_eq!(status(&second), 1);
        // Without the indicator nothing is deferred.
        let r = f.send("alice", v, vec![], vec![(CREATE_KEY_PAIR, bad_pair())]);
        assert_eq!(status(&items(&r)[0]), 1);
        assert!(!f.engine.asynchronous_pending());
    }
}

#[test]
fn stop_and_undo_semantics_apply_to_the_deferred_batch() {
    let v = Version(2, 1);
    let mut f = Fixture::new();
    let missing = vec![Node::text(UNIQUE_IDENTIFIER, "missing")];
    // Stop: the second item is never processed and Poll says so.
    let r = f.send(
        "alice",
        v,
        indicator(v, MANDATORY),
        vec![(GET, missing.clone()), (CREATE, aes(v))],
    );
    let values = items(&r).iter().map(correlation).collect::<Vec<_>>();
    f.engine.run_asynchronous();
    assert!(f.engine.store.list("alice").unwrap().is_empty());
    assert_eq!(status(&f.one("alice", v, POLL, acv(&values[0]))), 1);
    let skipped = f.one("alice", v, POLL, acv(&values[1]));
    assert_eq!((status(&skipped), reason(&skipped)), (1, 0x100));
    // Undo: the Create is undone and its object rolled back.
    let mut header = indicator(v, MANDATORY);
    header.push(Node::enumeration(BATCH_ERROR_CONTINUATION_OPTION, 3));
    let r = f.send("alice", v, header, vec![(CREATE, aes(v)), (GET, missing)]);
    let values = items(&r).iter().map(correlation).collect::<Vec<_>>();
    f.engine.run_asynchronous();
    assert!(f.engine.store.list("alice").unwrap().is_empty());
    assert_eq!(status(&f.one("alice", v, POLL, acv(&values[0]))), 3);
    assert_eq!(cancellation(&f.one("alice", v, CANCEL, acv(&values[0]))), 4);
    // A Cancel inside an undone batch has no effect.
    let r = f.send("alice", v, indicator(v, MANDATORY), vec![(CREATE, aes(v))]);
    let value = correlation(&items(&r)[0]);
    let undone = f.send(
        "alice",
        v,
        vec![Node::enumeration(BATCH_ERROR_CONTINUATION_OPTION, 3)],
        vec![
            (CANCEL, acv(&value)),
            (GET, vec![Node::text(UNIQUE_IDENTIFIER, "missing")]),
        ],
    );
    assert_eq!(
        items(&undone).iter().map(status).collect::<Vec<_>>(),
        [3, 1]
    );
    f.engine.run_asynchronous();
    assert_eq!(status(&f.one("alice", v, POLL, acv(&value))), 0);
    assert_eq!(f.engine.store.list("alice").unwrap().len(), 1);
}

#[test]
fn mandatory_refuses_synchronous_only_operations_and_bounds_the_queue() {
    let v = Version(2, 1);
    let mut f = Fixture::new();
    for op in [POLL, CANCEL, PROCESS, QUERY_ASYNC] {
        let r = f.send(
            "alice",
            v,
            indicator(v, MANDATORY),
            vec![(QUERY, vec![]), (op, acv(&[1]))],
        );
        let item = &items(&r)[0];
        assert!(item.get(OPERATION).is_none());
        assert_eq!(reason(item), 7);
    }
    for _ in 0..8 {
        let r = f.send("alice", v, indicator(v, MANDATORY), vec![(QUERY, vec![])]);
        assert_eq!(status(&items(&r)[0]), 2);
    }
    // The ninth Mandatory request exceeds the per-principal bound.
    let r = f.send("alice", v, indicator(v, MANDATORY), vec![(QUERY, vec![])]);
    assert_eq!(reason(&items(&r)[0]), 0x3a);
    // Optional falls back to synchronous processing (here, a failure).
    let r = f.send(
        "alice",
        v,
        indicator(v, OPTIONAL),
        vec![(CREATE_KEY_PAIR, bad_pair())],
    );
    assert_eq!(status(&items(&r)[0]), 1);
    // Another principal still has room.
    let r = f.send("bob", v, indicator(v, MANDATORY), vec![(QUERY, vec![])]);
    assert_eq!(status(&items(&r)[0]), 2);
    // Draft 3.0 shares the per-principal bound (tests/asynchronous_v3.rs).
    let r = f.send(
        "alice",
        Version(3, 0),
        indicator(Version(3, 0), MANDATORY),
        vec![(QUERY, vec![])],
    );
    assert_eq!(reason(&items(&r)[0]), 0x3a);
}

// REQ:1e70d2566b3b43b2 after Process the next Poll of that request is not Pending
#[test]
fn process_and_query_asynchronous_requests() {
    let v = Version(2, 1);
    let mut f = Fixture::new();
    let r = f.send(
        "alice",
        v,
        indicator(v, MANDATORY),
        vec![(CREATE, aes(v)), (QUERY, vec![])],
    );
    let values = items(&r).iter().map(correlation).collect::<Vec<_>>();
    let listed = f.one("alice", v, QUERY_ASYNC, vec![]);
    let requests = listed
        .required(RESPONSE_PAYLOAD)
        .unwrap()
        .all(ASYNCHRONOUS_REQUEST)
        .cloned()
        .collect::<Vec<_>>();
    assert_eq!(requests.len(), 2);
    for request in &requests {
        assert_eq!(
            request
                .required(PROCESSING_STAGE)
                .unwrap()
                .number()
                .unwrap(),
            1
        );
        assert!(request.get(SUBMISSION_DATE).is_some());
    }
    let only_create = f.one(
        "alice",
        v,
        QUERY_ASYNC,
        vec![Node::structure(
            OPERATIONS,
            vec![Node::enumeration(OPERATION, CREATE)],
        )],
    );
    assert_eq!(
        only_create
            .required(RESPONSE_PAYLOAD)
            .unwrap()
            .all(ASYNCHRONOUS_REQUEST)
            .count(),
        1
    );
    assert_eq!(
        f.one("bob", v, QUERY_ASYNC, vec![])
            .required(RESPONSE_PAYLOAD)
            .unwrap()
            .all(ASYNCHRONOUS_REQUEST)
            .count(),
        0
    );
    // Process: the next Poll is not Pending, without the background runner.
    let processed = f.one("alice", v, PROCESS, acv(&values[0]));
    assert_eq!(status(&processed), 0);
    assert!(!f.engine.asynchronous_pending());
    assert_eq!(status(&f.one("alice", v, POLL, acv(&values[0]))), 0);
    // Only the unobtained result is still reported, now Completed.
    let listed = f.one(
        "alice",
        v,
        QUERY_ASYNC,
        vec![Node::structure(
            ASYNCHRONOUS_CORRELATION_VALUES,
            values
                .iter()
                .map(|value| Node::bytes(ASYNCHRONOUS_CORRELATION_VALUE, value.clone()))
                .collect(),
        )],
    );
    assert_eq!(status(&listed), 0, "reason {}", reason(&listed));
    let requests = listed
        .required(RESPONSE_PAYLOAD)
        .unwrap()
        .all(ASYNCHRONOUS_REQUEST)
        .cloned()
        .collect::<Vec<_>>();
    assert_eq!(requests.len(), 1);
    assert_eq!(correlation(&requests[0]), values[1]);
    assert_eq!(
        requests[0]
            .required(PROCESSING_STAGE)
            .unwrap()
            .number()
            .unwrap(),
        3
    );
    // Process and Query Asynchronous Requests are 2.1 operations.
    let old = f.one("alice", Version(2, 0), PROCESS, acv(&values[0]));
    assert_eq!(reason(&old), 5);
}

#[test]
fn query_reports_asynchronous_capability_and_operations_by_version() {
    let mut f = Fixture::new();
    for (v, capable) in [
        (Version(1, 3), true),
        (Version(1, 4), true),
        (Version(2, 0), true),
        (Version(2, 1), true),
        (Version(3, 0), true),
    ] {
        let r = f.one(
            "alice",
            v,
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
        assert!(ops.contains(&CANCEL), "{}.{}", v.0, v.1);
        assert!(ops.contains(&POLL));
        assert_eq!(ops.contains(&0x2c), v.0 >= 2);
        assert_eq!(ops.contains(&0x33), v.0 >= 2);
        assert_eq!(ops.contains(&PROCESS), v >= Version(2, 1));
        assert_eq!(ops.contains(&QUERY_ASYNC), v >= Version(2, 1));
        // Interop is never advertised. Certify is implemented (all versions);
        // Notify and Put only for a principal with a client endpoint, which
        // this fixture does not configure.
        for absent in [0x34, 0x1b, 0x1c] {
            assert!(!ops.contains(&absent));
        }
        assert!(ops.contains(&6));
        let capability = payload.required(CAPABILITY_INFORMATION).unwrap();
        assert_eq!(
            capability
                .required(ASYNCHRONOUS_CAPABILITY)
                .unwrap()
                .flag()
                .unwrap(),
            capable
        );
    }
}
