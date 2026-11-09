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

//! Maximum Response Size and Response Too Large (1.4 sections 6.3, 6.10,
//! 6.13, tables 285, 327 and 366; 2.1 tables 399 and 434). For JSON and XML
//! the limit is the binary TTLV-equivalent length (Profiles 1.3-2.1 and draft
//! 3.0 sections 5.4 and 5.5), measured here by an independent oracle.
#[path = "support/ttlv_equivalent.rs"]
mod ttlv_equivalent;
use keytend_kmip_server::{
    encoding::Format,
    protocol::{Engine, Failure, Version},
    store::Store,
    tags::*,
    ttlv::Node,
};
use tempfile::TempDir;
use ttlv_equivalent::ttlv_equivalent;

const VERSIONS: [Version; 8] = [
    Version(1, 0),
    Version(1, 1),
    Version(1, 2),
    Version(1, 3),
    Version(1, 4),
    Version(2, 0),
    Version(2, 1),
    Version(3, 0),
];
/// The legacy binary API used by the native listener, then HTTPS JSON and XML.
const FORMATS: [Option<Format>; 3] = [None, Some(Format::Json), Some(Format::Xml)];
const STOP: u32 = 2;
const CONTINUE: u32 = 1;
const UNDO: u32 = 3;

struct Fixture {
    dir: TempDir,
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
    /// (operation, status) of every audit record, in order.
    fn audit(&self) -> Vec<(u32, u32)> {
        let db = rusqlite::Connection::open(self.dir.path().join("keys.sqlite")).unwrap();
        let mut query = db
            .prepare("SELECT operation,status FROM audit ORDER BY seq")
            .unwrap();
        query
            .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))
            .unwrap()
            .collect::<rusqlite::Result<Vec<_>>>()
            .unwrap()
    }
    fn create(&mut self, v: Version) -> String {
        let r = self
            .engine
            .process("alice", &batch(v, vec![create_item(v)], None, None, None))
            .unwrap();
        items(&r)[0]
            .required(RESPONSE_PAYLOAD)
            .unwrap()
            .required(UNIQUE_IDENTIFIER)
            .unwrap()
            .identifier_text()
            .unwrap()
            .to_owned()
    }
}

fn batch(
    v: Version,
    entries: Vec<(u32, Vec<Node>)>,
    continuation: Option<u32>,
    max: Option<i32>,
    correlation: Option<&str>,
) -> Node {
    let mut header = vec![v.node()];
    if let Some(max) = max {
        header.push(Node::int(MAXIMUM_RESPONSE_SIZE, max));
    }
    if let Some(c) = correlation {
        header.push(Node::text(CLIENT_CORRELATION_VALUE, c));
    }
    if let Some(c) = continuation {
        header.push(Node::enumeration(BATCH_ERROR_CONTINUATION_OPTION, c));
    }
    if v.0 < 3 {
        header.push(Node::int(BATCH_COUNT, entries.len() as i32));
    }
    let mut message = vec![Node::structure(REQUEST_HEADER, header)];
    for (index, (op, payload)) in entries.into_iter().enumerate() {
        let mut item = vec![Node::enumeration(OPERATION, op)];
        if v.0 < 3 {
            item.push(Node::bytes(UNIQUE_BATCH_ITEM_ID, vec![index as u8]));
        }
        item.push(Node::structure(REQUEST_PAYLOAD, payload));
        message.push(Node::structure(BATCH_ITEM, item));
    }
    Node::structure(REQUEST_MESSAGE, message)
}
fn create_item(v: Version) -> (u32, Vec<Node>) {
    let attrs = [
        (
            CRYPTOGRAPHIC_ALGORITHM,
            "Cryptographic Algorithm",
            Node::enumeration(CRYPTOGRAPHIC_ALGORITHM, 3),
        ),
        (
            CRYPTOGRAPHIC_LENGTH,
            "Cryptographic Length",
            Node::int(CRYPTOGRAPHIC_LENGTH, 256),
        ),
        (
            CRYPTOGRAPHIC_USAGE_MASK,
            "Cryptographic Usage Mask",
            Node::int(CRYPTOGRAPHIC_USAGE_MASK, 12),
        ),
    ];
    let container = if v.0 >= 2 {
        Node::structure(ATTRIBUTES, attrs.into_iter().map(|(_, _, a)| a).collect())
    } else {
        Node::structure(
            TEMPLATE_ATTRIBUTE,
            attrs
                .into_iter()
                .map(|(_, name, mut a)| {
                    a.tag = ATTRIBUTE_VALUE;
                    Node::structure(ATTRIBUTE, vec![Node::text(ATTRIBUTE_NAME, name), a])
                })
                .collect(),
        )
    };
    (1, vec![Node::enumeration(OBJECT_TYPE, 2), container])
}
fn uid(v: Version, id: &str) -> Node {
    if v.0 >= 3 {
        Node::identifier(UNIQUE_IDENTIFIER, id)
    } else {
        Node::text(UNIQUE_IDENTIFIER, id)
    }
}
/// Get the object created earlier in the batch through the ID Placeholder.
fn get_placeholder(v: Version) -> (u32, Vec<Node>) {
    if v.0 >= 3 {
        (10, vec![Node::enumeration(UNIQUE_IDENTIFIER, 1)])
    } else {
        (10, vec![])
    }
}
fn name(v: Version) -> String {
    format!("{}.{}", v.0, v.1)
}
fn items(r: &Node) -> Vec<&Node> {
    r.all(BATCH_ITEM).collect()
}
fn field(item: &Node, tag: u32) -> Option<u32> {
    item.get(tag).map(|n| n.number().unwrap())
}
fn statuses(r: &Node) -> Vec<u32> {
    items(r)
        .iter()
        .map(|i| field(i, RESULT_STATUS).unwrap())
        .collect()
}
fn operations(r: &Node) -> Vec<Option<u32>> {
    items(r).iter().map(|i| field(i, OPERATION)).collect()
}
fn ids(r: &Node) -> Vec<Option<Vec<u8>>> {
    items(r)
        .iter()
        .map(|i| {
            i.get(UNIQUE_BATCH_ITEM_ID)
                .map(|n| n.byte_string().unwrap().to_vec())
        })
        .collect()
}
fn expected_ids(v: Version, count: usize) -> Vec<Option<Vec<u8>>> {
    (0..count)
        .map(|i| (v.0 < 3).then(|| vec![i as u8]))
        .collect()
}
struct Reply {
    response: Node,
    /// Binary TTLV-equivalent length from the independent oracle.
    binary: usize,
    /// Length of the bytes written in the selected encoding.
    wire: usize,
}
/// Process through the legacy binary API (`None`) or the selected-encoding
/// entry point, then measure the reply as sent.
fn send(f: &mut Fixture, request: &Node, format: Option<Format>) -> Result<Reply, Failure> {
    let response = match format {
        None => f.engine.process("alice", request),
        Some(format) => f
            .engine
            .process_with_grants_encoded("alice", request, None, &[], format),
    }?;
    let format = format.unwrap_or(Format::Ttlv);
    let bytes = format.encode(&response).unwrap();
    assert!(bytes.len() <= keytend_kmip_server::encoding::MAX_TEXT_FRAME);
    let binary = ttlv_equivalent(format, &bytes);
    // The oracle and a binary re-encoding of the decoded reply must agree.
    assert_eq!(
        binary,
        Format::Ttlv
            .encode(&format.decode(&bytes).unwrap())
            .unwrap()
            .len()
    );
    Ok(Reply {
        response,
        binary,
        wire: bytes.len(),
    })
}
/// A failed item with only its REQUIRED fields (1.4 table 285; 2.1 table 399).
fn minimal_failure(v: Version, op: u32, index: u8) -> usize {
    let mut fields = vec![Node::enumeration(OPERATION, op)];
    if v.0 < 3 {
        fields.push(Node::bytes(UNIQUE_BATCH_ITEM_ID, vec![index]));
    }
    fields.push(Node::enumeration(RESULT_STATUS, 1));
    fields.push(Node::enumeration(RESULT_REASON, 2));
    Node::structure(BATCH_ITEM, fields).encoded_len()
}
/// Sizes from an unlimited run of the same batch: (message overhead
/// including the response header, success item sizes).
fn probe(v: Version, entries: Vec<(u32, Vec<Node>)>, other: bool) -> (usize, Vec<usize>) {
    let mut f = Fixture::new();
    let mut entries = entries;
    if other {
        let id = f.create(v);
        entries.push((20, vec![uid(v, &id)]));
    }
    let r = f
        .engine
        .process("alice", &batch(v, entries, Some(CONTINUE), None, None))
        .unwrap();
    assert!(statuses(&r).iter().all(|s| *s == 0), "probe failed");
    (
        8 + r.required(RESPONSE_HEADER).unwrap().encoded_len(),
        items(&r).iter().map(|i| i.encoded_len()).collect(),
    )
}
fn state(f: &Fixture, id: &str) -> u32 {
    f.engine.store.get("alice", id).unwrap().unwrap().state
}
fn fresh(f: &Fixture, id: &str) -> Option<bool> {
    f.engine
        .store
        .get("alice", id)
        .unwrap()
        .unwrap()
        .metadata
        .fresh
}
fn created_ids(f: &Fixture, before: &[String]) -> Vec<String> {
    f.engine
        .store
        .list("alice")
        .unwrap()
        .into_iter()
        .map(|o| o.id.clone())
        .filter(|id| !before.contains(id))
        .collect()
}

#[test]
fn text_batches_respect_the_aggregate_binary_equivalent_limit() {
    for v in [Version(1, 4), Version(2, 1)] {
        for format in [Format::Ttlv, Format::Json, Format::Xml] {
            for continuation in [STOP, CONTINUE, UNDO] {
                for max in [None, Some(1 << 20), Some(8 * 1024 * 1024)] {
                    let mut f = Fixture::new();
                    let attrs = if v.0 == 1 {
                        TEMPLATE_ATTRIBUTE
                    } else {
                        ATTRIBUTES
                    };
                    let registered = f
                        .engine
                        .process(
                            "alice",
                            &batch(
                                v,
                                vec![(
                                    3,
                                    vec![
                                        Node::enumeration(OBJECT_TYPE, 8),
                                        Node::structure(attrs, vec![]),
                                        Node::structure(
                                            OPAQUE_OBJECT,
                                            vec![
                                                Node::enumeration(OPAQUE_DATA_TYPE, 0x80000001),
                                                Node::bytes(OPAQUE_DATA_VALUE, vec![0x5a; 65536]),
                                            ],
                                        ),
                                    ],
                                )],
                                None,
                                None,
                                None,
                            ),
                        )
                        .unwrap();
                    let id = items(&registered)[0]
                        .required(RESPONSE_PAYLOAD)
                        .unwrap()
                        .required(UNIQUE_IDENTIFIER)
                        .unwrap()
                        .string()
                        .unwrap()
                        .to_owned();
                    let other = f.create(v);
                    let before = f.audit().len();
                    let mut entries = vec![(10, vec![uid(v, &id)]); 17];
                    entries.push((20, vec![uid(v, &other)]));
                    let response = f
                        .engine
                        .process_with_grants_encoded(
                            "alice",
                            &batch(v, entries, Some(continuation), max, None),
                            None,
                            &[],
                            format,
                        )
                        .unwrap();
                    assert!(response.encoded_len() <= keytend_kmip_server::ttlv::MAX_FRAME);
                    let bytes = format.encode(&response).unwrap();
                    let binary = ttlv_equivalent(format, &bytes);
                    assert!(binary <= max.unwrap_or(1 << 20) as usize);
                    // A 1 MiB client limit admits a larger JSON or XML body.
                    if format != Format::Ttlv {
                        assert!(bytes.len() > 1 << 20);
                    }
                    let expected = if continuation == CONTINUE {
                        let mut s = vec![0; 15];
                        s.extend([1, 1, 0]);
                        s
                    } else {
                        let mut s = vec![if continuation == UNDO { 3 } else { 0 }; 15];
                        s.push(1);
                        s
                    };
                    assert_eq!(statuses(&response), expected);
                    for item in items(&response)
                        .into_iter()
                        .filter(|i| field(i, RESULT_STATUS) == Some(1))
                    {
                        assert_eq!(field(item, RESULT_REASON), Some(2));
                    }
                    let audits = f.audit();
                    assert_eq!(
                        audits[before..].iter().map(|(_, s)| *s).collect::<Vec<_>>(),
                        expected
                    );
                    assert_eq!(
                        state(&f, &other),
                        if continuation == CONTINUE { 5 } else { 1 }
                    );
                    assert_eq!(ids(&response), expected_ids(v, expected.len()));
                }
            }
        }
    }
}
fn all_ids(f: &Fixture) -> Vec<String> {
    f.engine
        .store
        .list("alice")
        .unwrap()
        .into_iter()
        .map(|o| o.id.clone())
        .collect()
}

/// Stop: completed operations are not undone; the oversized item alone fails
/// and unprocessed items are neither executed nor returned (1.4 table 366).
#[test]
fn stop_keeps_completed_work_and_fails_only_the_oversized_item() {
    for v in VERSIONS {
        for format in FORMATS {
            let (base, sizes) = probe(v, vec![create_item(v), get_placeholder(v)], true);
            // Create fits with room for Get's smallest failure; Get's key does not.
            let exact = base + sizes[0] + minimal_failure(v, 10, 1);
            for max in [exact, exact - 1] {
                let mut f = Fixture::new();
                let other = f.create(v);
                let before = all_ids(&f);
                let audit = f.audit().len();
                let request = batch(
                    v,
                    vec![
                        create_item(v),
                        get_placeholder(v),
                        (20, vec![uid(v, &other)]),
                    ],
                    None,
                    Some(max as i32),
                    None,
                );
                let reply = send(&mut f, &request, format).unwrap();
                let r = &reply.response;
                assert!(reply.binary <= max, "{} {max}", name(v));
                if max == exact {
                    assert_eq!(reply.binary, max);
                    // JSON and XML bodies exceed the limit; their TTLV equivalent fits.
                    assert!(format.is_none() || reply.wire > max);
                    assert_eq!(statuses(r), vec![0, 1], "{}", name(v));
                    assert_eq!(operations(r), vec![Some(1), Some(10)]);
                    assert_eq!(ids(r), expected_ids(v, 2));
                    let get = items(r)[1];
                    assert_eq!(field(get, RESULT_REASON), Some(2));
                    assert!(get.get(RESULT_MESSAGE).is_none());
                    assert!(get.get(RESPONSE_PAYLOAD).is_none());
                    let created = created_ids(&f, &before);
                    assert_eq!(created.len(), 1, "{}: completed Create was undone", name(v));
                    // The rolled-back Get never served the key.
                    assert_ne!(fresh(&f, &created[0]), Some(false));
                    assert_eq!(f.audit()[audit..], [(1, 0), (10, 1)]);
                } else {
                    // Without room for a later failure, Create itself is too large.
                    assert_eq!(statuses(r), vec![1]);
                    assert_eq!(operations(r), vec![Some(1)]);
                    assert_eq!(field(items(r)[0], RESULT_REASON), Some(2));
                    assert!(items(r)[0].get(RESULT_MESSAGE).is_some());
                    assert!(created_ids(&f, &before).is_empty());
                    assert_eq!(f.audit()[audit..], [(1, 1)]);
                }
                // Destroy was never processed.
                assert_eq!(state(&f, &other), 1);
                f.engine.store.verify_audit().unwrap();
            }
        }
    }
}

/// Undo: a Response Too Large failure undoes earlier items, whose responses
/// are returned as Operation Undone (1.4 table 366; 2.1 section 9.19).
#[test]
fn undo_marks_prior_work_undone_when_a_later_response_is_too_large() {
    for v in VERSIONS {
        for format in FORMATS {
            let (base, sizes) = probe(v, vec![create_item(v), get_placeholder(v)], true);
            let exact = base + sizes[0] + minimal_failure(v, 10, 1);
            for max in [exact, exact - 1] {
                let mut f = Fixture::new();
                let other = f.create(v);
                let before = all_ids(&f);
                let audit = f.audit().len();
                let request = batch(
                    v,
                    vec![
                        create_item(v),
                        get_placeholder(v),
                        (20, vec![uid(v, &other)]),
                    ],
                    Some(UNDO),
                    Some(max as i32),
                    None,
                );
                let reply = send(&mut f, &request, format).unwrap();
                let r = &reply.response;
                assert!(reply.binary <= max);
                if max == exact {
                    // An Undone item has the size of its success.
                    assert_eq!(reply.binary, max);
                    assert!(format.is_none() || reply.wire > max);
                    assert_eq!(statuses(r), vec![3, 1], "{}", name(v));
                    assert_eq!(operations(r), vec![Some(1), Some(10)]);
                    assert_eq!(ids(r), expected_ids(v, 2));
                    assert!(items(r)[0].get(RESPONSE_PAYLOAD).is_some());
                    assert_eq!(field(items(r)[1], RESULT_REASON), Some(2));
                    assert_eq!(f.audit()[audit..], [(1, 3), (10, 1)]);
                } else {
                    assert_eq!(statuses(r), vec![1]);
                    assert_eq!(field(items(r)[0], RESULT_REASON), Some(2));
                    assert_eq!(f.audit()[audit..], [(1, 1)]);
                }
                assert!(created_ids(&f, &before).is_empty());
                assert_eq!(state(&f, &other), 1);
                f.engine.store.verify_audit().unwrap();
            }
        }
    }
}

/// Continue: each item keeps its own result. A later item still runs and an
/// earlier success is not reported as failed.
#[test]
fn continue_reports_each_item_and_processes_later_items() {
    for v in VERSIONS {
        for format in FORMATS {
            let (base, sizes) = probe(v, vec![create_item(v), get_placeholder(v)], true);
            // Room for Create, Get's smallest failure and Destroy's success.
            let exact = base + sizes[0] + minimal_failure(v, 10, 1) + sizes[2];
            for max in [exact, exact - 1] {
                let mut f = Fixture::new();
                let other = f.create(v);
                let before = all_ids(&f);
                let audit = f.audit().len();
                let request = batch(
                    v,
                    vec![
                        create_item(v),
                        get_placeholder(v),
                        (20, vec![uid(v, &other)]),
                    ],
                    Some(CONTINUE),
                    Some(max as i32),
                    None,
                );
                let reply = send(&mut f, &request, format).unwrap();
                let r = &reply.response;
                assert!(reply.binary <= max);
                assert_eq!(
                    operations(r),
                    vec![Some(1), Some(10), Some(20)],
                    "{}",
                    name(v)
                );
                assert_eq!(ids(r), expected_ids(v, 3));
                assert_eq!(field(items(r)[1], RESULT_REASON), Some(2));
                assert_eq!(created_ids(&f, &before).len(), 1);
                if max == exact {
                    assert_eq!(reply.binary, max);
                    // JSON and XML bodies exceed the limit; their TTLV equivalent fits.
                    assert!(format.is_none() || reply.wire > max);
                    assert_eq!(statuses(r), vec![0, 1, 0]);
                    assert_ne!(state(&f, &other), 1, "{}: Destroy was not applied", name(v));
                    assert_eq!(f.audit()[audit..], [(1, 0), (10, 1), (20, 0)]);
                } else {
                    // Destroy's success no longer fits; it alone is rolled back.
                    assert_eq!(statuses(r), vec![0, 1, 1]);
                    assert_eq!(field(items(r)[2], RESULT_REASON), Some(2));
                    assert_eq!(state(&f, &other), 1);
                    assert_eq!(f.audit()[audit..], [(1, 0), (10, 1), (20, 1)]);
                }
                f.engine.store.verify_audit().unwrap();
            }
        }
    }
}

/// With only the smallest legal response available, every item keeps its own
/// Result Reason; below that, nothing executes and no response is produced.
// REQ:1b3488aeb68c2ced 1.0/1.1 the reply never exceeds the Maximum Response Size the requester can handle
// REQ:fd269c13d20b5ee8 1.2-2.1 the reply never exceeds the Maximum Response Size the requester can handle
#[test]
fn smallest_legal_response_is_exact_and_smaller_limits_execute_nothing() {
    for v in VERSIONS {
        for format in FORMATS {
            let (base, _) = probe(v, vec![create_item(v), get_placeholder(v)], true);
            for (continuation, floor) in [
                (STOP, base + minimal_failure(v, 1, 0)),
                (UNDO, base + minimal_failure(v, 1, 0)),
                (
                    CONTINUE,
                    base + minimal_failure(v, 1, 0)
                        + minimal_failure(v, 10, 1)
                        + minimal_failure(v, 20, 2),
                ),
            ] {
                for max in [floor, floor - 1] {
                    let mut f = Fixture::new();
                    let other = f.create(v);
                    let before = all_ids(&f);
                    let audit = f.audit().len();
                    let request = batch(
                        v,
                        vec![
                            create_item(v),
                            get_placeholder(v),
                            (20, vec![uid(v, &other)]),
                        ],
                        Some(continuation),
                        Some(max as i32),
                        None,
                    );
                    let result = send(&mut f, &request, format);
                    if max < floor {
                        assert!(
                            result.is_err_and(|e| e.unanswerable()),
                            "{} {continuation}",
                            name(v)
                        );
                        assert_eq!(f.audit().len(), audit);
                    } else {
                        let reply = result.unwrap();
                        let r = &reply.response;
                        assert_eq!(reply.binary, max, "{} {continuation}", name(v));
                        assert!(format.is_none() || reply.wire > max);
                        assert!(items(r).iter().all(|i| i.get(RESULT_MESSAGE).is_none()));
                        if continuation == CONTINUE {
                            assert_eq!(statuses(r), vec![1, 1, 1]);
                            // Get failed for its own reason: Create made no placeholder.
                            let reasons = items(r)
                                .iter()
                                .map(|i| field(i, RESULT_REASON).unwrap())
                                .collect::<Vec<_>>();
                            assert_eq!(reasons[0], 2);
                            assert_ne!(reasons[1], 2, "{}: Get reason was falsified", name(v));
                            assert_eq!(reasons[2], 2);
                            assert_eq!(f.audit()[audit..], [(1, 1), (10, 1), (20, 1)]);
                        } else {
                            assert_eq!(statuses(r), vec![1]);
                            assert_eq!(f.audit()[audit..], [(1, 1)]);
                        }
                    }
                    assert!(created_ids(&f, &before).is_empty());
                    assert_eq!(state(&f, &other), 1);
                    f.engine.store.verify_audit().unwrap();
                }
            }
        }
    }
}

fn query() -> (u32, Vec<Node>) {
    (
        24,
        vec![
            Node::enumeration(QUERY_FUNCTION, 1),
            Node::enumeration(QUERY_FUNCTION, 2),
        ],
    )
}

/// Small limits: a legal Stop response with Operation and Unique
/// Batch Item ID fits in 256 bytes; a long Client Correlation Value is not
/// echoed when that is the only way to send a conforming response.
#[test]
fn small_limits_keep_item_fields_and_shed_optional_correlation() {
    for v in [Version(1, 4), Version(2, 0), Version(2, 1), Version(3, 0)] {
        for format in FORMATS {
            let mut f = Fixture::new();
            let request = batch(v, vec![query(), query()], None, Some(256), None);
            let reply = send(&mut f, &request, format).unwrap();
            let r = &reply.response;
            assert!(reply.binary <= 256);
            assert_eq!(statuses(r), vec![1]);
            assert_eq!(operations(r), vec![Some(24)]);
            assert_eq!(ids(r), expected_ids(v, 1));
            assert_eq!(field(items(r)[0], RESULT_REASON), Some(2));
            let correlation = "c".repeat(200);
            let request = batch(
                v,
                vec![query(), query(), query()],
                None,
                Some(256),
                Some(&correlation),
            );
            let reply = send(&mut f, &request, format).unwrap();
            let r = &reply.response;
            assert!(reply.binary <= 256, "{}", reply.binary);
            let header = r.required(RESPONSE_HEADER).unwrap();
            assert!(header.get(CLIENT_CORRELATION_VALUE).is_none());
            assert!(header.get(SERVER_CORRELATION_VALUE).is_some());
            assert_eq!(operations(r), vec![Some(24)]);
            assert_eq!(field(items(r)[0], RESULT_REASON), Some(2));
            // With room, the correlation is echoed as before.
            let request = batch(v, vec![query()], None, None, Some(&correlation));
            let r = send(&mut f, &request, format).unwrap().response;
            assert_eq!(
                r.required(RESPONSE_HEADER)
                    .unwrap()
                    .required(CLIENT_CORRELATION_VALUE)
                    .unwrap()
                    .string()
                    .unwrap(),
                correlation
            );
            assert_eq!(statuses(&r), vec![0]);
        }
    }
}

/// Header errors keep the message-level form, shed the optional Result
/// Message and correlation echo to fit, and are not sent when nothing fits.
#[test]
fn message_level_errors_are_bounded() {
    for v in VERSIONS {
        for format in FORMATS {
            let mut f = Fixture::new();
            // Batch Error Continuation Option 9 is invalid (header error).
            let invalid = |max: Option<i32>, correlation: Option<&str>| {
                batch(v, vec![query(), query()], Some(9), max, correlation)
            };
            let full = send(&mut f, &invalid(None, None), format).unwrap();
            let item = items(&full.response)[0];
            assert_eq!(field(item, OPERATION), None);
            assert_eq!(field(item, RESULT_REASON), Some(7));
            assert!(item.get(RESULT_MESSAGE).is_some());
            let terse = full.binary - item.required(RESULT_MESSAGE).unwrap().encoded_len();
            let reply = send(&mut f, &invalid(Some(terse as i32), None), format).unwrap();
            assert_eq!(reply.binary, terse);
            assert!(format.is_none() || reply.wire > terse);
            assert_eq!(field(items(&reply.response)[0], RESULT_REASON), Some(7));
            assert!(items(&reply.response)[0].get(RESULT_MESSAGE).is_none());
            let failure = send(&mut f, &invalid(Some(terse as i32 - 1), None), format);
            assert!(failure.is_err_and(|e| e.unanswerable()));
            if v >= Version(1, 4) {
                let correlation = "c".repeat(100);
                let reply = send(
                    &mut f,
                    &invalid(Some(terse as i32), Some(&correlation)),
                    format,
                )
                .unwrap();
                assert!(reply.binary <= terse);
                assert!(
                    reply
                        .response
                        .required(RESPONSE_HEADER)
                        .unwrap()
                        .get(CLIENT_CORRELATION_VALUE)
                        .is_none()
                );
            }
        }
    }
}

/// Undo with material: an earlier Get whose key was returned as Undone keeps
/// its served history; the oversized Get never served its key.
#[test]
fn undo_and_stop_record_exposure_only_for_returned_material() {
    for v in [Version(1, 4), Version(2, 1), Version(3, 0)] {
        let (base, sizes) = {
            let mut f = Fixture::new();
            let a = f.create(v);
            let b = f.create(v);
            let r = f
                .engine
                .process(
                    "alice",
                    &batch(
                        v,
                        vec![(10, vec![uid(v, &a)]), (10, vec![uid(v, &b)])],
                        None,
                        None,
                        None,
                    ),
                )
                .unwrap();
            (
                8 + r.required(RESPONSE_HEADER).unwrap().encoded_len(),
                items(&r)
                    .iter()
                    .map(|i| i.encoded_len())
                    .collect::<Vec<_>>(),
            )
        };
        let max = base + sizes[0] + minimal_failure(v, 10, 1);
        for (continuation, format) in [STOP, UNDO]
            .into_iter()
            .flat_map(|c| FORMATS.map(|format| (c, format)))
        {
            let mut f = Fixture::new();
            let a = f.create(v);
            let b = f.create(v);
            let request = batch(
                v,
                vec![(10, vec![uid(v, &a)]), (10, vec![uid(v, &b)])],
                Some(continuation),
                Some(max as i32),
                None,
            );
            let reply = send(&mut f, &request, format).unwrap();
            let r = &reply.response;
            assert_eq!(reply.binary, max);
            assert!(format.is_none() || reply.wire > max);
            let first = if continuation == UNDO { 3 } else { 0 };
            assert_eq!(statuses(r), vec![first, 1], "{}", name(v));
            assert!(items(r)[0].get(RESPONSE_PAYLOAD).is_some());
            assert_eq!(fresh(&f, &a), Some(false), "{} {continuation}", name(v));
            assert_eq!(fresh(&f, &b), Some(true), "{} {continuation}", name(v));
            f.engine.store.verify_audit().unwrap();
        }
    }
}

/// The selected encoding sizes every result and error. Sweeping limits never
/// yields an oversized reply, a batch result after a Stop failure, or a
/// message-level failure for a parsed batch.
#[test]
fn selected_encoding_bounds_every_candidate_response() {
    for format in [Format::Ttlv, Format::Json, Format::Xml] {
        for (v, count) in [
            (Version(1, 4), 1usize),
            (Version(2, 1), 3),
            (Version(3, 0), 2),
        ] {
            let mut seen = std::collections::BTreeSet::new();
            let mut f = Fixture::new();
            for max in (0..24_000).step_by(89) {
                for continuation in [STOP, CONTINUE, UNDO] {
                    let entries = (0..count).map(|_| query()).collect();
                    let option = (count > 1).then_some(continuation);
                    let request = batch(v, entries, option, Some(max as i32), Some("corr"));
                    let result =
                        f.engine
                            .process_with_grants_encoded("alice", &request, None, &[], format);
                    let Ok(r) = result else {
                        assert!(result.is_err_and(|e| e.unanswerable()));
                        seen.insert("unanswerable");
                        continue;
                    };
                    let bytes = format.encode(&r).unwrap();
                    let binary = ttlv_equivalent(format, &bytes);
                    assert!(binary <= max, "{} {max}: {binary} bytes", name(v));
                    assert!(bytes.len() <= keytend_kmip_server::encoding::MAX_TEXT_FRAME);
                    let status = statuses(&r);
                    assert!(operations(&r).iter().all(|o| *o == Some(24)));
                    if option == Some(CONTINUE) {
                        assert_eq!(status.len(), count);
                    } else if let Some(failed) = status.iter().position(|s| *s == 1) {
                        assert_eq!(failed + 1, status.len());
                        if option == Some(UNDO) {
                            assert!(status[..failed].iter().all(|s| *s == 3));
                        }
                    }
                    seen.insert(if status.contains(&1) {
                        "too large"
                    } else {
                        "fits"
                    });
                }
            }
            assert_eq!(seen.len(), 3, "{} {seen:?}", name(v));
        }
    }
}

/// The encoded entry point checks payload representability with the same
/// encoder: a NUL in an XML reply fails that item, not the batch.
#[test]
fn encoded_xml_failures_are_per_item_and_bounded() {
    let v = Version(2, 1);
    let mut f = Fixture::new();
    let id = f.create(v);
    let mut obj = f.engine.store.get("alice", &id).unwrap().unwrap();
    obj.id = "nul\0id".to_owned();
    f.engine.store.insert(&obj).unwrap();
    let request = batch(
        v,
        vec![(11, vec![uid(v, &obj.id)]), query()],
        Some(CONTINUE),
        None,
        None,
    );
    let r = f
        .engine
        .process_with_grants_encoded("alice", &request, None, &[], Format::Xml)
        .unwrap();
    assert_eq!(statuses(&r), vec![1, 0]);
    assert_eq!(field(items(&r)[0], RESULT_REASON), Some(8));
    assert!(Format::Xml.encode(&r).is_ok());
}

fn node_resources(n: &Node) -> (usize, usize) {
    n.children()
        .unwrap_or(&[])
        .iter()
        .fold((1, 0), |(count, depth), child| {
            let (child_count, child_depth) = node_resources(child);
            (count + child_count, depth.max(child_depth + 1))
        })
}

/// Small requests can amplify into a node-heavy response well below either
/// byte limit. Keep completed mutations/exposure, Undo history, IDs and audits.
#[test]
fn aggregate_node_limit_returns_partial_batches_without_a_client_limit() {
    for v in [Version(1, 4), Version(2, 1), Version(3, 0)] {
        // None covers the legacy public binary API used by the native listener.
        for format in [
            None,
            Some(Format::Ttlv),
            Some(Format::Json),
            Some(Format::Xml),
        ] {
            for continuation in [STOP, CONTINUE, UNDO] {
                for max in [None, Some(8 * 1024 * 1024)] {
                    let mut f = Fixture::new();
                    let existing = f.create(v);
                    let other = f.create(v);
                    let before = all_ids(&f);
                    let seq = f.audit().len();
                    let placeholder = if v.0 >= 3 {
                        vec![Node::enumeration(UNIQUE_IDENTIFIER, 1)]
                    } else {
                        vec![]
                    };
                    let mut entries = vec![
                        create_item(v),
                        (10, placeholder.clone()),
                        (10, vec![uid(v, &existing)]),
                    ];
                    // About 4096 object-type nodes per Query: draft 3.0 also
                    // lists User, Group and the four credential types (14
                    // types).
                    let repeats = if v.0 >= 3 { 292 } else { 512 };
                    entries.extend(vec![
                        (
                            24,
                            vec![Node::enumeration(QUERY_FUNCTION, 2); repeats]
                        );
                        4
                    ]);
                    entries.extend([(10, placeholder), (20, vec![uid(v, &other)])]);
                    let request = batch(v, entries, Some(continuation), max, Some("nodes"));
                    let response = match format {
                        Some(format) => f.engine.process_with_grants_encoded(
                            "alice",
                            &request,
                            None,
                            &[],
                            format,
                        ),
                        None => {
                            let mut checked = 0;
                            let result = f.engine.process_with_grants_checked(
                                "alice",
                                &request,
                                None,
                                &[],
                                &mut |payload| {
                                    assert_eq!(payload.tag, RESPONSE_PAYLOAD);
                                    checked += 1;
                                    Ok(())
                                },
                            );
                            // The oversized success payload is checked before
                            // its size rejection; the final message is not.
                            assert_eq!(checked, if continuation == CONTINUE { 9 } else { 7 });
                            result
                        }
                    }
                    .unwrap();
                    let mut expected = vec![if continuation == UNDO { 3 } else { 0 }; 6];
                    expected.push(1);
                    if continuation == CONTINUE {
                        expected.extend([0, 0]);
                    }
                    assert_eq!(statuses(&response), expected, "{} {continuation}", name(v));
                    assert_eq!(field(items(&response)[6], RESULT_REASON), Some(2));
                    assert_eq!(ids(&response), expected_ids(v, expected.len()));
                    assert_eq!(
                        f.audit()[seq..].iter().map(|(_, s)| *s).collect::<Vec<_>>(),
                        expected
                    );
                    assert_eq!(
                        created_ids(&f, &before).len(),
                        usize::from(continuation != UNDO)
                    );
                    assert_eq!(
                        state(&f, &other),
                        if continuation == CONTINUE { 5 } else { 1 }
                    );
                    // The first Get of this existing key is retained even by Undo.
                    assert_eq!(fresh(&f, &existing), Some(false));
                    if continuation == CONTINUE {
                        let created = items(&response)[0]
                            .required(RESPONSE_PAYLOAD)
                            .unwrap()
                            .required(UNIQUE_IDENTIFIER)
                            .unwrap();
                        let last_get = items(&response)[7]
                            .required(RESPONSE_PAYLOAD)
                            .unwrap()
                            .required(UNIQUE_IDENTIFIER)
                            .unwrap();
                        assert_eq!(
                            created.identifier_text().unwrap(),
                            last_get.identifier_text().unwrap()
                        );
                    }
                    assert!(node_resources(&response).0 <= 16_384);
                    let bytes = format.unwrap_or(Format::Ttlv).encode(&response).unwrap();
                    assert!(format.unwrap_or(Format::Ttlv).decode(&bytes).is_ok());
                    assert!(response.encoded_len() < keytend_kmip_server::ttlv::MAX_FRAME);
                    f.engine.store.verify_audit().unwrap();
                }
            }
        }
    }
}

/// A selected Create reference expands to two Gets. With only a single
/// failure slot left, Continue must collapse the request to one failure before
/// either Get executes; Stop/Undo may execute but must roll back the failed Get.
#[test]
fn node_reservations_cover_expansion_and_failed_get_exposure() {
    let v = Version(2, 1);
    for format in [Format::Ttlv, Format::Json, Format::Xml] {
        for continuation in [STOP, CONTINUE, UNDO] {
            let mut f = Fixture::new();
            let empty_entries = vec![create_item(v), create_item(v), (24, vec![])];
            let probe = f
                .engine
                .process(
                    "alice",
                    &batch(v, empty_entries, Some(CONTINUE), None, None),
                )
                .unwrap();
            let baseline = node_resources(&probe).0;
            // The nodes one Query function adds to the same batch. Query
            // Operations and Query Objects contribute one node per entry, so
            // their parity changes when operations or object types are added.
            let mut contribution = |function: u32| {
                let entries = vec![
                    create_item(v),
                    create_item(v),
                    (24, vec![Node::enumeration(QUERY_FUNCTION, function)]),
                ];
                let r = f
                    .engine
                    .process("alice", &batch(v, entries, Some(CONTINUE), None, None))
                    .unwrap();
                node_resources(&r).0 - baseline
            };
            let odd = [1, 2]
                .into_iter()
                .map(|function| (function, contribution(function)))
                .find(|(_, nodes)| nodes % 2 == 1);
            let before = all_ids(&f);
            let seq = f.audit().len();
            // Each Query Server Information contributes exactly two nodes.
            let mut deficit = 16_384 - baseline - 5;
            let mut functions = vec![];
            if deficit % 2 == 1 {
                let (function, nodes) =
                    odd.expect("Query Operations or Query Objects adds an odd number of nodes");
                functions.push(Node::enumeration(QUERY_FUNCTION, function));
                deficit -= nodes;
            }
            let repeats = deficit / 2;
            functions.extend(vec![Node::enumeration(QUERY_FUNCTION, 3); repeats]);
            let entries = vec![
                create_item(v),
                create_item(v),
                (24, functions),
                (10, vec![Node::enumeration(UNIQUE_IDENTIFIER, 3)]),
            ];
            let r = f
                .engine
                .process_with_grants_encoded(
                    "alice",
                    &batch(v, entries, Some(continuation), None, None),
                    None,
                    &[],
                    format,
                )
                .unwrap();
            assert_eq!(
                statuses(&r),
                vec![if continuation == UNDO { 3 } else { 0 }; 3]
                    .into_iter()
                    .chain([1])
                    .collect::<Vec<_>>()
            );
            assert_eq!(field(items(&r)[3], RESULT_REASON), Some(2));
            assert_eq!(ids(&r), expected_ids(v, 4));
            assert!(
                items(&r)[3].get(RESULT_MESSAGE).is_none(),
                "terse failure must use the reserved nodes"
            );
            assert_eq!(node_resources(&r).0, 16_384);
            let created = created_ids(&f, &before);
            assert_eq!(created.len(), if continuation == UNDO { 0 } else { 2 });
            for id in created {
                assert_eq!(
                    fresh(&f, &id),
                    Some(true),
                    "a failed Get must not record exposure"
                );
            }
            assert_eq!(
                f.audit()[seq..],
                [
                    (1, if continuation == UNDO { 3 } else { 0 }),
                    (1, if continuation == UNDO { 3 } else { 0 }),
                    (24, if continuation == UNDO { 3 } else { 0 }),
                    (10, 1)
                ]
            );
            assert!(format.encode(&r).is_ok());
            f.engine.store.verify_audit().unwrap();
        }
    }
}

/// Profiles MSGENC-JSON-M-1 and MSGENC-XML-M-1 (1.3 through 2.1 and draft
/// 3.0): Query Operations and Objects with Maximum Response Size 256 fails
/// with Response Too Large; with 2048 it succeeds. The 2048-byte limit is the
/// binary TTLV equivalent; this server's JSON and XML replies are larger.
// REQ:fd5636400b32dae6 XML Maximum Response Size is measured as the TTLV-encoded length
// REQ:2f2fdef0cb5aa1fd JSON Maximum Response Size is measured as the TTLV-encoded length
#[test]
fn oasis_message_encoding_vectors_use_the_binary_equivalent_limit() {
    for (v, correlated) in [
        (Version(1, 3), false),
        (Version(1, 4), false),
        (Version(2, 0), true),
        (Version(2, 1), true),
        (Version(3, 0), true),
    ] {
        for format in [Format::Json, Format::Xml] {
            let mut f = Fixture::new();
            for (step, max) in [(0, 256), (1, 2048)] {
                let label = format!(
                    "MSGENC-{}-M-1-{}{} step={step}",
                    if format == Format::Json {
                        "JSON"
                    } else {
                        "XML"
                    },
                    v.0,
                    v.1
                );
                let request = batch(
                    v,
                    vec![query()],
                    None,
                    Some(max),
                    correlated.then_some(label.as_str()),
                );
                let reply = send(&mut f, &request, Some(format)).unwrap();
                let r = &reply.response;
                assert!(reply.binary <= max as usize, "{label}: {}", reply.binary);
                assert_eq!(operations(r), vec![Some(24)], "{label}");
                if step == 0 {
                    assert_eq!(statuses(r), vec![1], "{label}");
                    assert_eq!(field(items(r)[0], RESULT_REASON), Some(2));
                } else {
                    assert_eq!(statuses(r), vec![0], "{label}");
                    assert!(reply.wire > max as usize, "{label}: {} bytes", reply.wire);
                }
            }
        }
    }
}

/// Query batches in JSON and XML at the exact binary TTLV-equivalent size of
/// the complete reply, and one byte below it, for every continuation option.
#[test]
fn text_query_batches_are_exact_at_the_binary_equivalent_limit() {
    for v in [Version(1, 4), Version(2, 1), Version(3, 0)] {
        for format in [Format::Json, Format::Xml] {
            for continuation in [STOP, CONTINUE, UNDO] {
                let mut f = Fixture::new();
                let request = |max| {
                    batch(
                        v,
                        vec![query(); 3],
                        Some(continuation),
                        max,
                        Some("correlation"),
                    )
                };
                let full = send(&mut f, &request(None), Some(format)).unwrap();
                assert_eq!(statuses(&full.response), vec![0; 3]);
                let exact = full.binary;
                for max in [exact, exact - 1] {
                    let reply = send(&mut f, &request(Some(max as i32)), Some(format)).unwrap();
                    let r = &reply.response;
                    assert!(reply.binary <= max);
                    assert!(
                        r.required(RESPONSE_HEADER)
                            .unwrap()
                            .get(CLIENT_CORRELATION_VALUE)
                            .is_some()
                    );
                    assert_eq!(operations(r), vec![Some(24); 3]);
                    assert_eq!(ids(r), expected_ids(v, 3));
                    if max == exact {
                        assert_eq!(reply.binary, exact);
                        assert!(reply.wire > max);
                        assert_eq!(statuses(r), vec![0; 3]);
                    } else {
                        let first = if continuation == UNDO { 3 } else { 0 };
                        assert_eq!(statuses(r), vec![first, first, 1], "{}", name(v));
                        assert_eq!(field(items(r)[2], RESULT_REASON), Some(2));
                    }
                }
            }
        }
    }
}
