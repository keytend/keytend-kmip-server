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

//! Engine request counters of `/metrics` (src/metrics.rs, docs/metrics.md):
//! client requests through the engine entry points are counted by version,
//! encoding, operation, status and reason, leases are split into granted and
//! refused, and nothing a client sends (identifiers, principals, Names)
//! appears in the exposition.
use keytend_kmip_server::{
    encoding::Format,
    metrics::{Census, Exposition, Registry},
    protocol::{Engine, Version},
    store::Store,
    tags::*,
    ttlv::Node,
};
use std::sync::Arc;

struct Fixture {
    _dir: tempfile::TempDir,
    engine: Engine,
    registry: Arc<Registry>,
}

fn fixture() -> Fixture {
    let dir = tempfile::tempdir().unwrap();
    let key = dir.path().join("master");
    std::fs::write(&key, [42; 32]).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    let store = Store::open(&dir.path().join("keys.sqlite"), &key).unwrap();
    let registry = Arc::new(Registry::new());
    let engine = Engine::new(store, false).with_metrics(registry.clone());
    Fixture {
        _dir: dir,
        engine,
        registry,
    }
}

fn request(v: Version, items: Vec<(u32, Vec<Node>)>) -> Node {
    let mut header = vec![v.node(), Node::int(BATCH_COUNT, items.len() as i32)];
    if items.len() > 1 {
        header.push(Node::enumeration(BATCH_ERROR_CONTINUATION_OPTION, 1));
    }
    let mut message = vec![Node::structure(REQUEST_HEADER, header)];
    for (i, (op, fields)) in items.into_iter().enumerate() {
        let mut item = vec![Node::enumeration(OPERATION, op)];
        // Multi-item batches need distinct Unique Batch Item IDs.
        item.push(Node::bytes(UNIQUE_BATCH_ITEM_ID, vec![i as u8 + 1]));
        item.push(Node::structure(REQUEST_PAYLOAD, fields));
        message.push(Node::structure(BATCH_ITEM, item));
    }
    Node::structure(REQUEST_MESSAGE, message)
}

fn create_2_1(f: &mut Fixture, name: &str) -> String {
    let attrs = Node::structure(
        ATTRIBUTES,
        vec![
            Node::enumeration(CRYPTOGRAPHIC_ALGORITHM, 3),
            Node::int(CRYPTOGRAPHIC_LENGTH, 128),
            Node::int(CRYPTOGRAPHIC_USAGE_MASK, 12),
            Node::structure(
                NAME,
                vec![
                    Node::text(NAME_VALUE, name),
                    Node::enumeration(NAME_TYPE, 1),
                ],
            ),
        ],
    );
    let r = f
        .engine
        .process(
            "alice-principal",
            &request(
                Version(2, 1),
                vec![(1, vec![Node::enumeration(OBJECT_TYPE, 2), attrs])],
            ),
        )
        .unwrap();
    r.required(BATCH_ITEM)
        .unwrap()
        .required(RESPONSE_PAYLOAD)
        .unwrap()
        .required(UNIQUE_IDENTIFIER)
        .unwrap()
        .identifier_text()
        .unwrap()
        .to_owned()
}

fn text(registry: &Registry) -> String {
    let mut out = Exposition::new();
    registry.write(&mut out);
    out.finish()
}

fn has(text: &str, line: &str) {
    assert!(text.lines().any(|l| l == line), "{line} missing:\n{text}");
}

#[test]
fn engine_requests_count_by_version_encoding_operation_and_result() {
    let mut f = fixture();
    let id = create_2_1(&mut f, "secret-name-label");
    let uid = || vec![Node::text(UNIQUE_IDENTIFIER, id.clone())];
    // A Pre-Active key gets no lease (Permission Denied), an Active one does.
    f.engine
        .process(
            "alice-principal",
            &request(Version(2, 1), vec![(16, uid())]),
        )
        .unwrap();
    f.engine
        .process(
            "alice-principal",
            &request(Version(2, 1), vec![(18, uid())]),
        )
        .unwrap();
    // Two items in one 1.4 message: a granted lease and a Get, over JSON.
    let json = request(Version(1, 4), vec![(16, uid()), (10, uid())]);
    f.engine
        .process_with_grants_encoded("alice-principal", &json, None, &[], Format::Json)
        .unwrap();
    // An operation the server does not know is counted as unknown, and the
    // other principal's Get as Object Not Found (2.1); neither adds a series per value.
    f.engine
        .process(
            "bob-principal",
            &request(Version(2, 0), vec![(0x8000_0042, vec![])]),
        )
        .unwrap();
    f.engine
        .process("bob-principal", &request(Version(2, 1), vec![(10, uid())]))
        .unwrap();
    // Operations the certificate policy does not allow are Permission Denied.
    f.engine
        .process_authorized(
            "alice-principal",
            &request(Version(1, 2), vec![(24, vec![])]),
            Some(&[]),
        )
        .unwrap();
    let text = text(&f.registry);
    for line in [
        "kmip_requests_total{version=\"2.1\",encoding=\"ttlv\"} 4",
        "kmip_requests_total{version=\"1.4\",encoding=\"json\"} 1",
        "kmip_requests_total{version=\"2.0\",encoding=\"ttlv\"} 1",
        "kmip_requests_total{version=\"1.2\",encoding=\"ttlv\"} 1",
        "kmip_operations_total{version=\"2.1\",encoding=\"ttlv\",operation=\"Create\",status=\"Success\",reason=\"none\"} 1",
        "kmip_operations_total{version=\"2.1\",encoding=\"ttlv\",operation=\"ObtainLease\",status=\"OperationFailed\",reason=\"PermissionDenied\"} 1",
        "kmip_operations_total{version=\"2.1\",encoding=\"ttlv\",operation=\"Activate\",status=\"Success\",reason=\"none\"} 1",
        "kmip_operations_total{version=\"1.4\",encoding=\"json\",operation=\"ObtainLease\",status=\"Success\",reason=\"none\"} 1",
        "kmip_operations_total{version=\"1.4\",encoding=\"json\",operation=\"Get\",status=\"Success\",reason=\"none\"} 1",
        "kmip_operations_total{version=\"2.1\",encoding=\"ttlv\",operation=\"Get\",status=\"OperationFailed\",reason=\"ObjectNotFound\"} 1",
        "kmip_operations_total{version=\"1.2\",encoding=\"ttlv\",operation=\"Query\",status=\"OperationFailed\",reason=\"PermissionDenied\"} 1",
        "kmip_leases_granted_total 1",
        "kmip_leases_refused_total{reason=\"PermissionDenied\"} 1",
        "kmip_request_duration_seconds_count{operation=\"Create\"} 1",
        "kmip_request_duration_seconds_count{operation=\"batch\"} 1",
        "kmip_request_batch_items_count 7",
        "kmip_request_batch_items_bucket{le=\"1\"} 6",
    ] {
        has(&text, line);
    }
    // The unknown operation (2.0 Operation Not Supported) stays one bounded series.
    assert!(
        text.lines().any(|l| l.starts_with(
            "kmip_operations_total{version=\"2.0\",encoding=\"ttlv\",operation=\"unknown\",status=\"OperationFailed\""
        )),
        "{text}"
    );
    for secret in [
        id.as_str(),
        "alice-principal",
        "bob-principal",
        "secret-name-label",
    ] {
        assert!(!text.contains(secret), "{secret} leaked:\n{text}");
    }
}

#[test]
fn malformed_messages_and_unsupported_versions_are_counted_without_their_content() {
    let mut f = fixture();
    // Not a Request Message: Invalid Message, no Operation in the answer.
    f.engine
        .process("p", &Node::structure(REQUEST_HEADER, vec![]))
        .unwrap();
    // A version this server does not implement is labelled by the version the
    // server answers with, never by the client's value.
    f.engine
        .process("p", &request(Version(9, 7), vec![(24, vec![])]))
        .unwrap();
    let text = text(&f.registry);
    assert!(
        text.lines().any(|l| l.starts_with("kmip_operations_total{")
            && l.contains(
                "operation=\"none\",status=\"OperationFailed\",reason=\"InvalidMessage\""
            )),
        "{text}"
    );
    assert!(!text.contains("9.7"), "{text}");
    assert!(
        text.contains("reason=\"UnsupportedProtocolVersion\""),
        "{text}"
    );
}

#[test]
fn census_pages_report_objects_by_type_and_state() {
    let mut f = fixture();
    let a = create_2_1(&mut f, "a");
    create_2_1(&mut f, "b");
    f.engine
        .process(
            "alice-principal",
            &request(
                Version(2, 1),
                vec![(18, vec![Node::text(UNIQUE_IDENTIFIER, a)])],
            ),
        )
        .unwrap();
    let mut census = Census::default();
    let mut after = None;
    loop {
        let page = f.engine.store.census_page(after.as_deref(), 1).unwrap();
        for (t, s) in page.objects {
            census.add(t, s);
        }
        census.unreadable += page.unreadable;
        match page.next {
            Some(next) => after = Some(next),
            None => break,
        }
    }
    f.registry.set_census(census);
    let text = text(&f.registry);
    has(
        &text,
        "kmip_objects{type=\"SymmetricKey\",state=\"Active\"} 1",
    );
    has(
        &text,
        "kmip_objects{type=\"SymmetricKey\",state=\"PreActive\"} 1",
    );
    has(&text, "kmip_objects_unreadable 0");
}
