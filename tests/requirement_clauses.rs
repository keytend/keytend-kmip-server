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

//! Focused tests for individual normative clauses of the requirement matrix.
//! Each asserting test names the clause digests it checks as `REQ:<digest>`
//! (see docs/specs/requirement-matrix.json); the paraphrases are our own words.
use keytend_kmip_server::{
    encoding::Format,
    protocol::{Engine, Version},
    store::Store,
    tags::*,
    ttlv::{self, Node, Value},
};
use tempfile::TempDir;

const FINAL: [Version; 7] = [
    Version(1, 0),
    Version(1, 1),
    Version(1, 2),
    Version(1, 3),
    Version(1, 4),
    Version(2, 0),
    Version(2, 1),
];

struct Fixture {
    _dir: TempDir,
    engine: Engine,
}
impl Fixture {
    fn new() -> Self {
        let d = tempfile::tempdir().unwrap();
        let k = d.path().join("master");
        std::fs::write(&k, [42; 32]).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&k, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        let store = Store::open(&d.path().join("keys.sqlite"), &k).unwrap();
        Self {
            _dir: d,
            engine: Engine::new(store, false),
        }
    }
    fn send(&mut self, request: &Node) -> Node {
        self.engine.process("alice", request).unwrap()
    }
}

/// A request with an explicit header and items; each item is
/// (operation, optional Unique Batch Item ID, payload).
fn message(header: Vec<Node>, items: Vec<(u32, Option<u8>, Vec<Node>)>) -> Node {
    let mut fields = vec![Node::structure(REQUEST_HEADER, header)];
    for (op, id, payload) in items {
        let mut item = vec![Node::enumeration(OPERATION, op)];
        if let Some(id) = id {
            item.push(Node::bytes(UNIQUE_BATCH_ITEM_ID, vec![id]));
        }
        item.push(Node::structure(REQUEST_PAYLOAD, payload));
        fields.push(Node::structure(BATCH_ITEM, item));
    }
    Node::structure(REQUEST_MESSAGE, fields)
}
fn req(v: Version, extra: Vec<Node>, items: Vec<(u32, Vec<Node>)>) -> Node {
    let mut header = vec![v.node()];
    header.extend(extra);
    header.push(Node::int(BATCH_COUNT, items.len() as i32));
    message(
        header,
        items
            .into_iter()
            .enumerate()
            .map(|(i, (op, p))| (op, Some(i as u8 + 1), p))
            .collect(),
    )
}
fn tags(n: &Node) -> Vec<u32> {
    n.children().unwrap().iter().map(|n| n.tag).collect()
}
fn items(r: &Node) -> Vec<&Node> {
    r.all(BATCH_ITEM).collect()
}
fn num(n: &Node, tag: u32) -> u32 {
    n.required(tag).unwrap().number().unwrap()
}
fn status(item: &Node) -> u32 {
    num(item, RESULT_STATUS)
}
fn statuses(r: &Node) -> Vec<u32> {
    items(r).into_iter().map(status).collect()
}
fn reason(r: &Node) -> u32 {
    num(items(r)[0], RESULT_REASON)
}
fn payload(r: &Node) -> &Node {
    let item = items(r)[0];
    assert_eq!(
        status(item),
        0,
        "reason {:?}",
        item.get(RESULT_REASON).map(|n| n.number())
    );
    item.required(RESPONSE_PAYLOAD).unwrap()
}
fn uid(id: &str) -> Node {
    Node::text(UNIQUE_IDENTIFIER, id)
}
fn attr_name(v: Version, name: &str, tag: u32) -> Node {
    if v.0 == 1 {
        Node::text(ATTRIBUTE_NAME, name)
    } else {
        Node::enumeration(ATTRIBUTE_REFERENCE, tag)
    }
}
fn aes_attributes(v: Version) -> Node {
    let a = [
        (
            "Cryptographic Algorithm",
            Node::enumeration(ATTRIBUTE_VALUE, 3),
        ),
        ("Cryptographic Length", Node::int(ATTRIBUTE_VALUE, 256)),
        ("Cryptographic Usage Mask", Node::int(ATTRIBUTE_VALUE, 12)),
    ];
    if v.0 >= 2 {
        Node::structure(
            ATTRIBUTES,
            vec![
                Node::enumeration(CRYPTOGRAPHIC_ALGORITHM, 3),
                Node::int(CRYPTOGRAPHIC_LENGTH, 256),
                Node::int(CRYPTOGRAPHIC_USAGE_MASK, 12),
            ],
        )
    } else {
        Node::structure(
            TEMPLATE_ATTRIBUTE,
            a.into_iter()
                .map(|(name, value)| {
                    Node::structure(ATTRIBUTE, vec![Node::text(ATTRIBUTE_NAME, name), value])
                })
                .collect(),
        )
    }
}
fn create_item(v: Version) -> (u32, Vec<Node>) {
    (
        1,
        vec![Node::enumeration(OBJECT_TYPE, 2), aes_attributes(v)],
    )
}
fn create(f: &mut Fixture, v: Version) -> String {
    let r = f.send(&req(v, vec![], vec![create_item(v)]));
    payload(&r)
        .required(UNIQUE_IDENTIFIER)
        .unwrap()
        .identifier_text()
        .unwrap()
        .to_owned()
}

// REQ:bc7dfe73e0538cd6 the response Protocol Version carries separate major and minor numbers
// REQ:9bb7ba013babad56 every minor version of a supported major version is accepted and answered in kind
// REQ:bb3f03f463623a00 every response header carries a Time Stamp
// REQ:2ca94de9f4e5489c the response header carries the Batch Count of the returned items
// REQ:dc8214a2afd6fdd8 a single-item response reports Batch Count 1
// REQ:de038f376f41bc7f a response always contains at least one Batch Item
// REQ:0298e37fb6c93578 the response message contains its required Response Header and Batch Item
// REQ:25b6c19ac6403ac0 response header, batch item and payload fields are emitted in table order
// REQ:ea3ab2746a28a8ed 1.x structures are encoded with fields in their table order
// REQ:881c80a9c6716120 2.x structures are encoded with fields in their table order
// REQ:71196dd119742ab9 a response item repeats its request's Unique Batch Item ID
// REQ:ef54215bcceea833 1.x response items repeat the request Operation and Unique Batch Item ID
// REQ:21f5c8bb7116e5fd 2.x response items repeat the request Operation and Unique Batch Item ID
// REQ:4f901adde8f2b657 a failed result always carries a Result Reason
// REQ:f2854edaa3cc4773 1.x failed response items include Result Reason
// REQ:22908de540907f50 2.x failed response items include Result Reason
// REQ:8b5697b42226e6ad a successful result never carries a Result Reason
#[test]
fn response_messages_have_required_fields_in_table_order_for_every_final_version() {
    let mut f = Fixture::new();
    for v in FINAL {
        let id = create(&mut f, v);
        let request = req(
            v,
            vec![Node::enumeration(BATCH_ERROR_CONTINUATION_OPTION, 1)],
            vec![
                (10, vec![uid(&id)]),
                (10, vec![uid("absent-object")]),
                (24, vec![Node::enumeration(QUERY_FUNCTION, 1)]),
            ],
        );
        let r = f.send(&request);
        assert_eq!(r.tag, RESPONSE_MESSAGE);
        assert_eq!(
            tags(&r),
            [RESPONSE_HEADER, BATCH_ITEM, BATCH_ITEM, BATCH_ITEM]
        );
        let header = r.required(RESPONSE_HEADER).unwrap();
        let mut expected = vec![PROTOCOL_VERSION, TIME_STAMP];
        if v >= Version(1, 4) {
            expected.push(SERVER_CORRELATION_VALUE);
        }
        expected.push(BATCH_COUNT);
        assert_eq!(tags(header), expected, "{}.{}", v.0, v.1);
        let version = header.required(PROTOCOL_VERSION).unwrap();
        assert_eq!(
            tags(version),
            [PROTOCOL_VERSION_MAJOR, PROTOCOL_VERSION_MINOR]
        );
        assert!(matches!(
            version.required(PROTOCOL_VERSION_MAJOR).unwrap().value,
            Value::Integer(m) if m as u32 == v.0
        ));
        assert!(matches!(
            version.required(PROTOCOL_VERSION_MINOR).unwrap().value,
            Value::Integer(m) if m as u32 == v.1
        ));
        assert!(matches!(
            header.required(TIME_STAMP).unwrap().value,
            Value::DateTime(t) if (t - keytend_kmip_server::store::now()).abs() < 60
        ));
        assert_eq!(num(header, BATCH_COUNT), 3);
        let found = items(&r);
        assert_eq!(statuses(&r), [0, 1, 0]);
        for (index, item) in found.iter().enumerate() {
            let source = items(&request)[index];
            assert!(item.get(OPERATION) == source.get(OPERATION));
            assert!(item.get(UNIQUE_BATCH_ITEM_ID) == source.get(UNIQUE_BATCH_ITEM_ID));
        }
        // Success: Operation, ID, Result Status, Response Payload; no reason.
        assert_eq!(
            tags(found[0]),
            [
                OPERATION,
                UNIQUE_BATCH_ITEM_ID,
                RESULT_STATUS,
                RESPONSE_PAYLOAD
            ]
        );
        let get = found[0].required(RESPONSE_PAYLOAD).unwrap();
        assert_eq!(tags(get), [OBJECT_TYPE, UNIQUE_IDENTIFIER, SYMMETRIC_KEY]);
        assert_eq!(
            tags(
                get.required(SYMMETRIC_KEY)
                    .unwrap()
                    .required(KEY_BLOCK)
                    .unwrap()
            )[..2],
            [KEY_FORMAT_TYPE, KEY_VALUE]
        );
        // Failure: Operation, ID, Result Status, Result Reason, Result Message.
        assert_eq!(
            tags(found[1]),
            [
                OPERATION,
                UNIQUE_BATCH_ITEM_ID,
                RESULT_STATUS,
                RESULT_REASON,
                RESULT_MESSAGE
            ]
        );
        assert_eq!(num(found[1], RESULT_REASON), not_found(v));
        for item in [found[0], found[2]] {
            assert!(item.get(RESULT_REASON).is_none());
            assert!(item.get(RESULT_MESSAGE).is_none());
        }
        // A single request yields a single item and Batch Count 1.
        let r = f.send(&req(v, vec![], vec![(24, vec![])]));
        assert_eq!(items(&r).len(), 1);
        assert_eq!(num(r.required(RESPONSE_HEADER).unwrap(), BATCH_COUNT), 1);
    }
}

// REQ:2ca94de9f4e5489c a request header without Batch Count is refused
// REQ:de038f376f41bc7f a request without any Batch Item is refused
// REQ:5eb1d666956ff569 1.x multi-item requests must give every item a Unique Batch Item ID
// REQ:9c19caac101e50be 2.x multi-item requests must give every item a Unique Batch Item ID
// REQ:3d1e34679d5e1713 1.x Batch Error Continuation Option accepts only its three values
// REQ:af910cbf117791ec 2.x Batch Error Continuation Option accepts only Undo, Stop or Continue
// REQ:3b0a44d0604b8413 a continuation option on a single-item request is refused
#[test]
fn malformed_message_framing_is_refused_before_any_item_runs() {
    for v in FINAL {
        let mut f = Fixture::new();
        let before = f.engine.store.list("alice").unwrap().len();
        // Refused as Invalid Message, or Invalid Field for a missing header field.
        let refused = |r: &Node| statuses(r) == [1] && [4, 7].contains(&reason(r));
        let header = |count: Option<i32>| {
            let mut h = vec![v.node()];
            if let Some(c) = count {
                h.push(Node::int(BATCH_COUNT, c));
            }
            h
        };
        let create = create_item(v);
        // Batch Count missing, or no Batch Item at all.
        let r = f.send(&message(header(None), vec![(1, None, create.1.clone())]));
        assert!(refused(&r), "{}.{}", v.0, v.1);
        let r = f.send(&message(header(Some(0)), vec![]));
        assert!(refused(&r));
        let r = f.send(&message(header(Some(1)), vec![]));
        assert!(refused(&r));
        // Two items, one or both without a Unique Batch Item ID.
        for ids in [[None, None], [Some(1), None]] {
            let r = f.send(&message(
                header(Some(2)),
                vec![(1, ids[0], create.1.clone()), (1, ids[1], create.1.clone())],
            ));
            assert!(refused(&r));
        }
        assert_eq!(f.engine.store.list("alice").unwrap().len(), before);
        // A single item may omit the ID; the reply then omits it too.
        let r = f.send(&message(header(Some(1)), vec![(24, None, vec![])]));
        assert_eq!(statuses(&r), [0]);
        assert!(items(&r)[0].get(UNIQUE_BATCH_ITEM_ID).is_none());
        // Continuation option: only Continue (1), Stop (2) and Undo (3).
        for value in [0, 4, 5, 0x8000_0001] {
            let r = f.send(&req(
                v,
                vec![Node::enumeration(BATCH_ERROR_CONTINUATION_OPTION, value)],
                vec![create.clone(), create.clone()],
            ));
            assert_eq!((statuses(&r), reason(&r)), (vec![1], 7), "{value}");
        }
        for value in [1, 2, 3] {
            let r = f.send(&req(
                v,
                vec![Node::enumeration(BATCH_ERROR_CONTINUATION_OPTION, value)],
                vec![create.clone()],
            ));
            assert_eq!((statuses(&r), reason(&r)), (vec![1], 7), "{value}");
        }
        assert_eq!(f.engine.store.list("alice").unwrap().len(), before);
        for value in [1, 2, 3] {
            let r = f.send(&req(
                v,
                vec![Node::enumeration(BATCH_ERROR_CONTINUATION_OPTION, value)],
                vec![create.clone(), create.clone()],
            ));
            assert_eq!(statuses(&r), [0, 0]);
        }
    }
}

// REQ:28e2762351fb4f84 with Batch Order Option True the items run in request order
// REQ:71c5dc54b817425e Batch Order Option True is supported, so it is honoured rather than rejected
#[test]
fn batch_order_option_true_runs_items_in_request_order() {
    for v in FINAL {
        let mut f = Fixture::new();
        // Get and Activate rely on the ID Placeholder left by the preceding
        // Create; Destroy then finds an Active key and must fail. Any other
        // order would change these results.
        let r = f.send(&req(
            v,
            vec![Node::boolean(BATCH_ORDER_OPTION, true)],
            vec![create_item(v), (10, vec![]), (18, vec![]), (20, vec![])],
        ));
        assert_eq!(
            items(&r)
                .iter()
                .map(|i| num(i, OPERATION))
                .collect::<Vec<_>>(),
            [1, 10, 18, 20]
        );
        assert_eq!(statuses(&r)[..3], [0, 0, 0], "{}.{}", v.0, v.1);
        assert_eq!(statuses(&r)[3], 1);
        let id = payload(&r)
            .required(UNIQUE_IDENTIFIER)
            .unwrap()
            .identifier_text()
            .unwrap()
            .to_owned();
        assert_eq!(f.engine.store.get("alice", &id).unwrap().unwrap().state, 2);
        // A non-Boolean option is malformed.
        let r = f.send(&req(
            v,
            vec![Node::int(BATCH_ORDER_OPTION, 1)],
            vec![(24, vec![]), (24, vec![])],
        ));
        assert_eq!(statuses(&r), [1]);
    }
}

// REQ:b1fc9df9339eb570 Asynchronous Indicator Prohibited is processed synchronously
// REQ:4fd3d7d24eda4561 under Prohibited no batch item is processed asynchronously
// REQ:934a95fa21fd7e43 under Prohibited every batch item is processed synchronously
// REQ:e65b16db98387ada 1.2-1.4: a client that cannot accept asynchronous replies gets synchronous processing
// REQ:054759bb317cf2d6 1.0/1.1: an asynchronous-incapable client is answered synchronously; the server never needs asynchronous processing, so no failure arises
#[test]
fn asynchronous_incapable_or_prohibited_requests_are_processed_synchronously() {
    for v in FINAL {
        let mut f = Fixture::new();
        let indicators = if v.0 == 1 {
            vec![None, Some(Node::boolean(ASYNCHRONOUS_INDICATOR, false))]
        } else {
            vec![None, Some(Node::enumeration(ASYNCHRONOUS_INDICATOR, 3))]
        };
        for indicator in indicators {
            let r = f.send(&req(
                v,
                indicator.into_iter().collect(),
                vec![create_item(v), (10, vec![]), (18, vec![])],
            ));
            assert_eq!(statuses(&r), [0, 0, 0], "{}.{}", v.0, v.1);
            for item in items(&r) {
                assert!(item.get(ASYNCHRONOUS_CORRELATION_VALUE).is_none());
                assert!(item.get(RESPONSE_PAYLOAD).is_some());
            }
            let id = payload(&r)
                .required(UNIQUE_IDENTIFIER)
                .unwrap()
                .identifier_text()
                .unwrap()
                .to_owned();
            // The work is complete when the response arrives.
            assert_eq!(f.engine.store.get("alice", &id).unwrap().unwrap().state, 2);
        }
    }
}

// REQ:c8fa1eb1caadd67b an object gets at most one replacement: a second Re-key of the same key fails
#[test]
fn rekey_creates_at_most_one_replacement_per_object() {
    for v in FINAL {
        let mut f = Fixture::new();
        let id = create(&mut f, v);
        payload(&f.send(&req(v, vec![], vec![(18, vec![uid(&id)])])));
        let r = f.send(&req(v, vec![], vec![(4, vec![uid(&id)])]));
        let first = payload(&r)
            .required(UNIQUE_IDENTIFIER)
            .unwrap()
            .identifier_text()
            .unwrap()
            .to_owned();
        let count = f.engine.store.list("alice").unwrap().len();
        let r = f.send(&req(v, vec![], vec![(4, vec![uid(&id)])]));
        assert_eq!(statuses(&r), [1], "{}.{}", v.0, v.1);
        assert_eq!(f.engine.store.list("alice").unwrap().len(), count);
        // The replacement itself may be replaced once, forming a chain.
        payload(&f.send(&req(v, vec![], vec![(4, vec![uid(&first)])])));
        let r = f.send(&req(v, vec![], vec![(4, vec![uid(&first)])]));
        assert_eq!(statuses(&r), [1]);
    }
}

// REQ:348fa01b982c9be3 1.x Delete Attribute of a read-only or required attribute fails with Permission Denied
#[test]
fn delete_attribute_of_read_only_or_required_attributes_is_permission_denied() {
    for v in &FINAL[..5] {
        let v = *v;
        let mut f = Fixture::new();
        let id = create(&mut f, v);
        for (name, tag) in [
            ("Unique Identifier", UNIQUE_IDENTIFIER),
            ("Object Type", OBJECT_TYPE),
            ("Cryptographic Algorithm", CRYPTOGRAPHIC_ALGORITHM),
            ("Cryptographic Length", CRYPTOGRAPHIC_LENGTH),
            ("State", STATE),
            ("Initial Date", INITIAL_DATE),
        ] {
            let r = f.send(&req(
                v,
                vec![],
                vec![(15, vec![uid(&id), attr_name(v, name, tag)])],
            ));
            assert_eq!(
                (statuses(&r), reason(&r)),
                (vec![1], 12),
                "{}.{} {name}",
                v.0,
                v.1
            );
        }
    }
}

// REQ:591d185fc5651efa Encryption Key Information is needed when MAC/Signature Key Information is absent
// REQ:7a18056bc29e5e9a MAC/Signature Key Information is needed when Encryption Key Information is absent
#[test]
fn key_wrapping_specification_without_any_key_information_is_refused() {
    for v in FINAL {
        let mut f = Fixture::new();
        let id = create(&mut f, v);
        let exported = f.engine.store.get("alice", &id).unwrap().unwrap();
        for method in [1, 2, 3] {
            let spec = Node::structure(
                KEY_WRAPPING_SPECIFICATION,
                vec![Node::enumeration(WRAPPING_METHOD, method)],
            );
            let r = f.send(&req(v, vec![], vec![(10, vec![uid(&id), spec])]));
            assert_eq!(statuses(&r), [1], "{}.{} {method}", v.0, v.1);
            assert!(items(&r)[0].get(RESPONSE_PAYLOAD).is_none());
        }
        let after = f.engine.store.get("alice", &id).unwrap().unwrap();
        assert_eq!(after.material, exported.material);
        assert_eq!(after.usage_consumed, exported.usage_consumed);
    }
}

// REQ:4266a1be5b0cab2e Server Information carries no vendor-specific field, so no standard equivalent is omitted
// REQ:e24eab42d848326b Query Server Information always returns the Server Information structure
#[test]
fn query_server_information_returns_the_structure_without_vendor_only_fields() {
    for v in FINAL {
        let mut f = Fixture::new();
        let r = f.send(&req(
            v,
            vec![],
            vec![(24, vec![Node::enumeration(QUERY_FUNCTION, 3)])],
        ));
        let p = payload(&r);
        assert!(
            !p.required(VENDOR_IDENTIFICATION)
                .unwrap()
                .string()
                .unwrap()
                .is_empty()
        );
        let info = p.required(SERVER_INFORMATION).unwrap();
        assert!(info.children().unwrap().iter().all(|n| n.tag < 0x540000));
    }
}

// REQ:e3d807a8302db89b the server's Random Number Generator attribute names its RNG Algorithm, Unspecified when undisclosed
#[test]
fn generated_keys_report_an_rng_algorithm() {
    for v in &FINAL[3..] {
        let v = *v;
        let mut f = Fixture::new();
        let id = create(&mut f, v);
        let r = f.send(&req(
            v,
            vec![],
            vec![(
                11,
                vec![
                    uid(&id),
                    attr_name(v, "Random Number Generator", RANDOM_NUMBER_GENERATOR),
                ],
            )],
        ));
        let p = payload(&r);
        let rng = if v.0 == 1 {
            p.required(ATTRIBUTE)
                .unwrap()
                .required(ATTRIBUTE_VALUE)
                .unwrap()
        } else {
            p.required(ATTRIBUTES)
                .unwrap()
                .required(RANDOM_NUMBER_GENERATOR)
                .unwrap()
        };
        assert!(matches!(
            rng.required(RNG_ALGORITHM).unwrap().value,
            Value::Enumeration(1)
        ));
    }
}

#[derive(serde::Deserialize)]
struct Registry {
    tags: std::collections::BTreeMap<String, u32>,
    enums: std::collections::BTreeMap<String, std::collections::BTreeMap<String, u32>>,
}
fn walk<'a>(n: &'a Node, out: &mut Vec<&'a Node>) {
    out.push(n);
    if let Value::Structure(children) = &n.value {
        for c in children {
            walk(c, out);
        }
    }
}

// REQ:cb2a69c3a3debb64 2.x responses use only tags and enumeration values listed (not Reserved) for that edition
// REQ:ae20ad1c598a08af every tag the server emits starts with byte 42 or 54
#[test]
fn responses_use_only_listed_tags_and_enumeration_values() {
    let registries: std::collections::BTreeMap<String, Registry> =
        serde_json::from_str(include_str!("../src/wire_registry.json")).unwrap();
    for v in [Version(2, 0), Version(2, 1)] {
        let registry = &registries[&format!("{}.{}", v.0, v.1)];
        let names: std::collections::BTreeMap<u32, &str> = registry
            .tags
            .iter()
            .filter(|(name, _)| !name.contains("Reserved"))
            .map(|(name, tag)| (*tag, name.as_str()))
            .collect();
        let mut f = Fixture::new();
        let id = create(&mut f, v);
        let pair = vec![
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
        ];
        let mut responses = vec![];
        for (op, p) in [
            (10, vec![uid(&id)]),
            (11, vec![uid(&id)]),
            (12, vec![uid(&id)]),
            (18, vec![uid(&id)]),
            (8, vec![]),
            (
                24,
                [1, 2, 3, 11, 14]
                    .map(|q| Node::enumeration(QUERY_FUNCTION, q))
                    .to_vec(),
            ),
            (30, vec![]),
            (2, pair),
            (10, vec![uid("absent")]),
        ] {
            responses.push(f.send(&req(v, vec![], vec![(op, p)])));
        }
        let mut seen = 0;
        for r in &responses {
            let mut nodes = vec![];
            walk(r, &mut nodes);
            for n in nodes {
                assert!(
                    [0x42, 0x54].contains(&((n.tag >> 16) as u8)),
                    "{:06x}",
                    n.tag
                );
                if n.tag >= 0x540000 {
                    continue;
                }
                let name = names
                    .get(&n.tag)
                    .unwrap_or_else(|| panic!("{}.{} unlisted tag {:06x}", v.0, v.1, n.tag));
                if let (Value::Enumeration(value), Some(table)) =
                    (&n.value, registry.enums.get(*name))
                {
                    assert!(
                        table
                            .iter()
                            .any(|(label, code)| code == value && !label.contains("Reserved")),
                        "{name} {value:#x}"
                    );
                }
                seen += 1;
            }
        }
        assert!(seen > 100);
    }
}

fn hex_encode(n: &Node) -> String {
    hex::encode(n.encode())
}

// REQ:628de315ec6879ba the decoder refuses any tag whose first byte is not 42 or 54
// REQ:ae20ad1c598a08af tags are three bytes beginning with 42 or 54 on decode and encode
#[test]
fn tags_outside_the_42_and_54_namespaces_are_refused() {
    for good in [
        "42002a02000000040000010000000000",
        "54000102000000040000000100000000",
    ] {
        let n = ttlv::decode(&hex::decode(good).unwrap()).unwrap();
        assert_eq!(hex_encode(&n), good);
    }
    for bad in [
        "00002a02000000040000010000000000",
        "43002a02000000040000010000000000",
        "41ffff02000000040000010000000000",
        "55000102000000040000000100000000",
    ] {
        assert!(ttlv::decode(&hex::decode(bad).unwrap()).is_err(), "{bad}");
    }
    // A structure containing a foreign tag is refused as a whole.
    let inner = "43000102000000040000000100000000";
    let outer = format!("42007b0100000010{inner}");
    assert!(ttlv::decode(&hex::decode(outer).unwrap()).is_err());
}

// REQ:210914047594ef27 text and byte strings get the fewest zero bytes reaching a multiple of eight
// REQ:e99ebe0a603b4f32 text strings are written without a terminating null byte
#[test]
fn strings_use_minimal_padding_and_no_null_terminator() {
    for len in 0..=17usize {
        let text = "a".repeat(len);
        for node in [
            Node::text(NAME_VALUE, text.clone()),
            Node::bytes(DATA, vec![0xab; len]),
        ] {
            let wire = node.encode();
            assert_eq!(wire.len(), 8 + len.next_multiple_of(8));
            assert_eq!(
                u32::from_be_bytes(wire[4..8].try_into().unwrap()) as usize,
                len
            );
            assert!(wire[8 + len..].iter().all(|&b| b == 0));
            assert!(ttlv::decode(&wire).unwrap() == node);
            // Excess padding is not accepted as part of the item.
            let mut extra = wire.clone();
            extra.extend([0; 8]);
            assert!(ttlv::decode(&extra).is_err());
        }
    }
    let wire = Node::text(NAME_VALUE, "abc").encode();
    assert_eq!(
        hex::encode(&wire),
        "4200550700000003616263".to_owned() + "0000000000"
    );
    assert!(!wire[8..11].contains(&0));
}

// REQ:134c7dc33baecbc7 Integer, Enumeration and Interval values are followed by four zero padding bytes
#[test]
fn four_byte_values_are_padded_with_four_zero_bytes() {
    for (node, hex) in [
        (
            Node::int(CRYPTOGRAPHIC_LENGTH, 256),
            "42002a02000000040000010000000000",
        ),
        (
            Node::enumeration(OBJECT_TYPE, 2),
            "42005705000000040000000200000000",
        ),
        (
            Node::interval(OFFSET, 27),
            "4200580a000000040000001b00000000",
        ),
    ] {
        assert_eq!(hex_encode(&node), hex);
        assert!(ttlv::decode(&hex::decode(hex).unwrap()).unwrap() == node);
        let mut bad = hex::decode(hex).unwrap();
        bad[15] = 1;
        assert!(ttlv::decode(&bad).is_err());
        assert!(ttlv::decode(&bad[..12]).is_err());
    }
}

// REQ:7e838d7a82d1e581 Big Integers are sign-extended with leading bytes to a multiple of eight
// REQ:9df2bd854291e7fa the Big Integer padding bytes are included in the Item Length
#[test]
fn big_integers_are_sign_extended_and_padding_is_counted_in_the_length() {
    for (value, hex) in [
        (
            vec![0x01],
            "4200040400000008".to_owned() + "0000000000000001",
        ),
        (
            vec![0x80],
            "4200040400000008".to_owned() + "ffffffffffffff80",
        ),
        (
            vec![0x7f, 0xff],
            "4200040400000008".to_owned() + "0000000000007fff",
        ),
        (
            vec![0xff; 9],
            "4200040400000010".to_owned() + "ffffffffffffffffffffffffffffffff",
        ),
        (
            vec![0; 8],
            "4200040400000008".to_owned() + "0000000000000000",
        ),
    ] {
        let node = Node {
            tag: 0x420004,
            value: Value::BigInteger(value),
        };
        assert_eq!(hex_encode(&node), hex);
        assert_eq!(node.encoded_len(), hex.len() / 2);
        let decoded = ttlv::decode(&hex::decode(&hex).unwrap()).unwrap();
        let Value::BigInteger(bytes) = &decoded.value else {
            panic!("expected Big Integer")
        };
        assert_eq!(bytes.len(), hex.len() / 2 - 8);
    }
    // A Big Integer whose length is not a multiple of eight is malformed.
    assert!(ttlv::decode(&hex::decode("42000404000000040000000100000000").unwrap()).is_err());
}

// REQ:51655f453531af44 Booleans are eight bytes holding exactly 0 or 1
#[test]
fn booleans_are_eight_byte_zero_or_one() {
    assert_eq!(
        hex_encode(&Node::boolean(BATCH_ORDER_OPTION, true)),
        "4200100600000008".to_owned() + "0000000000000001"
    );
    assert_eq!(
        hex_encode(&Node::boolean(BATCH_ORDER_OPTION, false)),
        "4200100600000008".to_owned() + "0000000000000000"
    );
    for bad in ["0000000000000002", "0100000000000000", "ffffffffffffffff"] {
        let wire = hex::decode("4200100600000008".to_owned() + bad).unwrap();
        assert!(ttlv::decode(&wire).is_err(), "{bad}");
    }
    assert!(ttlv::decode(&hex::decode("420010060000000400000001").unwrap()).is_err());
}

/// Profiles 1.3-2.1 section 5.4.1.1/5.5.1.1 CamelCase rules, applied
/// independently of the server's registry.
fn camel_case(text: &str) -> String {
    let chars: Vec<char> = text.replace(['(', ')'], " ").chars().collect();
    let word = |c: char| c.is_ascii_alphanumeric() || c == '_';
    let mut spaced = String::new();
    for (i, &c) in chars.iter().enumerate() {
        let next = chars.get(i + 1).copied().unwrap_or(' ');
        let after = chars.get(i + 2).copied().unwrap_or(' ');
        spaced.push(if word(c) || c.is_whitespace() {
            c
        } else if next.is_ascii_alphabetic() && after.is_ascii_lowercase() {
            ' '
        } else {
            '_'
        });
    }
    let mut words: Vec<String> = spaced.split_whitespace().map(str::to_owned).collect();
    if let Some(first) = words.first_mut() {
        let digits = first.chars().take_while(char::is_ascii_digit).count();
        let (lead, rest) = first.split_at(digits);
        *first = format!("{rest}{lead}");
    }
    words
        .iter()
        .map(|w| {
            let mut c = w.chars();
            c.next()
                .map(|f| f.to_ascii_uppercase().to_string() + c.as_str())
                .unwrap_or_default()
        })
        .collect()
}

// REQ:75e63e80ef7a5157 XML tag and enumeration text follows the normalized CamelCase form
// REQ:da98ea248b1489b1 JSON tag and enumeration text follows the normalized CamelCase form
// REQ:0de78f060bb686af the six normalization rules produce the names the server accepts
#[test]
fn normalized_camel_case_names_are_accepted_for_tags_and_enumerations() {
    assert_eq!(camel_case("3DES"), "DES3");
    assert_eq!(camel_case("Re-key Key Pair"), "ReKeyKeyPair");
    assert_eq!(camel_case("PKCS1 v1.5"), "PKCS1V1_5");
    let mut checked = 0;
    for tag in 0x420001..=0x42ffffu32 {
        let Some(text) = tag_name(tag) else { continue };
        let name = camel_case(text);
        let xml = format!("<{name}/>");
        let json = format!("{{\"tag\":\"{name}\",\"value\":[]}}");
        for (format, data) in [
            (Format::Xml, xml.as_bytes()),
            (Format::Json, json.as_bytes()),
        ] {
            let n = format
                .decode(data)
                .unwrap_or_else(|e| panic!("{text} -> {name}: {e}"));
            assert_eq!(n.tag, tag, "{text} -> {name}");
        }
        checked += 1;
    }
    assert!(checked > 300);
    for (tag, text, value) in [
        ("CryptographicAlgorithm", "3DES", 2),
        ("CryptographicAlgorithm", "AES", 3),
        ("PaddingMethod", "PKCS1 v1.5", 8),
        ("PaddingMethod", "ANSI X9.23", 6),
        ("PaddingMethod", "ISO 10126", 7),
        ("HashingAlgorithm", "SHA-256", 6),
        ("HashingAlgorithm", "SHA-512/224", 12),
        ("HashingAlgorithm", "RIPEMD-160", 9),
        ("Operation", "Re-key", 4),
        ("Operation", "Re-key Key Pair", 29),
        ("Operation", "Get Attribute List", 12),
        ("ObjectType", "Symmetric Key", 2),
        ("BlockCipherMode", "NIST Key Wrap", 13),
        ("BlockCipherMode", "AES Key Wrap Padding", 12),
        ("BlockCipherMode", "X9.102 AESKW", 14),
    ] {
        let name = camel_case(text);
        let xml = format!("<{tag} type=\"Enumeration\" value=\"{name}\"/>");
        let json = format!("{{\"tag\":\"{tag}\",\"type\":\"Enumeration\",\"value\":\"{name}\"}}");
        for (format, data) in [
            (Format::Xml, xml.as_bytes()),
            (Format::Json, json.as_bytes()),
        ] {
            let n = format
                .decode(data)
                .unwrap_or_else(|e| panic!("{text}: {e}"));
            assert!(n.value == Value::Enumeration(value), "{text} -> {name}");
        }
        // The unnormalized specification text is not a valid symbolic value.
        if name != text {
            let xml = format!("<{tag} type=\"Enumeration\" value=\"{text}\"/>");
            assert!(Format::Xml.decode(xml.as_bytes()).is_err(), "{text}");
        }
    }
}

// REQ:dc6469013ac69bdc 2.0 XML and JSON Date-Time text always carries a time zone
// REQ:4dc962c92099dbb4 2.1 XML and JSON Date-Time text always carries a time zone
#[test]
fn text_date_times_require_and_carry_a_time_zone() {
    for zoned in ["2001-01-01T10:00:00+10:00", "2001-01-01T00:00:00Z"] {
        let xml = format!("<ActivationDate type=\"DateTime\" value=\"{zoned}\"/>");
        let json =
            format!("{{\"tag\":\"ActivationDate\",\"type\":\"DateTime\",\"value\":\"{zoned}\"}}");
        for (format, data) in [
            (Format::Xml, xml.as_bytes()),
            (Format::Json, json.as_bytes()),
        ] {
            assert!(matches!(
                format.decode(data).unwrap().value,
                Value::DateTime(_)
            ));
        }
    }
    for local in ["2001-01-01T10:00:00", "2001-01-01T10:00:00.5"] {
        let xml = format!("<ActivationDate type=\"DateTime\" value=\"{local}\"/>");
        let json =
            format!("{{\"tag\":\"ActivationDate\",\"type\":\"DateTime\",\"value\":\"{local}\"}}");
        for (format, data) in [
            (Format::Xml, xml.as_bytes()),
            (Format::Json, json.as_bytes()),
        ] {
            assert!(format.decode(data).is_err(), "{local}");
        }
    }
    // The server writes XML Date-Time values in UTC with an explicit "Z".
    let xml = Format::Xml
        .encode(&Node::date(TIME_STAMP, 978307200))
        .unwrap();
    assert!(
        std::str::from_utf8(&xml)
            .unwrap()
            .contains("value=\"2001-01-01T00:00:00Z\"")
    );
}

// REQ:61c500dd37acc70e an XML request yields the same logical results as its TTLV form
// REQ:fc5d09c0f0db3234 a JSON request yields the same logical results as its TTLV form
#[test]
fn xml_and_json_requests_produce_the_same_logical_results_as_ttlv() {
    let v = Version(2, 1);
    let mut results = vec![];
    for format in [Format::Ttlv, Format::Xml, Format::Json] {
        let mut f = Fixture::new();
        let id = create(&mut f, v);
        let request = req(
            v,
            vec![Node::enumeration(BATCH_ERROR_CONTINUATION_OPTION, 1)],
            vec![
                (12, vec![uid(&id)]),
                (
                    24,
                    vec![
                        Node::enumeration(QUERY_FUNCTION, 1),
                        Node::enumeration(QUERY_FUNCTION, 2),
                    ],
                ),
                (10, vec![uid("absent")]),
                (8, vec![]),
            ],
        );
        let wire = format.encode(&request).unwrap();
        let decoded = format.decode(&wire).unwrap();
        assert!(decoded == request);
        let response = f
            .engine
            .process_with_grants_encoded("alice", &decoded, None, &[], format)
            .unwrap();
        let reply = format.decode(&format.encode(&response).unwrap()).unwrap();
        assert!(reply == response);
        // Compare everything except per-message identity and time values.
        let mut items: Vec<Node> = reply.all(BATCH_ITEM).cloned().collect();
        let scrub = |n: &mut Node, id: &str| {
            fn go(n: &mut Node, id: &str) {
                match &mut n.value {
                    Value::Structure(c) => c.iter_mut().for_each(|n| go(n, id)),
                    Value::DateTime(t) => *t = 0,
                    Value::TextString(s) if s == id => *s = "ID".into(),
                    _ => {}
                }
            }
            go(n, id)
        };
        items.iter_mut().for_each(|n| scrub(n, &id));
        results.push(items);
    }
    assert_eq!(
        statuses(&Node::structure(RESPONSE_MESSAGE, results[0].clone())),
        [0, 0, 1, 0]
    );
    assert!(results[0] == results[1]);
    assert!(results[0] == results[2]);
}

// REQ:c8608843ad06c8e7 1.x Create Key Pair without its REQUIRED attributes fails with Invalid Message
#[test]
fn legacy_create_key_pair_requires_algorithm_and_usage_mask() {
    let mut f = Fixture::new();
    let attribute = |name: &str, value: Node| {
        Node::structure(ATTRIBUTE, vec![Node::text(ATTRIBUTE_NAME, name), value])
    };
    let algorithm = || {
        attribute(
            "Cryptographic Algorithm",
            Node::enumeration(ATTRIBUTE_VALUE, 4),
        )
    };
    let length = || attribute("Cryptographic Length", Node::int(ATTRIBUTE_VALUE, 2048));
    let mask = |m| attribute("Cryptographic Usage Mask", Node::int(ATTRIBUTE_VALUE, m));
    for v in &FINAL[..5] {
        let v = *v;
        let common = |attrs: Vec<Node>| vec![Node::structure(COMMON_TEMPLATE_ATTRIBUTE, attrs)];
        // Table 112 (1.0) / 168 (1.4): Cryptographic Algorithm and Usage Mask are REQUIRED.
        for payload in [
            vec![],
            common(vec![algorithm(), length()]),
            common(vec![length(), mask(1)]),
        ] {
            let r = f.send(&req(v, vec![], vec![(2, payload)]));
            assert_eq!(statuses(&r), vec![1]);
            assert_eq!(reason(&r), 4, "{}.{}", v.0, v.1);
        }
        // Present anywhere in the request, they satisfy the table.
        let split = vec![
            Node::structure(COMMON_TEMPLATE_ATTRIBUTE, vec![algorithm(), length()]),
            Node::structure(PRIVATE_KEY_TEMPLATE_ATTRIBUTE, vec![mask(1)]),
            Node::structure(PUBLIC_KEY_TEMPLATE_ATTRIBUTE, vec![mask(2)]),
        ];
        payload(&f.send(&req(v, vec![], vec![(2, split)])));
    }
    // 2.0 and 2.1 (tables 176/191) drop the REQUIRED column: server defaults apply.
    for v in &FINAL[5..] {
        payload(&f.send(&req(*v, vec![], vec![(2, vec![])])));
    }
}

#[test]
fn duplicate_get_attributes_names_follow_each_edition() {
    let mut f = Fixture::new();
    for v in FINAL {
        let id = create(&mut f, v);
        let name = attr_name(v, "Cryptographic Algorithm", CRYPTOGRAPHIC_ALGORITHM);
        let r = f.send(&req(
            v,
            vec![],
            vec![(11, vec![uid(&id), name.clone(), name])],
        ));
        // 1.1-1.4 Get Attributes errors (1.1 table 261, 1.2 table 302): "The
        // same Attribute Name is present more than once" is Invalid Message.
        // 1.0 has no such row; 2.x has only the general prohibition.
        match v {
            Version(1, 0) => {
                payload(&r);
            }
            Version(1, _) => assert_eq!(reason(&r), 4),
            _ => assert_eq!(reason(&r), 7),
        }
    }
}

/// Item Not Found in 1.x; Object Not Found (0x37) where the 2.x and draft 3.0
/// error tables list it (see src/protocol/not_found.rs).
fn not_found(v: Version) -> u32 {
    if v.0 >= 2 { 0x37 } else { 1 }
}
