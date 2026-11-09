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

//! Server behavior decided while triaging the KMIP 1.1/1.2 Test Cases notes:
//! the Result Reason for an emptied ID
//! Placeholder, Get of a destroyed object, and Non-Critical Message
//! Extensions. Each test has positive and negative cases per edition.
use keytend_kmip_server::{
    protocol::{Engine, Version},
    store::Store,
    tags::*,
    ttlv::{Node, Value},
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
    fn send(&mut self, owner: &str, items: Vec<Node>, v: Version) -> Node {
        let mut fields = vec![Node::structure(
            REQUEST_HEADER,
            vec![v.node(), Node::int(BATCH_COUNT, items.len() as i32)],
        )];
        // Batched items carry a Unique Batch Item ID (1.x section 6.11).
        let batched = items.len() > 1;
        fields.extend(items.into_iter().enumerate().map(|(i, mut item)| {
            if batched && let Value::Structure(f) = &mut item.value {
                f.insert(1, Node::bytes(UNIQUE_BATCH_ITEM_ID, vec![i as u8 + 1]));
            }
            item
        }));
        self.engine
            .process(owner, &Node::structure(REQUEST_MESSAGE, fields))
            .unwrap()
    }
    fn call(&mut self, owner: &str, v: Version, op: u32, payload: Vec<Node>) -> Node {
        self.send(owner, vec![item(op, payload, vec![])], v)
    }
}

fn item(op: u32, payload: Vec<Node>, extra: Vec<Node>) -> Node {
    let mut fields = vec![
        Node::enumeration(OPERATION, op),
        Node::structure(REQUEST_PAYLOAD, payload),
    ];
    fields.extend(extra);
    Node::structure(BATCH_ITEM, fields)
}
fn items(r: &Node) -> Vec<&Node> {
    r.all(BATCH_ITEM).collect()
}
fn num(n: &Node, tag: u32) -> u32 {
    n.required(tag).unwrap().number().unwrap()
}
fn ok(item: &Node) -> &Node {
    assert_eq!(
        num(item, RESULT_STATUS),
        0,
        "reason {:?}",
        item.get(RESULT_REASON).map(|n| n.number())
    );
    item.required(RESPONSE_PAYLOAD).unwrap()
}
fn reason(item: &Node) -> u32 {
    assert_eq!(num(item, RESULT_STATUS), 1, "expected Operation Failed");
    num(item, RESULT_REASON)
}
fn uid(id: &str) -> Node {
    Node::text(UNIQUE_IDENTIFIER, id)
}
fn attribute(v: Version, name: &str, value: Node) -> Node {
    if v.0 >= 2 {
        return value;
    }
    Node::structure(
        ATTRIBUTE,
        vec![
            Node::text(ATTRIBUTE_NAME, name),
            Node {
                tag: ATTRIBUTE_VALUE,
                value: value.value,
            },
        ],
    )
}
fn name(v: Version, value: &str) -> Node {
    attribute(
        v,
        "Name",
        Node::structure(
            NAME,
            vec![
                Node::text(NAME_VALUE, value),
                Node::enumeration(NAME_TYPE, 1),
            ],
        ),
    )
}
fn create_payload(v: Version, key_name: &str) -> Vec<Node> {
    let attrs = vec![
        attribute(
            v,
            "Cryptographic Algorithm",
            Node::enumeration(CRYPTOGRAPHIC_ALGORITHM, 3),
        ),
        attribute(
            v,
            "Cryptographic Length",
            Node::int(CRYPTOGRAPHIC_LENGTH, 128),
        ),
        attribute(
            v,
            "Cryptographic Usage Mask",
            Node::int(CRYPTOGRAPHIC_USAGE_MASK, 12),
        ),
        name(v, key_name),
    ];
    let container = if v.0 >= 2 {
        ATTRIBUTES
    } else {
        TEMPLATE_ATTRIBUTE
    };
    vec![
        Node::enumeration(OBJECT_TYPE, 2),
        Node::structure(container, attrs),
    ]
}
fn create(f: &mut Fixture, v: Version, key_name: &str) -> String {
    let r = f.call("alice", v, 1, create_payload(v, key_name));
    ok(items(&r)[0])
        .required(UNIQUE_IDENTIFIER)
        .unwrap()
        .string()
        .unwrap()
        .to_owned()
}
fn locate(v: Version, key_name: &str) -> Vec<Node> {
    if v.0 >= 2 {
        vec![Node::structure(ATTRIBUTES, vec![name(v, key_name)])]
    } else {
        vec![name(v, key_name)]
    }
}

/// KMIP 1.x section 4.9: a Locate that matches nothing empties the ID
/// Placeholder, causing later batched operations without a Unique Identifier
/// "to fail". 1.x: Item Not Found, the only row the 1.x error tables give for
/// an unidentified object (1.1 table 260, 1.2 table 301 Get) and the reason
/// the 1.2 note expects (TC-152-11 in 1.1, TC-152-12 in 1.2). 2.x: Invalid
/// Field (2.1 Table 222 lists no Missing Data).
#[test]
fn emptied_id_placeholder_fails_with_the_editions_reason() {
    for v in FINAL {
        let mut f = Fixture::new();
        let id = create(&mut f, v, "present");
        // Negative: the Locate matches nothing, so the batched Get fails.
        let r = f.send(
            "alice",
            vec![
                item(8, locate(v, "absent"), vec![]),
                item(10, vec![], vec![]),
            ],
            v,
        );
        let got = items(&r);
        assert!(ok(got[0]).get(UNIQUE_IDENTIFIER).is_none());
        assert_eq!(
            reason(got[1]),
            if v.0 >= 2 { 7 } else { 1 },
            "{}.{}",
            v.0,
            v.1
        );
        // Without any preceding operation the placeholder is unset: same reason.
        let r = f.call("alice", v, 10, vec![]);
        assert_eq!(reason(items(&r)[0]), if v.0 >= 2 { 7 } else { 1 });
        // Positive: a single match sets the placeholder and the Get succeeds.
        let r = f.send(
            "alice",
            vec![
                item(8, locate(v, "present"), vec![]),
                item(10, vec![], vec![]),
            ],
            v,
        );
        let got = items(&r);
        ok(got[0]);
        assert_eq!(
            ok(got[1])
                .required(UNIQUE_IDENTIFIER)
                .unwrap()
                .string()
                .unwrap(),
            id
        );
        // An explicit unknown identifier is still the not-found reason.
        let r = f.call("alice", v, 10, vec![uid("absent")]);
        assert_eq!(reason(items(&r)[0]), if v.0 >= 2 { 0x37 } else { 1 });
    }
}

/// Every 1.x Get Errors table (1.0 table 236, 1.1 table 260, 1.2 table 301,
/// 1.3, 1.4): "Object exists and is not a Template, but the server only has
/// attributes for this object" -> Illegal Operation. Key Value Not Present is
/// never a Get reason in 1.x (1.2-1.4 list it for Re-key, Re-key Key Pair,
/// Derive Key and the 1.3+ cryptographic operations). 2.x: Object Destroyed.
#[test]
fn destroyed_get_is_illegal_operation_in_every_1x_edition() {
    for v in FINAL {
        let mut f = Fixture::new();
        let id = create(&mut f, v, "doomed");
        let live = create(&mut f, v, "live");
        ok(items(&f.call("alice", v, 20, vec![uid(&id)]))[0]);
        let r = f.call("alice", v, 10, vec![uid(&id)]);
        assert_eq!(
            reason(items(&r)[0]),
            if v.0 >= 2 { 0x36 } else { 11 },
            "{}.{}",
            v.0,
            v.1
        );
        // Negative: another owner learns nothing about the destroyed object.
        let r = f.call("bob", v, 10, vec![uid(&id)]);
        assert_eq!(reason(items(&r)[0]), if v.0 >= 2 { 0x37 } else { 1 });
        // A live object is unaffected.
        ok(items(&f.call("alice", v, 10, vec![uid(&live)]))[0]);
    }
}

fn extension(critical: bool) -> Node {
    // The TC-71-10/11/12 shape: vendor Acme, an Extensions-range field.
    Node::structure(
        MESSAGE_EXTENSION,
        vec![
            Node::text(VENDOR_IDENTIFICATION, "Acme"),
            Node::boolean(CRITICALITY_INDICATOR, critical),
            Node::structure(VENDOR_EXTENSION, vec![Node::text(0x540001, "na")]),
        ],
    )
}

// REQ:740c5de9849a527d a Non-Critical extension not understood is processed as if absent
// REQ:576184b7409e523e an unknown Critical extension still rejects the whole message
/// 1.0-1.4 section 6.16 (2.0/2.1 section 9.13): a Non-Critical extension the
/// receiver does not understand "MAY" be ignored and the rest of the message
/// processed; a Critical one "SHALL" reject the entire message.
#[test]
fn noncritical_extension_is_ignored_and_critical_still_rejects() {
    for v in FINAL {
        let mut f = Fixture::new();
        let r = f.send(
            "alice",
            vec![item(
                1,
                create_payload(v, "extended"),
                vec![extension(false)],
            )],
            v,
        );
        let created = ok(items(&r)[0]);
        assert_eq!(num(created, OBJECT_TYPE), 2);
        assert_eq!(f.engine.store.list("alice").unwrap().len(), 1);
        // Negative: the same request marked Critical creates nothing.
        let r = f.send(
            "alice",
            vec![item(
                1,
                create_payload(v, "critical"),
                vec![extension(true)],
            )],
            v,
        );
        assert_eq!(reason(items(&r)[0]), if v.0 >= 2 { 0x3c } else { 8 });
        assert_eq!(f.engine.store.list("alice").unwrap().len(), 1);
        // Negative: a Non-Critical extension that is malformed still fails.
        let malformed = Node::structure(
            MESSAGE_EXTENSION,
            vec![
                Node::text(VENDOR_IDENTIFICATION, "Acme"),
                Node::boolean(CRITICALITY_INDICATOR, false),
            ],
        );
        let r = f.send(
            "alice",
            vec![item(1, create_payload(v, "malformed"), vec![malformed])],
            v,
        );
        assert_eq!(reason(items(&r)[0]), 4);
        assert_eq!(f.engine.store.list("alice").unwrap().len(), 1);
    }
}
