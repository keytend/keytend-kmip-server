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

use keytend_kmip_server::{
    protocol::{Engine, Version},
    store::{Store, now},
    tags::*,
    ttlv::{Node, Value},
};

struct Fixture {
    dir: tempfile::TempDir,
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
    fn restart(&mut self) {
        self.engine = Engine::new(
            Store::open(
                &self.dir.path().join("keys.sqlite"),
                &self.dir.path().join("master"),
            )
            .unwrap(),
            true,
        );
    }
    fn call(&mut self, v: Version, owner: &str, op: u32, fields: Vec<Node>) -> Node {
        self.engine
            .process(owner, &request(v, vec![(op, fields)], None, None))
            .unwrap()
    }
    fn create(&mut self, v: Version, extra: Vec<Node>) -> String {
        let mut attrs = vec![
            Node::enumeration(CRYPTOGRAPHIC_ALGORITHM, 3),
            Node::int(CRYPTOGRAPHIC_LENGTH, 256),
            Node::int(CRYPTOGRAPHIC_USAGE_MASK, 12),
        ];
        attrs.extend(extra);
        let r = self.call(
            v,
            "alice",
            1,
            vec![
                Node::enumeration(OBJECT_TYPE, 2),
                if v.0 == 1 {
                    Node::structure(TEMPLATE_ATTRIBUTE, attrs.into_iter().map(legacy).collect())
                } else {
                    Node::structure(ATTRIBUTES, attrs)
                },
            ],
        );
        payload(&r)
            .required(UNIQUE_IDENTIFIER)
            .unwrap()
            .identifier_text()
            .unwrap()
            .to_owned()
    }
    fn adjust(
        &mut self,
        v: Version,
        id: &str,
        reference: Node,
        kind: u32,
        amount: Option<Value>,
    ) -> Node {
        let mut fields = vec![
            uid(v, id),
            reference,
            Node::enumeration(ADJUSTMENT_TYPE, kind),
        ];
        if let Some(value) = amount {
            fields.push(Node {
                tag: ADJUSTMENT_VALUE,
                value,
            });
        }
        self.call(v, "alice", 48, fields)
    }
    fn value(&self, id: &str, name: &str) -> Value {
        self.engine
            .store
            .get("alice", id)
            .unwrap()
            .unwrap()
            .attrs
            .iter()
            .find(|a| {
                a.tag == ATTRIBUTE && a.get(ATTRIBUTE_NAME).unwrap().string().unwrap() == name
            })
            .unwrap()
            .required(ATTRIBUTE_VALUE)
            .unwrap()
            .value
            .clone()
    }
}
fn request(
    v: Version,
    items: Vec<(u32, Vec<Node>)>,
    continuation: Option<u32>,
    maximum: Option<i32>,
) -> Node {
    let mut header = vec![v.node()];
    if v.0 < 3 {
        header.push(Node::int(BATCH_COUNT, items.len() as i32));
        if items.len() > 1 {
            header.push(Node::boolean(BATCH_ORDER_OPTION, true));
        }
    }
    if let Some(value) = continuation {
        header.push(Node::enumeration(BATCH_ERROR_CONTINUATION_OPTION, value));
    }
    if let Some(value) = maximum {
        header.push(Node::int(MAXIMUM_RESPONSE_SIZE, value));
    }
    let many = items.len() > 1;
    let mut fields = vec![Node::structure(REQUEST_HEADER, header)];
    for (index, (op, p)) in items.into_iter().enumerate() {
        let mut item = vec![
            Node::enumeration(OPERATION, op),
            Node::structure(REQUEST_PAYLOAD, p),
        ];
        if many && v.0 < 3 {
            item.push(Node::bytes(UNIQUE_BATCH_ITEM_ID, vec![index as u8]));
        }
        fields.push(Node::structure(BATCH_ITEM, item));
    }
    Node::structure(REQUEST_MESSAGE, fields)
}
fn uid(v: Version, id: &str) -> Node {
    if v.0 >= 3 {
        Node::identifier(UNIQUE_IDENTIFIER, id)
    } else {
        Node::text(UNIQUE_IDENTIFIER, id)
    }
}
fn payload(response: &Node) -> &Node {
    let item = response.required(BATCH_ITEM).unwrap();
    assert_eq!(
        item.required(RESULT_STATUS).unwrap().number().unwrap(),
        0,
        "reason {:?}",
        item.get(RESULT_REASON).and_then(|n| n.number().ok())
    );
    item.required(RESPONSE_PAYLOAD).unwrap()
}
fn reason(response: &Node) -> u32 {
    response
        .required(BATCH_ITEM)
        .unwrap()
        .required(RESULT_REASON)
        .unwrap()
        .number()
        .unwrap()
}
fn vendor(name: &str, value: Value) -> Node {
    Node::structure(
        ATTRIBUTE,
        vec![
            Node::text(VENDOR_IDENTIFICATION, "x"),
            Node::text(ATTRIBUTE_NAME, name),
            Node {
                tag: ATTRIBUTE_VALUE,
                value,
            },
        ],
    )
}
fn reference(name: &str) -> Node {
    Node::structure(
        ATTRIBUTE_REFERENCE,
        vec![
            Node::text(VENDOR_IDENTIFICATION, "x"),
            Node::text(ATTRIBUTE_NAME, name),
        ],
    )
}
const VERSIONS: [Version; 3] = [Version(2, 0), Version(2, 1), Version(3, 0)];

#[test]
fn numeric_interval_boolean_and_temporal_values_preserve_types_and_defaults_across_restart() {
    for v in VERSIONS {
        let mut f = Fixture::new();
        let start = [
            ("integer", Value::Integer(10)),
            ("long", Value::LongInteger(20)),
            ("interval", Value::Interval(30)),
            ("date", Value::DateTime(40)),
            ("extended", Value::DateTimeExtended(50)),
            ("boolean", Value::Boolean(false)),
        ];
        let id = f.create(
            v,
            start
                .iter()
                .map(|(name, value)| vendor(name, value.clone()))
                .collect(),
        );
        for (name, _) in &start[..5] {
            let out = f.adjust(v, &id, reference(name), 1, None);
            assert_eq!(payload(&out).children().unwrap().len(), 1);
        }
        assert!(f.value(&id, "integer") == Value::Integer(11));
        assert!(f.value(&id, "long") == Value::LongInteger(21));
        assert!(f.value(&id, "interval") == Value::Interval(31));
        assert!(f.value(&id, "date") == Value::DateTime(41));
        assert!(f.value(&id, "extended") == Value::DateTimeExtended(51));
        payload(&f.adjust(v, &id, reference("integer"), 2, Some(Value::LongInteger(4))));
        payload(&f.adjust(v, &id, reference("long"), 3, None));
        payload(&f.adjust(v, &id, reference("boolean"), 3, None));
        payload(&f.adjust(v, &id, reference("new"), 1, Some(Value::LongInteger(123))));
        f.restart();
        assert!(f.value(&id, "integer") == Value::Integer(7));
        assert!(f.value(&id, "long") == Value::LongInteger(-21));
        assert!(f.value(&id, "boolean") == Value::Boolean(true));
        assert!(f.value(&id, "new") == Value::LongInteger(123));
        f.engine.store.verify_integrity().unwrap();
    }
}

#[test]
fn signed_big_integer_boundaries_extend_sign_and_never_wrap() {
    for v in VERSIONS {
        let mut f = Fixture::new();
        let max = [vec![0x7f], vec![0xff; 15]].concat();
        let min = [vec![0x80], vec![0; 15]].concat();
        let id = f.create(
            v,
            vec![
                vendor("max", Value::BigInteger(max)),
                vendor("min", Value::BigInteger(min)),
                vendor("zero", Value::BigInteger(vec![0; 8])),
            ],
        );
        payload(&f.adjust(v, &id, reference("max"), 1, None));
        let positive = [vec![0; 8], vec![0x80], vec![0; 15]].concat();
        assert!(f.value(&id, "max") == Value::BigInteger(positive));
        payload(&f.adjust(v, &id, reference("min"), 2, None));
        let negative = [vec![0xff; 8], vec![0x7f], vec![0xff; 15]].concat();
        assert!(f.value(&id, "min") == Value::BigInteger(negative));
        payload(&f.adjust(v, &id, reference("zero"), 3, None));
        assert!(f.value(&id, "zero") == Value::BigInteger(vec![0; 8]));
        payload(&f.adjust(v, &id, reference("max"), 3, None));
        assert!(f.value(&id, "max") == Value::BigInteger([vec![0x80], vec![0; 15]].concat()));
        payload(&f.adjust(
            v,
            &id,
            reference("min"),
            1,
            Some(Value::BigInteger([vec![0; 7], vec![1]].concat())),
        ));
        assert!(f.value(&id, "min") == Value::BigInteger([vec![0x80], vec![0; 15]].concat()));
        f.restart();
        f.engine.store.verify_integrity().unwrap();
    }
}

#[test]
fn fixed_width_overflow_underflow_and_invalid_type_leave_values_unchanged() {
    for v in VERSIONS {
        let mut f = Fixture::new();
        let values = [
            ("int_max", Value::Integer(i32::MAX), 1),
            ("int_min", Value::Integer(i32::MIN), 3),
            ("long_max", Value::LongInteger(i64::MAX), 1),
            ("long_min", Value::LongInteger(i64::MIN), 3),
            ("interval_max", Value::Interval(u32::MAX), 1),
            ("interval_zero", Value::Interval(0), 2),
            ("date_max", Value::DateTime(i64::MAX), 1),
            ("extended_min", Value::DateTimeExtended(i64::MIN), 2),
        ];
        let id = f.create(
            v,
            values
                .iter()
                .map(|(name, value, _)| vendor(name, value.clone()))
                .collect(),
        );
        for (name, value, kind) in values {
            assert_eq!(reason(&f.adjust(v, &id, reference(name), kind, None)), 0x1b);
            assert!(f.value(&id, name) == value);
        }
        for (name, value, kind) in [
            ("text", Value::TextString("text".into()), 1),
            ("enum", Value::Enumeration(1), 3),
            ("flag", Value::Boolean(false), 1),
            ("period", Value::Interval(5), 3),
            ("timestamp", Value::DateTime(5), 3),
        ] {
            payload(&f.call(
                v,
                "alice",
                13,
                vec![
                    uid(v, &id),
                    Node::structure(NEW_ATTRIBUTE, vec![vendor(name, value)]),
                ],
            ));
            assert_eq!(reason(&f.adjust(v, &id, reference(name), kind, None)), 0x1c);
        }
        assert_eq!(
            reason(&f.adjust(v, &id, reference("missing"), 1, None)),
            0x1c
        );
        f.engine.store.verify_integrity().unwrap();
    }
}

#[test]
fn multi_instance_readonly_unknown_and_payload_types_have_specific_errors() {
    for v in VERSIONS {
        let mut f = Fixture::new();
        let id = f.create(
            v,
            vec![
                vendor("many", Value::Integer(1)),
                vendor("many", Value::Integer(2)),
                Node::text(OBJECT_GROUP, "one"),
                Node::text(OBJECT_GROUP, "two"),
            ],
        );
        assert_eq!(reason(&f.adjust(v, &id, reference("many"), 1, None)), 0x1e);
        assert_eq!(
            reason(&f.adjust(
                v,
                &id,
                Node::enumeration(ATTRIBUTE_REFERENCE, OBJECT_GROUP),
                1,
                None
            )),
            0x1e
        );
        for tag in [
            STATE,
            INITIAL_DATE,
            LAST_CHANGE_DATE,
            LEASE_TIME,
            CRYPTOGRAPHIC_LENGTH,
            CRYPTOGRAPHIC_USAGE_MASK,
        ] {
            assert_eq!(
                reason(&f.adjust(v, &id, Node::enumeration(ATTRIBUTE_REFERENCE, tag), 1, None)),
                0x1d
            );
        }
        assert_eq!(
            reason(&f.adjust(
                v,
                &id,
                Node::enumeration(ATTRIBUTE_REFERENCE, 0x4201ff),
                1,
                None
            )),
            0x1f
        );
        let fields = vec![
            uid(v, &id),
            reference("many"),
            Node::int(ADJUSTMENT_TYPE, 1),
        ];
        assert_eq!(reason(&f.call(v, "alice", 48, fields)), 7);
        let fields = vec![
            uid(v, &id),
            reference("many"),
            Node::enumeration(ADJUSTMENT_TYPE, 1),
            Node::enumeration(ADJUSTMENT_TYPE, 2),
        ];
        assert_eq!(reason(&f.call(v, "alice", 48, fields)), 7);
        let fields = vec![
            uid(v, &id),
            reference("many"),
            Node::enumeration(ADJUSTMENT_TYPE, 1),
            Node::int(ATTRIBUTE_INDEX, 0),
        ];
        assert_eq!(reason(&f.call(v, "alice", 48, fields)), 8);
    }
}

#[test]
fn lifecycle_date_adjustments_enforce_state_elapsed_dates_and_cross_date_constraints() {
    for v in VERSIONS {
        let mut f = Fixture::new();
        let future = now() + 3600;
        let id = f.create(
            v,
            vec![
                Node::date(ACTIVATION_DATE, future),
                Node::date(PROCESS_START_DATE, future + 100),
                Node::date(PROTECT_STOP_DATE, future + 200),
                Node::date(DEACTIVATION_DATE, future + 300),
            ],
        );
        payload(&f.adjust(
            v,
            &id,
            Node::enumeration(ATTRIBUTE_REFERENCE, ACTIVATION_DATE),
            1,
            Some(Value::Integer(10)),
        ));
        assert_eq!(
            reason(&f.adjust(
                v,
                &id,
                Node::enumeration(ATTRIBUTE_REFERENCE, ACTIVATION_DATE),
                1,
                Some(Value::Integer(100))
            )),
            7
        );
        assert_eq!(
            reason(&f.adjust(
                v,
                &id,
                Node::enumeration(ATTRIBUTE_REFERENCE, PROTECT_STOP_DATE),
                1,
                Some(Value::Integer(101))
            )),
            7
        );
        let absent = f.create(v, vec![]);
        assert_eq!(
            reason(&f.adjust(
                v,
                &absent,
                Node::enumeration(ATTRIBUTE_REFERENCE, ACTIVATION_DATE),
                1,
                None
            )),
            0x1c
        );
        let active = f.create(
            v,
            vec![
                Node::date(ACTIVATION_DATE, now() - 10),
                Node::date(PROCESS_START_DATE, now() - 5),
                Node::date(PROTECT_STOP_DATE, now() - 1),
            ],
        );
        for tag in [ACTIVATION_DATE, PROCESS_START_DATE, PROTECT_STOP_DATE] {
            assert_eq!(
                reason(&f.adjust(
                    v,
                    &active,
                    Node::enumeration(ATTRIBUTE_REFERENCE, tag),
                    1,
                    Some(Value::Integer(9999))
                )),
                // Activation Date is refused by lifecycle state; elapsed dates are read-only.
                if tag != ACTIVATION_DATE {
                    0x1d
                } else if v >= Version(2, 1) {
                    0x43
                } else {
                    12
                }
            );
        }
        let old = f.engine.store.get("alice", &id).unwrap().unwrap();
        assert!(
            old.attrs.iter().find(|a| a.tag == ACTIVATION_DATE).unwrap()
                == &Node::date(ACTIVATION_DATE, future + 10)
        );
        f.restart();
        f.engine.store.verify_integrity().unwrap();
    }
}

#[test]
fn boolean_adjustment_preserves_extraction_history_and_draft_monotonic_rules() {
    for v in VERSIONS {
        let mut f = Fixture::new();
        let id = f.create(v, vec![]);
        payload(&f.adjust(
            v,
            &id,
            Node::enumeration(ATTRIBUTE_REFERENCE, SENSITIVE),
            3,
            None,
        ));
        if v.0 >= 3 {
            assert_eq!(
                reason(&f.adjust(
                    v,
                    &id,
                    Node::enumeration(ATTRIBUTE_REFERENCE, SENSITIVE),
                    3,
                    None
                )),
                0x1d
            );
        } else {
            payload(&f.adjust(
                v,
                &id,
                Node::enumeration(ATTRIBUTE_REFERENCE, SENSITIVE),
                3,
                None,
            ));
        }
        payload(&f.adjust(
            v,
            &id,
            Node::enumeration(ATTRIBUTE_REFERENCE, EXTRACTABLE),
            3,
            None,
        ));
        if v.0 >= 3 {
            assert_eq!(
                reason(&f.adjust(
                    v,
                    &id,
                    Node::enumeration(ATTRIBUTE_REFERENCE, EXTRACTABLE),
                    3,
                    None
                )),
                0x1d
            );
        } else {
            payload(&f.adjust(
                v,
                &id,
                Node::enumeration(ATTRIBUTE_REFERENCE, EXTRACTABLE),
                3,
                None,
            ));
        }
        let obj = f.engine.store.get("alice", &id).unwrap().unwrap();
        assert_eq!(obj.metadata.always_sensitive, Some(false));
        assert_eq!(obj.metadata.never_extractable, Some(false));
    }
}

#[test]
fn version_gates_ownership_archive_destroy_and_identifier_rules_are_enforced() {
    let mut f = Fixture::new();
    for v in [
        Version(1, 0),
        Version(1, 1),
        Version(1, 2),
        Version(1, 3),
        Version(1, 4),
    ] {
        assert_eq!(reason(&f.call(v, "alice", 48, vec![])), 5);
        assert!(!keytend_kmip_server::protocol::operations(v).contains(&48));
    }
    for v in VERSIONS {
        assert!(keytend_kmip_server::protocol::operations(v).contains(&48));
        let id = f.create(v, vec![vendor("count", Value::Integer(0))]);
        let fields = vec![
            uid(v, &id),
            reference("count"),
            Node::enumeration(ADJUSTMENT_TYPE, 1),
        ];
        assert_eq!(reason(&f.call(v, "bob", 48, fields)), 1);
        let omitted = f.call(
            v,
            "alice",
            48,
            vec![reference("count"), Node::enumeration(ADJUSTMENT_TYPE, 1)],
        );
        // No 2.x or draft 3.0 error table lists Missing Data; Invalid Field
        // is in each (2.1 Table 172).
        assert_eq!(reason(&omitted), 7);
        payload(&f.call(v, "alice", 21, vec![uid(v, &id)]));
        assert_eq!(reason(&f.adjust(v, &id, reference("count"), 1, None)), 13);
        payload(&f.call(v, "alice", 22, vec![uid(v, &id)]));
        payload(&f.call(v, "alice", 20, vec![uid(v, &id)]));
        assert_eq!(reason(&f.adjust(v, &id, reference("count"), 1, None)), 0x43);
    }
}

#[test]
fn undo_failed_later_items_and_response_budget_roll_back_adjustments_and_index() {
    for v in VERSIONS {
        let mut f = Fixture::new();
        let id = f.create(v, vec![vendor("count", Value::Integer(10))]);
        let change = vec![
            uid(v, &id),
            reference("count"),
            Node::enumeration(ADJUSTMENT_TYPE, 1),
        ];
        let r = f
            .engine
            .process(
                "alice",
                &request(
                    v,
                    vec![(48, change.clone()), (0x7fff_ffff, vec![])],
                    Some(3),
                    None,
                ),
            )
            .unwrap();
        assert!(r.all(BATCH_ITEM).any(|i| i.get(RESULT_REASON).is_some()));
        assert!(f.value(&id, "count") == Value::Integer(10));
        // Continue must answer all eight items; even eight minimal failures
        // exceed 256 bytes, so nothing executes and no response is sent.
        let failure = f.engine.process(
            "alice",
            &request(v, vec![(48, change.clone()); 8], Some(1), Some(256)),
        );
        assert!(failure.is_err_and(|e| e.unanswerable()));
        assert!(f.value(&id, "count") == Value::Integer(10));
        f.engine.store.verify_integrity().unwrap();
        f.restart();
        assert!(f.value(&id, "count") == Value::Integer(10));
    }
}

fn legacy(mut a: Node) -> Node {
    let name = match a.tag {
        CRYPTOGRAPHIC_ALGORITHM => "Cryptographic Algorithm",
        CRYPTOGRAPHIC_LENGTH => "Cryptographic Length",
        CRYPTOGRAPHIC_USAGE_MASK => "Cryptographic Usage Mask",
        ACTIVATION_DATE => "Activation Date",
        DEACTIVATION_DATE => "Deactivation Date",
        PROCESS_START_DATE => "Process Start Date",
        PROTECT_STOP_DATE => "Protect Stop Date",
        _ => panic!("legacy fixture attribute"),
    };
    a.tag = ATTRIBUTE_VALUE;
    Node::structure(ATTRIBUTE, vec![Node::text(ATTRIBUTE_NAME, name), a])
}
fn mutation(v: Version, id: &str, a: Node) -> Vec<Node> {
    vec![
        uid(v, id),
        if v.0 == 1 {
            legacy(a)
        } else {
            Node::structure(NEW_ATTRIBUTE, vec![a])
        },
    ]
}

#[test]
fn lifecycle_date_mutations_obey_policy_in_all_final_editions() {
    for v in [
        Version(1, 1),
        Version(1, 2),
        Version(1, 3),
        Version(1, 4),
        Version(2, 0),
        Version(2, 1),
    ] {
        let mut f = Fixture::new();
        let future = now() + 3600;
        let id = f.create(
            v,
            vec![
                Node::date(ACTIVATION_DATE, future),
                Node::date(DEACTIVATION_DATE, future + 300),
            ],
        );
        for tag in [PROCESS_START_DATE, PROTECT_STOP_DATE] {
            payload(&f.call(
                v,
                "alice",
                13,
                mutation(v, &id, Node::date(tag, future + 100)),
            ));
            payload(&f.call(
                v,
                "alice",
                14,
                mutation(v, &id, Node::date(tag, future + 200)),
            ));
            let field = if v.0 == 1 {
                legacy(Node::date(tag, 0))
                    .required(ATTRIBUTE_NAME)
                    .unwrap()
                    .clone()
            } else {
                Node::enumeration(ATTRIBUTE_REFERENCE, tag)
            };
            assert_eq!(
                reason(&f.call(v, "alice", 15, vec![uid(v, &id), field])),
                if v.0 == 1 { 12 } else { 0x22 }
            );
        }
        // A locally valid new date still must respect all other stored dates.
        assert_eq!(
            reason(&f.call(
                v,
                "alice",
                14,
                mutation(v, &id, Node::date(ACTIVATION_DATE, future + 250))
            )),
            7
        );
        assert_eq!(
            reason(&f.call(
                v,
                "alice",
                14,
                mutation(v, &id, Node::date(DEACTIVATION_DATE, future + 150))
            )),
            7
        );
        // Setting Activation Date in the past immediately moves the object to Active.
        payload(&f.call(
            v,
            "alice",
            14,
            mutation(v, &id, Node::date(ACTIVATION_DATE, now() - 30)),
        ));
        assert_eq!(f.engine.store.get("alice", &id).unwrap().unwrap().state, 2);
        assert_eq!(
            reason(&f.call(
                v,
                "alice",
                14,
                mutation(v, &id, Node::date(ACTIVATION_DATE, future))
            )),
            if v >= Version(2, 1) { 0x43 } else { 12 }
        );
        for tag in [PROCESS_START_DATE, PROTECT_STOP_DATE] {
            payload(&f.call(
                v,
                "alice",
                14,
                mutation(v, &id, Node::date(tag, now() - 10)),
            ));
            assert_eq!(
                reason(&f.call(v, "alice", 14, mutation(v, &id, Node::date(tag, future)))),
                if v.0 == 1 { 12 } else { 0x22 }
            );
        }
        payload(&f.call(
            v,
            "alice",
            14,
            mutation(v, &id, Node::date(DEACTIVATION_DATE, now() - 1)),
        ));
        assert_eq!(f.engine.store.get("alice", &id).unwrap().unwrap().state, 3);
        assert_eq!(
            reason(&f.call(
                v,
                "alice",
                14,
                mutation(v, &id, Node::date(DEACTIVATION_DATE, future))
            )),
            if v >= Version(2, 1) { 0x43 } else { 12 }
        );
        f.restart();
        f.engine.store.verify_integrity().unwrap();
    }
}

#[test]
fn adjustment_resolves_explicit_placeholder_enumeration_and_response_indices() {
    for v in VERSIONS {
        let mut f = Fixture::new();
        let id = f.create(v, vec![vendor("count", Value::Integer(0))]);
        let mut refs = vec![
            Node::enumeration(UNIQUE_IDENTIFIER, 1),
            Node::enumeration(UNIQUE_IDENTIFIER, 3),
            Node::int(UNIQUE_IDENTIFIER, 0),
            Node::int(UNIQUE_IDENTIFIER, -1),
        ];
        if v.0 >= 3 {
            refs.push(Node {
                tag: UNIQUE_IDENTIFIER,
                value: Value::Reference(id.clone()),
            });
        }
        let create = vec![
            Node::enumeration(OBJECT_TYPE, 2),
            Node::structure(
                ATTRIBUTES,
                vec![
                    Node::enumeration(CRYPTOGRAPHIC_ALGORITHM, 3),
                    Node::int(CRYPTOGRAPHIC_LENGTH, 256),
                    Node::int(CRYPTOGRAPHIC_USAGE_MASK, 12),
                    vendor("count", Value::Integer(0)),
                ],
            ),
        ];
        let mut items = vec![(1, create)];
        for reference_id in refs {
            items.push((
                48,
                vec![
                    reference_id,
                    reference("count"),
                    Node::enumeration(ADJUSTMENT_TYPE, 1),
                ],
            ));
        }
        if v.0 < 3 {
            items.push((
                48,
                vec![reference("count"), Node::enumeration(ADJUSTMENT_TYPE, 1)],
            ));
        }
        let response = f
            .engine
            .process("alice", &request(v, items, None, None))
            .unwrap();
        let responses = response.all(BATCH_ITEM).collect::<Vec<_>>();
        for item in &responses {
            assert_eq!(
                item.required(RESULT_STATUS).unwrap().number().unwrap(),
                0,
                "{:?}",
                item.get(RESULT_REASON).and_then(|n| n.number().ok())
            );
        }
        let created = responses[0]
            .required(RESPONSE_PAYLOAD)
            .unwrap()
            .required(UNIQUE_IDENTIFIER)
            .unwrap()
            .identifier_text()
            .unwrap();
        assert!(f.value(created, "count") == Value::Integer(if v.0 < 3 { 5 } else { 4 }));
        if v.0 >= 3 {
            assert!(f.value(&id, "count") == Value::Integer(1));
        }
    }
}

#[test]
fn malformed_or_oversized_big_integer_and_standard_nonnumeric_values_fail_atomically() {
    for v in VERSIONS {
        let mut f = Fixture::new();
        let id = f.create(
            v,
            vec![
                vendor("count", Value::Integer(1)),
                Node::text(CONTACT_INFORMATION, "operator"),
            ],
        );
        for amount in [vec![], vec![0; 7], vec![0; 65_544]] {
            let expected = if amount.len() > 65_536 { 2 } else { 0x1c };
            assert_eq!(
                reason(&f.adjust(
                    v,
                    &id,
                    reference("count"),
                    1,
                    Some(Value::BigInteger(amount))
                )),
                expected
            );
            assert!(f.value(&id, "count") == Value::Integer(1));
        }
        for tag in [CONTACT_INFORMATION, CRYPTOGRAPHIC_PARAMETERS] {
            assert_eq!(
                reason(&f.adjust(v, &id, Node::enumeration(ATTRIBUTE_REFERENCE, tag), 1, None)),
                0x1c
            );
        }
        // Crossing the configured maximum Big Integer size must not replace its value.
        let large = vec![0x7f; 65_536];
        payload(&f.call(
            v,
            "alice",
            13,
            vec![
                uid(v, &id),
                Node::structure(
                    NEW_ATTRIBUTE,
                    vec![vendor("large", Value::BigInteger(large.clone()))],
                ),
            ],
        ));
        let mut amount = vec![0; 65_536];
        amount[0] = 1;
        assert_eq!(
            reason(&f.adjust(
                v,
                &id,
                reference("large"),
                1,
                Some(Value::BigInteger(amount))
            )),
            2
        );
        assert!(f.value(&id, "large") == Value::BigInteger(large));
        // The minimum representable value still fits at the resource boundary.
        let mut minimum = vec![0; 65_536];
        minimum[0] = 0x80;
        payload(&f.call(
            v,
            "alice",
            13,
            vec![
                uid(v, &id),
                Node::structure(
                    NEW_ATTRIBUTE,
                    vec![vendor("minimum", Value::BigInteger(minimum.clone()))],
                ),
            ],
        ));
        payload(&f.adjust(v, &id, reference("minimum"), 1, Some(Value::Integer(0))));
        assert!(f.value(&id, "minimum") == Value::BigInteger(minimum));
        f.engine.store.verify_integrity().unwrap();
    }
}
