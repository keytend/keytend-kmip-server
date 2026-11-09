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
    store::Store,
    tags::*,
    ttlv::{Node, Value},
};
use tempfile::TempDir;
#[path = "support/legacy.rs"]
mod legacy;
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
    /// With `--ec-curves extended` (secp256k1 and brainpool curves).
    fn extended_curves() -> Self {
        let Fixture { _dir, engine } = Self::new();
        Self {
            _dir,
            engine: engine.with_ec_curves(keytend_kmip_server::protocol::EcCurves::Extended),
        }
    }
}
fn req(v: Version, mut items: Vec<(u32, Vec<Node>)>) -> Node {
    if v.0 >= 3 {
        fn draft_fields(fields: &mut [Node]) {
            for n in fields {
                if n.tag == UNIQUE_IDENTIFIER
                    && let Value::TextString(value) = &n.value
                {
                    *n = Node::identifier(n.tag, value);
                } else if n.tag == NAME
                    && let Some(value) = n.get(NAME_VALUE).and_then(|n| n.string().ok())
                {
                    *n = Node::text(NAME, value);
                } else if [
                    ATTRIBUTES,
                    COMMON_ATTRIBUTES,
                    PRIVATE_KEY_ATTRIBUTES,
                    PUBLIC_KEY_ATTRIBUTES,
                    NEW_ATTRIBUTE,
                    CURRENT_ATTRIBUTE,
                ]
                .contains(&n.tag)
                    && let Value::Structure(fields) = &mut n.value
                {
                    draft_fields(fields);
                }
            }
        }
        for (op, fields) in &mut items {
            draft_fields(fields);
            if [
                4, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 29, 31, 32, 33, 34, 35,
                36, 49, 64,
            ]
            .contains(op)
                && !fields.iter().any(|n| n.tag == UNIQUE_IDENTIFIER)
            {
                fields.insert(0, Node::enumeration(UNIQUE_IDENTIFIER, 1));
            }
        }
    }
    let count = items.len();
    let mut n = vec![Node::structure(
        REQUEST_HEADER,
        if v.0 < 3 {
            vec![v.node(), Node::int(BATCH_COUNT, count as i32)]
        } else {
            vec![v.node()]
        },
    )];
    n.extend(items.into_iter().enumerate().map(|(index, (op, p))| {
        Node::structure(BATCH_ITEM, {
            let mut fields = vec![Node::enumeration(OPERATION, op)];
            if v.0 < 3 {
                fields.push(Node::bytes(UNIQUE_BATCH_ITEM_ID, vec![index as u8]));
            }
            fields.push(Node::structure(REQUEST_PAYLOAD, p));
            fields
        })
    }));
    Node::structure(REQUEST_MESSAGE, n)
}
fn call(e: &mut Engine, v: Version, owner: &str, op: u32, p: Vec<Node>) -> Node {
    e.process(owner, &req(v, vec![(op, p)])).unwrap()
}
fn payload(n: &Node) -> &Node {
    let item = n.get(BATCH_ITEM).unwrap();
    assert_eq!(
        item.get(RESULT_STATUS).unwrap().number().unwrap(),
        0,
        "reason {:?}",
        item.get(RESULT_REASON).map(|n| n.number().unwrap())
    );
    item.get(RESPONSE_PAYLOAD).unwrap()
}
fn reason(n: &Node) -> u32 {
    n.get(BATCH_ITEM)
        .unwrap()
        .get(RESULT_REASON)
        .unwrap()
        .number()
        .unwrap()
}
fn attrs(v: Version, extra: Vec<Node>) -> Node {
    let mut a = vec![
        Node::enumeration(CRYPTOGRAPHIC_ALGORITHM, 3),
        Node::int(CRYPTOGRAPHIC_LENGTH, 256),
        Node::int(CRYPTOGRAPHIC_USAGE_MASK, 12),
    ];
    a.extend(extra);
    container(v, a)
}
fn container(v: Version, a: Vec<Node>) -> Node {
    if v.0 >= 2 {
        Node::structure(ATTRIBUTES, a)
    } else {
        Node::structure(
            TEMPLATE_ATTRIBUTE,
            a.into_iter()
                .map(|mut a| {
                    let name = match a.tag {
                        CRYPTOGRAPHIC_ALGORITHM => "Cryptographic Algorithm",
                        CRYPTOGRAPHIC_LENGTH => "Cryptographic Length",
                        CRYPTOGRAPHIC_USAGE_MASK => "Cryptographic Usage Mask",
                        t => tag_name(t).unwrap(),
                    };
                    a.tag = ATTRIBUTE_VALUE;
                    Node::structure(ATTRIBUTE, vec![Node::text(ATTRIBUTE_NAME, name), a])
                })
                .collect(),
        )
    }
}
fn create(e: &mut Engine, v: Version, extra: Vec<Node>) -> String {
    payload(&call(
        e,
        v,
        "alice",
        1,
        vec![Node::enumeration(OBJECT_TYPE, 2), attrs(v, extra)],
    ))
    .get(UNIQUE_IDENTIFIER)
    .unwrap()
    .identifier_text()
    .unwrap()
    .into()
}
fn uid(id: &str) -> Node {
    Node::text(UNIQUE_IDENTIFIER, id)
}
fn usage_limits(total: i64, unit: u32) -> Node {
    Node::structure(
        USAGE_LIMITS,
        vec![
            Node::long(USAGE_LIMITS_TOTAL, total),
            Node::enumeration(USAGE_LIMITS_UNIT, unit),
        ],
    )
}
fn remaining(e: &mut Engine, v: Version, id: &str) -> i64 {
    let reference = if v.0 == 1 {
        Node::text(ATTRIBUTE_NAME, "Usage Limits")
    } else {
        Node::enumeration(ATTRIBUTE_REFERENCE, USAGE_LIMITS)
    };
    let r = call(e, v, "alice", 11, vec![uid(id), reference]);
    let p = payload(&r);
    let limits = if v.0 == 1 {
        p.required(ATTRIBUTE)
            .unwrap()
            .required(ATTRIBUTE_VALUE)
            .unwrap()
    } else {
        p.required(ATTRIBUTES)
            .unwrap()
            .required(USAGE_LIMITS)
            .unwrap()
    };
    match limits.required(USAGE_LIMITS_COUNT).unwrap().value {
        Value::LongInteger(v) => v,
        _ => panic!("Count must be Long Integer"),
    }
}
fn attribute_change(v: Version, attribute: Node) -> Node {
    if v.0 == 1 {
        container(v, vec![attribute]).children().unwrap()[0].clone()
    } else {
        Node::structure(NEW_ATTRIBUTE, vec![attribute])
    }
}

// REQ:474a579d359147a2 a Usage Limits Count given when creating an object is ignored (the count starts at the total)
#[test]
fn usage_initialization_allocation_restart_and_rekey_all_versions() {
    for v in Version::supported(true) {
        let mut f = Fixture::new();
        f.engine.experimental_v3 = true;
        let initial = Node::structure(
            USAGE_LIMITS,
            vec![
                Node::long(USAGE_LIMITS_TOTAL, 5),
                Node::long(USAGE_LIMITS_COUNT, -99),
                Node::enumeration(USAGE_LIMITS_UNIT, 2),
            ],
        );
        let id = create(&mut f.engine, v, vec![initial]);
        assert_eq!(remaining(&mut f.engine, v, &id), 5);
        assert_eq!(
            reason(&call(
                &mut f.engine,
                v,
                "alice",
                17,
                vec![uid(&id), Node::long(USAGE_LIMITS_COUNT, 1)]
            )),
            12
        );
        payload(&call(&mut f.engine, v, "alice", 18, vec![uid(&id)]));
        payload(&call(
            &mut f.engine,
            v,
            "alice",
            9,
            vec![uid(&id), Node::long(USAGE_LIMITS_COUNT, 5)],
        ));
        assert_eq!(remaining(&mut f.engine, v, &id), 5);
        payload(&call(
            &mut f.engine,
            v,
            "alice",
            17,
            vec![uid(&id), Node::long(USAGE_LIMITS_COUNT, 3)],
        ));
        assert_eq!(remaining(&mut f.engine, v, &id), 2);
        assert_eq!(
            reason(&call(
                &mut f.engine,
                v,
                "alice",
                17,
                vec![uid(&id), Node::long(USAGE_LIMITS_COUNT, 3)]
            )),
            if v.0 >= 2 { 0x1a } else { 12 }
        );
        assert_eq!(remaining(&mut f.engine, v, &id), 2);
        let path = f._dir.path().join("keys.sqlite");
        let key = f._dir.path().join("master");
        drop(f.engine);
        f.engine = Engine::new(Store::open(&path, &key).unwrap(), true);
        assert_eq!(remaining(&mut f.engine, v, &id), 2);
        assert!(
            f.engine
                .store
                .get("alice", &id)
                .unwrap()
                .unwrap()
                .usage_consumed
        );
        let r = call(&mut f.engine, v, "alice", 4, vec![uid(&id)]);
        let replacement = payload(&r)
            .required(UNIQUE_IDENTIFIER)
            .unwrap()
            .identifier_text()
            .unwrap()
            .to_owned();
        assert_eq!(remaining(&mut f.engine, v, &replacement), 5);
        assert!(
            !f.engine
                .store
                .get("alice", &replacement)
                .unwrap()
                .unwrap()
                .usage_consumed
        );
        assert_eq!(remaining(&mut f.engine, v, &id), 2);
        f.engine.store.verify_audit().unwrap();
    }
}

#[test]
fn usage_long_integer_validation_and_boundary_arithmetic() {
    let mut f = Fixture::new();
    let v = Version(2, 1);
    for limits in [
        Node::structure(USAGE_LIMITS, vec![Node::long(USAGE_LIMITS_TOTAL, -1)]),
        Node::structure(USAGE_LIMITS, vec![Node::int(USAGE_LIMITS_TOTAL, 5)]),
        Node::structure(
            USAGE_LIMITS,
            vec![
                Node::long(USAGE_LIMITS_TOTAL, 5),
                Node::int(USAGE_LIMITS_COUNT, 1),
            ],
        ),
        Node::structure(
            USAGE_LIMITS,
            vec![
                Node::long(USAGE_LIMITS_TOTAL, 5),
                Node::long(USAGE_LIMITS_TOTAL, 5),
            ],
        ),
    ] {
        assert_eq!(
            reason(&call(
                &mut f.engine,
                v,
                "alice",
                1,
                vec![Node::enumeration(OBJECT_TYPE, 2), attrs(v, vec![limits])]
            )),
            7
        );
    }
    let id = create(
        &mut f.engine,
        v,
        vec![Node::structure(USAGE_LIMITS, vec![])],
    );
    assert_eq!(remaining(&mut f.engine, v, &id), i64::MAX);
    payload(&call(&mut f.engine, v, "alice", 18, vec![uid(&id)]));
    for count in [
        Node::int(USAGE_LIMITS_COUNT, 1),
        Node::long(USAGE_LIMITS_COUNT, -1),
    ] {
        assert_eq!(
            reason(&call(&mut f.engine, v, "alice", 17, vec![uid(&id), count])),
            7
        );
    }
    payload(&call(
        &mut f.engine,
        v,
        "alice",
        17,
        vec![uid(&id), Node::long(USAGE_LIMITS_COUNT, i64::MAX)],
    ));
    assert_eq!(remaining(&mut f.engine, v, &id), 0);
    assert_eq!(
        reason(&call(
            &mut f.engine,
            v,
            "alice",
            17,
            vec![uid(&id), Node::long(USAGE_LIMITS_COUNT, 1)]
        )),
        0x1a
    );
}

#[test]
fn protective_crypto_consumes_budget_and_processing_does_not() {
    let mut f = Fixture::new();
    let v = Version(2, 1);
    for (total, unit) in [(1, 2), (3, 1)] {
        let id = create(
            &mut f.engine,
            v,
            vec![
                usage_limits(total, unit),
                Node::date(ACTIVATION_DATE, keytend_kmip_server::store::now() - 1),
            ],
        );
        let cp = Node::structure(
            CRYPTOGRAPHIC_PARAMETERS,
            vec![
                Node::enumeration(BLOCK_CIPHER_MODE, 9),
                Node::boolean(RANDOM_IV, true),
            ],
        );
        let data = Node::bytes(DATA, b"abc".to_vec());
        let r = call(
            &mut f.engine,
            v,
            "alice",
            31,
            vec![uid(&id), cp.clone(), data.clone()],
        );
        let encrypted = payload(&r);
        assert_eq!(remaining(&mut f.engine, v, &id), 0);
        assert_eq!(
            reason(&call(
                &mut f.engine,
                v,
                "alice",
                31,
                vec![uid(&id), cp, data]
            )),
            12
        );
        let decrypt = vec![
            uid(&id),
            Node::structure(
                CRYPTOGRAPHIC_PARAMETERS,
                vec![Node::enumeration(BLOCK_CIPHER_MODE, 9)],
            ),
            encrypted.required(DATA).unwrap().clone(),
            encrypted.required(IV_COUNTER_NONCE).unwrap().clone(),
            encrypted
                .required(AUTHENTICATED_ENCRYPTION_TAG)
                .unwrap()
                .clone(),
        ];
        for _ in 0..2 {
            payload(&call(&mut f.engine, v, "alice", 32, decrypt.clone()));
        }
        assert_eq!(remaining(&mut f.engine, v, &id), 0);
    }
    let r = call(
        &mut f.engine,
        v,
        "alice",
        1,
        vec![
            Node::enumeration(OBJECT_TYPE, 2),
            container(
                v,
                vec![
                    Node::enumeration(CRYPTOGRAPHIC_ALGORITHM, 9),
                    Node::int(CRYPTOGRAPHIC_LENGTH, 256),
                    Node::int(CRYPTOGRAPHIC_USAGE_MASK, 0x180),
                    usage_limits(3, 1),
                    Node::date(ACTIVATION_DATE, keytend_kmip_server::store::now() - 1),
                ],
            ),
        ],
    );
    let id = payload(&r)
        .required(UNIQUE_IDENTIFIER)
        .unwrap()
        .identifier_text()
        .unwrap()
        .to_owned();
    let r = call(
        &mut f.engine,
        v,
        "alice",
        35,
        vec![uid(&id), Node::bytes(DATA, b"abc".to_vec())],
    );
    let mac = payload(&r).required(MAC_DATA).unwrap().clone();
    assert_eq!(remaining(&mut f.engine, v, &id), 0);
    let r = call(
        &mut f.engine,
        v,
        "alice",
        36,
        vec![uid(&id), Node::bytes(DATA, b"abc".to_vec()), mac],
    );
    assert_eq!(
        payload(&r)
            .required(VALIDITY_INDICATOR)
            .unwrap()
            .number()
            .unwrap(),
        1
    );
    assert_eq!(remaining(&mut f.engine, v, &id), 0);
    assert_eq!(
        reason(&call(
            &mut f.engine,
            v,
            "alice",
            35,
            vec![uid(&id), Node::bytes(DATA, vec![0])]
        )),
        26
    );
}

#[test]
fn rsa_signing_budget_does_not_charge_verification_or_allow_public_sign_allocation() {
    let mut f = Fixture::new();
    let v = Version(2, 1);
    let r = call(
        &mut f.engine,
        v,
        "alice",
        2,
        vec![Node::structure(
            COMMON_ATTRIBUTES,
            vec![
                Node::enumeration(CRYPTOGRAPHIC_ALGORITHM, 4),
                Node::int(CRYPTOGRAPHIC_LENGTH, 2048),
                Node::int(CRYPTOGRAPHIC_USAGE_MASK, 3),
                usage_limits(1, 2),
                Node::structure(
                    CRYPTOGRAPHIC_PARAMETERS,
                    vec![Node::enumeration(HASHING_ALGORITHM, 6)],
                ),
            ],
        )],
    );
    let private = payload(&r)
        .required(PRIVATE_KEY_UNIQUE_IDENTIFIER)
        .unwrap()
        .identifier_text()
        .unwrap()
        .to_owned();
    let public = payload(&r)
        .required(PUBLIC_KEY_UNIQUE_IDENTIFIER)
        .unwrap()
        .identifier_text()
        .unwrap()
        .to_owned();
    for id in [&private, &public] {
        payload(&call(&mut f.engine, v, "alice", 18, vec![uid(id)]));
    }
    let data = Node::bytes(DATA, b"database context".to_vec());
    let r = call(
        &mut f.engine,
        v,
        "alice",
        33,
        vec![uid(&private), data.clone()],
    );
    let signature = payload(&r).required(SIGNATURE_DATA).unwrap().clone();
    assert_eq!(remaining(&mut f.engine, v, &private), 0);
    let r = call(
        &mut f.engine,
        v,
        "alice",
        34,
        vec![uid(&public), data, signature],
    );
    assert_eq!(
        payload(&r)
            .required(VALIDITY_INDICATOR)
            .unwrap()
            .number()
            .unwrap(),
        1
    );
    assert_eq!(remaining(&mut f.engine, v, &public), 1);
    assert_eq!(
        reason(&call(
            &mut f.engine,
            v,
            "alice",
            17,
            vec![uid(&public), Node::long(USAGE_LIMITS_COUNT, 1)]
        )),
        0x30
    );
}

// REQ:ac0eb02c93aef073 the Usage Limits Total may be corrected until Get Usage Allocation has touched the count
#[test]
fn budget_mutations_are_read_only_after_zero_allocation_or_protection() {
    for v in [Version(1, 0), Version(1, 4), Version(2, 1)] {
        let mut f = Fixture::new();
        let id = create(&mut f.engine, v, vec![]);
        payload(&call(
            &mut f.engine,
            v,
            "alice",
            13,
            vec![uid(&id), attribute_change(v, usage_limits(5, 2))],
        ));
        payload(&call(
            &mut f.engine,
            v,
            "alice",
            14,
            vec![
                uid(&id),
                attribute_change(
                    v,
                    Node::structure(USAGE_LIMITS, vec![Node::long(USAGE_LIMITS_TOTAL, 7)]),
                ),
            ],
        ));
        assert_eq!(remaining(&mut f.engine, v, &id), 7);
        let readonly = if v.0 >= 2 { 0x22 } else { 12 };
        assert_eq!(
            reason(&call(
                &mut f.engine,
                v,
                "alice",
                14,
                vec![
                    uid(&id),
                    attribute_change(
                        v,
                        Node::structure(USAGE_LIMITS, vec![Node::long(USAGE_LIMITS_COUNT, 7)])
                    )
                ]
            )),
            readonly
        );
        payload(&call(&mut f.engine, v, "alice", 18, vec![uid(&id)]));
        payload(&call(
            &mut f.engine,
            v,
            "alice",
            17,
            vec![uid(&id), Node::long(USAGE_LIMITS_COUNT, 0)],
        ));
        assert_eq!(remaining(&mut f.engine, v, &id), 7);
        for op in [13, 14] {
            assert_eq!(
                reason(&call(
                    &mut f.engine,
                    v,
                    "alice",
                    op,
                    vec![uid(&id), attribute_change(v, usage_limits(99, 2))]
                )),
                readonly
            );
        }
        let reference = if v.0 == 1 {
            Node::text(ATTRIBUTE_NAME, "Usage Limits")
        } else {
            Node::enumeration(ATTRIBUTE_REFERENCE, USAGE_LIMITS)
        };
        assert_eq!(
            reason(&call(
                &mut f.engine,
                v,
                "alice",
                15,
                vec![uid(&id), reference]
            )),
            readonly
        );
        if v.0 >= 2 {
            assert_eq!(
                reason(&call(
                    &mut f.engine,
                    v,
                    "alice",
                    49,
                    vec![uid(&id), attribute_change(v, usage_limits(99, 2))]
                )),
                readonly
            );
        }
        assert_eq!(remaining(&mut f.engine, v, &id), 7);
    }
}

#[test]
fn leases_and_checks_obey_deadlines_and_return_all_denied_attributes() {
    for v in Version::supported(true) {
        let mut f = Fixture::new();
        f.engine.experimental_v3 = true;
        let now = keytend_kmip_server::store::now();
        let id = create(
            &mut f.engine,
            v,
            vec![
                usage_limits(2, 2),
                Node::date(ACTIVATION_DATE, now - 60),
                Node::date(DEACTIVATION_DATE, now + 60),
                Node::date(PROTECT_STOP_DATE, now + 20),
            ],
        );
        let r = call(&mut f.engine, v, "alice", 16, vec![uid(&id)]);
        let lease = payload(&r).required(LEASE_TIME).unwrap();
        assert!(matches!(lease.value,Value::Interval(seconds) if seconds>0 && seconds<=20));
        assert!(
            payload(&r).required(LAST_CHANGE_DATE).unwrap().value
                == Value::DateTime(f.engine.store.get("alice", &id).unwrap().unwrap().updated)
        );
        let r = call(
            &mut f.engine,
            v,
            "alice",
            9,
            vec![
                uid(&id),
                Node::long(USAGE_LIMITS_COUNT, 3),
                Node::int(CRYPTOGRAPHIC_USAGE_MASK, 1),
                Node::interval(LEASE_TIME, 301),
            ],
        );
        let item = r.required(BATCH_ITEM).unwrap();
        let denied = item.required(RESPONSE_PAYLOAD).unwrap();
        assert_eq!(denied.children().unwrap().len(), 3);
        assert!(denied.get(UNIQUE_IDENTIFIER).is_none());
        for tag in [USAGE_LIMITS_COUNT, CRYPTOGRAPHIC_USAGE_MASK, LEASE_TIME] {
            denied.required(tag).unwrap();
        }
        assert_eq!(remaining(&mut f.engine, v, &id), 2);
        payload(&call(
            &mut f.engine,
            v,
            "alice",
            9,
            vec![
                uid(&id),
                Node::long(USAGE_LIMITS_COUNT, 2),
                Node::int(CRYPTOGRAPHIC_USAGE_MASK, 4),
                Node::interval(LEASE_TIME, 1),
            ],
        ));
        let mut stored = f.engine.store.get("alice", &id).unwrap().unwrap();
        stored.attrs.retain(|a| a.tag != PROTECT_STOP_DATE);
        stored.attrs.push(Node::date(PROTECT_STOP_DATE, now - 1));
        f.engine.store.put(&stored).unwrap();
        // Past its Protect Stop Date the Active key may still process data,
        // so the default `--lease-states` leases it up to its Deactivation
        // Date (docs/lifecycle.md#leases); `active` refuses it
        // (tests/lease_lifecycle.rs).
        let r = call(&mut f.engine, v, "alice", 16, vec![uid(&id)]);
        let lease = payload(&r).required(LEASE_TIME).unwrap();
        assert!(matches!(lease.value,Value::Interval(seconds) if seconds>20 && seconds<=60));
        let id = create(&mut f.engine, v, vec![]);
        assert_eq!(
            reason(&call(&mut f.engine, v, "alice", 16, vec![uid(&id)])),
            12
        );
        assert_eq!(
            reason(&call(
                &mut f.engine,
                v,
                "alice",
                17,
                vec![uid(&id), Node::long(USAGE_LIMITS_COUNT, 1)]
            )),
            // 1.4 Table 345: no Usage Limits attribute is Illegal Operation.
            if v.0 >= 2 { 0x21 } else { 0x0B }
        );
    }
}

#[test]
fn accounting_rolls_back_failures_and_undo_keeps_delivered_protection_charges() {
    let mut f = Fixture::new();
    let v = Version(2, 1);
    let id = create(
        &mut f.engine,
        v,
        vec![
            usage_limits(1, 2),
            Node::date(ACTIVATION_DATE, keytend_kmip_server::store::now() - 1),
        ],
    );
    let cp = Node::structure(
        CRYPTOGRAPHIC_PARAMETERS,
        vec![Node::enumeration(BLOCK_CIPHER_MODE, 2)],
    );
    assert_eq!(
        reason(&call(
            &mut f.engine,
            v,
            "alice",
            31,
            vec![uid(&id), cp.clone(), Node::bytes(DATA, vec![1])]
        )),
        10
    );
    assert_eq!(remaining(&mut f.engine, v, &id), 1);
    assert!(
        !f.engine
            .store
            .get("alice", &id)
            .unwrap()
            .unwrap()
            .usage_consumed
    );
    let r = f
        .engine
        .process(
            "alice",
            &batch_option(
                req(
                    v,
                    vec![
                        (17, vec![uid(&id), Node::long(USAGE_LIMITS_COUNT, 1)]),
                        (0x7fffffff, vec![]),
                    ],
                ),
                3,
            ),
        )
        .unwrap();
    assert_eq!(
        r.all(BATCH_ITEM)
            .next()
            .unwrap()
            .required(RESULT_STATUS)
            .unwrap()
            .number()
            .unwrap(),
        3
    );
    assert_eq!(remaining(&mut f.engine, v, &id), 1);
    assert!(
        !f.engine
            .store
            .get("alice", &id)
            .unwrap()
            .unwrap()
            .usage_consumed
    );
    let mut r = req(
        v,
        vec![(
            31,
            vec![uid(&id), cp.clone(), Node::bytes(DATA, vec![0; 1024])],
        )],
    );
    if let Value::Structure(fields) = &mut r.value
        && let Value::Structure(header) = &mut fields[0].value
    {
        header.push(Node::int(MAXIMUM_RESPONSE_SIZE, 256));
    }
    assert_eq!(reason(&f.engine.process("alice", &r).unwrap()), 2);
    assert_eq!(remaining(&mut f.engine, v, &id), 1);
    assert!(
        !f.engine
            .store
            .get("alice", &id)
            .unwrap()
            .unwrap()
            .usage_consumed
    );
    // Undo keeps the undone Encrypt payload (1.4 Tables 285/366), so the
    // delivered ciphertext keeps its Usage Limits debit.
    let undo_encrypt = batch_option(
        req(
            v,
            vec![
                (31, vec![uid(&id), cp, Node::bytes(DATA, vec![0; 16])]),
                (0x7fffffff, vec![]),
            ],
        ),
        3,
    );
    let r = f.engine.process("alice", &undo_encrypt).unwrap();
    assert_eq!(statuses(&r), vec![3, 1]);
    assert!(
        r.get(BATCH_ITEM)
            .unwrap()
            .required(RESPONSE_PAYLOAD)
            .unwrap()
            .get(DATA)
            .is_some()
    );
    assert_eq!(remaining(&mut f.engine, v, &id), 0);
    assert!(
        f.engine
            .store
            .get("alice", &id)
            .unwrap()
            .unwrap()
            .usage_consumed
    );
    // Repeating the failing batch cannot yield more output.
    let r = f.engine.process("alice", &undo_encrypt).unwrap();
    assert_eq!(statuses(&r), vec![1]);
    assert_eq!(reason(&r), 12);
    assert_eq!(remaining(&mut f.engine, v, &id), 0);
    f.engine.store.verify_audit().unwrap();
}

#[test]
fn storage_legacy_upgrade_preserves_old_records_and_rejects_downgrade_and_future_schemas() {
    let mut f = Fixture::new();
    let id = create(&mut f.engine, Version(2, 1), vec![]);
    let obj = f.engine.store.get("alice", &id).unwrap().unwrap();
    let mut value = serde_json::to_value(&obj).unwrap();
    value.as_object_mut().unwrap().remove("usage_consumed");
    value.as_object_mut().unwrap().remove("attribute_indices");
    value.as_object_mut().unwrap().remove("replacement_id");
    value.as_object_mut().unwrap().remove("wrapped");
    value.as_object_mut().unwrap().remove("secret_type");
    value.as_object_mut().unwrap().remove("imported");
    value.as_object_mut().unwrap().remove("metadata");
    value.as_object_mut().unwrap().remove("split");
    value.as_object_mut().unwrap().remove("protection_mask");
    value.as_object_mut().unwrap().remove("opaque_type");
    value.as_object_mut().unwrap().remove("pgp_version");
    value.as_object_mut().unwrap().remove("certificate_type");
    let decoded: keytend_kmip_server::store::Object = serde_json::from_value(value).unwrap();
    assert!(!decoded.usage_consumed);
    assert!(decoded.attribute_indices.is_empty());
    assert!(decoded.replacement_id.is_none());
    assert!(decoded.wrapped.is_none());
    assert!(!decoded.imported);
    assert!(decoded.split.is_none());
    assert_eq!(decoded.secret_type, 2);
    assert_eq!(decoded.opaque_type, 0x80000000);
    assert_eq!(decoded.pgp_version, 4);
    assert_eq!(decoded.certificate_type, 1);
    assert_eq!(decoded.protection_mask, 1);
    let path = f._dir.path().join("keys.sqlite");
    let key = f._dir.path().join("master");
    drop(f.engine);
    legacy::write(&path, &key, &[serde_json::to_value(&decoded).unwrap()], 1);
    let store = Store::open(&path, &key).unwrap();
    assert_eq!(
        store.get("alice", &id).unwrap().unwrap().material,
        obj.material
    );
    let c = rusqlite::Connection::open(&path).unwrap();
    assert_eq!(
        c.query_row("PRAGMA user_version", [], |r| r.get::<_, u32>(0))
            .unwrap(),
        keytend_kmip_server::store::STORAGE_SCHEMA as u32
    );
    drop(store);
    c.execute_batch("PRAGMA user_version=17").unwrap();
    assert!(Store::open(&path, &key).is_err());
    c.execute_batch("PRAGMA user_version=19").unwrap();
    drop(c);
    assert!(Store::open(&path, &key).is_err());
}
fn register_aes(e: &mut Engine, v: Version, key: Vec<u8>, extra: Vec<Node>) -> String {
    let mut a = vec![Node::int(CRYPTOGRAPHIC_USAGE_MASK, 12)];
    a.extend(extra);
    payload(&call(
        e,
        v,
        "alice",
        3,
        vec![
            Node::enumeration(OBJECT_TYPE, 2),
            container(v, a),
            Node::structure(
                SYMMETRIC_KEY,
                vec![Node::structure(
                    KEY_BLOCK,
                    vec![
                        Node::enumeration(KEY_FORMAT_TYPE, 1),
                        Node::structure(KEY_VALUE, vec![Node::bytes(KEY_MATERIAL, key.clone())]),
                        Node::enumeration(CRYPTOGRAPHIC_ALGORITHM, 3),
                        Node::int(CRYPTOGRAPHIC_LENGTH, (key.len() * 8) as i32),
                    ],
                )],
            ),
        ],
    ))
    .required(UNIQUE_IDENTIFIER)
    .unwrap()
    .identifier_text()
    .unwrap()
    .to_owned()
}

#[test]
fn stored_parameters_and_request_override_use_published_aes_vectors() {
    for v in Version::supported(true)
        .into_iter()
        .filter(|v| *v >= Version(1, 2))
    {
        let mut f = Fixture::new();
        f.engine.experimental_v3 = true;
        let ecb = Node::structure(
            CRYPTOGRAPHIC_PARAMETERS,
            vec![Node::enumeration(BLOCK_CIPHER_MODE, 2)],
        );
        let cbc = Node::structure(
            CRYPTOGRAPHIC_PARAMETERS,
            vec![Node::enumeration(BLOCK_CIPHER_MODE, 1)],
        );
        let key = hex::decode("2b7e151628aed2a6abf7158809cf4f3c").unwrap();
        let plaintext = Node::bytes(
            DATA,
            hex::decode("6bc1bee22e409f96e93d7e117393172a").unwrap(),
        );
        let id = register_aes(&mut f.engine, v, key, vec![ecb, cbc.clone()]);
        payload(&call(&mut f.engine, v, "alice", 18, vec![uid(&id)]));
        let response = call(
            &mut f.engine,
            v,
            "alice",
            31,
            vec![uid(&id), plaintext.clone()],
        );
        assert_eq!(
            payload(&response)
                .required(DATA)
                .unwrap()
                .byte_string()
                .unwrap(),
            hex::decode("3ad77bb40d7a3660a89ecaf32466ef97").unwrap()
        );
        assert!(payload(&response).get(IV_COUNTER_NONCE).is_none());
        let iv = Node::bytes(
            IV_COUNTER_NONCE,
            hex::decode("000102030405060708090a0b0c0d0e0f").unwrap(),
        );
        let response = call(
            &mut f.engine,
            v,
            "alice",
            31,
            vec![uid(&id), cbc, plaintext.clone(), iv],
        );
        assert_eq!(
            payload(&response)
                .required(DATA)
                .unwrap()
                .byte_string()
                .unwrap(),
            hex::decode("7649abac8119b246cee98e9b12e9197d").unwrap()
        );
        assert!(payload(&response).get(IV_COUNTER_NONCE).is_none());
        let reference = if v.0 == 1 {
            Node::text(ATTRIBUTE_NAME, "Cryptographic Parameters")
        } else {
            Node::enumeration(ATTRIBUTE_REFERENCE, CRYPTOGRAPHIC_PARAMETERS)
        };
        let response = call(&mut f.engine, v, "alice", 11, vec![uid(&id), reference]);
        if v.0 == 1 {
            let attributes: Vec<_> = payload(&response).all(ATTRIBUTE).collect();
            assert_eq!(attributes.len(), 2);
            for (i, a) in attributes.iter().enumerate() {
                assert_eq!(
                    a.required(ATTRIBUTE_INDEX).unwrap().number().unwrap(),
                    i as u32
                );
            }
        } else {
            assert_eq!(
                payload(&response)
                    .required(ATTRIBUTES)
                    .unwrap()
                    .all(CRYPTOGRAPHIC_PARAMETERS)
                    .count(),
                2
            );
        }
        // Explicit parameters replace the stored instance; omitted mode cannot
        // silently inherit ECB/CBC from another stored instance.
        let response = call(
            &mut f.engine,
            v,
            "alice",
            31,
            vec![
                uid(&id),
                Node::structure(CRYPTOGRAPHIC_PARAMETERS, vec![]),
                plaintext,
            ],
        );
        assert_eq!(reason(&response), 7);
    }
}

#[test]
fn gcm_parameter_units_validation_and_random_iv_precedence() {
    let mut f = Fixture::new();
    let v = Version(2, 1);
    let stored = Node::structure(
        CRYPTOGRAPHIC_PARAMETERS,
        vec![
            Node::enumeration(BLOCK_CIPHER_MODE, 9),
            Node::int(TAG_LENGTH, 16),
            Node::int(IV_LENGTH, 96),
            Node::boolean(RANDOM_IV, true),
        ],
    );
    let id = register_aes(&mut f.engine, v, vec![0; 16], vec![stored]);
    payload(&call(&mut f.engine, v, "alice", 18, vec![uid(&id)]));
    let data = Node::bytes(DATA, vec![0; 16]);
    let iv = Node::bytes(IV_COUNTER_NONCE, vec![0; 12]);
    let response = call(
        &mut f.engine,
        v,
        "alice",
        31,
        vec![uid(&id), data.clone(), iv.clone()],
    );
    let ciphertext = payload(&response).required(DATA).unwrap().clone();
    let tag = payload(&response)
        .required(AUTHENTICATED_ENCRYPTION_TAG)
        .unwrap()
        .clone();
    assert_eq!(
        ciphertext.byte_string().unwrap(),
        hex::decode("0388dace60b6a392f328c2b971b2fe78").unwrap()
    );
    assert_eq!(tag.byte_string().unwrap().len(), 16);
    assert!(payload(&response).get(IV_COUNTER_NONCE).is_none());
    let response = call(
        &mut f.engine,
        v,
        "alice",
        32,
        vec![uid(&id), ciphertext, iv.clone(), tag],
    );
    assert_eq!(
        payload(&response)
            .required(DATA)
            .unwrap()
            .byte_string()
            .unwrap(),
        &[0; 16]
    );
    let response = call(&mut f.engine, v, "alice", 31, vec![uid(&id), data.clone()]);
    assert_eq!(
        payload(&response)
            .required(IV_COUNTER_NONCE)
            .unwrap()
            .byte_string()
            .unwrap()
            .len(),
        12
    );
    // REQ: docs/interpretations.md (result reasons): an unsupported GCM Tag Length
    // is General Failure, as the OASIS traces CS-BC-M-GCM-1 expect.
    assert_eq!(
        reason(&call(
            &mut f.engine,
            v,
            "alice",
            31,
            vec![
                uid(&id),
                Node::structure(
                    CRYPTOGRAPHIC_PARAMETERS,
                    vec![
                        Node::enumeration(BLOCK_CIPHER_MODE, 9),
                        Node::int(TAG_LENGTH, 128),
                    ]
                ),
                data.clone(),
                iv.clone()
            ]
        )),
        0x100
    );
    let bad_parameters = vec![
        vec![
            Node::enumeration(BLOCK_CIPHER_MODE, 9),
            Node::int(IV_LENGTH, 12),
        ],
        vec![
            Node::enumeration(BLOCK_CIPHER_MODE, 9),
            Node::enumeration(TAG_LENGTH, 16),
        ],
        vec![
            Node::enumeration(BLOCK_CIPHER_MODE, 9),
            Node::int(TAG_LENGTH, 16),
            Node::int(TAG_LENGTH, 16),
        ],
        vec![
            Node::enumeration(BLOCK_CIPHER_MODE, 9),
            Node::boolean(PADDING_METHOD, false),
        ],
    ];
    for cp in bad_parameters {
        assert_eq!(
            reason(&call(
                &mut f.engine,
                v,
                "alice",
                31,
                vec![
                    uid(&id),
                    Node::structure(CRYPTOGRAPHIC_PARAMETERS, cp),
                    data.clone(),
                    iv.clone()
                ]
            )),
            7
        );
    }
    let id = create(
        &mut f.engine,
        v,
        vec![Node::date(
            ACTIVATION_DATE,
            keytend_kmip_server::store::now() - 1,
        )],
    );
    assert_eq!(
        reason(&call(&mut f.engine, v, "alice", 31, vec![uid(&id), data])),
        if v.0 >= 2 { 7 } else { 6 }
    );
}

#[test]
fn vendor_attributes_are_identified_by_vendor_and_name() {
    fn attribute(vendor: &str, name: &str, value: &str) -> Node {
        Node::structure(
            ATTRIBUTE,
            vec![
                Node::text(VENDOR_IDENTIFICATION, vendor),
                Node::text(ATTRIBUTE_NAME, name),
                Node::text(ATTRIBUTE_VALUE, value),
            ],
        )
    }
    let mut f = Fixture::new();
    let v = Version(2, 1);
    let one = attribute("x", "ID", "database-one");
    let two = attribute("vendor.two", "ID", "database-two");
    let id = create(&mut f.engine, v, vec![one.clone(), two]);
    let reference = Node::structure(
        ATTRIBUTE_REFERENCE,
        vec![
            Node::text(VENDOR_IDENTIFICATION, "x"),
            Node::text(ATTRIBUTE_NAME, "ID"),
        ],
    );
    let response = call(
        &mut f.engine,
        v,
        "alice",
        11,
        vec![uid(&id), reference.clone()],
    );
    assert_eq!(
        payload(&response)
            .required(ATTRIBUTES)
            .unwrap()
            .children()
            .unwrap()
            .len(),
        1
    );
    assert!(
        payload(&response)
            .required(ATTRIBUTES)
            .unwrap()
            .required(ATTRIBUTE)
            .unwrap()
            == &one
    );
    let response = call(&mut f.engine, v, "alice", 12, vec![uid(&id)]);
    assert!(
        payload(&response)
            .all(ATTRIBUTE_REFERENCE)
            .any(|n| n == &reference)
    );
    let response = call(
        &mut f.engine,
        v,
        "alice",
        8,
        vec![Node::structure(ATTRIBUTES, vec![one.clone()])],
    );
    assert_eq!(
        payload(&response)
            .required(UNIQUE_IDENTIFIER)
            .unwrap()
            .identifier_text()
            .unwrap(),
        id
    );
    for (vendor, expected) in [("y", 12), ("not-allowed", 7), ("", 7)] {
        assert_eq!(
            reason(&call(
                &mut f.engine,
                v,
                "alice",
                1,
                vec![
                    Node::enumeration(OBJECT_TYPE, 2),
                    attrs(v, vec![attribute(vendor, "ID", "value")])
                ]
            )),
            expected
        );
    }
    let duplicate = call(
        &mut f.engine,
        v,
        "alice",
        1,
        vec![
            Node::enumeration(OBJECT_TYPE, 2),
            attrs(v, vec![one.clone(), one]),
        ],
    );
    payload(&duplicate);
}

#[test]
fn locate_orders_by_creation_matches_subsets_and_updates_placeholder() {
    let mut f = Fixture::new();
    let v = Version(2, 1);
    let mut ids = vec![];
    for created in [100, 300, 200] {
        let name = Node::structure(
            APPLICATION_SPECIFIC_INFORMATION,
            vec![
                Node::text(APPLICATION_NAMESPACE, "database"),
                Node::text(APPLICATION_DATA, "data"),
            ],
        );
        let id = create(&mut f.engine, v, vec![name]);
        let mut o = f.engine.store.get("alice", &id).unwrap().unwrap();
        o.created = created;
        f.engine.store.put(&o).unwrap();
        ids.push(id);
    }
    let filter = Node::structure(
        ATTRIBUTES,
        vec![
            Node::int(CRYPTOGRAPHIC_USAGE_MASK, 4),
            Node::structure(
                APPLICATION_SPECIFIC_INFORMATION,
                vec![Node::text(APPLICATION_NAMESPACE, "database")],
            ),
        ],
    );
    let response = call(&mut f.engine, v, "alice", 8, vec![filter.clone()]);
    let ordered: Vec<_> = payload(&response)
        .all(UNIQUE_IDENTIFIER)
        .map(|n| n.string().unwrap())
        .collect();
    assert_eq!(ordered, vec![&ids[1], &ids[2], &ids[0]]);
    let response = f
        .engine
        .process(
            "alice",
            &req(
                v,
                vec![
                    (
                        8,
                        vec![
                            filter.clone(),
                            Node::int(MAXIMUM_ITEMS, 1),
                            Node::int(OFFSET_ITEMS, 1),
                        ],
                    ),
                    (10, vec![]),
                ],
            ),
        )
        .unwrap();
    let get = response.all(BATCH_ITEM).nth(1).unwrap();
    assert_eq!(get.required(RESULT_STATUS).unwrap().number().unwrap(), 0);
    assert_eq!(
        get.required(RESPONSE_PAYLOAD)
            .unwrap()
            .required(UNIQUE_IDENTIFIER)
            .unwrap()
            .identifier_text()
            .unwrap(),
        ids[2]
    );
    let response = f
        .engine
        .process(
            "alice",
            &req(
                v,
                vec![
                    (1, vec![Node::enumeration(OBJECT_TYPE, 2), attrs(v, vec![])]),
                    (8, vec![filter]),
                    (10, vec![]),
                ],
            ),
        )
        .unwrap();
    assert_eq!(
        response
            .all(BATCH_ITEM)
            .nth(2)
            .unwrap()
            .required(RESULT_REASON)
            .unwrap()
            .number()
            .unwrap(),
        if v.0 >= 2 { 7 } else { 6 }
    );
    assert_eq!(
        reason(&call(
            &mut f.engine,
            v,
            "alice",
            8,
            vec![Node::int(OFFSET_ITEMS, 100001)]
        )),
        0x1b
    );
}

#[test]
fn check_denial_clears_placeholder_and_reports_rejected_usage() {
    for v in [Version(1, 4), Version(2, 1)] {
        let mut f = Fixture::new();
        let response = f
            .engine
            .process(
                "alice",
                &batch_option(
                    req(
                        v,
                        vec![
                            (1, vec![Node::enumeration(OBJECT_TYPE, 2), attrs(v, vec![])]),
                            (9, vec![Node::int(CRYPTOGRAPHIC_USAGE_MASK, 1)]),
                            (10, vec![]),
                        ],
                    ),
                    1,
                ),
            )
            .unwrap();
        let items: Vec<_> = response.all(BATCH_ITEM).collect();
        assert_eq!(
            items[1].required(RESULT_REASON).unwrap().number().unwrap(),
            if v.0 >= 2 { 0x29 } else { 12 }
        );
        let rejected = items[1].required(RESPONSE_PAYLOAD).unwrap();
        assert!(rejected.get(UNIQUE_IDENTIFIER).is_none());
        assert_eq!(
            rejected
                .required(CRYPTOGRAPHIC_USAGE_MASK)
                .unwrap()
                .number()
                .unwrap(),
            1
        );
        // The emptied ID Placeholder: Item Not Found in 1.x (the only 1.x
        // error-table row for an unidentified object), Invalid Field in 2.x.
        assert_eq!(
            items[2].required(RESULT_REASON).unwrap().number().unwrap(),
            if v.0 >= 2 { 7 } else { 1 }
        );
        let id = items[0]
            .required(RESPONSE_PAYLOAD)
            .unwrap()
            .required(UNIQUE_IDENTIFIER)
            .unwrap()
            .identifier_text()
            .unwrap();
        payload(&call(&mut f.engine, v, "alice", 10, vec![uid(id)]));
    }
}

#[test]
fn scheduled_dates_are_resolved_before_using_persisted_keys() {
    let mut f = Fixture::new();
    let v = Version(2, 1);
    let now = keytend_kmip_server::store::now();
    let id = create(
        &mut f.engine,
        v,
        vec![Node::date(ACTIVATION_DATE, now + 3600)],
    );
    let cp = Node::structure(
        CRYPTOGRAPHIC_PARAMETERS,
        vec![
            Node::enumeration(BLOCK_CIPHER_MODE, 9),
            Node::boolean(RANDOM_IV, true),
        ],
    );
    assert_eq!(
        reason(&call(
            &mut f.engine,
            v,
            "alice",
            31,
            vec![uid(&id), cp.clone(), Node::bytes(DATA, vec![1])]
        )),
        0x43
    );
    // A persisted record after its scheduled time has passed can still contain
    // the old state. Build that fixture without sleeping or changing the host clock.
    let mut stored = f.engine.store.get("alice", &id).unwrap().unwrap();
    stored.attrs.retain(|a| a.tag != ACTIVATION_DATE);
    stored.attrs.push(Node::date(ACTIVATION_DATE, now - 60));
    assert_eq!(stored.state, 1);
    f.engine.store.put(&stored).unwrap();
    payload(&call(
        &mut f.engine,
        v,
        "alice",
        31,
        vec![uid(&id), cp.clone(), Node::bytes(DATA, vec![1])],
    ));
    assert_eq!(f.engine.store.get("alice", &id).unwrap().unwrap().state, 2);
    let mut stored = f.engine.store.get("alice", &id).unwrap().unwrap();
    stored.attrs.push(Node::date(DEACTIVATION_DATE, now - 1));
    assert_eq!(stored.state, 2);
    f.engine.store.put(&stored).unwrap();
    assert_eq!(
        reason(&call(
            &mut f.engine,
            v,
            "alice",
            31,
            vec![uid(&id), cp, Node::bytes(DATA, vec![1])]
        )),
        0x43
    );
    payload(&call(
        &mut f.engine,
        v,
        "alice",
        11,
        vec![uid(&id), Node::enumeration(ATTRIBUTE_REFERENCE, STATE)],
    ));
    assert_eq!(f.engine.store.get("alice", &id).unwrap().unwrap().state, 3);
}
#[test]
fn lifecycle_all_final_versions_and_opt_in_draft() {
    let mut f = Fixture::new();
    for v in Version::supported(false) {
        let id = create(&mut f.engine, v, vec![]);
        let r = call(&mut f.engine, v, "alice", 10, vec![uid(&id)]);
        let obj = payload(&r).get(SYMMETRIC_KEY).unwrap();
        assert_eq!(
            obj.get(KEY_BLOCK)
                .unwrap()
                .get(KEY_VALUE)
                .unwrap()
                .get(KEY_MATERIAL)
                .unwrap()
                .byte_string()
                .unwrap()
                .len(),
            32
        );
        assert_eq!(
            reason(&call(&mut f.engine, v, "bob", 10, vec![uid(&id)])),
            not_found(v)
        );
        payload(&call(&mut f.engine, v, "alice", 18, vec![uid(&id)]));
        // Destroy of an Active object: Permission Denied through 2.0, Wrong Key
        // Lifecycle State from 2.1 (2.1 Table 210; the 2.1 lifecycle traces).
        assert_eq!(
            reason(&call(&mut f.engine, v, "alice", 20, vec![uid(&id)])),
            if v >= Version(2, 1) { 0x43 } else { 12 }
        );
        payload(&call(
            &mut f.engine,
            v,
            "alice",
            19,
            vec![
                uid(&id),
                Node::structure(
                    REVOCATION_REASON,
                    vec![Node::enumeration(REVOCATION_REASON_CODE, 6)],
                ),
            ],
        ));
        payload(&call(&mut f.engine, v, "alice", 20, vec![uid(&id)]));
        // A second Destroy: Permission Denied in 1.x (1.4 Table 348), Object
        // Destroyed (0x36) in 2.x (2.0 Table 195, 2.1 Table 210).
        assert_eq!(
            reason(&call(&mut f.engine, v, "alice", 20, vec![uid(&id)])),
            if v.0 >= 2 { 0x36 } else { 12 }
        );
        // Get of a destroyed object is Object Destroyed in 2.x.
        assert_eq!(
            reason(&call(&mut f.engine, v, "alice", 10, vec![uid(&id)])),
            if v.0 >= 2 { 0x36 } else { 11 }
        );
    }
    assert_eq!(
        reason(&call(&mut f.engine, Version(3, 0), "alice", 59, vec![])),
        0x3f
    );
    f.engine.experimental_v3 = true;
    payload(&call(&mut f.engine, Version(3, 0), "alice", 59, vec![]));
}
#[test]
fn lifecycle_refusals_use_wrong_key_lifecycle_state_from_2_0() {
    // A second Activate (two clients racing to activate one Pre-Active key) and a Revoke of a
    // destroyed key are lifecycle refusals: Permission Denied in KMIP 1.x (1.4 Table 346), Wrong
    // Key Lifecycle State from 2.0 (Activate and Revoke error tables), as clients classify them.
    let mut f = Fixture::new();
    f.engine.experimental_v3 = true;
    for v in Version::supported(true) {
        let expected = if v.0 >= 2 { 0x43 } else { 12 };
        let id = create(&mut f.engine, v, vec![]);
        payload(&call(&mut f.engine, v, "alice", 18, vec![uid(&id)]));
        assert_eq!(
            reason(&call(&mut f.engine, v, "alice", 18, vec![uid(&id)])),
            expected,
            "second Activate at {}.{}",
            v.0,
            v.1
        );
        let revoke = || {
            vec![
                uid(&id),
                Node::structure(
                    REVOCATION_REASON,
                    vec![Node::enumeration(REVOCATION_REASON_CODE, 6)],
                ),
            ]
        };
        payload(&call(&mut f.engine, v, "alice", 19, revoke()));
        assert_eq!(
            reason(&call(&mut f.engine, v, "alice", 18, vec![uid(&id)])),
            expected,
            "Activate of a Deactivated key at {}.{}",
            v.0,
            v.1
        );
        payload(&call(&mut f.engine, v, "alice", 20, vec![uid(&id)]));
        assert_eq!(
            reason(&call(&mut f.engine, v, "alice", 19, revoke())),
            expected,
            "Revoke of a destroyed key at {}.{}",
            v.0,
            v.1
        );
    }
}
#[test]
fn gcm_authentication_state_and_usage() {
    let mut f = Fixture::new();
    let v = Version(2, 1);
    let id = create(&mut f.engine, v, vec![]);
    let cp = Node::structure(
        CRYPTOGRAPHIC_PARAMETERS,
        vec![
            Node::enumeration(BLOCK_CIPHER_MODE, 9),
            Node::boolean(RANDOM_IV, true),
        ],
    );
    assert_eq!(
        reason(&call(
            &mut f.engine,
            v,
            "alice",
            31,
            vec![
                uid(&id),
                cp.clone(),
                Node::bytes(DATA, b"database payload".to_vec())
            ]
        )),
        0x43
    );
    payload(&call(&mut f.engine, v, "alice", 18, vec![uid(&id)]));
    let encrypted = call(
        &mut f.engine,
        v,
        "alice",
        31,
        vec![
            uid(&id),
            cp,
            Node::bytes(DATA, b"database payload".to_vec()),
        ],
    );
    let p = payload(&encrypted);
    let decrypt = vec![
        uid(&id),
        Node::structure(
            CRYPTOGRAPHIC_PARAMETERS,
            vec![Node::enumeration(BLOCK_CIPHER_MODE, 9)],
        ),
        p.get(DATA).unwrap().clone(),
        p.get(IV_COUNTER_NONCE).unwrap().clone(),
        p.get(AUTHENTICATED_ENCRYPTION_TAG).unwrap().clone(),
    ];
    let plain = call(&mut f.engine, v, "alice", 32, decrypt.clone());
    assert_eq!(
        payload(&plain).get(DATA).unwrap().byte_string().unwrap(),
        b"database payload"
    );
    let mut bad = decrypt;
    *bad.last_mut().unwrap() = Node::bytes(AUTHENTICATED_ENCRYPTION_TAG, vec![0; 16]);
    let rejected = call(&mut f.engine, v, "alice", 32, bad);
    assert_eq!(reason(&rejected), 10);
    assert!(
        rejected
            .required(BATCH_ITEM)
            .unwrap()
            .get(RESPONSE_PAYLOAD)
            .is_none()
    );
}
#[test]
fn batch_placeholder_and_response_limit_rollback() {
    let mut f = Fixture::new();
    let v = Version(1, 4);
    let response = f
        .engine
        .process(
            "alice",
            &req(
                v,
                vec![
                    (1, vec![Node::enumeration(OBJECT_TYPE, 2), attrs(v, vec![])]),
                    (10, vec![]),
                ],
            ),
        )
        .unwrap();
    assert_eq!(response.all(BATCH_ITEM).count(), 2);
    for i in response.all(BATCH_ITEM) {
        assert_eq!(i.get(RESULT_STATUS).unwrap().number().unwrap(), 0);
    }
    let before = f.engine.store.list("alice").unwrap().len();
    let mut request = req(
        v,
        vec![
            (1, vec![Node::enumeration(OBJECT_TYPE, 2), attrs(v, vec![])]),
            (10, vec![]),
        ],
    );
    let Value::Structure(children) = &mut request.value else {
        unreachable!()
    };
    let Value::Structure(h) = &mut children[0].value else {
        unreachable!()
    };
    h.push(Node::int(MAXIMUM_RESPONSE_SIZE, 256));
    assert_eq!(reason(&f.engine.process("alice", &request).unwrap()), 2);
    assert_eq!(f.engine.store.list("alice").unwrap().len(), before);
}
#[test]
fn persistence_encryption_wrong_master_key_and_audit_tamper() {
    let mut f = Fixture::new();
    let v = Version(2, 1);
    let id = create(&mut f.engine, v, vec![]);
    let path = f._dir.path().join("keys.sqlite");
    let key = f._dir.path().join("master");
    let o = f.engine.store.get("alice", &id).unwrap().unwrap();
    let material = o.material.clone();
    drop(f.engine);
    let store = Store::open(&path, &key).unwrap();
    assert_eq!(store.get("alice", &id).unwrap().unwrap().material, material);
    store.verify_audit().unwrap();
    drop(store);
    for p in [path.clone(), path.with_extension("sqlite-wal")] {
        if let Ok(bytes) = std::fs::read(p) {
            assert!(!bytes.windows(material.len()).any(|w| w == material));
        }
    }
    std::fs::write(&key, [43; 32]).unwrap();
    assert!(Store::open(&path, &key).is_err());
    std::fs::write(&key, [42; 32]).unwrap();
    let c = rusqlite::Connection::open(&path).unwrap();
    c.execute("UPDATE audit SET status=9 WHERE seq=1", [])
        .unwrap();
    drop(c);
    assert!(Store::open(&path, &key).is_err());
}

fn batch_option(mut request: Node, continuation: u32) -> Node {
    let Value::Structure(message) = &mut request.value else {
        unreachable!()
    };
    let Value::Structure(header) = &mut message[0].value else {
        unreachable!()
    };
    header.push(Node::enumeration(
        BATCH_ERROR_CONTINUATION_OPTION,
        continuation,
    ));
    request
}

// REQ:92e085b7394e2bf9 under Stop and Continue, items completed before a failure stay committed
// REQ:1831767ee2dbada9 2.x Undo: a failed item rolls back every earlier item of the batch
// REQ:254fe24cc43eab02 2.x Stop: nothing after the failed item is processed
// REQ:dc6d7efe7324396a 1.x Undo: a failed item rolls back every earlier item of the batch
// REQ:5a194ffe65fff1fb 1.x Stop: nothing after the failed item is processed
// REQ:ecaf4118dbb1e0f7 1.x continuation options other than Stop are supported, so they are honoured rather than rejected
#[test]
fn batch_stop_continue_undo_and_durable_audit_outcomes() {
    for v in Version::supported(true) {
        for continuation in [1, 2, 3] {
            let mut f = Fixture::new();
            f.engine.experimental_v3 = true;
            let id = create(&mut f.engine, v, vec![]);
            let request = batch_option(
                req(
                    v,
                    vec![
                        (18, vec![uid(&id)]),
                        (1, vec![Node::enumeration(OBJECT_TYPE, 2), attrs(v, vec![])]),
                        (0x7fffffff, vec![]),
                        (20, vec![]),
                    ],
                ),
                continuation,
            );
            let response = f.engine.process("alice", &request).unwrap();
            let items: Vec<_> = response.all(BATCH_ITEM).collect();
            assert_eq!(items.len(), if continuation == 1 { 4 } else { 3 });
            if v.0 < 3 {
                assert_eq!(
                    response
                        .required(RESPONSE_HEADER)
                        .unwrap()
                        .required(BATCH_COUNT)
                        .unwrap()
                        .number()
                        .unwrap() as usize,
                    items.len()
                );
            } else {
                assert!(
                    response
                        .required(RESPONSE_HEADER)
                        .unwrap()
                        .get(BATCH_COUNT)
                        .is_none()
                );
            }
            let expected = if continuation == 3 { 3 } else { 0 };
            for item in &items[..2] {
                assert_eq!(
                    item.required(RESULT_STATUS).unwrap().number().unwrap(),
                    expected
                );
                if continuation == 3 {
                    assert!(item.get(RESPONSE_PAYLOAD).is_some());
                    assert!(item.get(RESULT_REASON).is_none());
                }
            }
            assert_eq!(
                items[2].required(RESULT_REASON).unwrap().number().unwrap(),
                5
            );
            assert_eq!(
                f.engine.store.get("alice", &id).unwrap().unwrap().state,
                if continuation == 3 { 1 } else { 2 }
            );
            if continuation == 1 {
                // The failed item must not clear the preceding Create's ID placeholder.
                assert_eq!(
                    items[3].required(RESULT_STATUS).unwrap().number().unwrap(),
                    0
                );
            }
            let path = f._dir.path().join("keys.sqlite");
            let key = f._dir.path().join("master");
            drop(f.engine);
            let store = Store::open(&path, &key).unwrap();
            assert_eq!(
                store.list("alice").unwrap().len(),
                if continuation == 3 { 1 } else { 2 }
            );
            store.verify_audit().unwrap();
            let c = rusqlite::Connection::open(path).unwrap();
            let statuses: Vec<u32> = c
                .prepare("SELECT status FROM audit WHERE seq>1 ORDER BY seq")
                .unwrap()
                .query_map([], |r| r.get(0))
                .unwrap()
                .map(Result::unwrap)
                .collect();
            assert_eq!(
                statuses,
                match continuation {
                    1 => vec![0, 0, 1, 0],
                    2 => vec![0, 0, 1],
                    _ => vec![3, 3, 1],
                }
            );
        }
    }
}

#[test]
fn undo_succeeds_when_all_items_succeed_and_includes_authorization_failures() {
    let mut f = Fixture::new();
    let v = Version(2, 1);
    let request = batch_option(
        req(
            v,
            vec![
                (1, vec![Node::enumeration(OBJECT_TYPE, 2), attrs(v, vec![])]),
                (18, vec![]),
                (10, vec![]),
            ],
        ),
        3,
    );
    let r = f.engine.process("alice", &request).unwrap();
    for item in r.all(BATCH_ITEM) {
        assert_eq!(item.required(RESULT_STATUS).unwrap().number().unwrap(), 0);
    }
    assert_eq!(f.engine.store.list("alice").unwrap().len(), 1);
    let r = f
        .engine
        .process_authorized("bob", &request, Some(&[1]))
        .unwrap();
    let items: Vec<_> = r.all(BATCH_ITEM).collect();
    assert_eq!(items.len(), 2);
    assert_eq!(
        items[0].required(RESULT_STATUS).unwrap().number().unwrap(),
        3
    );
    assert_eq!(
        items[1].required(RESULT_REASON).unwrap().number().unwrap(),
        12
    );
    assert!(f.engine.store.list("bob").unwrap().is_empty());
}

#[test]
fn header_errors_preserve_correlation_and_validate_synchronous_modes() {
    let mut f = Fixture::new();
    for v in [Version(1, 4), Version(2, 0), Version(2, 1)] {
        let mut r = req(v, vec![(24, vec![])]);
        let Value::Structure(message) = &mut r.value else {
            unreachable!()
        };
        let Value::Structure(header) = &mut message[0].value else {
            unreachable!()
        };
        header.push(Node::text(CLIENT_CORRELATION_VALUE, "check-errors"));
        header.push(Node::enumeration(BATCH_ERROR_CONTINUATION_OPTION, 3));
        let response = f.engine.process("alice", &r).unwrap();
        assert_eq!(reason(&response), 7);
        let h = response.required(RESPONSE_HEADER).unwrap();
        assert_eq!(
            h.required(CLIENT_CORRELATION_VALUE)
                .unwrap()
                .string()
                .unwrap(),
            "check-errors"
        );
        assert!(
            !h.required(SERVER_CORRELATION_VALUE)
                .unwrap()
                .string()
                .unwrap()
                .is_empty()
        );
        assert_eq!(h.children().unwrap().last().unwrap().tag, BATCH_COUNT);
    }
    // Mandatory is now deferred (asynchronous.rs); see tests/asynchronous.rs.
    for (mode, expected_reason) in [(2, None), (3, None), (4, Some(7))] {
        let mut r = req(Version(2, 1), vec![(59, vec![])]);
        let Value::Structure(message) = &mut r.value else {
            unreachable!()
        };
        let Value::Structure(header) = &mut message[0].value else {
            unreachable!()
        };
        header.push(Node::enumeration(ASYNCHRONOUS_INDICATOR, mode));
        let response = f.engine.process("alice", &r).unwrap();
        if let Some(expected) = expected_reason {
            assert_eq!(reason(&response), expected);
        } else {
            payload(&response);
        }
    }
}
fn header_field(mut request: Node, field: Node) -> Node {
    let Value::Structure(message) = &mut request.value else {
        unreachable!()
    };
    let Value::Structure(header) = &mut message[0].value else {
        unreachable!()
    };
    header.push(field);
    request
}
fn statuses(response: &Node) -> Vec<u32> {
    response
        .all(BATCH_ITEM)
        .map(|item| item.required(RESULT_STATUS).unwrap().number().unwrap())
        .collect()
}
fn audit_rows(f: &Fixture) -> i64 {
    rusqlite::Connection::open(f._dir.path().join("keys.sqlite"))
        .unwrap()
        .query_row("SELECT count(*) FROM audit", [], |r| r.get(0))
        .unwrap()
}
/// The message-level failure form: one Batch Item without Operation or
/// Unique Batch Item ID, and no payload.
fn message_rejection(v: Version, response: &Node) -> u32 {
    let items: Vec<_> = response.all(BATCH_ITEM).collect();
    assert_eq!(items.len(), 1);
    let header = response.required(RESPONSE_HEADER).unwrap();
    let version = header.required(PROTOCOL_VERSION).unwrap();
    assert_eq!(
        [PROTOCOL_VERSION_MAJOR, PROTOCOL_VERSION_MINOR].map(|tag| version
            .required(tag)
            .unwrap()
            .number()
            .unwrap()),
        [v.0, v.1]
    );
    if v.0 < 3 {
        assert_eq!(header.required(BATCH_COUNT).unwrap().number().unwrap(), 1);
    } else {
        assert!(header.get(BATCH_COUNT).is_none());
    }
    for tag in [OPERATION, UNIQUE_BATCH_ITEM_ID, RESPONSE_PAYLOAD] {
        assert!(items[0].get(tag).is_none(), "{tag:#x}");
    }
    assert_eq!(
        items[0].required(RESULT_STATUS).unwrap().number().unwrap(),
        1
    );
    items[0].required(RESULT_REASON).unwrap().number().unwrap()
}

fn critical_rejection(v: Version, response: &Node, request: &Node) -> u32 {
    let source = request
        .all(BATCH_ITEM)
        .find(|item| {
            item.all(MESSAGE_EXTENSION).any(|ext| {
                ext.children().is_ok_and(|fields| {
                    fields
                        .iter()
                        .any(|n| n.tag == CRITICALITY_INDICATOR && n.value == Value::Boolean(true))
                })
            })
        })
        .unwrap();
    let items: Vec<_> = response.all(BATCH_ITEM).collect();
    assert_eq!(items.len(), 1);
    assert!(items[0].get(OPERATION) == source.get(OPERATION));
    assert!(items[0].get(UNIQUE_BATCH_ITEM_ID) == source.get(UNIQUE_BATCH_ITEM_ID));
    assert!(items[0].get(RESPONSE_PAYLOAD).is_none());
    assert_eq!(
        items[0].required(RESULT_STATUS).unwrap().number().unwrap(),
        1
    );
    if v.0 < 3 {
        assert_eq!(
            response
                .required(RESPONSE_HEADER)
                .unwrap()
                .required(BATCH_COUNT)
                .unwrap()
                .number()
                .unwrap(),
            1
        );
    }
    items[0].required(RESULT_REASON).unwrap().number().unwrap()
}

#[test]
fn one_x_asynchronous_capability_is_answered_synchronously() {
    for minor in 0..=4 {
        let v = Version(1, minor);
        let mut f = Fixture::new();
        let capable = |r| header_field(r, Node::boolean(ASYNCHRONOUS_INDICATOR, true));
        let create_item = (1, vec![Node::enumeration(OBJECT_TYPE, 2), attrs(v, vec![])]);
        // Default Stop: the Get uses the Create's ID Placeholder.
        let r = f
            .engine
            .process(
                "alice",
                &capable(req(v, vec![create_item.clone(), (10, vec![])])),
            )
            .unwrap();
        assert_eq!(statuses(&r), [0, 0]);
        assert_eq!(
            r.required(RESPONSE_HEADER)
                .unwrap()
                .required(BATCH_COUNT)
                .unwrap()
                .number()
                .unwrap(),
            2
        );
        for (index, (item, op)) in r.all(BATCH_ITEM).zip([1, 10]).enumerate() {
            assert_eq!(item.required(OPERATION).unwrap().number().unwrap(), op);
            assert_eq!(
                item.required(UNIQUE_BATCH_ITEM_ID)
                    .unwrap()
                    .byte_string()
                    .unwrap(),
                [index as u8]
            );
            assert!(item.get(ASYNCHRONOUS_CORRELATION_VALUE).is_none());
            assert!(item.get(RESPONSE_PAYLOAD).is_some());
        }
        assert!(
            r.all(BATCH_ITEM)
                .nth(1)
                .unwrap()
                .required(RESPONSE_PAYLOAD)
                .unwrap()
                .get(SYMMETRIC_KEY)
                .is_some()
        );
        assert_eq!(f.engine.store.list("alice").unwrap().len(), 1);
        // Continue, Stop and Undo keep synchronous semantics. Cancel (25)
        // and Poll (26) stay unsupported operations, never Pending results.
        for (continuation, expected, objects) in [
            (1, vec![0, 1, 0], 3),
            (2, vec![0, 1], 4),
            (3, vec![3, 1], 4),
        ] {
            let async_op = if continuation == 1 { 26 } else { 25 };
            let request = capable(batch_option(
                req(
                    v,
                    vec![create_item.clone(), (async_op, vec![]), create_item.clone()],
                ),
                continuation,
            ));
            let r = f.engine.process("alice", &request).unwrap();
            assert_eq!(statuses(&r), expected, "{}.{} {continuation}", v.0, v.1);
            let failed = r.all(BATCH_ITEM).nth(1).unwrap();
            assert_eq!(
                failed.required(OPERATION).unwrap().number().unwrap(),
                async_op
            );
            // Poll and Cancel exist now; an empty payload lacks the
            // required Asynchronous Correlation Value.
            assert_eq!(failed.required(RESULT_REASON).unwrap().number().unwrap(), 7);
            assert!(
                r.all(BATCH_ITEM)
                    .all(|item| item.get(ASYNCHRONOUS_CORRELATION_VALUE).is_none())
            );
            assert_eq!(f.engine.store.list("alice").unwrap().len(), objects);
        }
        // False is still synchronous; 1.x encodes the indicator as Boolean.
        let r = f
            .engine
            .process(
                "alice",
                &header_field(
                    req(v, vec![(24, vec![])]),
                    Node::boolean(ASYNCHRONOUS_INDICATOR, false),
                ),
            )
            .unwrap();
        payload(&r);
        for wrong in [
            Node::enumeration(ASYNCHRONOUS_INDICATOR, 2),
            Node::int(ASYNCHRONOUS_INDICATOR, 1),
        ] {
            let request = header_field(req(v, vec![create_item.clone()]), wrong);
            let r = f.engine.process("alice", &request).unwrap();
            assert_eq!(message_rejection(v, &r), 7);
        }
        assert_eq!(f.engine.store.list("alice").unwrap().len(), 4);
        f.engine.store.verify_audit().unwrap();
    }
    // 2.x and the draft use the enumeration: a Boolean is invalid and Optional
    // runs a batch without key pair generation synchronously. Mandatory is
    // deferred (tests/asynchronous.rs, tests/asynchronous_v3.rs).
    for v in [Version(2, 0), Version(2, 1), Version(3, 0)] {
        let mut f = Fixture::new();
        f.engine.experimental_v3 = true;
        let query = || req(v, vec![(24, vec![])]);
        let r = f
            .engine
            .process(
                "alice",
                &header_field(query(), Node::boolean(ASYNCHRONOUS_INDICATOR, true)),
            )
            .unwrap();
        assert_eq!(message_rejection(v, &r), 7);
        let r = f
            .engine
            .process(
                "alice",
                &header_field(query(), Node::enumeration(ASYNCHRONOUS_INDICATOR, 2)),
            )
            .unwrap();
        assert!(
            r.required(BATCH_ITEM)
                .unwrap()
                .get(ASYNCHRONOUS_CORRELATION_VALUE)
                .is_none()
        );
        payload(&r);
        let r = f
            .engine
            .process(
                "alice",
                &header_field(query(), Node::enumeration(ASYNCHRONOUS_INDICATOR, 1)),
            )
            .unwrap();
        assert_eq!(statuses(&r), [2]);
    }
}

fn with_extension(mut request: Node, item: usize, extension: Node) -> Node {
    let Value::Structure(message) = &mut request.value else {
        unreachable!()
    };
    let Value::Structure(fields) = &mut message[item + 1].value else {
        unreachable!()
    };
    fields.push(extension);
    request
}
fn message_extension(vendor: &str, critical: bool) -> Node {
    Node::structure(
        MESSAGE_EXTENSION,
        vec![
            Node::text(VENDOR_IDENTIFICATION, vendor),
            Node::boolean(CRITICALITY_INDICATOR, critical),
            Node::structure(
                VENDOR_EXTENSION,
                vec![Node::text(0x540001, "opaque vendor data")],
            ),
        ],
    )
}

// REQ:576184b7409e523e an unknown Critical extension rejects the whole message and no item runs
#[test]
fn critical_message_extension_rejects_the_entire_message_before_any_item() {
    for v in Version::supported(true) {
        let expected = if v.0 >= 2 { 0x3c } else { 8 };
        for continuation in [None, Some(1), Some(2), Some(3)] {
            let mut f = Fixture::new();
            f.engine.experimental_v3 = true;
            let key = create(
                &mut f.engine,
                v,
                vec![
                    usage_limits(100, 1),
                    Node::date(ACTIVATION_DATE, keytend_kmip_server::store::now() - 1),
                ],
            );
            let mut items = vec![
                (1, vec![Node::enumeration(OBJECT_TYPE, 2), attrs(v, vec![])]),
                (10, vec![uid(&key)]),
            ];
            if v >= Version(1, 2) {
                items.push((
                    31,
                    vec![
                        uid(&key),
                        Node::structure(
                            CRYPTOGRAPHIC_PARAMETERS,
                            vec![
                                Node::enumeration(BLOCK_CIPHER_MODE, 9),
                                Node::boolean(RANDOM_IV, true),
                            ],
                        ),
                        Node::bytes(DATA, b"abc".to_vec()),
                    ],
                ));
            }
            items.push((18, vec![uid(&key)]));
            items.push((24, vec![]));
            let last = items.len() - 1;
            let mut request = with_extension(
                req(v, items),
                last,
                message_extension("keytend_kmip_server.unknown", true),
            );
            if let Some(continuation) = continuation {
                request = batch_option(request, continuation);
            }
            let before = serde_json::to_string(&f.engine.store.list("alice").unwrap()).unwrap();
            let audits = audit_rows(&f);
            let r = f.engine.process("alice", &request).unwrap();
            assert_eq!(
                critical_rejection(v, &r, &request),
                expected,
                "{}.{} {continuation:?}",
                v.0,
                v.1
            );
            // Certificate operation policy and another owner's or an absent
            // object do not change the answer, so nothing leaks before it.
            for (owner, allowed, target) in [
                ("bob", Some(&[24][..]), key.as_str()),
                ("bob", None, "absent"),
            ] {
                let other = with_extension(
                    req(v, vec![(10, vec![uid(target)]), (24, vec![])]),
                    1,
                    message_extension("acme", true),
                );
                let r = f.engine.process_authorized(owner, &other, allowed).unwrap();
                assert_eq!(critical_rejection(v, &r, &other), expected);
            }
            assert_eq!(audit_rows(&f), audits);
            assert_eq!(
                serde_json::to_string(&f.engine.store.list("alice").unwrap()).unwrap(),
                before
            );
            assert!(f.engine.store.list("bob").unwrap().is_empty());
            assert_eq!(remaining(&mut f.engine, v, &key), 100);
            f.engine.store.verify_audit().unwrap();
        }
    }
}

// REQ:d32cc43d1d172030 an extension lacking Vendor Identification, Criticality Indicator or Vendor Extension is malformed
// A well-formed Non-Critical extension is processed as if it were absent
// (1.x section 6.16, 2.x section 9.13: "MAY process the rest of the message").
#[test]
fn noncritical_or_undecidable_extensions_fail_only_their_item() {
    for v in Version::supported(true) {
        let mut f = Fixture::new();
        f.engine.experimental_v3 = true;
        let create_item = (1, vec![Node::enumeration(OBJECT_TYPE, 2), attrs(v, vec![])]);
        let body = || Node::structure(VENDOR_EXTENSION, vec![]);
        let vendor = || Node::text(VENDOR_IDENTIFICATION, "acme");
        let critical = |flag| Node::boolean(CRITICALITY_INDICATOR, flag);
        let ext = |fields| Node::structure(MESSAGE_EXTENSION, fields);
        // Not explicitly Critical but unparseable: the 1.x general errors
        // table fails the batch item with Invalid Message.
        let mut cases = vec![
            (
                vec![ext(vec![
                    vendor(),
                    Node::int(CRITICALITY_INDICATOR, 1),
                    body(),
                ])],
                4,
            ),
            (
                vec![ext(vec![
                    vendor(),
                    Node::enumeration(CRITICALITY_INDICATOR, 1),
                    body(),
                ])],
                4,
            ),
            (vec![ext(vec![vendor(), body()])], 4),
            (
                vec![ext(vec![
                    Node::bytes(VENDOR_IDENTIFICATION, b"acme".to_vec()),
                    critical(false),
                    body(),
                ])],
                4,
            ),
            (
                vec![ext(vec![
                    vendor(),
                    critical(false),
                    Node::text(VENDOR_EXTENSION, "x"),
                ])],
                4,
            ),
            (vec![ext(vec![critical(false), vendor(), body()])], 4),
            (
                vec![ext(vec![vendor(), critical(false), body(), body()])],
                4,
            ),
            (vec![Node::text(MESSAGE_EXTENSION, "acme")], 4),
            // A well-formed Non-Critical extension is ignored (0: the item
            // runs as if the extension were absent).
            (vec![message_extension("acme", false)], 0),
        ];
        if v.0 == 1 {
            // 1.x Request Batch Item tables do not let the field repeat.
            cases.push((
                vec![
                    message_extension("acme", false),
                    message_extension("acme", false),
                ],
                4,
            ));
            // 1.x places no character limit on the vendor.
            cases.push((vec![message_extension("acme corp", false)], 0));
        } else {
            // 2.0 table 358, 2.1 table 396 and draft table 506: "MAY be
            // repeated". 2.0+ limits the vendor to [A-Za-z0-9_.].
            cases.push((
                vec![
                    message_extension("acme", false),
                    message_extension("acme.two", false),
                ],
                0,
            ));
            cases.push((vec![message_extension("acme corp", false)], 4));
        }
        let mut objects = 0;
        for (extensions, expected) in cases {
            let mut request = batch_option(
                req(
                    v,
                    vec![create_item.clone(), (24, vec![]), create_item.clone()],
                ),
                1,
            );
            for extension in extensions {
                request = with_extension(request, 1, extension);
            }
            let r = f.engine.process("alice", &request).unwrap();
            if expected == 0 {
                assert_eq!(statuses(&r), [0, 0, 0], "{}.{}", v.0, v.1);
                let query = r.all(BATCH_ITEM).nth(1).unwrap();
                assert_eq!(query.required(OPERATION).unwrap().number().unwrap(), 24);
                assert!(query.get(RESPONSE_PAYLOAD).is_some());
                objects += 2;
                assert_eq!(f.engine.store.list("alice").unwrap().len(), objects);
                continue;
            }
            assert_eq!(statuses(&r), [0, 1, 0], "{}.{}", v.0, v.1);
            let refused = r.all(BATCH_ITEM).nth(1).unwrap();
            assert_eq!(refused.required(OPERATION).unwrap().number().unwrap(), 24);
            if v.0 < 3 {
                assert_eq!(
                    refused
                        .required(UNIQUE_BATCH_ITEM_ID)
                        .unwrap()
                        .byte_string()
                        .unwrap(),
                    [1]
                );
            }
            assert!(refused.get(RESPONSE_PAYLOAD).is_none());
            assert_eq!(
                refused.required(RESULT_REASON).unwrap().number().unwrap(),
                expected,
                "{}.{}",
                v.0,
                v.1
            );
            objects += 2;
            assert_eq!(f.engine.store.list("alice").unwrap().len(), objects);
        }
        f.engine.store.verify_audit().unwrap();
    }
}

#[test]
fn explicitly_critical_extensions_reject_the_message_even_if_malformed() {
    for v in Version::supported(true) {
        let expected = if v.0 >= 2 { 0x3c } else { 8 };
        let mut f = Fixture::new();
        f.engine.experimental_v3 = true;
        let create_item = (1, vec![Node::enumeration(OBJECT_TYPE, 2), attrs(v, vec![])]);
        let body = || Node::structure(VENDOR_EXTENSION, vec![]);
        let vendor = || Node::text(VENDOR_IDENTIFICATION, "acme");
        let critical = |flag| Node::boolean(CRITICALITY_INDICATOR, flag);
        let ext = |fields| Node::structure(MESSAGE_EXTENSION, fields);
        let cases = vec![
            // A malformed earlier item must not turn the message into a
            // per-item failure that lets the first item commit.
            vec![
                (1, ext(vec![vendor(), body()])),
                (2, message_extension("acme", true)),
            ],
            vec![(1, ext(vec![critical(true), vendor(), body()]))],
            vec![(1, ext(vec![vendor(), critical(true)]))],
            vec![(1, message_extension("acme corp", true))],
            vec![
                (1, message_extension("acme", false)),
                (1, message_extension("acme", true)),
            ],
        ];
        let audits = audit_rows(&f);
        for extensions in cases {
            let mut request = batch_option(
                req(
                    v,
                    vec![create_item.clone(), (24, vec![]), create_item.clone()],
                ),
                1,
            );
            for (item, extension) in extensions {
                request = with_extension(request, item, extension);
            }
            let r = f.engine.process("alice", &request).unwrap();
            assert_eq!(
                critical_rejection(v, &r, &request),
                expected,
                "{}.{}",
                v.0,
                v.1
            );
        }
        assert!(f.engine.store.list("alice").unwrap().is_empty());
        assert_eq!(audit_rows(&f), audits);
        f.engine.store.verify_audit().unwrap();
    }
}

#[test]
fn sensitive_and_non_extractable_are_enforced() {
    let mut f = Fixture::new();
    let v = Version(1, 4);
    for (tag, flag, expected) in [(SENSITIVE, true, 0x16), (EXTRACTABLE, false, 0x17)] {
        let id = create(&mut f.engine, v, vec![Node::boolean(tag, flag)]);
        assert_eq!(
            reason(&call(&mut f.engine, v, "alice", 10, vec![uid(&id)])),
            expected
        );
    }
}
#[test]
fn unsupported_operation_attribute_and_duplicate_rejected() {
    let mut f = Fixture::new();
    let v = Version(2, 1);
    // Interop (0x34) is a test-only control operation and is not implemented.
    assert_eq!(reason(&call(&mut f.engine, v, "alice", 0x34, vec![])), 5);
    assert_eq!(
        reason(&call(
            &mut f.engine,
            v,
            "alice",
            1,
            vec![
                Node::enumeration(OBJECT_TYPE, 2),
                attrs(
                    v,
                    vec![
                        Node::text(CONTACT_INFORMATION, "ok"),
                        Node::int(LEASE_TIME, 1)
                    ]
                )
            ]
        )),
        0x22
    );
    assert_eq!(
        reason(&call(
            &mut f.engine,
            v,
            "alice",
            1,
            vec![
                Node::enumeration(OBJECT_TYPE, 2),
                Node::enumeration(OBJECT_TYPE, 2)
            ]
        )),
        7
    );
}

#[test]
fn rekey_keeps_old_material_and_copies_activation_to_replacement() {
    let mut f = Fixture::new();
    let v = Version(2, 1);
    let old = create(&mut f.engine, v, vec![]);
    let before = f
        .engine
        .store
        .get("alice", &old)
        .unwrap()
        .unwrap()
        .material
        .clone();
    payload(&call(&mut f.engine, v, "alice", 18, vec![uid(&old)]));
    let r = call(&mut f.engine, v, "alice", 4, vec![uid(&old)]);
    let new = payload(&r)
        .get(UNIQUE_IDENTIFIER)
        .unwrap()
        .identifier_text()
        .unwrap();
    assert_ne!(new, old);
    let o = f.engine.store.get("alice", new).unwrap().unwrap();
    assert_eq!(o.state, 2);
    assert_eq!(o.material.len(), 32);
    assert_ne!(o.material, before);
    assert_eq!(
        f.engine.store.get("alice", &old).unwrap().unwrap().material,
        before
    );
}
#[test]
fn rsa_export_matches_its_key_format_and_signature_verification_checks_message() {
    let mut f = Fixture::new();
    let v = Version(2, 1);
    let r = call(
        &mut f.engine,
        v,
        "alice",
        2,
        vec![
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
        ],
    );
    let p = payload(&r);
    let private = p
        .get(PRIVATE_KEY_UNIQUE_IDENTIFIER)
        .unwrap()
        .identifier_text()
        .unwrap()
        .to_string();
    let public = p
        .get(PUBLIC_KEY_UNIQUE_IDENTIFIER)
        .unwrap()
        .identifier_text()
        .unwrap()
        .to_string();
    // The 2.x default is PKCS#1 (2.1 Table 81); PKCS#8 is available on request.
    for (requested, format) in [(None, 3), (Some(4), 4)] {
        let mut fields = vec![uid(&private)];
        fields.extend(requested.map(|f| Node::enumeration(KEY_FORMAT_TYPE, f)));
        let export = call(&mut f.engine, v, "alice", 10, fields);
        let block = payload(&export)
            .get(PRIVATE_KEY)
            .unwrap()
            .get(KEY_BLOCK)
            .unwrap();
        assert_eq!(
            block.get(KEY_FORMAT_TYPE).unwrap().number().unwrap(),
            format
        );
        let bytes = block
            .get(KEY_VALUE)
            .unwrap()
            .get(KEY_MATERIAL)
            .unwrap()
            .byte_string()
            .unwrap();
        if format == 4 {
            openssl::pkey::PKey::private_key_from_pkcs8(bytes)
                .expect("advertised PKCS8 must really be PKCS8");
        } else {
            openssl::rsa::Rsa::private_key_from_der(bytes)
                .expect("advertised PKCS1 must really be PKCS1");
            assert!(openssl::pkey::PKey::private_key_from_pkcs8(bytes).is_err());
        }
    }
    for id in [&private, &public] {
        payload(&call(&mut f.engine, v, "alice", 18, vec![uid(id)]));
    }
    let cp = Node::structure(
        CRYPTOGRAPHIC_PARAMETERS,
        vec![
            Node::enumeration(HASHING_ALGORITHM, 6),
            Node::enumeration(PADDING_METHOD, 8),
            Node::enumeration(CRYPTOGRAPHIC_ALGORITHM, 4),
        ],
    );
    let signature = call(
        &mut f.engine,
        v,
        "alice",
        33,
        vec![
            uid(&private),
            cp.clone(),
            Node::bytes(DATA, b"signed data".to_vec()),
        ],
    );
    let sig = payload(&signature).get(SIGNATURE_DATA).unwrap().clone();
    for (data, expected) in [(b"signed data".to_vec(), 1), (b"changed data".to_vec(), 2)] {
        let r = call(
            &mut f.engine,
            v,
            "alice",
            34,
            vec![
                uid(&public),
                cp.clone(),
                Node::bytes(DATA, data),
                sig.clone(),
            ],
        );
        assert_eq!(
            payload(&r)
                .get(VALIDITY_INDICATOR)
                .unwrap()
                .number()
                .unwrap(),
            expected
        );
    }
}
#[test]
fn hash_and_hmac_match_published_vectors() {
    let mut f = Fixture::new();
    let v = Version(1, 4);
    let h = call(
        &mut f.engine,
        v,
        "alice",
        39,
        vec![
            Node::structure(
                CRYPTOGRAPHIC_PARAMETERS,
                vec![Node::enumeration(HASHING_ALGORITHM, 6)],
            ),
            Node::bytes(DATA, b"abc".to_vec()),
        ],
    );
    assert_eq!(
        hex::encode(payload(&h).get(DATA).unwrap().byte_string().unwrap()),
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
    // RFC 4231 section 4.2, HMAC-SHA-256 test case 1.
    let attrs = container(
        v,
        vec![
            Node::enumeration(CRYPTOGRAPHIC_ALGORITHM, 9),
            Node::int(CRYPTOGRAPHIC_USAGE_MASK, 0x180),
        ],
    );
    let object = Node::structure(
        SYMMETRIC_KEY,
        vec![Node::structure(
            KEY_BLOCK,
            vec![
                Node::enumeration(KEY_FORMAT_TYPE, 1),
                Node::structure(KEY_VALUE, vec![Node::bytes(KEY_MATERIAL, vec![0x0b; 20])]),
                Node::enumeration(CRYPTOGRAPHIC_ALGORITHM, 9),
                Node::int(CRYPTOGRAPHIC_LENGTH, 160),
            ],
        )],
    );
    let registered = call(
        &mut f.engine,
        v,
        "alice",
        3,
        vec![Node::enumeration(OBJECT_TYPE, 2), attrs, object],
    );
    let id = payload(&registered)
        .get(UNIQUE_IDENTIFIER)
        .unwrap()
        .identifier_text()
        .unwrap();
    payload(&call(&mut f.engine, v, "alice", 18, vec![uid(id)]));
    let mac = call(
        &mut f.engine,
        v,
        "alice",
        35,
        vec![uid(id), Node::bytes(DATA, b"Hi There".to_vec())],
    );
    let expected =
        hex::decode("b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7").unwrap();
    assert_eq!(
        payload(&mac).get(MAC_DATA).unwrap().byte_string().unwrap(),
        expected
    );
    let r = call(
        &mut f.engine,
        v,
        "alice",
        36,
        vec![
            uid(id),
            Node::bytes(DATA, b"Hi There".to_vec()),
            Node::bytes(MAC_DATA, expected),
        ],
    );
    assert_eq!(
        payload(&r)
            .get(VALIDITY_INDICATOR)
            .unwrap()
            .number()
            .unwrap(),
        1
    );
}
#[test]
fn metadata_edits_and_backup_restore_preserve_identity() {
    let mut f = Fixture::new();
    let v = Version(2, 1);
    let id = create(&mut f.engine, v, vec![]);
    let name = Node::structure(
        NAME,
        vec![
            Node::text(NAME_VALUE, "initial"),
            Node::enumeration(NAME_TYPE, 1),
        ],
    );
    payload(&call(
        &mut f.engine,
        v,
        "alice",
        13,
        vec![uid(&id), Node::structure(NEW_ATTRIBUTE, vec![name])],
    ));
    let list = call(&mut f.engine, v, "alice", 12, vec![uid(&id)]);
    assert!(
        payload(&list)
            .all(ATTRIBUTE_REFERENCE)
            .any(|n| n.number().unwrap() == NAME)
    );
    payload(&call(
        &mut f.engine,
        v,
        "alice",
        49,
        vec![
            uid(&id),
            Node::structure(NEW_ATTRIBUTE, vec![Node::text(OBJECT_GROUP, "databases")]),
        ],
    ));
    payload(&call(
        &mut f.engine,
        v,
        "alice",
        15,
        vec![uid(&id), Node::enumeration(ATTRIBUTE_REFERENCE, NAME)],
    ));
    let path = f._dir.path().join("backup.sqlite");
    f.engine.store.backup(&path).unwrap();
    assert!(f.engine.store.backup(&path).is_err());
    let restore = Store::open(&path, &f._dir.path().join("master")).unwrap();
    let o = restore.get("alice", &id).unwrap().unwrap();
    assert!(o.attrs.iter().any(|n| n.tag == OBJECT_GROUP));
    assert!(!o.attrs.iter().any(|n| n.tag == NAME));
    restore.verify_audit().unwrap();
}
#[test]
fn hashing_enumerations_match_the_official_registry() {
    let registry: serde_json::Value =
        serde_json::from_str(include_str!("../docs/specs/registry.json")).unwrap();
    assert_eq!(
        registry["enums"]["HashingAlgorithm"]["SHA256"],
        keytend_kmip_server::codes::hash::SHA256
    );
    assert_eq!(
        registry["enums"]["HashingAlgorithm"]["SHA384"],
        keytend_kmip_server::codes::hash::SHA384
    );
    assert_eq!(
        registry["enums"]["HashingAlgorithm"]["SHA512"],
        keytend_kmip_server::codes::hash::SHA512
    );
}
#[test]
fn dates_and_digest_are_enforced_across_key_destruction() {
    let mut f = Fixture::new();
    let v = Version(2, 1);
    let time = keytend_kmip_server::store::now();
    let id = create(
        &mut f.engine,
        v,
        vec![
            Node::date(ACTIVATION_DATE, time - 60),
            Node::date(PROTECT_STOP_DATE, time - 1),
        ],
    );
    assert_eq!(f.engine.store.get("alice", &id).unwrap().unwrap().state, 2);
    let cp = Node::structure(
        CRYPTOGRAPHIC_PARAMETERS,
        vec![
            Node::enumeration(BLOCK_CIPHER_MODE, 9),
            Node::boolean(RANDOM_IV, true),
        ],
    );
    assert_eq!(
        reason(&call(
            &mut f.engine,
            v,
            "alice",
            31,
            vec![uid(&id), cp, Node::bytes(DATA, vec![1])]
        )),
        // Outside the date window: Wrong Key Lifecycle State from 2.1.
        0x43
    );
    let before = call(
        &mut f.engine,
        v,
        "alice",
        11,
        vec![uid(&id), Node::enumeration(ATTRIBUTE_REFERENCE, DIGEST)],
    );
    let digest = payload(&before)
        .get(ATTRIBUTES)
        .unwrap()
        .get(DIGEST)
        .unwrap()
        .clone();
    assert_eq!(digest.get(HASHING_ALGORITHM).unwrap().number().unwrap(), 6);
    payload(&call(
        &mut f.engine,
        v,
        "alice",
        19,
        vec![
            uid(&id),
            Node::structure(
                REVOCATION_REASON,
                vec![Node::enumeration(REVOCATION_REASON_CODE, 2)],
            ),
            Node::date(COMPROMISE_OCCURRENCE_DATE, time - 10),
        ],
    ));
    payload(&call(&mut f.engine, v, "alice", 20, vec![uid(&id)]));
    let after = call(
        &mut f.engine,
        v,
        "alice",
        11,
        vec![uid(&id), Node::enumeration(ATTRIBUTE_REFERENCE, DIGEST)],
    );
    assert!(
        payload(&after)
            .get(ATTRIBUTES)
            .unwrap()
            .get(DIGEST)
            .unwrap()
            == &digest
    );
}

fn active_rsa_pair(e: &mut Engine, v: Version, extra: Vec<Node>) -> (String, String) {
    let mut attributes = vec![
        Node::enumeration(CRYPTOGRAPHIC_ALGORITHM, 4),
        Node::int(CRYPTOGRAPHIC_LENGTH, 2048),
        Node::int(CRYPTOGRAPHIC_USAGE_MASK, 15),
    ];
    attributes.extend(extra);
    let mut common = container(v, attributes);
    common.tag = if v.0 >= 2 {
        COMMON_ATTRIBUTES
    } else {
        COMMON_TEMPLATE_ATTRIBUTE
    };
    let r = call(e, v, "alice", 2, vec![common]);
    let p = payload(&r);
    let private = p
        .required(PRIVATE_KEY_UNIQUE_IDENTIFIER)
        .unwrap()
        .identifier_text()
        .unwrap()
        .to_owned();
    let public = p
        .required(PUBLIC_KEY_UNIQUE_IDENTIFIER)
        .unwrap()
        .identifier_text()
        .unwrap()
        .to_owned();
    for id in [&private, &public] {
        payload(&call(e, v, "alice", 18, vec![uid(id)]));
    }
    (private, public)
}
fn rsa_public_bytes(e: &mut Engine, v: Version, id: &str) -> Vec<u8> {
    let r = call(e, v, "alice", 10, vec![uid(id)]);
    payload(&r)
        .required(PUBLIC_KEY)
        .unwrap()
        .required(KEY_BLOCK)
        .unwrap()
        .required(KEY_VALUE)
        .unwrap()
        .required(KEY_MATERIAL)
        .unwrap()
        .byte_string()
        .unwrap()
        .to_vec()
}
/// RSA public keys are X.509 SubjectPublicKeyInfo (1.x default) or PKCS#1
/// (the 2.0+ default, KMIP 2.1 Table 81).
fn rsa_public_key(der: &[u8]) -> openssl::pkey::PKey<openssl::pkey::Public> {
    openssl::pkey::PKey::public_key_from_der(der)
        .or_else(|_| {
            openssl::rsa::Rsa::public_key_from_der_pkcs1(der)
                .and_then(openssl::pkey::PKey::from_rsa)
        })
        .unwrap()
}
fn crypto_versions() -> [Version; 6] {
    [
        Version(1, 2),
        Version(1, 3),
        Version(1, 4),
        Version(2, 0),
        Version(2, 1),
        Version(3, 0),
    ]
}
#[test]
fn rsa_oaep_stored_parameters_boundaries_and_uniform_decryption_failure() {
    for v in crypto_versions() {
        let mut f = Fixture::new();
        f.engine.experimental_v3 = true;
        let mut fields = vec![
            Node::enumeration(PADDING_METHOD, 2),
            Node::enumeration(HASHING_ALGORITHM, 6),
        ];
        if v >= Version(1, 4) {
            fields.extend([
                Node::enumeration(MASK_GENERATOR_HASHING_ALGORITHM, 7),
                Node::bytes(P_SOURCE, b"database-a".to_vec()),
            ]);
        }
        let cp = Node::structure(CRYPTOGRAPHIC_PARAMETERS, fields.clone());
        let (private, public) = active_rsa_pair(&mut f.engine, v, vec![cp.clone()]);
        for message in [vec![], b"database key".to_vec(), vec![42; 190]] {
            let r = call(
                &mut f.engine,
                v,
                "alice",
                31,
                vec![uid(&public), Node::bytes(DATA, message.clone())],
            );
            let p = payload(&r);
            let ciphertext = p.required(DATA).unwrap().byte_string().unwrap().to_vec();
            assert_eq!(ciphertext.len(), 256);
            assert!(
                p.get(IV_COUNTER_NONCE).is_none() && p.get(AUTHENTICATED_ENCRYPTION_TAG).is_none()
            );
            let r = call(
                &mut f.engine,
                v,
                "alice",
                32,
                vec![uid(&private), Node::bytes(DATA, ciphertext.clone())],
            );
            assert_eq!(
                payload(&r).required(DATA).unwrap().byte_string().unwrap(),
                message
            );
            let mut wrong = fields.clone();
            wrong.retain(|n| n.tag != HASHING_ALGORITHM);
            wrong.push(Node::enumeration(HASHING_ALGORITHM, 7));
            let r = call(
                &mut f.engine,
                v,
                "alice",
                32,
                vec![
                    uid(&private),
                    Node::structure(CRYPTOGRAPHIC_PARAMETERS, wrong),
                    Node::bytes(DATA, ciphertext.clone()),
                ],
            );
            assert_eq!(reason(&r), 10);
            assert!(r.get(BATCH_ITEM).unwrap().get(RESPONSE_PAYLOAD).is_none());
            if v >= Version(1, 4) {
                let mut wrong_label = fields.clone();
                wrong_label.retain(|n| n.tag != P_SOURCE);
                wrong_label.push(Node::bytes(P_SOURCE, b"other-database".to_vec()));
                let r = call(
                    &mut f.engine,
                    v,
                    "alice",
                    32,
                    vec![
                        uid(&private),
                        Node::structure(CRYPTOGRAPHIC_PARAMETERS, wrong_label),
                        Node::bytes(DATA, ciphertext.clone()),
                    ],
                );
                assert_eq!(reason(&r), 10);
                assert!(r.get(BATCH_ITEM).unwrap().get(RESPONSE_PAYLOAD).is_none());
            }
            for bad in [vec![], vec![0; 255], vec![0; 256], vec![255; 256]] {
                let r = call(
                    &mut f.engine,
                    v,
                    "alice",
                    32,
                    vec![uid(&private), Node::bytes(DATA, bad)],
                );
                assert_eq!(reason(&r), 10);
                assert!(r.get(BATCH_ITEM).unwrap().get(RESPONSE_PAYLOAD).is_none());
            }
        }
        for extra in [
            Node::bytes(IV_COUNTER_NONCE, vec![0; 16]),
            Node::bytes(AUTHENTICATED_ENCRYPTION_ADDITIONAL_DATA, vec![]),
        ] {
            assert_eq!(
                reason(&call(
                    &mut f.engine,
                    v,
                    "alice",
                    31,
                    vec![uid(&public), Node::bytes(DATA, vec![0]), extra]
                )),
                7
            );
        }
        assert_eq!(
            reason(&call(
                &mut f.engine,
                v,
                "alice",
                31,
                vec![uid(&public), Node::bytes(DATA, vec![0; 191])]
            )),
            7
        );
        assert_eq!(
            reason(&call(
                &mut f.engine,
                v,
                "alice",
                31,
                vec![uid(&private), Node::bytes(DATA, vec![0])]
            )),
            8
        );
        assert_eq!(
            reason(&call(
                &mut f.engine,
                v,
                "alice",
                32,
                vec![uid(&public), Node::bytes(DATA, vec![0; 256])]
            )),
            8
        );
        let r = call(
            &mut f.engine,
            v,
            "alice",
            31,
            vec![
                uid(&public),
                Node::structure(CRYPTOGRAPHIC_PARAMETERS, vec![]),
                Node::bytes(DATA, vec![0]),
            ],
        );
        assert_eq!(reason(&r), if v.0 >= 2 { 7 } else { 6 }); // explicit parameters replace stored defaults
    }
}
#[test]
fn rsa_combined_algorithms_pss_defaults_and_prehashed_signatures_across_versions() {
    use openssl::{
        rsa::Padding,
        sign::{RsaPssSaltlen, Verifier},
    };
    for v in crypto_versions() {
        let mut f = Fixture::new();
        f.engine.experimental_v3 = true;
        let (private, public) = active_rsa_pair(&mut f.engine, v, vec![]);
        let public_key = rsa_public_key(&rsa_public_bytes(&mut f.engine, v, &public));
        for (algorithm, hash, pss) in [
            (4, 5, false),
            (5, 6, false),
            (6, 7, false),
            (7, 8, false),
            (8, 6, true),
        ] {
            let mut fields = vec![Node::enumeration(DIGITAL_SIGNATURE_ALGORITHM, algorithm)];
            if pss {
                fields.push(Node::enumeration(HASHING_ALGORITHM, hash));
            }
            let cp = Node::structure(CRYPTOGRAPHIC_PARAMETERS, fields);
            let message = b"RSA requirement verification";
            let r = call(
                &mut f.engine,
                v,
                "alice",
                33,
                vec![
                    uid(&private),
                    cp.clone(),
                    Node::bytes(DATA, message.to_vec()),
                ],
            );
            let signature = payload(&r)
                .required(SIGNATURE_DATA)
                .unwrap()
                .byte_string()
                .unwrap()
                .to_vec();
            let md = keytend_kmip_server::crypto::rsa::digest(hash).unwrap();
            let mut verifier = Verifier::new(md, &public_key).unwrap();
            if pss {
                // REQ: docs/interpretations.md (PSS in 1.3): 1.3 uses MGF1 with
                // the message hash and the maximum salt; 1.4+ and 1.0-1.2
                // keep MGF1-SHA-1 with their salt defaults.
                let maximum = public_key.rsa().unwrap().size() as i32 - md.size() as i32 - 2;
                verifier.set_rsa_padding(Padding::PKCS1_PSS).unwrap();
                verifier
                    .set_rsa_mgf1_md(if v == Version(1, 3) {
                        md
                    } else {
                        openssl::hash::MessageDigest::sha1()
                    })
                    .unwrap();
                verifier
                    .set_rsa_pss_saltlen(RsaPssSaltlen::custom(match v {
                        _ if v >= Version(1, 4) => 64,
                        _ if v == Version(1, 3) => maximum,
                        _ => 20,
                    }))
                    .unwrap();
            }
            verifier.update(message).unwrap();
            assert!(verifier.verify(&signature).unwrap());
            for (data, sig, expected) in [
                (message.to_vec(), signature.clone(), 1),
                (b"changed".to_vec(), signature.clone(), 2),
                (message.to_vec(), vec![], 2),
                (message.to_vec(), vec![0; 256], 2),
            ] {
                let r = call(
                    &mut f.engine,
                    v,
                    "alice",
                    34,
                    vec![
                        uid(&public),
                        cp.clone(),
                        Node::bytes(DATA, data),
                        Node::bytes(SIGNATURE_DATA, sig),
                    ],
                );
                assert_eq!(
                    payload(&r)
                        .required(VALIDITY_INDICATOR)
                        .unwrap()
                        .number()
                        .unwrap(),
                    expected
                );
            }
            if v >= Version(1, 4) {
                let digest = openssl::hash::hash(md, message).unwrap().to_vec();
                let r = call(
                    &mut f.engine,
                    v,
                    "alice",
                    33,
                    vec![
                        uid(&private),
                        cp.clone(),
                        Node::bytes(DIGESTED_DATA, digest.clone()),
                    ],
                );
                let prehashed_signature = payload(&r).required(SIGNATURE_DATA).unwrap().clone();
                if !pss {
                    assert_eq!(prehashed_signature.byte_string().unwrap(), signature);
                }
                let r = call(
                    &mut f.engine,
                    v,
                    "alice",
                    34,
                    vec![
                        uid(&public),
                        cp.clone(),
                        Node::bytes(DIGESTED_DATA, digest),
                        prehashed_signature,
                    ],
                );
                assert_eq!(
                    payload(&r)
                        .required(VALIDITY_INDICATOR)
                        .unwrap()
                        .number()
                        .unwrap(),
                    1
                );
            }
        }
        let r = call(
            &mut f.engine,
            v,
            "alice",
            33,
            vec![uid(&private), Node::bytes(DATA, vec![0])],
        );
        assert_eq!(reason(&r), if v.0 >= 2 { 7 } else { 6 });
        if v >= Version(3, 0) {
            let cp = Node::structure(
                CRYPTOGRAPHIC_PARAMETERS,
                vec![Node::enumeration(PADDING_METHOD, 10)],
            );
            let r = call(
                &mut f.engine,
                v,
                "alice",
                33,
                vec![
                    uid(&private),
                    cp,
                    Node::bytes(DATA, b"draft default".to_vec()),
                ],
            );
            let sig = payload(&r)
                .required(SIGNATURE_DATA)
                .unwrap()
                .byte_string()
                .unwrap();
            let mut verifier =
                Verifier::new(openssl::hash::MessageDigest::sha1(), &public_key).unwrap();
            verifier.set_rsa_padding(Padding::PKCS1_PSS).unwrap();
            verifier
                .set_rsa_mgf1_md(openssl::hash::MessageDigest::sha1())
                .unwrap();
            verifier
                .set_rsa_pss_saltlen(RsaPssSaltlen::custom(64))
                .unwrap();
            verifier.update(b"draft default").unwrap();
            assert!(verifier.verify(sig).unwrap());
        }
        let cp = Node::structure(
            CRYPTOGRAPHIC_PARAMETERS,
            vec![Node::enumeration(HASHING_ALGORITHM, 6)],
        );
        if v < Version(1, 4) {
            assert_eq!(
                reason(&call(
                    &mut f.engine,
                    v,
                    "alice",
                    33,
                    vec![uid(&private), cp, Node::bytes(DIGESTED_DATA, vec![0; 32])]
                )),
                7
            );
        }
    }
}
#[test]
fn rsa_parameter_rejections_preserve_budget_and_pss_salt_byte_lengths() {
    let mut f = Fixture::new();
    let v = Version(2, 1);
    let (private, public) = active_rsa_pair(&mut f.engine, v, vec![usage_limits(64, 1)]);
    let message = vec![9; 32];
    for parameter in [
        Node::enumeration(MASK_GENERATOR, 2),
        Node::enumeration(MASK_GENERATOR_HASHING_ALGORITHM, 999),
        Node::int(TRAILER_FIELD, 188),
    ] {
        let cp = Node::structure(
            CRYPTOGRAPHIC_PARAMETERS,
            vec![
                Node::enumeration(PADDING_METHOD, 10),
                Node::enumeration(HASHING_ALGORITHM, 6),
                parameter,
            ],
        );
        let r = call(
            &mut f.engine,
            v,
            "alice",
            33,
            vec![uid(&private), cp, Node::bytes(DATA, message.clone())],
        );
        assert_eq!(reason(&r), 0x3e);
        assert_eq!(remaining(&mut f.engine, v, &private), 64);
    }
    for fields in [
        vec![
            Node::enumeration(DIGITAL_SIGNATURE_ALGORITHM, 5),
            Node::enumeration(HASHING_ALGORITHM, 7),
        ],
        vec![
            Node::enumeration(DIGITAL_SIGNATURE_ALGORITHM, 5),
            Node::enumeration(PADDING_METHOD, 10),
        ],
        vec![
            Node::enumeration(PADDING_METHOD, 10),
            Node::enumeration(HASHING_ALGORITHM, 6),
            Node::int(SALT_LENGTH, 223),
        ],
        vec![
            Node::enumeration(PADDING_METHOD, 10),
            Node::enumeration(HASHING_ALGORITHM, 6),
            Node::int(SALT_LENGTH, -1),
        ],
        vec![
            Node::enumeration(PADDING_METHOD, 8),
            Node::enumeration(HASHING_ALGORITHM, 6),
            Node::int(SALT_LENGTH, 32),
        ],
    ] {
        let r = call(
            &mut f.engine,
            v,
            "alice",
            33,
            vec![
                uid(&private),
                Node::structure(CRYPTOGRAPHIC_PARAMETERS, fields),
                Node::bytes(DATA, message.clone()),
            ],
        );
        assert_eq!(reason(&r), 7);
        assert_eq!(remaining(&mut f.engine, v, &private), 64);
    }
    let cp = Node::structure(
        CRYPTOGRAPHIC_PARAMETERS,
        vec![
            Node::enumeration(PADDING_METHOD, 10),
            Node::enumeration(HASHING_ALGORITHM, 6),
            Node::int(SALT_LENGTH, 222),
            Node::int(TRAILER_FIELD, 1),
        ],
    );
    for bad in [
        vec![Node::bytes(DIGESTED_DATA, vec![0; 31])],
        vec![
            Node::bytes(DIGESTED_DATA, vec![0; 32]),
            Node::bytes(DATA, message.clone()),
        ],
    ] {
        let mut p = vec![uid(&private), cp.clone()];
        p.extend(bad);
        assert_eq!(reason(&call(&mut f.engine, v, "alice", 33, p)), 7);
        assert_eq!(remaining(&mut f.engine, v, &private), 64);
    }
    for _ in 0..2 {
        let r = call(
            &mut f.engine,
            v,
            "alice",
            33,
            vec![
                uid(&private),
                cp.clone(),
                Node::bytes(DATA, message.clone()),
            ],
        );
        let sig = payload(&r).required(SIGNATURE_DATA).unwrap().clone();
        let r = call(
            &mut f.engine,
            v,
            "alice",
            34,
            vec![
                uid(&public),
                cp.clone(),
                Node::bytes(DATA, message.clone()),
                sig,
            ],
        );
        assert_eq!(
            payload(&r)
                .required(VALIDITY_INDICATOR)
                .unwrap()
                .number()
                .unwrap(),
            1
        );
    }
    assert_eq!(remaining(&mut f.engine, v, &private), 0);
    assert_eq!(remaining(&mut f.engine, v, &public), 64);
    assert_eq!(
        reason(&call(
            &mut f.engine,
            v,
            "alice",
            33,
            vec![uid(&private), cp, Node::bytes(DATA, message.clone())]
        )),
        12
    );
    let oaep = Node::structure(
        CRYPTOGRAPHIC_PARAMETERS,
        vec![
            Node::enumeration(PADDING_METHOD, 2),
            Node::enumeration(HASHING_ALGORITHM, 6),
        ],
    );
    for _ in 0..2 {
        let r = call(
            &mut f.engine,
            v,
            "alice",
            31,
            vec![
                uid(&public),
                oaep.clone(),
                Node::bytes(DATA, message.clone()),
            ],
        );
        let ciphertext = payload(&r).required(DATA).unwrap().clone();
        let r = call(
            &mut f.engine,
            v,
            "alice",
            32,
            vec![uid(&private), oaep.clone(), ciphertext],
        );
        assert_eq!(
            payload(&r).required(DATA).unwrap().byte_string().unwrap(),
            message
        );
    }
    assert_eq!(remaining(&mut f.engine, v, &public), 0); // decrypt still allowed after exhaustion
    assert_eq!(
        reason(&call(
            &mut f.engine,
            v,
            "alice",
            31,
            vec![uid(&public), oaep, Node::bytes(DATA, message)]
        )),
        12
    );
}

#[test]
fn rsa_pkcs1_import_and_conversion_preserve_material_for_every_version() {
    let key = openssl::rsa::Rsa::generate(2048).unwrap();
    let private = key.private_key_to_der().unwrap();
    let public = key.public_key_to_der_pkcs1().unwrap();
    for v in [
        Version(1, 0),
        Version(1, 1),
        Version(1, 2),
        Version(1, 3),
        Version(1, 4),
        Version(2, 0),
        Version(2, 1),
        Version(3, 0),
    ] {
        let mut f = Fixture::new();
        f.engine.experimental_v3 = true;
        let mut ids = vec![];
        for (kind, object, bytes, converted) in
            [(4, PRIVATE_KEY, &private, 4), (3, PUBLIC_KEY, &public, 5)]
        {
            let r = call(
                &mut f.engine,
                v,
                "alice",
                3,
                vec![
                    Node::enumeration(OBJECT_TYPE, kind),
                    container(
                        v,
                        vec![
                            Node::enumeration(CRYPTOGRAPHIC_ALGORITHM, 4),
                            Node::int(CRYPTOGRAPHIC_LENGTH, 2048),
                            Node::int(CRYPTOGRAPHIC_USAGE_MASK, 15),
                        ],
                    ),
                    Node::structure(
                        object,
                        vec![Node::structure(
                            KEY_BLOCK,
                            vec![
                                Node::enumeration(KEY_FORMAT_TYPE, 3),
                                Node::structure(
                                    KEY_VALUE,
                                    vec![Node::bytes(KEY_MATERIAL, bytes.clone())],
                                ),
                                Node::enumeration(CRYPTOGRAPHIC_ALGORITHM, 4),
                                Node::int(CRYPTOGRAPHIC_LENGTH, 2048),
                            ],
                        )],
                    ),
                ],
            );
            let id = payload(&r)
                .required(UNIQUE_IDENTIFIER)
                .unwrap()
                .identifier_text()
                .unwrap()
                .to_owned();
            let export = call(&mut f.engine, v, "alice", 10, vec![uid(&id)]);
            let kb = payload(&export)
                .required(object)
                .unwrap()
                .required(KEY_BLOCK)
                .unwrap();
            assert_eq!(kb.required(KEY_FORMAT_TYPE).unwrap().number().unwrap(), 3);
            assert_eq!(
                kb.required(KEY_VALUE)
                    .unwrap()
                    .required(KEY_MATERIAL)
                    .unwrap()
                    .byte_string()
                    .unwrap(),
                bytes
            );
            let export = call(
                &mut f.engine,
                v,
                "alice",
                10,
                vec![uid(&id), Node::enumeration(KEY_FORMAT_TYPE, converted)],
            );
            let data = payload(&export)
                .required(object)
                .unwrap()
                .required(KEY_BLOCK)
                .unwrap()
                .required(KEY_VALUE)
                .unwrap()
                .required(KEY_MATERIAL)
                .unwrap()
                .byte_string()
                .unwrap();
            let n = if kind == 4 {
                openssl::pkey::PKey::private_key_from_pkcs8(data)
                    .unwrap()
                    .rsa()
                    .unwrap()
                    .n()
                    .to_vec()
            } else {
                openssl::pkey::PKey::public_key_from_der(data)
                    .unwrap()
                    .rsa()
                    .unwrap()
                    .n()
                    .to_vec()
            };
            assert_eq!(n, key.n().to_vec());
            payload(&call(&mut f.engine, v, "alice", 18, vec![uid(&id)]));
            ids.push(id);
        }
        if v >= Version(1, 2) {
            let cp = Node::structure(
                CRYPTOGRAPHIC_PARAMETERS,
                vec![Node::enumeration(HASHING_ALGORITHM, 6)],
            );
            let r = call(
                &mut f.engine,
                v,
                "alice",
                33,
                vec![
                    uid(&ids[0]),
                    cp.clone(),
                    Node::bytes(DATA, b"imported key".to_vec()),
                ],
            );
            let sig = payload(&r).required(SIGNATURE_DATA).unwrap().clone();
            let r = call(
                &mut f.engine,
                v,
                "alice",
                34,
                vec![
                    uid(&ids[1]),
                    cp,
                    Node::bytes(DATA, b"imported key".to_vec()),
                    sig,
                ],
            );
            assert_eq!(
                payload(&r)
                    .required(VALIDITY_INDICATOR)
                    .unwrap()
                    .number()
                    .unwrap(),
                1
            );
        }
    }
}

fn vendor_attribute(vendor: &str, name: &str, value: Node) -> Node {
    let mut value = value;
    value.tag = ATTRIBUTE_VALUE;
    Node::structure(
        ATTRIBUTE,
        vec![
            Node::text(VENDOR_IDENTIFICATION, vendor),
            Node::text(ATTRIBUTE_NAME, name),
            value,
        ],
    )
}
fn legacy_attribute(name: &str, value: Node, index: Option<i32>) -> Node {
    let mut value = value;
    value.tag = ATTRIBUTE_VALUE;
    let mut fields = vec![Node::text(ATTRIBUTE_NAME, name)];
    if let Some(index) = index {
        fields.push(Node::int(ATTRIBUTE_INDEX, index));
    }
    fields.push(value);
    Node::structure(ATTRIBUTE, fields)
}
fn legacy_values(e: &mut Engine, v: Version, id: &str, name: &str) -> Vec<(i32, Node)> {
    let r = call(
        e,
        v,
        "alice",
        11,
        vec![uid(id), Node::text(ATTRIBUTE_NAME, name)],
    );
    payload(&r)
        .all(ATTRIBUTE)
        .map(|a| {
            (
                a.get(ATTRIBUTE_INDEX)
                    .map_or(0, |n| n.number().unwrap() as i32),
                a.required(ATTRIBUTE_VALUE).unwrap().clone(),
            )
        })
        .collect()
}
#[test]
fn legacy_custom_attributes_keep_indices_and_cross_version_identity_after_restart() {
    for v in [
        Version(1, 0),
        Version(1, 1),
        Version(1, 2),
        Version(1, 3),
        Version(1, 4),
    ] {
        let mut f = Fixture::new();
        let custom = vendor_attribute("x", "ID", Node::text(ATTRIBUTE_VALUE, "first"));
        let id = create(&mut f.engine, v, vec![]);
        payload(&call(
            &mut f.engine,
            v,
            "alice",
            13,
            vec![
                uid(&id),
                legacy_attribute("x-ID", Node::text(ATTRIBUTE_VALUE, "first"), None),
            ],
        ));
        let r = call(
            &mut f.engine,
            v,
            "alice",
            13,
            vec![
                uid(&id),
                legacy_attribute("x-ID", Node::text(ATTRIBUTE_VALUE, "second"), None),
            ],
        );
        assert_eq!(
            payload(&r)
                .required(ATTRIBUTE)
                .unwrap()
                .required(ATTRIBUTE_INDEX)
                .unwrap()
                .number()
                .unwrap(),
            1
        );
        let r = call(
            &mut f.engine,
            v,
            "alice",
            13,
            vec![
                uid(&id),
                legacy_attribute("x-other", Node::int(ATTRIBUTE_VALUE, 99), None),
            ],
        );
        assert_eq!(
            payload(&r)
                .required(ATTRIBUTE)
                .unwrap()
                .required(ATTRIBUTE_INDEX)
                .unwrap()
                .number()
                .unwrap(),
            0
        );
        let listed = call(&mut f.engine, v, "alice", 12, vec![uid(&id)]);
        assert_eq!(
            payload(&listed)
                .all(ATTRIBUTE_NAME)
                .filter(|n| n.string().unwrap() == "x-ID")
                .count(),
            1
        );
        assert!(
            payload(&listed)
                .all(ATTRIBUTE_NAME)
                .any(|n| n.string().unwrap() == "x-other")
        );
        let reference = Node::structure(
            ATTRIBUTE_REFERENCE,
            vec![
                Node::text(VENDOR_IDENTIFICATION, "x"),
                Node::text(ATTRIBUTE_NAME, "ID"),
            ],
        );
        let r = call(
            &mut f.engine,
            Version(2, 1),
            "alice",
            11,
            vec![uid(&id), reference.clone()],
        );
        assert_eq!(
            payload(&r)
                .required(ATTRIBUTES)
                .unwrap()
                .all(ATTRIBUTE)
                .count(),
            2
        );
        let located = call(
            &mut f.engine,
            v,
            "alice",
            8,
            vec![legacy_attribute(
                "x-ID",
                Node::text(ATTRIBUTE_VALUE, "first"),
                None,
            )],
        );
        assert_eq!(
            payload(&located)
                .required(UNIQUE_IDENTIFIER)
                .unwrap()
                .identifier_text()
                .unwrap(),
            id
        );
        // No index means index 0 in every edition.
        let delete = vec![uid(&id), Node::text(ATTRIBUTE_NAME, "x-ID")];
        payload(&call(&mut f.engine, v, "alice", 15, delete));
        let values = legacy_values(&mut f.engine, v, &id, "x-ID");
        assert_eq!(values.len(), 1);
        assert_eq!(values[0].0, 1);
        assert_eq!(
            reason(&call(
                &mut f.engine,
                v,
                "alice",
                14,
                vec![
                    uid(&id),
                    legacy_attribute("x-ID", Node::text(ATTRIBUTE_VALUE, "missing-zero"), None)
                ]
            )),
            1
        );
        payload(&call(
            &mut f.engine,
            v,
            "alice",
            14,
            vec![
                uid(&id),
                legacy_attribute("x-ID", Node::text(ATTRIBUTE_VALUE, "updated"), Some(1)),
            ],
        ));
        assert_eq!(
            reason(&call(
                &mut f.engine,
                v,
                "alice",
                13,
                vec![
                    uid(&id),
                    legacy_attribute("x-ID", Node::text(ATTRIBUTE_VALUE, "bad-index"), Some(0))
                ]
            )),
            7
        );
        let path = f._dir.path().join("keys.sqlite");
        let master = f._dir.path().join("master");
        drop(f.engine);
        f.engine = Engine::new(Store::open(&path, &master).unwrap(), false);
        let values = legacy_values(&mut f.engine, v, &id, "x-ID");
        assert_eq!(values[0].0, 1);
        assert_eq!(values[0].1.string().unwrap(), "updated");
        // The lowest available index can be reused without changing index 1.
        payload(&call(
            &mut f.engine,
            Version(2, 1),
            "alice",
            13,
            vec![uid(&id), Node::structure(NEW_ATTRIBUTE, vec![custom])],
        ));
        let values = legacy_values(&mut f.engine, v, &id, "x-ID");
        assert_eq!(
            values.iter().map(|(i, _)| *i).collect::<Vec<_>>(),
            vec![0, 1]
        );
        f.engine.store.verify_audit().unwrap();
    }
}
#[test]
fn current_attribute_selection_set_ambiguity_and_delete_all_are_version_correct() {
    for v in [Version(2, 0), Version(2, 1), Version(3, 0)] {
        let mut f = Fixture::new();
        f.engine.experimental_v3 = true;
        let a = Node::text(OBJECT_GROUP, "one");
        let b = Node::text(OBJECT_GROUP, "two");
        let id = create(&mut f.engine, v, vec![a.clone(), b.clone()]);
        for op in [14, 49] {
            assert_eq!(
                reason(&call(
                    &mut f.engine,
                    v,
                    "alice",
                    op,
                    vec![
                        uid(&id),
                        Node::structure(NEW_ATTRIBUTE, vec![Node::text(OBJECT_GROUP, "ambiguous")])
                    ]
                )),
                0x1e
            );
        }
        let c = Node::text(OBJECT_GROUP, "three");
        payload(&call(
            &mut f.engine,
            v,
            "alice",
            14,
            vec![
                uid(&id),
                Node::structure(CURRENT_ATTRIBUTE, vec![b.clone()]),
                Node::structure(NEW_ATTRIBUTE, vec![c.clone()]),
            ],
        ));
        let r = call(
            &mut f.engine,
            v,
            "alice",
            14,
            vec![
                uid(&id),
                Node::structure(CURRENT_ATTRIBUTE, vec![b]),
                Node::structure(NEW_ATTRIBUTE, vec![c.clone()]),
            ],
        );
        assert_eq!(reason(&r), 0x20);
        payload(&call(
            &mut f.engine,
            v,
            "alice",
            15,
            vec![uid(&id), Node::structure(CURRENT_ATTRIBUTE, vec![a])],
        ));
        payload(&call(
            &mut f.engine,
            v,
            "alice",
            49,
            vec![
                uid(&id),
                Node::structure(NEW_ATTRIBUTE, vec![Node::text(OBJECT_GROUP, "set")]),
            ],
        ));
        payload(&call(
            &mut f.engine,
            v,
            "alice",
            15,
            vec![
                uid(&id),
                Node::enumeration(ATTRIBUTE_REFERENCE, OBJECT_GROUP),
            ],
        ));
        let r = call(
            &mut f.engine,
            v,
            "alice",
            11,
            vec![
                uid(&id),
                Node::enumeration(ATTRIBUTE_REFERENCE, OBJECT_GROUP),
            ],
        );
        // None requested exist: the identifier and an empty Attributes structure.
        assert_eq!(payload(&r).children().unwrap().len(), 2);
        assert!(
            payload(&r)
                .required(ATTRIBUTES)
                .unwrap()
                .children()
                .unwrap()
                .is_empty()
        );
        payload(&call(
            &mut f.engine,
            v,
            "alice",
            49,
            vec![uid(&id), Node::structure(NEW_ATTRIBUTE, vec![c.clone()])],
        ));
        payload(&call(
            &mut f.engine,
            v,
            "alice",
            13,
            vec![uid(&id), Node::structure(NEW_ATTRIBUTE, vec![c])],
        ));
        let r = call(
            &mut f.engine,
            v,
            "alice",
            15,
            vec![
                uid(&id),
                Node::structure(CURRENT_ATTRIBUTE, vec![Node::text(OBJECT_GROUP, "three")]),
            ],
        );
        assert_eq!(reason(&r), 0x1e); // identical values cannot uniquely select an instance
        payload(&call(
            &mut f.engine,
            v,
            "alice",
            15,
            vec![
                uid(&id),
                Node::enumeration(ATTRIBUTE_REFERENCE, OBJECT_GROUP),
            ],
        ));
    }
}
#[test]
fn indexed_cryptographic_parameter_deletion_and_reuse_select_the_lowest_instance() {
    for v in crypto_versions() {
        let mut f = Fixture::new();
        f.engine.experimental_v3 = true;
        let ecb = Node::structure(
            CRYPTOGRAPHIC_PARAMETERS,
            vec![Node::enumeration(BLOCK_CIPHER_MODE, 2)],
        );
        let cbc = Node::structure(
            CRYPTOGRAPHIC_PARAMETERS,
            vec![Node::enumeration(BLOCK_CIPHER_MODE, 1)],
        );
        let id = register_aes(&mut f.engine, v, vec![0; 16], vec![ecb.clone(), cbc]);
        payload(&call(&mut f.engine, v, "alice", 18, vec![uid(&id)]));
        payload(&call(
            &mut f.engine,
            Version(1, 4),
            "alice",
            15,
            vec![
                uid(&id),
                Node::text(ATTRIBUTE_NAME, "Cryptographic Parameters"),
            ],
        ));
        let values = legacy_values(
            &mut f.engine,
            Version(1, 4),
            &id,
            "Cryptographic Parameters",
        );
        assert_eq!(values.len(), 1);
        assert_eq!(values[0].0, 1);
        assert_eq!(
            reason(&call(
                &mut f.engine,
                v,
                "alice",
                31,
                vec![uid(&id), Node::bytes(DATA, vec![0; 16])]
            )),
            // A missing required IV is Invalid Message.
            4
        );
        let new = if v.0 == 1 {
            legacy_attribute("Cryptographic Parameters", ecb, None)
        } else {
            Node::structure(NEW_ATTRIBUTE, vec![ecb])
        };
        payload(&call(&mut f.engine, v, "alice", 13, vec![uid(&id), new]));
        let encrypted = call(
            &mut f.engine,
            v,
            "alice",
            31,
            vec![uid(&id), Node::bytes(DATA, vec![0; 16])],
        );
        assert_eq!(
            payload(&encrypted)
                .required(DATA)
                .unwrap()
                .byte_string()
                .unwrap(),
            hex::decode("66e94bd4ef8a2c3b884cfa59ca342b2e").unwrap()
        );
    }
}
#[test]
fn custom_value_ownership_types_selectors_limits_and_rollback_are_enforced() {
    let mut f = Fixture::new();
    let v = Version(2, 1);
    let id = create(&mut f.engine, v, vec![]);
    for version in [Version(1, 0), Version(1, 4), v] {
        let response = call(
            &mut f.engine,
            version,
            "alice",
            11,
            vec![
                uid(&id),
                if version.0 == 1 {
                    Node::text(ATTRIBUTE_NAME, "x-missing")
                } else {
                    Node::structure(
                        ATTRIBUTE_REFERENCE,
                        vec![
                            Node::text(VENDOR_IDENTIFICATION, "x"),
                            Node::text(ATTRIBUTE_NAME, "missing"),
                        ],
                    )
                },
            ],
        );
        // 1.x returns the identifier only; 2.x adds an empty Attributes.
        assert_eq!(
            payload(&response).children().unwrap().len(),
            if version.0 == 1 { 1 } else { 2 }
        );
    }
    let current = vendor_attribute("y", "server", Node::text(ATTRIBUTE_VALUE, "owned"));
    let mut stored = f.engine.store.get("alice", &id).unwrap().unwrap();
    stored.attrs.push(current.clone());
    f.engine.store.put(&stored).unwrap();
    for version in [Version(1, 4), v] {
        for op in [13, 14, 15] {
            let fields = if version.0 == 1 {
                if op == 15 {
                    vec![uid(&id), Node::text(ATTRIBUTE_NAME, "y-server")]
                } else {
                    vec![
                        uid(&id),
                        legacy_attribute("y-server", Node::text(ATTRIBUTE_VALUE, "tamper"), None),
                    ]
                }
            } else if op == 15 {
                vec![
                    uid(&id),
                    Node::structure(CURRENT_ATTRIBUTE, vec![current.clone()]),
                ]
            } else {
                vec![
                    uid(&id),
                    Node::structure(NEW_ATTRIBUTE, vec![current.clone()]),
                ]
            };
            assert_eq!(
                reason(&call(&mut f.engine, version, "alice", op, fields)),
                if version.0 >= 2 { 0x22 } else { 12 }
            );
        }
    }
    let invalid = vendor_attribute(
        "x",
        "nested",
        Node::structure(ATTRIBUTE_VALUE, vec![Node::structure(NAME, vec![])]),
    );
    assert_eq!(
        reason(&call(
            &mut f.engine,
            v,
            "alice",
            13,
            vec![uid(&id), Node::structure(NEW_ATTRIBUTE, vec![invalid])]
        )),
        7
    );
    let big = vendor_attribute(
        "x",
        "large",
        Node::bytes(ATTRIBUTE_VALUE, vec![42; 262_144]),
    );
    assert_eq!(
        reason(&call(
            &mut f.engine,
            v,
            "alice",
            13,
            vec![uid(&id), Node::structure(NEW_ATTRIBUTE, vec![big])]
        )),
        2
    );
    let added = vendor_attribute("x", "undo", Node::text(ATTRIBUTE_VALUE, "first"));
    let response = f
        .engine
        .process(
            "alice",
            &batch_option(
                req(
                    v,
                    vec![
                        (
                            13,
                            vec![uid(&id), Node::structure(NEW_ATTRIBUTE, vec![added])],
                        ),
                        (10, vec![uid("missing")]),
                    ],
                ),
                3,
            ),
        )
        .unwrap();
    assert_eq!(
        response
            .all(BATCH_ITEM)
            .next()
            .unwrap()
            .required(RESULT_STATUS)
            .unwrap()
            .number()
            .unwrap(),
        3
    );
    let values = legacy_values(&mut f.engine, Version(1, 4), &id, "x-undo");
    assert!(values.is_empty());
    let duplicate = Node::text(ATTRIBUTE_NAME, "x-missing");
    assert_eq!(
        reason(&call(
            &mut f.engine,
            Version(1, 4),
            "alice",
            11,
            vec![uid(&id), duplicate.clone(), duplicate]
        )),
        // 1.4 table 339: a repeated Attribute Name is Invalid Message.
        4
    );
    f.engine.store.verify_audit().unwrap();
}
// REQ:b4631429d54e6872 1.0/1.1 a Name already used by any owner on the server is refused
// REQ:b38a3c5f611e0eab 1.2-2.0 a Name already used by any owner on the server is refused
// REQ:861f552c8345979b 2.1 a Name already used by any owner on the server is refused
#[test]
fn names_are_unique_per_owner_and_rekey_transfers_them_atomically() {
    let name = |value: &str| {
        Node::structure(
            NAME,
            vec![
                Node::text(NAME_VALUE, value),
                Node::enumeration(NAME_TYPE, 1),
            ],
        )
    };
    for v in Version::supported(true) {
        let mut f = Fixture::new();
        f.engine.experimental_v3 = true;
        let old = create(
            &mut f.engine,
            v,
            vec![name("database-a"), name("database-b")],
        );
        let r = call(
            &mut f.engine,
            v,
            "alice",
            1,
            vec![
                Node::enumeration(OBJECT_TYPE, 2),
                attrs(
                    v,
                    vec![Node::structure(
                        NAME,
                        vec![
                            Node::enumeration(NAME_TYPE, 1),
                            Node::text(NAME_VALUE, "database-a"),
                        ],
                    )],
                ),
            ],
        );
        assert_eq!(reason(&r), if v.0 >= 2 { 0x35 } else { 7 });
        // REQ: docs/interpretations.md (name uniqueness): uniqueness is per owner,
        // so another tenant may use the Name and learns nothing about it.
        payload(&call(
            &mut f.engine,
            v,
            "bob",
            1,
            vec![
                Node::enumeration(OBJECT_TYPE, 2),
                attrs(v, vec![name("database-a")]),
            ],
        ));
        payload(&call(
            &mut f.engine,
            v,
            "bob",
            1,
            vec![
                Node::enumeration(OBJECT_TYPE, 2),
                attrs(v, vec![name("database-bob")]),
            ],
        ));
        payload(&call(&mut f.engine, v, "alice", 18, vec![uid(&old)]));
        let r = call(&mut f.engine, v, "alice", 4, vec![uid(&old)]);
        let replacement = payload(&r)
            .required(UNIQUE_IDENTIFIER)
            .unwrap()
            .identifier_text()
            .unwrap()
            .to_owned();
        assert!(
            !f.engine
                .store
                .get("alice", &old)
                .unwrap()
                .unwrap()
                .attrs
                .iter()
                .any(|a| a.tag == NAME)
        );
        assert_eq!(
            f.engine
                .store
                .get("alice", &replacement)
                .unwrap()
                .unwrap()
                .attrs
                .iter()
                .filter(|a| a.tag == NAME)
                .count(),
            2
        );
        let response = f
            .engine
            .process(
                "alice",
                &batch_option(
                    req(
                        v,
                        vec![
                            (13, vec![uid(&old), attribute_change(v, name("temporary"))]),
                            (10, vec![uid("missing")]),
                        ],
                    ),
                    3,
                ),
            )
            .unwrap();
        assert_eq!(
            response
                .all(BATCH_ITEM)
                .next()
                .unwrap()
                .required(RESULT_STATUS)
                .unwrap()
                .number()
                .unwrap(),
            3
        );
        payload(&call(
            &mut f.engine,
            v,
            "alice",
            13,
            vec![uid(&old), attribute_change(v, name("temporary"))],
        ));
        f.engine.store.verify_audit().unwrap();
    }
}

#[test]
fn attribute_inheritance_overrides_groups_without_losing_other_custom_names() {
    let mut f = Fixture::new();
    let v = Version(2, 1);
    let custom =
        |name: &str, value: &str| vendor_attribute("x", name, Node::text(ATTRIBUTE_VALUE, value));
    let name = |value: &str| {
        Node::structure(
            NAME,
            vec![
                Node::text(NAME_VALUE, value),
                Node::enumeration(NAME_TYPE, 1),
            ],
        )
    };
    let r = call(
        &mut f.engine,
        v,
        "alice",
        2,
        vec![
            Node::structure(
                COMMON_ATTRIBUTES,
                vec![
                    Node::enumeration(CRYPTOGRAPHIC_ALGORITHM, 3),
                    Node::int(CRYPTOGRAPHIC_LENGTH, 3072),
                    Node::text(OBJECT_GROUP, "common"),
                    custom("one", "common"),
                    custom("two", "retained"),
                ],
            ),
            Node::structure(
                PRIVATE_KEY_ATTRIBUTES,
                vec![
                    Node::enumeration(CRYPTOGRAPHIC_ALGORITHM, 4),
                    Node::int(CRYPTOGRAPHIC_LENGTH, 2048),
                    name("private"),
                    custom("one", "private"),
                ],
            ),
            Node::structure(
                PUBLIC_KEY_ATTRIBUTES,
                vec![
                    Node::enumeration(CRYPTOGRAPHIC_ALGORITHM, 4),
                    Node::int(CRYPTOGRAPHIC_LENGTH, 2048),
                    name("public"),
                ],
            ),
        ],
    );
    let private = payload(&r)
        .required(PRIVATE_KEY_UNIQUE_IDENTIFIER)
        .unwrap()
        .identifier_text()
        .unwrap()
        .to_owned();
    let public = payload(&r)
        .required(PUBLIC_KEY_UNIQUE_IDENTIFIER)
        .unwrap()
        .identifier_text()
        .unwrap()
        .to_owned();
    for (id, expected) in [(&private, "private"), (&public, "common")] {
        let object = f.engine.store.get("alice", id).unwrap().unwrap();
        assert_eq!(object.bits, 2048);
        assert_eq!(object.algorithm, 4);
        assert!(object.attrs.iter().any(|a| a == &custom("one", expected)));
        assert!(object.attrs.iter().any(|a| a == &custom("two", "retained")));
        assert!(object.attrs.contains(&custom("one", "common")));
        assert!(object.attrs.contains(&Node::text(OBJECT_GROUP, "common")));
    }
    let id = create(
        &mut f.engine,
        v,
        vec![custom("one", "old"), custom("two", "retained")],
    );
    payload(&call(&mut f.engine, v, "alice", 18, vec![uid(&id)]));
    let r = call(
        &mut f.engine,
        v,
        "alice",
        4,
        vec![
            uid(&id),
            Node::structure(ATTRIBUTES, vec![custom("one", "replacement")]),
        ],
    );
    let replacement = payload(&r)
        .required(UNIQUE_IDENTIFIER)
        .unwrap()
        .identifier_text()
        .unwrap()
        .to_owned();
    let object = f.engine.store.get("alice", &replacement).unwrap().unwrap();
    assert!(
        object
            .attrs
            .iter()
            .any(|a| a == &custom("one", "replacement"))
    );
    assert!(object.attrs.iter().any(|a| a == &custom("two", "retained")));
}

#[test]
fn draft_csd02_framing_omits_removed_fields_and_supports_ordered_batches_without_ids() {
    let mut f = Fixture::new();
    f.engine.experimental_v3 = true;
    let v = Version(3, 0);
    let r = call(&mut f.engine, v, "alice", 59, vec![]);
    payload(&r);
    assert!(
        r.required(RESPONSE_HEADER)
            .unwrap()
            .get(BATCH_COUNT)
            .is_none()
    );
    assert!(
        r.required(BATCH_ITEM)
            .unwrap()
            .get(UNIQUE_BATCH_ITEM_ID)
            .is_none()
    );
    for field in [
        Node::int(BATCH_COUNT, 1),
        Node::boolean(BATCH_ORDER_OPTION, true),
    ] {
        let mut request = req(v, vec![(59, vec![])]);
        if let Value::Structure(message) = &mut request.value
            && let Value::Structure(header) = &mut message[0].value
        {
            header.push(field);
        }
        let r = f.engine.process("alice", &request).unwrap();
        assert_eq!(reason(&r), 7);
        assert!(
            r.required(RESPONSE_HEADER)
                .unwrap()
                .get(BATCH_COUNT)
                .is_none()
        );
    }
    let mut request = req(v, vec![(59, vec![])]);
    if let Value::Structure(message) = &mut request.value
        && let Value::Structure(item) = &mut message[1].value
    {
        item.push(Node::bytes(UNIQUE_BATCH_ITEM_ID, vec![1]));
    }
    assert_eq!(reason(&f.engine.process("alice", &request).unwrap()), 7);
    for continuation in [None, Some(1)] {
        let request = req(v, vec![(59, vec![]), (0x7fffffff, vec![]), (59, vec![])]);
        let request =
            continuation.map_or_else(|| request.clone(), |c| batch_option(request.clone(), c));
        let r = f.engine.process("alice", &request).unwrap();
        let items = r.all(BATCH_ITEM).collect::<Vec<_>>();
        assert_eq!(items.len(), if continuation.is_none() { 2 } else { 3 });
        for item in &items {
            assert!(item.get(UNIQUE_BATCH_ITEM_ID).is_none());
        }
        assert_eq!(
            items[1].required(RESULT_REASON).unwrap().number().unwrap(),
            5
        );
    }
}

#[test]
fn draft_identifier_reference_name_and_attribute_types_preserve_cross_version_keys() {
    let mut f = Fixture::new();
    f.engine.experimental_v3 = true;
    let v = Version(3, 0);
    let id = create(&mut f.engine, v, vec![Node::text(NAME, "draft-database")]);
    let r = call(
        &mut f.engine,
        v,
        "alice",
        10,
        vec![Node::reference(UNIQUE_IDENTIFIER, &id)],
    );
    assert!(matches!(
        payload(&r).required(UNIQUE_IDENTIFIER).unwrap().value,
        Value::Identifier(_)
    ));
    let material = payload(&r)
        .required(SYMMETRIC_KEY)
        .unwrap()
        .required(KEY_BLOCK)
        .unwrap()
        .required(KEY_VALUE)
        .unwrap()
        .required(KEY_MATERIAL)
        .unwrap()
        .byte_string()
        .unwrap()
        .to_vec();
    for version in [
        Version(1, 0),
        Version(1, 4),
        Version(2, 0),
        Version(2, 1),
        v,
    ] {
        let r = call(&mut f.engine, version, "alice", 10, vec![uid(&id)]);
        assert_eq!(
            payload(&r)
                .required(SYMMETRIC_KEY)
                .unwrap()
                .required(KEY_BLOCK)
                .unwrap()
                .required(KEY_VALUE)
                .unwrap()
                .required(KEY_MATERIAL)
                .unwrap()
                .byte_string()
                .unwrap(),
            material
        );
        assert_eq!(
            payload(&r)
                .required(UNIQUE_IDENTIFIER)
                .unwrap()
                .identifier_text()
                .unwrap(),
            id
        );
    }
    let r = call(
        &mut f.engine,
        v,
        "alice",
        10,
        vec![Node::name_reference(UNIQUE_IDENTIFIER, "draft-database")],
    );
    assert_eq!(
        payload(&r)
            .required(UNIQUE_IDENTIFIER)
            .unwrap()
            .identifier_text()
            .unwrap(),
        id
    );
    assert_eq!(
        reason(&call(
            &mut f.engine,
            v,
            "bob",
            10,
            vec![Node::name_reference(UNIQUE_IDENTIFIER, "draft-database")]
        )),
        0x37
    );
    let r = call(
        &mut f.engine,
        v,
        "alice",
        11,
        vec![
            uid(&id),
            Node::enumeration(ATTRIBUTE_REFERENCE, NAME),
            Node::enumeration(ATTRIBUTE_REFERENCE, UNIQUE_IDENTIFIER),
            Node::enumeration(ATTRIBUTE_REFERENCE, SHORT_UNIQUE_IDENTIFIER),
            Node::enumeration(ATTRIBUTE_REFERENCE, OBJECT_CLASS),
        ],
    );
    let attrs = payload(&r).required(ATTRIBUTES).unwrap();
    assert_eq!(
        attrs.required(NAME).unwrap().string().unwrap(),
        "draft-database"
    );
    assert!(matches!(
        attrs.required(UNIQUE_IDENTIFIER).unwrap().value,
        Value::Identifier(_)
    ));
    assert_eq!(
        attrs
            .required(SHORT_UNIQUE_IDENTIFIER)
            .unwrap()
            .byte_string()
            .unwrap(),
        openssl::sha::sha256(id.as_bytes())
    );
    assert_eq!(attrs.required(OBJECT_CLASS).unwrap().number().unwrap(), 1);
    let mut request = req(v, vec![(10, vec![uid(&id)])]);
    if let Value::Structure(fields) = &mut request.value
        && let Value::Structure(fields) = &mut fields[1].value
        && let Some(p) = fields.iter_mut().find(|n| n.tag == REQUEST_PAYLOAD)
        && let Value::Structure(fields) = &mut p.value
    {
        fields[0] = uid(&id);
    }
    assert_eq!(reason(&f.engine.process("alice", &request).unwrap()), 7);
    assert_eq!(
        reason(&call(
            &mut f.engine,
            Version(2, 1),
            "alice",
            10,
            vec![Node::identifier(UNIQUE_IDENTIFIER, &id)]
        )),
        7
    );
}
#[test]
fn message_identifier_enumerations_integer_indices_and_pair_fanout_are_scoped() {
    for v in [Version(2, 0), Version(2, 1), Version(3, 0)] {
        let mut f = Fixture::new();
        f.engine.experimental_v3 = true;
        let mut common = container(
            v,
            vec![
                Node::enumeration(CRYPTOGRAPHIC_ALGORITHM, 4),
                Node::int(CRYPTOGRAPHIC_LENGTH, 2048),
                Node::int(CRYPTOGRAPHIC_USAGE_MASK, 15),
            ],
        );
        common.tag = if v.0 >= 2 {
            COMMON_ATTRIBUTES
        } else {
            COMMON_TEMPLATE_ATTRIBUTE
        };
        let r = f
            .engine
            .process(
                "alice",
                &req(
                    v,
                    vec![
                        (2, vec![common]),
                        (18, vec![Node::enumeration(UNIQUE_IDENTIFIER, 4)]),
                        (11, vec![Node::enumeration(UNIQUE_IDENTIFIER, 5)]),
                        (11, vec![Node::enumeration(UNIQUE_IDENTIFIER, 6)]),
                    ],
                ),
            )
            .unwrap();
        let items = r.all(BATCH_ITEM).collect::<Vec<_>>();
        assert_eq!(items.len(), 5);
        for item in &items {
            assert_eq!(item.required(RESULT_STATUS).unwrap().number().unwrap(), 0);
        }
        let pair = items[0].required(RESPONSE_PAYLOAD).unwrap();
        let private = pair
            .required(PRIVATE_KEY_UNIQUE_IDENTIFIER)
            .unwrap()
            .identifier_text()
            .unwrap();
        let public = pair
            .required(PUBLIC_KEY_UNIQUE_IDENTIFIER)
            .unwrap()
            .identifier_text()
            .unwrap();
        assert_eq!(
            items[1]
                .required(RESPONSE_PAYLOAD)
                .unwrap()
                .required(UNIQUE_IDENTIFIER)
                .unwrap()
                .identifier_text()
                .unwrap(),
            private
        );
        assert_eq!(
            items[2]
                .required(RESPONSE_PAYLOAD)
                .unwrap()
                .required(UNIQUE_IDENTIFIER)
                .unwrap()
                .identifier_text()
                .unwrap(),
            public
        );
        assert_eq!(
            f.engine.store.get("alice", private).unwrap().unwrap().state,
            2
        );
        assert_eq!(
            f.engine.store.get("alice", public).unwrap().unwrap().state,
            2
        );
        let r = f
            .engine
            .process(
                "alice",
                &req(
                    v,
                    vec![
                        (1, vec![Node::enumeration(OBJECT_TYPE, 2), attrs(v, vec![])]),
                        (10, vec![Node::int(UNIQUE_IDENTIFIER, 0)]),
                        (10, vec![Node::int(UNIQUE_IDENTIFIER, -1)]),
                        (10, vec![Node::enumeration(UNIQUE_IDENTIFIER, 3)]),
                    ],
                ),
            )
            .unwrap();
        let items = r.all(BATCH_ITEM).collect::<Vec<_>>();
        assert_eq!(items.len(), 4);
        let id = items[0]
            .required(RESPONSE_PAYLOAD)
            .unwrap()
            .required(UNIQUE_IDENTIFIER)
            .unwrap()
            .identifier_text()
            .unwrap();
        for item in &items[1..] {
            assert_eq!(
                item.required(RESPONSE_PAYLOAD)
                    .unwrap()
                    .required(UNIQUE_IDENTIFIER)
                    .unwrap()
                    .identifier_text()
                    .unwrap(),
                id
            );
        }
        for reference in [
            Node::int(UNIQUE_IDENTIFIER, 0),
            Node::int(UNIQUE_IDENTIFIER, i32::MIN),
            Node::int(UNIQUE_IDENTIFIER, -1),
        ] {
            assert_eq!(
                reason(&call(&mut f.engine, v, "alice", 10, vec![reference])),
                7
            );
        }
        assert_eq!(
            reason(&call(
                &mut f.engine,
                v,
                "alice",
                10,
                vec![Node::enumeration(UNIQUE_IDENTIFIER, 3)]
            )),
            if v.0 >= 2 { 7 } else { 6 }
        );
    }
}
#[test]
fn locate_reference_fanout_and_failed_factory_aliases_obey_batch_rollback() {
    for v in [Version(2, 0), Version(2, 1), Version(3, 0)] {
        let mut f = Fixture::new();
        f.engine.experimental_v3 = true;
        let one = create(&mut f.engine, v, vec![]);
        let two = create(&mut f.engine, v, vec![]);
        let r = f
            .engine
            .process(
                "alice",
                &req(
                    v,
                    vec![
                        (8, vec![]),
                        (10, vec![Node::enumeration(UNIQUE_IDENTIFIER, 11)]),
                    ],
                ),
            )
            .unwrap();
        let items = r.all(BATCH_ITEM).collect::<Vec<_>>();
        assert_eq!(items.len(), 3);
        let returned = items[1..]
            .iter()
            .map(|i| {
                i.required(RESPONSE_PAYLOAD)
                    .unwrap()
                    .required(UNIQUE_IDENTIFIER)
                    .unwrap()
                    .identifier_text()
                    .unwrap()
            })
            .collect::<Vec<_>>();
        assert!(returned.contains(&one.as_str()) && returned.contains(&two.as_str()));
        let r = f
            .engine
            .process(
                "alice",
                &batch_option(
                    req(
                        v,
                        vec![
                            (1, vec![Node::enumeration(OBJECT_TYPE, 2), attrs(v, vec![])]),
                            (
                                1,
                                vec![
                                    Node::enumeration(OBJECT_TYPE, 2),
                                    container(
                                        v,
                                        vec![Node::enumeration(CRYPTOGRAPHIC_ALGORITHM, 999)],
                                    ),
                                ],
                            ),
                            (10, vec![Node::enumeration(UNIQUE_IDENTIFIER, 3)]),
                        ],
                    ),
                    1,
                ),
            )
            .unwrap();
        assert_eq!(
            r.all(BATCH_ITEM)
                .nth(2)
                .unwrap()
                .required(RESULT_REASON)
                .unwrap()
                .number()
                .unwrap(),
            if v.0 >= 2 { 7 } else { 6 }
        );
        let r = f
            .engine
            .process(
                "alice",
                &batch_option(
                    req(
                        v,
                        vec![
                            (18, vec![uid(&one)]),
                            (10, vec![Node::int(UNIQUE_IDENTIFIER, 999)]),
                        ],
                    ),
                    3,
                ),
            )
            .unwrap();
        assert_eq!(
            r.all(BATCH_ITEM)
                .next()
                .unwrap()
                .required(RESULT_STATUS)
                .unwrap()
                .number()
                .unwrap(),
            3
        );
        assert_eq!(f.engine.store.get("alice", &one).unwrap().unwrap().state, 1);
        f.engine.store.verify_audit().unwrap();
    }
}
#[test]
fn draft_links_preserve_late_binding_and_mutations_target_the_right_link_type() {
    let mut f = Fixture::new();
    f.engine.experimental_v3 = true;
    let v = Version(3, 0);
    let first = create(&mut f.engine, v, vec![Node::text(NAME, "active-database")]);
    let second = create(&mut f.engine, v, vec![]);
    let source = create(
        &mut f.engine,
        v,
        vec![
            Node::reference(REPLACED_OBJECT_LINK, &first),
            Node::name_reference(REPLACEMENT_OBJECT_LINK, "active-database"),
        ],
    );
    let reference = |tag| Node::enumeration(ATTRIBUTE_REFERENCE, tag);
    let read = |e: &mut Engine| {
        call(
            e,
            v,
            "alice",
            11,
            vec![
                uid(&source),
                reference(REPLACED_OBJECT_LINK),
                reference(REPLACEMENT_OBJECT_LINK),
            ],
        )
    };
    let r = read(&mut f.engine);
    let a = payload(&r).required(ATTRIBUTES).unwrap();
    assert!(matches!(
        a.required(REPLACED_OBJECT_LINK).unwrap().value,
        Value::Reference(_)
    ));
    assert!(matches!(
        a.required(REPLACEMENT_OBJECT_LINK).unwrap().value,
        Value::NameReference(_)
    ));
    payload(&call(
        &mut f.engine,
        v,
        "alice",
        49,
        vec![
            uid(&first),
            Node::structure(NEW_ATTRIBUTE, vec![Node::text(NAME, "retired-database")]),
        ],
    ));
    payload(&call(
        &mut f.engine,
        v,
        "alice",
        49,
        vec![
            uid(&second),
            Node::structure(NEW_ATTRIBUTE, vec![Node::text(NAME, "active-database")]),
        ],
    ));
    let r = call(
        &mut f.engine,
        v,
        "alice",
        10,
        vec![Node::name_reference(UNIQUE_IDENTIFIER, "active-database")],
    );
    assert_eq!(
        payload(&r)
            .required(UNIQUE_IDENTIFIER)
            .unwrap()
            .identifier_text()
            .unwrap(),
        second
    );
    let path = f._dir.path().join("keys.sqlite");
    let master = f._dir.path().join("master");
    drop(f.engine);
    f.engine = Engine::new(Store::open(&path, &master).unwrap(), true);
    let r = read(&mut f.engine);
    let a = payload(&r).required(ATTRIBUTES).unwrap();
    assert_eq!(
        a.required(REPLACED_OBJECT_LINK)
            .unwrap()
            .identifier_text()
            .unwrap(),
        first
    );
    assert_eq!(
        a.required(REPLACEMENT_OBJECT_LINK)
            .unwrap()
            .identifier_text()
            .unwrap(),
        "active-database"
    );
    assert_eq!(
        reason(&call(
            &mut f.engine,
            Version(2, 1),
            "alice",
            11,
            vec![uid(&source), reference(LINK)]
        )),
        8
    );
    assert_eq!(
        reason(&call(
            &mut f.engine,
            v,
            "alice",
            13,
            vec![
                uid(&source),
                Node::structure(
                    NEW_ATTRIBUTE,
                    vec![Node::reference(REPLACEMENT_OBJECT_LINK, &second)]
                )
            ]
        )),
        0x23
    );
    payload(&call(
        &mut f.engine,
        v,
        "alice",
        49,
        vec![
            uid(&source),
            Node::structure(
                NEW_ATTRIBUTE,
                vec![Node::reference(REPLACEMENT_OBJECT_LINK, &second)],
            ),
        ],
    ));
    payload(&call(
        &mut f.engine,
        v,
        "alice",
        15,
        vec![uid(&source), reference(REPLACEMENT_OBJECT_LINK)],
    ));
    let r = read(&mut f.engine);
    let a = payload(&r).required(ATTRIBUTES).unwrap();
    assert!(a.get(REPLACEMENT_OBJECT_LINK).is_none());
    assert!(a.get(REPLACED_OBJECT_LINK).is_some());
    f.engine.store.verify_audit().unwrap();
}
#[test]
fn expanded_batch_limit_fails_only_expansion_and_preserves_prior_stop_changes() {
    let mut f = Fixture::new();
    let v = Version(2, 1);
    let mut ids = vec![];
    for _ in 0..128 {
        ids.push(create(&mut f.engine, v, vec![]));
    }
    let r = f
        .engine
        .process(
            "alice",
            &req(
                v,
                vec![
                    (18, vec![uid(&ids[0])]),
                    (8, vec![]),
                    (10, vec![Node::enumeration(UNIQUE_IDENTIFIER, 11)]),
                ],
            ),
        )
        .unwrap();
    let items: Vec<_> = r.all(BATCH_ITEM).collect();
    assert_eq!(items.len(), 3);
    assert_eq!(items[2].required(OPERATION).unwrap().number().unwrap(), 10);
    assert_eq!(
        items[2].required(RESULT_REASON).unwrap().number().unwrap(),
        0x3a
    );
    assert_eq!(
        f.engine.store.get("alice", &ids[0]).unwrap().unwrap().state,
        2
    );
    f.engine.store.verify_audit().unwrap();
}

#[test]
fn expanded_payload_and_correlation_limits_do_not_allocate_unbounded_copies() {
    let mut f = Fixture::new();
    let v = Version(2, 1);
    let one = create(&mut f.engine, v, vec![]);
    create(&mut f.engine, v, vec![]);
    let cp = Node::structure(
        CRYPTOGRAPHIC_PARAMETERS,
        vec![Node::enumeration(BLOCK_CIPHER_MODE, 2)],
    );
    let r = f
        .engine
        .process(
            "alice",
            &req(
                v,
                vec![
                    (18, vec![uid(&one)]),
                    (8, vec![]),
                    (
                        31,
                        vec![
                            Node::enumeration(UNIQUE_IDENTIFIER, 11),
                            cp,
                            Node::bytes(DATA, vec![0; 700_000]),
                        ],
                    ),
                ],
            ),
        )
        .unwrap();
    let items: Vec<_> = r.all(BATCH_ITEM).collect();
    assert_eq!(items.len(), 3);
    assert_eq!(items[2].required(OPERATION).unwrap().number().unwrap(), 31);
    assert_eq!(
        items[2].required(RESULT_REASON).unwrap().number().unwrap(),
        0x3a
    );
    assert_eq!(f.engine.store.get("alice", &one).unwrap().unwrap().state, 2);
    let mut request = req(v, vec![(24, vec![])]);
    if let Value::Structure(message) = &mut request.value
        && let Value::Structure(header) = &mut message[0].value
    {
        header.push(Node::text(CLIENT_CORRELATION_VALUE, "x".repeat(1_048_000)));
    }
    let response = f.engine.process("alice", &request).unwrap();
    assert_eq!(reason(&response), 7);
    assert!(response.encoded_len() < 1024);
}

fn history_link(kind: u32, id: &str) -> Node {
    Node::structure(
        LINK,
        vec![
            Node::enumeration(LINK_TYPE, kind),
            Node::text(LINKED_OBJECT_IDENTIFIER, id),
        ],
    )
}
fn stored_link(obj: &keytend_kmip_server::store::Object, kind: u32) -> Option<&str> {
    obj.attrs
        .iter()
        .find(|a| a.tag == LINK && a.get(LINK_TYPE).and_then(|n| n.number().ok()) == Some(kind))
        .and_then(|a| a.get(LINKED_OBJECT_IDENTIFIER))
        .and_then(|n| n.identifier_text().ok())
}
fn stored_date(obj: &keytend_kmip_server::store::Object, tag: u32) -> Option<i64> {
    obj.attrs
        .iter()
        .find(|a| a.tag == tag)
        .and_then(|a| match a.value {
            Value::DateTime(t) => Some(t),
            _ => None,
        })
}

#[test]
fn rekey_history_dates_and_deleted_link_guard_persist_in_every_version() {
    for v in Version::supported(true) {
        // 1.0 section 3.17 replaces a past Activation Date with the receipt
        // time, so the past Process Start Date below would precede it (3.20).
        if v == Version(1, 0) {
            continue;
        }
        let mut f = Fixture::new();
        f.engine.experimental_v3 = true;
        let t = keytend_kmip_server::store::now();
        let dates = [
            (ACTIVATION_DATE, t - 120),
            (PROCESS_START_DATE, t - 90),
            (PROTECT_STOP_DATE, t + 1000),
            (DEACTIVATION_DATE, t + 2000),
        ];
        let mut a = dates
            .iter()
            .map(|(tag, t)| Node::date(*tag, *t))
            .collect::<Vec<_>>();
        a.push(Node::structure(
            NAME,
            vec![
                Node::text(NAME_VALUE, "database-history"),
                Node::enumeration(NAME_TYPE, 1),
            ],
        ));
        let id = create(&mut f.engine, v, a);
        let mut old = f.engine.store.get("alice", &id).unwrap().unwrap();
        old.attrs.push(history_link(0x108, "parent"));
        old.attribute_indices
            .insert(format!("s:{LINK:06x}"), vec![3]);
        f.engine.store.put(&old).unwrap();
        let r = call(&mut f.engine, v, "alice", 4, vec![uid(&id)]);
        let next = payload(&r)
            .required(UNIQUE_IDENTIFIER)
            .unwrap()
            .identifier_text()
            .unwrap()
            .to_owned();
        let replacement = f.engine.store.get("alice", &next).unwrap().unwrap();
        let source = f.engine.store.get("alice", &id).unwrap().unwrap();
        assert_eq!(source.material, old.material);
        assert_ne!(replacement.material, old.material);
        assert_eq!(source.state, 2);
        assert_eq!(replacement.state, 2);
        assert_eq!(source.replacement_id.as_deref(), Some(next.as_str()));
        assert!(replacement.replacement_id.is_none());
        assert_eq!(stored_link(&source, 0x106), Some(next.as_str()));
        assert_eq!(stored_link(&source, 0x108), Some("parent"));
        assert_eq!(stored_link(&replacement, 0x107), Some(id.as_str()));
        assert!(stored_link(&replacement, 0x108).is_none());
        for (tag, time) in dates {
            assert_eq!(stored_date(&replacement, tag), Some(time));
        }
        let values = legacy_values(&mut f.engine, Version(1, 4), &id, "Link");
        assert!(
            values
                .iter()
                .any(|(i, a)| *i == 3 && a.get(LINK_TYPE).unwrap().number().unwrap() == 0x108)
        );
        assert!(
            values
                .iter()
                .any(|(i, a)| *i == 0 && a.get(LINK_TYPE).unwrap().number().unwrap() == 0x106)
        );
        let projected = call(
            &mut f.engine,
            Version(3, 0),
            "alice",
            11,
            vec![
                Node::identifier(UNIQUE_IDENTIFIER, &id),
                Node::enumeration(ATTRIBUTE_REFERENCE, REPLACEMENT_OBJECT_LINK),
            ],
        );
        assert!(
            payload(&projected)
                .required(ATTRIBUTES)
                .unwrap()
                .required(REPLACEMENT_OBJECT_LINK)
                .unwrap()
                .value
                == Value::Reference(next.clone())
        );
        assert_eq!(
            reason(&call(&mut f.engine, v, "alice", 4, vec![uid(&id)])),
            12
        );
        // Links are mutable under the spec; deletion must not erase server history.
        payload(&call(
            &mut f.engine,
            Version(1, 4),
            "alice",
            15,
            vec![
                uid(&id),
                Node::text(ATTRIBUTE_NAME, "Link"),
                Node::int(ATTRIBUTE_INDEX, 0),
            ],
        ));
        let path = f._dir.path().join("keys.sqlite");
        let key = f._dir.path().join("master");
        drop(f.engine);
        f.engine = Engine::new(Store::open(&path, &key).unwrap(), true);
        assert_eq!(
            reason(&call(&mut f.engine, v, "alice", 4, vec![uid(&id)])),
            12
        );
        let r = call(&mut f.engine, v, "alice", 4, vec![uid(&next)]);
        let last = payload(&r)
            .required(UNIQUE_IDENTIFIER)
            .unwrap()
            .identifier_text()
            .unwrap();
        let middle = f.engine.store.get("alice", &next).unwrap().unwrap();
        assert_eq!(stored_link(&middle, 0x107), Some(id.as_str()));
        assert_eq!(stored_link(&middle, 0x106), Some(last));
        assert_eq!(
            stored_link(&f.engine.store.get("alice", last).unwrap().unwrap(), 0x107),
            Some(next.as_str())
        );
        f.engine.store.verify_audit().unwrap();
    }
}

#[test]
fn rekey_offset_shifts_dates_and_allows_pre_active_sources_without_dates() {
    for v in Version::supported(true) {
        let mut f = Fixture::new();
        f.engine.experimental_v3 = true;
        let t = keytend_kmip_server::store::now() - 600;
        // 1.0 section 3.17 replaces a past Activation Date with the receipt
        // time, after which the past Process Start Date would precede it
        // (1.0 section 3.20), so the request fails instead.
        if v == Version(1, 0) {
            let r = call(
                &mut f.engine,
                v,
                "alice",
                1,
                vec![
                    Node::enumeration(OBJECT_TYPE, 2),
                    attrs(
                        v,
                        vec![
                            Node::date(ACTIVATION_DATE, t),
                            Node::date(PROCESS_START_DATE, t + 50),
                        ],
                    ),
                ],
            );
            let item = r.get(BATCH_ITEM).unwrap();
            assert_eq!(item.get(RESULT_REASON).unwrap().number().unwrap(), 7);
        } else {
            let id = create(
                &mut f.engine,
                v,
                vec![
                    Node::date(ACTIVATION_DATE, t),
                    Node::date(PROCESS_START_DATE, t + 50),
                    Node::date(PROTECT_STOP_DATE, t + 1200),
                    Node::date(DEACTIVATION_DATE, t + 1800),
                ],
            );
            let r = call(
                &mut f.engine,
                v,
                "alice",
                4,
                vec![uid(&id), Node::interval(OFFSET, 3600)],
            );
            let next = payload(&r)
                .required(UNIQUE_IDENTIFIER)
                .unwrap()
                .identifier_text()
                .unwrap();
            let o = f.engine.store.get("alice", next).unwrap().unwrap();
            let activation = o.created + 3600;
            assert_eq!(o.state, 1);
            assert_eq!(stored_date(&o, ACTIVATION_DATE), Some(activation));
            for (tag, offset) in [
                (PROCESS_START_DATE, 50),
                (PROTECT_STOP_DATE, 1200),
                (DEACTIVATION_DATE, 1800),
            ] {
                assert_eq!(stored_date(&o, tag), Some(activation + offset));
            }
            assert_eq!(
                stored_date(
                    &f.engine.store.get("alice", &id).unwrap().unwrap(),
                    ACTIVATION_DATE
                ),
                Some(t)
            );
        }
        for offset in [None, Some(0), Some(u32::MAX)] {
            let id = create(&mut f.engine, v, vec![]);
            let mut fields = vec![uid(&id)];
            if let Some(offset) = offset {
                fields.push(Node::interval(OFFSET, offset));
            }
            let r = call(&mut f.engine, v, "alice", 4, fields);
            let o = f
                .engine
                .store
                .get(
                    "alice",
                    payload(&r)
                        .required(UNIQUE_IDENTIFIER)
                        .unwrap()
                        .identifier_text()
                        .unwrap(),
                )
                .unwrap()
                .unwrap();
            assert_eq!(
                stored_date(&o, ACTIVATION_DATE),
                offset.map(|n| o.created + i64::from(n))
            );
            assert_eq!(o.state, if offset == Some(0) { 2 } else { 1 });
        }
    }
}

#[test]
fn rekey_rejections_and_state_reset_leave_source_unchanged() {
    for v in Version::supported(true) {
        let mut f = Fixture::new();
        f.engine.experimental_v3 = true;
        let id = create(
            &mut f.engine,
            v,
            vec![Node::date(
                PROCESS_START_DATE,
                keytend_kmip_server::store::now() + 500,
            )],
        );
        let before = f.engine.store.get("alice", &id).unwrap().unwrap();
        for (fields, expected) in [
            (vec![uid(&id), Node::interval(OFFSET, 1)], 0xb),
            (vec![uid(&id), Node::int(OFFSET, 1)], 7),
            (
                vec![
                    uid(&id),
                    Node::interval(OFFSET, 1),
                    container(v, vec![Node::date(ACTIVATION_DATE, 0)]),
                ],
                4,
            ),
            (
                vec![
                    uid(&id),
                    container(v, vec![Node::int(CRYPTOGRAPHIC_LENGTH, 129)]),
                ],
                7,
            ),
        ] {
            assert_eq!(
                reason(&call(&mut f.engine, v, "alice", 4, fields)),
                expected
            );
        }
        assert_eq!(
            reason(&call(&mut f.engine, v, "bob", 4, vec![uid(&id)])),
            not_found(v)
        );
        let after = f.engine.store.get("alice", &id).unwrap().unwrap();
        assert_eq!(
            serde_json::to_value(&before).unwrap(),
            serde_json::to_value(&after).unwrap()
        );
        for code in [1, 2] {
            let source = create(&mut f.engine, v, vec![]);
            payload(&call(&mut f.engine, v, "alice", 18, vec![uid(&source)]));
            let mut fields = vec![
                uid(&source),
                Node::structure(
                    REVOCATION_REASON,
                    vec![Node::enumeration(REVOCATION_REASON_CODE, code)],
                ),
            ];
            if code == 2 {
                fields.push(Node::date(
                    COMPROMISE_OCCURRENCE_DATE,
                    keytend_kmip_server::store::now() - 60,
                ));
            }
            payload(&call(&mut f.engine, v, "alice", 19, fields));
            let r = call(&mut f.engine, v, "alice", 4, vec![uid(&source)]);
            let o = f
                .engine
                .store
                .get(
                    "alice",
                    payload(&r)
                        .required(UNIQUE_IDENTIFIER)
                        .unwrap()
                        .identifier_text()
                        .unwrap(),
                )
                .unwrap()
                .unwrap();
            assert!(stored_date(&o, COMPROMISE_DATE).is_none());
            assert!(stored_date(&o, COMPROMISE_OCCURRENCE_DATE).is_none());
            assert_eq!(o.state, if code == 1 && v.0 < 3 { 3 } else { 2 });
        }
        let source = create(&mut f.engine, v, vec![]);
        let r = call(
            &mut f.engine,
            v,
            "alice",
            4,
            vec![
                uid(&source),
                container(
                    v,
                    vec![
                        Node::enumeration(CRYPTOGRAPHIC_ALGORITHM, 9),
                        Node::int(CRYPTOGRAPHIC_LENGTH, 512),
                        Node::int(CRYPTOGRAPHIC_USAGE_MASK, 128),
                    ],
                ),
            ],
        );
        let o = f
            .engine
            .store
            .get(
                "alice",
                payload(&r)
                    .required(UNIQUE_IDENTIFIER)
                    .unwrap()
                    .identifier_text()
                    .unwrap(),
            )
            .unwrap()
            .unwrap();
        assert_eq!(
            (o.algorithm, o.bits, o.usage, o.material.len()),
            (9, 512, 128, 64)
        );
        f.engine.store.verify_audit().unwrap();
    }
}

#[test]
fn rekey_failures_undo_and_response_limits_roll_back_both_records_and_history() {
    let mut f = Fixture::new();
    let v = Version(2, 1);
    let id = create(
        &mut f.engine,
        v,
        vec![Node::structure(
            NAME,
            vec![
                Node::text(NAME_VALUE, "atomic-history"),
                Node::enumeration(NAME_TYPE, 1),
            ],
        )],
    );
    payload(&call(&mut f.engine, v, "alice", 18, vec![uid(&id)]));
    let before = serde_json::to_value(f.engine.store.get("alice", &id).unwrap().unwrap()).unwrap();
    let conn = rusqlite::Connection::open(f._dir.path().join("keys.sqlite")).unwrap();
    conn.execute_batch("CREATE TRIGGER reject_new_object BEFORE INSERT ON objects BEGIN SELECT RAISE(ABORT,'injected insert failure'); END").unwrap();
    assert_eq!(
        reason(&call(&mut f.engine, v, "alice", 4, vec![uid(&id)])),
        0x100
    );
    conn.execute_batch("DROP TRIGGER reject_new_object")
        .unwrap();
    assert_eq!(
        serde_json::to_value(f.engine.store.get("alice", &id).unwrap().unwrap()).unwrap(),
        before
    );
    let r = f
        .engine
        .process(
            "alice",
            &batch_option(
                req(v, vec![(4, vec![uid(&id)]), (10, vec![uid("missing")])]),
                3,
            ),
        )
        .unwrap();
    let first = r.get(BATCH_ITEM).unwrap();
    assert_eq!(first.required(RESULT_STATUS).unwrap().number().unwrap(), 3);
    let undone_id = first
        .required(RESPONSE_PAYLOAD)
        .unwrap()
        .required(UNIQUE_IDENTIFIER)
        .unwrap()
        .identifier_text()
        .unwrap();
    assert!(f.engine.store.get("alice", undone_id).unwrap().is_none());
    assert_eq!(
        serde_json::to_value(f.engine.store.get("alice", &id).unwrap().unwrap()).unwrap(),
        before
    );
    let mut limited = req(v, vec![(4, vec![uid(&id)])]);
    if let Value::Structure(fields) = &mut limited.value
        && let Value::Structure(header) = &mut fields[0].value
    {
        header.push(Node::int(MAXIMUM_RESPONSE_SIZE, minimal_response_size(v)));
    }
    assert_eq!(reason(&f.engine.process("alice", &limited).unwrap()), 2);
    assert_eq!(
        serde_json::to_value(f.engine.store.get("alice", &id).unwrap().unwrap()).unwrap(),
        before
    );
    assert_eq!(f.engine.store.list("alice").unwrap().len(), 1);
    payload(&call(&mut f.engine, v, "alice", 4, vec![uid(&id)]));
    f.engine.store.verify_audit().unwrap();
}

#[test]
fn storage_insert_and_update_cannot_replace_an_existing_id_or_change_owner() {
    let mut f = Fixture::new();
    let id = create(&mut f.engine, Version(2, 1), vec![]);
    let mut object = f.engine.store.get("alice", &id).unwrap().unwrap();
    let before = object.material.clone();
    object.material.fill(0);
    assert!(f.engine.store.insert(&object).is_err());
    object.owner = "bob".into();
    assert!(f.engine.store.insert(&object).is_err());
    assert!(f.engine.store.put(&object).is_err());
    object.id = "missing-id".into();
    assert!(f.engine.store.put(&object).is_err());
    assert_eq!(
        f.engine.store.get("alice", &id).unwrap().unwrap().material,
        before
    );
    assert!(f.engine.store.get("bob", &id).unwrap().is_none());
}

#[test]
fn rekey_conflicting_history_overflow_and_capacity_errors_remain_atomic() {
    for v in Version::supported(true) {
        let mut f = Fixture::new();
        f.engine.experimental_v3 = true;
        let id = create(&mut f.engine, v, vec![]);
        let link = if v.0 >= 3 {
            Node::reference(REPLACED_OBJECT_LINK, "wrong-history")
        } else {
            history_link(0x107, "wrong-history")
        };
        assert_eq!(
            reason(&call(
                &mut f.engine,
                v,
                "alice",
                4,
                vec![uid(&id), container(v, vec![link])]
            )),
            7
        );
        let a = if v.0 >= 3 {
            Node::reference(REPLACEMENT_OBJECT_LINK, "one")
        } else {
            history_link(0x106, "one")
        };
        let b = if v.0 >= 3 {
            Node::reference(REPLACEMENT_OBJECT_LINK, "two")
        } else {
            history_link(0x106, "two")
        };
        payload(&call(
            &mut f.engine,
            v,
            "alice",
            13,
            vec![uid(&id), attribute_change(v, a)],
        ));
        assert_eq!(
            reason(&call(
                &mut f.engine,
                v,
                "alice",
                13,
                vec![uid(&id), attribute_change(v, b)]
            )),
            if v.0 >= 2 { 0x23 } else { 7 }
        );
        let mut o = f.engine.store.get("alice", &id).unwrap().unwrap();
        o.attrs.retain(|a| a.tag != LINK);
        o.attribute_indices.clear();
        o.attrs.extend([
            Node::date(ACTIVATION_DATE, 0),
            Node::date(PROCESS_START_DATE, i64::MAX),
        ]);
        f.engine.store.put(&o).unwrap();
        assert_eq!(
            reason(&call(
                &mut f.engine,
                v,
                "alice",
                4,
                vec![uid(&id), Node::interval(OFFSET, 1)]
            )),
            7
        );
        assert!(
            f.engine
                .store
                .get("alice", &id)
                .unwrap()
                .unwrap()
                .replacement_id
                .is_none()
        );
    }
    let mut f = Fixture::new();
    let v = Version(2, 1);
    let baseline = create(&mut f.engine, v, vec![]);
    let overhead = f
        .engine
        .store
        .get("alice", &baseline)
        .unwrap()
        .unwrap()
        .attrs
        .len();
    let a = (0..1024 - overhead)
        .map(|i| vendor_attribute("x", "capacity", Node::int(ATTRIBUTE_VALUE, i as i32)))
        .collect();
    let id = create(&mut f.engine, v, a);
    let before = serde_json::to_value(f.engine.store.get("alice", &id).unwrap().unwrap()).unwrap();
    assert_eq!(
        reason(&call(&mut f.engine, v, "alice", 4, vec![uid(&id)])),
        2
    );
    assert_eq!(
        serde_json::to_value(f.engine.store.get("alice", &id).unwrap().unwrap()).unwrap(),
        before
    );
    let name = |value: &str| {
        Node::structure(
            NAME,
            vec![
                Node::text(NAME_VALUE, value),
                Node::enumeration(NAME_TYPE, 1),
            ],
        )
    };
    let id = create(&mut f.engine, v, vec![name("retained-on-failure")]);
    create(&mut f.engine, v, vec![name("already-in-use")]);
    assert_eq!(
        reason(&call(
            &mut f.engine,
            v,
            "alice",
            4,
            vec![uid(&id), container(v, vec![name("already-in-use")])]
        )),
        0x35
    );
    let o = f.engine.store.get("alice", &id).unwrap().unwrap();
    assert!(o.replacement_id.is_none());
    assert!(o.attrs.contains(&name("retained-on-failure")));
    assert!(stored_link(&o, 0x106).is_none());
    f.engine.store.verify_audit().unwrap();
}

fn pair_source(v: Version, id: &str) -> Node {
    Node::text(
        if v.0 >= 3 {
            UNIQUE_IDENTIFIER
        } else {
            PRIVATE_KEY_UNIQUE_IDENTIFIER
        },
        id,
    )
}
fn pair_ids(n: &Node) -> (String, String) {
    let p = payload(n);
    (
        p.required(PRIVATE_KEY_UNIQUE_IDENTIFIER)
            .unwrap()
            .identifier_text()
            .unwrap()
            .to_owned(),
        p.required(PUBLIC_KEY_UNIQUE_IDENTIFIER)
            .unwrap()
            .identifier_text()
            .unwrap()
            .to_owned(),
    )
}
fn pair_container(v: Version, values: Vec<Node>) -> Node {
    if v.0 >= 2 {
        return container(v, values);
    }
    let fields = values
        .into_iter()
        .map(|a| {
            if a.tag == ATTRIBUTE {
                let vendor = a.required(VENDOR_IDENTIFICATION).unwrap().string().unwrap();
                let name = a.required(ATTRIBUTE_NAME).unwrap().string().unwrap();
                legacy_attribute(
                    &format!("{vendor}-{name}"),
                    a.required(ATTRIBUTE_VALUE).unwrap().clone(),
                    None,
                )
            } else {
                container(v, vec![a]).children().unwrap()[0].clone()
            }
        })
        .collect();
    Node::structure(TEMPLATE_ATTRIBUTE, fields)
}
fn pair_attributes(v: Version, private: bool, a: Vec<Node>) -> Node {
    let mut n = pair_container(v, a);
    n.tag = match (v.0 >= 2, private) {
        (true, true) => PRIVATE_KEY_ATTRIBUTES,
        (true, false) => PUBLIC_KEY_ATTRIBUTES,
        (false, true) => PRIVATE_KEY_TEMPLATE_ATTRIBUTE,
        (false, false) => PUBLIC_KEY_TEMPLATE_ATTRIBUTE,
    };
    n
}
fn pair_common(v: Version, a: Vec<Node>) -> Node {
    let mut n = pair_container(v, a);
    n.tag = if v.0 >= 2 {
        COMMON_ATTRIBUTES
    } else {
        COMMON_TEMPLATE_ATTRIBUTE
    };
    n
}

#[test]
fn rekey_pair_versions_preserve_originals_budgets_links_names_and_signatures() {
    for v in Version::supported(true)
        .into_iter()
        .filter(|v| *v >= Version(1, 1))
    {
        let mut f = Fixture::new();
        f.engine.experimental_v3 = true;
        let (private, public) = active_rsa_pair(&mut f.engine, v, vec![usage_limits(5, 2)]);
        let name = |value: &str| {
            Node::structure(
                NAME,
                vec![
                    Node::text(NAME_VALUE, value),
                    Node::enumeration(NAME_TYPE, 1),
                ],
            )
        };
        for (id, label) in [(&private, "private-history"), (&public, "public-history")] {
            payload(&call(
                &mut f.engine,
                v,
                "alice",
                13,
                vec![uid(id), attribute_change(v, name(label))],
            ));
        }
        payload(&call(
            &mut f.engine,
            v,
            "alice",
            17,
            vec![uid(&private), Node::long(USAGE_LIMITS_COUNT, 2)],
        ));
        let before_private = f.engine.store.get("alice", &private).unwrap().unwrap();
        let before_public = f.engine.store.get("alice", &public).unwrap().unwrap();
        let r = f
            .engine
            .process(
                "alice",
                &req(v, vec![(29, vec![pair_source(v, &private)]), (10, vec![])]),
            )
            .unwrap();
        let items = r.all(BATCH_ITEM).collect::<Vec<_>>();
        assert_eq!(items.len(), 2);
        let p = items[0].required(RESPONSE_PAYLOAD).unwrap();
        let next_private = p
            .required(PRIVATE_KEY_UNIQUE_IDENTIFIER)
            .unwrap()
            .identifier_text()
            .unwrap();
        let next_public = p
            .required(PUBLIC_KEY_UNIQUE_IDENTIFIER)
            .unwrap()
            .identifier_text()
            .unwrap();
        assert_eq!(
            items[1]
                .required(RESPONSE_PAYLOAD)
                .unwrap()
                .required(UNIQUE_IDENTIFIER)
                .unwrap()
                .identifier_text()
                .unwrap(),
            next_private
        );
        let a = f.engine.store.get("alice", next_private).unwrap().unwrap();
        let b = f.engine.store.get("alice", next_public).unwrap().unwrap();
        assert_eq!(a.state, 2);
        assert_eq!(b.state, 2);
        assert_ne!(a.material, before_private.material);
        assert_ne!(b.material, before_public.material);
        assert_eq!(a.created, b.created);
        assert_eq!(stored_link(&a, 0x102), Some(next_public));
        assert_eq!(stored_link(&b, 0x103), Some(next_private));
        for (old, new, before) in [
            (&private, &a, &before_private),
            (&public, &b, &before_public),
        ] {
            let source = f.engine.store.get("alice", old).unwrap().unwrap();
            assert_eq!(source.material, before.material);
            assert_eq!(source.state, before.state);
            assert_eq!(source.replacement_id.as_deref(), Some(new.id.as_str()));
            assert_eq!(stored_link(&source, 0x106), Some(new.id.as_str()));
            assert_eq!(stored_link(new, 0x107), Some(old.as_str()));
            assert!(!source.attrs.iter().any(|a| a.tag == NAME));
            assert!(new.attrs.iter().any(|a| a.tag == NAME));
            assert_eq!(
                stored_date(new, ACTIVATION_DATE),
                stored_date(before, ACTIVATION_DATE)
            );
        }
        assert_eq!(remaining(&mut f.engine, v, &private), 3);
        assert_eq!(remaining(&mut f.engine, v, next_private), 5);
        assert_eq!(remaining(&mut f.engine, v, next_public), 5);
        let secret = openssl::pkey::PKey::private_key_from_der(&a.material).unwrap();
        let public_key = rsa_public_key(&b.material);
        assert!(secret.public_eq(&public_key));
        let mut signer =
            openssl::sign::Signer::new(openssl::hash::MessageDigest::sha256(), &secret).unwrap();
        let signature = signer
            .sign_oneshot_to_vec(b"pair replacement proof")
            .unwrap();
        let mut verifier =
            openssl::sign::Verifier::new(openssl::hash::MessageDigest::sha256(), &public_key)
                .unwrap();
        assert!(
            verifier
                .verify_oneshot(&signature, b"pair replacement proof")
                .unwrap()
        );
        if v >= Version(1, 2) {
            let response = call(
                &mut f.engine,
                v,
                "alice",
                33,
                vec![
                    uid(next_private),
                    Node::structure(
                        CRYPTOGRAPHIC_PARAMETERS,
                        vec![
                            Node::enumeration(HASHING_ALGORITHM, 6),
                            Node::enumeration(PADDING_METHOD, 8),
                        ],
                    ),
                    Node::bytes(DATA, b"server pair signature".to_vec()),
                ],
            );
            let sig = payload(&response)
                .required(SIGNATURE_DATA)
                .unwrap()
                .byte_string()
                .unwrap();
            let mut verifier =
                openssl::sign::Verifier::new(openssl::hash::MessageDigest::sha256(), &public_key)
                    .unwrap();
            assert!(
                verifier
                    .verify_oneshot(sig, b"server pair signature")
                    .unwrap()
            );
        }
        assert_eq!(
            reason(&call(
                &mut f.engine,
                v,
                "alice",
                29,
                vec![pair_source(v, &private)]
            )),
            12
        );
        let path = f._dir.path().join("keys.sqlite");
        let key = f._dir.path().join("master");
        drop(f.engine);
        f.engine = Engine::new(Store::open(&path, &key).unwrap(), true);
        assert_eq!(
            f.engine
                .store
                .get("alice", next_private)
                .unwrap()
                .unwrap()
                .material,
            a.material
        );
        assert_eq!(
            reason(&call(
                &mut f.engine,
                v,
                "alice",
                29,
                vec![pair_source(v, &private)]
            )),
            12
        );
        f.engine.store.verify_audit().unwrap();
    }
}

#[test]
fn rekey_pair_offsets_and_request_union_preserve_key_specific_attributes() {
    for v in [Version(1, 1), Version(2, 1), Version(3, 0)] {
        let mut f = Fixture::new();
        f.engine.experimental_v3 = true;
        let (private, public) = active_rsa_pair(&mut f.engine, v, vec![]);
        for (id, duration) in [(&private, 1200), (&public, 2400)] {
            let mut object = f.engine.store.get("alice", id).unwrap().unwrap();
            let activation = stored_date(&object, ACTIVATION_DATE).unwrap();
            object
                .attrs
                .push(Node::date(DEACTIVATION_DATE, activation + duration));
            f.engine.store.put(&object).unwrap();
        }
        let r = call(
            &mut f.engine,
            v,
            "alice",
            29,
            vec![
                pair_source(v, &private),
                Node::interval(OFFSET, 3600),
                pair_common(
                    v,
                    vec![
                        Node::int(CRYPTOGRAPHIC_LENGTH, 3072),
                        Node::text(OBJECT_GROUP, "common"),
                        vendor_attribute("x", "union", Node::int(ATTRIBUTE_VALUE, 1)),
                    ],
                ),
                pair_attributes(
                    v,
                    true,
                    vec![
                        Node::int(CRYPTOGRAPHIC_USAGE_MASK, 1),
                        Node::text(OBJECT_GROUP, "private"),
                        Node::text(OBJECT_GROUP, "common"),
                        vendor_attribute("x", "union", Node::int(ATTRIBUTE_VALUE, 2)),
                    ],
                ),
                pair_attributes(
                    v,
                    false,
                    vec![
                        Node::int(CRYPTOGRAPHIC_USAGE_MASK, 2),
                        Node::text(OBJECT_GROUP, "public"),
                    ],
                ),
            ],
        );
        let (a, b) = pair_ids(&r);
        for (id, duration, mask, groups) in [
            (&a, 1200, 1, vec!["common", "private"]),
            (&b, 2400, 2, vec!["common", "public"]),
        ] {
            let object = f.engine.store.get("alice", id).unwrap().unwrap();
            assert_eq!(object.bits, 3072);
            assert_eq!(object.usage, mask);
            assert_eq!(object.state, 1);
            assert_eq!(
                stored_date(&object, ACTIVATION_DATE),
                Some(object.created + 3600)
            );
            assert_eq!(
                stored_date(&object, DEACTIVATION_DATE),
                Some(object.created + 3600 + duration)
            );
            let actual = object
                .attrs
                .iter()
                .filter(|a| a.tag == OBJECT_GROUP)
                .map(|n| n.string().unwrap())
                .collect::<Vec<_>>();
            assert_eq!(actual, groups);
        }
        assert_eq!(
            f.engine
                .store
                .get("alice", &a)
                .unwrap()
                .unwrap()
                .attrs
                .iter()
                .filter(|n| n.tag == ATTRIBUTE)
                .count(),
            2
        );
        assert_eq!(
            f.engine
                .store
                .get("alice", &b)
                .unwrap()
                .unwrap()
                .attrs
                .iter()
                .filter(|n| n.tag == ATTRIBUTE)
                .count(),
            1
        );
    }
}

#[test]
fn rekey_pair_owner_policy_peer_consistency_and_wrong_version_are_enforced() {
    let mut f = Fixture::new();
    let v = Version(2, 1);
    f.engine.experimental_v3 = true;
    let (private, public) = active_rsa_pair(&mut f.engine, v, vec![]);
    let snapshot = serde_json::to_value(f.engine.store.list("alice").unwrap()).unwrap();
    assert_eq!(
        reason(&call(
            &mut f.engine,
            Version(1, 0),
            "alice",
            29,
            vec![pair_source(Version(1, 0), &private)]
        )),
        5
    );
    assert_eq!(
        reason(&call(
            &mut f.engine,
            v,
            "bob",
            29,
            vec![pair_source(v, &private)]
        )),
        not_found(v)
    );
    let denied = f
        .engine
        .process_authorized(
            "alice",
            &req(v, vec![(29, vec![pair_source(v, &private)])]),
            Some(&[10]),
        )
        .unwrap();
    assert_eq!(reason(&denied), 12);
    assert_eq!(
        reason(&call(
            &mut f.engine,
            v,
            "alice",
            29,
            vec![pair_source(v, &public)]
        )),
        12
    );
    assert_eq!(
        reason(&call(&mut f.engine, v, "alice", 29, vec![uid(&private)])),
        8
    );
    assert_eq!(
        serde_json::to_value(f.engine.store.list("alice").unwrap()).unwrap(),
        snapshot
    );
    let original = f.engine.store.get("alice", &public).unwrap().unwrap();
    let (_, different) = active_rsa_pair(&mut f.engine, v, vec![]);
    let mut wrong = original.clone();
    wrong.material = f
        .engine
        .store
        .get("alice", &different)
        .unwrap()
        .unwrap()
        .material
        .clone();
    f.engine.store.put(&wrong).unwrap();
    assert_eq!(
        reason(&call(
            &mut f.engine,
            v,
            "alice",
            29,
            vec![pair_source(v, &private)]
        )),
        12
    );
    let mut wrong = original.clone();
    wrong.attrs.retain(|n| n.tag != LINK);
    f.engine.store.put(&wrong).unwrap();
    assert_eq!(
        reason(&call(
            &mut f.engine,
            v,
            "alice",
            29,
            vec![pair_source(v, &private)]
        )),
        12
    );
    let mut wrong = original.clone();
    wrong.material.clear();
    f.engine.store.put(&wrong).unwrap();
    assert_eq!(
        reason(&call(
            &mut f.engine,
            v,
            "alice",
            29,
            vec![pair_source(v, &private)]
        )),
        0x13
    );
    let mut wrong = original.clone();
    wrong.replacement_id = Some("retained-history".into());
    f.engine.store.put(&wrong).unwrap();
    assert_eq!(
        reason(&call(
            &mut f.engine,
            v,
            "alice",
            29,
            vec![pair_source(v, &private)]
        )),
        12
    );
    f.engine.store.put(&original).unwrap();
    assert!(
        f.engine
            .store
            .get("alice", &private)
            .unwrap()
            .unwrap()
            .replacement_id
            .is_none()
    );
    payload(&call(
        &mut f.engine,
        Version(3, 0),
        "alice",
        29,
        vec![pair_source(Version(3, 0), &public)],
    ));
    f.engine.store.verify_audit().unwrap();
}

#[test]
fn rekey_pair_second_insert_failure_undo_size_and_name_conflicts_roll_back_four_objects() {
    let mut f = Fixture::new();
    let v = Version(2, 1);
    let (private, _) = active_rsa_pair(&mut f.engine, v, vec![]);
    let snapshot = serde_json::to_value(f.engine.store.list("alice").unwrap()).unwrap();
    let conn = rusqlite::Connection::open(f._dir.path().join("keys.sqlite")).unwrap();
    conn.execute_batch("CREATE TRIGGER reject_second_pair_insert BEFORE INSERT ON objects WHEN (SELECT COUNT(*) FROM objects)>2 BEGIN SELECT RAISE(ABORT,'injected second insert failure'); END").unwrap();
    assert_eq!(
        reason(&call(
            &mut f.engine,
            v,
            "alice",
            29,
            vec![pair_source(v, &private)]
        )),
        0x100
    );
    conn.execute_batch("DROP TRIGGER reject_second_pair_insert")
        .unwrap();
    assert_eq!(
        serde_json::to_value(f.engine.store.list("alice").unwrap()).unwrap(),
        snapshot
    );
    let undone = f
        .engine
        .process(
            "alice",
            &batch_option(
                req(
                    v,
                    vec![
                        (29, vec![pair_source(v, &private)]),
                        (10, vec![uid("missing")]),
                    ],
                ),
                3,
            ),
        )
        .unwrap();
    let first = undone.get(BATCH_ITEM).unwrap();
    assert_eq!(first.required(RESULT_STATUS).unwrap().number().unwrap(), 3);
    let ids = first.required(RESPONSE_PAYLOAD).unwrap();
    for tag in [PRIVATE_KEY_UNIQUE_IDENTIFIER, PUBLIC_KEY_UNIQUE_IDENTIFIER] {
        assert!(
            f.engine
                .store
                .get(
                    "alice",
                    ids.required(tag).unwrap().identifier_text().unwrap()
                )
                .unwrap()
                .is_none()
        );
    }
    assert_eq!(
        serde_json::to_value(f.engine.store.list("alice").unwrap()).unwrap(),
        snapshot
    );
    let mut limited = req(v, vec![(29, vec![pair_source(v, &private)])]);
    if let Value::Structure(fields) = &mut limited.value
        && let Value::Structure(header) = &mut fields[0].value
    {
        header.push(Node::int(MAXIMUM_RESPONSE_SIZE, 256));
    }
    assert_eq!(reason(&f.engine.process("alice", &limited).unwrap()), 2);
    assert_eq!(
        serde_json::to_value(f.engine.store.list("alice").unwrap()).unwrap(),
        snapshot
    );
    let name = Node::structure(
        NAME,
        vec![
            Node::text(NAME_VALUE, "common-name-collision"),
            Node::enumeration(NAME_TYPE, 1),
        ],
    );
    assert_eq!(
        reason(&call(
            &mut f.engine,
            v,
            "alice",
            29,
            vec![pair_source(v, &private), pair_common(v, vec![name])]
        )),
        0x35
    );
    assert_eq!(
        serde_json::to_value(f.engine.store.list("alice").unwrap()).unwrap(),
        snapshot
    );
    f.engine.store.verify_audit().unwrap();
}

#[test]
fn rekey_pair_batch_factory_aliases_indices_and_expanded_generation_limit() {
    for v in [Version(2, 0), Version(2, 1), Version(3, 0)] {
        let mut f = Fixture::new();
        f.engine.experimental_v3 = true;
        let root = if v.0 >= 3 {
            UNIQUE_IDENTIFIER
        } else {
            PRIVATE_KEY_UNIQUE_IDENTIFIER
        };
        let request = req(
            v,
            vec![
                (
                    2,
                    vec![pair_common(
                        v,
                        vec![
                            Node::enumeration(CRYPTOGRAPHIC_ALGORITHM, 4),
                            Node::int(CRYPTOGRAPHIC_LENGTH, 2048),
                        ],
                    )],
                ),
                (29, vec![Node::enumeration(root, 5)]),
                (18, vec![Node::enumeration(UNIQUE_IDENTIFIER, 15)]),
                (10, vec![Node::enumeration(UNIQUE_IDENTIFIER, 16)]),
                (10, vec![Node::enumeration(UNIQUE_IDENTIFIER, 17)]),
            ],
        );
        let r = f.engine.process("alice", &request).unwrap();
        let items = r.all(BATCH_ITEM).collect::<Vec<_>>();
        assert_eq!(items.len(), 6);
        for item in &items {
            assert_eq!(item.required(RESULT_STATUS).unwrap().number().unwrap(), 0);
        }
        let ids = items[1].required(RESPONSE_PAYLOAD).unwrap();
        for (index, tag) in [
            (4, PRIVATE_KEY_UNIQUE_IDENTIFIER),
            (5, PUBLIC_KEY_UNIQUE_IDENTIFIER),
        ] {
            assert_eq!(
                items[index]
                    .required(RESPONSE_PAYLOAD)
                    .unwrap()
                    .required(UNIQUE_IDENTIFIER)
                    .unwrap()
                    .identifier_text()
                    .unwrap(),
                ids.required(tag).unwrap().identifier_text().unwrap()
            );
        }
        assert_eq!(
            reason(&call(
                &mut f.engine,
                v,
                "alice",
                29,
                vec![Node::int(root, 0)]
            )),
            7
        );
    }
    let mut f = Fixture::new();
    let v = Version(2, 1);
    for _ in 0..5 {
        active_rsa_pair(&mut f.engine, v, vec![]);
    }
    let request = req(
        v,
        vec![
            (
                8,
                vec![Node::structure(
                    ATTRIBUTES,
                    vec![Node::enumeration(OBJECT_TYPE, 4)],
                )],
            ),
            (
                29,
                vec![Node::enumeration(PRIVATE_KEY_UNIQUE_IDENTIFIER, 11)],
            ),
        ],
    );
    let response = f.engine.process("alice", &request).unwrap();
    let items: Vec<_> = response.all(BATCH_ITEM).collect();
    assert_eq!(items.len(), 6);
    for item in &items[..5] {
        assert_eq!(item.required(RESULT_STATUS).unwrap().number().unwrap(), 0);
    }
    assert_eq!(items[5].required(OPERATION).unwrap().number().unwrap(), 29);
    assert_eq!(
        items[5].required(RESULT_REASON).unwrap().number().unwrap(),
        0x3a
    );
    assert_eq!(f.engine.store.list("alice").unwrap().len(), 18);
    f.engine.store.verify_audit().unwrap();
}

#[test]
fn rekey_pair_pkcs1_registration_and_late_bound_draft_peer_links() {
    let mut f = Fixture::new();
    f.engine.experimental_v3 = true;
    let v = Version(3, 0);
    let key = openssl::rsa::Rsa::generate(2048).unwrap();
    let mut ids = vec![];
    for (kind, tag, name, material) in [
        (
            4,
            PRIVATE_KEY,
            "named-private",
            key.private_key_to_der().unwrap(),
        ),
        (
            3,
            PUBLIC_KEY,
            "named-public",
            key.public_key_to_der_pkcs1().unwrap(),
        ),
    ] {
        let r = call(
            &mut f.engine,
            v,
            "alice",
            3,
            vec![
                Node::enumeration(OBJECT_TYPE, kind),
                container(
                    v,
                    vec![
                        Node::text(NAME, name),
                        Node::int(CRYPTOGRAPHIC_USAGE_MASK, 15),
                    ],
                ),
                Node::structure(
                    tag,
                    vec![Node::structure(
                        KEY_BLOCK,
                        vec![
                            Node::enumeration(KEY_FORMAT_TYPE, 3),
                            Node::enumeration(CRYPTOGRAPHIC_ALGORITHM, 4),
                            Node::int(CRYPTOGRAPHIC_LENGTH, 2048),
                            Node::structure(KEY_VALUE, vec![Node::bytes(KEY_MATERIAL, material)]),
                        ],
                    )],
                ),
            ],
        );
        ids.push(
            payload(&r)
                .required(UNIQUE_IDENTIFIER)
                .unwrap()
                .identifier_text()
                .unwrap()
                .to_owned(),
        );
    }
    for (id, tag, name) in [
        (&ids[0], PUBLIC_KEY_LINK, "named-public"),
        (&ids[1], PRIVATE_KEY_LINK, "named-private"),
    ] {
        payload(&call(
            &mut f.engine,
            v,
            "alice",
            13,
            vec![
                uid(id),
                Node::structure(NEW_ATTRIBUTE, vec![Node::name_reference(tag, name)]),
            ],
        ));
    }
    let r = call(
        &mut f.engine,
        v,
        "alice",
        29,
        vec![Node::name_reference(UNIQUE_IDENTIFIER, "named-public")],
    );
    let (private, public) = pair_ids(&r);
    let a = f.engine.store.get("alice", &private).unwrap().unwrap();
    let b = f.engine.store.get("alice", &public).unwrap().unwrap();
    assert_eq!(a.format, 3);
    assert_eq!(b.format, 3);
    let a = openssl::rsa::Rsa::private_key_from_der(&a.material).unwrap();
    let b = openssl::rsa::Rsa::public_key_from_der_pkcs1(&b.material).unwrap();
    assert_eq!(a.n(), b.n());
    assert_eq!(a.e(), b.e());
    assert_eq!(
        f.engine
            .store
            .get("alice", &ids[0])
            .unwrap()
            .unwrap()
            .replacement_id
            .as_deref(),
        Some(private.as_str())
    );
}

fn aes_wrapping_parameters(padded: bool) -> Node {
    Node::structure(
        CRYPTOGRAPHIC_PARAMETERS,
        vec![Node::enumeration(
            BLOCK_CIPHER_MODE,
            if padded { 12 } else { 13 },
        )],
    )
}
fn register_wrapping_key(
    e: &mut Engine,
    v: Version,
    key: &[u8],
    mut extra: Vec<Node>,
    cp: Node,
) -> String {
    let mut a = vec![
        Node::enumeration(CRYPTOGRAPHIC_ALGORITHM, 3),
        Node::int(CRYPTOGRAPHIC_LENGTH, (key.len() * 8) as i32),
        Node::int(CRYPTOGRAPHIC_USAGE_MASK, 48),
        cp,
    ];
    a.append(&mut extra);
    let r = call(
        e,
        v,
        "alice",
        3,
        vec![
            Node::enumeration(OBJECT_TYPE, 2),
            pair_container(v, a),
            Node::structure(
                SYMMETRIC_KEY,
                vec![Node::structure(
                    KEY_BLOCK,
                    vec![
                        Node::enumeration(KEY_FORMAT_TYPE, 1),
                        Node::structure(KEY_VALUE, vec![Node::bytes(KEY_MATERIAL, key.to_vec())]),
                        Node::enumeration(CRYPTOGRAPHIC_ALGORITHM, 3),
                        Node::int(CRYPTOGRAPHIC_LENGTH, (key.len() * 8) as i32),
                    ],
                )],
            ),
        ],
    );
    payload(&r)
        .required(UNIQUE_IDENTIFIER)
        .unwrap()
        .identifier_text()
        .unwrap()
        .to_owned()
}
fn wrapping_spec(
    v: Version,
    key: &str,
    option: Option<u32>,
    cp: Option<Node>,
    selectors: Vec<Node>,
) -> Node {
    let mut info = vec![if v.0 >= 3 {
        Node::reference(UNIQUE_IDENTIFIER, key)
    } else {
        uid(key)
    }];
    if let Some(cp) = cp {
        info.push(cp);
    }
    let mut fields = vec![
        Node::enumeration(WRAPPING_METHOD, 1),
        Node::structure(ENCRYPTION_KEY_INFORMATION, info),
    ];
    if let Some(option) = option {
        fields.push(Node::enumeration(ENCODING_OPTION, option));
    }
    fields.extend(selectors);
    Node::structure(KEY_WRAPPING_SPECIFICATION, fields)
}
fn get_wrapped(e: &mut Engine, v: Version, id: &str, spec: Node, format: u32) -> Node {
    call(
        e,
        v,
        "alice",
        10,
        vec![uid(id), Node::enumeration(KEY_FORMAT_TYPE, format), spec],
    )
}
fn wrapped_object(response: &Node) -> Node {
    let p = payload(response);
    p.required(match p.required(OBJECT_TYPE).unwrap().number().unwrap() {
        2 => SYMMETRIC_KEY,
        3 => PUBLIC_KEY,
        4 => PRIVATE_KEY,
        7 => SECRET_DATA,
        _ => panic!("unexpected wrapped object"),
    })
    .unwrap()
    .clone()
}
fn register_wrapped(e: &mut Engine, v: Version, object: Node, attrs: Vec<Node>) -> Node {
    let kind = match object.tag {
        SYMMETRIC_KEY => 2,
        PUBLIC_KEY => 3,
        PRIVATE_KEY => 4,
        SECRET_DATA => 7,
        _ => panic!("bad wrapped type"),
    };
    call(
        e,
        v,
        "alice",
        3,
        vec![
            Node::enumeration(OBJECT_TYPE, kind),
            pair_container(v, attrs),
            object,
        ],
    )
}

// REQ:b3c8ff8f43cf8fc8 with No Encoding the wrapped Key Value is the bare key material, without attributes
// REQ:0ebefa2f9e5cd8e8 without Encoding Option the wrapped Key Value is a TTLV-encoded Key Value
// REQ:a15a41270251cc04 1.1 with No Encoding the wrapped Key Value is the bare key material, without attributes
// REQ:ae3a760f5f7e6b35 1.2+ with No Encoding the wrapped Key Value is the bare key material, without attributes
// REQ:0cb6d49c1cfc43f9 1.1 without Encoding Option the wrapped Key Value is TTLV-encoded
// REQ:6c5456b23ce1d90e 1.2+ without Encoding Option the wrapped Key Value is TTLV-encoded
#[test]
fn aes_wrapped_get_and_registration_support_all_versions_encodings_and_extraction_flags() {
    for v in Version::supported(true) {
        let mut f = Fixture::new();
        f.engine.experimental_v3 = true;
        let sensitive = if v >= Version(1, 4) {
            vec![Node::boolean(SENSITIVE, true)]
        } else {
            vec![]
        };
        let id = register_aes(&mut f.engine, v, vec![7; 32], sensitive);
        if v >= Version(1, 4) {
            assert_eq!(
                reason(&call(&mut f.engine, v, "alice", 10, vec![uid(&id)])),
                0x16
            );
        }
        for padded in [false, true] {
            let cp = aes_wrapping_parameters(padded);
            let key = register_wrapping_key(&mut f.engine, v, &[3; 32], vec![], cp.clone());
            payload(&call(&mut f.engine, v, "alice", 18, vec![uid(&key)]));
            let options = if v == Version(1, 0) {
                vec![None]
            } else {
                vec![None, Some(1), Some(2)]
            };
            for option in options {
                let r = get_wrapped(
                    &mut f.engine,
                    v,
                    &id,
                    wrapping_spec(v, &key, option, Some(cp.clone()), vec![]),
                    1,
                );
                let object = wrapped_object(&r);
                let block = object.required(KEY_BLOCK).unwrap();
                let ciphertext = block.required(KEY_VALUE).unwrap().byte_string().unwrap();
                let plain =
                    keytend_kmip_server::crypto::wrapping::aes(&[3; 32], ciphertext, padded, false)
                        .unwrap();
                if option == Some(1) {
                    assert_eq!(plain.as_slice(), [7; 32]);
                } else {
                    let value = keytend_kmip_server::ttlv::decode(&plain).unwrap();
                    assert_eq!(
                        value.required(KEY_MATERIAL).unwrap().byte_string().unwrap(),
                        [7; 32]
                    );
                }
                let r = register_wrapped(
                    &mut f.engine,
                    v,
                    object,
                    vec![Node::int(CRYPTOGRAPHIC_USAGE_MASK, 12)],
                );
                let imported = payload(&r)
                    .required(UNIQUE_IDENTIFIER)
                    .unwrap()
                    .identifier_text()
                    .unwrap();
                let stored = f.engine.store.get("alice", imported).unwrap().unwrap();
                assert_eq!(stored.material, vec![7; 32]);
                assert_ne!(imported, id);
                if v.0 >= 2 {
                    assert_eq!(stored_link(&stored, 0x10e), Some(key.as_str()));
                }
                assert_eq!(
                    f.engine.store.get("alice", &key).unwrap().unwrap().material,
                    vec![3; 32]
                );
            }
        }
        if v >= Version(1, 4) {
            let key = register_wrapping_key(
                &mut f.engine,
                v,
                &[3; 16],
                vec![],
                aes_wrapping_parameters(true),
            );
            let no = register_aes(
                &mut f.engine,
                v,
                vec![4; 16],
                vec![Node::boolean(EXTRACTABLE, false)],
            );
            assert_eq!(
                reason(&get_wrapped(
                    &mut f.engine,
                    v,
                    &no,
                    wrapping_spec(v, &key, None, None, vec![]),
                    1
                )),
                0x17
            );
            assert!(
                !f.engine
                    .store
                    .get("alice", &key)
                    .unwrap()
                    .unwrap()
                    .usage_consumed
            );
        }
        f.engine.store.verify_audit().unwrap();
    }
}

#[test]
fn wrapped_metadata_and_transparent_formats_preserve_identity_and_registration_overrides() {
    for v in [Version(1, 0), Version(1, 4), Version(2, 1), Version(3, 0)] {
        let mut f = Fixture::new();
        f.engine.experimental_v3 = true;
        let key = register_wrapping_key(
            &mut f.engine,
            v,
            &[3; 24],
            vec![],
            aes_wrapping_parameters(true),
        );
        payload(&call(&mut f.engine, v, "alice", 18, vec![uid(&key)]));
        let r = call(
            &mut f.engine,
            v,
            "alice",
            3,
            vec![
                Node::enumeration(OBJECT_TYPE, 2),
                pair_container(
                    v,
                    vec![
                        Node::int(CRYPTOGRAPHIC_USAGE_MASK, 12),
                        Node::text(OBJECT_GROUP, "one"),
                        Node::text(OBJECT_GROUP, "two"),
                        vendor_attribute("x", "colour", Node::text(ATTRIBUTE_VALUE, "red")),
                    ],
                ),
                Node::structure(
                    SYMMETRIC_KEY,
                    vec![Node::structure(
                        KEY_BLOCK,
                        vec![
                            Node::enumeration(KEY_FORMAT_TYPE, 1),
                            Node::structure(
                                KEY_VALUE,
                                vec![Node::bytes(KEY_MATERIAL, vec![9; 16])],
                            ),
                            Node::enumeration(CRYPTOGRAPHIC_ALGORITHM, 3),
                            Node::int(CRYPTOGRAPHIC_LENGTH, 128),
                        ],
                    )],
                ),
            ],
        );
        let id = payload(&r)
            .required(UNIQUE_IDENTIFIER)
            .unwrap()
            .identifier_text()
            .unwrap()
            .to_owned();
        let selectors = if v.0 >= 3 {
            vec![
                Node::enumeration(ATTRIBUTE_REFERENCE, OBJECT_GROUP),
                Node::structure(
                    ATTRIBUTE_REFERENCE,
                    vec![
                        Node::text(VENDOR_IDENTIFICATION, "x"),
                        Node::text(ATTRIBUTE_NAME, "colour"),
                    ],
                ),
            ]
        } else {
            vec![
                Node::text(ATTRIBUTE_NAME, "Object Group"),
                Node::text(ATTRIBUTE_NAME, "x-colour"),
            ]
        };
        let r = get_wrapped(
            &mut f.engine,
            v,
            &id,
            wrapping_spec(v, &key, None, None, selectors.clone()),
            7,
        );
        let object = wrapped_object(&r);
        let block = object.required(KEY_BLOCK).unwrap();
        let plain = keytend_kmip_server::crypto::wrapping::aes(
            &[3; 24],
            block.required(KEY_VALUE).unwrap().byte_string().unwrap(),
            true,
            false,
        )
        .unwrap();
        let value = keytend_kmip_server::ttlv::decode(&plain).unwrap();
        assert_eq!(
            value
                .required(KEY_MATERIAL)
                .unwrap()
                .required(KEY)
                .unwrap()
                .byte_string()
                .unwrap(),
            [9; 16]
        );
        assert_eq!(
            if v.0 == 1 {
                value.all(ATTRIBUTE).count()
            } else {
                value
                    .required(ATTRIBUTES)
                    .unwrap()
                    .children()
                    .unwrap()
                    .len()
            },
            3
        );
        let r = register_wrapped(
            &mut f.engine,
            v,
            object,
            vec![
                Node::int(CRYPTOGRAPHIC_USAGE_MASK, 12),
                Node::text(OBJECT_GROUP, "override"),
            ],
        );
        let stored = f
            .engine
            .store
            .get(
                "alice",
                payload(&r)
                    .required(UNIQUE_IDENTIFIER)
                    .unwrap()
                    .identifier_text()
                    .unwrap(),
            )
            .unwrap()
            .unwrap();
        assert_eq!(stored.material, vec![9; 16]);
        assert_eq!(stored.format, 7);
        assert_eq!(
            stored
                .attrs
                .iter()
                .filter(|n| n.tag == OBJECT_GROUP)
                .count(),
            1
        );
        assert!(stored.attrs.contains(&Node::text(OBJECT_GROUP, "override")));
        assert!(stored.attrs.contains(&vendor_attribute(
            "x",
            "colour",
            Node::text(ATTRIBUTE_VALUE, "red")
        )));
        if v >= Version(1, 1) {
            assert_eq!(
                reason(&get_wrapped(
                    &mut f.engine,
                    v,
                    &id,
                    wrapping_spec(v, &key, Some(1), None, selectors),
                    1
                )),
                // No Encoding with wrapped attributes: Encoding Option Error
                // (1.4 Table 338; listed in the 2.x Get table too).
                0x12
            );
            assert_eq!(
                reason(&get_wrapped(
                    &mut f.engine,
                    v,
                    &id,
                    wrapping_spec(v, &key, Some(1), None, vec![]),
                    7
                )),
                // No Encoding of transparent material: Encoding Option Error.
                0x12
            );
        }
    }
}

#[test]
fn rsa_oaep_wrapping_uses_owned_public_private_roles_and_preserves_parameters() {
    for v in Version::supported(true) {
        let mut f = Fixture::new();
        f.engine.experimental_v3 = true;
        let mut fields = vec![
            Node::enumeration(PADDING_METHOD, 2),
            Node::enumeration(HASHING_ALGORITHM, 6),
        ];
        if v >= Version(1, 4) {
            fields.extend([
                Node::enumeration(MASK_GENERATOR, 1),
                Node::enumeration(MASK_GENERATOR_HASHING_ALGORITHM, 6),
                Node::bytes(P_SOURCE, b"key transfer".to_vec()),
            ]);
        }
        let cp = Node::structure(CRYPTOGRAPHIC_PARAMETERS, fields);
        let pair = call(
            &mut f.engine,
            v,
            "alice",
            2,
            vec![
                pair_common(
                    v,
                    vec![
                        Node::enumeration(CRYPTOGRAPHIC_ALGORITHM, 4),
                        Node::int(CRYPTOGRAPHIC_LENGTH, 2048),
                        cp.clone(),
                    ],
                ),
                pair_attributes(v, true, vec![Node::int(CRYPTOGRAPHIC_USAGE_MASK, 32)]),
                pair_attributes(v, false, vec![Node::int(CRYPTOGRAPHIC_USAGE_MASK, 16)]),
            ],
        );
        let (private, public) = pair_ids(&pair);
        for id in [&private, &public] {
            payload(&call(&mut f.engine, v, "alice", 18, vec![uid(id)]));
        }
        let id = register_aes(&mut f.engine, v, vec![8; 32], vec![]);
        let r = get_wrapped(
            &mut f.engine,
            v,
            &id,
            wrapping_spec(v, &public, None, None, vec![]),
            1,
        );
        let object = wrapped_object(&r);
        let cipher = object
            .required(KEY_BLOCK)
            .unwrap()
            .required(KEY_VALUE)
            .unwrap()
            .byte_string()
            .unwrap();
        let secret = f.engine.store.get("alice", &private).unwrap().unwrap();
        let parameters = keytend_kmip_server::crypto::rsa::OaepParameters {
            hash: 6,
            mgf_hash: if v >= Version(1, 4) { 6 } else { 4 },
            label: if v >= Version(1, 4) {
                b"key transfer"
            } else {
                b""
            },
        };
        let plaintext =
            keytend_kmip_server::crypto::rsa::oaep_decrypt(&secret.material, parameters, cipher)
                .unwrap();
        assert_eq!(
            keytend_kmip_server::ttlv::decode(&plaintext)
                .unwrap()
                .required(KEY_MATERIAL)
                .unwrap()
                .byte_string()
                .unwrap(),
            [8; 32]
        );
        let r = register_wrapped(
            &mut f.engine,
            v,
            object,
            vec![Node::int(CRYPTOGRAPHIC_USAGE_MASK, 12)],
        );
        assert_eq!(
            f.engine
                .store
                .get(
                    "alice",
                    payload(&r)
                        .required(UNIQUE_IDENTIFIER)
                        .unwrap()
                        .identifier_text()
                        .unwrap()
                )
                .unwrap()
                .unwrap()
                .material,
            vec![8; 32]
        );
        assert!(
            !f.engine
                .store
                .get("alice", &private)
                .unwrap()
                .unwrap()
                .usage_consumed
        );
        assert!(
            f.engine
                .store
                .get("alice", &public)
                .unwrap()
                .unwrap()
                .usage_consumed
        );
        let mut wrong = secret.clone();
        wrong.usage = 1;
        f.engine.store.put(&wrong).unwrap();
        let r = get_wrapped(
            &mut f.engine,
            v,
            &id,
            wrapping_spec(v, &private, None, None, vec![]),
            1,
        );
        assert_eq!(reason(&r), if v.0 >= 2 { 0x29 } else { 12 });
        f.engine.store.verify_audit().unwrap();
    }
}

#[test]
fn wrapping_budgets_failures_policy_and_restart_are_atomic() {
    let mut f = Fixture::new();
    let v = Version(2, 1);
    let key = register_wrapping_key(
        &mut f.engine,
        v,
        &[3; 16],
        vec![usage_limits(2, 2)],
        aes_wrapping_parameters(true),
    );
    payload(&call(&mut f.engine, v, "alice", 18, vec![uid(&key)]));
    let id = register_aes(&mut f.engine, v, vec![4; 16], vec![]);
    let spec = wrapping_spec(v, &key, Some(1), None, vec![]);
    let r = get_wrapped(&mut f.engine, v, &id, spec.clone(), 1);
    let object = wrapped_object(&r);
    assert_eq!(remaining(&mut f.engine, v, &key), 1);
    let snapshot = serde_json::to_value(f.engine.store.list("alice").unwrap()).unwrap();
    let mut corrupted = object.clone();
    if let Value::Structure(fields) = &mut corrupted.value
        && let Value::Structure(fields) = &mut fields[0].value
    {
        for value in fields.iter_mut().filter(|n| n.tag == KEY_VALUE) {
            if let Value::ByteString(bytes) = &mut value.value {
                bytes[0] ^= 1;
            }
        }
    }
    assert_eq!(
        reason(&register_wrapped(
            &mut f.engine,
            v,
            corrupted,
            vec![Node::int(CRYPTOGRAPHIC_USAGE_MASK, 12)]
        )),
        10
    );
    assert_eq!(
        serde_json::to_value(f.engine.store.list("alice").unwrap()).unwrap(),
        snapshot
    );
    let request = req(v, vec![(10, vec![uid(&id), spec.clone()])]);
    assert_eq!(
        reason(
            &f.engine
                .process_authorized("alice", &request, Some(&[3]))
                .unwrap()
        ),
        12
    );
    let mut limited = request.clone();
    if let Value::Structure(fields) = &mut limited.value
        && let Value::Structure(header) = &mut fields[0].value
    {
        header.push(Node::int(MAXIMUM_RESPONSE_SIZE, 256));
    }
    assert_eq!(reason(&f.engine.process("alice", &limited).unwrap()), 2);
    assert_eq!(remaining(&mut f.engine, v, &key), 1);
    let denied = f
        .engine
        .process(
            "bob",
            &req(
                v,
                vec![(
                    3,
                    vec![
                        Node::enumeration(OBJECT_TYPE, 2),
                        container(v, vec![Node::int(CRYPTOGRAPHIC_USAGE_MASK, 12)]),
                        object,
                    ],
                )],
            ),
        )
        .unwrap();
    // 2.1 Wrapping Object Not Found: a foreign wrapping key looks missing.
    assert_eq!(reason(&denied), 0x42);
    payload(&get_wrapped(&mut f.engine, v, &id, spec.clone(), 1));
    assert_eq!(remaining(&mut f.engine, v, &key), 0);
    assert_eq!(
        reason(&get_wrapped(&mut f.engine, v, &id, spec.clone(), 1)),
        0x1a
    );
    let path = f._dir.path().join("keys.sqlite");
    let master = f._dir.path().join("master");
    drop(f.engine);
    f.engine = Engine::new(Store::open(&path, &master).unwrap(), false);
    assert_eq!(remaining(&mut f.engine, v, &key), 0);
    assert_eq!(reason(&get_wrapped(&mut f.engine, v, &id, spec, 1)), 0x1a);
    f.engine.store.verify_audit().unwrap();
}

#[test]
fn wrapped_get_undo_keeps_kek_charge_and_import_undo_rolls_back() {
    let mut f = Fixture::new();
    let v = Version(2, 1);
    let key = register_wrapping_key(
        &mut f.engine,
        v,
        &[3; 32],
        vec![usage_limits(3, 2)],
        aes_wrapping_parameters(true),
    );
    payload(&call(&mut f.engine, v, "alice", 18, vec![uid(&key)]));
    let id = register_aes(&mut f.engine, v, vec![6; 32], vec![]);
    let spec = wrapping_spec(v, &key, None, None, vec![]);
    let r = f
        .engine
        .process(
            "alice",
            &batch_option(
                req(
                    v,
                    vec![
                        (10, vec![uid(&id), spec.clone()]),
                        (10, vec![uid("missing")]),
                    ],
                ),
                3,
            ),
        )
        .unwrap();
    // The undone Get keeps its wrapped payload, so the wrap keeps its charge.
    assert_eq!(statuses(&r), vec![3, 1]);
    let undone = r
        .get(BATCH_ITEM)
        .unwrap()
        .required(RESPONSE_PAYLOAD)
        .unwrap();
    assert!(
        undone
            .required(SYMMETRIC_KEY)
            .unwrap()
            .required(KEY_BLOCK)
            .unwrap()
            .get(KEY_WRAPPING_DATA)
            .is_some()
    );
    assert_eq!(remaining(&mut f.engine, v, &key), 2);
    let object = wrapped_object(&get_wrapped(&mut f.engine, v, &id, spec.clone(), 1));
    let r = f
        .engine
        .process(
            "alice",
            &batch_option(
                req(
                    v,
                    vec![
                        (
                            3,
                            vec![
                                Node::enumeration(OBJECT_TYPE, 2),
                                container(v, vec![Node::int(CRYPTOGRAPHIC_USAGE_MASK, 12)]),
                                object,
                            ],
                        ),
                        (10, vec![uid("missing")]),
                    ],
                ),
                3,
            ),
        )
        .unwrap();
    let first = r.get(BATCH_ITEM).unwrap();
    assert_eq!(first.required(RESULT_STATUS).unwrap().number().unwrap(), 3);
    let undone = first
        .required(RESPONSE_PAYLOAD)
        .unwrap()
        .required(UNIQUE_IDENTIFIER)
        .unwrap()
        .identifier_text()
        .unwrap();
    assert!(f.engine.store.get("alice", undone).unwrap().is_none());
    assert_eq!(remaining(&mut f.engine, v, &key), 1);
    // The last unit is spent by the first wrap; the second wrap is refused
    // and the batch is undone. No later failing batch obtains another wrap.
    let twice = batch_option(
        req(
            v,
            vec![
                (10, vec![uid(&id), spec.clone()]),
                (10, vec![uid(&id), spec]),
            ],
        ),
        3,
    );
    let r = f.engine.process("alice", &twice).unwrap();
    assert_eq!(statuses(&r), vec![3, 1]);
    assert_eq!(
        r.all(BATCH_ITEM)
            .nth(1)
            .unwrap()
            .required(RESULT_REASON)
            .unwrap()
            .number()
            .unwrap(),
        0x1a
    );
    assert_eq!(remaining(&mut f.engine, v, &key), 0);
    let r = f.engine.process("alice", &twice).unwrap();
    assert_eq!(statuses(&r), vec![1]);
    assert_eq!(remaining(&mut f.engine, v, &key), 0);
    f.engine.store.verify_audit().unwrap();
}

// REQ:72a7c647431b7021 2.x wrapping parameters given in the request must match one stored instance of the key
// REQ:31036bbf743b74ee 1.x wrapping parameters given in the request must match one stored instance of the key
// REQ:7e48efcd4d0a3d29 1.x without request parameters the key's lowest-index Cryptographic Parameters are used
#[test]
fn wrapping_parameter_selection_versioned_references_and_validation_are_strict() {
    for v in Version::supported(true) {
        let mut f = Fixture::new();
        f.engine.experimental_v3 = true;
        let cp = aes_wrapping_parameters(true);
        let key = register_wrapping_key(&mut f.engine, v, &[2; 16], vec![], cp.clone());
        payload(&call(&mut f.engine, v, "alice", 18, vec![uid(&key)]));
        let id = register_aes(&mut f.engine, v, vec![5; 16], vec![]);
        let before = serde_json::to_value(f.engine.store.list("alice").unwrap()).unwrap();
        assert_eq!(
            reason(&get_wrapped(
                &mut f.engine,
                v,
                &id,
                wrapping_spec(v, &key, None, Some(aes_wrapping_parameters(false)), vec![]),
                1
            )),
            if v.0 == 1 { 1 } else { 7 }
        );
        assert_eq!(
            serde_json::to_value(f.engine.store.list("alice").unwrap()).unwrap(),
            before
        );
        if v == Version(1, 0) {
            assert_eq!(
                reason(&get_wrapped(
                    &mut f.engine,
                    v,
                    &id,
                    wrapping_spec(v, &key, Some(1), None, vec![]),
                    1
                )),
                7
            );
        }
        let mut no = f.engine.store.get("alice", &key).unwrap().unwrap();
        no.attrs.retain(|n| n.tag != CRYPTOGRAPHIC_PARAMETERS);
        f.engine.store.put(&no).unwrap();
        assert_eq!(
            reason(&get_wrapped(
                &mut f.engine,
                v,
                &id,
                wrapping_spec(v, &key, None, None, vec![]),
                1
            )),
            if v.0 == 1 { 1 } else { 7 }
        );
        assert_eq!(
            reason(&get_wrapped(
                &mut f.engine,
                v,
                &id,
                wrapping_spec(v, &key, None, Some(cp.clone()), vec![]),
                1
            )),
            if v.0 == 1 { 1 } else { 7 }
        );
        no.attrs
            .extend([aes_wrapping_parameters(false), cp.clone()]);
        no.attribute_indices
            .insert(format!("s:{CRYPTOGRAPHIC_PARAMETERS:06x}"), vec![3, 1]);
        f.engine.store.put(&no).unwrap();
        let r = get_wrapped(
            &mut f.engine,
            v,
            &id,
            wrapping_spec(v, &key, None, None, vec![]),
            1,
        );
        assert_eq!(
            wrapped_object(&r)
                .required(KEY_BLOCK)
                .unwrap()
                .required(KEY_WRAPPING_DATA)
                .unwrap()
                .required(ENCRYPTION_KEY_INFORMATION)
                .unwrap()
                .required(CRYPTOGRAPHIC_PARAMETERS)
                .unwrap()
                .required(BLOCK_CIPHER_MODE)
                .unwrap()
                .number()
                .unwrap(),
            12
        );
        if v.0 >= 2 {
            let spec = Node::structure(
                KEY_WRAPPING_SPECIFICATION,
                vec![
                    Node::enumeration(WRAPPING_METHOD, 1),
                    Node::structure(
                        ENCRYPTION_KEY_INFORMATION,
                        vec![Node::int(UNIQUE_IDENTIFIER, 0)],
                    ),
                ],
            );
            let r = f
                .engine
                .process(
                    "alice",
                    &req(v, vec![(10, vec![uid(&key)]), (10, vec![uid(&id), spec])]),
                )
                .unwrap();
            assert_eq!(
                r.all(BATCH_ITEM)
                    .last()
                    .unwrap()
                    .required(RESULT_STATUS)
                    .unwrap()
                    .number()
                    .unwrap(),
                0
            );
        }
        if v.0 >= 3 {
            payload(&call(
                &mut f.engine,
                v,
                "alice",
                13,
                vec![
                    uid(&key),
                    Node::structure(NEW_ATTRIBUTE, vec![Node::text(NAME, "named-wrapping-key")]),
                ],
            ));
            let spec = Node::structure(
                KEY_WRAPPING_SPECIFICATION,
                vec![
                    Node::enumeration(WRAPPING_METHOD, 1),
                    Node::structure(
                        ENCRYPTION_KEY_INFORMATION,
                        vec![Node::name_reference(
                            UNIQUE_IDENTIFIER,
                            "named-wrapping-key",
                        )],
                    ),
                ],
            );
            // REQ: docs/interpretations.md (Key Wrapping Data): a wrapping key is never
            // named by Name Reference.
            assert_eq!(reason(&get_wrapped(&mut f.engine, v, &id, spec, 1)), 7);
            // Identifier and Reference are accepted; the response uses
            // Identifier, as the OASIS trace AX-M-2-30 does.
            for named in [
                Node::identifier(UNIQUE_IDENTIFIER, &key),
                Node::reference(UNIQUE_IDENTIFIER, &key),
            ] {
                let spec = Node::structure(
                    KEY_WRAPPING_SPECIFICATION,
                    vec![
                        Node::enumeration(WRAPPING_METHOD, 1),
                        Node::structure(ENCRYPTION_KEY_INFORMATION, vec![named]),
                    ],
                );
                let r = get_wrapped(&mut f.engine, v, &id, spec, 1);
                assert!(
                    wrapped_object(&r)
                        .required(KEY_BLOCK)
                        .unwrap()
                        .required(KEY_WRAPPING_DATA)
                        .unwrap()
                        .required(ENCRYPTION_KEY_INFORMATION)
                        .unwrap()
                        .required(UNIQUE_IDENTIFIER)
                        .unwrap()
                        .value
                        == Value::Identifier(key.clone())
                );
            }
        }
    }
}

#[test]
fn wrapping_counts_encoded_bytes_and_denies_wrong_roles_and_invalid_envelopes() {
    let mut f = Fixture::new();
    let v = Version(2, 1);
    let key = register_wrapping_key(
        &mut f.engine,
        v,
        &[3; 16],
        vec![usage_limits(48, 1)],
        aes_wrapping_parameters(true),
    );
    payload(&call(&mut f.engine, v, "alice", 18, vec![uid(&key)]));
    let id = register_aes(&mut f.engine, v, vec![7; 32], vec![]);
    let r = get_wrapped(
        &mut f.engine,
        v,
        &id,
        wrapping_spec(v, &key, None, None, vec![]),
        1,
    );
    let object = wrapped_object(&r);
    assert_eq!(remaining(&mut f.engine, v, &key), 0);
    let mut wrapper = f.engine.store.get("alice", &key).unwrap().unwrap();
    wrapper.usage = 16;
    f.engine.store.put(&wrapper).unwrap();
    assert_eq!(
        reason(&register_wrapped(
            &mut f.engine,
            v,
            object.clone(),
            vec![Node::int(CRYPTOGRAPHIC_USAGE_MASK, 12)]
        )),
        0x29
    );
    wrapper.usage = 32;
    f.engine.store.put(&wrapper).unwrap();
    assert_eq!(
        reason(&get_wrapped(
            &mut f.engine,
            v,
            &id,
            wrapping_spec(v, &key, None, None, vec![]),
            1
        )),
        0x29
    );
    wrapper.usage = 48;
    f.engine.store.put(&wrapper).unwrap();
    let before = f.engine.store.list("alice").unwrap().len();
    let mut invalid = object;
    if let Value::Structure(fields) = &mut invalid.value
        && let Value::Structure(block) = &mut fields[0].value
    {
        let empty = Node::structure(KEY_VALUE, vec![]).encode();
        let encrypted =
            keytend_kmip_server::crypto::wrapping::aes(&[3; 16], &empty, true, true).unwrap();
        for field in block.iter_mut().filter(|n| n.tag == KEY_VALUE) {
            *field = Node::bytes(KEY_VALUE, encrypted.to_vec());
        }
    }
    assert_eq!(
        reason(&register_wrapped(
            &mut f.engine,
            v,
            invalid,
            vec![Node::int(CRYPTOGRAPHIC_USAGE_MASK, 12)]
        )),
        7
    );
    assert_eq!(f.engine.store.list("alice").unwrap().len(), before);
    assert_eq!(remaining(&mut f.engine, v, &key), 0);
    f.engine.store.verify_audit().unwrap();
}

fn transfer_import_fields(
    v: Version,
    exported: &Node,
    id: &str,
    replace: bool,
    wrap: Option<u32>,
) -> Vec<Node> {
    let renamed = exported
        .required(UNIQUE_IDENTIFIER)
        .unwrap()
        .identifier_text()
        .unwrap()
        != id;
    let mut fields = exported.children().unwrap().to_vec();
    fields.retain(|n| n.tag != UNIQUE_IDENTIFIER);
    fields.insert(0, uid(id));
    if v.0 == 1 {
        fields.retain(|n| n.tag != OBJECT_TYPE);
    }
    for n in &mut fields {
        if v.0 == 1
            && n.tag == ATTRIBUTE
            && n.get(ATTRIBUTE_NAME).unwrap().string().unwrap() == "Unique Identifier"
        {
            if let Value::Structure(a) = &mut n.value {
                *a.iter_mut().find(|n| n.tag == ATTRIBUTE_VALUE).unwrap() =
                    Node::text(ATTRIBUTE_VALUE, id);
            }
        } else if n.tag == ATTRIBUTES
            && let Value::Structure(a) = &mut n.value
        {
            for n in a {
                if n.tag == UNIQUE_IDENTIFIER {
                    *n = uid(id);
                }
                if n.tag == SHORT_UNIQUE_IDENTIFIER && renamed {
                    *n = Node::bytes(
                        SHORT_UNIQUE_IDENTIFIER,
                        openssl::sha::sha256(id.as_bytes()).to_vec(),
                    );
                }
            }
        }
    }
    if replace {
        fields.push(Node::boolean(REPLACE_EXISTING, true));
    }
    if let Some(wrap) = wrap {
        fields.push(Node::enumeration(KEY_WRAP_TYPE, wrap));
    }
    fields
}
fn transfer_edit_attrs(v: Version, fields: &mut [Node], tag: u32, value: Option<Node>) {
    if v.0 == 1 {
        for n in fields {
            if n.tag == ATTRIBUTE
                && n.get(ATTRIBUTE_NAME).unwrap().string().unwrap() == tag_name(tag).unwrap()
                && let Value::Structure(a) = &mut n.value
            {
                let mut value = value.clone().unwrap();
                value.tag = ATTRIBUTE_VALUE;
                *a.iter_mut().find(|n| n.tag == ATTRIBUTE_VALUE).unwrap() = value;
            }
        }
    } else {
        let a = fields.iter_mut().find(|n| n.tag == ATTRIBUTES).unwrap();
        if let Value::Structure(a) = &mut a.value {
            a.retain(|n| n.tag != tag);
            if let Some(value) = value {
                a.push(value);
            }
        }
    }
}
#[test]
fn import_export_versions_preserve_dates_usage_metadata_and_explicit_ids() {
    for v in [Version(1, 4), Version(2, 0), Version(2, 1), Version(3, 0)] {
        let mut f = Fixture::new();
        f.engine.experimental_v3 = true;
        let id = create(&mut f.engine, v, vec![usage_limits(10, 2)]);
        payload(&call(&mut f.engine, v, "alice", 18, vec![uid(&id)]));
        payload(&call(
            &mut f.engine,
            v,
            "alice",
            17,
            vec![uid(&id), Node::long(USAGE_LIMITS_COUNT, 3)],
        ));
        let original = f.engine.store.get("alice", &id).unwrap().unwrap();
        let exported = call(&mut f.engine, v, "alice", 43, vec![uid(&id)]);
        let mut fields = transfer_import_fields(v, payload(&exported), "restored", false, None);
        transfer_edit_attrs(
            v,
            &mut fields,
            INITIAL_DATE,
            Some(Node::date(INITIAL_DATE, 100)),
        );
        transfer_edit_attrs(
            v,
            &mut fields,
            LAST_CHANGE_DATE,
            Some(Node::date(LAST_CHANGE_DATE, 200)),
        );
        payload(&call(&mut f.engine, v, "alice", 42, fields));
        let restored = f.engine.store.get("alice", "restored").unwrap().unwrap();
        assert_eq!(restored.material, original.material);
        assert_eq!(restored.created, 100);
        assert_eq!(restored.updated, 200);
        assert_eq!(restored.state, 2);
        assert!(restored.imported);
        assert!(restored.usage_consumed);
        assert_eq!(remaining(&mut f.engine, v, "restored"), 7);
        let again = call(&mut f.engine, v, "alice", 43, vec![uid("restored")]);
        let fields = transfer_import_fields(v, payload(&again), "restored", true, None);
        payload(&call(&mut f.engine, v, "alice", 42, fields));
        assert_eq!(remaining(&mut f.engine, v, "restored"), 7);
        f.engine.store.verify_audit().unwrap();
    }
    let mut f = Fixture::new();
    for v in [Version(1, 0), Version(1, 1), Version(1, 2), Version(1, 3)] {
        assert_eq!(reason(&call(&mut f.engine, v, "alice", 42, vec![])), 5);
        assert_eq!(reason(&call(&mut f.engine, v, "alice", 43, vec![])), 5);
    }
}
/// NUL is reserved for the server's hidden record identifiers (records.rs):
/// an imported identifier containing it is Invalid Field, so a client can
/// never occupy a record's identifier.
#[test]
fn import_refuses_identifiers_containing_nul() {
    for v in [Version(1, 4), Version(2, 1), Version(3, 0)] {
        let mut f = Fixture::new();
        f.engine.experimental_v3 = true;
        let id = create(&mut f.engine, v, vec![]);
        let exported = call(&mut f.engine, v, "alice", 43, vec![uid(&id)]);
        for hostile in ["constraints\0\0server", "fingerprint\0abc", "\0"] {
            let fields = transfer_import_fields(v, payload(&exported), hostile, false, None);
            assert_eq!(
                reason(&call(&mut f.engine, v, "alice", 42, fields)),
                7,
                "{v:?} {hostile:?}"
            );
            assert!(f.engine.store.owner_of(hostile).unwrap().is_none());
        }
    }
}
#[test]
fn import_collision_owner_invalid_replacement_undo_and_response_overflow_are_atomic() {
    let mut f = Fixture::new();
    let v = Version(2, 1);
    let id = create(&mut f.engine, v, vec![]);
    let original = f.engine.store.get("alice", &id).unwrap().unwrap();
    let exported = call(&mut f.engine, v, "alice", 43, vec![uid(&id)]);
    let fields = transfer_import_fields(v, payload(&exported), &id, false, None);
    assert_eq!(reason(&call(&mut f.engine, v, "alice", 42, fields)), 24);
    let fields = transfer_import_fields(v, payload(&exported), &id, true, None);
    assert_eq!(reason(&call(&mut f.engine, v, "bob", 42, fields)), 12);
    let mut fields = transfer_import_fields(v, payload(&exported), &id, true, None);
    let key = fields.iter_mut().find(|n| n.tag == SYMMETRIC_KEY).unwrap();
    if let Value::Structure(fields) = &mut key.value {
        let block = fields.iter_mut().find(|n| n.tag == KEY_BLOCK).unwrap();
        if let Value::Structure(fields) = &mut block.value {
            *fields.iter_mut().find(|n| n.tag == KEY_VALUE).unwrap() =
                Node::structure(KEY_VALUE, vec![Node::bytes(KEY_MATERIAL, vec![1; 16])]);
        }
    }
    assert_eq!(reason(&call(&mut f.engine, v, "alice", 42, fields)), 7);
    assert_eq!(
        f.engine.store.get("alice", &id).unwrap().unwrap().material,
        original.material
    );
    let fields = transfer_import_fields(v, payload(&exported), "undo-import", false, None);
    let response = f
        .engine
        .process(
            "alice",
            &batch_option(req(v, vec![(42, fields), (10, vec![uid("missing")])]), 3),
        )
        .unwrap();
    assert_eq!(
        response
            .get(BATCH_ITEM)
            .unwrap()
            .required(RESULT_STATUS)
            .unwrap()
            .number()
            .unwrap(),
        3
    );
    assert!(
        f.engine
            .store
            .get("alice", "undo-import")
            .unwrap()
            .is_none()
    );
    let fields = transfer_import_fields(v, payload(&exported), "overflow-import", false, None);
    let mut request = req(v, vec![(42, fields)]);
    if let Value::Structure(fields) = &mut request.value
        && let Value::Structure(header) = &mut fields[0].value
    {
        header.push(Node::int(MAXIMUM_RESPONSE_SIZE, minimal_response_size(v)));
    }
    assert_eq!(reason(&f.engine.process("alice", &request).unwrap()), 2);
    assert!(
        f.engine
            .store
            .get("alice", "overflow-import")
            .unwrap()
            .is_none()
    );
    f.engine.store.verify_audit().unwrap();
}
#[test]
fn opaque_import_keeps_ciphertext_after_use_restart_and_wrapping_key_destruction() {
    for v in [Version(1, 4), Version(2, 0), Version(2, 1), Version(3, 0)] {
        let mut f = Fixture::new();
        f.engine.experimental_v3 = true;
        let kek = register_wrapping_key(
            &mut f.engine,
            v,
            &[3; 32],
            vec![],
            aes_wrapping_parameters(true),
        );
        payload(&call(&mut f.engine, v, "alice", 18, vec![uid(&kek)]));
        let id = register_aes(&mut f.engine, v, vec![6; 32], vec![]);
        let exported = call(
            &mut f.engine,
            v,
            "alice",
            43,
            vec![uid(&id), wrapping_spec(v, &kek, Some(2), None, vec![])],
        );
        let expected = payload(&exported).required(SYMMETRIC_KEY).unwrap().clone();
        let fields = transfer_import_fields(
            v,
            payload(&exported),
            "opaque-import",
            false,
            if v.0 == 1 { None } else { Some(2) },
        );
        payload(&call(&mut f.engine, v, "alice", 42, fields));
        let stored = f
            .engine
            .store
            .get("alice", "opaque-import")
            .unwrap()
            .unwrap();
        assert!(stored.material.is_empty());
        assert!(stored.wrapped.as_ref().unwrap().opaque);
        assert_eq!(key(&mut f.engine, v, "opaque-import"), vec![6; 32]);
        payload(&call(
            &mut f.engine,
            v,
            "alice",
            18,
            vec![uid("opaque-import")],
        ));
        let parameters = Node::structure(
            CRYPTOGRAPHIC_PARAMETERS,
            vec![
                Node::enumeration(BLOCK_CIPHER_MODE, 1),
                Node::enumeration(PADDING_METHOD, 3),
            ],
        );
        payload(&call(
            &mut f.engine,
            v,
            "alice",
            31,
            vec![
                uid("opaque-import"),
                parameters,
                Node::bytes(IV_COUNTER_NONCE, vec![0; 16]),
                Node::bytes(DATA, vec![7; 16]),
            ],
        ));
        assert!(
            f.engine
                .store
                .get("alice", "opaque-import")
                .unwrap()
                .unwrap()
                .material
                .is_empty()
        );
        let path = f._dir.path().join("keys.sqlite");
        let master = f._dir.path().join("master");
        drop(f.engine);
        f.engine = Engine::new(Store::open(&path, &master).unwrap(), true);
        assert_eq!(key(&mut f.engine, v, "opaque-import"), vec![6; 32]);
        payload(&call(
            &mut f.engine,
            v,
            "alice",
            19,
            vec![
                uid(&kek),
                Node::structure(
                    REVOCATION_REASON,
                    vec![Node::enumeration(REVOCATION_REASON_CODE, 1)],
                ),
            ],
        ));
        payload(&call(&mut f.engine, v, "alice", 20, vec![uid(&kek)]));
        assert_eq!(
            reason(&call(
                &mut f.engine,
                v,
                "alice",
                10,
                vec![uid("opaque-import")]
            )),
            0x13
        );
        let r = call(
            &mut f.engine,
            v,
            "alice",
            10,
            vec![uid("opaque-import"), Node::enumeration(KEY_WRAP_TYPE, 2)],
        );
        assert!(payload(&r).required(SYMMETRIC_KEY).unwrap() == &expected);
        payload(&call(
            &mut f.engine,
            v,
            "alice",
            11,
            vec![uid("opaque-import")],
        ));
        payload(&call(
            &mut f.engine,
            v,
            "alice",
            19,
            vec![
                uid("opaque-import"),
                Node::structure(
                    REVOCATION_REASON,
                    vec![Node::enumeration(REVOCATION_REASON_CODE, 1)],
                ),
            ],
        ));
        payload(&call(
            &mut f.engine,
            v,
            "alice",
            20,
            vec![uid("opaque-import")],
        ));
        assert!(
            f.engine
                .store
                .get("alice", "opaque-import")
                .unwrap()
                .unwrap()
                .wrapped
                .is_none()
        );
    }
}
#[test]
fn import_not_wrapped_validates_before_store_and_register_retains_original_envelope() {
    for v in [Version(1, 4), Version(2, 1), Version(3, 0)] {
        let mut f = Fixture::new();
        f.engine.experimental_v3 = true;
        let kek = register_wrapping_key(
            &mut f.engine,
            v,
            &[3; 32],
            vec![],
            aes_wrapping_parameters(true),
        );
        payload(&call(&mut f.engine, v, "alice", 18, vec![uid(&kek)]));
        let id = register_aes(&mut f.engine, v, vec![6; 32], vec![]);
        let export = call(
            &mut f.engine,
            v,
            "alice",
            43,
            vec![uid(&id), wrapping_spec(v, &kek, Some(1), None, vec![])],
        );
        let fields = transfer_import_fields(v, payload(&export), "clear-import", false, Some(1));
        payload(&call(&mut f.engine, v, "alice", 42, fields));
        let obj = f
            .engine
            .store
            .get("alice", "clear-import")
            .unwrap()
            .unwrap();
        assert_eq!(obj.material, vec![6; 32]);
        assert!(obj.wrapped.is_none());
        let object = payload(&export).required(SYMMETRIC_KEY).unwrap().clone();
        let r = register_wrapped(
            &mut f.engine,
            v,
            object.clone(),
            vec![Node::int(CRYPTOGRAPHIC_USAGE_MASK, 12)],
        );
        let registered = payload(&r)
            .required(UNIQUE_IDENTIFIER)
            .unwrap()
            .identifier_text()
            .unwrap()
            .to_owned();
        let r = call(
            &mut f.engine,
            v,
            "alice",
            10,
            vec![uid(&registered), Node::enumeration(KEY_WRAP_TYPE, 2)],
        );
        assert!(payload(&r).required(SYMMETRIC_KEY).unwrap() == &object);
        assert_eq!(key(&mut f.engine, v, &registered), vec![6; 32]);
        let other = if v.0 == 1 {
            Version(2, 1)
        } else {
            Version(1, 4)
        };
        payload(&call(
            &mut f.engine,
            other,
            "alice",
            10,
            vec![uid(&registered), Node::enumeration(KEY_WRAP_TYPE, 2)],
        ));
    }
}
#[test]
fn destroyed_export_import_retains_metadata_and_rejects_hidden_material() {
    for v in [Version(1, 4), Version(2, 1), Version(3, 0)] {
        let mut f = Fixture::new();
        f.engine.experimental_v3 = true;
        let id = create(&mut f.engine, v, vec![]);
        payload(&call(&mut f.engine, v, "alice", 20, vec![uid(&id)]));
        let export = call(&mut f.engine, v, "alice", 43, vec![uid(&id)]);
        assert!(
            payload(&export)
                .required(SYMMETRIC_KEY)
                .unwrap()
                .required(KEY_BLOCK)
                .unwrap()
                .get(KEY_VALUE)
                .is_none()
        );
        let fields = transfer_import_fields(v, payload(&export), "destroyed-import", false, None);
        payload(&call(&mut f.engine, v, "alice", 42, fields));
        let obj = f
            .engine
            .store
            .get("alice", "destroyed-import")
            .unwrap()
            .unwrap();
        assert_eq!(obj.state, 5);
        assert!(obj.material.is_empty());
        assert_eq!(
            reason(&call(
                &mut f.engine,
                v,
                "alice",
                10,
                vec![uid("destroyed-import")]
            )),
            if v.0 >= 2 { 0x36 } else { 11 }
        );
        payload(&call(
            &mut f.engine,
            v,
            "alice",
            43,
            vec![uid("destroyed-import")],
        ));
        let mut fields = transfer_import_fields(v, payload(&export), "hidden-import", false, None);
        if let Value::Structure(a) = &mut fields
            .iter_mut()
            .find(|n| n.tag == SYMMETRIC_KEY)
            .unwrap()
            .value
            && let Value::Structure(b) = &mut a[0].value
        {
            b.push(Node::structure(
                KEY_VALUE,
                vec![Node::bytes(KEY_MATERIAL, vec![6; 32])],
            ));
        }
        assert_eq!(reason(&call(&mut f.engine, v, "alice", 42, fields)), 7);
        assert!(
            f.engine
                .store
                .get("alice", "hidden-import")
                .unwrap()
                .is_none()
        );
    }
}

fn key(e: &mut Engine, v: Version, id: &str) -> Vec<u8> {
    let response = call(e, v, "alice", 10, vec![uid(id)]);
    payload(&response)
        .required(SYMMETRIC_KEY)
        .unwrap()
        .required(KEY_BLOCK)
        .unwrap()
        .required(KEY_VALUE)
        .unwrap()
        .required(KEY_MATERIAL)
        .unwrap()
        .byte_string()
        .unwrap()
        .to_vec()
}

#[test]
fn import_preserves_legacy_index_gaps_and_does_not_synthesize_optional_metadata() {
    let mut f = Fixture::new();
    let v = Version(1, 4);
    let id = create(
        &mut f.engine,
        v,
        vec![
            Node::text(OBJECT_GROUP, "first"),
            Node::text(OBJECT_GROUP, "second"),
        ],
    );
    payload(&call(
        &mut f.engine,
        v,
        "alice",
        15,
        vec![
            uid(&id),
            Node::text(ATTRIBUTE_NAME, "Object Group"),
            Node::int(ATTRIBUTE_INDEX, 0),
        ],
    ));
    let exported = call(&mut f.engine, v, "alice", 43, vec![uid(&id)]);
    let fields = transfer_import_fields(v, payload(&exported), "indexed-restore", false, None);
    payload(&call(&mut f.engine, v, "alice", 42, fields));
    let response = call(
        &mut f.engine,
        v,
        "alice",
        11,
        vec![
            uid("indexed-restore"),
            Node::text(ATTRIBUTE_NAME, "Object Group"),
        ],
    );
    let attr = payload(&response).required(ATTRIBUTE).unwrap();
    assert_eq!(attr.required(ATTRIBUTE_INDEX).unwrap().number().unwrap(), 1);
    assert_eq!(
        attr.required(ATTRIBUTE_VALUE).unwrap().string().unwrap(),
        "second"
    );
    let v = Version(2, 1);
    let exported = call(&mut f.engine, v, "alice", 43, vec![uid(&id)]);
    let mut fields = transfer_import_fields(v, payload(&exported), "minimal-restore", false, None);
    {
        let tag = LEASE_TIME;
        transfer_edit_attrs(v, &mut fields, tag, None);
    }
    payload(&call(&mut f.engine, v, "alice", 42, fields));
    let response = call(&mut f.engine, v, "alice", 43, vec![uid("minimal-restore")]);
    let attrs = payload(&response).required(ATTRIBUTES).unwrap();
    {
        let tag = LEASE_TIME;
        assert!(attrs.get(tag).is_none());
    }
    let mut fields = transfer_import_fields(v, payload(&response), "missing-state", false, None);
    transfer_edit_attrs(v, &mut fields, STATE, None);
    assert_eq!(
        reason(&call(&mut f.engine, v, "alice", 42, fields)),
        if v.0 >= 2 { 7 } else { 6 }
    );
}
#[test]
fn import_wrap_type_rules_authentication_failures_and_draft_factory_aliases() {
    let mut f = Fixture::new();
    let v = Version(2, 1);
    f.engine.experimental_v3 = true;
    let kek = register_wrapping_key(
        &mut f.engine,
        v,
        &[3; 32],
        vec![],
        aes_wrapping_parameters(true),
    );
    payload(&call(&mut f.engine, v, "alice", 18, vec![uid(&kek)]));
    let id = register_aes(&mut f.engine, v, vec![6; 32], vec![]);
    let clear = call(&mut f.engine, v, "alice", 43, vec![uid(&id)]);
    let fields = transfer_import_fields(v, payload(&clear), "invalid-wrap", false, Some(1));
    assert_eq!(reason(&call(&mut f.engine, v, "alice", 42, fields)), 7);
    let mut exported = call(
        &mut f.engine,
        v,
        "alice",
        43,
        vec![uid(&id), wrapping_spec(v, &kek, Some(2), None, vec![])],
    );
    let fields = transfer_import_fields(v, payload(&exported), "missing-wrap", false, None);
    assert_eq!(reason(&call(&mut f.engine, v, "alice", 42, fields)), 7);
    fn corrupt(n: &mut Node) {
        if n.tag == KEY_VALUE
            && let Value::ByteString(bytes) = &mut n.value
        {
            bytes[0] ^= 1;
        } else if let Value::Structure(fields) = &mut n.value {
            for n in fields {
                corrupt(n);
            }
        }
    }
    corrupt(&mut exported);
    let fields = transfer_import_fields(v, payload(&exported), "corrupt-clear", false, Some(1));
    assert_eq!(reason(&call(&mut f.engine, v, "alice", 42, fields)), 10);
    assert!(
        f.engine
            .store
            .get("alice", "corrupt-clear")
            .unwrap()
            .is_none()
    );
    let fields = transfer_import_fields(v, payload(&exported), "corrupt-opaque", false, Some(2));
    payload(&call(&mut f.engine, v, "alice", 42, fields));
    assert_eq!(
        reason(&call(
            &mut f.engine,
            v,
            "alice",
            10,
            vec![uid("corrupt-opaque")]
        )),
        10
    );
    payload(&call(
        &mut f.engine,
        v,
        "alice",
        10,
        vec![uid("corrupt-opaque"), Node::enumeration(KEY_WRAP_TYPE, 2)],
    ));
    let v = Version(3, 0);
    let exported = call(&mut f.engine, v, "alice", 43, vec![uid(&id)]);
    let fields = transfer_import_fields(v, payload(&exported), "draft-import", false, None);
    let response = f
        .engine
        .process(
            "alice",
            &req(
                v,
                vec![
                    (42, fields),
                    (43, vec![Node::enumeration(UNIQUE_IDENTIFIER, 9)]),
                ],
            ),
        )
        .unwrap();
    assert_eq!(response.all(BATCH_ITEM).count(), 2);
    for item in response.all(BATCH_ITEM) {
        assert_eq!(item.required(RESULT_STATUS).unwrap().number().unwrap(), 0);
    }
    let response = call(&mut f.engine, v, "alice", 10, vec![uid("draft-import")]);
    assert_eq!(
        payload(&response)
            .required(UNIQUE_IDENTIFIER)
            .unwrap()
            .identifier_text()
            .unwrap(),
        "draft-import"
    );
    let response = call(&mut f.engine, v, "alice", 43, vec![]);
    assert_eq!(reason(&response), if v.0 >= 2 { 7 } else { 6 });
}

fn derivation_source(
    e: &mut Engine,
    v: Version,
    kind: u32,
    secret_type: u32,
    algorithm: u32,
    bytes: &[u8],
    extra: Vec<Node>,
) -> String {
    let mut fields = vec![Node::int(CRYPTOGRAPHIC_USAGE_MASK, 512)];
    fields.extend(extra);
    let mut block = vec![
        Node::enumeration(KEY_FORMAT_TYPE, 1),
        Node::structure(KEY_VALUE, vec![Node::bytes(KEY_MATERIAL, bytes.to_vec())]),
        Node::int(CRYPTOGRAPHIC_LENGTH, (bytes.len() * 8) as i32),
    ];
    if algorithm != 0 {
        block.push(Node::enumeration(CRYPTOGRAPHIC_ALGORITHM, algorithm));
    }
    let mut object = vec![];
    if kind == 7 {
        object.push(Node::enumeration(SECRET_DATA_TYPE, secret_type));
    }
    object.push(Node::structure(KEY_BLOCK, block));
    let response = call(
        e,
        v,
        "alice",
        3,
        vec![
            Node::enumeration(OBJECT_TYPE, kind),
            pair_container(v, fields),
            Node::structure(
                if kind == 7 {
                    SECRET_DATA
                } else {
                    SYMMETRIC_KEY
                },
                object,
            ),
        ],
    );
    let id = payload(&response)
        .required(UNIQUE_IDENTIFIER)
        .unwrap()
        .identifier_text()
        .unwrap()
        .to_owned();
    payload(&call(e, v, "alice", 18, vec![uid(&id)]));
    id
}
fn derive_fields(
    v: Version,
    ids: &[&str],
    kind: u32,
    bits: u32,
    method: u32,
    params: Vec<Node>,
    extra: Vec<Node>,
) -> Vec<Node> {
    let mut attrs = vec![
        Node::int(CRYPTOGRAPHIC_LENGTH, bits as i32),
        Node::int(CRYPTOGRAPHIC_USAGE_MASK, 12),
    ];
    if kind == 2 {
        attrs.push(Node::enumeration(CRYPTOGRAPHIC_ALGORITHM, 3));
    }
    attrs.extend(extra);
    let mut fields = vec![Node::enumeration(OBJECT_TYPE, kind)];
    fields.extend(ids.iter().map(|id| uid(id)));
    fields.extend([
        Node::enumeration(DERIVATION_METHOD, method),
        Node::structure(DERIVATION_PARAMETERS, params),
        pair_container(v, attrs),
    ]);
    fields
}
fn derived_id(e: &mut Engine, v: Version, fields: Vec<Node>) -> String {
    let response = call(e, v, "alice", 5, fields);
    payload(&response)
        .required(UNIQUE_IDENTIFIER)
        .unwrap()
        .identifier_text()
        .unwrap()
        .to_owned()
}
fn derived_bytes(e: &mut Engine, v: Version, id: &str, kind: u32) -> Vec<u8> {
    let response = call(e, v, "alice", 10, vec![uid(id)]);
    payload(&response)
        .required(if kind == 7 {
            SECRET_DATA
        } else {
            SYMMETRIC_KEY
        })
        .unwrap()
        .required(KEY_BLOCK)
        .unwrap()
        .required(KEY_VALUE)
        .unwrap()
        .required(KEY_MATERIAL)
        .unwrap()
        .byte_string()
        .unwrap()
        .to_vec()
}
#[test]
fn derive_all_original_methods_all_versions_with_password_types_and_reciprocal_links() {
    for v in Version::supported(true) {
        let mut f = Fixture::new();
        f.engine.experimental_v3 = true;
        let cp = Node::structure(
            CRYPTOGRAPHIC_PARAMETERS,
            vec![Node::enumeration(BLOCK_CIPHER_MODE, 2)],
        );
        let bytes = hex::decode("000102030405060708090a0b0c0d0e0f").unwrap();
        let base = derivation_source(
            &mut f.engine,
            v,
            2,
            2,
            3,
            &bytes,
            vec![cp.clone(), usage_limits(8, 2)],
        );
        let id = derived_id(
            &mut f.engine,
            v,
            derive_fields(
                v,
                &[&base],
                2,
                128,
                2,
                vec![Node::structure(
                    CRYPTOGRAPHIC_PARAMETERS,
                    vec![Node::enumeration(HASHING_ALGORITHM, 6)],
                )],
                vec![],
            ),
        );
        assert_eq!(
            derived_bytes(&mut f.engine, v, &id, 2),
            openssl::sha::sha256(&bytes)[..16]
        );
        let input = hex::decode("00112233445566778899aabbccddeeff").unwrap();
        let encrypted = derived_id(
            &mut f.engine,
            v,
            derive_fields(
                v,
                &[&base],
                2,
                128,
                4,
                vec![cp, Node::bytes(DERIVATION_DATA, input)],
                vec![],
            ),
        );
        assert_eq!(
            hex::encode(derived_bytes(&mut f.engine, v, &encrypted, 2)),
            "69c4e0d86a7b0430d8cdb78070b4c55a"
        );
        assert_eq!(remaining(&mut f.engine, v, &base), 6);
        let source = f.engine.store.get("alice", &base).unwrap().unwrap();
        let target = f.engine.store.get("alice", &id).unwrap().unwrap();
        assert!(has_link(&source.attrs, 0x105, &id));
        assert!(has_link(&target.attrs, 0x104, &base));
        assert_eq!(target.state, 1);
        let pass = derivation_source(&mut f.engine, v, 7, 1, 0, b"passwd", vec![]);
        let output = derived_id(
            &mut f.engine,
            v,
            derive_fields(
                v,
                &[&pass],
                7,
                512,
                1,
                vec![
                    Node::structure(
                        CRYPTOGRAPHIC_PARAMETERS,
                        vec![Node::enumeration(HASHING_ALGORITHM, 6)],
                    ),
                    Node::bytes(SALT, b"salt".to_vec()),
                    Node::int(ITERATION_COUNT, 1),
                ],
                vec![],
            ),
        );
        assert_eq!(
            hex::encode(derived_bytes(&mut f.engine, v, &output, 7)),
            "55ac046e56e3089fec1691c22544b605f94185216dde0465e68b9d57c20dacbc49ca9cccf179b645991664b39d77ef317c71b845b1e30bd509112041d3a19783"
        );
        assert_eq!(
            f.engine
                .store
                .get("alice", &pass)
                .unwrap()
                .unwrap()
                .secret_type,
            1
        );
        assert_eq!(
            f.engine
                .store
                .get("alice", &output)
                .unwrap()
                .unwrap()
                .secret_type,
            2
        );
        let hmac = derivation_source(&mut f.engine, v, 2, 2, 9, &[0x0b; 20], vec![]);
        let output = derived_id(
            &mut f.engine,
            v,
            derive_fields(
                v,
                &[&hmac],
                2,
                256,
                3,
                vec![
                    Node::bytes(DERIVATION_DATA, b"Hi There".to_vec()),
                    Node::structure(
                        CRYPTOGRAPHIC_PARAMETERS,
                        vec![Node::enumeration(HASHING_ALGORITHM, 8)],
                    ),
                ],
                vec![],
            ),
        );
        assert_eq!(
            hex::encode(derived_bytes(&mut f.engine, v, &output, 2)),
            "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
        );
        let key = derivation_source(&mut f.engine, v, 2, 2, 9, &[7; 32], vec![]);
        for (method, expected) in [
            (
                5,
                "6cd613b0fed8ca44c6adb82eeb721d709edefda35db4ff2f1a68b59ad4e0cb16",
            ),
            (
                6,
                "5d936ffdd215fa2b8ad94ec70a3851bf9761af46d0cf761c2ecbf51be92c5acd",
            ),
            (
                7,
                "1e70e68bb7e922b94c2ca3f334885c3bcb27ce23009001fa712681630f13bd58",
            ),
        ] {
            let mut params = vec![Node::bytes(DERIVATION_DATA, b"label\0context".to_vec())];
            if method == 6 {
                params.push(Node::bytes(INITIALIZATION_VECTOR, vec![0; 32]));
            }
            let output = derived_id(
                &mut f.engine,
                v,
                derive_fields(v, &[&key], 2, 256, method, params, vec![]),
            );
            assert_eq!(
                hex::encode(derived_bytes(&mut f.engine, v, &output, 2)),
                expected
            );
        }
        f.engine.store.verify_audit().unwrap();
    }
}
#[test]
fn derive_hkdf_aws_version_gates_parameter_defaults_and_required_attributes() {
    let mut f = Fixture::new();
    f.engine.experimental_v3 = true;
    for v in Version::supported(true) {
        let base = derivation_source(
            &mut f.engine,
            v,
            2,
            2,
            9,
            &[0x0b; 22],
            vec![Node::structure(
                CRYPTOGRAPHIC_PARAMETERS,
                vec![Node::enumeration(BLOCK_CIPHER_MODE, 1)],
            )],
        );
        let fields = derive_fields(
            v,
            &[&base],
            7,
            336,
            10,
            vec![
                Node::bytes(SALT, hex::decode("000102030405060708090a0b0c").unwrap()),
                Node::bytes(
                    DERIVATION_DATA,
                    hex::decode("f0f1f2f3f4f5f6f7f8f9").unwrap(),
                ),
            ],
            vec![],
        );
        if v.0 < 2 {
            // HKDF is not a 1.x Derivation Method: "Invalid Derivation
            // Method" is Invalid Field (1.4 Table 333).
            assert_eq!(reason(&call(&mut f.engine, v, "alice", 5, fields)), 7);
            continue;
        }
        let id = derived_id(&mut f.engine, v, fields);
        assert_eq!(
            hex::encode(derived_bytes(&mut f.engine, v, &id, 7)),
            "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"
        );
        let secret = derivation_source(
            &mut f.engine,
            v,
            7,
            1,
            0,
            b"wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
            vec![],
        );
        let fields = derive_fields(
            v,
            &[&secret],
            2,
            256,
            9,
            [b"20150830".to_vec(), b"us-east-1".to_vec(), b"iam".to_vec()]
                .into_iter()
                .map(|data| Node::bytes(DERIVATION_DATA, data))
                .collect(),
            vec![],
        );
        let id = derived_id(&mut f.engine, v, fields);
        assert_eq!(
            hex::encode(derived_bytes(&mut f.engine, v, &id, 2)),
            "c4afb1cc5771d871763a393e44b703571b55cc28424d1a5e86da6ed3c154a4b9"
        );
        let mut fields = derive_fields(
            v,
            &[&base],
            2,
            256,
            2,
            vec![Node::structure(
                CRYPTOGRAPHIC_PARAMETERS,
                vec![Node::enumeration(HASHING_ALGORITHM, 6)],
            )],
            vec![],
        );
        if let Value::Structure(attrs) = &mut fields
            .iter_mut()
            .find(|n| n.tag == ATTRIBUTES)
            .unwrap()
            .value
        {
            attrs.retain(|n| n.tag != CRYPTOGRAPHIC_ALGORITHM);
        }
        assert_eq!(
            reason(&call(&mut f.engine, v, "alice", 5, fields)),
            if v.0 >= 2 { 7 } else { 6 }
        );
    }
}
#[test]
fn derive_two_sources_validate_ownership_state_usage_data_binding_and_no_placeholder() {
    let mut f = Fixture::new();
    let v = Version(2, 1);
    let key = derivation_source(
        &mut f.engine,
        v,
        2,
        2,
        9,
        &[7; 32],
        vec![usage_limits(2, 2)],
    );
    let data = derivation_source(
        &mut f.engine,
        v,
        7,
        2,
        0,
        b"input",
        vec![usage_limits(2, 2)],
    );
    let fields = derive_fields(v, &[&key, &data], 2, 256, 3, vec![], vec![]);
    let id = derived_id(&mut f.engine, v, fields.clone());
    assert_eq!(
        derived_bytes(&mut f.engine, v, &id, 2),
        keytend_kmip_server::crypto::mac(6, &[7; 32], b"input").unwrap()
    );
    assert_eq!(remaining(&mut f.engine, v, &key), 1);
    assert_eq!(remaining(&mut f.engine, v, &data), 1);
    let obj = f.engine.store.get("alice", &id).unwrap().unwrap();
    assert!(has_link(&obj.attrs, 0x104, &key));
    assert!(has_link(&obj.attrs, 0x104, &data));
    assert_eq!(
        reason(&call(&mut f.engine, v, "bob", 5, fields.clone())),
        not_found(v)
    );
    let mut redundant = fields.clone();
    if let Value::Structure(params) = &mut redundant
        .iter_mut()
        .find(|n| n.tag == DERIVATION_PARAMETERS)
        .unwrap()
        .value
    {
        params.push(Node::bytes(DERIVATION_DATA, b"redundant".to_vec()));
    }
    assert_eq!(reason(&call(&mut f.engine, v, "alice", 5, redundant)), 7);
    let fields = derive_fields(
        v,
        &[],
        2,
        256,
        3,
        vec![Node::bytes(DERIVATION_DATA, vec![])],
        vec![],
    );
    assert_eq!(
        reason(&call(&mut f.engine, v, "alice", 5, fields)),
        if v.0 >= 2 { 7 } else { 6 }
    );
    let mut fields = derive_fields(
        v,
        &[&key],
        2,
        256,
        3,
        vec![Node::bytes(DERIVATION_DATA, vec![])],
        vec![],
    );
    *fields
        .iter_mut()
        .find(|n| n.tag == UNIQUE_IDENTIFIER)
        .unwrap() = Node::enumeration(UNIQUE_IDENTIFIER, 1);
    assert_eq!(reason(&call(&mut f.engine, v, "alice", 5, fields)), 7);
    let denied = create(&mut f.engine, v, vec![]);
    payload(&call(&mut f.engine, v, "alice", 18, vec![uid(&denied)]));
    let fields = derive_fields(
        v,
        &[&denied],
        2,
        128,
        2,
        vec![Node::structure(
            CRYPTOGRAPHIC_PARAMETERS,
            vec![Node::enumeration(HASHING_ALGORITHM, 6)],
        )],
        vec![],
    );
    assert_eq!(reason(&call(&mut f.engine, v, "alice", 5, fields)), 0x29);
    payload(&call(
        &mut f.engine,
        v,
        "alice",
        19,
        vec![
            uid(&key),
            Node::structure(
                REVOCATION_REASON,
                vec![Node::enumeration(REVOCATION_REASON_CODE, 1)],
            ),
        ],
    ));
    let fields = derive_fields(v, &[&key, &data], 2, 256, 3, vec![], vec![]);
    assert_eq!(reason(&call(&mut f.engine, v, "alice", 5, fields)), 0x43);
}
// REQ:6d85af451e35d4f2 explicit Derivation Data together with a Secret Data source is refused
#[test]
fn derivation_data_with_a_secret_data_source_is_refused_in_every_version() {
    for v in Version::supported(false) {
        let mut f = Fixture::new();
        let key = derivation_source(&mut f.engine, v, 2, 2, 9, &[7; 32], vec![]);
        let data = derivation_source(&mut f.engine, v, 7, 2, 0, b"input", vec![]);
        let fields = derive_fields(v, &[&key, &data], 2, 256, 3, vec![], vec![]);
        let mut both = fields.clone();
        if let Value::Structure(params) = &mut both
            .iter_mut()
            .find(|n| n.tag == DERIVATION_PARAMETERS)
            .unwrap()
            .value
        {
            params.push(Node::bytes(DERIVATION_DATA, b"input".to_vec()));
        }
        // 1.x Derive Key table (1.4 Table 333): ambiguous derivation data is
        // Invalid Message.
        assert_eq!(
            reason(&call(&mut f.engine, v, "alice", 5, both)),
            if v.0 == 1 { 4 } else { 7 }
        );
        assert_eq!(f.engine.store.list("alice").unwrap().len(), 2);
        // Either input alone is accepted.
        derived_id(&mut f.engine, v, fields);
        let explicit = derive_fields(
            v,
            &[&key],
            2,
            256,
            3,
            vec![Node::bytes(DERIVATION_DATA, b"input".to_vec())],
            vec![],
        );
        derived_id(&mut f.engine, v, explicit);
    }
}

#[test]
fn derive_failures_and_undo_keep_only_delivered_source_charges() {
    let mut f = Fixture::new();
    let v = Version(2, 1);
    let key = derivation_source(
        &mut f.engine,
        v,
        2,
        2,
        9,
        &[7; 32],
        vec![usage_limits(2, 2)],
    );
    let data = derivation_source(
        &mut f.engine,
        v,
        7,
        2,
        0,
        b"input",
        vec![usage_limits(0, 2)],
    );
    let fields = derive_fields(v, &[&key, &data], 2, 256, 3, vec![], vec![]);
    assert_eq!(reason(&call(&mut f.engine, v, "alice", 5, fields)), 0x1a);
    assert_eq!(remaining(&mut f.engine, v, &key), 2);
    let before = f.engine.store.get("alice", &key).unwrap().unwrap();
    assert!(
        !before
            .attrs
            .iter()
            .any(|a| link_kind_test(a) == Some(0x105))
    );
    let fields = derive_fields(
        v,
        &[&key],
        2,
        256,
        3,
        vec![Node::bytes(DERIVATION_DATA, b"input".to_vec())],
        vec![],
    );
    let response = f
        .engine
        .process(
            "alice",
            &batch_option(
                req(v, vec![(5, fields.clone()), (10, vec![uid("missing")])]),
                3,
            ),
        )
        .unwrap();
    // The undone derivation keeps its source debit, but neither the derived
    // object nor the source's Derived Key link survives.
    assert_eq!(statuses(&response), vec![3, 1]);
    let derived = response
        .get(BATCH_ITEM)
        .unwrap()
        .required(RESPONSE_PAYLOAD)
        .unwrap()
        .required(UNIQUE_IDENTIFIER)
        .unwrap()
        .identifier_text()
        .unwrap();
    assert!(f.engine.store.get("alice", derived).unwrap().is_none());
    assert_eq!(remaining(&mut f.engine, v, &key), 1);
    let before = f.engine.store.get("alice", &key).unwrap().unwrap();
    assert!(before.usage_consumed);
    assert!(
        !before
            .attrs
            .iter()
            .any(|a| link_kind_test(a) == Some(0x105))
    );
    let connection = rusqlite::Connection::open(f._dir.path().join("keys.sqlite")).unwrap();
    connection.execute_batch("CREATE TRIGGER reject_derivation BEFORE INSERT ON objects BEGIN SELECT RAISE(FAIL,'injected derivation failure'); END;").unwrap();
    assert_eq!(reason(&call(&mut f.engine, v, "alice", 5, fields)), 0x100);
    assert_eq!(remaining(&mut f.engine, v, &key), 1);
    let after = f.engine.store.get("alice", &key).unwrap().unwrap();
    assert!(before.attrs == after.attrs);
    f.engine.store.verify_audit().unwrap();
}
fn link_kind_test(n: &Node) -> Option<u32> {
    n.get(LINK_TYPE).and_then(|n| n.number().ok())
}
#[test]
fn password_secret_data_type_survives_wrapping_restore_and_store_restart() {
    let mut f = Fixture::new();
    let v = Version(2, 1);
    let id = derivation_source(&mut f.engine, v, 7, 1, 0, b"password", vec![]);
    let kek = register_wrapping_key(
        &mut f.engine,
        v,
        &[3; 32],
        vec![],
        aes_wrapping_parameters(true),
    );
    payload(&call(&mut f.engine, v, "alice", 18, vec![uid(&kek)]));
    let response = call(
        &mut f.engine,
        v,
        "alice",
        43,
        vec![uid(&id), wrapping_spec(v, &kek, Some(2), None, vec![])],
    );
    let fields = transfer_import_fields(v, payload(&response), "opaque-password", false, Some(2));
    payload(&call(&mut f.engine, v, "alice", 42, fields));
    let path = f._dir.path().join("keys.sqlite");
    let master = f._dir.path().join("master");
    drop(f.engine);
    f.engine = Engine::new(Store::open(&path, &master).unwrap(), false);
    let output = derived_id(
        &mut f.engine,
        v,
        derive_fields(
            v,
            &["opaque-password"],
            2,
            256,
            1,
            vec![
                Node::bytes(SALT, b"salt".to_vec()),
                Node::int(ITERATION_COUNT, 2),
            ],
            vec![],
        ),
    );
    assert_eq!(
        derived_bytes(&mut f.engine, v, &output, 2),
        keytend_kmip_server::crypto::derivation::pbkdf2(4, b"password", b"salt", 2, 32)
            .unwrap()
            .as_slice()
    );
    let restored = f
        .engine
        .store
        .get("alice", "opaque-password")
        .unwrap()
        .unwrap();
    assert_eq!(restored.secret_type, 1);
    assert!(restored.material.is_empty());
    let response = call(&mut f.engine, v, "alice", 10, vec![uid("opaque-password")]);
    assert_eq!(
        payload(&response)
            .required(SECRET_DATA)
            .unwrap()
            .required(SECRET_DATA_TYPE)
            .unwrap()
            .number()
            .unwrap(),
        1
    );
}
fn has_link(attrs: &[Node], kind: u32, id: &str) -> bool {
    attrs.iter().any(|n| {
        link_kind_test(n) == Some(kind)
            && n.get(LINKED_OBJECT_IDENTIFIER)
                .and_then(|n| n.identifier_text().ok())
                == Some(id)
    })
}
#[test]
fn derivation_undo_keeps_source_charge_without_derived_keys_and_batch_work_is_bounded() {
    let mut f = Fixture::new();
    let v = Version(2, 1);
    let source = derivation_source(
        &mut f.engine,
        v,
        2,
        2,
        9,
        &[7; 32],
        vec![usage_limits(8, 2)],
    );
    let fields = derive_fields(
        v,
        &[&source],
        2,
        256,
        3,
        vec![Node::bytes(DERIVATION_DATA, b"data".to_vec())],
        vec![],
    );
    let response = f
        .engine
        .process(
            "alice",
            &batch_option(
                req(
                    v,
                    vec![
                        (5, fields.clone()),
                        (10, vec![Node::enumeration(UNIQUE_IDENTIFIER, 8)]),
                        (10, vec![uid("missing")]),
                    ],
                ),
                3,
            ),
        )
        .unwrap();
    // The derived key returned in the undone Get is charged to its source
    // (Usage Limits reflect applied protection); the derived object is gone.
    assert_eq!(statuses(&response), vec![3, 3, 1]);
    let items: Vec<_> = response.all(BATCH_ITEM).collect();
    let derived = items[0]
        .required(RESPONSE_PAYLOAD)
        .unwrap()
        .required(UNIQUE_IDENTIFIER)
        .unwrap()
        .identifier_text()
        .unwrap();
    assert!(f.engine.store.get("alice", derived).unwrap().is_none());
    assert!(
        items[1]
            .required(RESPONSE_PAYLOAD)
            .unwrap()
            .get(SYMMETRIC_KEY)
            .is_some()
    );
    assert_eq!(remaining(&mut f.engine, v, &source), 7);
    let response = f
        .engine
        .process(
            "alice",
            &req(v, (0..5).map(|_| (5, fields.clone())).collect()),
        )
        .unwrap();
    let items: Vec<_> = response.all(BATCH_ITEM).collect();
    assert_eq!(items.len(), 5);
    for item in &items[..4] {
        assert_eq!(item.required(RESULT_STATUS).unwrap().number().unwrap(), 0);
    }
    assert_eq!(items[4].required(OPERATION).unwrap().number().unwrap(), 5);
    assert_eq!(
        items[4].required(RESULT_REASON).unwrap().number().unwrap(),
        0x3a
    );
    assert_eq!(remaining(&mut f.engine, v, &source), 3);
    let obj = f.engine.store.get("alice", &source).unwrap().unwrap();
    assert_eq!(
        obj.attrs
            .iter()
            .filter(|a| link_kind_test(a) == Some(0x105))
            .count(),
        4
    );
    f.engine.store.verify_audit().unwrap();
}
#[test]
fn derivation_factory_aliases_multi_source_references_and_transparent_output_are_versioned() {
    let mut f = Fixture::new();
    f.engine.experimental_v3 = true;
    for v in [Version(2, 0), Version(2, 1), Version(3, 0)] {
        let source = derivation_source(&mut f.engine, v, 2, 2, 9, &[7; 32], vec![]);
        let fields = derive_fields(
            v,
            &[&source],
            2,
            256,
            3,
            vec![Node::bytes(DERIVATION_DATA, b"data".to_vec())],
            vec![Node::enumeration(KEY_FORMAT_TYPE, 7)],
        );
        let response = f
            .engine
            .process(
                "alice",
                &req(
                    v,
                    vec![
                        (5, fields),
                        (10, vec![Node::enumeration(UNIQUE_IDENTIFIER, 8)]),
                    ],
                ),
            )
            .unwrap();
        for item in response.all(BATCH_ITEM) {
            assert_eq!(item.required(RESULT_STATUS).unwrap().number().unwrap(), 0);
        }
        let last = response
            .all(BATCH_ITEM)
            .last()
            .unwrap()
            .required(RESPONSE_PAYLOAD)
            .unwrap();
        assert_eq!(
            last.required(SYMMETRIC_KEY)
                .unwrap()
                .required(KEY_BLOCK)
                .unwrap()
                .required(KEY_VALUE)
                .unwrap()
                .required(KEY_MATERIAL)
                .unwrap()
                .required(KEY)
                .unwrap()
                .byte_string()
                .unwrap(),
            keytend_kmip_server::crypto::mac(6, &[7; 32], b"data").unwrap()
        );
    }
}
#[test]
fn derive_aes_cmac_modes_and_source_byte_budgets_with_response_rollback() {
    use keytend_kmip_server::crypto::derivation::{
        CounterLocation, KbkdfParameters, Mode, Prf, sp800108,
    };
    for v in [Version(1, 0), Version(1, 4), Version(2, 1), Version(3, 0)] {
        let mut f = Fixture::new();
        f.engine.experimental_v3 = true;
        let cp = Node::structure(
            CRYPTOGRAPHIC_PARAMETERS,
            vec![Node::enumeration(BLOCK_CIPHER_MODE, 7)],
        );
        let base = derivation_source(
            &mut f.engine,
            v,
            2,
            2,
            3,
            &[5; 16],
            vec![cp.clone(), usage_limits(96, 1)],
        );
        for (method, mode) in [
            (5, Mode::Counter),
            (6, Mode::Feedback),
            (7, Mode::DoublePipeline),
        ] {
            let id = derived_id(
                &mut f.engine,
                v,
                derive_fields(
                    v,
                    &[&base],
                    2,
                    256,
                    method,
                    vec![
                        Node::bytes(DERIVATION_DATA, b"label\0context".to_vec()),
                        cp.clone(),
                    ],
                    vec![],
                ),
            );
            let mut fixed = b"label\0context".to_vec();
            fixed.extend_from_slice(&256u32.to_be_bytes());
            let expected = sp800108(
                &[5; 16],
                KbkdfParameters {
                    mode,
                    prf: Prf::Cmac,
                    fixed: &fixed,
                    iv: &[],
                    counter_bytes: 4,
                    counter_location: CounterLocation::AfterIteration,
                },
                32,
            )
            .unwrap();
            assert_eq!(derived_bytes(&mut f.engine, v, &id, 2), expected.as_slice());
        }
        assert_eq!(remaining(&mut f.engine, v, &base), 0);
    }
    let mut f = Fixture::new();
    let v = Version(2, 1);
    let base = derivation_source(
        &mut f.engine,
        v,
        2,
        2,
        9,
        &[7; 32],
        vec![usage_limits(1, 2)],
    );
    let fields = derive_fields(
        v,
        &[&base],
        2,
        256,
        3,
        vec![Node::bytes(DERIVATION_DATA, b"data".to_vec())],
        vec![],
    );
    let mut request = req(v, vec![(5, fields)]);
    if let Value::Structure(fields) = &mut request.value
        && let Value::Structure(header) = &mut fields[0].value
    {
        header.push(Node::int(MAXIMUM_RESPONSE_SIZE, minimal_response_size(v)));
    }
    assert_eq!(reason(&f.engine.process("alice", &request).unwrap()), 2);
    assert_eq!(remaining(&mut f.engine, v, &base), 1);
    let stored = f.engine.store.get("alice", &base).unwrap().unwrap();
    assert!(
        !stored
            .attrs
            .iter()
            .any(|a| link_kind_test(a) == Some(0x105))
    );
}

/// The smallest legal TTLV response to one `req` batch item: the response
/// header and Operation, Unique Batch Item ID (before 3.0), Result Status and
/// Result Reason, without the optional Result Message.
fn minimal_response_size(v: Version) -> i32 {
    let correlation = if v >= Version(1, 4) { 48 } else { 0 };
    let count = if v.0 < 3 { 16 } else { 0 };
    8 + (8 + 40 + 16 + correlation + count) + (56 + count)
}
fn metadata_attr(e: &mut Engine, v: Version, id: &str, tag: u32) -> Option<Node> {
    let selector = if v.0 == 1 {
        Node::text(ATTRIBUTE_NAME, tag_name(tag).unwrap())
    } else {
        Node::enumeration(ATTRIBUTE_REFERENCE, tag)
    };
    let response = call(e, v, "alice", 11, vec![uid(id), selector]);
    let p = payload(&response);
    if v.0 == 1 {
        p.get(ATTRIBUTE).map(|a| {
            let mut n = a.required(ATTRIBUTE_VALUE).unwrap().clone();
            n.tag = tag;
            n
        })
    } else {
        p.get(ATTRIBUTES).and_then(|a| a.get(tag)).cloned()
    }
}
fn metadata_flag(e: &mut Engine, v: Version, id: &str, tag: u32) -> bool {
    metadata_attr(e, v, id, tag).unwrap().flag().unwrap()
}
fn set_flag(e: &mut Engine, v: Version, id: &str, tag: u32, value: bool) -> Node {
    call(
        e,
        v,
        "alice",
        if v.0 == 1 { 14 } else { 49 },
        vec![uid(id), attribute_change(v, Node::boolean(tag, value))],
    )
}
#[test]
fn generated_metadata_defaults_and_fresh_exposure_are_versioned_and_durable() {
    for v in Version::supported(true) {
        let mut f = Fixture::new();
        f.engine.experimental_v3 = true;
        let id = create(&mut f.engine, v, vec![]);
        for (tag, available) in [
            (FRESH, v >= Version(1, 1)),
            (ORIGINAL_CREATION_DATE, v >= Version(1, 2)),
            (RANDOM_NUMBER_GENERATOR, v >= Version(1, 3)),
            (SENSITIVE, v >= Version(1, 4)),
            (EXTRACTABLE, v >= Version(1, 4)),
            (ALWAYS_SENSITIVE, v >= Version(1, 4)),
            (NEVER_EXTRACTABLE, v >= Version(1, 4)),
        ] {
            assert_eq!(
                metadata_attr(&mut f.engine, v, &id, tag).is_some(),
                available
            );
        }
        if v >= Version(1, 1) {
            assert!(metadata_flag(&mut f.engine, v, &id, FRESH));
        }
        if v >= Version(1, 2) {
            let obj = f.engine.store.get("alice", &id).unwrap().unwrap();
            assert!(
                matches!(metadata_attr(&mut f.engine,v,&id,ORIGINAL_CREATION_DATE).unwrap().value,Value::DateTime(t) if t==obj.created)
            );
        }
        if v >= Version(1, 4) {
            assert!(!metadata_flag(&mut f.engine, v, &id, SENSITIVE));
            assert!(metadata_flag(&mut f.engine, v, &id, EXTRACTABLE));
            assert!(!metadata_flag(&mut f.engine, v, &id, ALWAYS_SENSITIVE));
            assert!(!metadata_flag(&mut f.engine, v, &id, NEVER_EXTRACTABLE));
        }
        let key = derived_bytes(&mut f.engine, v, &id, 2);
        assert!(!metadata_flag(&mut f.engine, Version(2, 1), &id, FRESH));
        let path = f._dir.path().join("keys.sqlite");
        let master = f._dir.path().join("master");
        drop(f.engine);
        f.engine = Engine::new(Store::open(&path, &master).unwrap(), true);
        assert!(!metadata_flag(&mut f.engine, Version(2, 1), &id, FRESH));
        assert_eq!(derived_bytes(&mut f.engine, v, &id, 2), key);
    }
}
#[test]
fn final_extraction_flags_are_mutable_with_monotonic_histories_and_draft_tightening() {
    for v in [Version(1, 4), Version(2, 0), Version(2, 1), Version(3, 0)] {
        let mut f = Fixture::new();
        f.engine.experimental_v3 = true;
        let id = create(
            &mut f.engine,
            v,
            vec![
                Node::boolean(SENSITIVE, true),
                Node::boolean(EXTRACTABLE, false),
            ],
        );
        assert!(metadata_flag(&mut f.engine, v, &id, ALWAYS_SENSITIVE));
        assert!(metadata_flag(&mut f.engine, v, &id, NEVER_EXTRACTABLE));
        if v.0 < 3 {
            payload(&set_flag(&mut f.engine, v, &id, SENSITIVE, false));
            payload(&set_flag(&mut f.engine, v, &id, EXTRACTABLE, true));
            assert!(!metadata_flag(&mut f.engine, v, &id, ALWAYS_SENSITIVE));
            assert!(!metadata_flag(&mut f.engine, v, &id, NEVER_EXTRACTABLE));
            payload(&set_flag(&mut f.engine, v, &id, SENSITIVE, true));
            payload(&set_flag(&mut f.engine, v, &id, EXTRACTABLE, false));
            assert!(!metadata_flag(&mut f.engine, v, &id, ALWAYS_SENSITIVE));
            assert!(!metadata_flag(&mut f.engine, v, &id, NEVER_EXTRACTABLE));
        } else {
            assert_eq!(
                reason(&set_flag(&mut f.engine, v, &id, SENSITIVE, false)),
                0x22
            );
            assert_eq!(
                reason(&set_flag(&mut f.engine, v, &id, EXTRACTABLE, true)),
                0x22
            );
            let other = create(&mut f.engine, v, vec![]);
            payload(&set_flag(&mut f.engine, v, &other, SENSITIVE, true));
            payload(&set_flag(&mut f.engine, v, &other, EXTRACTABLE, false));
            assert!(!metadata_flag(&mut f.engine, v, &other, ALWAYS_SENSITIVE));
            assert!(!metadata_flag(&mut f.engine, v, &other, NEVER_EXTRACTABLE));
        }
        for tag in [FRESH, ALWAYS_SENSITIVE, NEVER_EXTRACTABLE] {
            assert_eq!(
                reason(&set_flag(&mut f.engine, v, &id, tag, true)),
                if v.0 >= 2 { 0x22 } else { 12 }
            );
        }
        let deletion = if v.0 == 1 {
            Node::text(ATTRIBUTE_NAME, "Sensitive")
        } else {
            Node::enumeration(ATTRIBUTE_REFERENCE, SENSITIVE)
        };
        assert_eq!(
            reason(&call(
                &mut f.engine,
                v,
                "alice",
                15,
                vec![uid(&id), deletion]
            )),
            if v.0 >= 2 { 0x22 } else { 12 }
        );
    }
}
#[test]
fn freshness_and_extraction_history_survive_undo_when_material_was_returned() {
    let mut f = Fixture::new();
    let v = Version(2, 1);
    let id = create(
        &mut f.engine,
        v,
        vec![
            Node::boolean(SENSITIVE, true),
            Node::boolean(EXTRACTABLE, false),
        ],
    );
    let request = batch_option(
        req(
            v,
            vec![
                (
                    49,
                    vec![
                        uid(&id),
                        attribute_change(v, Node::boolean(SENSITIVE, false)),
                    ],
                ),
                (
                    49,
                    vec![
                        uid(&id),
                        attribute_change(v, Node::boolean(EXTRACTABLE, true)),
                    ],
                ),
                (10, vec![uid(&id)]),
                (10, vec![uid("missing")]),
            ],
        ),
        3,
    );
    let response = f.engine.process("alice", &request).unwrap();
    let items = response.all(BATCH_ITEM).collect::<Vec<_>>();
    assert_eq!(items.len(), 4);
    assert_eq!(
        items[2].required(RESULT_STATUS).unwrap().number().unwrap(),
        3
    );
    assert!(
        items[2]
            .required(RESPONSE_PAYLOAD)
            .unwrap()
            .required(SYMMETRIC_KEY)
            .is_ok()
    );
    assert!(metadata_flag(&mut f.engine, v, &id, SENSITIVE));
    assert!(!metadata_flag(&mut f.engine, v, &id, EXTRACTABLE));
    assert!(!metadata_flag(&mut f.engine, v, &id, FRESH));
    assert!(!metadata_flag(&mut f.engine, v, &id, ALWAYS_SENSITIVE));
    assert!(!metadata_flag(&mut f.engine, v, &id, NEVER_EXTRACTABLE));
    f.engine.store.verify_audit().unwrap();
    let fresh = create(&mut f.engine, v, vec![]);
    let mut request = req(v, vec![(10, vec![uid(&fresh)])]);
    if let Value::Structure(fields) = &mut request.value
        && let Value::Structure(header) = &mut fields[0].value
    {
        header.push(Node::int(MAXIMUM_RESPONSE_SIZE, minimal_response_size(v)));
    }
    assert_eq!(reason(&f.engine.process("alice", &request).unwrap()), 2);
    assert!(metadata_flag(&mut f.engine, v, &fresh, FRESH));
}
#[test]
fn registered_origin_and_rng_are_write_once_and_generated_preferences_are_honored() {
    for v in [
        Version(1, 2),
        Version(1, 3),
        Version(1, 4),
        Version(2, 1),
        Version(3, 0),
    ] {
        let mut f = Fixture::new();
        f.engine.experimental_v3 = true;
        let id = register_aes(&mut f.engine, v, vec![7; 32], vec![]);
        let origin = Node::date(ORIGINAL_CREATION_DATE, 10);
        payload(&call(
            &mut f.engine,
            v,
            "alice",
            13,
            vec![uid(&id), attribute_change(v, origin.clone())],
        ));
        assert!(matches!(
            metadata_attr(&mut f.engine, v, &id, ORIGINAL_CREATION_DATE)
                .unwrap()
                .value,
            Value::DateTime(10)
        ));
        let mutation = call(
            &mut f.engine,
            v,
            "alice",
            if v.0 == 1 { 14 } else { 49 },
            vec![
                uid(&id),
                attribute_change(v, Node::date(ORIGINAL_CREATION_DATE, 20)),
            ],
        );
        assert_eq!(reason(&mutation), if v.0 >= 2 { 0x22 } else { 12 });
        let bad = call(
            &mut f.engine,
            v,
            "alice",
            1,
            vec![Node::enumeration(OBJECT_TYPE, 2), attrs(v, vec![origin])],
        );
        assert_eq!(reason(&bad), if v.0 >= 2 { 0x22 } else { 12 });
        if v >= Version(1, 3) {
            let info = Node::structure(
                RANDOM_NUMBER_GENERATOR,
                vec![
                    Node::enumeration(RNG_ALGORITHM, 3),
                    Node::enumeration(DRBG_ALGORITHM, 4),
                ],
            );
            payload(&call(
                &mut f.engine,
                v,
                "alice",
                13,
                vec![uid(&id), attribute_change(v, info.clone())],
            ));
            assert!(metadata_attr(&mut f.engine, v, &id, RANDOM_NUMBER_GENERATOR).unwrap() == info);
            assert_eq!(
                reason(&call(
                    &mut f.engine,
                    v,
                    "alice",
                    1,
                    vec![
                        Node::enumeration(OBJECT_TYPE, 2),
                        attrs(v, vec![info.clone()])
                    ]
                )),
                8
            );
            let unspecified = Node::structure(
                RANDOM_NUMBER_GENERATOR,
                vec![Node::enumeration(RNG_ALGORITHM, 1)],
            );
            let generated = create(&mut f.engine, v, vec![info, unspecified.clone()]);
            assert!(
                metadata_attr(&mut f.engine, v, &generated, RANDOM_NUMBER_GENERATOR).unwrap()
                    == unspecified
            );
        }
    }
}
#[test]
fn replacement_pair_derivation_and_import_metadata_preserve_their_own_origins() {
    let mut f = Fixture::new();
    let v = Version(2, 1);
    let source = register_aes(
        &mut f.engine,
        v,
        vec![7; 32],
        vec![
            Node::date(ORIGINAL_CREATION_DATE, 10),
            Node::structure(
                RANDOM_NUMBER_GENERATOR,
                vec![Node::enumeration(RNG_ALGORITHM, 3)],
            ),
        ],
    );
    payload(&call(&mut f.engine, v, "alice", 18, vec![uid(&source)]));
    derived_bytes(&mut f.engine, v, &source, 2);
    let response = call(&mut f.engine, v, "alice", 4, vec![uid(&source)]);
    let replacement = payload(&response)
        .required(UNIQUE_IDENTIFIER)
        .unwrap()
        .string()
        .unwrap()
        .to_owned();
    let obj = f.engine.store.get("alice", &replacement).unwrap().unwrap();
    assert!(metadata_flag(&mut f.engine, v, &replacement, FRESH));
    assert!(
        matches!(metadata_attr(&mut f.engine,v,&replacement,ORIGINAL_CREATION_DATE).unwrap().value,Value::DateTime(t) if t==obj.created)
    );
    assert_eq!(
        metadata_attr(&mut f.engine, v, &replacement, RANDOM_NUMBER_GENERATOR)
            .unwrap()
            .required(RNG_ALGORITHM)
            .unwrap()
            .number()
            .unwrap(),
        1
    );
    let base = derivation_source(&mut f.engine, v, 2, 2, 9, &[7; 32], vec![]);
    let derived = derived_id(
        &mut f.engine,
        v,
        derive_fields(
            v,
            &[&base],
            2,
            256,
            3,
            vec![Node::bytes(DERIVATION_DATA, b"input".to_vec())],
            vec![],
        ),
    );
    assert!(metadata_flag(&mut f.engine, v, &derived, FRESH));
    assert!(metadata_attr(&mut f.engine, v, &derived, ORIGINAL_CREATION_DATE).is_some());
    assert!(metadata_attr(&mut f.engine, v, &derived, RANDOM_NUMBER_GENERATOR).is_some());
    let export = call(&mut f.engine, v, "alice", 43, vec![uid(&derived)]);
    assert!(metadata_flag(&mut f.engine, v, &derived, FRESH));
    let fields = transfer_import_fields(v, payload(&export), "metadata-restored", false, None);
    payload(&call(&mut f.engine, v, "alice", 42, fields));
    assert!(metadata_flag(&mut f.engine, v, "metadata-restored", FRESH));
    let mut fields = transfer_import_fields(v, payload(&export), "invalid-history", false, None);
    transfer_edit_attrs(
        v,
        &mut fields,
        ALWAYS_SENSITIVE,
        Some(Node::boolean(ALWAYS_SENSITIVE, true)),
    );
    assert_eq!(reason(&call(&mut f.engine, v, "alice", 42, fields)), 7);
}
#[test]
fn import_requires_mandatory_metadata_unique_short_ids_and_valid_material_digests() {
    let mut f = Fixture::new();
    let v = Version(2, 1);
    let id = create(&mut f.engine, v, vec![]);
    let export = call(&mut f.engine, v, "alice", 43, vec![uid(&id)]);
    for tag in [
        FRESH,
        SENSITIVE,
        EXTRACTABLE,
        ALWAYS_SENSITIVE,
        NEVER_EXTRACTABLE,
        SHORT_UNIQUE_IDENTIFIER,
        DIGEST,
    ] {
        let mut fields = transfer_import_fields(v, payload(&export), "incomplete", false, None);
        transfer_edit_attrs(v, &mut fields, tag, None);
        assert_eq!(
            reason(&call(&mut f.engine, v, "alice", 42, fields)),
            if v.0 >= 2 { 7 } else { 6 }
        );
        assert!(f.engine.store.get("alice", "incomplete").unwrap().is_none());
    }
    let mut fields = transfer_import_fields(v, payload(&export), "short-wrong-size", false, None);
    transfer_edit_attrs(
        v,
        &mut fields,
        SHORT_UNIQUE_IDENTIFIER,
        Some(Node::bytes(SHORT_UNIQUE_IDENTIFIER, vec![0; 4])),
    );
    assert_eq!(reason(&call(&mut f.engine, v, "alice", 42, fields)), 7);
    let mut fields = transfer_import_fields(v, payload(&export), "short-collision", false, None);
    transfer_edit_attrs(
        v,
        &mut fields,
        SHORT_UNIQUE_IDENTIFIER,
        Some(Node::bytes(
            SHORT_UNIQUE_IDENTIFIER,
            openssl::sha::sha256(id.as_bytes()).to_vec(),
        )),
    );
    assert_eq!(reason(&call(&mut f.engine, v, "alice", 42, fields)), 7);
    let mut digest = metadata_attr(&mut f.engine, v, &id, DIGEST).unwrap();
    if let Value::Structure(fields) = &mut digest.value {
        *fields.iter_mut().find(|n| n.tag == DIGEST_VALUE).unwrap() =
            Node::bytes(DIGEST_VALUE, vec![0; 32]);
    }
    let mut fields = transfer_import_fields(v, payload(&export), "wrong-digest", false, None);
    transfer_edit_attrs(v, &mut fields, DIGEST, Some(digest));
    assert_eq!(reason(&call(&mut f.engine, v, "alice", 42, fields)), 7);
    let mut fields = transfer_import_fields(v, payload(&export), "custom-short", false, None);
    transfer_edit_attrs(
        v,
        &mut fields,
        SHORT_UNIQUE_IDENTIFIER,
        Some(Node::bytes(SHORT_UNIQUE_IDENTIFIER, vec![0x55; 32])),
    );
    payload(&call(&mut f.engine, v, "alice", 42, fields));
    assert_eq!(
        metadata_attr(&mut f.engine, v, "custom-short", SHORT_UNIQUE_IDENTIFIER)
            .unwrap()
            .byte_string()
            .unwrap(),
        &[0x55; 32]
    );
}
#[test]
fn opaque_import_defers_missing_digest_until_unwrap_and_preserves_ciphertext_storage() {
    let mut f = Fixture::new();
    let v = Version(2, 1);
    let id = register_aes(&mut f.engine, v, vec![7; 32], vec![]);
    let kek = register_wrapping_key(
        &mut f.engine,
        v,
        &[3; 32],
        vec![],
        aes_wrapping_parameters(true),
    );
    payload(&call(&mut f.engine, v, "alice", 18, vec![uid(&kek)]));
    let export = call(
        &mut f.engine,
        v,
        "alice",
        43,
        vec![uid(&id), wrapping_spec(v, &kek, Some(2), None, vec![])],
    );
    let mut fields = transfer_import_fields(v, payload(&export), "deferred-digest", false, Some(2));
    transfer_edit_attrs(v, &mut fields, DIGEST, None);
    payload(&call(&mut f.engine, v, "alice", 42, fields));
    assert!(metadata_attr(&mut f.engine, v, "deferred-digest", DIGEST).is_none());
    assert_eq!(
        derived_bytes(&mut f.engine, v, "deferred-digest", 2),
        vec![7; 32]
    );
    let stored = f
        .engine
        .store
        .get("alice", "deferred-digest")
        .unwrap()
        .unwrap();
    assert!(stored.material.is_empty());
    assert!(stored.attrs.iter().any(|a| a.tag == DIGEST));
    let mut fields =
        transfer_import_fields(v, payload(&export), "bad-opaque-digest", false, Some(2));
    transfer_edit_attrs(
        v,
        &mut fields,
        DIGEST,
        Some(Node::structure(
            DIGEST,
            vec![
                Node::enumeration(HASHING_ALGORITHM, 6),
                Node::bytes(DIGEST_VALUE, vec![0; 32]),
                Node::enumeration(KEY_FORMAT_TYPE, 1),
            ],
        )),
    );
    payload(&call(&mut f.engine, v, "alice", 42, fields));
    assert_eq!(
        reason(&call(
            &mut f.engine,
            v,
            "alice",
            10,
            vec![uid("bad-opaque-digest")]
        )),
        10
    );
    assert!(metadata_flag(&mut f.engine, v, "bad-opaque-digest", FRESH));
}
#[test]
fn legacy_metadata_is_conservative_and_locate_agrees_with_get_attributes() {
    let mut f = Fixture::new();
    let v = Version(2, 1);
    let id = create(&mut f.engine, v, vec![]);
    let mut obj = f.engine.store.get("alice", &id).unwrap().unwrap();
    obj.metadata = Default::default();
    obj.attrs
        .retain(|a| !matches!(a.tag, ORIGINAL_CREATION_DATE | RANDOM_NUMBER_GENERATOR));
    f.engine.store.put(&obj).unwrap();
    assert!(!metadata_flag(&mut f.engine, v, &id, FRESH));
    assert!(metadata_attr(&mut f.engine, v, &id, ORIGINAL_CREATION_DATE).is_none());
    let response = call(
        &mut f.engine,
        v,
        "alice",
        8,
        vec![Node::structure(
            ATTRIBUTES,
            vec![Node::boolean(FRESH, false)],
        )],
    );
    assert!(
        payload(&response)
            .all(UNIQUE_IDENTIFIER)
            .any(|n| n.string().unwrap() == id)
    );
}
#[test]
fn imported_old_version_objects_gain_newly_defined_identifiers_without_fabricating_freshness() {
    let mut f = Fixture::new();
    f.engine.experimental_v3 = true;
    let v = Version(1, 4);
    let id = create(&mut f.engine, v, vec![]);
    let exported = call(&mut f.engine, v, "alice", 43, vec![uid(&id)]);
    let fields = transfer_import_fields(v, payload(&exported), "legacy-wire-import", false, None);
    payload(&call(&mut f.engine, v, "alice", 42, fields));
    let short = metadata_attr(
        &mut f.engine,
        Version(2, 1),
        "legacy-wire-import",
        SHORT_UNIQUE_IDENTIFIER,
    )
    .unwrap();
    assert_eq!(
        short.byte_string().unwrap(),
        openssl::sha::sha256(b"legacy-wire-import")
    );
    assert!(
        metadata_attr(
            &mut f.engine,
            Version(3, 0),
            "legacy-wire-import",
            OBJECT_CLASS
        )
        .is_some()
    );
    assert!(!metadata_flag(
        &mut f.engine,
        Version(3, 0),
        "legacy-wire-import",
        FRESH
    ));
}
#[test]
fn export_undo_retains_extraction_history_with_version_correct_freshness() {
    for v in [Version(1, 4), Version(2, 1)] {
        let mut f = Fixture::new();
        let id = create(
            &mut f.engine,
            v,
            vec![
                Node::boolean(SENSITIVE, true),
                Node::boolean(EXTRACTABLE, false),
            ],
        );
        let modify = if v.0 == 1 { 14 } else { 49 };
        let request = batch_option(
            req(
                v,
                vec![
                    (
                        modify,
                        vec![
                            uid(&id),
                            attribute_change(v, Node::boolean(SENSITIVE, false)),
                        ],
                    ),
                    (
                        modify,
                        vec![
                            uid(&id),
                            attribute_change(v, Node::boolean(EXTRACTABLE, true)),
                        ],
                    ),
                    (43, vec![uid(&id)]),
                    (10, vec![uid("missing")]),
                ],
            ),
            3,
        );
        let response = f.engine.process("alice", &request).unwrap();
        assert_eq!(
            response
                .all(BATCH_ITEM)
                .nth(2)
                .unwrap()
                .required(RESULT_STATUS)
                .unwrap()
                .number()
                .unwrap(),
            3
        );
        assert!(!metadata_flag(&mut f.engine, v, &id, ALWAYS_SENSITIVE));
        assert!(!metadata_flag(&mut f.engine, v, &id, NEVER_EXTRACTABLE));
        assert_eq!(metadata_flag(&mut f.engine, v, &id, FRESH), v.0 >= 2);
    }
}

fn storage_ids(engine: &mut Engine, v: Version, mask: Option<i32>) -> Vec<String> {
    let fields = mask
        .map(|m| Node::int(STORAGE_STATUS_MASK, m))
        .into_iter()
        .collect();
    let response = call(engine, v, "alice", 8, fields);
    payload(&response)
        .all(UNIQUE_IDENTIFIER)
        .map(|n| n.identifier_text().unwrap().to_owned())
        .collect()
}

// REQ:b0f698ed0d0b465a 1.x operations on an archived object fail with Object Archived until it is recovered
// REQ:999b87ee473c27dc 2.x operations on an archived object fail with Object Archived until it is recovered
// REQ:963f6309206ff10b Recover removes the Archive Date
#[test]
fn archive_recover_every_version_preserves_material_and_enforces_access() {
    for v in Version::supported(true) {
        let mut f = Fixture::new();
        f.engine.experimental_v3 = true;
        let id = create(&mut f.engine, v, vec![]);
        let original = f.engine.store.get("alice", &id).unwrap().unwrap();
        payload(&call(&mut f.engine, v, "alice", 18, vec![uid(&id)]));
        payload(&call(&mut f.engine, v, "alice", 21, vec![uid(&id)]));
        let archived = f.engine.store.get("alice", &id).unwrap().unwrap();
        assert!(archived.attrs.iter().any(|a| a.tag == ARCHIVE_DATE));
        assert_eq!(archived.state, 2);
        assert_eq!(archived.material, original.material);
        for op in [4, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21] {
            assert_eq!(
                reason(&call(
                    &mut f.engine,
                    v,
                    "alice",
                    op,
                    if op == 17 {
                        vec![uid(&id), Node::long(USAGE_LIMITS_COUNT, 1)]
                    } else {
                        vec![uid(&id)]
                    }
                )),
                13,
                "{}.{} op {op}",
                v.0,
                v.1
            );
        }
        if v >= Version(1, 4) {
            assert_eq!(
                reason(&call(&mut f.engine, v, "alice", 43, vec![uid(&id)])),
                13
            );
        }
        assert!(storage_ids(&mut f.engine, v, None).is_empty());
        assert_eq!(storage_ids(&mut f.engine, v, Some(2)), [id.as_str()]);
        assert_eq!(storage_ids(&mut f.engine, v, Some(3)), [id.as_str()]);
        assert!(storage_ids(&mut f.engine, v, Some(0)).is_empty());
        assert_eq!(
            reason(&call(&mut f.engine, v, "bob", 22, vec![uid(&id)])),
            not_found(v)
        );
        let denied = f
            .engine
            .process_authorized("alice", &req(v, vec![(22, vec![uid(&id)])]), Some(&[10]))
            .unwrap();
        assert_eq!(reason(&denied), 12);
        payload(&call(&mut f.engine, v, "alice", 22, vec![uid(&id)]));
        let recovered = f.engine.store.get("alice", &id).unwrap().unwrap();
        assert!(!recovered.attrs.iter().any(|a| a.tag == ARCHIVE_DATE));
        assert_eq!(recovered.state, 2);
        assert_eq!(recovered.material, original.material);
        payload(&call(&mut f.engine, v, "alice", 10, vec![uid(&id)]));
        payload(&call(&mut f.engine, v, "alice", 22, vec![uid(&id)]));
        assert_eq!(storage_ids(&mut f.engine, v, None), [id]);
        f.engine.store.verify_audit().unwrap();
    }
}

#[test]
fn archive_storage_masks_keep_destroyed_metadata_and_do_not_revive_keys() {
    for v in Version::supported(true) {
        let mut f = Fixture::new();
        f.engine.experimental_v3 = true;
        let live = create(&mut f.engine, v, vec![]);
        let dead = create(&mut f.engine, v, vec![]);
        payload(&call(&mut f.engine, v, "alice", 20, vec![uid(&dead)]));
        if v.0 >= 2 {
            assert_eq!(storage_ids(&mut f.engine, v, None), [live.as_str()]);
            assert_eq!(storage_ids(&mut f.engine, v, Some(4)), [dead.as_str()]);
        } else {
            // 1.x on-line Locate omits destroyed objects (Profiles SKFF-M-5/6/7);
            // explicit State or Destroy Date selection still reaches retained metadata.
            assert_eq!(storage_ids(&mut f.engine, v, None), [live.as_str()]);
            for filter in [
                vec![Node::enumeration(STATE, 5)],
                // Absent dates count as the end of time, so the range stays finite.
                vec![
                    Node::date(DESTROY_DATE, 0),
                    Node::date(DESTROY_DATE, 1 << 40),
                ],
            ] {
                let fields = container(v, filter).children().unwrap().to_vec();
                let response = call(&mut f.engine, v, "alice", 8, fields);
                let ids: Vec<_> = payload(&response)
                    .all(UNIQUE_IDENTIFIER)
                    .map(|n| n.identifier_text().unwrap().to_owned())
                    .collect();
                assert_eq!(ids, std::slice::from_ref(&dead));
            }
            let fields = container(v, vec![Node::enumeration(STATE, 1)])
                .children()
                .unwrap()
                .to_vec();
            let response = call(&mut f.engine, v, "alice", 8, fields);
            let ids: Vec<_> = payload(&response)
                .all(UNIQUE_IDENTIFIER)
                .map(|n| n.identifier_text().unwrap().to_owned())
                .collect();
            assert_eq!(ids, std::slice::from_ref(&live));
        }
        payload(&call(&mut f.engine, v, "alice", 21, vec![uid(&dead)]));
        if v.0 >= 2 {
            assert!(storage_ids(&mut f.engine, v, Some(2)).is_empty());
            assert!(storage_ids(&mut f.engine, v, Some(4)).is_empty());
            assert_eq!(storage_ids(&mut f.engine, v, Some(6)), [dead.as_str()]);
        } else {
            assert_eq!(storage_ids(&mut f.engine, v, Some(2)), [dead.as_str()]);
        }
        payload(&call(&mut f.engine, v, "alice", 22, vec![uid(&dead)]));
        let object = f.engine.store.get("alice", &dead).unwrap().unwrap();
        assert_eq!(object.state, 5);
        assert!(object.material.is_empty());
        assert_ne!(
            call(&mut f.engine, v, "alice", 10, vec![uid(&dead)])
                .get(BATCH_ITEM)
                .unwrap()
                .required(RESULT_STATUS)
                .unwrap()
                .number()
                .unwrap(),
            0
        );
        for node in [
            Node::int(STORAGE_STATUS_MASK, -1),
            Node::int(STORAGE_STATUS_MASK, if v.0 >= 2 { 8 } else { 4 }),
            Node::enumeration(STORAGE_STATUS_MASK, 1),
        ] {
            assert_eq!(reason(&call(&mut f.engine, v, "alice", 8, vec![node])), 7);
        }
        assert_eq!(
            reason(&call(
                &mut f.engine,
                v,
                "alice",
                8,
                vec![
                    Node::int(STORAGE_STATUS_MASK, 1),
                    Node::int(STORAGE_STATUS_MASK, 2)
                ]
            )),
            7
        );
    }
}

#[test]
fn archive_transactions_placeholders_draft_references_and_response_limits_are_atomic() {
    for v in Version::supported(true) {
        let mut f = Fixture::new();
        f.engine.experimental_v3 = true;
        let id = create(&mut f.engine, v, vec![]);
        let request = batch_option(
            req(v, vec![(21, vec![uid(&id)]), (10, vec![uid("missing")])]),
            3,
        );
        let response = f.engine.process("alice", &request).unwrap();
        assert_eq!(
            response
                .get(BATCH_ITEM)
                .unwrap()
                .required(RESULT_STATUS)
                .unwrap()
                .number()
                .unwrap(),
            3
        );
        payload(&call(&mut f.engine, v, "alice", 10, vec![uid(&id)]));
        payload(&call(&mut f.engine, v, "alice", 21, vec![uid(&id)]));
        let request = batch_option(
            req(v, vec![(22, vec![uid(&id)]), (10, vec![uid("missing")])]),
            3,
        );
        f.engine.process("alice", &request).unwrap();
        assert_eq!(
            reason(&call(&mut f.engine, v, "alice", 10, vec![uid(&id)])),
            13
        );
        let mut request = req(v, vec![(22, vec![uid(&id)])]);
        if let Value::Structure(message) = &mut request.value
            && let Value::Structure(header) = &mut message[0].value
        {
            header.push(Node::int(MAXIMUM_RESPONSE_SIZE, minimal_response_size(v)));
        }
        assert_eq!(reason(&f.engine.process("alice", &request).unwrap()), 2);
        assert_eq!(
            reason(&call(&mut f.engine, v, "alice", 10, vec![uid(&id)])),
            13
        );
        let response = f
            .engine
            .process(
                "alice",
                &req(
                    v,
                    vec![
                        (8, vec![Node::int(STORAGE_STATUS_MASK, 2)]),
                        (22, vec![]),
                        (10, vec![]),
                    ],
                ),
            )
            .unwrap();
        for item in response.all(BATCH_ITEM) {
            assert_eq!(item.required(RESULT_STATUS).unwrap().number().unwrap(), 0);
        }
        // Archive does not set the ID Placeholder: an explicit different target
        // does not replace the result of the preceding Locate.
        let other = create(&mut f.engine, v, vec![]);
        let selector = container(v, vec![uid(&id)]);
        let locate_fields = if v.0 == 1 {
            selector.children().unwrap().to_vec()
        } else {
            vec![selector]
        };
        let response = f
            .engine
            .process(
                "alice",
                &req(
                    v,
                    vec![(8, locate_fields), (21, vec![uid(&other)]), (10, vec![])],
                ),
            )
            .unwrap();
        for item in response.all(BATCH_ITEM) {
            assert_eq!(item.required(RESULT_STATUS).unwrap().number().unwrap(), 0);
        }
        if v.0 >= 3 {
            let response = f
                .engine
                .process(
                    "alice",
                    &req(
                        v,
                        vec![(
                            22,
                            vec![Node::reference(
                                UNIQUE_IDENTIFIER,
                                "missing-batch-reference",
                            )],
                        )],
                    ),
                )
                .unwrap();
            assert_ne!(
                response
                    .get(BATCH_ITEM)
                    .unwrap()
                    .required(RESULT_STATUS)
                    .unwrap()
                    .number()
                    .unwrap(),
                0
            );
            let mut request = req(v, vec![(22, vec![uid(&other)])]);
            if let Value::Structure(fields) = &mut request.value
                && let Value::Structure(item) = &mut fields[1].value
                && let Value::Structure(p) = &mut item
                    .iter_mut()
                    .find(|n| n.tag == REQUEST_PAYLOAD)
                    .unwrap()
                    .value
            {
                p.clear();
            }
            assert_eq!(
                reason(&f.engine.process("alice", &request).unwrap()),
                if v.0 >= 2 { 7 } else { 6 }
            );
        }
        f.engine.store.verify_audit().unwrap();
    }
}

#[test]
fn archive_date_is_read_only_and_restore_preserves_archival_access_policy() {
    for v in [Version(1, 4), Version(2, 0), Version(2, 1), Version(3, 0)] {
        let mut f = Fixture::new();
        f.engine.experimental_v3 = true;
        let id = create(&mut f.engine, v, vec![]);
        let exported = call(&mut f.engine, v, "alice", 43, vec![uid(&id)]);
        let mut fields =
            transfer_import_fields(v, payload(&exported), "restored-archive", false, None);
        if v.0 == 1 {
            fields.push(Node::structure(
                ATTRIBUTE,
                vec![
                    Node::text(ATTRIBUTE_NAME, "Archive Date"),
                    Node::date(ATTRIBUTE_VALUE, 123),
                ],
            ));
        } else if let Value::Structure(attrs) = &mut fields
            .iter_mut()
            .find(|n| n.tag == ATTRIBUTES)
            .unwrap()
            .value
        {
            attrs.push(Node::date(ARCHIVE_DATE, 123));
        }
        payload(&call(&mut f.engine, v, "alice", 42, fields));
        assert_eq!(
            reason(&call(
                &mut f.engine,
                v,
                "alice",
                10,
                vec![uid("restored-archive")]
            )),
            13
        );
        assert_eq!(storage_ids(&mut f.engine, v, Some(2)), ["restored-archive"]);
        payload(&call(
            &mut f.engine,
            v,
            "alice",
            22,
            vec![uid("restored-archive")],
        ));
        let clone = f
            .engine
            .store
            .get("alice", "restored-archive")
            .unwrap()
            .unwrap();
        assert!(!clone.attrs.iter().any(|a| a.tag == ARCHIVE_DATE));
        assert_eq!(
            clone.material,
            f.engine.store.get("alice", &id).unwrap().unwrap().material
        );
        let date = Node::date(ARCHIVE_DATE, 456);
        let field = if v.0 == 1 {
            Node::structure(
                ATTRIBUTE,
                vec![
                    Node::text(ATTRIBUTE_NAME, "Archive Date"),
                    Node::date(ATTRIBUTE_VALUE, 456),
                ],
            )
        } else {
            Node::structure(NEW_ATTRIBUTE, vec![date])
        };
        assert_eq!(
            reason(&call(&mut f.engine, v, "alice", 13, vec![uid(&id), field])),
            if v.0 >= 2 { 0x22 } else { 12 }
        );
    }
}

#[test]
fn archive_recovery_persists_exact_ciphertext_material_and_does_not_unwrap_early() {
    let mut f = Fixture::new();
    let v = Version(2, 1);
    let cp = aes_wrapping_parameters(false);
    let kek = register_wrapping_key(&mut f.engine, v, &[3; 32], vec![], cp.clone());
    payload(&call(&mut f.engine, v, "alice", 18, vec![uid(&kek)]));
    let id = create(&mut f.engine, v, vec![]);
    let spec = wrapping_spec(v, &kek, None, Some(cp), vec![]);
    let exported = call(&mut f.engine, v, "alice", 43, vec![uid(&id), spec]);
    let mut fields =
        transfer_import_fields(v, payload(&exported), "archived-envelope", false, Some(2));
    if let Value::Structure(a) = &mut fields
        .iter_mut()
        .find(|n| n.tag == ATTRIBUTES)
        .unwrap()
        .value
    {
        a.push(Node::date(ARCHIVE_DATE, 123));
    }
    payload(&call(&mut f.engine, v, "alice", 42, fields));
    let path = f._dir.path().join("keys.sqlite");
    let key = f._dir.path().join("master");
    drop(f.engine);
    f.engine = Engine::new(Store::open(&path, &key).unwrap(), false);
    assert_eq!(
        reason(&call(
            &mut f.engine,
            v,
            "alice",
            10,
            vec![
                uid("archived-envelope"),
                Node::enumeration(KEY_WRAP_TYPE, 2)
            ]
        )),
        13
    );
    payload(&call(
        &mut f.engine,
        v,
        "alice",
        22,
        vec![uid("archived-envelope")],
    ));
    payload(&call(
        &mut f.engine,
        v,
        "alice",
        10,
        vec![uid("archived-envelope")],
    ));
    let stored = f
        .engine
        .store
        .get("alice", "archived-envelope")
        .unwrap()
        .unwrap();
    assert!(stored.material.is_empty());
    assert!(stored.wrapped.as_ref().unwrap().opaque);
    payload(&call(&mut f.engine, v, "alice", 21, vec![uid(&kek)]));
    assert_eq!(
        reason(&call(
            &mut f.engine,
            v,
            "alice",
            10,
            vec![uid("archived-envelope")]
        )),
        0x40
    );
    payload(&call(&mut f.engine, v, "alice", 22, vec![uid(&kek)]));
    payload(&call(
        &mut f.engine,
        v,
        "alice",
        10,
        vec![uid("archived-envelope")],
    ));
}

#[test]
fn archived_derivation_sources_and_pair_peers_cannot_bypass_recovery() {
    for v in Version::supported(true) {
        let mut f = Fixture::new();
        f.engine.experimental_v3 = true;
        let source = derivation_source(
            &mut f.engine,
            v,
            2,
            2,
            9,
            &[7; 32],
            vec![usage_limits(3, 2)],
        );
        payload(&call(&mut f.engine, v, "alice", 21, vec![uid(&source)]));
        let fields = derive_fields(
            v,
            &[&source],
            2,
            256,
            2,
            vec![Node::structure(
                CRYPTOGRAPHIC_PARAMETERS,
                vec![Node::enumeration(HASHING_ALGORITHM, 6)],
            )],
            vec![],
        );
        assert_eq!(
            reason(&call(&mut f.engine, v, "alice", 5, fields.clone())),
            13
        );
        payload(&call(&mut f.engine, v, "alice", 22, vec![uid(&source)]));
        derived_id(&mut f.engine, v, fields);
        assert_eq!(remaining(&mut f.engine, v, &source), 2);
        if v >= Version(1, 1) {
            let (private, public) = active_rsa_pair(&mut f.engine, v, vec![]);
            let before = f.engine.store.list("alice").unwrap().len();
            payload(&call(&mut f.engine, v, "alice", 21, vec![uid(&public)]));
            assert_eq!(
                reason(&call(
                    &mut f.engine,
                    v,
                    "alice",
                    29,
                    vec![pair_source(v, &private)]
                )),
                13
            );
            assert_eq!(f.engine.store.list("alice").unwrap().len(), before);
            payload(&call(&mut f.engine, v, "alice", 22, vec![uid(&public)]));
            payload(&call(
                &mut f.engine,
                v,
                "alice",
                29,
                vec![pair_source(v, &private)],
            ));
        }
    }
}

#[test]
fn schema_eight_imported_archive_dates_require_recovery_after_upgrade() {
    let mut f = Fixture::new();
    let v = Version(2, 1);
    let id = create(&mut f.engine, v, vec![]);
    let mut obj = f.engine.store.get("alice", &id).unwrap().unwrap();
    let original = obj.material.clone();
    obj.attrs.push(Node::date(ARCHIVE_DATE, 123));
    obj.imported = true;
    f.engine.store.put(&obj).unwrap();
    let path = f._dir.path().join("keys.sqlite");
    let key = f._dir.path().join("master");
    drop(f.engine);
    legacy::write(&path, &key, &[serde_json::to_value(&obj).unwrap()], 8);
    f.engine = Engine::new(Store::open(&path, &key).unwrap(), false);
    assert_eq!(
        reason(&call(&mut f.engine, v, "alice", 10, vec![uid(&id)])),
        13
    );
    let date = Node::date(ARCHIVE_DATE, 123);
    let response = call(
        &mut f.engine,
        v,
        "alice",
        8,
        vec![
            Node::int(STORAGE_STATUS_MASK, 2),
            Node::structure(ATTRIBUTES, vec![date]),
        ],
    );
    assert_eq!(
        payload(&response)
            .required(UNIQUE_IDENTIFIER)
            .unwrap()
            .identifier_text()
            .unwrap(),
        id
    );
    payload(&call(&mut f.engine, v, "alice", 22, vec![uid(&id)]));
    assert_eq!(
        f.engine.store.get("alice", &id).unwrap().unwrap().material,
        original
    );
}

fn ec_pair(e: &mut Engine, v: Version, alg: u32, curve: u32, extra: Vec<Node>) -> (String, String) {
    let mut a = vec![
        Node::enumeration(CRYPTOGRAPHIC_ALGORITHM, alg),
        Node::int(CRYPTOGRAPHIC_USAGE_MASK, 3),
        Node::structure(
            CRYPTOGRAPHIC_DOMAIN_PARAMETERS,
            vec![Node::enumeration(RECOMMENDED_CURVE, curve)],
        ),
    ];
    a.extend(extra);
    let r = call(e, v, "alice", 2, vec![pair_common(v, a)]);
    let ids = pair_ids(&r);
    for id in [&ids.0, &ids.1] {
        payload(&call(e, v, "alice", 18, vec![uid(id)]));
    }
    ids
}
fn ec_get_material(
    e: &mut Engine,
    v: Version,
    id: &str,
    kind: u32,
    format: u32,
    compression: Option<u32>,
) -> Node {
    let mut fields = vec![uid(id), Node::enumeration(KEY_FORMAT_TYPE, format)];
    if let Some(c) = compression {
        fields.push(Node::enumeration(KEY_COMPRESSION_TYPE, c));
    }
    let r = call(e, v, "alice", 10, fields);
    payload(&r)
        .required(if kind == 4 { PRIVATE_KEY } else { PUBLIC_KEY })
        .unwrap()
        .clone()
}

#[test]
fn ec_pairs_formats_registration_and_curve_versions_preserve_components() {
    for v in Version::supported(true) {
        // secp256k1 (25) below needs `--ec-curves extended`.
        let mut f = Fixture::extended_curves();
        f.engine.experimental_v3 = true;
        for curve in [7, 10] {
            let (private, public) = ec_pair(&mut f.engine, v, 6, curve, vec![]);
            let expected_private = f.engine.store.get("alice", &private).unwrap().unwrap();
            let expected_public = f.engine.store.get("alice", &public).unwrap().unwrap();
            let legacy = if v >= Version(1, 3) { 20 } else { 14 };
            assert_eq!(expected_private.format, legacy);
            assert_eq!(expected_public.format, legacy + 1);
            for (id, kind, formats) in [
                (&private, 4, vec![4, 6, legacy]),
                (&public, 3, vec![5, legacy + 1]),
            ] {
                for format in formats {
                    let object = ec_get_material(&mut f.engine, v, id, kind, format, None);
                    let material = object
                        .required(KEY_BLOCK)
                        .unwrap()
                        .required(KEY_VALUE)
                        .unwrap()
                        .required(KEY_MATERIAL)
                        .unwrap();
                    if format >= 14 {
                        assert!(matches!(material.value, Value::Structure(_)));
                    }
                    let r = call(
                        &mut f.engine,
                        v,
                        "alice",
                        3,
                        vec![
                            Node::enumeration(OBJECT_TYPE, kind),
                            container(v, vec![Node::int(CRYPTOGRAPHIC_USAGE_MASK, 3)]),
                            object,
                        ],
                    );
                    let clone = payload(&r)
                        .required(UNIQUE_IDENTIFIER)
                        .unwrap()
                        .identifier_text()
                        .unwrap();
                    let value = f.engine.store.get("alice", clone).unwrap().unwrap();
                    assert_eq!(
                        keytend_kmip_server::crypto::ec::info(&value.material, kind == 4)
                            .unwrap()
                            .0,
                        curve
                    );
                    let original = if kind == 4 {
                        openssl::pkey::PKey::private_key_from_der(&expected_private.material)
                            .unwrap()
                            .public_key_to_der()
                            .unwrap()
                    } else {
                        expected_public.material.clone()
                    };
                    let cloned = if kind == 4 {
                        openssl::pkey::PKey::private_key_from_der(&value.material)
                            .unwrap()
                            .public_key_to_der()
                            .unwrap()
                    } else {
                        value.material.clone()
                    };
                    assert_eq!(original, cloned);
                }
            }
            for compression in [2, 4] {
                let object =
                    ec_get_material(&mut f.engine, v, &public, 3, legacy + 1, Some(compression));
                let r = call(
                    &mut f.engine,
                    v,
                    "alice",
                    3,
                    vec![
                        Node::enumeration(OBJECT_TYPE, 3),
                        container(v, vec![Node::int(CRYPTOGRAPHIC_USAGE_MASK, 2)]),
                        object,
                    ],
                );
                payload(&r);
            }
            assert_ne!(
                call(
                    &mut f.engine,
                    v,
                    "alice",
                    10,
                    vec![uid(&public), Node::enumeration(KEY_COMPRESSION_TYPE, 3)]
                )
                .get(BATCH_ITEM)
                .unwrap()
                .required(RESULT_STATUS)
                .unwrap()
                .number()
                .unwrap(),
                0
            );
        }
        if v >= Version(1, 2) {
            ec_pair(&mut f.engine, v, 26, 25, vec![]);
        }
        if v.0 >= 2 {
            let id = f
                .engine
                .store
                .list("alice")
                .unwrap()
                .iter()
                .find(|o| o.object_type == 4)
                .unwrap()
                .id
                .clone();
            assert_eq!(
                reason(&call(
                    &mut f.engine,
                    v,
                    "alice",
                    10,
                    vec![uid(&id), Node::enumeration(KEY_FORMAT_TYPE, 14)]
                )),
                16
            );
        }
    }
}

#[test]
fn ec_signatures_combined_hashes_prehashes_validity_and_budgets_are_enforced() {
    for v in Version::supported(true)
        .into_iter()
        .filter(|v| *v >= Version(1, 2))
    {
        let mut f = Fixture::new();
        f.engine.experimental_v3 = true;
        let (private, public) = ec_pair(&mut f.engine, v, 26, 7, vec![usage_limits(10, 2)]);
        let native = openssl::pkey::PKey::public_key_from_der(
            &f.engine
                .store
                .get("alice", &public)
                .unwrap()
                .unwrap()
                .material,
        )
        .unwrap();
        for (hash, combined) in [(6, 14), (7, 15), (8, 16)] {
            let cp = Node::structure(
                CRYPTOGRAPHIC_PARAMETERS,
                vec![Node::enumeration(DIGITAL_SIGNATURE_ALGORITHM, combined)],
            );
            let signed = call(
                &mut f.engine,
                v,
                "alice",
                33,
                vec![
                    uid(&private),
                    cp.clone(),
                    Node::bytes(DATA, b"EC independent message".to_vec()),
                ],
            );
            let signature = payload(&signed)
                .required(SIGNATURE_DATA)
                .unwrap()
                .byte_string()
                .unwrap()
                .to_vec();
            let mut verify = openssl::sign::Verifier::new(
                keytend_kmip_server::crypto::rsa::digest(hash).unwrap(),
                &native,
            )
            .unwrap();
            verify.update(b"EC independent message").unwrap();
            assert!(verify.verify(&signature).unwrap());
            for (message, expected) in [
                (b"EC independent message".as_slice(), 1),
                (b"incorrect".as_slice(), 2),
            ] {
                let r = call(
                    &mut f.engine,
                    v,
                    "alice",
                    34,
                    vec![
                        uid(&public),
                        cp.clone(),
                        Node::bytes(DATA, message.to_vec()),
                        Node::bytes(SIGNATURE_DATA, signature.clone()),
                    ],
                );
                assert_eq!(
                    payload(&r)
                        .required(VALIDITY_INDICATOR)
                        .unwrap()
                        .number()
                        .unwrap(),
                    expected
                );
            }
            if v >= Version(1, 4) {
                let digest = openssl::hash::hash(
                    keytend_kmip_server::crypto::rsa::digest(hash).unwrap(),
                    b"prehashed message",
                )
                .unwrap();
                let r = call(
                    &mut f.engine,
                    v,
                    "alice",
                    33,
                    vec![
                        uid(&private),
                        cp.clone(),
                        Node::bytes(DIGESTED_DATA, digest.to_vec()),
                    ],
                );
                let sig = payload(&r)
                    .required(SIGNATURE_DATA)
                    .unwrap()
                    .byte_string()
                    .unwrap()
                    .to_vec();
                let r = call(
                    &mut f.engine,
                    v,
                    "alice",
                    34,
                    vec![
                        uid(&public),
                        cp.clone(),
                        Node::bytes(DATA, b"prehashed message".to_vec()),
                        Node::bytes(SIGNATURE_DATA, sig),
                    ],
                );
                assert_eq!(
                    payload(&r)
                        .required(VALIDITY_INDICATOR)
                        .unwrap()
                        .number()
                        .unwrap(),
                    1
                );
            }
        }
        let before = remaining(&mut f.engine, v, &private);
        let conflicting = Node::structure(
            CRYPTOGRAPHIC_PARAMETERS,
            vec![
                Node::enumeration(DIGITAL_SIGNATURE_ALGORITHM, 14),
                Node::enumeration(HASHING_ALGORITHM, 7),
            ],
        );
        assert_eq!(
            reason(&call(
                &mut f.engine,
                v,
                "alice",
                33,
                vec![uid(&private), conflicting, Node::bytes(DATA, vec![])]
            )),
            7
        );
        assert_eq!(remaining(&mut f.engine, v, &private), before);
        payload(&call(&mut f.engine, v, "alice", 21, vec![uid(&private)]));
        assert_eq!(
            reason(&call(&mut f.engine, v, "alice", 33, vec![uid(&private)])),
            13
        );
    }
}

#[test]
fn ec_invalid_scalars_points_constraints_and_formats_leave_no_objects() {
    let mut f = Fixture::new();
    let v = Version(2, 1);
    for scalar in [vec![0; 8], vec![0x80; 8]] {
        let object = Node::structure(
            PRIVATE_KEY,
            vec![Node::structure(
                KEY_BLOCK,
                vec![
                    Node::enumeration(KEY_FORMAT_TYPE, 20),
                    Node::enumeration(CRYPTOGRAPHIC_ALGORITHM, 6),
                    Node::structure(
                        KEY_VALUE,
                        vec![Node::structure(
                            KEY_MATERIAL,
                            vec![
                                Node::enumeration(RECOMMENDED_CURVE, 7),
                                Node {
                                    tag: D,
                                    value: Value::BigInteger(scalar),
                                },
                            ],
                        )],
                    ),
                ],
            )],
        );
        assert_eq!(
            reason(&call(
                &mut f.engine,
                v,
                "alice",
                3,
                vec![
                    Node::enumeration(OBJECT_TYPE, 4),
                    container(v, vec![]),
                    object
                ]
            )),
            7
        );
    }
    for curve in [7, 69] {
        let object = Node::structure(
            PUBLIC_KEY,
            vec![Node::structure(
                KEY_BLOCK,
                vec![
                    Node::enumeration(KEY_FORMAT_TYPE, 21),
                    Node::enumeration(CRYPTOGRAPHIC_ALGORITHM, 6),
                    Node::structure(
                        KEY_VALUE,
                        vec![Node::structure(
                            KEY_MATERIAL,
                            vec![
                                Node::enumeration(RECOMMENDED_CURVE, curve),
                                Node::bytes(Q_STRING, vec![0]),
                            ],
                        )],
                    ),
                ],
            )],
        );
        assert_ne!(
            call(
                &mut f.engine,
                v,
                "alice",
                3,
                vec![
                    Node::enumeration(OBJECT_TYPE, 3),
                    container(v, vec![]),
                    object
                ]
            )
            .get(BATCH_ITEM)
            .unwrap()
            .required(RESULT_STATUS)
            .unwrap()
            .number()
            .unwrap(),
            0
        );
    }
    let common = pair_common(
        v,
        vec![
            Node::enumeration(CRYPTOGRAPHIC_ALGORITHM, 6),
            Node::int(CRYPTOGRAPHIC_LENGTH, 384),
            Node::structure(
                CRYPTOGRAPHIC_DOMAIN_PARAMETERS,
                vec![Node::enumeration(RECOMMENDED_CURVE, 7)],
            ),
        ],
    );
    assert_eq!(reason(&call(&mut f.engine, v, "alice", 2, vec![common])), 7);
    assert!(f.engine.store.list("alice").unwrap().is_empty());
}

#[test]
fn ec_pair_replacement_keeps_originals_and_preserves_requested_curve_and_format() {
    for v in Version::supported(true)
        .into_iter()
        .filter(|v| *v >= Version(1, 1))
    {
        let mut f = Fixture::new();
        f.engine.experimental_v3 = true;
        let (private, public) = ec_pair(&mut f.engine, v, 6, 7, vec![]);
        let original = f
            .engine
            .store
            .get("alice", &private)
            .unwrap()
            .unwrap()
            .material
            .clone();
        let common = pair_common(
            v,
            vec![
                Node::int(CRYPTOGRAPHIC_LENGTH, 384),
                Node::structure(
                    CRYPTOGRAPHIC_DOMAIN_PARAMETERS,
                    vec![Node::enumeration(RECOMMENDED_CURVE, 10)],
                ),
            ],
        );
        let r = call(
            &mut f.engine,
            v,
            "alice",
            29,
            vec![pair_source(v, &private), common],
        );
        let (next_private, next_public) = pair_ids(&r);
        assert_eq!(
            f.engine
                .store
                .get("alice", &private)
                .unwrap()
                .unwrap()
                .material,
            original
        );
        assert_eq!(
            f.engine
                .store
                .get("alice", &next_private)
                .unwrap()
                .unwrap()
                .bits,
            384
        );
        assert_eq!(
            keytend_kmip_server::crypto::ec::info(
                &f.engine
                    .store
                    .get("alice", &next_public)
                    .unwrap()
                    .unwrap()
                    .material,
                false
            )
            .unwrap()
            .0,
            10
        );
        assert_ne!(next_public, public);
        assert_eq!(
            reason(&call(
                &mut f.engine,
                v,
                "alice",
                29,
                vec![pair_source(v, &private)]
            )),
            12
        );
        f.engine.store.verify_audit().unwrap();
    }
}

#[test]
fn ec_wrapped_restore_sensitive_policy_and_rekey_imported_short_ids_remain_consistent() {
    for v in [Version(1, 4), Version(2, 1), Version(3, 0)] {
        let mut f = Fixture::new();
        f.engine.experimental_v3 = true;
        let (private, public) = ec_pair(&mut f.engine, v, 6, 7, vec![]);
        let original = f
            .engine
            .store
            .get("alice", &private)
            .unwrap()
            .unwrap()
            .material
            .clone();
        let cp = aes_wrapping_parameters(true);
        let kek = register_wrapping_key(&mut f.engine, v, &[3; 32], vec![], cp.clone());
        payload(&call(&mut f.engine, v, "alice", 18, vec![uid(&kek)]));
        for format in [4, 6, 20] {
            let spec = wrapping_spec(v, &kek, None, Some(cp.clone()), vec![]);
            let r = get_wrapped(&mut f.engine, v, &private, spec, format);
            let object = wrapped_object(&r);
            let registered = register_wrapped(
                &mut f.engine,
                v,
                object,
                vec![Node::int(CRYPTOGRAPHIC_USAGE_MASK, 1)],
            );
            let registered = payload(&registered)
                .required(UNIQUE_IDENTIFIER)
                .unwrap()
                .identifier_text()
                .unwrap()
                .to_owned();
            let obj = f.engine.store.get("alice", &registered).unwrap().unwrap();
            assert_eq!(
                keytend_kmip_server::crypto::ec::info(&obj.material, true)
                    .unwrap()
                    .0,
                7
            );
            let actual = openssl::pkey::PKey::private_key_from_der(&obj.material)
                .unwrap()
                .public_key_to_der()
                .unwrap();
            let expected = openssl::pkey::PKey::private_key_from_der(&original)
                .unwrap()
                .public_key_to_der()
                .unwrap();
            assert_eq!(actual, expected);
        }
        // Import an encoded EC pair, then replace it. Server-generated short IDs
        // must be assigned to the new identities instead of copying restore IDs.
        let mut imported = vec![];
        for (id, kind, format, new_id) in [
            (&private, 4, 20, "restored-ec-private"),
            (&public, 3, 21, "restored-ec-public"),
        ] {
            let exported = call(
                &mut f.engine,
                v,
                "alice",
                43,
                vec![uid(id), Node::enumeration(KEY_FORMAT_TYPE, format)],
            );
            let mut fields = transfer_import_fields(v, payload(&exported), new_id, false, None);
            if v.0 >= 2
                && let Value::Structure(attrs) = &mut fields
                    .iter_mut()
                    .find(|n| n.tag == ATTRIBUTES)
                    .unwrap()
                    .value
            {
                *attrs.iter_mut().find(|n| n.tag == KEY_FORMAT_TYPE).unwrap() =
                    Node::enumeration(KEY_FORMAT_TYPE, format);
            }
            payload(&call(&mut f.engine, v, "alice", 42, fields));
            let mut obj = f.engine.store.get("alice", new_id).unwrap().unwrap();
            let peer = if kind == 4 {
                "restored-ec-public"
            } else {
                "restored-ec-private"
            };
            obj.attrs.retain(|a| a.tag != LINK);
            obj.attribute_indices.remove(&format!("s:{LINK:06x}"));
            obj.attrs
                .push(history_link(if kind == 4 { 0x102 } else { 0x103 }, peer));
            f.engine.store.put(&obj).unwrap();
            imported.push(obj.id.clone());
        }
        let replaced = call(
            &mut f.engine,
            v,
            "alice",
            29,
            vec![pair_source(v, &imported[0])],
        );
        let (next_private, next_public) = pair_ids(&replaced);
        for id in [next_private, next_public] {
            let r = call(&mut f.engine, v, "alice", 11, vec![uid(&id)]);
            if v >= Version(2, 1) {
                let a = payload(&r).required(ATTRIBUTES).unwrap();
                assert_eq!(a.all(SHORT_UNIQUE_IDENTIFIER).count(), 1);
                assert_eq!(
                    a.required(SHORT_UNIQUE_IDENTIFIER)
                        .unwrap()
                        .byte_string()
                        .unwrap(),
                    openssl::sha::sha256(id.as_bytes())
                );
            }
        }
        let flag = if v.0 == 1 {
            Node::structure(
                ATTRIBUTE,
                vec![
                    Node::text(ATTRIBUTE_NAME, "Sensitive"),
                    Node::boolean(ATTRIBUTE_VALUE, true),
                ],
            )
        } else {
            Node::structure(NEW_ATTRIBUTE, vec![Node::boolean(SENSITIVE, true)])
        };
        payload(&call(
            &mut f.engine,
            v,
            "alice",
            if v.0 == 1 { 14 } else { 49 },
            vec![uid(&private), flag],
        ));
        assert_eq!(
            reason(&call(&mut f.engine, v, "alice", 10, vec![uid(&private)])),
            0x16
        );
        let spec = wrapping_spec(v, &kek, None, Some(cp.clone()), vec![]);
        payload(&get_wrapped(&mut f.engine, v, &private, spec, 4));
    }
}

fn grant(
    owner: &str,
    id: &str,
    operations: &[u32],
) -> keytend_kmip_server::authorization::ObjectGrant {
    keytend_kmip_server::authorization::ObjectGrant {
        owner: owner.into(),
        user: None,
        device: None,
        identifier: id.into(),
        operations: operations.to_vec(),
    }
}
fn granted(
    engine: &mut Engine,
    caller: &str,
    v: Version,
    op: u32,
    fields: Vec<Node>,
    allowed: &[u32],
    grants: &[keytend_kmip_server::authorization::ObjectGrant],
) -> Node {
    engine
        .process_with_grants(caller, &req(v, vec![(op, fields)]), Some(allowed), grants)
        .unwrap()
}

#[test]
fn exact_object_grants_separate_get_metadata_locate_and_operation_policy() {
    for v in Version::supported(true) {
        let mut f = Fixture::new();
        f.engine.experimental_v3 = true;
        let shared = create(&mut f.engine, v, vec![]);
        let hidden = create(&mut f.engine, v, vec![]);
        let material = f
            .engine
            .store
            .get("alice", &shared)
            .unwrap()
            .unwrap()
            .material
            .clone();
        let own = get_id(&call(
            &mut f.engine,
            v,
            "bob",
            1,
            vec![Node::enumeration(OBJECT_TYPE, 2), attrs(v, vec![])],
        ));
        let get_only = [grant("alice", &shared, &[10])];
        let policy = [8, 10, 11, 12];
        let response = granted(
            &mut f.engine,
            "bob",
            v,
            10,
            vec![uid(&shared)],
            &policy,
            &get_only,
        );
        let object = payload(&response)
            .required(SYMMETRIC_KEY)
            .unwrap()
            .required(KEY_BLOCK)
            .unwrap()
            .required(KEY_VALUE)
            .unwrap()
            .required(KEY_MATERIAL)
            .unwrap();
        assert_eq!(object.byte_string().unwrap(), material);
        assert_eq!(
            reason(&granted(
                &mut f.engine,
                "bob",
                v,
                10,
                vec![uid(&hidden)],
                &policy,
                &get_only
            )),
            not_found(v)
        );
        assert_eq!(
            reason(&granted(
                &mut f.engine,
                "bob",
                v,
                11,
                vec![uid(&shared)],
                &policy,
                &get_only
            )),
            not_found(v)
        );
        assert_eq!(
            reason(&granted(
                &mut f.engine,
                "bob",
                v,
                12,
                vec![uid(&shared)],
                &policy,
                &get_only
            )),
            not_found(v)
        );
        let listing = granted(&mut f.engine, "bob", v, 8, vec![], &policy, &get_only);
        assert_eq!(
            payload(&listing)
                .all(UNIQUE_IDENTIFIER)
                .map(|n| n.identifier_text().unwrap())
                .collect::<Vec<_>>(),
            vec![own.as_str()]
        );
        for op in [1, 13, 20] {
            assert_eq!(
                reason(&granted(
                    &mut f.engine,
                    "bob",
                    v,
                    op,
                    vec![uid(&shared)],
                    &policy,
                    &get_only
                )),
                12
            );
        }
        // A broad operation ACL still cannot turn a read grant into object ownership.
        assert_eq!(
            reason(&granted(
                &mut f.engine,
                "bob",
                v,
                20,
                vec![uid(&shared)],
                &[20],
                &get_only
            )),
            not_found(v)
        );
        assert_eq!(
            reason(&granted(
                &mut f.engine,
                "bob",
                v,
                10,
                vec![uid(&shared)],
                &[],
                &get_only
            )),
            12
        );
        let list_only = [grant("alice", &shared, &[8])];
        let listing = granted(&mut f.engine, "bob", v, 8, vec![], &policy, &list_only);
        let ids = payload(&listing)
            .all(UNIQUE_IDENTIFIER)
            .map(|n| n.identifier_text().unwrap())
            .collect::<Vec<_>>();
        assert_eq!(ids.len(), 2);
        assert!(ids.contains(&shared.as_str()) && ids.contains(&own.as_str()));
        assert_eq!(
            reason(&granted(
                &mut f.engine,
                "bob",
                v,
                10,
                vec![uid(&shared)],
                &policy,
                &list_only
            )),
            not_found(v)
        );
        for op in [11, 12] {
            payload(&granted(
                &mut f.engine,
                "bob",
                v,
                op,
                vec![uid(&shared)],
                &policy,
                &[grant("alice", &shared, &[op])],
            ));
        }
        assert_eq!(
            reason(&granted(
                &mut f.engine,
                "bob",
                v,
                10,
                vec![uid(&shared)],
                &policy,
                &[grant("carol", &shared, &[10])]
            )),
            not_found(v)
        );
        // No grant state survives this request; ordinary ownership lookups remain strict.
        assert_eq!(
            reason(&call(&mut f.engine, v, "bob", 10, vec![uid(&shared)])),
            not_found(v)
        );
        assert_eq!(
            reason(&granted(
                &mut f.engine,
                "bob",
                v,
                10,
                vec![uid(&shared)],
                &policy,
                &[]
            )),
            not_found(v)
        );
        assert_eq!(
            f.engine
                .store
                .get("alice", &shared)
                .unwrap()
                .unwrap()
                .material,
            material
        );
        assert!(f.engine.store.get("bob", &shared).unwrap().is_none());
        f.engine.store.verify_audit().unwrap();
    }
}

#[test]
fn scoped_locate_paginates_one_global_authorized_order_without_leaking_hidden_totals() {
    let mut f = Fixture::new();
    let v = Version(2, 1);
    let mut all = vec![];
    for (index, owner) in ["alice", "alice", "alice", "bob", "bob", "carol", "carol"]
        .into_iter()
        .enumerate()
    {
        let id = get_id(&call(
            &mut f.engine,
            v,
            owner,
            1,
            vec![Node::enumeration(OBJECT_TYPE, 2), attrs(v, vec![])],
        ));
        let mut object = f.engine.store.get(owner, &id).unwrap().unwrap();
        object.created = 100 + index as i64;
        f.engine.store.put(&object).unwrap();
        all.push(id);
    }
    let grants = [
        grant("alice", &all[0], &[8]),
        grant("alice", &all[2], &[8]),
        grant("carol", &all[5], &[8]),
        grant("bob", &all[3], &[8]),
    ];
    let expected = [&all[5], &all[4], &all[3], &all[2], &all[0]];
    let mut observed = vec![];
    for offset in [0, 2, 4] {
        let response = granted(
            &mut f.engine,
            "bob",
            v,
            8,
            vec![Node::int(MAXIMUM_ITEMS, 2), Node::int(OFFSET_ITEMS, offset)],
            &[8],
            &grants,
        );
        assert_eq!(
            payload(&response)
                .required(LOCATED_ITEMS)
                .unwrap()
                .number()
                .unwrap(),
            5
        );
        observed.extend(
            payload(&response)
                .all(UNIQUE_IDENTIFIER)
                .map(|n| n.string().unwrap().to_owned()),
        );
    }
    assert_eq!(observed, expected.into_iter().cloned().collect::<Vec<_>>());
    let no_rows = granted(
        &mut f.engine,
        "bob",
        v,
        8,
        vec![Node::int(MAXIMUM_ITEMS, 0)],
        &[8],
        &grants,
    );
    assert_eq!(
        payload(&no_rows)
            .required(LOCATED_ITEMS)
            .unwrap()
            .number()
            .unwrap(),
        5
    );
    assert_eq!(payload(&no_rows).all(UNIQUE_IDENTIFIER).count(), 0);
    let filter = if v.0 == 1 {
        vec![]
    } else {
        vec![Node::structure(ATTRIBUTES, vec![uid(&all[6])])]
    };
    let hidden = granted(&mut f.engine, "bob", v, 8, filter, &[8], &grants);
    assert_eq!(
        payload(&hidden)
            .required(LOCATED_ITEMS)
            .unwrap()
            .number()
            .unwrap(),
        0
    );
    let batch = req(
        v,
        vec![
            (8, vec![Node::structure(ATTRIBUTES, vec![uid(&all[0])])]),
            (10, vec![Node::enumeration(UNIQUE_IDENTIFIER, 1)]),
        ],
    );
    let response = f
        .engine
        .process_with_grants("bob", &batch, Some(&[8, 10]), &grants)
        .unwrap();
    let items = response.all(BATCH_ITEM).collect::<Vec<_>>();
    assert_eq!(
        items[0].required(RESULT_STATUS).unwrap().number().unwrap(),
        0
    );
    assert_eq!(
        items[1].required(RESULT_REASON).unwrap().number().unwrap(),
        not_found(v)
    );
}

#[test]
fn delegated_get_undo_retains_actual_owner_exposure_and_authenticated_actor_audit() {
    for v in Version::supported(true)
        .into_iter()
        .filter(|v| *v >= Version(1, 1))
    {
        let mut f = Fixture::new();
        f.engine.experimental_v3 = true;
        let shared = create(&mut f.engine, v, vec![]);
        let request = batch_option(
            req(
                v,
                vec![
                    (10, vec![uid(&shared)]),
                    (10, vec![uid("missing-delegation")]),
                ],
            ),
            3,
        );
        let response = f
            .engine
            .process_with_grants(
                "bob",
                &request,
                Some(&[10]),
                &[grant("alice", &shared, &[10])],
            )
            .unwrap();
        let items = response.all(BATCH_ITEM).collect::<Vec<_>>();
        assert_eq!(
            items[0].required(RESULT_STATUS).unwrap().number().unwrap(),
            3
        );
        assert_eq!(
            items[1].required(RESULT_STATUS).unwrap().number().unwrap(),
            1
        );
        let object = f.engine.store.get("alice", &shared).unwrap().unwrap();
        assert_eq!(object.metadata.fresh, Some(false));
        if v >= Version(1, 4) {
            assert_eq!(object.metadata.never_extractable, Some(false));
        }
        let conn = rusqlite::Connection::open(f._dir.path().join("keys.sqlite")).unwrap();
        let actors = conn
            .prepare("SELECT principal FROM audit ORDER BY seq DESC LIMIT 2")
            .unwrap()
            .query_map([], |r| r.get::<_, String>(0))
            .unwrap()
            .collect::<rusqlite::Result<Vec<_>>>()
            .unwrap();
        assert_eq!(actors, vec!["bob", "bob"]);
        f.engine.store.verify_audit().unwrap();
        let fresh = create(&mut f.engine, v, vec![]);
        let mut request = req(v, vec![(10, vec![uid(&fresh)])]);
        let Value::Structure(fields) = &mut request.value else {
            unreachable!()
        };
        let Value::Structure(header) = &mut fields[0].value else {
            unreachable!()
        };
        header.push(Node::int(MAXIMUM_RESPONSE_SIZE, minimal_response_size(v)));
        let response = f
            .engine
            .process_with_grants(
                "bob",
                &request,
                Some(&[10]),
                &[grant("alice", &fresh, &[10])],
            )
            .unwrap();
        assert_eq!(reason(&response), 2);
        assert_eq!(
            f.engine
                .store
                .get("alice", &fresh)
                .unwrap()
                .unwrap()
                .metadata
                .fresh,
            Some(true)
        );
    }
}

fn get_id(response: &Node) -> String {
    payload(response)
        .required(UNIQUE_IDENTIFIER)
        .unwrap()
        .identifier_text()
        .unwrap()
        .to_owned()
}

#[test]
fn shared_get_preserves_extraction_rules_without_authorizing_foreign_wrapping_keys() {
    for v in [Version(1, 4), Version(2, 1), Version(3, 0)] {
        let mut f = Fixture::new();
        f.engine.experimental_v3 = true;
        let target = create(&mut f.engine, v, vec![Node::boolean(SENSITIVE, true)]);
        let expected = f
            .engine
            .store
            .get("alice", &target)
            .unwrap()
            .unwrap()
            .material
            .clone();
        let alice_kek = register_wrapping_key(
            &mut f.engine,
            v,
            &[7; 16],
            vec![Node::boolean(SENSITIVE, true)],
            aes_wrapping_parameters(false),
        );
        payload(&call(&mut f.engine, v, "alice", 18, vec![uid(&alice_kek)]));
        let own_kek = get_id(&call(
            &mut f.engine,
            v,
            "bob",
            1,
            vec![
                Node::enumeration(OBJECT_TYPE, 2),
                container(
                    v,
                    vec![
                        Node::enumeration(CRYPTOGRAPHIC_ALGORITHM, 3),
                        Node::int(CRYPTOGRAPHIC_LENGTH, 128),
                        Node::int(CRYPTOGRAPHIC_USAGE_MASK, 48),
                        aes_wrapping_parameters(false),
                    ],
                ),
            ],
        ));
        payload(&call(&mut f.engine, v, "bob", 18, vec![uid(&own_kek)]));
        let own_material = f
            .engine
            .store
            .get("bob", &own_kek)
            .unwrap()
            .unwrap()
            .material
            .clone();
        let grants = [
            grant("alice", &target, &[10]),
            grant("alice", &alice_kek, &[10]),
        ];
        assert_ne!(
            result_status(&granted(
                &mut f.engine,
                "bob",
                v,
                10,
                vec![uid(&target)],
                &[10],
                &grants
            )),
            0
        );
        let own_spec = wrapping_spec(
            v,
            &own_kek,
            Some(1),
            Some(aes_wrapping_parameters(false)),
            vec![],
        );
        let wrapped = granted(
            &mut f.engine,
            "bob",
            v,
            10,
            vec![uid(&target), own_spec],
            &[10],
            &grants,
        );
        let object = wrapped_object(&wrapped);
        let encrypted = object
            .required(KEY_BLOCK)
            .unwrap()
            .required(KEY_VALUE)
            .unwrap()
            .byte_string()
            .unwrap();
        assert_eq!(
            keytend_kmip_server::crypto::wrapping::aes(&own_material, encrypted, false, false)
                .unwrap()
                .as_slice(),
            expected
        );
        let own_target = get_id(&call(
            &mut f.engine,
            v,
            "bob",
            1,
            vec![Node::enumeration(OBJECT_TYPE, 2), attrs(v, vec![])],
        ));
        let forbidden = wrapping_spec(
            v,
            &alice_kek,
            Some(1),
            Some(aes_wrapping_parameters(false)),
            vec![],
        );
        assert_eq!(
            reason(&granted(
                &mut f.engine,
                "bob",
                v,
                10,
                vec![uid(&own_target), forbidden],
                &[10],
                &grants
            )),
            wrapping_not_found(v)
        );
        assert_eq!(
            f.engine
                .store
                .get("alice", &target)
                .unwrap()
                .unwrap()
                .material,
            expected
        );
        f.engine.store.verify_audit().unwrap();
    }
}

#[test]
fn draft_name_references_resolve_only_objects_granted_for_the_current_operation() {
    let mut f = Fixture::new();
    let v = Version(3, 0);
    f.engine.experimental_v3 = true;
    let shared = create(&mut f.engine, v, vec![Node::text(NAME, "shared-name")]);
    create(&mut f.engine, v, vec![Node::text(NAME, "hidden-name")]);
    let grants = [grant("alice", &shared, &[10])];
    let response = granted(
        &mut f.engine,
        "bob",
        v,
        10,
        vec![Node::name_reference(UNIQUE_IDENTIFIER, "shared-name")],
        &[8, 10, 11],
        &grants,
    );
    assert_eq!(get_id(&response), shared);
    for (op, name) in [(10, "hidden-name"), (11, "shared-name")] {
        assert_eq!(
            reason(&granted(
                &mut f.engine,
                "bob",
                v,
                op,
                vec![Node::name_reference(UNIQUE_IDENTIFIER, name)],
                &[8, 10, 11],
                &grants
            )),
            0x37
        );
    }
    let listing = granted(&mut f.engine, "bob", v, 8, vec![], &[8, 10, 11], &grants);
    assert_eq!(payload(&listing).all(UNIQUE_IDENTIFIER).count(), 0);
}

fn result_status(response: &Node) -> u32 {
    response
        .required(BATCH_ITEM)
        .unwrap()
        .required(RESULT_STATUS)
        .unwrap()
        .number()
        .unwrap()
}

#[test]
fn object_grants_cannot_bypass_archival_access_or_recover_another_owners_key() {
    for v in Version::supported(true) {
        let mut f = Fixture::new();
        f.engine.experimental_v3 = true;
        let shared = create(&mut f.engine, v, vec![]);
        let grants = [grant("alice", &shared, &[8, 10])];
        payload(&call(&mut f.engine, v, "alice", 21, vec![uid(&shared)]));
        assert_eq!(
            reason(&granted(
                &mut f.engine,
                "bob",
                v,
                10,
                vec![uid(&shared)],
                &[8, 10, 22],
                &grants
            )),
            13
        );
        let online = granted(&mut f.engine, "bob", v, 8, vec![], &[8, 10, 22], &grants);
        assert_eq!(payload(&online).all(UNIQUE_IDENTIFIER).count(), 0);
        let archival = granted(
            &mut f.engine,
            "bob",
            v,
            8,
            vec![Node::int(STORAGE_STATUS_MASK, 2)],
            &[8, 10, 22],
            &grants,
        );
        assert_eq!(get_id(&archival), shared);
        assert_eq!(
            reason(&granted(
                &mut f.engine,
                "bob",
                v,
                22,
                vec![uid(&shared)],
                &[8, 10, 22],
                &grants
            )),
            not_found(v)
        );
        payload(&call(&mut f.engine, v, "alice", 22, vec![uid(&shared)]));
        payload(&granted(
            &mut f.engine,
            "bob",
            v,
            10,
            vec![uid(&shared)],
            &[8, 10, 22],
            &grants,
        ));
    }
}

#[test]
fn legacy_locate_matches_link_structures() {
    for v in [Version(1, 1), Version(1, 4), Version(2, 0), Version(2, 1)] {
        let at = format!("{}.{}", v.0, v.1);
        let mut f = Fixture::new();
        let k0 = create(&mut f.engine, v, vec![]);
        let k1 = create(&mut f.engine, v, vec![history_link(0x107, &k0)]);
        let k2 = create(&mut f.engine, v, vec![history_link(0x107, &k0)]);
        let k3 = create(&mut f.engine, v, vec![history_link(0x106, &k1)]);
        let locate = |e: &mut Engine, link: Node| {
            let filter = if v.0 >= 2 {
                Node::structure(ATTRIBUTES, vec![link])
            } else {
                let mut link = link;
                link.tag = ATTRIBUTE_VALUE;
                Node::structure(ATTRIBUTE, vec![Node::text(ATTRIBUTE_NAME, "Link"), link])
            };
            call(e, v, "alice", 8, vec![filter])
        };
        let ids = |r: &Node| {
            let mut ids: Vec<String> = payload(r)
                .all(UNIQUE_IDENTIFIER)
                .map(|n| n.string().unwrap().to_string())
                .collect();
            ids.sort();
            ids
        };
        let mut both = vec![k1.clone(), k2.clone()];
        both.sort();
        assert_eq!(
            ids(&locate(&mut f.engine, history_link(0x107, &k0))),
            both,
            "{at}"
        );
        assert_eq!(
            ids(&locate(&mut f.engine, history_link(0x106, &k1))),
            vec![k3.clone()],
            "{at}"
        );
        assert!(
            ids(&locate(&mut f.engine, history_link(0x106, &k0))).is_empty(),
            "{at}"
        );
        let by_type = Node::structure(LINK, vec![Node::enumeration(LINK_TYPE, 0x107)]);
        assert_eq!(reason(&locate(&mut f.engine, by_type)), 7, "{at}");
        let bad_type = Node::structure(
            LINK,
            vec![
                Node::enumeration(LINK_TYPE, 0x200),
                Node::text(LINKED_OBJECT_IDENTIFIER, &k0),
            ],
        );
        assert_eq!(reason(&locate(&mut f.engine, bad_type)), 7, "{at}");
        let empty_target = Node::structure(
            LINK,
            vec![
                Node::enumeration(LINK_TYPE, 0x107),
                Node::text(LINKED_OBJECT_IDENTIFIER, ""),
            ],
        );
        assert_eq!(reason(&locate(&mut f.engine, empty_target)), 7, "{at}");
        let extra = Node::structure(
            LINK,
            vec![
                Node::enumeration(LINK_TYPE, 0x107),
                Node::text(NAME_VALUE, "x"),
            ],
        );
        // An unknown field is Invalid Field in 1.x (1.4 Table 327).
        assert_eq!(
            reason(&locate(&mut f.engine, extra)),
            if v.0 == 1 { 7 } else { 8 },
            "{at}"
        );
    }
}

#[test]
fn failing_protection_item_in_undo_reports_identity_and_durable_prefix_outcomes() {
    for v in Version::supported(true) {
        for op in [5, 31, 33, 35, 10, 43] {
            let mut f = Fixture::new();
            f.engine.experimental_v3 = true;
            let mut fields = vec![];
            if [10, 43].contains(&op) {
                fields.push(Node::structure(KEY_WRAPPING_SPECIFICATION, vec![]));
            }
            let response = f
                .engine
                .process(
                    "alice",
                    &batch_option(
                        req(
                            v,
                            vec![
                                (1, vec![Node::enumeration(OBJECT_TYPE, 2), attrs(v, vec![])]),
                                (op, fields),
                                (1, vec![Node::enumeration(OBJECT_TYPE, 2), attrs(v, vec![])]),
                                (24, vec![Node::enumeration(QUERY_FUNCTION, 1)]),
                            ],
                        ),
                        3,
                    ),
                )
                .unwrap();
            let items: Vec<_> = response.all(BATCH_ITEM).collect();
            assert_eq!(items.len(), 2, "{}.{} op {op}", v.0, v.1);
            for (index, item) in items.iter().enumerate() {
                assert_eq!(
                    item.required(OPERATION).unwrap().number().unwrap(),
                    if index == 0 { 1 } else { op }
                );
                assert_eq!(
                    item.required(RESULT_STATUS).unwrap().number().unwrap(),
                    if index == 0 { 3 } else { 1 }
                );
                if v.0 < 3 {
                    assert_eq!(
                        item.required(UNIQUE_BATCH_ITEM_ID)
                            .unwrap()
                            .byte_string()
                            .unwrap(),
                        &[index as u8]
                    );
                } else {
                    assert!(item.get(UNIQUE_BATCH_ITEM_ID).is_none());
                }
            }
            // The protection item now executes and fails on its own invalid
            // request; it is not refused as a capability before execution.
            assert!(items[1].get(RESULT_REASON).is_some());
            assert!(items[1].get(RESPONSE_PAYLOAD).is_none());
            let path = f._dir.path().join("keys.sqlite");
            drop(f.engine);
            let store = Store::open(&path, &f._dir.path().join("master")).unwrap();
            assert!(store.list("alice").unwrap().is_empty());
            store.verify_audit().unwrap();
            let c = rusqlite::Connection::open(path).unwrap();
            let events: Vec<(u32, u32)> = c
                .prepare("SELECT operation,status FROM audit ORDER BY seq")
                .unwrap()
                .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))
                .unwrap()
                .map(Result::unwrap)
                .collect();
            assert_eq!(events, vec![(1, 3), (op, 1)]);
        }
    }
}

#[test]
fn expanded_item_cap_reserves_continue_results_and_applies_stop_and_undo() {
    for v in [Version(2, 0), Version(2, 1), Version(3, 0)] {
        for count in [125, 126, 128] {
            for continuation in [1, 2, 3] {
                let mut f = Fixture::new();
                f.engine.experimental_v3 = true;
                let mut first = String::new();
                for _ in 0..count {
                    let id = create(&mut f.engine, v, vec![]);
                    if first.is_empty() {
                        first = id;
                    }
                }
                let r = f
                    .engine
                    .process(
                        "alice",
                        &batch_option(
                            req(
                                v,
                                vec![
                                    (18, vec![uid(&first)]),
                                    (8, vec![]),
                                    (10, vec![Node::enumeration(UNIQUE_IDENTIFIER, 11)]),
                                    (24, vec![Node::enumeration(QUERY_FUNCTION, 1)]),
                                ],
                            ),
                            continuation,
                        ),
                    )
                    .unwrap();
                let items: Vec<_> = r.all(BATCH_ITEM).collect();
                let expected = if count == 125 {
                    vec![0; 128]
                } else {
                    match continuation {
                        1 => vec![0, 0, 1, 0],
                        2 => vec![0, 0, 1],
                        _ => vec![3, 3, 1],
                    }
                };
                let statuses: Vec<_> = items
                    .iter()
                    .map(|i| i.required(RESULT_STATUS).unwrap().number().unwrap())
                    .collect();
                assert_eq!(statuses, expected);
                assert!(items.len() <= 128);
                for (index, item) in items.iter().enumerate() {
                    let request_index = if count == 125 && (2..127).contains(&index) {
                        2
                    } else if count == 125 && index == 127 {
                        3
                    } else {
                        index
                    };
                    assert_eq!(
                        item.required(OPERATION).unwrap().number().unwrap(),
                        [18, 8, 10, 24][request_index]
                    );
                    if v.0 < 3 {
                        assert_eq!(
                            item.required(UNIQUE_BATCH_ITEM_ID)
                                .unwrap()
                                .byte_string()
                                .unwrap(),
                            &[request_index as u8]
                        );
                    }
                }
                if count > 125 {
                    assert_eq!(
                        items[2].required(RESULT_REASON).unwrap().number().unwrap(),
                        0x3a
                    );
                }
                let path = f._dir.path().join("keys.sqlite");
                drop(f.engine);
                let store = Store::open(&path, &f._dir.path().join("master")).unwrap();
                assert_eq!(
                    store.get("alice", &first).unwrap().unwrap().state,
                    if count > 125 && continuation == 3 {
                        1
                    } else {
                        2
                    }
                );
                assert_eq!(store.list("alice").unwrap().len(), count);
                store.verify_audit().unwrap();
                let c = rusqlite::Connection::open(path).unwrap();
                let audit: Vec<u32> = c
                    .prepare("SELECT status FROM audit WHERE seq>? ORDER BY seq")
                    .unwrap()
                    .query_map([count as i64], |r| r.get(0))
                    .unwrap()
                    .map(Result::unwrap)
                    .collect();
                assert_eq!(audit, expected);
            }
        }
    }
}

#[test]
fn undone_protection_keeps_exposure_and_debit_but_discards_stream_context() {
    let mut f = Fixture::new();
    let v = Version(2, 1);
    let id = register_aes(&mut f.engine, v, vec![6; 32], vec![usage_limits(8, 2)]);
    payload(&call(&mut f.engine, v, "alice", 18, vec![uid(&id)]));
    for _ in 0..2 {
        let response = f
            .engine
            .process(
                "alice",
                &batch_option(
                    req(
                        v,
                        vec![
                            (10, vec![uid(&id)]),
                            (
                                31,
                                vec![
                                    uid(&id),
                                    Node::structure(
                                        CRYPTOGRAPHIC_PARAMETERS,
                                        vec![Node::enumeration(BLOCK_CIPHER_MODE, 2)],
                                    ),
                                    Node::bytes(DATA, vec![0; 16]),
                                    Node::boolean(INIT_INDICATOR, true),
                                    Node::boolean(FINAL_INDICATOR, false),
                                ],
                            ),
                            (10, vec![uid("missing")]),
                        ],
                    ),
                    3,
                ),
            )
            .unwrap();
        let items: Vec<_> = response.all(BATCH_ITEM).collect();
        assert_eq!(statuses(&response), vec![3, 3, 1]);
        assert!(
            items[0]
                .required(RESPONSE_PAYLOAD)
                .unwrap()
                .get(SYMMETRIC_KEY)
                .is_some()
        );
        assert_eq!(items[1].required(OPERATION).unwrap().number().unwrap(), 31);
        let correlation = items[1]
            .required(RESPONSE_PAYLOAD)
            .unwrap()
            .required(CORRELATION_VALUE)
            .unwrap()
            .clone();
        let db = rusqlite::Connection::open(f._dir.path().join("keys.sqlite")).unwrap();
        let audit: Vec<(u32, u32)> = db
            .prepare("SELECT operation,status FROM audit ORDER BY seq DESC LIMIT 3")
            .unwrap()
            .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))
            .unwrap()
            .map(Result::unwrap)
            .collect();
        assert_eq!(audit, vec![(10, 1), (31, 3), (10, 3)]);
        // The undone stream context is discarded with the batch.
        let resumed = call(
            &mut f.engine,
            v,
            "alice",
            31,
            vec![
                uid(&id),
                correlation,
                Node::bytes(DATA, vec![0; 16]),
                Node::boolean(FINAL_INDICATOR, true),
            ],
        );
        assert_eq!(statuses(&resumed), vec![1]);
    }
    let path = f._dir.path().join("keys.sqlite");
    drop(f.engine);
    f.engine = Engine::new(
        Store::open(&path, &f._dir.path().join("master")).unwrap(),
        false,
    );
    // Each undone Init delivered output and keeps its one-object debit.
    assert_eq!(remaining(&mut f.engine, v, &id), 6);
    assert!(!metadata_flag(&mut f.engine, v, &id, FRESH));
    f.engine.store.verify_audit().unwrap();
}

fn undo_audit_tail(f: &Fixture, count: i64) -> Vec<(u32, u32)> {
    let db = rusqlite::Connection::open(f._dir.path().join("keys.sqlite")).unwrap();
    let mut rows: Vec<(u32, u32)> = db
        .prepare("SELECT operation,status FROM audit ORDER BY seq DESC LIMIT ?")
        .unwrap()
        .query_map([count], |r| Ok((r.get(0)?, r.get(1)?)))
        .unwrap()
        .map(Result::unwrap)
        .collect();
    rows.reverse();
    rows
}
fn undo_wrapped_material(item: &Node) -> Vec<u8> {
    let block = item
        .required(RESPONSE_PAYLOAD)
        .unwrap()
        .required(SYMMETRIC_KEY)
        .unwrap()
        .required(KEY_BLOCK)
        .unwrap();
    // No Encoding Option was requested, so none is echoed (TTLV is implied).
    assert!(
        block
            .required(KEY_WRAPPING_DATA)
            .unwrap()
            .get(ENCODING_OPTION)
            .is_none()
    );
    let ciphertext = block.required(KEY_VALUE).unwrap().byte_string().unwrap();
    let plain =
        keytend_kmip_server::crypto::wrapping::aes(&[3; 32], ciphertext, false, false).unwrap();
    keytend_kmip_server::ttlv::decode(&plain)
        .unwrap()
        .required(KEY_MATERIAL)
        .unwrap()
        .byte_string()
        .unwrap()
        .to_vec()
}

/// The AX-M-2 shape: under Undo, Create/wrapped Get pairs that all succeed
/// return every item as Success with the versioned item correlation.
#[test]
fn successful_undo_batch_returns_wrapped_gets_and_charges_once() {
    for v in Version::supported(true) {
        let mut f = Fixture::new();
        f.engine.experimental_v3 = true;
        let kek = register_wrapping_key(
            &mut f.engine,
            v,
            &[3; 32],
            vec![usage_limits(10, 2)],
            aes_wrapping_parameters(false),
        );
        payload(&call(&mut f.engine, v, "alice", 18, vec![uid(&kek)]));
        let spec = wrapping_spec(v, &kek, None, None, vec![]);
        let create = (1, vec![Node::enumeration(OBJECT_TYPE, 2), attrs(v, vec![])]);
        let r = f
            .engine
            .process(
                "alice",
                &batch_option(
                    req(
                        v,
                        vec![
                            create.clone(),
                            (10, vec![spec.clone()]),
                            create,
                            (10, vec![spec]),
                        ],
                    ),
                    3,
                ),
            )
            .unwrap();
        let at = format!("{}.{}", v.0, v.1);
        assert_eq!(statuses(&r), vec![0; 4], "{at}");
        let header = r.required(RESPONSE_HEADER).unwrap();
        if v.0 < 3 {
            assert_eq!(
                header.required(BATCH_COUNT).unwrap().number().unwrap(),
                4,
                "{at}"
            );
        } else {
            assert!(header.get(BATCH_COUNT).is_none(), "{at}");
        }
        let items: Vec<_> = r.all(BATCH_ITEM).collect();
        for (index, item) in items.iter().enumerate() {
            assert_eq!(
                item.required(OPERATION).unwrap().number().unwrap(),
                [1, 10, 1, 10][index]
            );
            match item.get(UNIQUE_BATCH_ITEM_ID) {
                Some(id) if v.0 < 3 => assert_eq!(id.byte_string().unwrap(), [index as u8]),
                None if v.0 >= 3 => {}
                other => panic!("{at}: unexpected batch item ID {}", other.is_some()),
            }
        }
        for pair in [0, 2] {
            let created = items[pair]
                .required(RESPONSE_PAYLOAD)
                .unwrap()
                .required(UNIQUE_IDENTIFIER)
                .unwrap()
                .identifier_text()
                .unwrap();
            let got = items[pair + 1].required(RESPONSE_PAYLOAD).unwrap();
            assert_eq!(
                got.required(UNIQUE_IDENTIFIER)
                    .unwrap()
                    .identifier_text()
                    .unwrap(),
                created
            );
            let stored = f.engine.store.get("alice", created).unwrap().unwrap();
            assert_eq!(undo_wrapped_material(items[pair + 1]), stored.material);
        }
        // Without a failure nothing is re-applied: each wrap is charged once.
        assert_eq!(remaining(&mut f.engine, v, &kek), 8, "{at}");
        f.engine.store.verify_audit().unwrap();
    }
}

/// A failing Undo batch after wrapped Gets removes the batch-created key,
/// keeps the persistent target's exposure history and the KEK's debits, and
/// records final audit statuses, all durably.
#[test]
fn undo_after_wrapped_get_keeps_kek_debit_and_exposure_but_no_created_key() {
    for v in [Version(1, 4), Version(2, 1), Version(3, 0)] {
        let mut f = Fixture::new();
        f.engine.experimental_v3 = true;
        let kek = register_wrapping_key(
            &mut f.engine,
            v,
            &[3; 32],
            vec![usage_limits(10, 2)],
            aes_wrapping_parameters(false),
        );
        payload(&call(&mut f.engine, v, "alice", 18, vec![uid(&kek)]));
        let target = create(&mut f.engine, v, vec![]);
        assert!(metadata_flag(&mut f.engine, v, &target, FRESH));
        assert!(!metadata_flag(&mut f.engine, v, &target, NEVER_EXTRACTABLE));
        let spec = wrapping_spec(v, &kek, None, None, vec![]);
        let r = f
            .engine
            .process(
                "alice",
                &batch_option(
                    req(
                        v,
                        vec![
                            (1, vec![Node::enumeration(OBJECT_TYPE, 2), attrs(v, vec![])]),
                            (10, vec![spec.clone()]),
                            (10, vec![uid(&target), spec]),
                            (10, vec![uid("missing")]),
                        ],
                    ),
                    3,
                ),
            )
            .unwrap();
        let at = format!("{}.{}", v.0, v.1);
        assert_eq!(statuses(&r), vec![3, 3, 3, 1], "{at}");
        let items: Vec<_> = r.all(BATCH_ITEM).collect();
        // Table 285: an Undone item is not a failure and keeps its payload.
        let created = items[0]
            .required(RESPONSE_PAYLOAD)
            .unwrap()
            .required(UNIQUE_IDENTIFIER)
            .unwrap()
            .identifier_text()
            .unwrap()
            .to_owned();
        undo_wrapped_material(items[1]);
        let target_material = f
            .engine
            .store
            .get("alice", &target)
            .unwrap()
            .unwrap()
            .material
            .clone();
        assert_eq!(undo_wrapped_material(items[2]), target_material);
        assert!(items[3].get(RESPONSE_PAYLOAD).is_none());
        assert_eq!(
            undo_audit_tail(&f, 4),
            vec![(1, 3), (10, 3), (10, 3), (10, 1)],
            "{at}"
        );
        let path = f._dir.path().join("keys.sqlite");
        drop(f.engine);
        f.engine = Engine::new(
            Store::open(&path, &f._dir.path().join("master")).unwrap(),
            true,
        );
        assert!(
            f.engine.store.get("alice", &created).unwrap().is_none(),
            "{at}"
        );
        // Both wraps were delivered, so both KEK units stay spent and the
        // Usage Limits are read-only from now on.
        assert_eq!(remaining(&mut f.engine, v, &kek), 8, "{at}");
        assert!(
            f.engine
                .store
                .get("alice", &kek)
                .unwrap()
                .unwrap()
                .usage_consumed
        );
        // The target's wrapped value left the server: Fresh and Never
        // Extractable record that even though the batch was undone.
        assert!(!metadata_flag(&mut f.engine, v, &target, FRESH), "{at}");
        assert!(
            !metadata_flag(&mut f.engine, v, &target, NEVER_EXTRACTABLE),
            "{at}"
        );
        f.engine.store.verify_audit().unwrap();
    }
}

/// Encrypt with a key created in the same Undo batch returns its ciphertext
/// as Undone, but the key is gone and cannot be used afterwards. A
/// persistent key used in the same batch keeps its debit.
#[test]
fn undo_after_encrypt_with_batch_created_key_leaves_no_key_and_charges_only_delivered_output() {
    for v in [Version(1, 4), Version(2, 1), Version(3, 0)] {
        let mut f = Fixture::new();
        f.engine.experimental_v3 = true;
        let active = Node::date(ACTIVATION_DATE, keytend_kmip_server::store::now() - 1);
        let persistent = create(&mut f.engine, v, vec![usage_limits(5, 2), active.clone()]);
        let cp = Node::structure(
            CRYPTOGRAPHIC_PARAMETERS,
            vec![
                Node::enumeration(BLOCK_CIPHER_MODE, 2),
                Node::boolean(RANDOM_IV, true),
            ],
        );
        let r = f
            .engine
            .process(
                "alice",
                &batch_option(
                    req(
                        v,
                        vec![
                            (
                                1,
                                vec![
                                    Node::enumeration(OBJECT_TYPE, 2),
                                    attrs(v, vec![usage_limits(5, 2), active.clone()]),
                                ],
                            ),
                            (31, vec![cp.clone(), Node::bytes(DATA, vec![1; 16])]),
                            (
                                31,
                                vec![uid(&persistent), cp.clone(), Node::bytes(DATA, vec![2; 16])],
                            ),
                            (10, vec![uid("missing")]),
                        ],
                    ),
                    3,
                ),
            )
            .unwrap();
        let at = format!("{}.{}", v.0, v.1);
        assert_eq!(statuses(&r), vec![3, 3, 3, 1], "{at}");
        let items: Vec<_> = r.all(BATCH_ITEM).collect();
        let created = items[0]
            .required(RESPONSE_PAYLOAD)
            .unwrap()
            .required(UNIQUE_IDENTIFIER)
            .unwrap()
            .identifier_text()
            .unwrap()
            .to_owned();
        for item in &items[1..3] {
            assert!(item.required(RESPONSE_PAYLOAD).unwrap().get(DATA).is_some());
        }
        assert!(
            f.engine.store.get("alice", &created).unwrap().is_none(),
            "{at}"
        );
        assert_eq!(remaining(&mut f.engine, v, &persistent), 4, "{at}");
        let reuse = call(
            &mut f.engine,
            v,
            "alice",
            32,
            vec![uid(&created), cp, Node::bytes(DATA, vec![0; 16])],
        );
        assert_eq!(statuses(&reuse), vec![1], "{at}");
        assert_eq!(
            undo_audit_tail(&f, 6),
            vec![(1, 3), (31, 3), (31, 3), (10, 1), (11, 0), (32, 1)],
            "{at}"
        );
        f.engine.store.verify_audit().unwrap();
    }
}

/// A wrapped Get that executes but is then refused because its response does
/// not fit is a failed item: its KEK debit is rolled back with the batch.
#[test]
fn undo_failed_wrapped_get_after_execution_keeps_no_debit() {
    let v = Version(2, 1);
    let mut f = Fixture::new();
    let kek = register_wrapping_key(
        &mut f.engine,
        v,
        &[3; 32],
        vec![usage_limits(10, 2)],
        aes_wrapping_parameters(false),
    );
    payload(&call(&mut f.engine, v, "alice", 18, vec![uid(&kek)]));
    let target = create(&mut f.engine, v, vec![]);
    let spec = wrapping_spec(v, &kek, None, None, vec![]);
    let mut found = false;
    for limit in (64..2048).step_by(4) {
        let request = header_field(
            batch_option(
                req(
                    v,
                    vec![
                        (11, vec![uid(&target)]),
                        (10, vec![uid(&target), spec.clone()]),
                    ],
                ),
                3,
            ),
            Node::int(MAXIMUM_RESPONSE_SIZE, limit),
        );
        // Limits too small for any conforming answer reject the message.
        let Ok(r) = f.engine.process("alice", &request) else {
            continue;
        };
        let items: Vec<_> = r.all(BATCH_ITEM).collect();
        if statuses(&r) == vec![3, 1]
            && items[1].required(RESULT_REASON).unwrap().number().unwrap() == 2
        {
            found = true;
            break;
        }
    }
    assert!(found);
    assert_eq!(remaining(&mut f.engine, v, &kek), 10);
    assert!(
        !f.engine
            .store
            .get("alice", &kek)
            .unwrap()
            .unwrap()
            .usage_consumed
    );
    assert!(metadata_flag(&mut f.engine, v, &target, FRESH));
    f.engine.store.verify_audit().unwrap();
}

#[test]
fn rsa_pair_attempt_cap_has_durable_stop_continue_and_undo_outcomes() {
    for v in [Version(1, 4), Version(2, 1), Version(3, 0)] {
        for continuation in [1, 2, 3] {
            let mut f = Fixture::new();
            f.engine.experimental_v3 = true;
            let fields = vec![pair_common(
                v,
                vec![
                    Node::enumeration(CRYPTOGRAPHIC_ALGORITHM, 4),
                    Node::int(CRYPTOGRAPHIC_LENGTH, 2048),
                    // REQUIRED in 1.x (1.4 table 168).
                    Node::int(CRYPTOGRAPHIC_USAGE_MASK, 3),
                ],
            )];
            let mut entries = vec![(2, fields); 6];
            entries.push((24, vec![Node::enumeration(QUERY_FUNCTION, 1)]));
            let response = f
                .engine
                .process("alice", &batch_option(req(v, entries), continuation))
                .unwrap();
            let items: Vec<_> = response.all(BATCH_ITEM).collect();
            let expected = if continuation == 1 {
                vec![0, 0, 0, 0, 1, 1, 0]
            } else if continuation == 2 {
                vec![0, 0, 0, 0, 1]
            } else {
                vec![3, 3, 3, 3, 1]
            };
            let statuses: Vec<_> = items
                .iter()
                .map(|i| i.required(RESULT_STATUS).unwrap().number().unwrap())
                .collect();
            assert_eq!(statuses, expected);
            for (index, item) in items
                .iter()
                .enumerate()
                .take(if continuation == 1 { 6 } else { 5 })
                .skip(4)
            {
                assert_eq!(item.required(OPERATION).unwrap().number().unwrap(), 2);
                assert_eq!(
                    item.required(RESULT_REASON).unwrap().number().unwrap(),
                    if v.0 >= 2 { 0x3a } else { 0x100 }
                );
                assert!(item.get(RESPONSE_PAYLOAD).is_none());
                if v.0 < 3 {
                    assert_eq!(
                        item.required(UNIQUE_BATCH_ITEM_ID)
                            .unwrap()
                            .byte_string()
                            .unwrap(),
                        &[index as u8]
                    );
                }
            }
            let path = f._dir.path().join("keys.sqlite");
            drop(f.engine);
            let store = Store::open(&path, &f._dir.path().join("master")).unwrap();
            assert_eq!(
                store.list("alice").unwrap().len(),
                if continuation == 3 { 0 } else { 8 }
            );
            store.verify_audit().unwrap();
            let db = rusqlite::Connection::open(path).unwrap();
            let audit: Vec<u32> = db
                .prepare("SELECT status FROM audit ORDER BY seq")
                .unwrap()
                .query_map([], |r| r.get(0))
                .unwrap()
                .map(Result::unwrap)
                .collect();
            assert_eq!(audit, expected);
        }
    }
}

#[test]
fn critical_extension_preserves_correlation_under_response_limits() {
    use keytend_kmip_server::encoding::Format;
    for v in [Version(1, 4), Version(2, 1), Version(3, 0)] {
        let mut f = Fixture::new();
        f.engine.experimental_v3 = true;
        for format in [Format::Ttlv, Format::Json, Format::Xml] {
            for mode in [1, 2, 3] {
                for limit in (0..=512).step_by(16) {
                    let request = with_extension(
                        req(
                            v,
                            vec![
                                (1, vec![Node::enumeration(OBJECT_TYPE, 2), attrs(v, vec![])]),
                                (24, vec![]),
                                (24, vec![]),
                            ],
                        ),
                        1,
                        message_extension("acme", true),
                    );
                    let request = batch_option(request, mode);
                    let request = header_field(
                        request,
                        Node::text(CLIENT_CORRELATION_VALUE, "c".repeat(1024)),
                    );
                    let request = header_field(request, Node::int(MAXIMUM_RESPONSE_SIZE, limit));
                    match f
                        .engine
                        .process_with_grants_encoded("alice", &request, None, &[], format)
                    {
                        Ok(response) => {
                            assert!(response.encoded_len() <= limit as usize);
                            assert_eq!(
                                critical_rejection(v, &response, &request),
                                if v.0 == 1 { 8 } else { 0x3c }
                            );
                            assert!(
                                response
                                    .required(RESPONSE_HEADER)
                                    .unwrap()
                                    .get(CLIENT_CORRELATION_VALUE)
                                    .is_none()
                            );
                            format.encode(&response).unwrap();
                        }
                        Err(error) => assert!(error.unanswerable()),
                    }
                    assert!(f.engine.store.list("alice").unwrap().is_empty());
                    assert_eq!(audit_rows(&f), 0);
                }
            }
        }
    }
}

#[test]
fn destroyed_get_uses_only_result_reasons_defined_in_its_edition() {
    for v in std::iter::once(Version(1, 0)).chain(Version::supported(true)) {
        let mut f = Fixture::new();
        f.engine.experimental_v3 = true;
        let id = create(&mut f.engine, v, vec![]);
        payload(&call(&mut f.engine, v, "alice", 20, vec![uid(&id)]));
        let before = serde_json::to_value(f.engine.store.list("alice").unwrap()).unwrap();
        let response = call(&mut f.engine, v, "alice", 10, vec![uid(&id)]);
        let item = response.required(BATCH_ITEM).unwrap();
        assert_eq!(item.required(OPERATION).unwrap().number().unwrap(), 10);
        assert_eq!(item.required(RESULT_STATUS).unwrap().number().unwrap(), 1);
        assert_eq!(
            item.required(RESULT_REASON).unwrap().number().unwrap(),
            // Object Destroyed (0x36) exists from 2.0; every
            // 1.x Get Errors table gives Illegal Operation for an object
            // with attributes only (1.2 table 301 included).
            if v.0 >= 2 { 0x36 } else { 11 },
            "{}.{}",
            v.0,
            v.1
        );
        assert!(item.get(RESPONSE_PAYLOAD).is_none());
        assert_eq!(
            serde_json::to_value(f.engine.store.list("alice").unwrap()).unwrap(),
            before
        );
        assert!(
            f.engine
                .store
                .get("alice", &id)
                .unwrap()
                .unwrap()
                .material
                .is_empty()
        );
        f.engine.store.verify_audit().unwrap();
    }
}

fn alternative_name(value: &str, kind: u32) -> Node {
    Node::structure(
        ALTERNATIVE_NAME,
        vec![
            Node::text(ALTERNATIVE_NAME_VALUE, value),
            Node::enumeration(ALTERNATIVE_NAME_TYPE, kind),
        ],
    )
}
fn alternative_values(e: &mut Engine, v: Version, id: &str) -> Vec<Node> {
    let selector = if v.0 == 1 {
        Node::text(ATTRIBUTE_NAME, "Alternative Name")
    } else {
        Node::enumeration(ATTRIBUTE_REFERENCE, ALTERNATIVE_NAME)
    };
    let r = call(e, v, "alice", 11, vec![uid(id), selector]);
    if v.0 == 1 {
        payload(&r)
            .all(ATTRIBUTE)
            .map(|a| {
                let mut a = a.required(ATTRIBUTE_VALUE).unwrap().clone();
                a.tag = ALTERNATIVE_NAME;
                a
            })
            .collect()
    } else {
        payload(&r)
            .get(ATTRIBUTES)
            .map_or(vec![], |a| a.all(ALTERNATIVE_NAME).cloned().collect())
    }
}
fn alternative_input(v: Version, a: Node, index: Option<i32>) -> Node {
    if v.0 == 1 {
        legacy_attribute("Alternative Name", a, index)
    } else {
        Node::structure(NEW_ATTRIBUTE, vec![a])
    }
}
fn alternative_filter(v: Version, a: Node) -> Node {
    if v.0 == 1 {
        legacy_attribute("Alternative Name", a, None)
    } else {
        Node::structure(ATTRIBUTES, vec![a])
    }
}
#[test]
fn alternative_name_versions_lifecycle_and_full_pair_locate() {
    for v in Version::supported(true)
        .into_iter()
        .filter(|v| *v >= Version(1, 2))
    {
        let mut f = Fixture::new();
        f.engine.experimental_v3 = true;
        let values = (1..=7)
            .map(|kind| alternative_name("same literal / no syntax policy", kind))
            .collect::<Vec<_>>();
        let id = create(&mut f.engine, v, values.clone());
        let other = create(&mut f.engine, v, vec![values[0].clone()]);
        assert!(alternative_values(&mut f.engine, v, &id) == values);
        let list = call(&mut f.engine, v, "alice", 12, vec![uid(&id)]);
        let count = if v.0 == 1 {
            payload(&list)
                .all(ATTRIBUTE_NAME)
                .filter(|n| n.string().unwrap() == "Alternative Name")
                .count()
        } else {
            payload(&list)
                .all(ATTRIBUTE_REFERENCE)
                .filter(|n| n.number().ok() == Some(ALTERNATIVE_NAME))
                .count()
        };
        assert_eq!(count, 1);
        let r = call(
            &mut f.engine,
            v,
            "alice",
            8,
            vec![alternative_filter(v, values[1].clone())],
        );
        let ids = payload(&r)
            .all(UNIQUE_IDENTIFIER)
            .map(|n| n.identifier_text().unwrap())
            .collect::<Vec<_>>();
        assert_eq!(ids, vec![id.as_str()]);
        let r = call(
            &mut f.engine,
            v,
            "alice",
            8,
            vec![alternative_filter(v, values[0].clone())],
        );
        assert_eq!(payload(&r).all(UNIQUE_IDENTIFIER).count(), 2);
        let r = call(
            &mut f.engine,
            v,
            "bob",
            8,
            vec![alternative_filter(v, values[0].clone())],
        );
        assert_eq!(payload(&r).all(UNIQUE_IDENTIFIER).count(), 0);
        assert_eq!(
            reason(&call(&mut f.engine, v, "bob", 11, vec![uid(&id)])),
            not_found(v)
        );
        assert_eq!(
            reason(&call(
                &mut f.engine,
                v,
                "bob",
                13,
                vec![uid(&id), alternative_input(v, values[0].clone(), None)]
            )),
            not_found(v)
        );
        // Repeated identical values are legal, bounded instances; 2.x value selection is ambiguous.
        payload(&call(
            &mut f.engine,
            v,
            "alice",
            13,
            vec![uid(&other), alternative_input(v, values[0].clone(), None)],
        ));
        if v.0 >= 2 {
            let r = call(
                &mut f.engine,
                v,
                "alice",
                15,
                vec![
                    uid(&other),
                    Node::structure(CURRENT_ATTRIBUTE, vec![values[0].clone()]),
                ],
            );
            assert_eq!(reason(&r), 0x1e);
            payload(&call(
                &mut f.engine,
                v,
                "alice",
                15,
                vec![
                    uid(&other),
                    Node::enumeration(ATTRIBUTE_REFERENCE, ALTERNATIVE_NAME),
                ],
            ));
        } else {
            payload(&call(
                &mut f.engine,
                v,
                "alice",
                15,
                vec![
                    uid(&other),
                    Node::text(ATTRIBUTE_NAME, "Alternative Name"),
                    Node::int(ATTRIBUTE_INDEX, 1),
                ],
            ));
        }
        f.engine.store.verify_audit().unwrap();
    }
}
#[test]
fn alternative_name_malformed_version_and_resource_limits_are_atomic() {
    for v in Version::supported(true) {
        let mut f = Fixture::new();
        f.engine.experimental_v3 = true;
        let id = create(
            &mut f.engine,
            v,
            if v >= Version(1, 2) {
                vec![alternative_name("unchanged", 1)]
            } else {
                vec![]
            },
        );
        let mut cases = vec![
            (Node::text(ALTERNATIVE_NAME, "flat"), 7),
            (
                Node::structure(
                    ALTERNATIVE_NAME,
                    vec![Node::text(ALTERNATIVE_NAME_VALUE, "missing")],
                ),
                6,
            ),
            (
                Node::structure(
                    ALTERNATIVE_NAME,
                    vec![Node::enumeration(ALTERNATIVE_NAME_TYPE, 1)],
                ),
                6,
            ),
            (
                Node::structure(
                    ALTERNATIVE_NAME,
                    vec![
                        Node::int(ALTERNATIVE_NAME_VALUE, 1),
                        Node::enumeration(ALTERNATIVE_NAME_TYPE, 1),
                    ],
                ),
                7,
            ),
            (
                Node::structure(
                    ALTERNATIVE_NAME,
                    vec![
                        Node::text(ALTERNATIVE_NAME_VALUE, "x"),
                        Node::int(ALTERNATIVE_NAME_TYPE, 1),
                    ],
                ),
                7,
            ),
            (
                Node::structure(
                    ALTERNATIVE_NAME,
                    vec![
                        Node::enumeration(ALTERNATIVE_NAME_TYPE, 1),
                        Node::text(ALTERNATIVE_NAME_VALUE, "reversed"),
                    ],
                ),
                7,
            ),
            (
                Node::structure(
                    ALTERNATIVE_NAME,
                    vec![
                        Node::text(ALTERNATIVE_NAME_VALUE, "x"),
                        Node::text(ALTERNATIVE_NAME_VALUE, "duplicate"),
                        Node::enumeration(ALTERNATIVE_NAME_TYPE, 1),
                    ],
                ),
                // A field given twice is Invalid Message in 1.x (Table 327).
                if v.0 == 1 { 4 } else { 7 },
            ),
            (
                Node::structure(
                    ALTERNATIVE_NAME,
                    vec![
                        Node::text(ALTERNATIVE_NAME_VALUE, "x"),
                        Node::enumeration(ALTERNATIVE_NAME_TYPE, 1),
                        Node::text(CONTACT_INFORMATION, "extra"),
                    ],
                ),
                // An unknown field is Invalid Field in 1.x (Table 327).
                if v.0 == 1 { 7 } else { 8 },
            ),
            (alternative_name("x", 0), 8),
            (alternative_name("x", 8), 8),
            (alternative_name("x", 0x80000001), 8),
            (alternative_name(&"é".repeat(2049), 1), 2),
        ];
        if v < Version(1, 2) {
            cases = vec![(alternative_name("unavailable", 1), 8)];
        }
        for (a, expected) in cases {
            let expected = if expected == 6 { 7 } else { expected };
            let before = serde_json::to_value(f.engine.store.get("alice", &id).unwrap()).unwrap();
            let r = call(
                &mut f.engine,
                v,
                "alice",
                1,
                vec![Node::enumeration(OBJECT_TYPE, 2), attrs(v, vec![a.clone()])],
            );
            assert_eq!(reason(&r), expected, "Create in {}.{}", v.0, v.1);
            let r = call(
                &mut f.engine,
                v,
                "alice",
                13,
                vec![uid(&id), alternative_input(v, a.clone(), None)],
            );
            assert_eq!(reason(&r), expected, "Add in {}.{}", v.0, v.1);
            let r = call(
                &mut f.engine,
                v,
                "alice",
                14,
                vec![
                    uid(&id),
                    alternative_input(v, a.clone(), if v.0 == 1 { Some(0) } else { None }),
                ],
            );
            assert_eq!(reason(&r), expected, "Modify in {}.{}", v.0, v.1);
            if v.0 >= 2 {
                let r = call(
                    &mut f.engine,
                    v,
                    "alice",
                    15,
                    vec![
                        uid(&id),
                        Node::structure(CURRENT_ATTRIBUTE, vec![a.clone()]),
                    ],
                );
                assert_eq!(reason(&r), expected, "Delete current in {}.{}", v.0, v.1);
            }
            let legal_partial = v >= Version(1, 2)
                && matches!(&a.value,
                Value::Structure(fields) if fields.len() == 1 &&
                [ALTERNATIVE_NAME_VALUE, ALTERNATIVE_NAME_TYPE].contains(&fields[0].tag));
            let r = call(&mut f.engine, v, "alice", 8, vec![alternative_filter(v, a)]);
            if legal_partial {
                assert_eq!(statuses(&r)[0], 0, "Partial Locate in {}.{}", v.0, v.1);
            } else {
                assert_eq!(reason(&r), expected, "Locate in {}.{}", v.0, v.1);
            }
            assert_eq!(
                serde_json::to_value(f.engine.store.get("alice", &id).unwrap()).unwrap(),
                before
            );
        }
        if v >= Version(1, 2) {
            // Exactly 4096 UTF-8 bytes, empty text and ordinary syntax are all accepted.
            payload(&call(
                &mut f.engine,
                v,
                "alice",
                13,
                vec![
                    uid(&id),
                    alternative_input(v, alternative_name(&"é".repeat(2048), 1), None),
                ],
            ));
            payload(&call(
                &mut f.engine,
                v,
                "alice",
                13,
                vec![
                    uid(&id),
                    alternative_input(v, alternative_name("", 7), None),
                ],
            ));
            let r = call(
                &mut f.engine,
                v,
                "alice",
                1,
                vec![
                    Node::enumeration(OBJECT_TYPE, 2),
                    attrs(v, vec![alternative_name("x", 1); 1025]),
                ],
            );
            assert_eq!(reason(&r), 2);
            let r = call(
                &mut f.engine,
                v,
                "alice",
                1,
                vec![
                    Node::enumeration(OBJECT_TYPE, 2),
                    attrs(v, vec![alternative_name(&"x".repeat(4096), 1); 64]),
                ],
            );
            assert_eq!(reason(&r), 2);
        }
    }
}
#[test]
fn alternative_name_stable_indices_modify_restart_restore_and_rekey() {
    for v in [
        Version(1, 2),
        Version(1, 3),
        Version(1, 4),
        Version(2, 0),
        Version(2, 1),
        Version(3, 0),
    ] {
        let mut f = Fixture::new();
        f.engine.experimental_v3 = true;
        let a = alternative_name("first", 1);
        let b = alternative_name("second", 2);
        let c = alternative_name("third", 3);
        let id = register_aes(&mut f.engine, v, vec![5; 32], vec![a.clone(), b.clone()]);
        let deletion = if v.0 == 1 {
            vec![
                uid(&id),
                Node::text(ATTRIBUTE_NAME, "Alternative Name"),
                Node::int(ATTRIBUTE_INDEX, 0),
            ]
        } else {
            vec![uid(&id), Node::structure(CURRENT_ATTRIBUTE, vec![a])]
        };
        payload(&call(&mut f.engine, v, "alice", 15, deletion));
        let mut modification = vec![uid(&id), alternative_input(v, c.clone(), Some(1))];
        if v.0 >= 2 {
            modification.push(Node::structure(CURRENT_ATTRIBUTE, vec![b]));
        }
        payload(&call(&mut f.engine, v, "alice", 14, modification));
        if v.0 == 1 {
            assert_eq!(
                legacy_values(&mut f.engine, v, &id, "Alternative Name")[0].0,
                1
            );
            let r = call(
                &mut f.engine,
                v,
                "alice",
                13,
                vec![uid(&id), alternative_input(v, c.clone(), Some(4))],
            );
            assert_eq!(reason(&r), 7);
        }
        if v >= Version(1, 4) {
            let exported = call(&mut f.engine, v, "alice", 43, vec![uid(&id)]);
            let fields =
                transfer_import_fields(v, payload(&exported), "alias-restored", false, None);
            payload(&call(&mut f.engine, v, "alice", 42, fields));
            assert!(alternative_values(&mut f.engine, v, "alias-restored") == vec![c.clone()]);
            if v.0 == 1 {
                assert_eq!(
                    legacy_values(&mut f.engine, v, "alias-restored", "Alternative Name")[0].0,
                    1
                );
            }
        }
        payload(&call(
            &mut f.engine,
            v,
            "alice",
            13,
            vec![
                uid(&id),
                alternative_input(v, alternative_name("reuses zero", 4), None),
            ],
        ));
        if v.0 == 1 {
            assert_eq!(
                legacy_values(&mut f.engine, v, &id, "Alternative Name")
                    .iter()
                    .map(|(i, _)| *i)
                    .collect::<Vec<_>>(),
                vec![0, 1]
            );
        }
        let store_path = f._dir.path().join("keys.sqlite");
        let master = f._dir.path().join("master");
        drop(f.engine);
        f.engine = Engine::new(Store::open(&store_path, &master).unwrap(), false);
        f.engine.experimental_v3 = true;
        assert_eq!(alternative_values(&mut f.engine, v, &id).len(), 2);
        payload(&call(&mut f.engine, v, "alice", 18, vec![uid(&id)]));
        let r = call(&mut f.engine, v, "alice", 4, vec![uid(&id)]);
        let replacement = payload(&r)
            .required(UNIQUE_IDENTIFIER)
            .unwrap()
            .identifier_text()
            .unwrap();
        assert!(
            alternative_values(&mut f.engine, v, replacement)
                == alternative_values(&mut f.engine, v, &id)
        );
        f.engine.store.verify_audit().unwrap();
    }
}
#[test]
fn alternative_name_undo_and_cross_version_access_preserve_attributes() {
    let mut f = Fixture::new();
    let v = Version(2, 1);
    let id = create(&mut f.engine, v, vec![alternative_name("persistent", 5)]);
    let before = serde_json::to_value(f.engine.store.get("alice", &id).unwrap()).unwrap();
    let mut request = req(
        v,
        vec![
            (
                13,
                vec![
                    uid(&id),
                    alternative_input(v, alternative_name("rollback", 1), None),
                ],
            ),
            (
                13,
                vec![
                    uid(&id),
                    alternative_input(v, alternative_name("bad", 0), None),
                ],
            ),
        ],
    );
    if let Value::Structure(fields) = &mut request.value
        && let Value::Structure(header) = &mut fields[0].value
    {
        header.push(Node::enumeration(BATCH_ERROR_CONTINUATION_OPTION, 3));
    }
    let r = f.engine.process("alice", &request).unwrap();
    assert_eq!(
        r.all(BATCH_ITEM)
            .next()
            .unwrap()
            .required(RESULT_STATUS)
            .unwrap()
            .number()
            .unwrap(),
        3
    );
    assert_eq!(
        serde_json::to_value(f.engine.store.get("alice", &id).unwrap()).unwrap(),
        before
    );
    for old in [Version(1, 0), Version(1, 1)] {
        let r = call(&mut f.engine, old, "alice", 11, vec![uid(&id)]);
        assert!(
            !payload(&r).all(ATTRIBUTE).any(|a| a
                .required(ATTRIBUTE_NAME)
                .unwrap()
                .string()
                .unwrap()
                == "Alternative Name")
        );
        assert_eq!(
            reason(&call(
                &mut f.engine,
                old,
                "alice",
                15,
                vec![uid(&id), Node::text(ATTRIBUTE_NAME, "Alternative Name")]
            )),
            8
        );
        assert!(serde_json::to_value(f.engine.store.get("alice", &id).unwrap()).unwrap() == before);
    }
    assert!(
        alternative_values(&mut f.engine, Version(1, 2), &id)
            == vec![alternative_name("persistent", 5)]
    );
    // Alternative names are never Name aliases for identifier resolution.
    f.engine.experimental_v3 = true;
    let r = call(
        &mut f.engine,
        Version(3, 0),
        "alice",
        10,
        vec![Node::name_reference(UNIQUE_IDENTIFIER, "persistent")],
    );
    assert_eq!(reason(&r), 0x37);
}

#[test]
fn alternative_name_pair_union_rekey_pair_derivation_and_wrapped_value() {
    for v in [Version(1, 2), Version(2, 1), Version(3, 0)] {
        let mut f = Fixture::new();
        f.engine.experimental_v3 = true;
        let common = alternative_name("common", 1);
        let private_alias = alternative_name("private", 2);
        let r = call(
            &mut f.engine,
            v,
            "alice",
            2,
            vec![
                pair_common(
                    v,
                    vec![
                        Node::enumeration(CRYPTOGRAPHIC_ALGORITHM, 4),
                        Node::int(CRYPTOGRAPHIC_LENGTH, 2048),
                        common.clone(),
                    ],
                ),
                pair_attributes(
                    v,
                    true,
                    vec![
                        Node::int(CRYPTOGRAPHIC_USAGE_MASK, 1),
                        common.clone(),
                        private_alias.clone(),
                    ],
                ),
                pair_attributes(v, false, vec![Node::int(CRYPTOGRAPHIC_USAGE_MASK, 2)]),
            ],
        );
        let (private, public) = pair_ids(&r);
        assert!(
            alternative_values(&mut f.engine, v, &private)
                == vec![common.clone(), private_alias.clone()]
        );
        assert!(alternative_values(&mut f.engine, v, &public) == vec![common.clone()]);
        for id in [&private, &public] {
            payload(&call(&mut f.engine, v, "alice", 18, vec![uid(id)]));
        }
        let r = call(
            &mut f.engine,
            v,
            "alice",
            29,
            vec![pair_source(v, &private)],
        );
        let (new_private, new_public) = pair_ids(&r);
        assert!(
            alternative_values(&mut f.engine, v, &new_private)
                == vec![common.clone(), private_alias]
        );
        assert!(alternative_values(&mut f.engine, v, &new_public) == vec![common.clone()]);
        let base = derivation_source(&mut f.engine, v, 2, 2, 3, &[6; 16], vec![]);
        let fields = derive_fields(
            v,
            &[&base],
            2,
            128,
            2,
            vec![Node::structure(
                CRYPTOGRAPHIC_PARAMETERS,
                vec![Node::enumeration(HASHING_ALGORITHM, 6)],
            )],
            vec![common.clone(), common.clone()],
        );
        let derived = derived_id(&mut f.engine, v, fields);
        assert!(alternative_values(&mut f.engine, v, &derived) == vec![common.clone(), common]);
        let wrapper = register_wrapping_key(
            &mut f.engine,
            v,
            &[8; 16],
            vec![],
            aes_wrapping_parameters(true),
        );
        payload(&call(&mut f.engine, v, "alice", 18, vec![uid(&wrapper)]));
        let spec = wrapping_spec(
            v,
            &wrapper,
            Some(2),
            Some(aes_wrapping_parameters(true)),
            vec![if v.0 >= 3 {
                Node::enumeration(ATTRIBUTE_REFERENCE, ALTERNATIVE_NAME)
            } else {
                Node::text(ATTRIBUTE_NAME, "Alternative Name")
            }],
        );
        let wrapped = get_wrapped(&mut f.engine, v, &derived, spec, 1);
        let restored = register_wrapped(&mut f.engine, v, wrapped_object(&wrapped).clone(), vec![]);
        let restored = payload(&restored)
            .required(UNIQUE_IDENTIFIER)
            .unwrap()
            .identifier_text()
            .unwrap();
        assert!(
            alternative_values(&mut f.engine, v, restored)
                == alternative_values(&mut f.engine, v, &derived)
        );
        f.engine.store.verify_audit().unwrap();
    }
}

#[test]
fn alternative_name_locate_partial_structures_match_one_instance_and_principal() {
    for v in Version::supported(true)
        .into_iter()
        .filter(|v| *v >= Version(1, 2))
    {
        let mut f = Fixture::new();
        f.engine.experimental_v3 = true;
        let first = create(
            &mut f.engine,
            v,
            vec![alternative_name("needle", 1), alternative_name("second", 5)],
        );
        let other = create(&mut f.engine, v, vec![alternative_name("needle", 7)]);
        let _without_alias = create(&mut f.engine, v, vec![]);
        let response = call(
            &mut f.engine,
            v,
            "bob",
            1,
            vec![
                Node::enumeration(OBJECT_TYPE, 2),
                attrs(v, vec![alternative_name("needle", 1)]),
            ],
        );
        let bob = payload(&response)
            .required(UNIQUE_IDENTIFIER)
            .unwrap()
            .identifier_text()
            .unwrap()
            .to_owned();
        let locate = |engine: &mut Engine, principal: &str, fields: Vec<Node>| {
            let response = call(
                engine,
                v,
                principal,
                8,
                vec![alternative_filter(
                    v,
                    Node::structure(ALTERNATIVE_NAME, fields),
                )],
            );
            assert_eq!(statuses(&response)[0], 0);
            let mut ids = payload(&response)
                .all(UNIQUE_IDENTIFIER)
                .map(|n| n.identifier_text().unwrap().to_owned())
                .collect::<Vec<_>>();
            ids.sort();
            ids
        };
        let mut all = vec![first.clone(), other.clone()];
        all.sort();
        assert_eq!(
            locate(
                &mut f.engine,
                "alice",
                vec![Node::text(ALTERNATIVE_NAME_VALUE, "needle")]
            ),
            all
        );
        assert_eq!(
            locate(
                &mut f.engine,
                "alice",
                vec![Node::enumeration(ALTERNATIVE_NAME_TYPE, 5)]
            ),
            vec![first.clone()]
        );
        assert_eq!(locate(&mut f.engine, "alice", vec![]), all);
        assert!(
            locate(
                &mut f.engine,
                "alice",
                vec![
                    Node::text(ALTERNATIVE_NAME_VALUE, "needle"),
                    Node::enumeration(ALTERNATIVE_NAME_TYPE, 5)
                ]
            )
            .is_empty()
        );
        assert_eq!(
            locate(
                &mut f.engine,
                "bob",
                vec![Node::text(ALTERNATIVE_NAME_VALUE, "needle")]
            ),
            vec![bob]
        );
        // A field given twice is Invalid Message in 1.x (1.4 Table 327).
        let twice = if v.0 == 1 { 4 } else { 7 };
        for (fields, expected) in [
            (vec![Node::int(ALTERNATIVE_NAME_VALUE, 1)], 7),
            (vec![Node::int(ALTERNATIVE_NAME_TYPE, 1)], 7),
            (
                vec![
                    Node::text(ALTERNATIVE_NAME_VALUE, "x"),
                    Node::text(ALTERNATIVE_NAME_VALUE, "x"),
                ],
                twice,
            ),
        ] {
            let response = call(
                &mut f.engine,
                v,
                "alice",
                8,
                vec![alternative_filter(
                    v,
                    Node::structure(ALTERNATIVE_NAME, fields),
                )],
            );
            assert_eq!(reason(&response), expected);
        }
        let response = call(
            &mut f.engine,
            v,
            "alice",
            8,
            vec![alternative_filter(
                v,
                Node::structure(
                    ALTERNATIVE_NAME,
                    vec![Node::text(ALTERNATIVE_NAME_VALUE, "é".repeat(2049))],
                ),
            )],
        );
        assert_eq!(reason(&response), 2);
        f.engine.store.verify_audit().unwrap();
    }
}

/// Item Not Found in 1.x; Object Not Found (0x37) where the 2.x and draft 3.0
/// error tables list it (see src/protocol/not_found.rs).
fn not_found(v: Version) -> u32 {
    if v.0 >= 2 { 0x37 } else { 1 }
}

/// 1.x Item Not Found; the 2.x and draft 3.0 Get, Export (2.1 Tables 219,
/// 222) and unwrap paths name Wrapping Object Not Found (0x42).
fn wrapping_not_found(v: Version) -> u32 {
    if v.0 >= 2 { 0x42 } else { 1 }
}
