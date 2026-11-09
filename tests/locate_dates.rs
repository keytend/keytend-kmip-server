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
}
fn request(v: Version, items: Vec<(u32, Vec<Node>)>, _: Option<u32>, _: Option<i32>) -> Node {
    let mut header = vec![v.node()];
    if v.0 < 3 {
        header.push(Node::int(BATCH_COUNT, items.len() as i32));
        header.push(Node::boolean(BATCH_ORDER_OPTION, true));
    }
    let mut fields = vec![Node::structure(REQUEST_HEADER, header)];
    let many = items.len() > 1;
    fields.extend(items.into_iter().enumerate().map(|(index, (op, p))| {
        let mut item = vec![
            Node::enumeration(OPERATION, op),
            Node::structure(REQUEST_PAYLOAD, p),
        ];
        if many && v.0 < 3 {
            item.push(Node::bytes(UNIQUE_BATCH_ITEM_ID, vec![index as u8]));
        }
        Node::structure(BATCH_ITEM, item)
    }));
    Node::structure(REQUEST_MESSAGE, fields)
}
fn payload(n: &Node) -> &Node {
    let item = n.get(BATCH_ITEM).unwrap();
    assert_eq!(
        item.required(RESULT_STATUS).unwrap().number().unwrap(),
        0,
        "reason {:?}",
        item.get(RESULT_REASON).and_then(|n| n.number().ok())
    );
    item.required(RESPONSE_PAYLOAD).unwrap()
}
fn reason(n: &Node) -> u32 {
    n.required(BATCH_ITEM)
        .unwrap()
        .required(RESULT_REASON)
        .unwrap()
        .number()
        .unwrap()
}
fn uid(v: Version, id: &str) -> Node {
    if v.0 >= 3 {
        Node::identifier(UNIQUE_IDENTIFIER, id)
    } else {
        Node::text(UNIQUE_IDENTIFIER, id)
    }
}
fn legacy(mut n: Node) -> Node {
    let name = match n.tag {
        CRYPTOGRAPHIC_ALGORITHM => "Cryptographic Algorithm",
        CRYPTOGRAPHIC_LENGTH => "Cryptographic Length",
        CRYPTOGRAPHIC_USAGE_MASK => "Cryptographic Usage Mask",
        ACTIVATION_DATE => "Activation Date",
        ARCHIVE_DATE => "Archive Date",
        COMPROMISE_DATE => "Compromise Date",
        COMPROMISE_OCCURRENCE_DATE => "Compromise Occurrence Date",
        DEACTIVATION_DATE => "Deactivation Date",
        DESTROY_DATE => "Destroy Date",
        INITIAL_DATE => "Initial Date",
        LAST_CHANGE_DATE => "Last Change Date",
        PROCESS_START_DATE => "Process Start Date",
        PROTECT_STOP_DATE => "Protect Stop Date",
        ORIGINAL_CREATION_DATE => "Original Creation Date",
        OBJECT_GROUP => "Object Group",
        _ => panic!("fixture legacy attribute"),
    };
    n.tag = ATTRIBUTE_VALUE;
    Node::structure(ATTRIBUTE, vec![Node::text(ATTRIBUTE_NAME, name), n])
}
fn filters(v: Version, attrs: Vec<Node>) -> Vec<Node> {
    if v.0 == 1 {
        attrs.into_iter().map(legacy).collect()
    } else {
        vec![Node::structure(ATTRIBUTES, attrs)]
    }
}
fn locate(f: &mut Fixture, v: Version, attrs: Vec<Node>) -> Vec<String> {
    let r = f.call(v, "alice", 8, filters(v, attrs));
    payload(&r)
        .all(UNIQUE_IDENTIFIER)
        .map(|n| n.identifier_text().unwrap().to_owned())
        .collect()
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
const VERSIONS: [Version; 7] = [
    Version(1, 1),
    Version(1, 2),
    Version(1, 3),
    Version(1, 4),
    Version(2, 0),
    Version(2, 1),
    Version(3, 0),
];

#[test]
fn single_exact_inclusive_reversed_and_undefined_dates_work_across_editions() {
    for v in VERSIONS {
        let mut f = Fixture::new();
        let future = now() + 10000;
        let missing = f.create(v, vec![]);
        let ids = (0..3)
            .map(|i| f.create(v, vec![Node::date(ACTIVATION_DATE, future + i * 100)]))
            .collect::<Vec<_>>();
        assert_eq!(
            locate(&mut f, v, vec![Node::date(ACTIVATION_DATE, future + 100)]),
            vec![ids[1].clone()]
        );
        assert_eq!(
            locate(
                &mut f,
                v,
                vec![
                    Node::date(ACTIVATION_DATE, future),
                    Node::date(ACTIVATION_DATE, future + 100)
                ]
            ),
            vec![ids[1].clone(), ids[0].clone()]
        );
        assert_eq!(
            locate(
                &mut f,
                v,
                vec![
                    Node::date(ACTIVATION_DATE, future + 100),
                    Node::date(ACTIVATION_DATE, future)
                ]
            ),
            vec![ids[1].clone(), ids[0].clone()]
        );
        assert_eq!(
            locate(&mut f, v, vec![Node::date(ACTIVATION_DATE, i64::MAX)]),
            vec![missing.clone()]
        );
        assert_eq!(
            locate(
                &mut f,
                v,
                vec![
                    Node::date(ACTIVATION_DATE, future + 200),
                    Node::date(ACTIVATION_DATE, i64::MAX)
                ]
            ),
            vec![ids[2].clone(), missing]
        );
        assert_eq!(
            locate(
                &mut f,
                v,
                vec![
                    Node::date(ACTIVATION_DATE, future + 100),
                    Node::date(ACTIVATION_DATE, future + 100)
                ]
            ),
            vec![ids[1].clone()]
        );
        assert!(locate(&mut f, v, vec![Node::date(ACTIVATION_DATE, future + 201)]).is_empty());
        f.restart();
        assert_eq!(
            locate(&mut f, v, vec![Node::date(ACTIVATION_DATE, future + 100)]),
            vec![ids[1].clone()]
        );
        f.engine.store.verify_integrity().unwrap();
    }
}

#[test]
fn every_supported_standard_date_matches_extremes_and_original_creation_is_versioned() {
    for v in VERSIONS {
        let mut f = Fixture::new();
        let id = f.create(v, vec![]);
        let mut object = f.engine.store.get("alice", &id).unwrap().unwrap();
        object.created = i64::MIN;
        object.updated = i64::MAX;
        for tag in [
            ACTIVATION_DATE,
            COMPROMISE_DATE,
            COMPROMISE_OCCURRENCE_DATE,
            DEACTIVATION_DATE,
            DESTROY_DATE,
            PROCESS_START_DATE,
            PROTECT_STOP_DATE,
            ORIGINAL_CREATION_DATE,
        ] {
            object.attrs.retain(|a| a.tag != tag);
            object.attrs.push(Node::date(tag, 123));
        }
        f.engine.store.put(&object).unwrap();
        for tag in [
            ACTIVATION_DATE,
            COMPROMISE_DATE,
            COMPROMISE_OCCURRENCE_DATE,
            DEACTIVATION_DATE,
            DESTROY_DATE,
            PROCESS_START_DATE,
            PROTECT_STOP_DATE,
        ] {
            assert_eq!(
                locate(&mut f, v, vec![Node::date(tag, 123)]),
                vec![id.clone()]
            );
            assert_eq!(
                locate(
                    &mut f,
                    v,
                    vec![Node::date(tag, i64::MIN), Node::date(tag, i64::MAX)]
                ),
                vec![id.clone()]
            );
        }
        assert_eq!(
            locate(&mut f, v, vec![Node::date(INITIAL_DATE, i64::MIN)]),
            vec![id.clone()]
        );
        assert_eq!(
            locate(&mut f, v, vec![Node::date(LAST_CHANGE_DATE, i64::MAX)]),
            vec![id.clone()]
        );
        let original = f.call(
            v,
            "alice",
            8,
            filters(v, vec![Node::date(ORIGINAL_CREATION_DATE, 123)]),
        );
        if v < Version(1, 2) {
            assert_eq!(reason(&original), 7);
        } else {
            assert_eq!(payload(&original).all(UNIQUE_IDENTIFIER).count(), 1);
        }
    }
}

#[test]
fn date_ranges_intersect_and_usage_guide_active_at_time_query_excludes_ended_keys() {
    for v in VERSIONS {
        let mut f = Fixture::new();
        let start = now() - 1000;
        let live = f.create(v, vec![Node::date(ACTIVATION_DATE, start)]);
        f.create(
            v,
            vec![
                Node::date(ACTIVATION_DATE, start),
                Node::date(DEACTIVATION_DATE, start + 50),
            ],
        );
        let compromised = f.create(v, vec![Node::date(ACTIVATION_DATE, start)]);
        let mut object = f.engine.store.get("alice", &compromised).unwrap().unwrap();
        object.state = 4;
        object.attrs.push(Node::date(COMPROMISE_DATE, start + 50));
        f.engine.store.put(&object).unwrap();
        let query = vec![
            Node::date(ACTIVATION_DATE, 0),
            Node::date(ACTIVATION_DATE, start + 100),
            Node::date(DEACTIVATION_DATE, start + 101),
            Node::date(DEACTIVATION_DATE, i64::MAX),
            Node::date(COMPROMISE_DATE, start + 101),
            Node::date(COMPROMISE_DATE, i64::MAX),
        ];
        assert_eq!(locate(&mut f, v, query), vec![live]);
    }
}

#[test]
fn vendor_date_identity_type_and_multi_instance_ranges_are_kept_distinct() {
    for v in [Version(2, 0), Version(2, 1), Version(3, 0)] {
        let mut f = Fixture::new();
        let id = f.create(
            v,
            vec![
                vendor("time", Value::DateTime(10)),
                vendor("time", Value::DateTime(20)),
                vendor("micro", Value::DateTimeExtended(-10)),
            ],
        );
        let wrong = f.create(v, vec![vendor("time", Value::TextString("20".into()))]);
        let missing = f.create(v, vec![]);
        assert_eq!(
            locate(
                &mut f,
                v,
                vec![
                    vendor("time", Value::DateTime(15)),
                    vendor("time", Value::DateTime(25))
                ]
            ),
            vec![id.clone()]
        );
        assert_eq!(
            locate(
                &mut f,
                v,
                vec![vendor("micro", Value::DateTimeExtended(-10))]
            ),
            vec![id.clone()]
        );
        assert_eq!(
            locate(&mut f, v, vec![vendor("time", Value::DateTime(i64::MAX))]),
            vec![missing.clone()]
        );
        assert_eq!(
            locate(&mut f, v, vec![vendor("other", Value::DateTime(i64::MAX))]),
            vec![missing, wrong, id]
        );
    }
}

#[test]
fn malformed_dates_and_excess_bounds_fail_before_search() {
    for v in VERSIONS {
        let mut f = Fixture::new();
        f.create(v, vec![]);
        for value in [
            Value::Integer(1),
            Value::LongInteger(1),
            Value::DateTimeExtended(1),
            Value::TextString("1".into()),
        ] {
            assert_eq!(
                reason(&f.call(
                    v,
                    "alice",
                    8,
                    filters(
                        v,
                        vec![Node {
                            tag: ACTIVATION_DATE,
                            value
                        }]
                    )
                )),
                7
            );
        }
        assert_eq!(
            reason(&f.call(
                v,
                "alice",
                8,
                filters(v, vec![Node::date(INITIAL_DATE, 1); 3])
            )),
            7
        );
        if v.0 >= 2 {
            assert_eq!(
                reason(&f.call(
                    v,
                    "alice",
                    8,
                    filters(v, vec![vendor("t", Value::DateTime(1)); 3])
                )),
                7
            );
        }
        f.engine.store.verify_integrity().unwrap();
    }
}

#[test]
fn legacy_indices_are_ignored_for_date_range_boundaries() {
    for v in [Version(1, 1), Version(1, 2), Version(1, 3), Version(1, 4)] {
        let mut f = Fixture::new();
        let future = now() + 3600;
        let id = f.create(v, vec![Node::date(ACTIVATION_DATE, future)]);
        let mut fields = vec![];
        for (index, value) in [(77, future - 1), (99, future + 1)] {
            let mut a = legacy(Node::date(ACTIVATION_DATE, value));
            if let Value::Structure(children) = &mut a.value {
                children.push(Node::int(ATTRIBUTE_INDEX, index));
            }
            fields.push(a);
        }
        let r = f.call(v, "alice", 8, fields);
        assert_eq!(
            payload(&r)
                .required(UNIQUE_IDENTIFIER)
                .unwrap()
                .identifier_text()
                .unwrap(),
            id
        );
    }
}

#[test]
fn pagination_grants_archival_and_placeholder_follow_filtered_results() {
    for v in VERSIONS {
        let mut f = Fixture::new();
        let future = now() + 3600;
        let old = f.create(v, vec![Node::date(ACTIVATION_DATE, future)]);
        let newest = f.create(v, vec![Node::date(ACTIVATION_DATE, future + 100)]);
        let query = filters(
            v,
            vec![
                Node::date(ACTIVATION_DATE, future),
                Node::date(ACTIVATION_DATE, future + 100),
            ],
        );
        assert!(
            payload(&f.call(v, "bob", 8, query.clone()))
                .all(UNIQUE_IDENTIFIER)
                .next()
                .is_none()
        );
        let grants = [keytend_kmip_server::authorization::ObjectGrant {
            owner: "alice".into(),
            user: None,
            device: None,
            identifier: old.clone(),
            operations: vec![8],
        }];
        let r = f
            .engine
            .process_with_grants(
                "bob",
                &request(v, vec![(8, query.clone())], None, None),
                Some(&[8]),
                &grants,
            )
            .unwrap();
        assert_eq!(
            payload(&r)
                .required(UNIQUE_IDENTIFIER)
                .unwrap()
                .identifier_text()
                .unwrap(),
            old
        );
        if v >= Version(1, 3) {
            let mut fields = query.clone();
            fields.extend([Node::int(MAXIMUM_ITEMS, 1), Node::int(OFFSET_ITEMS, 1)]);
            let get_id = if v.0 >= 3 {
                vec![Node::enumeration(UNIQUE_IDENTIFIER, 1)]
            } else {
                vec![]
            };
            let r = f
                .engine
                .process(
                    "alice",
                    &request(v, vec![(8, fields), (10, get_id)], None, None),
                )
                .unwrap();
            assert_eq!(
                payload(&r)
                    .required(LOCATED_ITEMS)
                    .unwrap()
                    .number()
                    .unwrap(),
                2
            );
            assert_eq!(
                r.all(BATCH_ITEM)
                    .nth(1)
                    .unwrap()
                    .required(RESPONSE_PAYLOAD)
                    .unwrap()
                    .required(UNIQUE_IDENTIFIER)
                    .unwrap()
                    .identifier_text()
                    .unwrap(),
                old
            );
        }
        payload(&f.call(v, "alice", 21, vec![uid(v, &newest)]));
        assert_eq!(
            locate(
                &mut f,
                v,
                vec![
                    Node::date(ACTIVATION_DATE, future),
                    Node::date(ACTIVATION_DATE, future + 100)
                ]
            ),
            vec![old]
        );
        // Archive Date may itself be matched without broadening storage eligibility.
        let mut archived = filters(
            v,
            vec![
                Node::date(ARCHIVE_DATE, 0),
                Node::date(ARCHIVE_DATE, i64::MAX),
            ],
        );
        archived.push(Node::int(STORAGE_STATUS_MASK, 2));
        assert_eq!(
            payload(&f.call(v, "alice", 8, archived))
                .required(UNIQUE_IDENTIFIER)
                .unwrap()
                .identifier_text()
                .unwrap(),
            newest
        );
    }
}
