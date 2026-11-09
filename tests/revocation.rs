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
    ttlv::Node,
};

struct Fixture {
    _dir: tempfile::TempDir,
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
        let engine = Engine::new(Store::open(&dir.path().join("store"), &key).unwrap(), true);
        Self { _dir: dir, engine }
    }
    fn call(&mut self, v: Version, op: u32, fields: Vec<Node>) -> Node {
        self.engine
            .process("owner", &message(v, op, fields))
            .unwrap()
    }
}
fn message(v: Version, op: u32, fields: Vec<Node>) -> Node {
    let mut header = vec![v.node()];
    if v.0 < 3 {
        header.push(Node::int(BATCH_COUNT, 1));
    }
    Node::structure(
        REQUEST_MESSAGE,
        vec![
            Node::structure(REQUEST_HEADER, header),
            Node::structure(
                BATCH_ITEM,
                vec![
                    Node::enumeration(OPERATION, op),
                    Node::structure(REQUEST_PAYLOAD, fields),
                ],
            ),
        ],
    )
}
fn id(v: Version, identifier: &str) -> Node {
    if v.0 >= 3 {
        Node::reference(UNIQUE_IDENTIFIER, identifier)
    } else {
        Node::text(UNIQUE_IDENTIFIER, identifier)
    }
}
fn body(n: &Node) -> &Node {
    let item = n.required(BATCH_ITEM).unwrap();
    assert_eq!(
        item.required(RESULT_STATUS).unwrap().number().unwrap(),
        0,
        "{}",
        serde_json::to_string(n).unwrap()
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

fn make_key(f: &mut Fixture, v: Version) -> String {
    let attrs = vec![
        Node::enumeration(CRYPTOGRAPHIC_ALGORITHM, 3),
        Node::int(CRYPTOGRAPHIC_LENGTH, 128),
        Node::int(CRYPTOGRAPHIC_USAGE_MASK, 12),
    ];
    let container = if v.0 >= 2 {
        Node::structure(ATTRIBUTES, attrs)
    } else {
        Node::structure(
            TEMPLATE_ATTRIBUTE,
            attrs
                .into_iter()
                .map(|a| {
                    Node::structure(
                        ATTRIBUTE,
                        vec![
                            Node::text(ATTRIBUTE_NAME, tag_name(a.tag).unwrap()),
                            Node {
                                tag: ATTRIBUTE_VALUE,
                                value: a.value,
                            },
                        ],
                    )
                })
                .collect(),
        )
    };
    body(&f.call(v, 1, vec![Node::enumeration(OBJECT_TYPE, 2), container]))
        .required(UNIQUE_IDENTIFIER)
        .unwrap()
        .identifier_text()
        .unwrap()
        .to_owned()
}
fn revoke_reason(code: u32) -> Node {
    Node::structure(
        REVOCATION_REASON,
        vec![Node::enumeration(REVOCATION_REASON_CODE, code)],
    )
}
fn snapshot(f: &Fixture, key: &str) -> serde_json::Value {
    serde_json::to_value(f.engine.store.get("owner", key).unwrap().unwrap()).unwrap()
}
fn stored_attrs(f: &Fixture, key: &str) -> Vec<Node> {
    f.engine
        .store
        .get("owner", key)
        .unwrap()
        .unwrap()
        .attrs
        .clone()
}
fn legacy_attr(mut n: Node) -> Node {
    let name = tag_name(n.tag).unwrap();
    n.tag = ATTRIBUTE_VALUE;
    Node::structure(ATTRIBUTE, vec![Node::text(ATTRIBUTE_NAME, name), n])
}
fn import_fields(v: Version, p: &Node, attrs: Vec<Node>) -> Vec<Node> {
    let mut fields = p
        .children()
        .unwrap()
        .iter()
        .filter(|n| ![ATTRIBUTE, ATTRIBUTES].contains(&n.tag))
        .cloned()
        .collect::<Vec<_>>();
    if v.0 == 1 {
        // Preserve the exported stable indices for repeated attributes.
        fields.extend(attrs.into_iter().map(|n| {
            p.all(ATTRIBUTE)
                .find(|a| {
                    a.get(ATTRIBUTE_NAME).and_then(|a| a.string().ok()) == tag_name(n.tag)
                        && a.get(ATTRIBUTE_VALUE).is_some_and(|a| a.value == n.value)
                })
                .cloned()
                .unwrap_or_else(|| legacy_attr(n))
        }));
    } else {
        fields.push(Node::structure(ATTRIBUTES, attrs));
    }
    fields.push(Node::boolean(REPLACE_EXISTING, true));
    fields
}

#[test]
fn revocation_reason_roundtrips_and_import_rejects_inconsistent_restores_atomically() {
    for v in [Version(1, 4), Version(2, 0), Version(2, 1), Version(3, 0)] {
        let mut f = Fixture::new();
        let key = make_key(&mut f, v);
        body(&f.call(v, 18, vec![id(v, &key)]));
        for stage in 0..3 {
            if stage == 0 {
                let mut rr = revoke_reason(5);
                if let keytend_kmip_server::ttlv::Value::Structure(fields) = &mut rr.value {
                    fields.push(Node::text(REVOCATION_MESSAGE, "history ".repeat(20_000)));
                }
                body(&f.call(v, 19, vec![id(v, &key), rr]));
            } else if stage == 1 && v.0 < 3 {
                body(&f.call(v, 19, vec![id(v, &key), revoke_reason(2)]));
            } else if stage == 2 {
                body(&f.call(v, 20, vec![id(v, &key)]));
            }
            let exported = f.call(v, 43, vec![id(v, &key)]);
            let p = body(&exported);
            let attrs = returned_attrs(v, p);
            let original = stored_attrs(&f, &key);
            assert!(
                attrs.iter().find(|n| n.tag == REVOCATION_REASON)
                    == original.iter().find(|n| n.tag == REVOCATION_REASON)
            );
            let response = f.call(v, 11, vec![id(v, &key)]);
            assert!(
                returned_attrs(v, body(&response))
                    .iter()
                    .find(|n| n.tag == REVOCATION_REASON)
                    == original.iter().find(|n| n.tag == REVOCATION_REASON)
            );
            let fields = import_fields(v, p, attrs.clone());
            body(&f.call(v, 42, fields));
            let restored = stored_attrs(&f, &key);
            for tag in [
                REVOCATION_REASON,
                COMPROMISE_DATE,
                COMPROMISE_OCCURRENCE_DATE,
                DEACTIVATION_DATE,
                DESTROY_DATE,
            ] {
                assert!(
                    restored.iter().find(|n| n.tag == tag)
                        == original.iter().find(|n| n.tag == tag)
                );
            }
            let before = snapshot(&f, &key);
            let changed = |tag: u32, value: Option<Node>| {
                let mut a = attrs.clone();
                a.retain(|n| n.tag != tag);
                a.extend(value);
                import_fields(v, p, a)
            };
            let is_compromised = v.0 >= 3 || stage > 0;
            let lifecycle_date = if is_compromised {
                COMPROMISE_DATE
            } else {
                DEACTIVATION_DATE
            };
            let mut invalids = vec![
                changed(STATE, Some(Node::enumeration(STATE, 2))),
                changed(lifecycle_date, None),
                changed(
                    lifecycle_date,
                    Some(Node::date(
                        lifecycle_date,
                        keytend_kmip_server::store::now() + 3600,
                    )),
                ),
                changed(
                    REVOCATION_REASON,
                    Some(Node::structure(
                        REVOCATION_REASON,
                        vec![Node::int(REVOCATION_REASON_CODE, 2)],
                    )),
                ),
            ];
            if stage < 2 {
                invalids.push(changed(
                    DESTROY_DATE,
                    Some(Node::date(DESTROY_DATE, keytend_kmip_server::store::now())),
                ));
            }
            if is_compromised {
                invalids.push(changed(
                    COMPROMISE_OCCURRENCE_DATE,
                    Some(Node::date(
                        COMPROMISE_OCCURRENCE_DATE,
                        keytend_kmip_server::store::now() + 3600,
                    )),
                ));
                invalids.push(changed(STATE, Some(Node::enumeration(STATE, 3))));
            } else {
                invalids.push(changed(REVOCATION_REASON, Some(revoke_reason(2))));
                invalids.push(changed(
                    COMPROMISE_DATE,
                    Some(Node::date(
                        COMPROMISE_DATE,
                        keytend_kmip_server::store::now(),
                    )),
                ));
            }
            let mut duplicate = attrs.clone();
            duplicate.push(
                attrs
                    .iter()
                    .find(|n| n.tag == REVOCATION_REASON)
                    .unwrap()
                    .clone(),
            );
            invalids.push(import_fields(v, p, duplicate));
            for fields in invalids {
                assert_ne!(reason(&f.call(v, 42, fields)), 0);
                assert_eq!(snapshot(&f, &key), before);
            }
        }
    }
}

#[test]
fn import_preserves_revocation_history_across_protocol_editions() {
    for (source, code, expected_state) in [(Version(1, 1), 3, 3), (Version(3, 0), 1, 4)] {
        let mut f = Fixture::new();
        let key = make_key(&mut f, source);
        body(&f.call(source, 18, vec![id(source, &key)]));
        body(&f.call(source, 19, vec![id(source, &key), revoke_reason(code)]));
        let original = stored_attrs(&f, &key);
        for target in [Version(1, 4), Version(2, 0), Version(2, 1), Version(3, 0)] {
            let response = f.call(target, 43, vec![id(target, &key)]);
            let p = body(&response);
            body(&f.call(
                target,
                42,
                import_fields(target, p, returned_attrs(target, p)),
            ));
            let restored = stored_attrs(&f, &key);
            assert_eq!(state(&mut f, target, &key), expected_state);
            for tag in [
                REVOCATION_REASON,
                DEACTIVATION_DATE,
                COMPROMISE_DATE,
                COMPROMISE_OCCURRENCE_DATE,
            ] {
                assert!(
                    restored.iter().find(|n| n.tag == tag)
                        == original.iter().find(|n| n.tag == tag)
                );
            }
        }
    }
}

#[test]
fn reason_is_server_owned_and_locate_filter_matches_the_stored_reason() {
    for v in Version::supported(true) {
        let mut f = Fixture::new();
        let key = make_key(&mut f, v);
        body(&f.call(
            v,
            19,
            vec![
                id(v, &key),
                revoke_reason(2),
                Node::date(COMPROMISE_OCCURRENCE_DATE, 1),
            ],
        ));
        let before = snapshot(&f, &key);
        let rr = revoke_reason(5);
        let attempts = if v.0 == 1 {
            vec![
                (13, vec![id(v, &key), legacy_attr(rr.clone())]),
                (14, vec![id(v, &key), legacy_attr(rr.clone())]),
                (
                    15,
                    vec![id(v, &key), Node::text(ATTRIBUTE_NAME, "Revocation Reason")],
                ),
            ]
        } else {
            vec![
                (
                    13,
                    vec![
                        id(v, &key),
                        Node::structure(NEW_ATTRIBUTE, vec![rr.clone()]),
                    ],
                ),
                (
                    14,
                    vec![
                        id(v, &key),
                        Node::structure(NEW_ATTRIBUTE, vec![rr.clone()]),
                    ],
                ),
                (
                    15,
                    vec![
                        id(v, &key),
                        Node::enumeration(ATTRIBUTE_REFERENCE, REVOCATION_REASON),
                    ],
                ),
            ]
        };
        for (op, fields) in attempts {
            assert_ne!(reason(&f.call(v, op, fields)), 0);
            assert_eq!(snapshot(&f, &key), before);
        }
        // Locate filters on the reason (docs/locate.md): reason 5
        // matches nothing, the stored reason 2 matches the key.
        let filter = |rr: Node| {
            if v.0 == 1 {
                legacy_attr(rr)
            } else {
                Node::structure(ATTRIBUTES, vec![rr])
            }
        };
        let located = |f: &mut Fixture, rr: Node| -> Vec<String> {
            body(&f.call(v, 8, vec![filter(rr)]))
                .all(UNIQUE_IDENTIFIER)
                .map(|n| n.identifier_text().unwrap().to_owned())
                .collect()
        };
        assert!(located(&mut f, rr.clone()).is_empty());
        assert_eq!(located(&mut f, revoke_reason(2)), vec![key.clone()]);
        let a = if v.0 == 1 {
            Node::structure(TEMPLATE_ATTRIBUTE, vec![legacy_attr(rr)])
        } else {
            Node::structure(ATTRIBUTES, vec![rr])
        };
        assert_ne!(
            reason(&f.call(v, 1, vec![Node::enumeration(OBJECT_TYPE, 2), a])),
            0
        );
    }
}

#[test]
fn rekey_and_split_do_not_inherit_revocation_history() {
    for v in [Version(1, 2), Version(1, 4), Version(2, 1), Version(3, 0)] {
        let mut f = Fixture::new();
        let key = make_key(&mut f, v);
        body(&f.call(
            v,
            19,
            vec![
                id(v, &key),
                revoke_reason(2),
                Node::date(COMPROMISE_OCCURRENCE_DATE, 1),
            ],
        ));
        let replacement = body(&f.call(v, 4, vec![id(v, &key)]))
            .required(UNIQUE_IDENTIFIER)
            .unwrap()
            .identifier_text()
            .unwrap()
            .to_owned();
        assert!(!stored_attrs(&f, &replacement).iter().any(|a| {
            [
                REVOCATION_REASON,
                COMPROMISE_DATE,
                COMPROMISE_OCCURRENCE_DATE,
            ]
            .contains(&a.tag)
        }));
        let attrs = if v.0 >= 3 {
            vec![Node::enumeration(SPLIT_KEY_POLYNOMIAL, 2)]
        } else {
            vec![]
        };
        let container = if v.0 == 1 {
            Node::structure(TEMPLATE_ATTRIBUTE, vec![])
        } else {
            Node::structure(ATTRIBUTES, attrs)
        };
        let response = f.call(
            v,
            40,
            vec![
                id(v, &key),
                Node::enumeration(OBJECT_TYPE, 5),
                Node::int(SPLIT_KEY_PARTS, 3),
                Node::int(SPLIT_KEY_THRESHOLD, 2),
                Node::enumeration(SPLIT_KEY_METHOD, 4),
                container,
            ],
        );
        let parts = body(&response)
            .all(UNIQUE_IDENTIFIER)
            .map(|n| n.identifier_text().unwrap().to_owned())
            .collect::<Vec<_>>();
        assert_eq!(parts.len(), 3);
        for part in parts {
            assert!(!stored_attrs(&f, &part).iter().any(|a| {
                [
                    REVOCATION_REASON,
                    COMPROMISE_DATE,
                    COMPROMISE_OCCURRENCE_DATE,
                ]
                .contains(&a.tag)
            }));
        }
        assert!(
            stored_attrs(&f, &key)
                .iter()
                .any(|a| a.tag == REVOCATION_REASON)
        );
    }
}

#[test]
fn draft_deactivate_only_transitions_from_active_and_preserves_rejected_history() {
    let v = Version(3, 0);
    let mut f = Fixture::new();
    let key = make_key(&mut f, v);
    for stage in 0..4 {
        let before = snapshot(&f, &key);
        assert_eq!(reason(&f.call(v, 64, vec![id(v, &key)])), 0x43);
        assert_eq!(snapshot(&f, &key), before);
        match stage {
            0 => {
                body(&f.call(v, 18, vec![id(v, &key)]));
                body(&f.call(v, 64, vec![id(v, &key)]));
            }
            1 => {
                body(&f.call(v, 19, vec![id(v, &key)]));
            }
            2 => {
                body(&f.call(v, 20, vec![id(v, &key)]));
            }
            _ => {}
        }
    }
}

#[test]
fn revoke_reserves_exported_metadata_at_storage_boundary() {
    for v in [Version(1, 4), Version(2, 1), Version(3, 0)] {
        for overflow in [false, true] {
            let mut f = Fixture::new();
            let key = make_key(&mut f, v);
            let response = f.call(v, 11, vec![id(v, &key)]);
            let attrs = returned_attrs(v, body(&response));
            let projected_size: usize = attrs.iter().map(Node::encoded_len).sum();
            let growth =
                revoke_reason(2).encoded_len() + 2 * Node::date(COMPROMISE_DATE, 0).encoded_len();
            let padding = 262_144 - projected_size - growth - 8 + usize::from(overflow);
            let mut obj = f.engine.store.get("owner", &key).unwrap().unwrap();
            obj.attrs
                .push(Node::text(CONTACT_INFORMATION, "x".repeat(padding)));
            f.engine.store.put(&obj).unwrap();
            let before = snapshot(&f, &key);
            let response = f.call(v, 19, vec![id(v, &key), revoke_reason(2)]);
            if overflow {
                assert_eq!(reason(&response), 2);
                assert_eq!(snapshot(&f, &key), before);
            } else {
                body(&response);
                let exported = f.call(v, 43, vec![id(v, &key)]);
                let attrs = returned_attrs(v, body(&exported));
                assert_eq!(attrs.iter().map(Node::encoded_len).sum::<usize>(), 262_144);
                body(&f.call(v, 42, import_fields(v, body(&exported), attrs)));
                assert_eq!(state(&mut f, v, &key), 4);
            }
        }
        for overflow in [false, true] {
            let mut f = Fixture::new();
            let key = make_key(&mut f, v);
            let response = f.call(v, 11, vec![id(v, &key)]);
            let projected_count = returned_attrs(v, body(&response)).len();
            let mut obj = f.engine.store.get("owner", &key).unwrap().unwrap();
            for index in 0..1021 - projected_count + usize::from(overflow) {
                obj.attrs
                    .push(Node::text(OBJECT_GROUP, format!("group-{index}")));
            }
            f.engine.store.put(&obj).unwrap();
            let before = snapshot(&f, &key);
            let response = f.call(v, 19, vec![id(v, &key), revoke_reason(2)]);
            if overflow {
                assert_eq!(reason(&response), 2);
                assert_eq!(snapshot(&f, &key), before);
            } else {
                body(&response);
                let exported = f.call(v, 43, vec![id(v, &key)]);
                let attrs = returned_attrs(v, body(&exported));
                assert_eq!(attrs.len(), 1024);
                body(&f.call(v, 42, import_fields(v, body(&exported), attrs)));
                assert_eq!(state(&mut f, v, &key), 4);
            }
        }
    }
}
fn returned_attrs(v: Version, p: &Node) -> Vec<Node> {
    if v.0 >= 2 {
        p.required(ATTRIBUTES).unwrap().children().unwrap().to_vec()
    } else {
        p.all(ATTRIBUTE)
            .map(|a| {
                let name = a.required(ATTRIBUTE_NAME).unwrap().string().unwrap();
                let tag = (0x420000..=0x420200)
                    .find(|&tag| tag_name(tag) == Some(name))
                    .unwrap();
                let mut n = a.required(ATTRIBUTE_VALUE).unwrap().clone();
                n.tag = tag;
                n
            })
            .collect()
    }
}

#[test]
fn revoke_transition_matrix_preserves_reason_dates_and_rejects_repeats_atomically() {
    for v in Version::supported(true) {
        let mut f = Fixture::new();
        for start in 1..=6 {
            for code in 1..=7 {
                let key = make_key(&mut f, v);
                if [2, 3].contains(&start) {
                    body(&f.call(v, 18, vec![id(v, &key)]));
                }
                if start == 3 {
                    if v.0 >= 3 {
                        body(&f.call(v, 64, vec![id(v, &key)]));
                    } else {
                        body(&f.call(v, 19, vec![id(v, &key), revoke_reason(5)]));
                    }
                }
                if [4, 6].contains(&start) {
                    body(&f.call(
                        v,
                        19,
                        vec![
                            id(v, &key),
                            revoke_reason(2),
                            Node::date(COMPROMISE_OCCURRENCE_DATE, 1),
                        ],
                    ));
                }
                if start >= 5 {
                    body(&f.call(v, 20, vec![id(v, &key)]));
                }
                assert_eq!(state(&mut f, v, &key), start);
                let before = snapshot(&f, &key);
                let compromise = v.0 >= 3 || code == 2 || v >= Version(1, 3) && code == 3;
                let allowed = if compromise {
                    [1, 2, 3, 5].contains(&start)
                } else {
                    start == 2
                };
                let mut rr = revoke_reason(code);
                if let keytend_kmip_server::ttlv::Value::Structure(fields) = &mut rr.value {
                    fields.push(Node::text(REVOCATION_MESSAGE, "bounded history"));
                }
                let mut fields = vec![id(v, &key), rr.clone()];
                if compromise {
                    fields.push(Node::date(COMPROMISE_OCCURRENCE_DATE, 2));
                }
                let r = f.call(v, 19, fields.clone());
                if allowed {
                    body(&r);
                    assert_eq!(
                        state(&mut f, v, &key),
                        if start == 5 {
                            6
                        } else if compromise {
                            4
                        } else {
                            3
                        }
                    );
                    let attrs = stored_attrs(&f, &key);
                    assert!(
                        attrs
                            .iter()
                            .filter(|n| n.tag == REVOCATION_REASON)
                            .collect::<Vec<_>>()
                            == vec![&rr]
                    );
                    if compromise {
                        assert!(attrs.contains(&Node::date(COMPROMISE_OCCURRENCE_DATE, 2)));
                        assert!(attrs.iter().any(|n| n.tag == COMPROMISE_DATE));
                    }
                    let revoked = snapshot(&f, &key);
                    assert_eq!(
                        reason(&f.call(v, 19, fields)),
                        if v.0 >= 2 { 0x43 } else { 12 }
                    );
                    assert_eq!(snapshot(&f, &key), revoked);
                } else {
                    assert_eq!(
                        reason(&r),
                        if v.0 >= 2 { 0x43 } else { 12 },
                        "{}.{} state={start} code={code}",
                        v.0,
                        v.1
                    );
                    assert_eq!(snapshot(&f, &key), before);
                }
            }
        }
    }
}

#[test]
fn revoke_validates_entire_structure_and_bounds_post_mutation_storage() {
    for v in [Version(1, 4), Version(2, 1), Version(3, 0)] {
        let mut f = Fixture::new();
        let key = make_key(&mut f, v);
        let before = snapshot(&f, &key);
        for fields in [
            vec![],
            vec![Node::enumeration(REVOCATION_REASON_CODE, 8)],
            vec![
                Node::enumeration(REVOCATION_REASON_CODE, 2),
                Node::text(CONTACT_INFORMATION, "unexpected"),
            ],
            vec![Node::int(REVOCATION_REASON_CODE, 2)],
            vec![
                Node::enumeration(REVOCATION_REASON_CODE, 2),
                Node::enumeration(REVOCATION_REASON_CODE, 3),
            ],
            vec![
                Node::enumeration(REVOCATION_REASON_CODE, 2),
                Node::bytes(REVOCATION_MESSAGE, vec![1]),
            ],
            vec![
                Node::enumeration(REVOCATION_REASON_CODE, 2),
                Node::text(REVOCATION_MESSAGE, "a"),
                Node::text(REVOCATION_MESSAGE, "b"),
            ],
        ] {
            assert_ne!(
                reason(&f.call(
                    v,
                    19,
                    vec![id(v, &key), Node::structure(REVOCATION_REASON, fields)]
                )),
                0
            );
            assert_eq!(snapshot(&f, &key), before);
        }
        assert_ne!(
            reason(&f.call(v, 19, vec![id(v, &key), revoke_reason(2), revoke_reason(3)])),
            0
        );
        assert_eq!(snapshot(&f, &key), before);
        let oversized = Node::structure(
            REVOCATION_REASON,
            vec![
                Node::enumeration(REVOCATION_REASON_CODE, 2),
                Node::text(REVOCATION_MESSAGE, "x".repeat(300_000)),
            ],
        );
        assert_eq!(reason(&f.call(v, 19, vec![id(v, &key), oversized])), 2);
        assert_eq!(snapshot(&f, &key), before);

        // Test the aggregate byte limit: the reason alone is below the limit.
        let mut obj = f.engine.store.get("owner", &key).unwrap().unwrap();
        obj.attrs
            .push(Node::text(CONTACT_INFORMATION, "x".repeat(200_000)));
        f.engine.store.put(&obj).unwrap();
        let before = snapshot(&f, &key);
        let large = Node::structure(
            REVOCATION_REASON,
            vec![
                Node::enumeration(REVOCATION_REASON_CODE, 2),
                Node::text(REVOCATION_MESSAGE, "x".repeat(65_536)),
            ],
        );
        assert_eq!(reason(&f.call(v, 19, vec![id(v, &key), large])), 2);
        assert_eq!(snapshot(&f, &key), before);

        // Count growth includes the reason and both compromise dates.
        obj.attrs.retain(|a| a.tag != CONTACT_INFORMATION);
        while obj.attrs.len() < 1022 {
            obj.attrs.push(Node::text(
                OBJECT_GROUP,
                format!("group-{}", obj.attrs.len()),
            ));
        }
        f.engine.store.put(&obj).unwrap();
        let before = snapshot(&f, &key);
        assert_eq!(
            reason(&f.call(v, 19, vec![id(v, &key), revoke_reason(2)])),
            2
        );
        assert_eq!(snapshot(&f, &key), before);
    }
}
fn state(f: &mut Fixture, v: Version, key: &str) -> u32 {
    let response = f.call(v, 11, vec![id(v, key)]);
    let p = body(&response);
    if v.0 >= 2 {
        p.required(ATTRIBUTES)
            .unwrap()
            .required(STATE)
            .unwrap()
            .number()
            .unwrap()
    } else {
        p.all(ATTRIBUTE)
            .find(|a| a.get(ATTRIBUTE_NAME).and_then(|n| n.string().ok()) == Some("State"))
            .unwrap()
            .required(ATTRIBUTE_VALUE)
            .unwrap()
            .number()
            .unwrap()
    }
}
#[test]
fn draft_revoke_defaults_reason_and_compromises_every_reason() {
    for code in 0..=7 {
        let mut f = Fixture::new();
        let v = Version(3, 0);
        let key = make_key(&mut f, v);
        let mut fields = vec![id(v, &key)];
        if code != 0 {
            fields.push(revoke_reason(code));
        }
        body(&f.call(v, 19, fields));
        assert_eq!(state(&mut f, v, &key), 4);
        body(&f.call(v, 20, vec![id(v, &key)]));
        assert_eq!(state(&mut f, v, &key), 6);
    }
}
#[test]
fn final_revoke_still_requires_reason_and_preserves_state_split() {
    for v in [
        Version(1, 1),
        Version(1, 2),
        Version(1, 3),
        Version(1, 4),
        Version(2, 0),
        Version(2, 1),
    ] {
        let mut f = Fixture::new();
        let key = make_key(&mut f, v);
        assert_ne!(reason(&f.call(v, 19, vec![id(v, &key)])), 0);
        assert_eq!(state(&mut f, v, &key), 1);
        for code in 1..=7 {
            let key = make_key(&mut f, v);
            body(&f.call(v, 18, vec![id(v, &key)]));
            let mut fields = vec![id(v, &key), revoke_reason(code)];
            if v < Version(1, 3) && code == 2 {
                fields.push(Node::date(
                    COMPROMISE_OCCURRENCE_DATE,
                    keytend_kmip_server::store::now(),
                ));
            }
            body(&f.call(v, 19, fields));
            assert_eq!(
                state(&mut f, v, &key),
                if code == 2 || v >= Version(1, 3) && code == 3 {
                    4
                } else {
                    3
                }
            );
        }
    }
}

#[test]
fn revocation_occurrence_dates_are_versioned_and_failures_are_atomic() {
    for v in [
        Version(1, 3),
        Version(1, 4),
        Version(2, 0),
        Version(2, 1),
        Version(3, 0),
    ] {
        let mut f = Fixture::new();
        let key = make_key(&mut f, v);
        let before = f.engine.store.get("owner", &key).unwrap().unwrap();
        for invalid in [
            vec![id(v, &key), revoke_reason(8)],
            vec![
                id(v, &key),
                revoke_reason(2),
                Node::date(
                    COMPROMISE_OCCURRENCE_DATE,
                    keytend_kmip_server::store::now() + 3600,
                ),
            ],
            vec![
                id(v, &key),
                revoke_reason(2),
                Node::int(COMPROMISE_OCCURRENCE_DATE, 1),
            ],
        ] {
            assert_ne!(reason(&f.call(v, 19, invalid)), 0);
            let after = f.engine.store.get("owner", &key).unwrap().unwrap();
            assert_eq!(after.state, before.state);
            assert_eq!(after.updated, before.updated);
            assert_eq!(
                serde_json::to_value(&after.attrs).unwrap(),
                serde_json::to_value(&before.attrs).unwrap()
            );
        }
        let occurrence = before.created - 100;
        let request = vec![
            id(v, &key),
            revoke_reason(1),
            Node::date(COMPROMISE_OCCURRENCE_DATE, occurrence),
        ];
        if v.0 >= 3 {
            body(&f.call(v, 19, request));
            let object = f.engine.store.get("owner", &key).unwrap().unwrap();
            assert_eq!(
                object
                    .attrs
                    .iter()
                    .find(|n| n.tag == COMPROMISE_OCCURRENCE_DATE)
                    .map(|n| match n.value {
                        keytend_kmip_server::ttlv::Value::DateTime(t) => t,
                        _ => panic!("date type"),
                    }),
                Some(occurrence)
            );
        } else {
            assert_ne!(reason(&f.call(v, 19, request)), 0);
        }
        // The draft request above already compromised its object. Use a fresh
        // object for the omitted-date default, rather than rewriting history.
        let key = if v.0 >= 3 { make_key(&mut f, v) } else { key };
        let before = f.engine.store.get("owner", &key).unwrap().unwrap();
        body(&f.call(v, 19, vec![id(v, &key), revoke_reason(2)]));
        let object = f.engine.store.get("owner", &key).unwrap().unwrap();
        assert_eq!(
            object
                .attrs
                .iter()
                .find(|n| n.tag == COMPROMISE_OCCURRENCE_DATE)
                .map(|n| match n.value {
                    keytend_kmip_server::ttlv::Value::DateTime(t) => t,
                    _ => panic!("date type"),
                }),
            Some(before.created)
        );
        assert_eq!(object.material, before.material);
        assert!(object.attrs.iter().any(|n| n.tag == COMPROMISE_DATE));
    }
}

#[test]
fn legacy_key_compromise_requires_occurrence_before_any_mutation() {
    for v in [Version(1, 1), Version(1, 2)] {
        let mut f = Fixture::new();
        let key = make_key(&mut f, v);
        let before = f.engine.store.get("owner", &key).unwrap().unwrap();
        let response = f.call(v, 19, vec![id(v, &key), revoke_reason(2)]);
        let item = response.required(BATCH_ITEM).unwrap();
        assert_eq!(
            item.required(RESULT_STATUS).unwrap().number().unwrap(),
            1,
            "legacy compromise without its required occurrence date succeeded"
        );
        let after = f.engine.store.get("owner", &key).unwrap().unwrap();
        assert_eq!(
            serde_json::to_value(&before).unwrap(),
            serde_json::to_value(&after).unwrap()
        );
        body(&f.call(
            v,
            19,
            vec![
                id(v, &key),
                revoke_reason(2),
                Node::date(COMPROMISE_OCCURRENCE_DATE, before.created - 60),
            ],
        ));
        assert_eq!(state(&mut f, v, &key), 4);
    }
}
