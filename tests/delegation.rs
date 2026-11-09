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

//! Delegated Login (2.0/2.1 section 6.1.12, draft 3.0): Rights validation,
//! per-item authorization of delegated tickets, budgets, Logout and the
//! asynchronous refusal (docs/tickets.md#delegated-login).
#[path = "support/tickets.rs"]
mod support;
use keytend_kmip_server::{tags::*, ttlv::Node};
use support::*;

/// Delegated Login by alice (no request credentials), returning the Ticket.
fn delegate(f: &mut Fixture, v: keytend_kmip_server::protocol::Version, r: Vec<Node>) -> Node {
    ticket(&f.one("alice", v, None, DELEGATED_LOGIN, rights(r)))
}
fn objects(v: keytend_kmip_server::protocol::Version, ids: &[&str]) -> Vec<Node> {
    ids.iter().map(|id| identifier(v, id)).collect()
}

#[test]
fn rights_are_validated_against_the_delegator() {
    let mut f = Fixture::new();
    let mine = f.key("alice", V21, "mine");
    let theirs = f.key("bob", V21, "theirs");
    let delegated = |f: &mut Fixture, allowed: Option<&[u32]>, p: Vec<Node>| {
        let r = f.send_with(
            "alice",
            allowed,
            V21,
            vec![],
            None,
            vec![(DELEGATED_LOGIN, p)],
        );
        r[0].clone()
    };
    // Rights is required and must hold at least one Right.
    assert_eq!(reason(&delegated(&mut f, None, vec![])), 7);
    assert_eq!(reason(&delegated(&mut f, None, rights(vec![]))), 7);
    // An operation outside the delegator's own allowlist.
    let allowed = [10, 24, 47];
    assert_eq!(
        reason(&delegated(
            &mut f,
            Some(&allowed),
            rights(vec![right(&[CREATE], vec![], None)])
        )),
        12
    );
    ticket(&delegated(
        &mut f,
        Some(&allowed),
        rights(vec![right(&[GET], vec![], None)]),
    ));
    // Operations that are never delegated, even when the delegator may
    // use them.
    for op in [25, 26, 45, 47, 50, 53, 57, 58] {
        assert_eq!(
            reason(&delegated(
                &mut f,
                None,
                rights(vec![right(&[op], vec![], None)])
            )),
            12,
            "op {op}"
        );
    }
    // Objects the delegator does not own, and unknown identifiers.
    for id in [theirs.as_str(), "missing"] {
        assert_eq!(
            reason(&delegated(
                &mut f,
                None,
                rights(vec![right(&[GET], objects(V21, &[id]), None)])
            )),
            12
        );
    }
    // Object Groups is Feature Not Supported where defined (2.1), and not a
    // 2.0 field.
    let grouped = Node::structure(
        RIGHT,
        vec![Node::structure(
            OBJECT_GROUPS,
            vec![Node::text(OBJECT_GROUP, "g")],
        )],
    );
    assert_eq!(
        reason(&delegated(&mut f, None, rights(vec![grouped.clone()]))),
        8
    );
    let r = f.send(
        "alice",
        V20,
        None,
        vec![(DELEGATED_LOGIN, rights(vec![grouped]))],
    );
    assert_eq!(reason(&r[0]), 7);
    // Other enumerations and Integers in Objects are not supported; empty
    // Operations or Objects are invalid.
    for value in [
        Node::enumeration(UNIQUE_IDENTIFIER, 3),
        Node::int(UNIQUE_IDENTIFIER, 0),
    ] {
        assert_eq!(
            reason(&delegated(
                &mut f,
                None,
                rights(vec![right(&[GET], vec![value], None)])
            )),
            8
        );
    }
    for empty in [OPERATIONS, OBJECTS] {
        assert_eq!(
            reason(&delegated(
                &mut f,
                None,
                rights(vec![Node::structure(
                    RIGHT,
                    vec![Node::structure(empty, vec![])]
                )])
            )),
            7
        );
    }
    // Limits: 16 Rights, 32 Objects per Right.
    let many = (0..17).map(|_| right(&[GET], vec![], None)).collect();
    assert_eq!(reason(&delegated(&mut f, None, rights(many))), 0x3a);
    let ids = vec![mine.as_str(); 33];
    assert_eq!(
        reason(&delegated(
            &mut f,
            None,
            rights(vec![right(&[GET], objects(V21, &ids), None)])
        )),
        0x3a
    );
    // Right Usage Limits follow the Login rules.
    assert_eq!(
        reason(&delegated(
            &mut f,
            None,
            rights(vec![right(&[GET], vec![], Some(usage_limits(1, 2)))])
        )),
        7
    );
    ticket(&delegated(
        &mut f,
        None,
        rights(vec![right(&[GET], objects(V21, &[&mine]), None)]),
    ));
}

#[test]
fn a_delegate_acts_as_the_delegator_within_its_rights() {
    for v in [V20, V21, V3] {
        let mut f = Fixture::new();
        let k = f.key("alice", v, "k");
        let other = f.key("alice", v, "other");
        let t = delegate(&mut f, v, vec![right(&[GET], objects(v, &[&k]), None)]);
        // bob presents alice's ticket and reads K as alice.
        let item = f.one("bob", v, by_ticket(&t), GET, get(v, &k));
        assert!(has_key_material(&item), "{}.{}", v.0, v.1);
        // Not another object, not Locate, not another operation.
        assert_eq!(
            reason(&f.one("bob", v, by_ticket(&t), GET, get(v, &other))),
            12
        );
        assert_eq!(reason(&f.one("bob", v, by_ticket(&t), LOCATE, vec![])), 12);
        assert_eq!(
            reason(&f.one("bob", v, by_ticket(&t), DESTROY, get(v, &k))),
            12
        );
        // Any other object reference in the payload is refused.
        let wrapped = vec![
            identifier(v, &k),
            Node::structure(
                KEY_WRAPPING_SPECIFICATION,
                vec![
                    Node::enumeration(WRAPPING_METHOD, 1),
                    Node::structure(ENCRYPTION_KEY_INFORMATION, vec![identifier(v, &other)]),
                ],
            ),
        ];
        assert_eq!(reason(&f.one("bob", v, by_ticket(&t), GET, wrapped)), 12);
        // Without the ticket, bob does not see alice's key.
        assert_ne!(status(&f.one("bob", v, None, GET, get(v, &k))), 0);
    }
}

#[test]
fn rights_without_objects_cover_the_delegator_allowlist() {
    let mut f = Fixture::new();
    // A Right without Operations means every delegatable operation.
    let t = delegate(&mut f, V21, vec![right(&[], vec![], None)]);
    let id = uid(&f.one("bob", V21, by_ticket(&t), CREATE, aes(V21, "made")));
    // The object belongs to alice, the delegator.
    payload(&f.one("alice", V21, None, GET, get(V21, &id)));
    assert_ne!(status(&f.one("bob", V21, None, GET, get(V21, &id))), 0);
    payload(&f.one("bob", V21, by_ticket(&t), QUERY, vec![]));
    let located = f.one("bob", V21, by_ticket(&t), LOCATE, locate_name("made"));
    assert!(payload(&located).get(UNIQUE_IDENTIFIER).is_some());
    // Never-delegated operations stay refused.
    let cancel = vec![Node::bytes(ASYNCHRONOUS_CORRELATION_VALUE, vec![1])];
    for (op, p) in [(LOGIN, vec![]), (25, cancel)] {
        assert_eq!(
            reason(&f.one("bob", V21, by_ticket(&t), op, p)),
            12,
            "op {op}"
        );
    }
    // The snapshot of alice's allowlist at issue limits the delegate.
    let r = f.send_with(
        "alice",
        Some(&[10, 24, 47]),
        V21,
        vec![],
        None,
        vec![(DELEGATED_LOGIN, rights(vec![right(&[], vec![], None)]))],
    );
    let narrow = ticket(&r[0]);
    payload(&f.one("bob", V21, by_ticket(&narrow), GET, get(V21, &id)));
    assert_eq!(
        reason(&f.one("bob", V21, by_ticket(&narrow), CREATE, aes(V21, "x"))),
        12
    );
}

#[test]
fn the_placeholder_is_the_target_of_an_omitted_identifier() {
    let mut f = Fixture::new();
    let k = f.key("alice", V21, "k");
    let t = delegate(
        &mut f,
        V21,
        vec![
            right(&[LOCATE], vec![], None),
            right(&[GET], objects(V21, &[&k]), None),
        ],
    );
    let r = f.send(
        "bob",
        V21,
        by_ticket(&t),
        vec![(LOCATE, locate_name("k")), (GET, vec![])],
    );
    payload(&r[0]);
    assert!(has_key_material(&r[1]));
    // An Objects-only Right cannot Locate.
    let t = delegate(&mut f, V21, vec![right(&[], objects(V21, &[&k]), None)]);
    assert_eq!(
        reason(&f.one("bob", V21, by_ticket(&t), LOCATE, locate_name("k"))),
        12
    );
    payload(&f.one("bob", V21, by_ticket(&t), GET, get(V21, &k)));
    // The placeholder of an object outside Objects is no target.
    let other = f.key("alice", V21, "other");
    let t = delegate(
        &mut f,
        V21,
        vec![
            right(&[LOCATE], vec![], None),
            right(&[GET], objects(V21, &[&k]), None),
        ],
    );
    let r = f.send(
        "bob",
        V21,
        by_ticket(&t),
        vec![(LOCATE, locate_name("other")), (GET, vec![])],
    );
    assert_eq!(uid(&r[0]), other);
    assert_eq!(reason(&r[1]), 12);
}

/// A Right with Objects permits only object-scoped operations, so listing
/// another operation in it is refused when the ticket is issued.
#[test]
fn a_right_with_objects_lists_only_object_scoped_operations() {
    let mut f = Fixture::new();
    let k = f.key("alice", V21, "k");
    for op in [LOCATE, CREATE] {
        let r = f.one(
            "alice",
            V21,
            None,
            DELEGATED_LOGIN,
            rights(vec![right(&[GET, op], objects(V21, &[&k]), None)]),
        );
        assert_eq!(reason(&r), 7, "operation {op}");
    }
    delegate(
        &mut f,
        V21,
        vec![right(&[GET, DESTROY], objects(V21, &[&k]), None)],
    );
}

#[test]
fn objects_may_name_the_id_placeholder() {
    let mut f = Fixture::new();
    let r = f.send(
        "alice",
        V21,
        None,
        vec![
            (CREATE, aes(V21, "fresh")),
            (
                DELEGATED_LOGIN,
                rights(vec![right(
                    &[GET],
                    vec![Node::enumeration(UNIQUE_IDENTIFIER, 1)],
                    None,
                )]),
            ),
        ],
    );
    let k = uid(&r[0]);
    let t = ticket(&r[1]);
    payload(&f.one("bob", V21, by_ticket(&t), GET, get(V21, &k)));
    // Draft 3.0 identifier types resolve as in any other request.
    let k3 = f.key("alice", V3, "three");
    let t = delegate(
        &mut f,
        V3,
        vec![right(
            &[GET],
            vec![Node::name_reference(UNIQUE_IDENTIFIER, "three")],
            None,
        )],
    );
    payload(&f.one("bob", V3, by_ticket(&t), GET, get(V3, &k3)));
    // A 2.x delegated ticket does not authenticate 3.0 requests.
    let t = delegate(&mut f, V21, vec![right(&[QUERY], vec![], None)]);
    assert_eq!(reason(&f.one("bob", V3, by_ticket(&t), QUERY, vec![])), 3);
}

#[test]
fn the_presenting_certificate_still_limits_the_delegate() {
    let mut f = Fixture::new();
    let k = f.key("alice", V21, "k");
    let t = delegate(&mut f, V21, vec![right(&[GET, QUERY], vec![], None)]);
    let r = f.send_with(
        "bob",
        Some(&[24]),
        V21,
        vec![],
        by_ticket(&t),
        vec![(GET, get(V21, &k))],
    );
    assert_eq!(reason(&r[0]), 12);
    let r = f.send_with(
        "bob",
        Some(&[24]),
        V21,
        vec![],
        by_ticket(&t),
        vec![(QUERY, vec![])],
    );
    payload(&r[0]);
    // An unlisted certificate never reaches credential evaluation.
    let r = f.send_with(
        "mallory",
        Some(&[]),
        V21,
        vec![],
        by_ticket(&t),
        vec![(QUERY, vec![])],
    );
    assert_eq!(reason(&r[0]), 12);
}

#[test]
fn a_delegated_ticket_must_be_the_only_credential() {
    let mut f = Fixture::new();
    let t = delegate(&mut f, V21, vec![right(&[QUERY], vec![], None)]);
    for other in [password("Fred", "fred"), meter()] {
        assert_eq!(
            reason(&f.one(
                "alice",
                V21,
                auth(vec![ticket_credential(&t), other]),
                QUERY,
                vec![]
            )),
            3
        );
    }
    payload(&f.one("bob", V21, by_ticket(&t), QUERY, vec![]));
}

#[test]
fn a_delegate_may_log_out_only_its_own_ticket() {
    let mut f = Fixture::new();
    let x = f.key("alice", V21, "x");
    let t1 = delegate(&mut f, V21, vec![right(&[DESTROY], vec![], None)]);
    let t2 = delegate(&mut f, V21, vec![right(&[QUERY], vec![], None)]);
    let r = f.send(
        "bob",
        V21,
        by_ticket(&t1),
        vec![(LOGOUT, vec![t2.clone()]), (DESTROY, get(V21, &x))],
    );
    assert_eq!(reason(&r[0]), 12);
    assert_eq!(r.len(), 1, "Stop ends the batch");
    payload(&f.one("alice", V21, None, GET, get(V21, &x)));
    payload(&f.one("carol", V21, by_ticket(&t2), QUERY, vec![]));
    // Its own ticket needs no Right.
    payload(&f.one("bob", V21, by_ticket(&t1), LOGOUT, vec![t1.clone()]));
    assert_eq!(reason(&f.one("bob", V21, by_ticket(&t1), QUERY, vec![])), 3);
    // The issuing principal may log out its delegated tickets; others not.
    assert_eq!(
        reason(&f.one("bob", V21, None, LOGOUT, vec![t2.clone()])),
        0x19
    );
    payload(&f.one("alice", V21, None, LOGOUT, vec![t2.clone()]));
    assert_eq!(
        reason(&f.one("carol", V21, by_ticket(&t2), QUERY, vec![])),
        3
    );
}

#[test]
fn delegated_messages_are_never_deferred() {
    let mut f = Fixture::new();
    let k = f.key("alice", V21, "k");
    let t = delegate(&mut f, V21, vec![right(&[CREATE, GET], vec![], None)]);
    let r = f.send_with(
        "bob",
        None,
        V21,
        asynchronous(MANDATORY),
        by_ticket(&t),
        vec![(GET, get(V21, &k))],
    );
    assert_eq!(r.len(), 1);
    assert_eq!(reason(&r[0]), 7);
    // Optional runs synchronously, even for long-running operations.
    let r = f.send_with(
        "bob",
        None,
        V21,
        asynchronous(OPTIONAL),
        by_ticket(&t),
        vec![(GET, get(V21, &k)), (CREATE, aes(V21, "sync"))],
    );
    assert!(has_key_material(&r[0]));
    uid(&r[1]);
    assert!(!f.engine.asynchronous_pending());
}

#[test]
fn right_budgets_are_charged_and_never_refunded() {
    let mut f = Fixture::new();
    let k = f.key("alice", V21, "k");
    let t = delegate(
        &mut f,
        V21,
        vec![
            right(&[GET], objects(V21, &[&k]), Some(usage_limits(1, 1))),
            right(&[QUERY], vec![], None),
        ],
    );
    let r = f.send_with(
        "bob",
        None,
        V21,
        continuation(UNDO),
        by_ticket(&t),
        vec![(GET, get(V21, &k)), (GET, get(V21, &k))],
    );
    assert_eq!(r.len(), 2);
    assert_eq!(status(&r[0]), 3);
    assert!(has_key_material(&r[0]));
    assert_eq!(reason(&r[1]), 12);
    assert_eq!(
        reason(&f.one("bob", V21, by_ticket(&t), GET, get(V21, &k))),
        12
    );
    // The other Right still works.
    payload(&f.one("bob", V21, by_ticket(&t), QUERY, vec![]));
    // The ticket-level budget covers every Right.
    let t = delegate_with(
        &mut f,
        vec![usage_limits(1, 1)],
        vec![right(&[QUERY], vec![], None)],
    );
    payload(&f.one("bob", V21, by_ticket(&t), QUERY, vec![]));
    assert_eq!(reason(&f.one("bob", V21, by_ticket(&t), QUERY, vec![])), 12);
}
fn delegate_with(f: &mut Fixture, extra: Vec<Node>, r: Vec<Node>) -> Node {
    let mut p = extra;
    p.extend(rights(r));
    ticket(&f.one("alice", V21, None, DELEGATED_LOGIN, p))
}

#[test]
fn the_audit_principal_names_delegator_and_presenter() {
    let mut f = Fixture::new();
    let k = f.key("alice", V21, "k");
    let t = ticket(&f.one(
        "alice",
        V21,
        auth(vec![password("Fred", "fred")]),
        DELEGATED_LOGIN,
        rights(vec![right(&[GET], vec![], None)]),
    ));
    payload(&f.one("bob", V21, by_ticket(&t), GET, get(V21, &k)));
    let principals = f.audit_principals();
    assert_eq!(
        principals.last().unwrap(),
        "alice\0user\0Fred\0delegate\0bob",
        "{principals:?}"
    );
}
