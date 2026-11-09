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

//! Login and Logout in KMIP 2.0 and 2.1 (sections 6.1.29/6.1.30 and
//! 6.1.30/6.1.31), the Ticket credential, Request Count and Usage Limits
//! budgets, and issuance rules shared with draft 3.0 (docs/tickets.md).
#[path = "support/tickets.rs"]
mod support;
use keytend_kmip_server::{protocol::Version, tags::*, ttlv::Node};
use support::*;

#[test]
fn two_x_login_needs_no_credentials_and_binds_principal_and_edition() {
    for v in [V20, V21] {
        let mut f = Fixture::new();
        let ticket = f.login(v, None, vec![]);
        assert_eq!(
            ticket
                .required(TICKET_VALUE)
                .unwrap()
                .byte_string()
                .unwrap()
                .len(),
            32
        );
        assert_eq!(
            ticket.required(TICKET_TYPE).unwrap().number().unwrap(),
            1,
            "Ticket Type Login"
        );
        // The ticket authenticates as the principal: alice sees the key.
        let item = f.one("alice", v, by_ticket(&ticket), CREATE, aes(v, "k"));
        let id = uid(&item);
        payload(&f.one("alice", v, None, GET, get(v, &id)));
        // Another principal, or another major edition: Authentication Not
        // Successful.
        assert_eq!(
            reason(&f.one("bob", v, by_ticket(&ticket), QUERY, vec![])),
            3
        );
        assert_eq!(
            reason(&f.one("alice", V3, by_ticket(&ticket), QUERY, vec![])),
            3
        );
        // Both 2.x editions share a ticket.
        let other = if v == V20 { V21 } else { V20 };
        payload(&f.one("alice", other, by_ticket(&ticket), QUERY, vec![]));
    }
    // A 3.0 ticket does not authenticate 2.x requests.
    let mut f = Fixture::new();
    let ticket = f.login(V3, auth(vec![password("Fred", "fred")]), vec![]);
    assert_eq!(
        reason(&f.one("alice", V21, by_ticket(&ticket), QUERY, vec![])),
        3
    );
}

#[test]
fn users_file_and_credential_identity_tickets_keep_the_login_identity() {
    let mut f = Fixture::new();
    let fred = auth(vec![password("Fred", "fred")]);
    let ticket = f.login(V21, fred.clone(), vec![]);
    // A wrong password at Login fails the message.
    assert_eq!(
        reason(&f.one(
            "alice",
            V21,
            auth(vec![password("Fred", "x")]),
            LOGIN,
            vec![]
        )),
        3
    );
    // The ticket names Fred: it combines with Fred's password, not Barney's.
    payload(&f.one(
        "alice",
        V21,
        auth(vec![ticket_credential(&ticket), password("Fred", "fred")]),
        QUERY,
        vec![],
    ));
    assert_eq!(
        reason(&f.one(
            "alice",
            V21,
            auth(vec![
                ticket_credential(&ticket),
                password("Barney", "barney")
            ]),
            QUERY,
            vec![],
        )),
        3
    );
    // The audit chain records Fred for requests made with the ticket.
    let item = f.one("alice", V21, by_ticket(&ticket), CREATE, aes(V21, "k"));
    uid(&item);
    assert!(
        f.audit_principals().last().unwrap() == "alice\0user\0Fred",
        "{:?}",
        f.audit_principals()
    );

    // Under credential identity the ticket owns objects as Fred.
    let mut f = Fixture::new();
    f.engine.use_credential_identity("alice");
    let ticket = f.login(V21, fred.clone(), vec![]);
    let id = uid(&f.one("alice", V21, by_ticket(&ticket), CREATE, aes(V21, "k")));
    payload(&f.one("alice", V21, fred.clone(), GET, get(V21, &id)));
    assert_ne!(status(&f.one("alice", V21, None, GET, get(V21, &id))), 0);
    assert_ne!(
        status(&f.one(
            "alice",
            V21,
            auth(vec![password("Barney", "barney")]),
            GET,
            get(V21, &id)
        )),
        0
    );
    // A principal-level ticket under credential identity owns as the
    // principal.
    let bare = f.login(V21, None, vec![]);
    let id = uid(&f.one("alice", V21, by_ticket(&bare), CREATE, aes(V21, "p")));
    payload(&f.one("alice", V21, None, GET, get(V21, &id)));
}

#[test]
fn device_only_login_succeeds_and_tickets_never_renew_themselves() {
    let mut f = Fixture::new();
    f.engine.use_credential_identity("alice");
    let ticket = f.login(V21, auth(vec![meter()]), vec![]);
    let id = uid(&f.one("alice", V21, by_ticket(&ticket), CREATE, aes(V21, "m")));
    payload(&f.one("alice", V21, auth(vec![meter()]), GET, get(V21, &id)));
    // A request authenticated by a ticket cannot obtain another ticket.
    assert_eq!(
        reason(&f.one("alice", V21, by_ticket(&ticket), LOGIN, vec![])),
        12
    );
    assert_eq!(
        reason(&f.one(
            "alice",
            V21,
            by_ticket(&ticket),
            DELEGATED_LOGIN,
            rights(vec![right(&[QUERY], vec![], None)])
        )),
        12
    );
    // Not even together with a password of the same user.
    let fred = f.login(V21, auth(vec![password("Fred", "fred")]), vec![]);
    assert_eq!(
        reason(&f.one(
            "alice",
            V21,
            auth(vec![ticket_credential(&fred), password("Fred", "fred")]),
            LOGIN,
            vec![]
        )),
        12
    );
}

#[test]
fn request_count_limits_redemptions() {
    let mut f = Fixture::new();
    let ticket = f.login(V21, None, vec![Node::int(REQUEST_COUNT, 2)]);
    for _ in 0..2 {
        payload(&f.one("alice", V21, by_ticket(&ticket), QUERY, vec![]));
    }
    assert_eq!(
        reason(&f.one("alice", V21, by_ticket(&ticket), QUERY, vec![])),
        3
    );
    // An exhausted ticket still exists until Logout.
    payload(&f.one("alice", V21, None, LOGOUT, vec![ticket.clone()]));
    for count in [0, -1] {
        assert_eq!(
            reason(&f.one(
                "alice",
                V21,
                None,
                LOGIN,
                vec![Node::int(REQUEST_COUNT, count)]
            )),
            7
        );
    }
}

#[test]
fn an_exhausted_ticket_still_runs_its_queued_batch_until_logout() {
    let mut f = Fixture::new();
    let ticket = f.login(V21, None, vec![Node::int(REQUEST_COUNT, 1)]);
    let r = f.send_with(
        "alice",
        None,
        V21,
        asynchronous(MANDATORY),
        by_ticket(&ticket),
        vec![(CREATE, aes(V21, "queued"))],
    );
    assert_eq!(status(&r[0]), 2, "Pending");
    let acv = r[0]
        .required(ASYNCHRONOUS_CORRELATION_VALUE)
        .unwrap()
        .clone();
    // The Request Count is spent: no new message may present the ticket.
    assert_eq!(
        reason(&f.one("alice", V21, by_ticket(&ticket), QUERY, vec![])),
        3
    );
    // The batch it authenticated still runs.
    payload(&f.one("alice", V21, None, PROCESS, vec![acv.clone()]));
    let polled = f.one("alice", V21, None, POLL, vec![acv]);
    uid(&polled);

    // A logged-out ticket's queued batch no longer runs.
    let ticket = f.login(V21, None, vec![]);
    let r = f.send_with(
        "alice",
        None,
        V21,
        asynchronous(MANDATORY),
        by_ticket(&ticket),
        vec![(CREATE, aes(V21, "orphan"))],
    );
    let acv = r[0]
        .required(ASYNCHRONOUS_CORRELATION_VALUE)
        .unwrap()
        .clone();
    payload(&f.one("alice", V21, None, LOGOUT, vec![ticket]));
    f.one("alice", V21, None, PROCESS, vec![acv.clone()]);
    let polled = f.one("alice", V21, None, POLL, vec![acv]);
    assert_eq!(reason(&polled), 3);
    let located = f.one("alice", V21, None, LOCATE, locate_name("orphan"));
    assert!(payload(&located).get(UNIQUE_IDENTIFIER).is_none());
}

#[test]
fn lease_and_usage_limits_are_validated() {
    let mut f = Fixture::new();
    let fred = auth(vec![password("Fred", "fred")]);
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let limits = |total: i64, count: i64, unit: u32| {
        Node::structure(
            USAGE_LIMITS,
            vec![
                Node::long(USAGE_LIMITS_TOTAL, total),
                Node::long(USAGE_LIMITS_COUNT, count),
                Node::enumeration(USAGE_LIMITS_UNIT, unit),
            ],
        )
    };
    for v in [V20, V21, V3] {
        // Draft 3.0 Login still needs a password; 2.x needs nothing.
        let credentials = if v.0 >= 3 { fred.clone() } else { None };
        let cases: Vec<(Vec<Node>, u32)> = vec![
            (vec![Node::interval(LEASE_TIME, 0)], 7),
            (vec![Node::interval(LEASE_TIME, 86_401)], 7),
            (vec![Node::date(LEASE_TIME, now - 10)], 7),
            (vec![Node::date(LEASE_TIME, now + 86_500)], 7),
            (vec![limits(10, 1, 1)], 8),
            (vec![limits(1, 2, 2)], 7),
            (vec![limits(1, 0, 2)], 7),
            (vec![limits(1, 1, 9)], 7),
            (vec![Node::structure(USAGE_LIMITS, vec![])], 7),
            (
                vec![Node::structure(
                    USAGE_LIMITS,
                    vec![
                        Node::long(USAGE_LIMITS_TOTAL, 1),
                        Node::enumeration(USAGE_LIMITS_UNIT, 2),
                    ],
                )],
                7,
            ),
        ];
        for (p, expected) in cases {
            assert_eq!(
                reason(&f.one("alice", v, credentials.clone(), LOGIN, p.clone())),
                expected,
                "{}.{} {}",
                v.0,
                v.1,
                serde_json::to_string(&p).unwrap()
            );
        }
        for p in [
            vec![Node::interval(LEASE_TIME, 86_400)],
            vec![Node::date(LEASE_TIME, now + 3600)],
            vec![usage_limits(5, 5)],
            vec![usage_limits(5, 2), Node::int(REQUEST_COUNT, 3)],
        ] {
            ticket(&f.one("alice", v, credentials.clone(), LOGIN, p));
        }
    }
}

#[test]
fn sixty_fifth_live_ticket_is_a_server_limit() {
    let mut f = Fixture::new();
    let tickets = (0..64)
        .map(|_| f.login(V21, None, vec![]))
        .collect::<Vec<_>>();
    assert_eq!(reason(&f.one("alice", V21, None, LOGIN, vec![])), 0x3a);
    // Another principal has its own allowance.
    ticket(&f.one("bob", V21, None, LOGIN, vec![]));
    // Logout frees a slot.
    payload(&f.one("alice", V21, None, LOGOUT, vec![tickets[0].clone()]));
    f.login(V21, None, vec![]);
    // Repeated Login and Logout keeps the live set bounded.
    let mut live = tickets[1..].to_vec();
    for _ in 0..100 {
        let oldest = live.remove(0);
        payload(&f.one("alice", V21, None, LOGOUT, vec![oldest]));
        live.push(f.login(V21, None, vec![]));
    }
    assert_eq!(reason(&f.one("alice", V21, None, LOGIN, vec![])), 0x3a);
}

#[test]
fn undo_never_refunds_ticket_usage() {
    for v in [V21, V3] {
        let mut f = Fixture::new();
        let id = f.key("alice", v, "k");
        let credentials = if v.0 >= 3 {
            auth(vec![password("Fred", "fred")])
        } else {
            None
        };
        let ticket = f.login(v, credentials, vec![usage_limits(1, 1)]);
        let r = f.send_with(
            "alice",
            None,
            v,
            continuation(UNDO),
            by_ticket(&ticket),
            vec![(GET, get(v, &id)), (GET, get(v, &id)), (GET, get(v, &id))],
        );
        // Exactly one item carries key material, as Operation Undone.
        assert_eq!(r.len(), 2);
        assert_eq!(status(&r[0]), 3);
        assert!(has_key_material(&r[0]));
        assert_eq!(reason(&r[1]), 12);
        assert!(!has_key_material(&r[1]));
        // The spent unit stays spent after the rollback.
        assert_eq!(
            reason(&f.one("alice", v, by_ticket(&ticket), GET, get(v, &id))),
            12
        );
    }
}

#[test]
fn a_failed_item_still_consumes_usage() {
    let mut f = Fixture::new();
    let id = f.key("alice", V21, "k");
    let ticket = f.login(V21, None, vec![usage_limits(2, 2)]);
    assert_ne!(
        status(&f.one("alice", V21, by_ticket(&ticket), GET, get(V21, "missing"))),
        0
    );
    payload(&f.one("alice", V21, by_ticket(&ticket), GET, get(V21, &id)));
    assert_eq!(
        reason(&f.one("alice", V21, by_ticket(&ticket), GET, get(V21, &id))),
        12
    );
}

#[test]
fn an_undone_logout_revives_the_ticket_but_not_its_budget() {
    let mut f = Fixture::new();
    let id = f.key("alice", V21, "k");
    let ticket = f.login(V21, None, vec![usage_limits(2, 2)]);
    let r = f.send_with(
        "alice",
        None,
        V21,
        continuation(UNDO),
        by_ticket(&ticket),
        vec![
            (GET, get(V21, &id)),
            (LOGOUT, vec![ticket.clone()]),
            (GET, get(V21, &id)),
        ],
    );
    assert_eq!(r.len(), 3);
    assert_eq!(status(&r[0]), 3);
    assert_eq!(status(&r[1]), 3);
    // Items after the Logout are no longer authenticated.
    assert_eq!(reason(&r[2]), 12);
    // The ticket is back (it redeems), but both units are spent.
    assert_eq!(
        reason(&f.one("alice", V21, by_ticket(&ticket), GET, get(V21, &id))),
        12
    );
    payload(&f.one("alice", V21, None, LOGOUT, vec![ticket.clone()]));
}

#[test]
fn logout_ends_a_ticket_at_once() {
    let mut f = Fixture::new();
    let id = f.key("alice", V21, "k");
    let ticket = f.login(V21, None, vec![]);
    // Unknown, malformed and foreign tickets: Invalid Ticket.
    let unknown = Node::structure(
        TICKET,
        vec![
            Node::enumeration(TICKET_TYPE, 1),
            Node::bytes(TICKET_VALUE, vec![0; 32]),
        ],
    );
    assert_eq!(
        reason(&f.one("alice", V21, None, LOGOUT, vec![unknown])),
        0x19
    );
    assert_eq!(
        reason(&f.one("bob", V21, None, LOGOUT, vec![ticket.clone()])),
        0x19
    );
    assert_eq!(reason(&f.one("alice", V21, None, LOGOUT, vec![])), 7);
    // [Logout(T), Get K] authenticated by T: the Get is refused.
    let r = f.send(
        "alice",
        V21,
        by_ticket(&ticket),
        vec![(LOGOUT, vec![ticket.clone()]), (GET, get(V21, &id))],
    );
    payload(&r[0]);
    assert_eq!(reason(&r[1]), 12);
    assert_eq!(
        reason(&f.one("alice", V21, by_ticket(&ticket), QUERY, vec![])),
        3
    );
    assert_eq!(
        reason(&f.one("alice", V21, None, LOGOUT, vec![ticket])),
        0x19
    );
}

#[test]
fn ticket_issuance_is_never_asynchronous() {
    let mut f = Fixture::new();
    for (op, p) in [
        (LOGIN, vec![]),
        (DELEGATED_LOGIN, rights(vec![right(&[QUERY], vec![], None)])),
    ] {
        let r = f.send_with(
            "alice",
            None,
            V21,
            asynchronous(MANDATORY),
            None,
            vec![(QUERY, vec![]), (op, p.clone())],
        );
        assert_eq!(r.len(), 1);
        assert_eq!(reason(&r[0]), 7, "op {op}");
        let r = f.send_with(
            "alice",
            None,
            V21,
            asynchronous(OPTIONAL),
            None,
            vec![(op, p)],
        );
        ticket(&r[0]);
    }
    assert!(!f.engine.asynchronous_pending());
}

#[test]
fn query_lists_login_logout_and_delegated_login_from_2_0() {
    let mut f = Fixture::new();
    let operations = |f: &mut Fixture, v: Version| -> Vec<u32> {
        let item = f.one(
            "alice",
            v,
            None,
            QUERY,
            vec![Node::enumeration(QUERY_FUNCTION, 1)],
        );
        payload(&item)
            .all(OPERATION)
            .map(|n| n.number().unwrap())
            .collect()
    };
    for v in [V20, V21, V3] {
        let ops = operations(&mut f, v);
        for op in [LOGIN, LOGOUT, DELEGATED_LOGIN] {
            assert!(ops.contains(&op), "{}.{} op {op}", v.0, v.1);
        }
    }
    let ops = operations(&mut f, V14);
    assert!(!ops.contains(&LOGIN) && !ops.contains(&DELEGATED_LOGIN));
    assert_eq!(reason(&f.one("alice", V14, None, LOGIN, vec![])), 5);
    // The certificate policy gates Login like every other operation.
    let r = f.send_with(
        "alice",
        Some(&[24]),
        V21,
        vec![],
        None,
        vec![(LOGIN, vec![])],
    );
    assert_eq!(reason(&r[0]), 12);
    // 1.x does not define the Ticket credential type.
    let ticket = f.login(V21, None, vec![]);
    assert_eq!(
        reason(&f.one("alice", V14, by_ticket(&ticket), QUERY, vec![])),
        7
    );
}
