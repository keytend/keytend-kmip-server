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

//! Draft 3.0 System Objects, request-header credentials, Login tickets, Get
//! Constraints, Group Link and Obliterate, including version gating.
use keytend_kmip_server::{
    credentials::{PasswordVerifier, PolicyUser},
    protocol::{Engine, Version},
    store::Store,
    tags::*,
    ttlv::{Node, Value},
};

const V3: Version = Version(3, 0);
const V21: Version = Version(2, 1);

struct Fixture {
    dir: tempfile::TempDir,
    engine: Engine,
}
impl Fixture {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let key = dir.path().join("master");
        std::fs::write(&key, [7; 32]).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        let engine = Self::open(&dir);
        Self { dir, engine }
    }
    fn open(dir: &tempfile::TempDir) -> Engine {
        let store =
            Store::open(&dir.path().join("keys.sqlite"), &dir.path().join("master")).unwrap();
        let mut engine = Engine::new(store, true);
        engine
            .add_policy_users(
                "alice",
                vec![PolicyUser {
                    username: "administrator".into(),
                    password_scrypt: PasswordVerifier::new(b"password").unwrap(),
                    administrator: true,
                    hashed_password: None,
                    one_time_password: None,
                }],
            )
            .unwrap();
        engine
    }
    fn restart(&mut self) {
        self.engine = Self::open(&self.dir);
    }
    fn call(&mut self, owner: &str, v: Version, auth: Option<Node>, op: u32, p: Vec<Node>) -> Node {
        self.engine
            .process(owner, &request(v, auth, vec![(op, p)]))
            .unwrap()
    }
}
fn request(v: Version, auth: Option<Node>, items: Vec<(u32, Vec<Node>)>) -> Node {
    let mut header = vec![v.node()];
    if v.0 < 3 {
        header.push(Node::int(BATCH_COUNT, items.len() as i32));
    }
    header.extend(auth);
    let mut fields = vec![Node::structure(REQUEST_HEADER, header)];
    let many = items.len() > 1;
    fields.extend(items.into_iter().enumerate().map(|(i, (op, p))| {
        let mut item = vec![
            Node::enumeration(OPERATION, op),
            Node::structure(REQUEST_PAYLOAD, p),
        ];
        if many && v.0 < 3 {
            item.push(Node::bytes(UNIQUE_BATCH_ITEM_ID, vec![i as u8]));
        }
        Node::structure(BATCH_ITEM, item)
    }));
    Node::structure(REQUEST_MESSAGE, fields)
}
fn password(user: &str, password: &str) -> Option<Node> {
    Some(Node::structure(
        AUTHENTICATION,
        vec![Node::structure(
            CREDENTIAL,
            vec![
                Node::enumeration(CREDENTIAL_TYPE, 1),
                Node::structure(
                    CREDENTIAL_VALUE,
                    vec![Node::text(USERNAME, user), Node::text(PASSWORD, password)],
                ),
            ],
        )],
    ))
}
fn admin() -> Option<Node> {
    password("administrator", "password")
}
fn ticket_auth(ticket: &Node) -> Option<Node> {
    Some(Node::structure(
        AUTHENTICATION,
        vec![Node::structure(
            CREDENTIAL,
            vec![
                Node::enumeration(CREDENTIAL_TYPE, 6),
                Node::structure(CREDENTIAL_VALUE, vec![ticket.clone()]),
            ],
        )],
    ))
}
fn item(n: &Node) -> &Node {
    n.required(BATCH_ITEM).unwrap()
}
fn payload(n: &Node) -> &Node {
    let item = item(n);
    assert_eq!(
        item.required(RESULT_STATUS).unwrap().number().unwrap(),
        0,
        "reason {:?} {:?}",
        item.get(RESULT_REASON).and_then(|n| n.number().ok()),
        item.get(RESULT_MESSAGE).and_then(|n| n.string().ok())
    );
    item.required(RESPONSE_PAYLOAD).unwrap()
}
fn reason(n: &Node) -> u32 {
    item(n).required(RESULT_REASON).unwrap().number().unwrap()
}
fn uid(n: &Node) -> String {
    payload(n)
        .required(UNIQUE_IDENTIFIER)
        .unwrap()
        .identifier_text()
        .unwrap()
        .to_owned()
}
fn password_credential(f: &mut Fixture, auth: Option<Node>, secret: &str) -> Node {
    f.call(
        "alice",
        V3,
        auth,
        63,
        vec![
            Node::enumeration(CREDENTIAL_TYPE, 7),
            Node::structure(ATTRIBUTES, vec![]),
            Node::structure(PASSWORD_CREDENTIAL, vec![Node::text(PASSWORD, secret)]),
        ],
    )
}
fn create_user(f: &mut Fixture, auth: Option<Node>, name: &str, links: &[&str]) -> Node {
    let mut attrs = vec![Node::text(NAME, name)];
    attrs.extend(links.iter().map(|id| Node::reference(CREDENTIAL_LINK, *id)));
    f.call(
        "alice",
        V3,
        auth,
        62,
        vec![Node::structure(ATTRIBUTES, attrs)],
    )
}
fn create_group(f: &mut Fixture, owner: &str, auth: Option<Node>, name: &str) -> Node {
    f.call(
        owner,
        V3,
        auth,
        60,
        vec![Node::structure(ATTRIBUTES, vec![Node::text(NAME, name)])],
    )
}
fn secret_attrs(extra: Vec<Node>) -> Vec<Node> {
    let mut attrs = vec![Node::int(CRYPTOGRAPHIC_USAGE_MASK, 4)];
    attrs.extend(extra);
    attrs
}
fn register_secret(f: &mut Fixture, v: Version, extra: Vec<Node>) -> Node {
    f.call(
        "alice",
        v,
        None,
        3,
        vec![
            Node::enumeration(OBJECT_TYPE, 7),
            Node::structure(ATTRIBUTES, secret_attrs(extra)),
            Node::structure(
                SECRET_DATA,
                vec![
                    Node::enumeration(SECRET_DATA_TYPE, 1),
                    Node::structure(
                        KEY_BLOCK,
                        vec![
                            Node::enumeration(KEY_FORMAT_TYPE, 1),
                            Node::structure(KEY_VALUE, vec![Node::bytes(KEY_MATERIAL, [42; 16])]),
                        ],
                    ),
                ],
            ),
        ],
    )
}
fn certificate_der() -> Vec<u8> {
    use openssl::{asn1::Asn1Time, hash::MessageDigest, pkey::PKey, rsa::Rsa, x509::*};
    let key = PKey::from_rsa(Rsa::generate(2048).unwrap()).unwrap();
    let mut name = X509NameBuilder::new().unwrap();
    name.append_entry_by_text("CN", "credential").unwrap();
    let name = name.build();
    let mut b = X509Builder::new().unwrap();
    b.set_version(2).unwrap();
    b.set_subject_name(&name).unwrap();
    b.set_issuer_name(&name).unwrap();
    b.set_pubkey(&key).unwrap();
    b.set_not_before(&Asn1Time::days_from_now(0).unwrap())
        .unwrap();
    b.set_not_after(&Asn1Time::days_from_now(1).unwrap())
        .unwrap();
    b.sign(&key, MessageDigest::sha256()).unwrap();
    b.build().to_der().unwrap()
}

#[test]
fn credentials_users_and_header_authentication_follow_the_draft() {
    let mut f = Fixture::new();
    // Profiles 3.0 traces BL-M-15..19: the operator-provisioned administrator
    // creates password and certificate credentials, then users linking them.
    let pw = uid(&password_credential(&mut f, admin(), "password1"));
    let der = certificate_der();
    let cert = uid(&f.call(
        "alice",
        V3,
        admin(),
        63,
        vec![
            Node::enumeration(CREDENTIAL_TYPE, 8),
            Node::structure(ATTRIBUTES, vec![]),
            Node::structure(
                CERTIFICATE,
                vec![
                    Node::enumeration(CERTIFICATE_TYPE, 1),
                    Node::bytes(CERTIFICATE_VALUE, der.clone()),
                ],
            ),
        ],
    ));
    uid(&create_user(&mut f, admin(), "test-user", &[&cert, &pw]));
    // The new user authenticates with its own password, not another one,
    // but only an administrator creates System Objects (system.rs).
    payload(&f.call("alice", V3, password("test-user", "password1"), 24, vec![]));
    assert_eq!(
        reason(&create_group(
            &mut f,
            "alice",
            password("test-user", "password1"),
            "g1",
        )),
        12
    );
    uid(&create_group(&mut f, "alice", admin(), "g1"));
    for auth in [
        password("test-user", "password"),
        password("administrator", "password1"),
        password("nobody", "password1"),
        password("test-user", ""),
    ] {
        assert_eq!(reason(&create_group(&mut f, "alice", auth, "g2")), 3);
    }
    // Credentials bind to the certificate principal: bob cannot use them.
    assert_eq!(reason(&create_group(&mut f, "bob", admin(), "g3")), 3);
    assert_eq!(
        reason(&create_group(
            &mut f,
            "bob",
            password("test-user", "password1"),
            "g3"
        )),
        3
    );
    // System Objects require a verified credential (spec section 2.1).
    assert_eq!(reason(&password_credential(&mut f, None, "x")), 12);
    assert_eq!(reason(&create_user(&mut f, None, "u", &[&pw])), 12);
    assert_eq!(reason(&create_group(&mut f, "alice", None, "g4")), 12);
    // Names are unique per principal and type, including policy users.
    assert_eq!(
        reason(&create_user(&mut f, admin(), "test-user", &[&pw])),
        0x35
    );
    assert_eq!(
        reason(&create_user(&mut f, admin(), "administrator", &[&pw])),
        0x35
    );
    assert_eq!(reason(&create_group(&mut f, "alice", admin(), "g1")), 0x35);
    // A user needs a Credential Link to a credential of this principal.
    assert_eq!(reason(&create_user(&mut f, admin(), "u2", &[])), 7);
    let key = uid(&register_secret(&mut f, V3, vec![]));
    assert_eq!(reason(&create_user(&mut f, admin(), "u2", &[&key])), 0x2d);
    assert_eq!(
        reason(&create_user(&mut f, admin(), "u2", &["missing"])),
        0x2d
    );
    // Unsupported or unverifiable credential forms are refused, not ignored.
    let presalted = f.call(
        "alice",
        V3,
        admin(),
        63,
        vec![
            Node::enumeration(CREDENTIAL_TYPE, 7),
            Node::structure(ATTRIBUTES, vec![]),
            Node::structure(
                PASSWORD_CREDENTIAL,
                vec![Node::bytes(SALTED_PASSWORD, [1; 32])],
            ),
        ],
    );
    assert_eq!(reason(&presalted), 8);
    let device = f.call(
        "alice",
        V3,
        admin(),
        63,
        vec![
            Node::enumeration(CREDENTIAL_TYPE, 2),
            Node::structure(ATTRIBUTES, vec![]),
            Node::structure(DEVICE_CREDENTIAL, vec![]),
        ],
    );
    // Draft 3.0 2.1.3.2: "The client SHALL provide at least one field"
    // (Device credentials: tests/system_credentials_v3.rs).
    assert_eq!(reason(&device), 7);
    let bad_cert = f.call(
        "alice",
        V3,
        admin(),
        63,
        vec![
            Node::enumeration(CREDENTIAL_TYPE, 8),
            Node::structure(ATTRIBUTES, vec![]),
            Node::structure(
                CERTIFICATE,
                vec![
                    Node::enumeration(CERTIFICATE_TYPE, 1),
                    Node::bytes(CERTIFICATE_VALUE, der[..der.len() - 1].to_vec()),
                ],
            ),
        ],
    );
    assert_eq!(reason(&bad_cert), 7);
    // Only the scrypt verifier is stored, and it survives a restart.
    f.restart();
    let store = Store::open(
        &f.dir.path().join("keys.sqlite"),
        &f.dir.path().join("master"),
    )
    .unwrap();
    let stored = store.get("alice\0system", &pw).unwrap().unwrap();
    assert!(!stored.material.windows(9).any(|w| w == b"password1"));
    assert!(store.get("alice", &pw).unwrap().is_none());
    drop(store);
    payload(&f.call("alice", V3, password("test-user", "password1"), 24, vec![]));
}

#[test]
fn authentication_and_system_operations_are_draft_only() {
    let mut f = Fixture::new();
    // KMIP 2.1 verifies header credentials too, but keeps rejecting the
    // draft operations.
    payload(&f.call("alice", V21, admin(), 24, vec![]));
    assert_eq!(
        reason(&f.call("alice", V21, password("administrator", "x"), 24, vec![])),
        3
    );
    // Login and Logout are 2.x operations too and need no credentials
    // there (tickets.rs).
    payload(&f.call("alice", V21, None, 45, vec![]));
    assert_eq!(reason(&f.call("alice", V21, None, 46, vec![])), 7);
    // Get Constraints is a 2.1 operation too, for the server-wide set
    // (constraints.rs).
    payload(&f.call("alice", V21, None, 56, vec![]));
    // Draft 3.0 System Objects and Obliterate.
    for op in [60, 61, 62, 63] {
        assert_eq!(
            reason(&f.call("alice", V21, None, op, vec![])),
            5,
            "op {op}"
        );
    }
    let query = |f: &mut Fixture, v: Version, function: u32| -> Vec<u32> {
        let r = f.call(
            "alice",
            v,
            None,
            24,
            vec![Node::enumeration(QUERY_FUNCTION, function)],
        );
        payload(&r)
            .children()
            .unwrap()
            .iter()
            .map(|n| n.number().unwrap())
            .collect()
    };
    let ops = query(&mut f, V3, 1);
    for op in [45, 46, 56, 60, 61, 62, 63] {
        assert!(ops.contains(&op), "op {op}");
    }
    // Set Constraints is offered (tests/constraints.rs).
    assert!(ops.contains(&55));
    assert!(!query(&mut f, V21, 1).contains(&60));
    assert!(query(&mut f, V3, 2).contains(&11));
    assert!(!query(&mut f, V21, 2).contains(&11));
    // Get Constraints reports the empty set until Set Constraints is used.
    let r = f.call("alice", V3, None, 56, vec![]);
    assert!(payload(&r).required(CONSTRAINTS).unwrap() == &Node::structure(CONSTRAINTS, vec![]));
    // Malformed or unsupported header credentials fail the whole message.
    let empty = Some(Node::structure(AUTHENTICATION, vec![]));
    assert_eq!(reason(&f.call("alice", V3, empty, 24, vec![])), 7);
    let device = Some(Node::structure(
        AUTHENTICATION,
        vec![Node::structure(
            CREDENTIAL,
            vec![
                Node::enumeration(CREDENTIAL_TYPE, 2),
                Node::structure(CREDENTIAL_VALUE, vec![]),
            ],
        )],
    ));
    // A Device credential needs at least one field (section 2.1.2).
    assert_eq!(reason(&f.call("alice", V3, device, 24, vec![])), 7);
    assert_eq!(
        reason(&f.call("alice", V3, password("administrator", "x"), 24, vec![])),
        3
    );
    // Query without credentials still works; with valid ones too.
    payload(&f.call("alice", V3, admin(), 24, vec![]));
    // A verified device names no user, so it cannot create System Objects.
    f.engine
        .add_policy_devices(
            "alice",
            vec![keytend_kmip_server::credentials::PolicyDevice {
                name: "meter".into(),
                device_serial_number: Some("serial".into()),
                device_identifier: None,
                network_identifier: None,
                machine_identifier: None,
                media_identifier: None,
                password_scrypt: PasswordVerifier::new(b"device").unwrap(),
            }],
        )
        .unwrap();
    let meter = Some(Node::structure(
        AUTHENTICATION,
        vec![Node::structure(
            CREDENTIAL,
            vec![
                Node::enumeration(CREDENTIAL_TYPE, 2),
                Node::structure(
                    CREDENTIAL_VALUE,
                    vec![
                        Node::text(DEVICE_SERIAL_NUMBER, "serial"),
                        Node::text(PASSWORD, "device"),
                    ],
                ),
            ],
        )],
    ));
    payload(&f.call("alice", V3, meter.clone(), 24, vec![]));
    assert_eq!(reason(&password_credential(&mut f, meter, "pw")), 12);
}

#[test]
fn login_tickets_are_bound_bounded_and_revocable() {
    let mut f = Fixture::new();
    let login =
        |f: &mut Fixture, auth: Option<Node>, p: Vec<Node>| f.call("alice", V3, auth, 45, p);
    assert_eq!(reason(&login(&mut f, None, vec![])), 12);
    let r = login(&mut f, admin(), vec![Node::int(REQUEST_COUNT, 2)]);
    let ticket = payload(&r).required(TICKET).unwrap().clone();
    assert_eq!(
        ticket
            .required(TICKET_VALUE)
            .unwrap()
            .byte_string()
            .unwrap()
            .len(),
        32
    );
    uid(&create_group(&mut f, "alice", ticket_auth(&ticket), "t1"));
    // A ticket cannot mint another ticket, and other principals cannot use it.
    assert_eq!(reason(&login(&mut f, ticket_auth(&ticket), vec![])), 12);
    assert_eq!(
        reason(&create_group(&mut f, "bob", ticket_auth(&ticket), "t2")),
        3
    );
    // The Request Count of 2 is now spent.
    assert_eq!(
        reason(&create_group(&mut f, "alice", ticket_auth(&ticket), "t3")),
        3
    );
    let r = login(&mut f, admin(), vec![]);
    let ticket = payload(&r).required(TICKET).unwrap().clone();
    assert_eq!(
        reason(&f.call("bob", V3, None, 46, vec![ticket.clone()])),
        0x19
    );
    payload(&f.call("alice", V3, None, 46, vec![ticket.clone()]));
    assert_eq!(
        reason(&create_group(&mut f, "alice", ticket_auth(&ticket), "t4")),
        3
    );
    assert_eq!(reason(&f.call("alice", V3, None, 46, vec![ticket])), 0x19);
    for p in [
        vec![Node::interval(LEASE_TIME, 0)],
        vec![Node::interval(LEASE_TIME, 86_401)],
        vec![Node::int(REQUEST_COUNT, 0)],
        vec![Node::structure(USAGE_LIMITS, vec![])],
    ] {
        assert_ne!(
            item(&login(&mut f, admin(), p))
                .required(RESULT_STATUS)
                .unwrap()
                .number()
                .unwrap(),
            0
        );
    }
    // Usage Limits with Unit Object are supported (tickets.rs): one unit
    // per batch item executed under the ticket.
    let r = login(
        &mut f,
        admin(),
        vec![Node::structure(
            USAGE_LIMITS,
            vec![
                Node::long(USAGE_LIMITS_TOTAL, 1),
                Node::long(USAGE_LIMITS_COUNT, 1),
                Node::enumeration(USAGE_LIMITS_UNIT, 2),
            ],
        )],
    );
    let limited = payload(&r).required(TICKET).unwrap().clone();
    payload(&f.call("alice", V3, ticket_auth(&limited), 24, vec![]));
    assert_eq!(
        reason(&f.call("alice", V3, ticket_auth(&limited), 24, vec![])),
        12
    );
    // An undone Login leaves no usable ticket.
    let mut undo = request(
        V3,
        admin(),
        vec![
            (45, vec![]),
            (61, vec![Node::identifier(UNIQUE_IDENTIFIER, "missing")]),
        ],
    );
    if let Value::Structure(fields) = &mut undo.value
        && let Value::Structure(header) = &mut fields[0].value
    {
        header.push(Node::enumeration(BATCH_ERROR_CONTINUATION_OPTION, 3));
    }
    let r = f.engine.process("alice", &undo).unwrap();
    let undone = r.all(BATCH_ITEM).next().unwrap();
    assert_eq!(undone.required(RESULT_STATUS).unwrap().number().unwrap(), 3);
    let ticket = undone
        .required(RESPONSE_PAYLOAD)
        .unwrap()
        .required(TICKET)
        .unwrap()
        .clone();
    assert_eq!(
        reason(&create_group(&mut f, "alice", ticket_auth(&ticket), "t6")),
        3
    );
    // Tickets live in memory only.
    let r = login(&mut f, admin(), vec![]);
    let ticket = payload(&r).required(TICKET).unwrap().clone();
    f.restart();
    assert_eq!(
        reason(&create_group(&mut f, "alice", ticket_auth(&ticket), "t5")),
        3
    );
}

#[test]
fn obliterate_removes_objects_and_keeps_the_store_authenticated() {
    let mut f = Fixture::new();
    // Many records exercise every authenticated-index removal shape.
    let mut ids = (0..40)
        .map(|_| uid(&register_secret(&mut f, V3, vec![])))
        .collect::<Vec<_>>();
    ids.sort();
    let order = (0..ids.len())
        .map(|i| (i * 17) % ids.len())
        .collect::<Vec<_>>();
    for (n, i) in order.iter().enumerate() {
        let r = f.call(
            "alice",
            V3,
            None,
            61,
            vec![Node::identifier(UNIQUE_IDENTIFIER, &*ids[*i])],
        );
        assert!(payload(&r).children().unwrap().is_empty());
        // Draft 3.0 section 6.1.41: "Any attempt to reference an object with
        // the Unique Identifier SHALL return an Object Not Found error." The
        // BL-M-20-30 trace shows Item Not Found here; the draft text governs.
        let r = f.call(
            "alice",
            V3,
            None,
            11,
            vec![Node::identifier(UNIQUE_IDENTIFIER, &*ids[*i])],
        );
        assert_eq!(reason(&r), 0x37);
        if n % 9 == 0 {
            // Store::open verifies the whole authenticated index.
            f.restart();
        }
        if n == 20 {
            let r = f.call(
                "alice",
                V3,
                None,
                8,
                vec![Node::structure(ATTRIBUTES, vec![])],
            );
            assert!(payload(&r).required(LOCATED_ITEMS).unwrap().value == Value::Integer(19));
        }
    }
    f.restart();
    // Unknown identifiers, other owners' objects and no Active-state restriction.
    assert_eq!(
        reason(&f.call(
            "alice",
            V3,
            None,
            61,
            vec![Node::identifier(UNIQUE_IDENTIFIER, "x")]
        )),
        0x37
    );
    let id = uid(&register_secret(&mut f, V3, vec![]));
    assert_eq!(
        reason(&f.call(
            "bob",
            V3,
            None,
            61,
            vec![Node::identifier(UNIQUE_IDENTIFIER, &*id)]
        )),
        0x37
    );
    payload(&f.call(
        "alice",
        V3,
        None,
        18,
        vec![Node::identifier(UNIQUE_IDENTIFIER, &*id)],
    ));
    payload(&f.call(
        "alice",
        V3,
        None,
        61,
        vec![Node::identifier(UNIQUE_IDENTIFIER, &*id)],
    ));
    // System Objects need a verified credential to be obliterated.
    let group = uid(&create_group(&mut f, "alice", admin(), "doomed"));
    assert_eq!(
        reason(&f.call(
            "alice",
            V3,
            None,
            61,
            vec![Node::identifier(UNIQUE_IDENTIFIER, &*group)]
        )),
        12
    );
    payload(&f.call(
        "alice",
        V3,
        admin(),
        61,
        vec![Node::identifier(UNIQUE_IDENTIFIER, &*group)],
    ));
    uid(&create_group(&mut f, "alice", admin(), "doomed"));
    // Obliterating a user's only credential leaves the user unable to log in.
    let pw = uid(&password_credential(&mut f, admin(), "secret"));
    uid(&create_user(&mut f, admin(), "temp", &[&pw]));
    payload(&f.call("alice", V3, password("temp", "secret"), 24, vec![]));
    payload(&f.call(
        "alice",
        V3,
        admin(),
        61,
        vec![Node::identifier(UNIQUE_IDENTIFIER, &*pw)],
    ));
    assert_eq!(
        reason(&f.call("alice", V3, password("temp", "secret"), 24, vec![])),
        3
    );
    f.restart();
}

#[test]
fn group_link_is_stored_located_and_hidden_before_draft() {
    let mut f = Fixture::new();
    let group = Node::name_reference(GROUP_LINK, "storage-group");
    let id = uid(&register_secret(&mut f, V3, vec![group.clone()]));
    let other = uid(&register_secret(&mut f, V3, vec![]));
    let locate = |f: &mut Fixture, filter: Node| -> Vec<String> {
        let r = f.call(
            "alice",
            V3,
            None,
            8,
            vec![Node::structure(ATTRIBUTES, vec![filter])],
        );
        payload(&r)
            .all(UNIQUE_IDENTIFIER)
            .map(|n| n.identifier_text().unwrap().to_owned())
            .collect()
    };
    assert_eq!(locate(&mut f, group.clone()), vec![id.clone()]);
    assert!(locate(&mut f, Node::name_reference(GROUP_LINK, "other")).is_empty());
    // Group Link is multi-instance and client-modifiable (draft table 142).
    let add = f.call(
        "alice",
        V3,
        None,
        13,
        vec![
            Node::identifier(UNIQUE_IDENTIFIER, &*other),
            Node::structure(NEW_ATTRIBUTE, vec![Node::reference(GROUP_LINK, "g-uid")]),
        ],
    );
    payload(&add);
    payload(&f.call(
        "alice",
        V3,
        None,
        13,
        vec![
            Node::identifier(UNIQUE_IDENTIFIER, &*other),
            Node::structure(NEW_ATTRIBUTE, vec![group.clone()]),
        ],
    ));
    let mut found = locate(&mut f, group.clone());
    found.sort();
    let mut expected = vec![id.clone(), other.clone()];
    expected.sort();
    assert_eq!(found, expected);
    let attrs = f.call(
        "alice",
        V3,
        None,
        11,
        vec![
            Node::identifier(UNIQUE_IDENTIFIER, &*other),
            Node::enumeration(ATTRIBUTE_REFERENCE, GROUP_LINK & 0xffffff),
        ],
    );
    assert_eq!(
        payload(&attrs)
            .required(ATTRIBUTES)
            .unwrap()
            .all(GROUP_LINK)
            .count(),
        2
    );
    // KMIP 2.1 neither accepts nor reveals the draft attribute.
    let r = register_secret(&mut f, V21, vec![Node::text(GROUP_LINK, "g")]);
    assert_eq!(reason(&r), 8);
    let r = f.call(
        "alice",
        V21,
        None,
        11,
        vec![Node::text(UNIQUE_IDENTIFIER, &*id)],
    );
    assert!(
        payload(&r)
            .required(ATTRIBUTES)
            .unwrap()
            .get(GROUP_LINK)
            .is_none()
    );
    let r = f.call(
        "alice",
        V21,
        None,
        8,
        vec![Node::structure(
            ATTRIBUTES,
            vec![Node::text(GROUP_LINK, "g")],
        )],
    );
    assert_eq!(reason(&r), 8);
    // Invalid Group Link encodings.
    for bad in [
        Node::text(GROUP_LINK, "x"),
        Node::name_reference(GROUP_LINK, ""),
    ] {
        assert_ne!(
            item(&register_secret(&mut f, V3, vec![bad]))
                .required(RESULT_STATUS)
                .unwrap()
                .number()
                .unwrap(),
            0
        );
    }
}
