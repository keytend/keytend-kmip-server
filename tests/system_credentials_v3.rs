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

//! Draft 3.0 Device, One Time Password and Hashed Password Credential System
//! Objects (sections 2.1.3.2-2.1.3.4): Create Credential, User links,
//! request-header verification, secrecy and version gating.
use keytend_kmip_server::{
    credentials::{
        HashName, PasswordVerifier, PolicyDevice, PolicyUser, TotpDigest, TotpSecret,
        hashed_password_parts,
    },
    protocol::{Engine, Version},
    store::Store,
    tags::*,
    ttlv::{Node, Value},
};

const V3: Version = Version(3, 0);
const V21: Version = Version(2, 1);
const SEED: [u8; 20] = *b"w23-totp-seed-bytes!";

struct Fixture {
    dir: tempfile::TempDir,
    engine: Engine,
}
fn admin_user() -> PolicyUser {
    PolicyUser {
        username: "administrator".into(),
        password_scrypt: PasswordVerifier::new(b"password").unwrap(),
        administrator: true,
        hashed_password: None,
        one_time_password: None,
    }
}
impl Fixture {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let key = dir.path().join("master");
        std::fs::write(&key, [5; 32]).unwrap();
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
        for principal in ["alice", "bob"] {
            engine
                .add_policy_users(principal, vec![admin_user()])
                .unwrap();
        }
        engine
    }
    fn call(&mut self, owner: &str, v: Version, auth: Option<Node>, op: u32, p: Vec<Node>) -> Node {
        self.batch(owner, v, auth, vec![(op, p)])
    }
    fn batch(
        &mut self,
        owner: &str,
        v: Version,
        auth: Option<Node>,
        items: Vec<(u32, Vec<Node>)>,
    ) -> Node {
        let mut header = vec![v.node()];
        if v.0 < 3 {
            header.push(Node::int(BATCH_COUNT, items.len() as i32));
        }
        header.extend(auth);
        let mut fields = vec![Node::structure(REQUEST_HEADER, header)];
        fields.extend(items.into_iter().map(|(op, p)| {
            Node::structure(
                BATCH_ITEM,
                vec![
                    Node::enumeration(OPERATION, op),
                    Node::structure(REQUEST_PAYLOAD, p),
                ],
            )
        }));
        self.engine
            .process(owner, &Node::structure(REQUEST_MESSAGE, fields))
            .unwrap()
    }
    /// A Query (operation 24) authenticated by `credential`.
    fn query(&mut self, owner: &str, v: Version, credential: Node) -> Node {
        self.call(
            owner,
            v,
            auth(vec![credential]),
            24,
            vec![Node::enumeration(QUERY_FUNCTION, 2)],
        )
    }
    fn create_credential(&mut self, owner: &str, kind: u32, attrs: Vec<Node>, value: Node) -> Node {
        self.call(
            owner,
            V3,
            admin(),
            63,
            vec![
                Node::enumeration(CREDENTIAL_TYPE, kind),
                Node::structure(ATTRIBUTES, attrs),
                value,
            ],
        )
    }
    fn password_credential(&mut self, owner: &str, secret: &str) -> String {
        uid(&self.create_credential(
            owner,
            7,
            vec![],
            Node::structure(PASSWORD_CREDENTIAL, vec![Node::text(PASSWORD, secret)]),
        ))
    }
    fn create_user(&mut self, owner: &str, name: &str, links: &[&str]) -> Node {
        let mut attrs = vec![Node::text(NAME, name)];
        attrs.extend(links.iter().map(|id| Node::reference(CREDENTIAL_LINK, *id)));
        self.call(
            owner,
            V3,
            admin(),
            62,
            vec![Node::structure(ATTRIBUTES, attrs)],
        )
    }
    fn obliterate(&mut self, id: &str) -> Node {
        self.call(
            "alice",
            V3,
            admin(),
            61,
            vec![Node::identifier(UNIQUE_IDENTIFIER, id)],
        )
    }
}
fn auth(credentials: Vec<Node>) -> Option<Node> {
    Some(Node::structure(AUTHENTICATION, credentials))
}
fn credential(kind: u32, fields: Vec<Node>) -> Node {
    Node::structure(
        CREDENTIAL,
        vec![
            Node::enumeration(CREDENTIAL_TYPE, kind),
            Node::structure(CREDENTIAL_VALUE, fields),
        ],
    )
}
fn password(user: &str, secret: &str) -> Node {
    credential(
        1,
        vec![Node::text(USERNAME, user), Node::text(PASSWORD, secret)],
    )
}
fn admin() -> Option<Node> {
    auth(vec![password("administrator", "password")])
}
fn item(n: &Node) -> &Node {
    n.required(BATCH_ITEM).unwrap()
}
fn ok(n: &Node) -> &Node {
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
    ok(n)
        .required(UNIQUE_IDENTIFIER)
        .unwrap()
        .identifier_text()
        .unwrap()
        .to_owned()
}
fn now_micros() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_micros() as i64
}

fn device_value(fields: Vec<Node>) -> Node {
    Node::structure(DEVICE_CREDENTIAL, fields)
}
fn device_auth(serial: &str, network: Option<&str>, secret: &str) -> Node {
    let mut fields = vec![Node::text(DEVICE_SERIAL_NUMBER, serial)];
    fields.extend(network.map(|n| Node::text(NETWORK_IDENTIFIER, n)));
    fields.push(Node::text(PASSWORD, secret));
    credential(2, fields)
}

fn totp() -> TotpSecret {
    TotpSecret {
        seed: SEED.to_vec(),
        digest: TotpDigest::Sha1,
        digits: 6,
        interval: 30,
    }
}
fn otp_value(extra: Vec<Node>) -> Node {
    let mut fields = vec![
        Node::enumeration(OTP_ALGORITHM, 2),
        Node::bytes(OTP_SEED, SEED.to_vec()),
    ];
    fields.extend(extra);
    Node::structure(OTP_CREDENTIAL, fields)
}
fn otp_auth(user: &str, secret: Option<&str>, code: &str) -> Node {
    let mut fields = vec![Node::text(USERNAME, user)];
    fields.extend(secret.map(|p| Node::text(PASSWORD, p)));
    fields.push(Node::text(ONE_TIME_PASSWORD, code));
    credential(4, fields)
}
/// The current TOTP step, waiting out the end of a step so that a test does
/// not straddle a boundary.
fn fresh_step() -> i64 {
    let seconds = now_micros() / 1_000_000;
    if seconds % 30 >= 26 {
        std::thread::sleep(std::time::Duration::from_secs((31 - seconds % 30) as u64));
    }
    totp().step(now_micros() / 1_000_000)
}
fn code(step: i64) -> String {
    totp().code(step).to_string()
}

fn hashed_value(user: &str, secret: &str) -> Node {
    let (s1, s2) = hashed_password_parts(HashName::Sha256, user, secret);
    Node::structure(
        HASHED_PASSWORD_CREDENTIAL,
        vec![
            Node::bytes(HASHED_USERNAME_PASSWORD, s1.to_vec()),
            Node::bytes(HASHED_PASSWORD_USERNAME, s2.to_vec()),
        ],
    )
}
fn hashed_auth(user: &str, secret: &str, ts: i64) -> Node {
    let (s1, s2) = hashed_password_parts(HashName::Sha256, user, secret);
    let mut value = HashName::Sha256.hash(&[&s1, &ts.to_be_bytes()]).to_vec();
    value.extend_from_slice(&s2);
    credential(
        5,
        vec![
            Node::text(USERNAME, user),
            Node {
                tag: TIME_STAMP,
                value: Value::DateTimeExtended(ts),
            },
            Node::bytes(HASHED_PASSWORD, value),
        ],
    )
}

// REQ:72a98fa5f94675ee Device Credential serial, network, machine or media identifiers are unique
// REQ:9cbd3c0bf244d380 a Device Credential carries at least one field
// REQ:04ec1bda799f7239 a device password (Password Link to a Password Credential) authenticates the device
// REQ:c4636690cc01e236 the server sets the Credential Type of a credential System Object
#[test]
fn device_credentials_authenticate_a_device_but_no_user() {
    let mut f = Fixture::new();
    let secret = f.password_credential("alice", "device-secret-1");
    let link = || Node::reference(PASSWORD_LINK, &secret);
    let device = uid(&f.create_credential(
        "alice",
        2,
        vec![link()],
        device_value(vec![
            Node::text(DEVICE_SERIAL_NUMBER, "SN-1"),
            Node::text(NETWORK_IDENTIFIER, "net-1"),
        ]),
    ));
    // Every identifier must match and the linked password must verify.
    ok(&f.query(
        "alice",
        V3,
        device_auth("SN-1", Some("net-1"), "device-secret-1"),
    ));
    for wrong in [
        device_auth("SN-1", Some("net-1"), "device-secret-2"),
        device_auth("SN-1", None, "device-secret-1"),
        device_auth("SN-2", Some("net-1"), "device-secret-1"),
        credential(
            2,
            vec![
                Node::text(DEVICE_SERIAL_NUMBER, "SN-1"),
                Node::text(NETWORK_IDENTIFIER, "net-1"),
            ],
        ),
    ] {
        assert_eq!(reason(&f.query("alice", V3, wrong)), 3);
    }
    // Bound to the certificate principal, and verified only in draft 3.0.
    let good = || device_auth("SN-1", Some("net-1"), "device-secret-1");
    assert_eq!(reason(&f.query("bob", V3, good())), 3);
    assert_eq!(reason(&f.query("alice", V21, good())), 3);
    // A device names no user, so it cannot create System Objects.
    let r = f.call(
        "alice",
        V3,
        auth(vec![good()]),
        60,
        vec![Node::structure(ATTRIBUTES, vec![Node::text(NAME, "g")])],
    );
    assert_eq!(reason(&r), 12);
    // A device credential is a valid User Credential Link target but proves
    // nothing about the user.
    let pw = f.password_credential("alice", "user-secret-1");
    uid(&f.create_user("alice", "device-owner", &[&device, &pw]));

    // Table 7 and 2.1.3.2 checks.
    let create = |f: &mut Fixture, attrs: Vec<Node>, fields: Vec<Node>| {
        f.create_credential("alice", 2, attrs, device_value(fields))
    };
    assert_eq!(reason(&create(&mut f, vec![link()], vec![])), 7);
    // Device Identifier alone is not in the set that SHALL be unique.
    assert_eq!(
        reason(&create(
            &mut f,
            vec![link()],
            vec![Node::text(DEVICE_IDENTIFIER, "d")]
        )),
        7
    );
    // The serial number is already used (with another network identifier).
    assert_eq!(
        reason(&create(
            &mut f,
            vec![link()],
            vec![
                Node::text(DEVICE_SERIAL_NUMBER, "SN-1"),
                Node::text(NETWORK_IDENTIFIER, "net-1"),
            ]
        )),
        7
    );
    // Table 7 has no Password field; the secret is the Password Link.
    assert_eq!(
        reason(&create(
            &mut f,
            vec![link()],
            vec![
                Node::text(DEVICE_SERIAL_NUMBER, "SN-3"),
                Node::text(PASSWORD, "x")
            ]
        )),
        8
    );
    let sn3 = || vec![Node::text(DEVICE_SERIAL_NUMBER, "SN-3")];
    assert_eq!(reason(&create(&mut f, vec![], sn3())), 8);
    assert_eq!(
        reason(&create(
            &mut f,
            vec![Node::reference(PASSWORD_LINK, &device)],
            sn3()
        )),
        0x2d
    );
    // Credential Type is server-set (Read Only Attribute, table 279).
    assert_eq!(
        reason(&create(
            &mut f,
            vec![link(), Node::enumeration(CREDENTIAL_TYPE, 2)],
            sn3()
        )),
        0x22
    );
    // Another principal's Password Credential is not visible.
    let bobs = f.password_credential("bob", "bob-secret");
    assert_eq!(
        reason(&create(
            &mut f,
            vec![Node::reference(PASSWORD_LINK, &bobs)],
            sn3()
        )),
        0x2d
    );
    // A second device with its own serial number may share the password.
    let second = uid(&create(&mut f, vec![link()], sn3()));
    assert_ne!(second, device);
    // Section 4.35.11: the Password Link may be the ID Placeholder of the
    // Password Credential created earlier in the same batch.
    let batch = f.batch(
        "alice",
        V3,
        admin(),
        vec![
            (
                63,
                vec![
                    Node::enumeration(CREDENTIAL_TYPE, 7),
                    Node::structure(ATTRIBUTES, vec![]),
                    Node::structure(PASSWORD_CREDENTIAL, vec![Node::text(PASSWORD, "batch-1")]),
                ],
            ),
            (
                63,
                vec![
                    Node::enumeration(CREDENTIAL_TYPE, 2),
                    Node::structure(ATTRIBUTES, vec![Node::enumeration(PASSWORD_LINK, 1)]),
                    device_value(vec![Node::text(MEDIA_IDENTIFIER, "media-4")]),
                ],
            ),
        ],
    );
    let statuses = batch
        .all(BATCH_ITEM)
        .map(|i| i.required(RESULT_STATUS).unwrap().number().unwrap())
        .collect::<Vec<_>>();
    assert_eq!(statuses, [0, 0]);
    ok(&f.query(
        "alice",
        V3,
        credential(
            2,
            vec![
                Node::text(MEDIA_IDENTIFIER, "media-4"),
                Node::text(PASSWORD, "batch-1"),
            ],
        ),
    ));

    // A provisioned device may not share identifiers with a System Device
    // Credential (one source per device).
    let conflict = PolicyDevice {
        name: "sensor".into(),
        device_serial_number: Some("SN-1".into()),
        device_identifier: None,
        network_identifier: Some("net-1".into()),
        machine_identifier: None,
        media_identifier: None,
        password_scrypt: PasswordVerifier::new(b"x").unwrap(),
    };
    assert!(
        f.engine
            .add_policy_devices("alice", vec![conflict.clone()])
            .is_err()
    );
    let mut distinct = conflict;
    distinct.device_serial_number = Some("SN-9".into());
    f.engine
        .add_policy_devices("alice", vec![distinct])
        .unwrap();
    ok(&f.query("alice", V3, good()));

    // Obliterating the linked Password Credential disables the device.
    ok(&f.obliterate(&secret));
    assert_eq!(reason(&f.query("alice", V3, good())), 3);
}

#[test]
fn one_time_password_credentials_need_the_password_and_are_single_use() {
    let mut f = Fixture::new();
    let pw = f.password_credential("alice", "otp-user-secret");
    let otp = uid(&f.create_credential(
        "alice",
        4,
        vec![],
        otp_value(vec![
            Node::enumeration(OTP_DIGEST, 7),
            Node::interval(OTP_INTERVAL, 30),
            Node::int(OTP_DIGITS, 6),
            Node::text(OTP_SERIAL, "token-1"),
        ]),
    ));
    uid(&f.create_user("alice", "otp-user", &[&pw, &otp]));
    let step = fresh_step();
    // A wrong Password does not consume the code; a missing one fails.
    assert_eq!(
        reason(&f.query(
            "alice",
            V3,
            otp_auth("otp-user", Some("wrong"), &code(step))
        )),
        3
    );
    assert_eq!(
        reason(&f.query("alice", V3, otp_auth("otp-user", None, &code(step)))),
        3
    );
    if code(step) != "000000" {
        assert_eq!(
            reason(&f.query(
                "alice",
                V3,
                otp_auth("otp-user", Some("otp-user-secret"), "000000")
            )),
            3
        );
    }
    // Draft 3.0 2.1.3.3: the OTP "may only be used for a single authentication".
    let good = || otp_auth("otp-user", Some("otp-user-secret"), &code(step));
    ok(&f.query("alice", V3, good()));
    assert_eq!(reason(&f.query("alice", V3, good())), 3);
    // The next step's code is still accepted once, an earlier one never.
    let next = || otp_auth("otp-user", Some("otp-user-secret"), &code(step + 1));
    ok(&f.query("alice", V3, next()));
    assert_eq!(
        reason(&f.query(
            "alice",
            V3,
            otp_auth("otp-user", Some("otp-user-secret"), &code(step - 1))
        )),
        3
    );
    // Another principal, and protocol 2.1, never see System Users.
    let later = || otp_auth("otp-user", Some("otp-user-secret"), &code(step + 1));
    assert_eq!(reason(&f.query("bob", V3, later())), 3);
    assert_eq!(reason(&f.query("alice", V21, later())), 3);

    // An OTP-proven user can Login; obliterating the OTP credential revokes
    // the ticket, since the ticket re-checks the credential that proved it.
    let user = f.password_credential("alice", "second-secret");
    let otp2 = uid(&f.create_credential("alice", 4, vec![], otp_value(vec![])));
    uid(&f.create_user("alice", "otp-user-2", &[&user, &otp2]));
    let step = fresh_step();
    let login = f.call(
        "alice",
        V3,
        auth(vec![otp_auth(
            "otp-user-2",
            Some("second-secret"),
            &code(step),
        )]),
        45,
        vec![],
    );
    let ticket = ok(&login).required(TICKET).unwrap().clone();
    let ticket_auth = || credential(6, vec![ticket.clone()]);
    ok(&f.query("alice", V3, ticket_auth()));
    ok(&f.obliterate(&otp2));
    assert_eq!(reason(&f.query("alice", V3, ticket_auth())), 3);

    // A user linking an OTP credential but no Password Credential cannot
    // authenticate with it.
    let lone = uid(&f.create_credential("alice", 4, vec![], otp_value(vec![])));
    let spare = f.password_credential("alice", "unused");
    uid(&f.create_user("alice", "otp-only", &[&lone]));
    assert_eq!(
        reason(&f.query(
            "alice",
            V3,
            otp_auth("otp-only", Some("unused"), &code(step))
        )),
        3
    );
    // At most one OTP credential per user; another principal's is unknown.
    assert_eq!(reason(&f.create_user("alice", "two", &[&otp, &lone])), 0x3a);
    let bobs = uid(&f.create_credential("bob", 4, vec![], otp_value(vec![])));
    assert_eq!(
        reason(&f.create_user("alice", "foreign", &[&spare, &bobs])),
        0x2d
    );

    // Table 9 checks.
    let bad = |f: &mut Fixture, attrs: Vec<Node>, fields: Vec<Node>| {
        reason(&f.create_credential("alice", 4, attrs, Node::structure(OTP_CREDENTIAL, fields)))
    };
    let seed = || Node::bytes(OTP_SEED, SEED.to_vec());
    // HOTP, a server-generated seed and unknown digests are not offered.
    assert_eq!(
        bad(
            &mut f,
            vec![],
            vec![Node::enumeration(OTP_ALGORITHM, 1), seed()]
        ),
        8
    );
    assert_eq!(
        bad(&mut f, vec![], vec![Node::enumeration(OTP_ALGORITHM, 2)]),
        8
    );
    assert_eq!(
        bad(
            &mut f,
            vec![],
            vec![
                Node::enumeration(OTP_ALGORITHM, 2),
                seed(),
                Node::enumeration(OTP_DIGEST, 3)
            ]
        ),
        8
    );
    assert_eq!(bad(&mut f, vec![], vec![seed()]), 7);
    // A seed below 128 bits (RFC 4226 R6) and out-of-range digits fail.
    assert_eq!(
        bad(
            &mut f,
            vec![],
            vec![
                Node::enumeration(OTP_ALGORITHM, 2),
                Node::bytes(OTP_SEED, vec![1; 15])
            ]
        ),
        7
    );
    assert_eq!(
        bad(
            &mut f,
            vec![],
            vec![
                Node::enumeration(OTP_ALGORITHM, 2),
                seed(),
                Node::int(OTP_DIGITS, 9)
            ]
        ),
        7
    );
    // Table 186: OTP Counter is set by the server only.
    assert_eq!(
        bad(
            &mut f,
            vec![Node::bytes(OTP_COUNTER, vec![0; 8])],
            vec![Node::enumeration(OTP_ALGORITHM, 2), seed()]
        ),
        0x22
    );
    // HMAC-SHA256 seeds are accepted.
    uid(&f.create_credential(
        "alice",
        4,
        vec![],
        otp_value(vec![Node::enumeration(OTP_DIGEST, 9)]),
    ));
}

// REQ:f3f16670b77bfb32 a System User's Hashed Password Timestamp must increase
#[test]
fn hashed_password_credentials_verify_against_the_linked_object() {
    let mut f = Fixture::new();
    let hashed =
        uid(&f.create_credential("alice", 5, vec![], hashed_value("hp-user", "hp-secret")));
    uid(&f.create_user("alice", "hp-user", &[&hashed]));
    let ts = now_micros();
    let response = f.query("alice", V3, hashed_auth("hp-user", "hp-secret", ts));
    ok(&response);
    // Server Hashed Password = Hash(Timestamp || S1 || Hash(S2)).
    let (s1, s2) = hashed_password_parts(HashName::Sha256, "hp-user", "hp-secret");
    let expected =
        openssl::sha::sha256(&[&ts.to_be_bytes()[..], &s1, &openssl::sha::sha256(&s2)].concat());
    assert_eq!(
        response
            .required(RESPONSE_HEADER)
            .unwrap()
            .required(SERVER_HASHED_PASSWORD)
            .unwrap()
            .byte_string()
            .unwrap(),
        expected
    );
    // Replays, older timestamps and wrong passwords fail.
    for wrong in [
        hashed_auth("hp-user", "hp-secret", ts),
        hashed_auth("hp-user", "hp-secret", ts - 1),
        hashed_auth("hp-user", "hp-secreu", ts + 1),
    ] {
        assert_eq!(reason(&f.query("alice", V3, wrong)), 3);
    }
    ok(&f.query("alice", V3, hashed_auth("hp-user", "hp-secret", ts + 2)));
    assert_eq!(
        reason(&f.query("bob", V3, hashed_auth("hp-user", "hp-secret", ts + 3))),
        3
    );
    assert_eq!(
        reason(&f.query("alice", V21, hashed_auth("hp-user", "hp-secret", ts + 4))),
        3
    );
    // An administrator check still needs a users-file administrator.
    let r = f.call(
        "alice",
        V3,
        auth(vec![hashed_auth("hp-user", "hp-secret", ts + 5)]),
        60,
        vec![Node::structure(ATTRIBUTES, vec![Node::text(NAME, "g")])],
    );
    assert_eq!(reason(&r), 12);

    // Table 11 checks: SHA-2 only, lengths must match the algorithm.
    let make = |f: &mut Fixture, fields: Vec<Node>| {
        reason(&f.create_credential(
            "alice",
            5,
            vec![],
            Node::structure(HASHED_PASSWORD_CREDENTIAL, fields),
        ))
    };
    let (s1, s2) = (s1.to_vec(), s2.to_vec());
    let halves = || {
        vec![
            Node::bytes(HASHED_USERNAME_PASSWORD, s1.clone()),
            Node::bytes(HASHED_PASSWORD_USERNAME, s2.clone()),
        ]
    };
    let mut sha1 = vec![Node::enumeration(HASHING_ALGORITHM, 4)];
    sha1.extend(halves());
    assert_eq!(make(&mut f, sha1), 8);
    let mut sha512 = vec![Node::enumeration(HASHING_ALGORITHM, 8)];
    sha512.extend(halves());
    assert_eq!(make(&mut f, sha512), 7);
    assert_eq!(
        make(
            &mut f,
            vec![Node::bytes(HASHED_USERNAME_PASSWORD, s1.clone())]
        ),
        7
    );
    let other = uid(&f.create_credential("alice", 5, vec![], hashed_value("x", "y")));
    assert_eq!(
        reason(&f.create_user("alice", "two", &[&hashed, &other])),
        0x3a
    );
}

#[test]
fn credential_objects_are_never_returned_and_query_lists_them() {
    let mut f = Fixture::new();
    let secret = f.password_credential("alice", "device-secret-1");
    let device = uid(&f.create_credential(
        "alice",
        2,
        vec![Node::reference(PASSWORD_LINK, &secret)],
        device_value(vec![Node::text(MACHINE_IDENTIFIER, "m-1")]),
    ));
    let otp = uid(&f.create_credential("alice", 4, vec![], otp_value(vec![])));
    let hashed =
        uid(&f.create_credential("alice", 5, vec![], hashed_value("hp-user", "hp-secret")));
    let missing = reason(&f.call(
        "alice",
        V3,
        None,
        10,
        vec![Node::identifier(UNIQUE_IDENTIFIER, "no-such-object")],
    ));
    for id in [&device, &otp, &hashed] {
        for op in [10, 11, 20] {
            let r = f.call(
                "alice",
                V3,
                admin(),
                op,
                vec![Node::identifier(UNIQUE_IDENTIFIER, &**id)],
            );
            assert_eq!(reason(&r), missing, "operation {op}");
        }
    }
    for kind in [14, 15, 16] {
        let r = f.call(
            "alice",
            V3,
            admin(),
            8,
            vec![Node::structure(
                ATTRIBUTES,
                vec![Node::enumeration(OBJECT_TYPE, kind)],
            )],
        );
        assert!(ok(&r).get(UNIQUE_IDENTIFIER).is_none());
    }
    // Neither the database file nor the decrypted record holds the seed in
    // the clear, or the S2 half of the Hashed Password.
    let (_, s2) = hashed_password_parts(HashName::Sha256, "hp-user", "hp-secret");
    let database = std::fs::read(f.dir.path().join("keys.sqlite")).unwrap();
    assert!(!database.windows(SEED.len()).any(|w| w == SEED));
    let seed_hex = hex::encode(SEED);
    assert!(
        !database
            .windows(seed_hex.len())
            .any(|w| w == seed_hex.as_bytes())
    );
    let store = Store::open(
        &f.dir.path().join("keys.sqlite"),
        &f.dir.path().join("master"),
    )
    .unwrap();
    let record = store.get("alice\0system", &hashed).unwrap().unwrap();
    assert_eq!(record.object_type, 16);
    assert!(!record.material.windows(32).any(|w| w == &s2[..]));
    assert!(
        !record
            .material
            .windows(s2.len() * 2)
            .any(|w| w == hex::encode(&s2).as_bytes())
    );
    assert_eq!(
        store
            .get("alice\0system", &device)
            .unwrap()
            .unwrap()
            .object_type,
        14
    );
    assert_eq!(
        store
            .get("alice\0system", &otp)
            .unwrap()
            .unwrap()
            .object_type,
        15
    );
    drop(store);
    // Obliterate needs an administrator and removes them.
    let pw = f.password_credential("alice", "plain-user");
    uid(&f.create_user("alice", "plain", &[&pw]));
    let r = f.call(
        "alice",
        V3,
        auth(vec![password("plain", "plain-user")]),
        61,
        vec![Node::identifier(UNIQUE_IDENTIFIER, &*otp)],
    );
    assert_eq!(reason(&r), 12);
    for id in [&device, &otp, &hashed] {
        ok(&f.obliterate(id));
        assert_eq!(reason(&f.obliterate(id)), 0x37);
    }
    // Query Object Types lists every draft 3.0 System Object type, and no
    // System Object type before 3.0.
    let types = |f: &mut Fixture, v: Version| {
        let r = f.call(
            "alice",
            v,
            None,
            24,
            vec![Node::enumeration(QUERY_FUNCTION, 2)],
        );
        ok(&r)
            .all(OBJECT_TYPE)
            .map(|n| n.number().unwrap())
            .collect::<Vec<_>>()
    };
    let v3 = types(&mut f, V3);
    for kind in 11..=16 {
        assert!(v3.contains(&kind), "{kind}");
    }
    assert!(types(&mut f, V21).iter().all(|k| *k < 11));
}
