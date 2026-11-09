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

//! Request-header Authentication in every protocol version: credentials are
//! verified against users and devices provisioned for the certificate
//! principal, and a credential that does not verify fails the message.
use keytend_kmip_server::{
    credentials::{PasswordVerifier, PolicyDevice, PolicyUser},
    protocol::{Engine, Version},
    store::Store,
    tags::*,
    ttlv::Node,
};

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
    _dir: tempfile::TempDir,
    engine: Engine,
}
impl Fixture {
    fn new(provisioned: bool) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let key = dir.path().join("master");
        std::fs::write(&key, [9; 32]).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        let store = Store::open(&dir.path().join("keys.sqlite"), &key).unwrap();
        let mut engine = Engine::new(store, false);
        if provisioned {
            let user = |name: &str, password: &[u8]| PolicyUser {
                username: name.into(),
                password_scrypt: PasswordVerifier::new(password).unwrap(),
                administrator: false,
                hashed_password: None,
                one_time_password: None,
            };
            engine
                .add_policy_users(
                    "alice",
                    vec![user("Fred", b"password1"), user("Barney", b"secret2")],
                )
                .unwrap();
            engine
                .add_policy_devices(
                    "alice",
                    vec![PolicyDevice {
                        name: "meter".into(),
                        device_serial_number: Some("serNum123456".into()),
                        device_identifier: Some("devID2233".into()),
                        network_identifier: None,
                        machine_identifier: Some("machineID1".into()),
                        media_identifier: None,
                        password_scrypt: PasswordVerifier::new(b"secret").unwrap(),
                    }],
                )
                .unwrap();
        }
        Self { _dir: dir, engine }
    }
    fn call(&mut self, owner: &str, v: Version, credentials: Vec<Node>) -> Node {
        let mut header = vec![v.node()];
        if !credentials.is_empty() {
            header.push(Node::structure(AUTHENTICATION, credentials));
        }
        header.push(Node::int(BATCH_COUNT, 1));
        let request = Node::structure(
            REQUEST_MESSAGE,
            vec![
                Node::structure(REQUEST_HEADER, header),
                Node::structure(
                    BATCH_ITEM,
                    vec![
                        Node::enumeration(OPERATION, 24),
                        Node::structure(
                            REQUEST_PAYLOAD,
                            vec![Node::enumeration(QUERY_FUNCTION, 1)],
                        ),
                    ],
                ),
            ],
        );
        self.engine.process(owner, &request).unwrap()
    }
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
fn password(user: &str, password: &str) -> Node {
    credential(
        1,
        vec![Node::text(USERNAME, user), Node::text(PASSWORD, password)],
    )
}
fn device(fields: &[(u32, &str)]) -> Node {
    credential(
        2,
        fields
            .iter()
            .map(|(tag, value)| Node::text(*tag, *value))
            .collect(),
    )
}
fn meter(password: &str) -> Vec<(u32, &str)> {
    vec![
        (DEVICE_SERIAL_NUMBER, "serNum123456"),
        (PASSWORD, password),
        (DEVICE_IDENTIFIER, "devID2233"),
        (MACHINE_IDENTIFIER, "machineID1"),
    ]
}
/// The Result Reason of a failed message, or None on success.
fn outcome(response: &Node) -> Option<u32> {
    let item = response.required(BATCH_ITEM).unwrap();
    match item.required(RESULT_STATUS).unwrap().number().unwrap() {
        0 => None,
        _ => Some(item.required(RESULT_REASON).unwrap().number().unwrap()),
    }
}

// REQ:9c0635f13d23322a the server supports authentication as the profiles define it
// REQ:667186976ba2206b Profiles 1.1: header credentials are considered with the channel identity
// REQ:7f05898c542e9c5a Profiles 1.2-1.4: the channel identity along with the credentials determines the client
// REQ:6bc935b517300895 without an Authentication object the channel identity alone is used
// REQ:14d4a48c816d9e13 Profiles 1.1: without credentials the channel identity is the client identity
// REQ:f0ce78ff9bc9a2fb HTTPS requests reach the same Engine path, so client authenticity is handled alike
#[test]
fn username_and_password_credentials_must_verify_in_every_version() {
    let mut f = Fixture::new(true);
    for v in FINAL {
        assert_eq!(
            outcome(&f.call("alice", v, vec![])),
            None,
            "{}.{}",
            v.0,
            v.1
        );
        assert_eq!(
            outcome(&f.call("alice", v, vec![password("Fred", "password1")])),
            None
        );
        for bad in [
            password("Fred", "password2"),
            password("Wilma", "password1"),
            password("Fred", ""),
            credential(1, vec![Node::text(USERNAME, "Fred")]),
        ] {
            // Authentication Not Successful fails the whole message.
            assert_eq!(
                outcome(&f.call("alice", v, vec![bad])),
                Some(3),
                "{}.{}",
                v.0,
                v.1
            );
        }
        // Users belong to one certificate principal only.
        assert_eq!(
            outcome(&f.call("bob", v, vec![password("Fred", "password1")])),
            Some(3)
        );
        // Unknown Credential Value fields are refused, not ignored.
        let extra = credential(
            1,
            vec![
                Node::text(USERNAME, "Fred"),
                Node::text(PASSWORD, "password1"),
                Node::text(DEVICE_IDENTIFIER, "x"),
            ],
        );
        assert_ne!(outcome(&f.call("alice", v, vec![extra])), None);
    }
}

#[test]
fn without_provisioned_users_no_credential_is_accepted() {
    // "Consider" never means "ignore": with nothing to verify against, a
    // presented credential fails rather than being accepted unverified.
    let mut f = Fixture::new(false);
    for v in FINAL {
        assert_eq!(outcome(&f.call("alice", v, vec![])), None);
        assert_eq!(
            outcome(&f.call("alice", v, vec![password("Fred", "password1")])),
            Some(3),
            "{}.{}",
            v.0,
            v.1
        );
        if v >= Version(1, 1) {
            assert_eq!(
                outcome(&f.call("alice", v, vec![device(&meter("secret"))])),
                Some(3)
            );
        }
    }
}

// REQ:7640c4dcb8d92aa5 1.0/1.1: the Authentication structure contains a Credential
// REQ:58c3f2010f3aed9a 1.2+: the Authentication structure contains one or more Credentials
#[test]
fn credential_count_follows_each_version() {
    let mut f = Fixture::new(true);
    for v in FINAL {
        assert_eq!(
            outcome(&f.call("alice", v, vec![Node::text(USERNAME, "Fred")])),
            Some(7),
            "{}.{}",
            v.0,
            v.1
        );
        let two = vec![password("Fred", "password1"), password("Fred", "password1")];
        if v < Version(1, 2) {
            assert_eq!(
                outcome(&f.call("alice", v, two)),
                Some(7),
                "{}.{}",
                v.0,
                v.1
            );
        } else {
            assert_eq!(outcome(&f.call("alice", v, two)), None, "{}.{}", v.0, v.1);
            // Every credential must be satisfied, and name one user.
            let mixed = vec![password("Fred", "password1"), password("Fred", "nope")];
            assert_eq!(outcome(&f.call("alice", v, mixed)), Some(3));
            let users = vec![password("Fred", "password1"), password("Barney", "secret2")];
            assert_eq!(outcome(&f.call("alice", v, users)), Some(3));
            // A user and a device of the same principal may be combined.
            let both = vec![password("Fred", "password1"), device(&meter("secret"))];
            assert_eq!(outcome(&f.call("alice", v, both)), None);
            let five = vec![password("Fred", "password1"); 5];
            assert_eq!(outcome(&f.call("alice", v, five)), Some(7));
        }
    }
}

#[test]
fn device_credentials_match_exactly_and_require_the_password() {
    let mut f = Fixture::new(true);
    // KMIP 1.0 defines only Username and Password (table 194).
    assert_eq!(
        outcome(&f.call("alice", Version(1, 0), vec![device(&meter("secret"))])),
        Some(7)
    );
    for v in &FINAL[1..] {
        let v = *v;
        assert_eq!(
            outcome(&f.call("alice", v, vec![device(&meter("secret"))])),
            None,
            "{}.{}",
            v.0,
            v.1
        );
        assert_eq!(
            outcome(&f.call("alice", v, vec![device(&meter("wrong"))])),
            Some(3)
        );
        let mut missing = meter("secret");
        missing.retain(|(tag, _)| *tag != MACHINE_IDENTIFIER);
        assert_eq!(
            outcome(&f.call("alice", v, vec![device(&missing)])),
            Some(3)
        );
        let mut extra = meter("secret");
        extra.push((MEDIA_IDENTIFIER, "mediaID313"));
        assert_eq!(outcome(&f.call("alice", v, vec![device(&extra)])), Some(3));
        let mut no_password = meter("secret");
        no_password.retain(|(tag, _)| *tag != PASSWORD);
        assert_eq!(
            outcome(&f.call("alice", v, vec![device(&no_password)])),
            Some(3)
        );
        assert_eq!(outcome(&f.call("alice", v, vec![device(&[])])), Some(7));
        assert_eq!(
            outcome(&f.call("bob", v, vec![device(&meter("secret"))])),
            Some(3)
        );
    }
}

#[test]
fn unverifiable_credential_types_are_refused_not_ignored() {
    let mut f = Fixture::new(true);
    for v in FINAL {
        // Attestation (1.2+) is defined but not verifiable here; earlier
        // versions do not define it at all. One Time Password, Hashed
        // Password and Ticket (2.0+) are verified (tests/proof_credentials.rs,
        // tests/tickets.rs); an empty value lacks their required fields, and
        // before 2.0 the types are undefined: Invalid Field.
        let expected = if v >= Version(1, 2) { 8 } else { 7 };
        assert_eq!(
            outcome(&f.call("alice", v, vec![credential(3, vec![])])),
            Some(expected),
            "{}.{} Attestation",
            v.0,
            v.1
        );
        // Empty One Time Password, Hashed Password and Ticket values, and
        // the draft-only Password and Certificate types: Invalid Field.
        for kind in [4, 5, 6, 7, 8, 0x8000_0001] {
            assert_eq!(
                outcome(&f.call("alice", v, vec![credential(kind, vec![])])),
                Some(7)
            );
        }
    }
}
