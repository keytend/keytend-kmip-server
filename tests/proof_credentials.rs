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

//! KMIP 2.0+ Hashed Password and One Time Password request-header
//! credentials: verification, replay refusal, constant work per attempt and
//! the response header Server Hashed Password.
use keytend_kmip_server::{
    credentials::{
        self, HashName, HashedPasswordSecret, PasswordVerifier, PolicyUser, TotpDigest, TotpSecret,
        hashed_password_parts,
    },
    protocol::{Engine, Version},
    store::Store,
    tags::*,
    ttlv::{Node, Value},
};
use std::path::{Path, PathBuf};

const HASHED: u32 = 5;
const OTP: u32 = 4;
const V2: [Version; 2] = [Version(2, 0), Version(2, 1)];

struct Fixture {
    dir: tempfile::TempDir,
    engine: Engine,
}
fn totp() -> TotpSecret {
    TotpSecret {
        seed: (0..20).collect(),
        digest: TotpDigest::Sha1,
        digits: 6,
        interval: 30,
    }
}
fn users() -> Vec<PolicyUser> {
    let user = |name: &str, password: &str, hashed: bool, otp: bool| PolicyUser {
        username: name.into(),
        password_scrypt: PasswordVerifier::new(password.as_bytes()).unwrap(),
        administrator: false,
        hashed_password: hashed
            .then(|| HashedPasswordSecret::new(HashName::Sha256, name, password).unwrap()),
        one_time_password: otp.then(totp),
    };
    vec![
        user("Fred", "password1", true, true),
        // A user without Hashed Password or One Time Password material.
        user("Barney", "secret2", false, false),
    ]
}
fn open(path: &Path, v3: bool) -> Engine {
    let store = Store::open(&path.join("keys.sqlite"), &path.join("master")).unwrap();
    let mut engine = Engine::new(store, v3);
    engine.add_policy_users("alice", users()).unwrap();
    engine
}
impl Fixture {
    fn new() -> Self {
        Self::with_v3(false)
    }
    fn with_v3(v3: bool) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let key = dir.path().join("master");
        std::fs::write(&key, [9; 32]).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        let engine = open(dir.path(), v3);
        Self { dir, engine }
    }
    /// A restarted server on the same database.
    fn restart(&mut self) {
        self.engine = open(self.dir.path(), false);
    }
    fn database(&self) -> PathBuf {
        self.dir.path().join("keys.sqlite")
    }
    fn call(&mut self, owner: &str, v: Version, credentials: Vec<Node>) -> Node {
        let mut header = vec![v.node()];
        header.push(Node::structure(AUTHENTICATION, credentials));
        if v.0 < 3 {
            header.push(Node::int(BATCH_COUNT, 1));
        }
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
/// The Result Reason of a failed message, or None on success.
fn outcome(response: &Node) -> Option<u32> {
    let item = response.required(BATCH_ITEM).unwrap();
    match item.required(RESULT_STATUS).unwrap().number().unwrap() {
        0 => None,
        _ => Some(item.required(RESULT_REASON).unwrap().number().unwrap()),
    }
}
fn now_micros() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_micros() as i64
}
fn timestamp(micros: i64) -> Node {
    Node {
        tag: TIME_STAMP,
        value: Value::DateTimeExtended(micros),
    }
}
/// Hashed Password = Hash(S1 || Timestamp) || S2 for a username and password.
fn hashed_value(algorithm: HashName, user: &str, password: &str, ts: i64) -> Vec<u8> {
    let (s1, s2) = hashed_password_parts(algorithm, user, password);
    let mut value = algorithm.hash(&[&s1, &ts.to_be_bytes()]).to_vec();
    value.extend_from_slice(&s2);
    value
}
fn hashed(user: &str, password: &str, ts: i64, algorithm: Option<u32>) -> Node {
    let mut fields = vec![Node::text(USERNAME, user), timestamp(ts)];
    if let Some(a) = algorithm {
        fields.push(Node::enumeration(HASHING_ALGORITHM, a));
    }
    fields.push(Node::bytes(
        HASHED_PASSWORD,
        hashed_value(HashName::Sha256, user, password, ts),
    ));
    credential(HASHED, fields)
}
fn otp(user: &str, password: Option<&str>, code: &str) -> Node {
    let mut fields = vec![Node::text(USERNAME, user)];
    if let Some(p) = password {
        fields.push(Node::text(PASSWORD, p));
    }
    fields.push(Node::text(ONE_TIME_PASSWORD, code));
    credential(OTP, fields)
}
/// The current TOTP step, after waiting out the last seconds of a step so
/// that a test does not straddle a boundary.
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

// REQ:66f456bdfa1554f7 without a Hashing Algorithm the Hashed Password is SHA-256
#[test]
fn hashed_password_defaults_to_sha_256_and_proves_the_server() {
    for v in V2 {
        let mut f = Fixture::new();
        let ts = now_micros();
        let response = f.call("alice", v, vec![hashed("Fred", "password1", ts, None)]);
        assert_eq!(outcome(&response), None, "{v:?}");
        // Response header Server Hashed Password = Hash(Timestamp || S1 || Hash(S2)).
        let header = response.required(RESPONSE_HEADER).unwrap();
        let (s1, s2) = hashed_password_parts(HashName::Sha256, "Fred", "password1");
        let expected = openssl::sha::sha256(
            &[&ts.to_be_bytes()[..], &s1, &openssl::sha::sha256(&s2)].concat(),
        );
        let fields = header.children().unwrap();
        let at = fields
            .iter()
            .position(|n| n.tag == SERVER_HASHED_PASSWORD)
            .expect("Server Hashed Password");
        assert_eq!(fields[at].byte_string().unwrap(), expected);
        assert_eq!(fields[at - 1].tag, TIME_STAMP);
        // An explicit SHA-256 is the same algorithm.
        let ok = f.call(
            "alice",
            v,
            vec![hashed("Fred", "password1", ts + 1, Some(6))],
        );
        assert_eq!(outcome(&ok), None);
        // A SHA-256 value labelled SHA-512 does not verify.
        assert_eq!(
            outcome(&f.call(
                "alice",
                v,
                vec![hashed("Fred", "password1", ts + 2, Some(8))]
            )),
            Some(3)
        );
        // Other credentials leave the header unchanged.
        let other = f.call(
            "alice",
            v,
            vec![credential(
                1,
                vec![
                    Node::text(USERNAME, "Barney"),
                    Node::text(PASSWORD, "secret2"),
                ],
            )],
        );
        assert_eq!(outcome(&other), None);
        assert!(
            other
                .required(RESPONSE_HEADER)
                .unwrap()
                .get(SERVER_HASHED_PASSWORD)
                .is_none()
        );
    }
}

#[test]
fn hashed_password_timestamps_must_increase_and_stay_near_the_clock() {
    let mut f = Fixture::new();
    let v = Version(2, 1);
    let ts = now_micros();
    let first = hashed("Fred", "password1", ts, None);
    assert_eq!(outcome(&f.call("alice", v, vec![first.clone()])), None);
    // "SHALL monotonically increase": a replay or an older Timestamp fails.
    assert_eq!(outcome(&f.call("alice", v, vec![first.clone()])), Some(3));
    assert_eq!(
        outcome(&f.call("alice", v, vec![hashed("Fred", "password1", ts - 1, None)])),
        Some(3)
    );
    // The last accepted Timestamp survives a restart.
    f.restart();
    assert_eq!(outcome(&f.call("alice", v, vec![first])), Some(3));
    assert_eq!(
        outcome(&f.call("alice", v, vec![hashed("Fred", "password1", ts + 1, None)])),
        None
    );
    // Timestamps more than five minutes from the server clock fail.
    for skew in [-301_000_000, 301_000_000] {
        assert_eq!(
            outcome(&f.call(
                "alice",
                v,
                vec![hashed("Fred", "password1", now_micros() + skew, None)]
            )),
            Some(3)
        );
    }
    // The replay table names no user.
    let db = rusqlite::Connection::open(f.database()).unwrap();
    let names: Vec<Vec<u8>> = db
        .prepare("SELECT name FROM credential_replay")
        .unwrap()
        .query_map([], |r| r.get(0))
        .unwrap()
        .map(Result::unwrap)
        .collect();
    assert_eq!(names.len(), 1);
    assert!(!names[0].windows(4).any(|w| w == b"Fred"));
}

#[test]
fn wrong_hashed_passwords_fail_alike_with_one_scrypt_evaluation() {
    let mut f = Fixture::new();
    let v = Version(2, 0);
    let ts = now_micros();
    let good = hashed_value(HashName::Sha256, "Fred", "password1", ts);
    let wrong = hashed_value(HashName::Sha256, "Fred", "password2", ts);
    // Right first half, wrong S2; wrong first half, right S2.
    let mixed = [
        [&good[..32], &wrong[32..]].concat(),
        [&wrong[..32], &good[32..]].concat(),
    ];
    let value = |user: &str, bytes: Vec<u8>| {
        credential(
            HASHED,
            vec![
                Node::text(USERNAME, user),
                timestamp(ts),
                Node::bytes(HASHED_PASSWORD, bytes),
            ],
        )
    };
    let cases = vec![
        value("Fred", wrong.clone()),
        value("Fred", mixed[0].clone()),
        value("Fred", mixed[1].clone()),
        value("Fred", good[..48].to_vec()),
        // A user without Hashed Password material, and an unknown user.
        value(
            "Barney",
            hashed_value(HashName::Sha256, "Barney", "secret2", ts),
        ),
        value("Wilma", hashed_value(HashName::Sha256, "Wilma", "x", ts)),
    ];
    for case in cases {
        let before = credentials::derivations();
        assert_eq!(outcome(&f.call("alice", v, vec![case])), Some(3));
        assert_eq!(credentials::derivations(), before + 1);
    }
    // The failures consumed nothing: the right value still verifies once.
    let before = credentials::derivations();
    assert_eq!(
        outcome(&f.call("alice", v, vec![value("Fred", good.clone())])),
        None
    );
    assert_eq!(credentials::derivations(), before + 1);
    // Another principal's certificate cannot use Fred.
    let later = hashed("Fred", "password1", ts + 5, None);
    assert_eq!(outcome(&f.call("bob", v, vec![later])), Some(3));
}

#[test]
fn malformed_hashed_password_values_are_invalid_fields() {
    let mut f = Fixture::new();
    let ts = now_micros();
    let bytes = hashed_value(HashName::Sha256, "Fred", "password1", ts);
    for fields in [
        // Timestamp is a Date Time Extended, not a Date Time.
        vec![
            Node::text(USERNAME, "Fred"),
            Node::date(TIME_STAMP, ts / 1_000_000),
            Node::bytes(HASHED_PASSWORD, bytes.clone()),
        ],
        vec![
            Node::text(USERNAME, "Fred"),
            Node::bytes(HASHED_PASSWORD, bytes.clone()),
        ],
        vec![timestamp(ts), Node::bytes(HASHED_PASSWORD, bytes.clone())],
        vec![Node::text(USERNAME, "Fred"), timestamp(ts)],
    ] {
        assert_eq!(
            outcome(&f.call("alice", Version(2, 1), vec![credential(HASHED, fields)])),
            Some(7)
        );
    }
    // A field outside the table is refused as every unknown field is.
    let extra = vec![
        Node::text(USERNAME, "Fred"),
        timestamp(ts),
        Node::bytes(HASHED_PASSWORD, bytes.clone()),
        Node::text(PASSWORD, "password1"),
    ];
    assert_eq!(
        outcome(&f.call("alice", Version(2, 1), vec![credential(HASHED, extra)])),
        Some(8)
    );
    // Before 2.0 the Credential Type is undefined.
    for v in [Version(1, 2), Version(1, 4)] {
        assert_eq!(
            outcome(&f.call("alice", v, vec![hashed("Fred", "password1", ts, None)])),
            Some(7)
        );
    }
}

#[test]
fn hashed_password_precomputation_covers_the_evaluation() {
    let mut f = Fixture::new();
    let header = |credential: Node| {
        Node::structure(
            REQUEST_MESSAGE,
            vec![
                Node::structure(
                    REQUEST_HEADER,
                    vec![
                        Version(2, 1).node(),
                        Node::structure(AUTHENTICATION, vec![credential]),
                        Node::int(BATCH_COUNT, 1),
                    ],
                ),
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
        )
    };
    let step = fresh_step();
    for request in [
        header(hashed("Fred", "password1", now_micros(), None)),
        header(hashed("Wilma", "x", now_micros(), None)),
        header(otp("Fred", Some("password1"), &code(step))),
        header(otp("Wilma", Some("x"), "000000")),
    ] {
        let work = f.engine.credential_work("alice", &request, None);
        assert!(!work.is_empty());
        let done = work.run();
        let before = credentials::derivations();
        done.scope(|| f.engine.process("alice", &request).unwrap());
        assert_eq!(credentials::derivations(), before);
    }
}

#[test]
fn one_time_passwords_need_the_password_and_work_once() {
    for v in V2 {
        let mut f = Fixture::new();
        let step = fresh_step();
        // A right code with a wrong or missing Password fails and is not
        // consumed.
        for password in [Some("password2"), None, Some("")] {
            assert_eq!(
                outcome(&f.call("alice", v, vec![otp("Fred", password, &code(step))])),
                Some(3)
            );
        }
        let now = otp("Fred", Some("password1"), &code(step));
        assert_eq!(outcome(&f.call("alice", v, vec![now.clone()])), None);
        // "may only be used for a single authentication".
        assert_eq!(outcome(&f.call("alice", v, vec![now.clone()])), Some(3));
        // The previous step's code is older than the accepted one.
        assert_eq!(
            outcome(&f.call(
                "alice",
                v,
                vec![otp("Fred", Some("password1"), &code(step - 1))]
            )),
            Some(3)
        );
        // One step ahead is within the window; two are not.
        assert_eq!(
            outcome(&f.call(
                "alice",
                v,
                vec![otp("Fred", Some("password1"), &code(step + 2))]
            )),
            Some(3)
        );
        let next = otp("Fred", Some("password1"), &code(step + 1));
        assert_eq!(outcome(&f.call("alice", v, vec![next.clone()])), None);
        // A restart keeps the used steps.
        f.restart();
        assert_eq!(outcome(&f.call("alice", v, vec![next])), Some(3));
        assert_eq!(outcome(&f.call("alice", v, vec![now])), Some(3));
    }
}

#[test]
fn wrong_one_time_passwords_fail_alike_with_one_scrypt_evaluation() {
    let mut f = Fixture::new();
    let v = Version(2, 1);
    let step = fresh_step();
    let wrong = if code(step) == "000000" {
        "000001"
    } else {
        "000000"
    };
    for case in [
        otp("Fred", Some("password1"), wrong),
        otp("Fred", Some("password1"), &code(step - 2)),
        otp("Fred", Some("password1"), &code(step)[..5]),
        otp("Fred", Some("password2"), &code(step)),
        // A user without a seed (whose Password is right), and an unknown user.
        otp("Barney", Some("secret2"), &code(step)),
        otp("Wilma", Some("password1"), &code(step)),
    ] {
        let before = credentials::derivations();
        assert_eq!(outcome(&f.call("alice", v, vec![case])), Some(3));
        assert_eq!(credentials::derivations(), before + 1);
    }
    assert_eq!(
        outcome(&f.call("bob", v, vec![otp("Fred", Some("password1"), &code(step))])),
        Some(3)
    );
    // Malformed values are Invalid Field; before 2.0 the type is undefined.
    for fields in [
        vec![
            Node::text(USERNAME, "Fred"),
            Node::text(PASSWORD, "password1"),
        ],
        vec![
            Node::text(PASSWORD, "password1"),
            Node::text(ONE_TIME_PASSWORD, code(step)),
        ],
        vec![
            Node::text(USERNAME, "Fred"),
            Node::text(PASSWORD, "password1"),
            Node::bytes(ONE_TIME_PASSWORD, code(step).into_bytes()),
        ],
    ] {
        assert_eq!(
            outcome(&f.call("alice", v, vec![credential(OTP, fields)])),
            Some(7)
        );
    }
    assert_eq!(
        outcome(&f.call(
            "alice",
            Version(1, 4),
            vec![otp("Fred", Some("password1"), &code(step))]
        )),
        Some(7)
    );
    // The right credential still works after all of that.
    assert_eq!(
        outcome(&f.call(
            "alice",
            v,
            vec![otp("Fred", Some("password1"), &code(step))]
        )),
        None
    );
}

#[test]
fn combined_credentials_must_name_one_user_and_attestation_stays_refused() {
    let mut f = Fixture::new();
    let v = Version(2, 1);
    let step = fresh_step();
    let password = credential(
        1,
        vec![
            Node::text(USERNAME, "Fred"),
            Node::text(PASSWORD, "password1"),
        ],
    );
    // "If multiple Credential structures are provided then they must ALL be
    // satisfied": one user proved three ways.
    let response = f.call(
        "alice",
        v,
        vec![
            password.clone(),
            otp("Fred", Some("password1"), &code(step)),
            hashed("Fred", "password1", now_micros(), None),
        ],
    );
    assert_eq!(outcome(&response), None);
    // Different users, or one failing credential, fail the message.
    let barney = credential(
        1,
        vec![
            Node::text(USERNAME, "Barney"),
            Node::text(PASSWORD, "secret2"),
        ],
    );
    assert_eq!(
        outcome(&f.call(
            "alice",
            v,
            vec![barney, hashed("Fred", "password1", now_micros(), None)]
        )),
        Some(3)
    );
    assert_eq!(
        outcome(&f.call(
            "alice",
            v,
            vec![password, hashed("Fred", "password9", now_micros(), None)]
        )),
        Some(3)
    );
    // Attestation (1.2+) has no verification procedure here.
    let attestation = credential(
        3,
        vec![
            Node::structure(
                NONCE,
                vec![
                    Node::bytes(NONCE_ID, vec![1]),
                    Node::bytes(NONCE_VALUE, vec![2; 16]),
                ],
            ),
            Node::enumeration(ATTESTATION_TYPE, 1),
            Node::bytes(ATTESTATION_MEASUREMENT, vec![3; 32]),
        ],
    );
    for v in [Version(1, 2), Version(1, 4), Version(2, 0), Version(2, 1)] {
        assert_eq!(
            outcome(&f.call("alice", v, vec![attestation.clone()])),
            Some(8)
        );
    }
}

#[test]
fn draft_3_0_verifies_the_same_credential_values() {
    let mut f = Fixture::with_v3(true);
    let v = Version(3, 0);
    let step = fresh_step();
    assert_eq!(
        outcome(&f.call(
            "alice",
            v,
            vec![hashed("Fred", "password1", now_micros(), None)]
        )),
        None
    );
    assert_eq!(
        outcome(&f.call(
            "alice",
            v,
            vec![otp("Fred", Some("password1"), &code(step))]
        )),
        None
    );
}

#[test]
fn master_key_rotation_keeps_the_replay_counters() {
    let mut f = Fixture::new();
    let v = Version(2, 1);
    let used = hashed("Fred", "password1", now_micros(), None);
    assert_eq!(outcome(&f.call("alice", v, vec![used.clone()])), None);
    let dir = f.dir.path();
    let key = dir.join("master2");
    std::fs::write(&key, [7; 32]).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    let rotated = dir.join("rotated.sqlite");
    f.engine.store.rotate_master_key(&key, &rotated).unwrap();
    let mut engine = Engine::new(Store::open(&rotated, &key).unwrap(), false);
    engine.add_policy_users("alice", users()).unwrap();
    f.engine = engine;
    assert_eq!(outcome(&f.call("alice", v, vec![used])), Some(3));
}
