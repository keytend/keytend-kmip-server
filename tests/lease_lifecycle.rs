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

//! Obtain Lease by lifecycle state (`--lease-states`, src/protocol/lease.rs,
//! docs/lifecycle.md#leases) and the reasons of state-only refusals.
use keytend_kmip_server::{
    protocol::{Engine, LeaseStates, Version},
    store::Store,
    tags::*,
    ttlv::{Node, Value},
};

const VERSIONS: [Version; 8] = [
    Version(1, 0),
    Version(1, 1),
    Version(1, 2),
    Version(1, 3),
    Version(1, 4),
    Version(2, 0),
    Version(2, 1),
    Version(3, 0),
];
const PERMISSION_DENIED: u32 = 12;
const WRONG_KEY_LIFECYCLE_STATE: u32 = 0x43;

struct Fixture {
    _dir: tempfile::TempDir,
    engine: Engine,
}
impl Fixture {
    fn new(states: LeaseStates, maximum: u32) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let key = dir.path().join("master");
        std::fs::write(&key, [42; 32]).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        let store = Store::open(&dir.path().join("keys.sqlite"), &key).unwrap();
        let engine = Engine::new(store, true)
            .with_lease_states(states)
            .with_maximum_lease(maximum);
        Self { _dir: dir, engine }
    }
    fn call(&mut self, v: Version, op: u32, fields: Vec<Node>) -> Node {
        let mut header = vec![v.node()];
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
                        Node::enumeration(OPERATION, op),
                        Node::structure(REQUEST_PAYLOAD, fields),
                    ],
                ),
            ],
        );
        self.engine
            .process("alice", &request)
            .unwrap()
            .required(BATCH_ITEM)
            .unwrap()
            .clone()
    }
    fn ok(&mut self, v: Version, op: u32, fields: Vec<Node>) -> Node {
        payload(&self.call(v, op, fields)).clone()
    }
    /// An AES key allowed to Encrypt and Decrypt, with extra attributes.
    fn create(&mut self, v: Version, extra: Vec<Node>) -> String {
        let mut attrs = vec![
            Node::enumeration(CRYPTOGRAPHIC_ALGORITHM, 3),
            Node::int(CRYPTOGRAPHIC_LENGTH, 128),
            Node::int(CRYPTOGRAPHIC_USAGE_MASK, 12),
        ];
        attrs.extend(extra);
        let container = if v.0 >= 2 {
            Node::structure(ATTRIBUTES, attrs)
        } else {
            Node::structure(TEMPLATE_ATTRIBUTE, attrs.into_iter().map(legacy).collect())
        };
        let p = self.ok(v, 1, vec![Node::enumeration(OBJECT_TYPE, 2), container]);
        p.required(UNIQUE_IDENTIFIER)
            .unwrap()
            .identifier_text()
            .unwrap()
            .to_owned()
    }
    fn lease(&mut self, v: Version, id: &str) -> Node {
        self.call(v, 16, vec![uid(v, id)])
    }
    /// Active to Deactivated: Revoke with a reason other than a compromise
    /// (1.x/2.x), draft 3.0 Deactivate (a 3.0 Revoke always compromises).
    fn deactivate(&mut self, v: Version, id: &str) {
        if v.0 >= 3 {
            self.ok(v, 64, vec![uid(v, id)]);
        } else {
            self.ok(v, 19, vec![uid(v, id), revocation(1)]);
        }
    }
    fn compromise(&mut self, v: Version, id: &str) {
        self.ok(
            v,
            19,
            vec![
                uid(v, id),
                revocation(2),
                Node::date(COMPROMISE_OCCURRENCE_DATE, 2),
            ],
        );
    }
    fn state(&self, id: &str) -> u32 {
        self.engine.store.get("alice", id).unwrap().unwrap().state
    }
}
fn legacy(mut n: Node) -> Node {
    let name = tag_name(n.tag).unwrap();
    n.tag = ATTRIBUTE_VALUE;
    Node::structure(ATTRIBUTE, vec![Node::text(ATTRIBUTE_NAME, name), n])
}
fn uid(v: Version, id: &str) -> Node {
    if v.0 >= 3 {
        Node::reference(UNIQUE_IDENTIFIER, id)
    } else {
        Node::text(UNIQUE_IDENTIFIER, id)
    }
}
fn revocation(code: u32) -> Node {
    Node::structure(
        REVOCATION_REASON,
        vec![Node::enumeration(REVOCATION_REASON_CODE, code)],
    )
}
fn payload(item: &Node) -> &Node {
    assert_eq!(
        item.required(RESULT_STATUS).unwrap().number().unwrap(),
        0,
        "reason {:?} {:?}",
        item.get(RESULT_REASON).and_then(|n| n.number().ok()),
        item.get(RESULT_MESSAGE).and_then(|n| n.string().ok())
    );
    item.required(RESPONSE_PAYLOAD).unwrap()
}
fn refusal(item: &Node) -> (u32, String) {
    assert_eq!(item.required(RESULT_STATUS).unwrap().number().unwrap(), 1);
    (
        item.required(RESULT_REASON).unwrap().number().unwrap(),
        item.required(RESULT_MESSAGE)
            .unwrap()
            .string()
            .unwrap()
            .to_owned(),
    )
}
fn granted(item: &Node) -> u32 {
    match payload(item).required(LEASE_TIME).unwrap().value {
        Value::Interval(seconds) => seconds,
        _ => panic!("Lease Time must be an Interval"),
    }
}
fn cbc() -> Node {
    Node::structure(
        CRYPTOGRAPHIC_PARAMETERS,
        vec![
            Node::enumeration(BLOCK_CIPHER_MODE, 1),
            Node::enumeration(PADDING_METHOD, 3),
        ],
    )
}
fn encrypt(f: &mut Fixture, v: Version, id: &str) -> Node {
    f.call(
        v,
        31,
        vec![
            uid(v, id),
            cbc(),
            Node::bytes(DATA, b"protected record".to_vec()),
            Node::bytes(IV_COUNTER_NONCE, vec![9; 16]),
        ],
    )
}
fn decrypt(f: &mut Fixture, v: Version, id: &str, data: Vec<u8>) -> Node {
    f.call(
        v,
        32,
        vec![
            uid(v, id),
            cbc(),
            Node::bytes(DATA, data),
            Node::bytes(IV_COUNTER_NONCE, vec![9; 16]),
        ],
    )
}
fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

/// A Deactivated key is leased by default, and with the lease it still
/// decrypts while the server keeps refusing encryption (State: 1.4 section
/// 3.22, 2.1 section 4.57). `--lease-states active` refuses it, Permission
/// Denied in every edition (1.4 Table 344, 2.1 Table 270, 3.0 Table 379).
#[test]
fn deactivated_objects_are_leased_by_default_and_refused_when_only_active_is_set() {
    for v in VERSIONS {
        for states in [LeaseStates::ActiveDeactivated, LeaseStates::Active] {
            let mut f = Fixture::new(states, 3600);
            let key = f.create(v, vec![]);
            f.ok(v, 18, vec![uid(v, &key)]);
            assert_eq!(granted(&f.lease(v, &key)), 3600, "{v:?} Active");
            let crypto = v >= Version(1, 2);
            let cipher = crypto.then(|| {
                payload(&encrypt(&mut f, v, &key))
                    .required(DATA)
                    .unwrap()
                    .byte_string()
                    .unwrap()
                    .to_vec()
            });
            f.deactivate(v, &key);
            assert_eq!(f.state(&key), 3);
            let lease = f.lease(v, &key);
            if states == LeaseStates::ActiveDeactivated {
                assert_eq!(granted(&lease), 3600, "{v:?} Deactivated");
                // Check judges a requested lease by the same rule.
                let check = vec![uid(v, &key), Node::interval(LEASE_TIME, 600)];
                payload(&f.call(v, 9, check));
            } else {
                assert_eq!(
                    refusal(&lease),
                    (
                        PERMISSION_DENIED,
                        "A Deactivated object cannot receive a lease (server lease policy: Active objects only)"
                            .to_owned()
                    ),
                    "{v:?}"
                );
                let check = vec![uid(v, &key), Node::interval(LEASE_TIME, 600)];
                assert_eq!(refusal(&f.call(v, 9, check)).0, PERMISSION_DENIED);
            }
            if let Some(cipher) = cipher {
                let plain = decrypt(&mut f, v, &key, cipher);
                assert_eq!(
                    payload(&plain)
                        .required(DATA)
                        .unwrap()
                        .byte_string()
                        .unwrap(),
                    b"protected record",
                    "{v:?} a Deactivated key still decrypts"
                );
                let (reason, _) = refusal(&encrypt(&mut f, v, &key));
                let expected = if v.0 >= 2 {
                    WRONG_KEY_LIFECYCLE_STATE
                } else {
                    PERMISSION_DENIED
                };
                assert_eq!(reason, expected, "{v:?} a Deactivated key never encrypts");
            }
        }
    }
}

/// Pre-Active, Compromised and Destroyed objects are refused in both
/// settings, with Permission Denied and a message naming the state.
#[test]
fn pre_active_compromised_and_destroyed_objects_are_refused_by_state() {
    for v in VERSIONS {
        for states in [LeaseStates::ActiveDeactivated, LeaseStates::Active] {
            let mut f = Fixture::new(states, 3600);
            let key = f.create(v, vec![]);
            assert_eq!(
                refusal(&f.lease(v, &key)),
                (
                    PERMISSION_DENIED,
                    "A Pre-Active object cannot receive a lease".to_owned()
                ),
                "{v:?}"
            );
            f.ok(v, 18, vec![uid(v, &key)]);
            f.compromise(v, &key);
            assert_eq!(f.state(&key), 4);
            assert_eq!(
                refusal(&f.lease(v, &key)),
                (
                    PERMISSION_DENIED,
                    "A Compromised object cannot receive a lease".to_owned()
                ),
                "{v:?}"
            );
            let other = f.create(v, vec![]);
            f.ok(v, 20, vec![uid(v, &other)]);
            assert_eq!(
                refusal(&f.lease(v, &other)),
                (
                    PERMISSION_DENIED,
                    "A Destroyed object cannot receive a lease".to_owned()
                ),
                "{v:?}"
            );
        }
    }
}

/// An Active lease ends where the permitted use narrows (Protect Stop Date,
/// Deactivation Date); a Deactivated lease has no such date (KMIP defines no
/// end of processing) and is bounded by the stored Lease Time alone.
#[test]
fn lease_length_follows_the_lifecycle_dates() {
    for v in VERSIONS {
        let mut f = Fixture::new(LeaseStates::ActiveDeactivated, 120);
        let soon = now() + 60;
        let key = f.create(v, vec![Node::date(DEACTIVATION_DATE, soon)]);
        f.ok(v, 18, vec![uid(v, &key)]);
        let lease = granted(&f.lease(v, &key));
        assert!((55..=60).contains(&lease), "{v:?} {lease}");
        // Protect Stop Date before the Deactivation Date bounds it first.
        let key = f.create(
            v,
            vec![
                Node::date(PROTECT_STOP_DATE, now() + 30),
                Node::date(DEACTIVATION_DATE, now() + 90),
            ],
        );
        f.ok(v, 18, vec![uid(v, &key)]);
        let lease = granted(&f.lease(v, &key));
        assert!((25..=30).contains(&lease), "{v:?} {lease}");
        // Deactivated: the stored maximum, whatever the dates.
        f.deactivate(v, &key);
        assert_eq!(granted(&f.lease(v, &key)), 120, "{v:?}");
    }
}

/// An Active key past its Protect Stop Date may still process data until its
/// Deactivation Date: the default setting leases it up to that date, while
/// `active` keeps the rc.4 refusal. A Deactivated key before its Process
/// Start Date may not be used at all and is refused in either setting.
#[test]
fn passed_and_future_usage_dates() {
    for v in VERSIONS {
        for states in [LeaseStates::ActiveDeactivated, LeaseStates::Active] {
            let mut f = Fixture::new(states, 3600);
            let start = now() - 10;
            let key = f.create(
                v,
                vec![
                    Node::date(ACTIVATION_DATE, start),
                    Node::date(PROTECT_STOP_DATE, start),
                    Node::date(DEACTIVATION_DATE, now() + 100),
                ],
            );
            assert_eq!(f.state(&key), 2, "{v:?}");
            let lease = f.lease(v, &key);
            if states == LeaseStates::ActiveDeactivated {
                let lease = granted(&lease);
                assert!((95..=100).contains(&lease), "{v:?} {lease}");
            } else {
                assert_eq!(
                    refusal(&lease),
                    (
                        PERMISSION_DENIED,
                        "The object's Protect Stop Date has passed".to_owned()
                    ),
                    "{v:?}"
                );
            }

            let key = f.create(
                v,
                vec![
                    Node::date(ACTIVATION_DATE, start),
                    Node::date(PROCESS_START_DATE, now() + 1000),
                ],
            );
            f.deactivate(v, &key);
            let expected = if states == LeaseStates::ActiveDeactivated {
                "The object cannot be used before its Process Start Date"
            } else {
                "A Deactivated object cannot receive a lease (server lease policy: Active objects only)"
            };
            assert_eq!(
                refusal(&f.lease(v, &key)),
                (PERMISSION_DENIED, expected.to_owned()),
                "{v:?}"
            );
        }
    }
}

/// With a Lease Time of zero (`--max-lease-seconds 0`) Obtain Lease
/// returns zero, "no lease interval is effective" (1.4 section 4.17, 2.1
/// section 6.1.35), for Active and Deactivated objects; a lifecycle date
/// ahead still bounds an Active lease.
#[test]
fn zero_lease_time_is_no_lease_limit() {
    for v in VERSIONS {
        let mut f = Fixture::new(LeaseStates::ActiveDeactivated, 0);
        let key = f.create(v, vec![]);
        f.ok(v, 18, vec![uid(v, &key)]);
        assert_eq!(granted(&f.lease(v, &key)), 0, "{v:?}");
        f.deactivate(v, &key);
        assert_eq!(granted(&f.lease(v, &key)), 0, "{v:?}");
        let dated = f.create(v, vec![Node::date(DEACTIVATION_DATE, now() + 60)]);
        f.ok(v, 18, vec![uid(v, &dated)]);
        let lease = granted(&f.lease(v, &dated));
        assert!((55..=60).contains(&lease), "{v:?} {lease}");
    }
}

/// Revoke, draft 3.0 Deactivate and Activate refusals caused only by the
/// lifecycle state are Wrong Key Lifecycle State from 2.0 (2.0 Table 271 and
/// 2.1 Table 297 Revoke, 3.0 Table 295 Deactivate, 2.0 Table 151 Activate).
/// The 1.x tables have no lifecycle reason for them: Activate is Permission
/// Denied (1.4 Table 346) and Revoke keeps Permission Denied.
#[test]
fn state_only_lifecycle_refusals_are_wrong_key_lifecycle_state_from_2_0() {
    for v in VERSIONS {
        let mut f = Fixture::new(LeaseStates::ActiveDeactivated, 3600);
        let expected = if v.0 >= 2 {
            WRONG_KEY_LIFECYCLE_STATE
        } else {
            PERMISSION_DENIED
        };
        let key = f.create(v, vec![]);
        if v.0 >= 3 {
            let (reason, _) = refusal(&f.call(v, 64, vec![uid(v, &key)]));
            assert_eq!(reason, expected, "Deactivate of a Pre-Active object");
        }
        f.ok(v, 18, vec![uid(v, &key)]);
        let (reason, _) = refusal(&f.call(v, 18, vec![uid(v, &key)]));
        assert_eq!(reason, expected, "{v:?} Activate of an Active object");
        f.deactivate(v, &key);
        let again = if v.0 >= 3 {
            f.call(v, 64, vec![uid(v, &key)])
        } else {
            f.call(v, 19, vec![uid(v, &key), revocation(1)])
        };
        assert_eq!(
            refusal(&again),
            (
                expected,
                if v.0 >= 3 {
                    "Deactivate requires an Active object"
                } else {
                    "Revoke is not permitted in this lifecycle state"
                }
                .to_owned()
            ),
            "{v:?} repeated deactivation"
        );
    }
}

/// docs/clients.md: a Destroyed key has no Key Value, so Decrypt fails with
/// Key Value Not Present before any lifecycle check.
#[test]
fn destroyed_keys_have_no_key_value_for_decryption() {
    for v in VERSIONS.into_iter().filter(|v| *v >= Version(1, 2)) {
        let mut f = Fixture::new(LeaseStates::ActiveDeactivated, 3600);
        let key = f.create(v, vec![]);
        f.ok(v, 20, vec![uid(v, &key)]);
        let (reason, _) = refusal(&decrypt(&mut f, v, &key, vec![0; 16]));
        assert_eq!(reason, 0x13, "{v:?}");
    }
}
