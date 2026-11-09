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

//! Credential identity (Profiles 2.0/2.1 section 3.1.3): with the policy
//! option, a verified user or device of a certificate principal is the client
//! identity, owns its objects and is authorized as itself. The default keeps
//! the certificate principal as the only identity.
use keytend_kmip_server::{
    authorization::ObjectGrant,
    credentials::{PasswordVerifier, PolicyDevice, PolicyUser},
    protocol::{Engine, Outbound, ServerToClient, Subscription, Version},
    store::Store,
    tags::*,
    ttlv::Node,
};
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

const V21: Version = Version(2, 1);
const V14: Version = Version(1, 4);
const V3: Version = Version(3, 0);

struct Fixture {
    _dir: tempfile::TempDir,
    engine: Engine,
    sent: Arc<Mutex<Vec<Outbound>>>,
}
fn fixture(credential_identity: bool) -> Fixture {
    let dir = tempfile::tempdir().unwrap();
    let key = dir.path().join("master");
    std::fs::write(&key, [4; 32]).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    let store = Store::open(&dir.path().join("keys.sqlite"), &key).unwrap();
    let sent = Arc::new(Mutex::new(vec![]));
    let sink = {
        let sent = sent.clone();
        Box::new(move |o: Outbound| {
            sent.lock().unwrap().push(o);
            true
        })
    };
    let subscriptions = HashMap::from([(
        "alice".to_owned(),
        Subscription {
            version: V21,
            notify: true,
            put: true,
        },
    )]);
    let mut engine = Engine::new(store, true)
        .with_server_to_client(ServerToClient::new(subscriptions, sink).unwrap());
    let user = |name: &str, password: &[u8]| PolicyUser {
        username: name.into(),
        password_scrypt: PasswordVerifier::new(password).unwrap(),
        // Both may create System Objects (system.rs administrators).
        administrator: true,
        hashed_password: None,
        one_time_password: None,
    };
    engine
        .add_policy_users(
            "alice",
            vec![user("Fred", b"fred"), user("Barney", b"barney")],
        )
        .unwrap();
    engine
        .add_policy_devices(
            "alice",
            vec![PolicyDevice {
                name: "meter".into(),
                device_serial_number: Some("serNum1".into()),
                device_identifier: None,
                network_identifier: None,
                machine_identifier: None,
                media_identifier: None,
                password_scrypt: PasswordVerifier::new(b"meter").unwrap(),
            }],
        )
        .unwrap();
    if credential_identity {
        engine.use_credential_identity("alice");
    }
    Fixture {
        _dir: dir,
        engine,
        sent,
    }
}
fn credential(kind: u32, fields: Vec<Node>) -> Node {
    Node::structure(
        AUTHENTICATION,
        vec![Node::structure(
            CREDENTIAL,
            vec![
                Node::enumeration(CREDENTIAL_TYPE, kind),
                Node::structure(CREDENTIAL_VALUE, fields),
            ],
        )],
    )
}
fn user(name: &str) -> Option<Node> {
    Some(credential(
        1,
        vec![
            Node::text(USERNAME, name),
            Node::text(PASSWORD, name.to_lowercase()),
        ],
    ))
}
fn meter() -> Option<Node> {
    Some(credential(
        2,
        vec![
            Node::text(DEVICE_SERIAL_NUMBER, "serNum1"),
            Node::text(PASSWORD, "meter"),
        ],
    ))
}
impl Fixture {
    fn call_with(
        &mut self,
        owner: &str,
        v: Version,
        auth: Option<Node>,
        op: u32,
        payload: Vec<Node>,
        grants: &[ObjectGrant],
    ) -> Node {
        let mut header = vec![v.node()];
        header.extend(auth);
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
                        Node::structure(REQUEST_PAYLOAD, payload),
                    ],
                ),
            ],
        );
        let response = self
            .engine
            .process_with_grants(owner, &request, None, grants)
            .unwrap();
        response.required(BATCH_ITEM).unwrap().clone()
    }
    fn call(&mut self, owner: &str, v: Version, auth: Option<Node>, op: u32, p: Vec<Node>) -> Node {
        self.call_with(owner, v, auth, op, p, &[])
    }
    fn create(&mut self, v: Version, auth: Option<Node>) -> String {
        let attrs = vec![
            (
                CRYPTOGRAPHIC_ALGORITHM,
                Node::enumeration(CRYPTOGRAPHIC_ALGORITHM, 3),
            ),
            (CRYPTOGRAPHIC_LENGTH, Node::int(CRYPTOGRAPHIC_LENGTH, 256)),
            (
                CRYPTOGRAPHIC_USAGE_MASK,
                Node::int(CRYPTOGRAPHIC_USAGE_MASK, 12),
            ),
        ];
        let container = if v.0 >= 2 {
            Node::structure(ATTRIBUTES, attrs.into_iter().map(|(_, a)| a).collect())
        } else {
            Node::structure(
                TEMPLATE_ATTRIBUTE,
                attrs
                    .into_iter()
                    .map(|(tag, mut a)| {
                        a.tag = ATTRIBUTE_VALUE;
                        Node::structure(
                            ATTRIBUTE,
                            vec![Node::text(ATTRIBUTE_NAME, tag_name(tag).unwrap()), a],
                        )
                    })
                    .collect(),
            )
        };
        let item = self.call(
            "alice",
            v,
            auth,
            1,
            vec![Node::enumeration(OBJECT_TYPE, 2), container],
        );
        assert_eq!(status(&item), Ok(()));
        item.required(RESPONSE_PAYLOAD)
            .unwrap()
            .required(UNIQUE_IDENTIFIER)
            .unwrap()
            .identifier_text()
            .unwrap()
            .to_owned()
    }
    fn get(&mut self, v: Version, auth: Option<Node>, id: &str) -> Result<(), u32> {
        let id = if v.0 >= 3 {
            Node::identifier(UNIQUE_IDENTIFIER, id)
        } else {
            Node::text(UNIQUE_IDENTIFIER, id)
        };
        status(&self.call("alice", v, auth, 10, vec![id]))
    }
    fn locate(&mut self, v: Version, auth: Option<Node>) -> Vec<String> {
        let item = self.call("alice", v, auth, 8, vec![]);
        item.required(RESPONSE_PAYLOAD)
            .unwrap()
            .all(UNIQUE_IDENTIFIER)
            .map(|n| n.identifier_text().unwrap().to_owned())
            .collect()
    }
}
fn status(item: &Node) -> Result<(), u32> {
    match item.required(RESULT_STATUS).unwrap().number().unwrap() {
        0 => Ok(()),
        _ => Err(item.required(RESULT_REASON).unwrap().number().unwrap()),
    }
}

// REQ:profiles-2.0:54c6c9e8ff7fe236 credentials in the request determine the client identity
// REQ:profiles-2.1:54c6c9e8ff7fe236 credentials in the request determine the client identity
// REQ:profiles-2.1:19dd3478cabf78e7 without Authentication the channel identity is used
#[test]
fn verified_users_own_their_objects_when_the_principal_uses_credential_identity() {
    let mut f = fixture(true);
    for v in [V21, V14] {
        let fred = f.create(v, user("Fred"));
        assert_eq!(f.get(v, user("Fred"), &fred), Ok(()));
        // Not found for another user and for the bare certificate: Item Not
        // Found in 1.x, Object Not Found from 2.0 (docs/messages.md#unknown-identifiers).
        let missing = if v.0 >= 2 { 0x37 } else { 1 };
        assert_eq!(f.get(v, user("Barney"), &fred), Err(missing));
        assert_eq!(f.get(v, None, &fred), Err(missing));
        let channel = f.create(v, None);
        assert_eq!(f.get(v, user("Fred"), &channel), Err(missing));
        assert_eq!(f.get(v, None, &channel), Ok(()));
        assert!(f.locate(v, user("Fred")).contains(&fred));
        assert!(!f.locate(v, user("Fred")).contains(&channel));
        assert!(!f.locate(v, user("Barney")).contains(&fred));
        assert!(!f.locate(v, None).contains(&fred));
        // A device credential alone is its own identity.
        let device = f.create(v, meter());
        assert_eq!(f.get(v, meter(), &device), Ok(()));
        assert_eq!(f.get(v, user("Fred"), &device), Err(missing));
    }
    // Failed credentials still fail the message (Authentication Not Successful).
    assert_eq!(
        f.get(
            V21,
            Some(credential(
                1,
                vec![Node::text(USERNAME, "Fred"), Node::text(PASSWORD, "x")]
            )),
            "x"
        ),
        Err(3)
    );
}

#[test]
fn by_default_users_of_one_certificate_share_its_objects() {
    let mut f = fixture(false);
    let fred = f.create(V21, user("Fred"));
    assert_eq!(f.get(V21, user("Barney"), &fred), Ok(()));
    assert_eq!(f.get(V21, None, &fred), Ok(()));
}

#[test]
fn grants_can_name_a_credential_identity() {
    let mut f = fixture(true);
    let fred = f.create(V21, user("Fred"));
    let grant = |user: Option<&str>| ObjectGrant {
        owner: "alice".into(),
        user: user.map(Into::into),
        device: None,
        identifier: fred.clone(),
        operations: vec![8, 10],
    };
    let get = vec![Node::text(UNIQUE_IDENTIFIER, fred.clone())];
    // A grant on the principal does not reach its user's object.
    let item = f.call_with("bob", V21, None, 10, get.clone(), &[grant(None)]);
    assert_eq!(status(&item), Err(0x37));
    let item = f.call_with("bob", V21, None, 10, get, &[grant(Some("Fred"))]);
    assert_eq!(status(&item), Ok(()));
    let item = f.call_with("bob", V21, None, 8, vec![], &[grant(Some("Fred"))]);
    assert!(
        item.required(RESPONSE_PAYLOAD)
            .unwrap()
            .all(UNIQUE_IDENTIFIER)
            .any(|n| n.string().unwrap() == fred)
    );
}

#[test]
fn server_to_client_messages_of_users_go_to_the_principal_endpoint() {
    let mut f = fixture(true);
    let fred = f.create(V21, user("Fred"));
    let sent = std::mem::take(&mut *f.sent.lock().unwrap());
    assert_eq!(sent.len(), 1);
    assert_eq!(sent[0].endpoint, "alice");
    assert_eq!(sent[0].owner, "alice\0user\0Fred");
    assert_eq!(
        (sent[0].operation, sent[0].object.as_str()),
        (28, fred.as_str())
    );
    // Query advertises the principal's delivery to its users as well.
    let item = f.call(
        "alice",
        V21,
        user("Fred"),
        24,
        vec![Node::enumeration(QUERY_FUNCTION, 1)],
    );
    let ops = item
        .required(RESPONSE_PAYLOAD)
        .unwrap()
        .all(OPERATION)
        .map(|n| n.number().unwrap())
        .collect::<Vec<_>>();
    assert!(ops.contains(&27) && ops.contains(&28));
}

#[test]
fn draft_3_0_system_objects_and_tickets_stay_with_the_principal() {
    let mut f = fixture(true);
    // Login as Fred, then the ticket authenticates Fred: his identity again.
    let item = f.call("alice", V3, user("Fred"), 45, vec![]);
    assert_eq!(status(&item), Ok(()));
    let ticket = item
        .required(RESPONSE_PAYLOAD)
        .unwrap()
        .required(TICKET)
        .unwrap()
        .clone();
    let by_ticket = || Some(credential(6, vec![ticket.clone()]));
    let fred = f.create(V3, user("Fred"));
    assert_eq!(f.get(V3, by_ticket(), &fred), Ok(()));
    assert_eq!(f.get(V3, user("Barney"), &fred), Err(0x37));
    // A Group System Object created by Fred is visible to Barney's uniqueness
    // check: System Objects belong to the principal.
    let group = |name: &str| vec![Node::structure(ATTRIBUTES, vec![Node::text(NAME, name)])];
    let item = f.call("alice", V3, user("Fred"), 60, group("wilma"));
    assert_eq!(
        status(&item),
        Ok(()),
        "{}",
        serde_json::to_string(&item).unwrap()
    );
    assert_eq!(
        status(&f.call("alice", V3, user("Barney"), 60, group("wilma"))),
        Err(0x35)
    );
    // Logout with the principal identity finds Fred's ticket.
    assert_eq!(
        status(&f.call("alice", V3, None, 46, vec![ticket.clone()])),
        Ok(())
    );
}
