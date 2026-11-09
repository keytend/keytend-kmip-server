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

//! Shared fixture for the Login, Logout and Delegated Login tests
//! (tests/tickets.rs, tests/delegation.rs).
#![allow(dead_code)]
use keytend_kmip_server::{
    credentials::{PasswordVerifier, PolicyDevice, PolicyUser},
    protocol::{Engine, Version},
    store::Store,
    tags::*,
    ttlv::Node,
};

pub const V20: Version = Version(2, 0);
pub const V21: Version = Version(2, 1);
pub const V3: Version = Version(3, 0);
pub const V14: Version = Version(1, 4);

pub const CREATE: u32 = 1;
pub const LOCATE: u32 = 8;
pub const GET: u32 = 10;
pub const DESTROY: u32 = 20;
pub const QUERY: u32 = 24;
pub const POLL: u32 = 26;
pub const LOGIN: u32 = 45;
pub const LOGOUT: u32 = 46;
pub const DELEGATED_LOGIN: u32 = 47;
pub const PROCESS: u32 = 58;

pub const MANDATORY: u32 = 1;
pub const OPTIONAL: u32 = 2;
pub const UNDO: u32 = 3;

pub struct Fixture {
    pub dir: tempfile::TempDir,
    pub engine: Engine,
}
impl Fixture {
    /// alice has the users Fred and Barney and the device meter; bob has
    /// none. Draft 3.0 is enabled.
    pub fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let key = dir.path().join("master");
        std::fs::write(&key, [5; 32]).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        let store = Store::open(&dir.path().join("keys.sqlite"), &key).unwrap();
        let mut engine = Engine::new(store, true);
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
        Self { dir, engine }
    }
    /// One request message; `header` adds header fields (Asynchronous
    /// Indicator, Batch Error Continuation Option).
    pub fn send_with(
        &mut self,
        owner: &str,
        allowed: Option<&[u32]>,
        v: Version,
        header: Vec<Node>,
        auth: Option<Node>,
        items: Vec<(u32, Vec<Node>)>,
    ) -> Vec<Node> {
        let request = request(v, header, auth, items);
        let r = self
            .engine
            .process_authorized(owner, &request, allowed)
            .unwrap();
        r.all(BATCH_ITEM).cloned().collect()
    }
    pub fn send(
        &mut self,
        owner: &str,
        v: Version,
        auth: Option<Node>,
        items: Vec<(u32, Vec<Node>)>,
    ) -> Vec<Node> {
        self.send_with(owner, None, v, vec![], auth, items)
    }
    pub fn one(
        &mut self,
        owner: &str,
        v: Version,
        auth: Option<Node>,
        op: u32,
        payload: Vec<Node>,
    ) -> Node {
        let mut r = self.send(owner, v, auth, vec![(op, payload)]);
        assert_eq!(r.len(), 1);
        r.remove(0)
    }
    /// Login (no request credentials unless `auth`), returning the Ticket.
    pub fn login(&mut self, v: Version, auth: Option<Node>, payload: Vec<Node>) -> Node {
        let item = self.one("alice", v, auth, LOGIN, payload);
        ticket(&item)
    }
    /// A 256-bit AES key owned by `owner`, with the Name `name`.
    pub fn key(&mut self, owner: &str, v: Version, name: &str) -> String {
        let item = self.one(owner, v, None, CREATE, aes(v, name));
        uid(&item)
    }
    /// The audit principals recorded so far, oldest first.
    pub fn audit_principals(&self) -> Vec<String> {
        let db = rusqlite::Connection::open(self.dir.path().join("keys.sqlite")).unwrap();
        let mut statement = db
            .prepare("SELECT principal FROM audit ORDER BY seq")
            .unwrap();
        statement
            .query_map([], |row| row.get::<_, String>(0))
            .unwrap()
            .map(Result::unwrap)
            .collect()
    }
}

pub fn request(
    v: Version,
    header: Vec<Node>,
    auth: Option<Node>,
    items: Vec<(u32, Vec<Node>)>,
) -> Node {
    let mut fields = vec![v.node()];
    fields.extend(header);
    if v.0 < 3 {
        fields.push(Node::int(BATCH_COUNT, items.len() as i32));
    }
    fields.extend(auth);
    let many = items.len() > 1;
    let mut message = vec![Node::structure(REQUEST_HEADER, fields)];
    for (index, (op, payload)) in items.into_iter().enumerate() {
        let mut item = vec![Node::enumeration(OPERATION, op)];
        if many && v.0 < 3 {
            item.push(Node::bytes(UNIQUE_BATCH_ITEM_ID, vec![index as u8]));
        }
        item.push(Node::structure(REQUEST_PAYLOAD, payload));
        message.push(Node::structure(BATCH_ITEM, item));
    }
    Node::structure(REQUEST_MESSAGE, message)
}
pub fn asynchronous(mode: u32) -> Vec<Node> {
    vec![Node::enumeration(ASYNCHRONOUS_INDICATOR, mode)]
}
pub fn continuation(option: u32) -> Vec<Node> {
    vec![Node::enumeration(BATCH_ERROR_CONTINUATION_OPTION, option)]
}

pub fn status(item: &Node) -> u32 {
    item.required(RESULT_STATUS).unwrap().number().unwrap()
}
/// The Result Reason of a failed item; panics on success.
pub fn reason(item: &Node) -> u32 {
    assert_ne!(status(item), 0, "expected a failure");
    item.required(RESULT_REASON).unwrap().number().unwrap()
}
pub fn payload(item: &Node) -> &Node {
    assert_eq!(
        status(item),
        0,
        "reason {:?} {:?}",
        item.get(RESULT_REASON).and_then(|n| n.number().ok()),
        item.get(RESULT_MESSAGE).and_then(|n| n.string().ok())
    );
    item.required(RESPONSE_PAYLOAD).unwrap()
}
pub fn uid(item: &Node) -> String {
    payload(item)
        .required(UNIQUE_IDENTIFIER)
        .unwrap()
        .identifier_text()
        .unwrap()
        .to_owned()
}
pub fn ticket(item: &Node) -> Node {
    payload(item).required(TICKET).unwrap().clone()
}
/// Whether a successful or undone Get response carries key material.
pub fn has_key_material(item: &Node) -> bool {
    item.get(RESPONSE_PAYLOAD)
        .and_then(|p| p.get(SYMMETRIC_KEY))
        .is_some()
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
pub fn auth(credentials: Vec<Node>) -> Option<Node> {
    Some(Node::structure(AUTHENTICATION, credentials))
}
pub fn password(user: &str, password: &str) -> Node {
    credential(
        1,
        vec![Node::text(USERNAME, user), Node::text(PASSWORD, password)],
    )
}
pub fn meter() -> Node {
    credential(
        2,
        vec![
            Node::text(DEVICE_SERIAL_NUMBER, "serNum1"),
            Node::text(PASSWORD, "meter"),
        ],
    )
}
pub fn ticket_credential(ticket: &Node) -> Node {
    credential(6, vec![ticket.clone()])
}
pub fn by_ticket(ticket: &Node) -> Option<Node> {
    auth(vec![ticket_credential(ticket)])
}

pub fn identifier(v: Version, id: &str) -> Node {
    if v.0 >= 3 {
        Node::identifier(UNIQUE_IDENTIFIER, id)
    } else {
        Node::text(UNIQUE_IDENTIFIER, id)
    }
}
pub fn get(v: Version, id: &str) -> Vec<Node> {
    vec![identifier(v, id)]
}
pub fn aes(v: Version, name: &str) -> Vec<Node> {
    let name = if v.0 >= 3 {
        Node::text(NAME, name)
    } else {
        Node::structure(
            NAME,
            vec![
                Node::text(NAME_VALUE, name),
                Node::enumeration(NAME_TYPE, 1),
            ],
        )
    };
    vec![
        Node::enumeration(OBJECT_TYPE, 2),
        Node::structure(
            ATTRIBUTES,
            vec![
                Node::enumeration(CRYPTOGRAPHIC_ALGORITHM, 3),
                Node::int(CRYPTOGRAPHIC_LENGTH, 256),
                Node::int(CRYPTOGRAPHIC_USAGE_MASK, 12),
                name,
            ],
        ),
    ]
}
/// Locate by Name (2.x encoding).
pub fn locate_name(name: &str) -> Vec<Node> {
    vec![Node::structure(
        ATTRIBUTES,
        vec![Node::structure(
            NAME,
            vec![
                Node::text(NAME_VALUE, name),
                Node::enumeration(NAME_TYPE, 1),
            ],
        )],
    )]
}
/// Usage Limits with Unit Object.
pub fn usage_limits(total: i64, count: i64) -> Node {
    Node::structure(
        USAGE_LIMITS,
        vec![
            Node::long(USAGE_LIMITS_TOTAL, total),
            Node::long(USAGE_LIMITS_COUNT, count),
            Node::enumeration(USAGE_LIMITS_UNIT, 2),
        ],
    )
}
/// One Right: Operations, Objects and optional Usage Limits.
pub fn right(operations: &[u32], objects: Vec<Node>, usage: Option<Node>) -> Node {
    let mut fields = vec![];
    fields.extend(usage);
    if !operations.is_empty() {
        fields.push(Node::structure(
            OPERATIONS,
            operations
                .iter()
                .map(|op| Node::enumeration(OPERATION, *op))
                .collect(),
        ));
    }
    if !objects.is_empty() {
        fields.push(Node::structure(OBJECTS, objects));
    }
    Node::structure(RIGHT, fields)
}
pub fn rights(rights: Vec<Node>) -> Vec<Node> {
    vec![Node::structure(RIGHTS, rights)]
}
