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

// KMIP 2.x Log, the PKCS#11 operation subset, and the Protection Level,
// Protection Period and Quantum Safe attributes.

use keytend_kmip_server::{
    protocol::{Engine, Version},
    store::Store,
    tags::*,
    ttlv::{Node, Value},
};

const CREATE: u32 = 1;
const CREATE_KEY_PAIR: u32 = 2;
const LOCATE: u32 = 8;
const GET_ATTRIBUTES: u32 = 11;
const ADD_ATTRIBUTE: u32 = 13;
const DELETE_ATTRIBUTE: u32 = 15;
const LOG: u32 = 0x2c;
const SET_ATTRIBUTE: u32 = 0x31;
const PKCS11: u32 = 0x33;
const C_INITIALIZE: u32 = 1;
const C_FINALIZE: u32 = 2;
const C_GET_INFO: u32 = 3;
const C_ENCRYPT: u32 = 31;

struct Fixture {
    engine: Engine,
    _directory: tempfile::TempDir,
}
impl Fixture {
    fn new() -> Self {
        let directory = tempfile::tempdir().unwrap();
        let master = directory.path().join("master");
        std::fs::write(&master, [5; 32]).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&master, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        let store = Store::open(&directory.path().join("store.sqlite"), &master).unwrap();
        Self {
            engine: Engine::new(store, true),
            _directory: directory,
        }
    }
    fn batch(
        &mut self,
        owner: &str,
        v: Version,
        header: Vec<Node>,
        items: Vec<(u32, Vec<Node>)>,
    ) -> Vec<Node> {
        let mut fields = vec![v.node()];
        fields.extend(header);
        if v.0 < 3 {
            fields.push(Node::int(BATCH_COUNT, items.len() as i32));
        }
        let mut message = vec![Node::structure(REQUEST_HEADER, fields)];
        for (index, (op, payload)) in items.into_iter().enumerate() {
            let mut item = vec![Node::enumeration(OPERATION, op)];
            if v.0 < 3 {
                item.push(Node::bytes(UNIQUE_BATCH_ITEM_ID, vec![index as u8]));
            }
            item.push(Node::structure(REQUEST_PAYLOAD, payload));
            message.push(Node::structure(BATCH_ITEM, item));
        }
        self.engine
            .process(owner, &Node::structure(REQUEST_MESSAGE, message))
            .unwrap()
            .all(BATCH_ITEM)
            .cloned()
            .collect()
    }
    fn one(&mut self, owner: &str, v: Version, op: u32, payload: Vec<Node>) -> Node {
        self.batch(owner, v, vec![], vec![(op, payload)]).remove(0)
    }
}
fn status(item: &Node) -> u32 {
    item.required(RESULT_STATUS).unwrap().number().unwrap()
}
fn reason(item: &Node) -> u32 {
    assert_eq!(status(item), 1);
    item.required(RESULT_REASON).unwrap().number().unwrap()
}
fn payload(item: &Node) -> &Node {
    assert_eq!(status(item), 0);
    item.required(RESPONSE_PAYLOAD).unwrap()
}

#[test]
fn log_accepts_bounded_messages_from_two_x() {
    let mut f = Fixture::new();
    for v in [Version(2, 0), Version(2, 1), Version(3, 0)] {
        let item = f.one(
            "alice",
            v,
            LOG,
            vec![Node::text(
                LOG_MESSAGE,
                "Registered a symmetric key.\nforged",
            )],
        );
        assert!(payload(&item).children().unwrap().is_empty());
        assert_eq!(
            reason(&f.one(
                "alice",
                v,
                LOG,
                vec![Node::text(LOG_MESSAGE, "x".repeat(4097))]
            )),
            7
        );
        assert_eq!(reason(&f.one("alice", v, LOG, vec![])), 7);
        assert_eq!(
            reason(&f.one(
                "alice",
                v,
                LOG,
                vec![Node::text(LOG_MESSAGE, "a"), Node::int(DATA_LENGTH, 1)]
            )),
            8
        );
    }
    // Log does not exist before 2.0.
    assert_eq!(
        reason(&f.one(
            "alice",
            Version(1, 4),
            LOG,
            vec![Node::text(LOG_MESSAGE, "a")]
        )),
        5
    );
    // A Log item under Undo is reported Undone with its batch.
    let items = f.batch(
        "alice",
        Version(2, 1),
        vec![Node::enumeration(BATCH_ERROR_CONTINUATION_OPTION, 3)],
        vec![
            (LOG, vec![Node::text(LOG_MESSAGE, "undone")]),
            (LOG, vec![]),
        ],
    );
    assert_eq!(items.iter().map(status).collect::<Vec<_>>(), [3, 1]);
    // Denied by the principal's operation policy.
    let fields = vec![Version(2, 1).node(), Node::int(BATCH_COUNT, 1)];
    let request = Node::structure(
        REQUEST_MESSAGE,
        vec![
            Node::structure(REQUEST_HEADER, fields),
            Node::structure(
                BATCH_ITEM,
                vec![
                    Node::enumeration(OPERATION, LOG),
                    Node::structure(REQUEST_PAYLOAD, vec![Node::text(LOG_MESSAGE, "a")]),
                ],
            ),
        ],
    );
    let r = f
        .engine
        .process_authorized("alice", &request, Some(&[24]))
        .unwrap();
    assert_eq!(reason(r.get(BATCH_ITEM).unwrap()), 12);
    f.engine.store.verify_audit().unwrap();
}

fn pkcs11(function: u32, handle: Option<&[u8]>, input: Option<&[u8]>) -> Vec<Node> {
    let mut p = vec![Node::enumeration(PKCS_11_FUNCTION, function)];
    if let Some(handle) = handle {
        p.push(Node::bytes(CORRELATION_VALUE, handle.to_vec()));
    }
    if let Some(input) = input {
        p.push(Node::bytes(PKCS_11_INPUT_PARAMETERS, input.to_vec()));
    }
    p
}
fn return_code(p: &Node) -> u32 {
    p.required(PKCS_11_RETURN_CODE).unwrap().number().unwrap()
}
fn handle(p: &Node) -> Option<Vec<u8>> {
    p.get(CORRELATION_VALUE)
        .map(|n| n.byte_string().unwrap().to_vec())
}

#[test]
fn pkcs11_initialize_get_info_finalize() {
    for v in [Version(2, 0), Version(2, 1), Version(3, 0)] {
        pkcs11_lifecycle(v);
    }
}
/// REQ: docs/interpretations.md (PKCS#11): the Correlation Value is returned
/// by C_Initialize; draft 3.0 also echoes it in C_GetInfo and C_Finalize
/// responses (OASIS traces PKCS11-M-1-20/21/30).
fn pkcs11_lifecycle(v: Version) {
    let mut f = Fixture::new();
    let echo = v.0 >= 3;
    let r = f.one("alice", v, PKCS11, pkcs11(C_INITIALIZE, None, Some(&[1])));
    let p = payload(&r);
    assert_eq!(
        p.children()
            .unwrap()
            .iter()
            .map(|n| n.tag)
            .collect::<Vec<_>>(),
        [PKCS_11_FUNCTION, CORRELATION_VALUE, PKCS_11_RETURN_CODE]
    );
    assert_eq!(return_code(p), 0);
    let library = handle(p).unwrap();
    assert_eq!(library.len(), 16);

    let r = f.one("alice", v, PKCS11, pkcs11(C_GET_INFO, Some(&library), None));
    let p = payload(&r);
    assert_eq!(return_code(p), 0);
    assert_eq!(handle(p), echo.then(|| library.clone()));
    let info = p
        .required(PKCS_11_OUTPUT_PARAMETERS)
        .unwrap()
        .byte_string()
        .unwrap()
        .to_vec();
    // CK_INFO: cryptokiVersion 3.0, manufacturerID[32], 8-byte flags,
    // libraryDescription[32], libraryVersion.
    let mut expected = vec![3, 0];
    expected.extend(format!("{:<32}", "Keytend").bytes());
    expected.extend([0; 8]);
    expected.extend(format!("{:<32}", "Keytend PKCS#11 over KMIP").bytes());
    expected.extend([
        env!("CARGO_PKG_VERSION_MAJOR").parse::<u8>().unwrap(),
        env!("CARGO_PKG_VERSION_MINOR").parse::<u8>().unwrap(),
    ]);
    assert_eq!(info, expected);

    // A second C_Initialize on a live instance names it again.
    let r = f.one(
        "alice",
        v,
        PKCS11,
        pkcs11(C_INITIALIZE, Some(&library), Some(&[1])),
    );
    assert_eq!(return_code(payload(&r)), 0x191);
    assert_eq!(handle(payload(&r)).as_deref(), Some(&library[..]));
    // Unsupported functions of the V3.0 interface never return the handle.
    let r = f.one(
        "alice",
        v,
        PKCS11,
        pkcs11(C_ENCRYPT, Some(&library), Some(&[0; 9])),
    );
    assert_eq!(return_code(payload(&r)), 0x54);
    assert!(handle(payload(&r)).is_none());
    // Another principal cannot use the handle.
    let r = f.one("bob", v, PKCS11, pkcs11(C_GET_INFO, Some(&library), None));
    let p = payload(&r);
    assert_eq!(return_code(p), 0x190);
    assert!(handle(p).is_none() && p.get(PKCS_11_OUTPUT_PARAMETERS).is_none());

    let r = f.one("alice", v, PKCS11, pkcs11(C_FINALIZE, Some(&library), None));
    let p = payload(&r);
    assert_eq!(return_code(p), 0);
    assert_eq!(handle(p), echo.then(|| library.clone()));
    for function in [C_GET_INFO, C_FINALIZE] {
        let r = f.one("alice", v, PKCS11, pkcs11(function, Some(&library), None));
        assert_eq!(return_code(payload(&r)), 0x190);
        assert!(handle(payload(&r)).is_none());
    }
    let r = f.one("alice", v, PKCS11, pkcs11(C_GET_INFO, None, None));
    assert_eq!(return_code(payload(&r)), 0x190);
}

#[test]
fn pkcs11_errors_use_kmip_result_reasons() {
    let mut f = Fixture::new();
    for v in [Version(2, 0), Version(2, 1), Version(3, 0)] {
        // Encoding version other than 1, or no version byte: Codec Error.
        for input in [None, Some(&[2][..]), Some(&[1, 1][..])] {
            let r = f.one("alice", v, PKCS11, pkcs11(C_INITIALIZE, None, input));
            assert_eq!(reason(&r), 0x45);
        }
        let r = f.one("alice", v, PKCS11, pkcs11(C_GET_INFO, None, Some(&[0])));
        assert_eq!(reason(&r), 0x45);
        // Functions outside CK_FUNCTION_LIST_3_0 and vendor functions.
        for function in [
            Node::enumeration(PKCS_11_FUNCTION, 0),
            Node::enumeration(PKCS_11_FUNCTION, 93),
            Node::int(PKCS_11_FUNCTION, 3),
        ] {
            let r = f.one("alice", v, PKCS11, vec![function]);
            assert_eq!(reason(&r), 0x46);
        }
        // An interface other than the standard "PKCS 11".
        let mut p = vec![Node::text(PKCS_11_INTERFACE, "Vendor 11")];
        p.extend(pkcs11(C_INITIALIZE, None, Some(&[1])));
        assert_eq!(reason(&f.one("alice", v, PKCS11, p)), 0x47);
        let mut p = vec![Node::text(PKCS_11_INTERFACE, "PKCS 11")];
        p.extend(pkcs11(C_INITIALIZE, None, Some(&[1])));
        let r = f.one("alice", v, PKCS11, p);
        assert_eq!(
            payload(&r).children().unwrap()[0].string().unwrap(),
            "PKCS 11"
        );
        assert_eq!(reason(&f.one("alice", v, PKCS11, vec![])), 7);
    }
    assert_eq!(
        reason(&f.one(
            "alice",
            Version(1, 4),
            PKCS11,
            pkcs11(C_INITIALIZE, None, Some(&[1]))
        )),
        5
    );
}

#[test]
fn pkcs11_instances_are_bounded_per_principal_and_undone_with_their_batch() {
    let mut f = Fixture::new();
    let v = Version(2, 1);
    let first = handle(payload(&f.one(
        "alice",
        v,
        PKCS11,
        pkcs11(C_INITIALIZE, None, Some(&[1])),
    )))
    .unwrap();
    for _ in 0..16 {
        f.one("alice", v, PKCS11, pkcs11(C_INITIALIZE, None, Some(&[1])));
    }
    // The least recently used instance was finalized to make room.
    let r = f.one("alice", v, PKCS11, pkcs11(C_GET_INFO, Some(&first), None));
    assert_eq!(return_code(payload(&r)), 0x190);
    // An undone C_Initialize leaves no instance behind.
    let items = f.batch(
        "alice",
        v,
        vec![Node::enumeration(BATCH_ERROR_CONTINUATION_OPTION, 3)],
        vec![
            (PKCS11, pkcs11(C_INITIALIZE, None, Some(&[1]))),
            (PKCS11, vec![]),
        ],
    );
    assert_eq!(status(&items[0]), 3);
    let undone = handle(items[0].required(RESPONSE_PAYLOAD).unwrap()).unwrap();
    let r = f.one("alice", v, PKCS11, pkcs11(C_GET_INFO, Some(&undone), None));
    assert_eq!(return_code(payload(&r)), 0x190);
}

fn key(bits: i32, extra: Vec<Node>) -> Vec<Node> {
    let mut attrs = vec![
        Node::enumeration(CRYPTOGRAPHIC_ALGORITHM, 3),
        Node::int(CRYPTOGRAPHIC_LENGTH, bits),
        Node::int(CRYPTOGRAPHIC_USAGE_MASK, 12),
    ];
    attrs.extend(extra);
    vec![
        Node::enumeration(OBJECT_TYPE, 2),
        Node::structure(ATTRIBUTES, attrs),
    ]
}
fn quantum(level: u32, period: u32, safe: bool) -> Vec<Node> {
    vec![
        Node::enumeration(PROTECTION_LEVEL, level),
        Node {
            tag: PROTECTION_PERIOD,
            value: Value::Interval(period),
        },
        Node::boolean(QUANTUM_SAFE, safe),
    ]
}
fn uid(item: &Node) -> String {
    payload(item)
        .required(UNIQUE_IDENTIFIER)
        .unwrap()
        .identifier_text()
        .unwrap()
        .to_owned()
}

#[test]
fn quantum_safe_creation_requires_a_qualifying_key() {
    let mut f = Fixture::new();
    for v in [Version(2, 0), Version(2, 1), Version(3, 0)] {
        // Profiles QS-M-2-20/21/30: AES-128, High, ~13 years, Quantum Safe.
        let r = f.one("alice", v, CREATE, key(128, quantum(1, 409968000, true)));
        assert_eq!(reason(&r), 0x100);
        let r = f.one("alice", v, CREATE, key(256, quantum(1, 409968000, true)));
        let id = uid(&r);
        let target = if v.0 >= 3 {
            Node::identifier(UNIQUE_IDENTIFIER, id.clone())
        } else {
            Node::text(UNIQUE_IDENTIFIER, id.clone())
        };
        let r = f.one("alice", v, GET_ATTRIBUTES, vec![target]);
        let attrs = payload(&r).required(ATTRIBUTES).unwrap();
        assert_eq!(
            attrs.required(PROTECTION_LEVEL).unwrap().number().unwrap(),
            1
        );
        assert_eq!(
            attrs.required(PROTECTION_PERIOD).unwrap().number().unwrap(),
            409968000
        );
        assert!(attrs.required(QUANTUM_SAFE).unwrap().flag().unwrap());
        // Without the flag, level and period alone are recorded.
        let r = f.one("alice", v, CREATE, key(128, quantum(2, 60, false)));
        uid(&r);
        // Invalid values.
        let r = f.one(
            "alice",
            v,
            CREATE,
            key(256, vec![Node::enumeration(PROTECTION_LEVEL, 3)]),
        );
        assert_eq!(reason(&r), 7);
        let r = f.one(
            "alice",
            v,
            CREATE,
            key(256, vec![Node::int(PROTECTION_PERIOD, 5)]),
        );
        assert_eq!(reason(&r), 7);
        // Duplicates are single-valued attributes.
        let mut twice = quantum(1, 1, false);
        twice.push(Node::boolean(QUANTUM_SAFE, false));
        assert_eq!(reason(&f.one("alice", v, CREATE, key(256, twice))), 8);
    }
    // No asymmetric key this server implements is quantum safe.
    let v = Version(2, 1);
    let r = f.one(
        "alice",
        v,
        CREATE_KEY_PAIR,
        vec![
            Node::structure(
                COMMON_ATTRIBUTES,
                vec![
                    Node::enumeration(CRYPTOGRAPHIC_ALGORITHM, 4),
                    Node::int(CRYPTOGRAPHIC_LENGTH, 2048),
                    Node::boolean(QUANTUM_SAFE, true),
                ],
            ),
            Node::structure(
                PRIVATE_KEY_ATTRIBUTES,
                vec![Node::int(CRYPTOGRAPHIC_USAGE_MASK, 1)],
            ),
            Node::structure(
                PUBLIC_KEY_ATTRIBUTES,
                vec![Node::int(CRYPTOGRAPHIC_USAGE_MASK, 2)],
            ),
        ],
    );
    assert_eq!(reason(&r), 0x100);
}

#[test]
fn quantum_safe_attributes_are_client_modifiable_locatable_and_two_x_only() {
    let mut f = Fixture::new();
    let v = Version(2, 1);
    let weak = uid(&f.one("alice", v, CREATE, key(128, vec![])));
    let strong = uid(&f.one("alice", v, CREATE, key(256, vec![])));
    let set = |id: &str, a: Node| {
        vec![
            Node::text(UNIQUE_IDENTIFIER, id),
            Node::structure(NEW_ATTRIBUTE, vec![a]),
        ]
    };
    // Flagging a key that does not qualify fails and changes nothing.
    for op in [ADD_ATTRIBUTE, SET_ATTRIBUTE] {
        let r = f.one(
            "alice",
            v,
            op,
            set(&weak, Node::boolean(QUANTUM_SAFE, true)),
        );
        assert_eq!(reason(&r), 0x100);
    }
    let r = f.one(
        "alice",
        v,
        SET_ATTRIBUTE,
        set(&strong, Node::boolean(QUANTUM_SAFE, true)),
    );
    uid(&r);
    let r = f.one(
        "alice",
        v,
        ADD_ATTRIBUTE,
        set(&strong, Node::enumeration(PROTECTION_LEVEL, 2)),
    );
    uid(&r);
    let r = f.one(
        "alice",
        v,
        ADD_ATTRIBUTE,
        set(&strong, Node::enumeration(PROTECTION_LEVEL, 1)),
    );
    assert_eq!(reason(&r), 0x23);
    let locate = |f: &mut Fixture, filter: Node| {
        let r = f.one(
            "alice",
            v,
            LOCATE,
            vec![Node::structure(ATTRIBUTES, vec![filter])],
        );
        payload(&r)
            .all(UNIQUE_IDENTIFIER)
            .map(|n| n.identifier_text().unwrap().to_owned())
            .collect::<Vec<_>>()
    };
    assert_eq!(
        locate(&mut f, Node::boolean(QUANTUM_SAFE, true)),
        [strong.as_str()]
    );
    assert_eq!(
        locate(&mut f, Node::enumeration(PROTECTION_LEVEL, 2)),
        [strong.as_str()]
    );
    assert!(locate(&mut f, Node::enumeration(PROTECTION_LEVEL, 1)).is_empty());
    // The client may delete the flag.
    let r = f.one(
        "alice",
        v,
        DELETE_ATTRIBUTE,
        vec![
            Node::text(UNIQUE_IDENTIFIER, strong.clone()),
            Node::enumeration(ATTRIBUTE_REFERENCE, QUANTUM_SAFE),
        ],
    );
    uid(&r);
    assert!(locate(&mut f, Node::boolean(QUANTUM_SAFE, true)).is_empty());
    // KMIP 1.x has no such attributes: hidden from 1.4 Get Attributes.
    let r = f.one(
        "alice",
        Version(1, 4),
        GET_ATTRIBUTES,
        vec![Node::text(UNIQUE_IDENTIFIER, strong.clone())],
    );
    let names = payload(&r)
        .all(ATTRIBUTE)
        .map(|a| {
            a.required(ATTRIBUTE_NAME)
                .unwrap()
                .string()
                .unwrap()
                .to_owned()
        })
        .collect::<Vec<_>>();
    assert!(!names.is_empty());
    assert!(!names.iter().any(|n| n.starts_with("Protection L")));
}
