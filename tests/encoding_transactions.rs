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

use keytend_kmip_server::{
    encoding::Format,
    protocol::{Engine, Version},
    store::Store,
    tags::*,
    ttlv::{Node, Value},
};
struct Fixture {
    _d: tempfile::TempDir,
    e: Engine,
}
impl Fixture {
    fn new() -> Self {
        let d = tempfile::tempdir().unwrap();
        let k = d.path().join("master");
        std::fs::write(&k, [7; 32]).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&k, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        let s = Store::open(&d.path().join("store"), &k).unwrap();
        Self {
            _d: d,
            e: Engine::new(s, true),
        }
    }
}
fn request(items: Vec<(u32, Vec<Node>)>, extra: Vec<Node>) -> Node {
    let mut h = vec![
        Version(2, 1).node(),
        Node::int(BATCH_COUNT, items.len() as i32),
    ];
    h.extend(extra);
    let mut fields = vec![Node::structure(REQUEST_HEADER, h)];
    for (i, (op, p)) in items.into_iter().enumerate() {
        fields.push(Node::structure(
            BATCH_ITEM,
            vec![
                Node::enumeration(OPERATION, op),
                Node::bytes(UNIQUE_BATCH_ITEM_ID, vec![i as u8]),
                Node::structure(REQUEST_PAYLOAD, p),
            ],
        ));
    }
    Node::structure(REQUEST_MESSAGE, fields)
}
fn body(n: &Node) -> &Node {
    let item = n.get(BATCH_ITEM).unwrap();
    assert_eq!(item.required(RESULT_STATUS).unwrap().number().unwrap(), 0);
    item.required(RESPONSE_PAYLOAD).unwrap()
}
fn reason(n: &Node) -> u32 {
    n.get(BATCH_ITEM)
        .unwrap()
        .required(RESULT_REASON)
        .unwrap()
        .number()
        .unwrap()
}
fn create(limited: bool) -> Vec<Node> {
    let mut attrs = vec![
        Node::enumeration(CRYPTOGRAPHIC_ALGORITHM, 3),
        Node::int(CRYPTOGRAPHIC_LENGTH, 256),
        Node::int(CRYPTOGRAPHIC_USAGE_MASK, 12),
    ];
    if limited {
        attrs.push(Node::structure(
            USAGE_LIMITS,
            vec![
                Node::long(USAGE_LIMITS_TOTAL, 1),
                Node::enumeration(USAGE_LIMITS_UNIT, 2),
            ],
        ));
    }
    vec![
        Node::enumeration(OBJECT_TYPE, 2),
        Node::structure(ATTRIBUTES, attrs),
    ]
}
fn key(f: &mut Fixture, limited: bool) -> String {
    let r =
        f.e.process("owner", &request(vec![(1, create(limited))], vec![]))
            .unwrap();
    let id = body(&r)
        .required(UNIQUE_IDENTIFIER)
        .unwrap()
        .string()
        .unwrap()
        .to_owned();
    body(
        &f.e.process(
            "owner",
            &request(vec![(18, vec![Node::text(UNIQUE_IDENTIFIER, &id)])], vec![]),
        )
        .unwrap(),
    );
    id
}
fn encoded(f: &mut Fixture, r: &Node, format: Format) -> Node {
    f.e.process_with_grants_encoded("owner", r, None, &[], format)
        .unwrap()
}
#[test]
fn xml_unrepresentable_get_rolls_back_fresh_and_continue_keeps_other_successes() {
    let mut f = Fixture::new();
    let id = key(&mut f, false);
    let mut obj = f.e.store.get("owner", &id).unwrap().unwrap();
    obj.id = "literal\0identifier".to_owned();
    f.e.store.insert(&obj).unwrap();
    let fields = vec![Node::text(UNIQUE_IDENTIFIER, &obj.id)];
    let r = encoded(
        &mut f,
        &request(vec![(10, fields.clone())], vec![]),
        Format::Xml,
    );
    assert_eq!(reason(&r), 8);
    assert_eq!(
        f.e.store
            .get("owner", &obj.id)
            .unwrap()
            .unwrap()
            .metadata
            .fresh,
        Some(true)
    );
    assert!(Format::Xml.encode(&r).is_ok());
    let r = encoded(
        &mut f,
        &request(
            vec![(10, fields), (1, create(false))],
            vec![Node::enumeration(BATCH_ERROR_CONTINUATION_OPTION, 1)],
        ),
        Format::Xml,
    );
    let status = r
        .all(BATCH_ITEM)
        .map(|n| n.required(RESULT_STATUS).unwrap().number().unwrap())
        .collect::<Vec<_>>();
    assert_eq!(status, vec![1, 0]);
    assert_eq!(f.e.store.list("owner").unwrap().len(), 3);
    assert_eq!(
        f.e.store
            .get("owner", &obj.id)
            .unwrap()
            .unwrap()
            .metadata
            .fresh,
        Some(true)
    );
}
#[test]
fn xml_representation_failure_undoes_prior_mutation_without_exposure() {
    let mut f = Fixture::new();
    let id = key(&mut f, false);
    let mut obj = f.e.store.get("owner", &id).unwrap().unwrap();
    obj.id = "bad\0id".to_owned();
    f.e.store.insert(&obj).unwrap();
    let r = encoded(
        &mut f,
        &request(
            vec![
                (1, create(false)),
                (10, vec![Node::text(UNIQUE_IDENTIFIER, &obj.id)]),
            ],
            vec![Node::enumeration(BATCH_ERROR_CONTINUATION_OPTION, 3)],
        ),
        Format::Xml,
    );
    assert_eq!(
        r.all(BATCH_ITEM)
            .map(|i| i.required(RESULT_STATUS).unwrap().number().unwrap())
            .collect::<Vec<_>>(),
        vec![3, 1]
    );
    assert_eq!(f.e.store.list("owner").unwrap().len(), 2);
    assert_eq!(
        f.e.store
            .get("owner", &obj.id)
            .unwrap()
            .unwrap()
            .metadata
            .fresh,
        Some(true)
    );
}
#[test]
fn encoded_response_budget_restores_usage_and_multipart_state() {
    let mut f = Fixture::new();
    let id = key(&mut f, true);
    let fields = vec![
        Node::text(UNIQUE_IDENTIFIER, &id),
        Node::structure(
            CRYPTOGRAPHIC_PARAMETERS,
            vec![
                Node::enumeration(BLOCK_CIPHER_MODE, 6),
                Node::enumeration(PADDING_METHOD, 1),
            ],
        ),
        Node::bytes(IV_COUNTER_NONCE, vec![1; 16]),
        Node::bytes(DATA, vec![2; 4096]),
        Node::boolean(INIT_INDICATOR, true),
    ];
    // The limit is the binary TTLV equivalent in JSON too (Profiles 2.1
    // section 5.5): 4096 bytes of ciphertext cannot fit in 4096.
    let limited = request(
        vec![(31, fields.clone())],
        vec![Node::int(MAXIMUM_RESPONSE_SIZE, 4096)],
    );
    let r = encoded(&mut f, &limited, Format::Json);
    assert_eq!(reason(&r), 2);
    let message = request(
        vec![(31, fields)],
        vec![Node::int(MAXIMUM_RESPONSE_SIZE, 5000)],
    );
    let remaining = |f: &Fixture| {
        let o = f.e.store.get("owner", &id).unwrap().unwrap();
        match o
            .attrs
            .iter()
            .find(|a| a.tag == USAGE_LIMITS)
            .unwrap()
            .required(USAGE_LIMITS_COUNT)
            .unwrap()
            .value
        {
            Value::LongInteger(n) => n,
            _ => panic!(),
        }
    };
    assert_eq!(remaining(&f), 1);
    // A larger limit fits the binary equivalent, although the JSON body is
    // larger than 5000 bytes, and succeeds without a leaked earlier context.
    let r = encoded(&mut f, &message, Format::Json);
    assert!(Format::Json.encode(&r).unwrap().len() > 5000);
    let token = body(&r)
        .required(CORRELATION_VALUE)
        .unwrap()
        .byte_string()
        .unwrap()
        .to_vec();
    assert_eq!(remaining(&f), 0);
    let r =
        f.e.process(
            "owner",
            &request(
                vec![(
                    31,
                    vec![
                        Node::text(UNIQUE_IDENTIFIER, &id),
                        Node::bytes(CORRELATION_VALUE, token),
                        Node::boolean(FINAL_INDICATOR, true),
                    ],
                )],
                vec![],
            ),
        )
        .unwrap();
    body(&r);
}
#[test]
fn database_failure_after_encoding_never_returns_encoded_success() {
    let mut f = Fixture::new();
    let id = key(&mut f, false);
    rusqlite::Connection::open(f._d.path().join("store")).unwrap().execute_batch("CREATE TRIGGER fail_response_audit BEFORE INSERT ON audit BEGIN SELECT RAISE(ABORT,'test audit unavailable'); END;").unwrap();
    let r = encoded(
        &mut f,
        &request(vec![(10, vec![Node::text(UNIQUE_IDENTIFIER, &id)])], vec![]),
        Format::Json,
    );
    assert_eq!(reason(&r), 0x100);
    assert_eq!(
        f.e.store.get("owner", &id).unwrap().unwrap().metadata.fresh,
        Some(true)
    );
    assert!(r.get(BATCH_ITEM).unwrap().get(RESPONSE_PAYLOAD).is_none());
}

#[test]
fn aggregate_node_budget_restores_usage_and_does_not_leak_stream_slots() {
    for format in [Format::Ttlv, Format::Json, Format::Xml] {
        let mut f = Fixture::new();
        let id = key(&mut f, true);
        let fields = vec![
            Node::text(UNIQUE_IDENTIFIER, &id),
            Node::structure(
                CRYPTOGRAPHIC_PARAMETERS,
                vec![
                    Node::enumeration(BLOCK_CIPHER_MODE, 6),
                    Node::enumeration(PADDING_METHOD, 1),
                ],
            ),
            Node::bytes(IV_COUNTER_NONCE, vec![1; 16]),
            Node::bytes(DATA, vec![2; 32]),
            Node::boolean(INIT_INDICATOR, true),
        ];
        // Header + Query consumes 16,379 nodes, leaving exactly the five
        // required failure nodes. The stream's bytes fit, but its nodes do not.
        let message = request(
            vec![
                (24, vec![Node::enumeration(QUERY_FUNCTION, 3); 8183]),
                (31, fields.clone()),
            ],
            vec![Node::enumeration(BATCH_ERROR_CONTINUATION_OPTION, 1)],
        );
        // Seventeen failures would exhaust the owner's sixteen stream slots if
        // an unreturned Init leaked a context, even with its usage charge restored.
        for _ in 0..17 {
            let r = encoded(&mut f, &message, format);
            let items = r.all(BATCH_ITEM).collect::<Vec<_>>();
            assert_eq!(items.len(), 2);
            assert_eq!(
                items[0].required(RESULT_STATUS).unwrap().number().unwrap(),
                0
            );
            assert_eq!(
                items[1].required(RESULT_REASON).unwrap().number().unwrap(),
                2
            );
            assert!(items[1].get(RESPONSE_PAYLOAD).is_none());
            assert!(items[1].get(RESULT_MESSAGE).is_none());
            assert!(format.encode(&r).is_ok());
            let object = f.e.store.get("owner", &id).unwrap().unwrap();
            assert!(matches!(
                object
                    .attrs
                    .iter()
                    .find(|a| a.tag == USAGE_LIMITS)
                    .unwrap()
                    .required(USAGE_LIMITS_COUNT)
                    .unwrap()
                    .value,
                Value::LongInteger(1)
            ));
        }
        let r = encoded(&mut f, &request(vec![(31, fields)], vec![]), format);
        let token = body(&r)
            .required(CORRELATION_VALUE)
            .unwrap()
            .byte_string()
            .unwrap()
            .to_vec();
        let r = encoded(
            &mut f,
            &request(
                vec![(
                    31,
                    vec![
                        Node::text(UNIQUE_IDENTIFIER, &id),
                        Node::bytes(CORRELATION_VALUE, token),
                        Node::boolean(FINAL_INDICATOR, true),
                    ],
                )],
                vec![],
            ),
            format,
        );
        body(&r);
        f.e.store.verify_audit().unwrap();
    }
}
