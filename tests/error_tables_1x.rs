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

//! Every row of the KMIP 1.0-1.4 error tables (section 11 of each edition):
//! each row's error condition is produced and its Result Reason checked, in
//! every edition whose table has the row. A row whose condition no client
//! request can produce on this server is listed with the reason it cannot
//! arise. `ROWS` holds one entry per distinct row; `rows_match_the_tables`
//! checks that the entries add up to each edition's table row count, so no
//! row is skipped. Labels paraphrase the conditions in our own words.
use keytend_kmip_server::{
    protocol::{Engine, Version},
    store::Store,
    tags::*,
    ttlv::{Node, Value},
};
use tempfile::TempDir;

// 1.x Result Reasons (1.4 section 9.1.3.2.28).
const ITEM_NOT_FOUND: u32 = 0x01;
const RESPONSE_TOO_LARGE: u32 = 0x02;
const INVALID_MESSAGE: u32 = 0x04;
const OPERATION_NOT_SUPPORTED: u32 = 0x05;
const INVALID_FIELD: u32 = 0x07;
const FEATURE_NOT_SUPPORTED: u32 = 0x08;
const CRYPTOGRAPHIC_FAILURE: u32 = 0x0A;
const ILLEGAL_OPERATION: u32 = 0x0B;
const PERMISSION_DENIED: u32 = 0x0C;
const OBJECT_ARCHIVED: u32 = 0x0D;
const APPLICATION_NAMESPACE_NOT_SUPPORTED: u32 = 0x0F;
const KEY_FORMAT_TYPE_NOT_SUPPORTED: u32 = 0x10;
const ENCODING_OPTION_ERROR: u32 = 0x12;
const KEY_VALUE_NOT_PRESENT: u32 = 0x13;
const SENSITIVE_REASON: u32 = 0x16;
const NOT_EXTRACTABLE: u32 = 0x17;
const OBJECT_ALREADY_EXISTS: u32 = 0x18;

const V: [Version; 5] = [
    Version(1, 0),
    Version(1, 1),
    Version(1, 2),
    Version(1, 3),
    Version(1, 4),
];

struct Fixture {
    _dir: TempDir,
    engine: Engine,
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
        let store = Store::open(&d.path().join("keys.sqlite"), &k).unwrap();
        Self {
            _dir: d,
            engine: Engine::new(store, false),
        }
    }
    fn send(&mut self, request: &Node) -> Node {
        self.engine.process("alice", request).unwrap()
    }
    fn call(&mut self, v: Version, op: u32, payload: Vec<Node>) -> Node {
        self.send(&req(v, vec![], vec![(op, payload)]))
    }
    fn ok(&mut self, v: Version, op: u32, payload: Vec<Node>) -> Node {
        let r = self.call(v, op, payload);
        let item = r.required(BATCH_ITEM).unwrap();
        assert_eq!(
            num(item, RESULT_STATUS),
            0,
            "{}.{} op {op}: {:?}",
            v.0,
            v.1,
            item.get(RESULT_MESSAGE)
                .map(|n| n.string().unwrap().to_owned())
        );
        item.required(RESPONSE_PAYLOAD).unwrap().clone()
    }
    fn id(&mut self, v: Version, op: u32, payload: Vec<Node>) -> String {
        text(&self.ok(v, op, payload), UNIQUE_IDENTIFIER)
    }
}

fn req(v: Version, extra: Vec<Node>, items: Vec<(u32, Vec<Node>)>) -> Node {
    let mut header = vec![v.node()];
    header.extend(extra);
    header.push(Node::int(BATCH_COUNT, items.len() as i32));
    let mut fields = vec![Node::structure(REQUEST_HEADER, header)];
    for (i, (op, payload)) in items.into_iter().enumerate() {
        fields.push(Node::structure(
            BATCH_ITEM,
            vec![
                Node::enumeration(OPERATION, op),
                Node::bytes(UNIQUE_BATCH_ITEM_ID, vec![i as u8 + 1]),
                Node::structure(REQUEST_PAYLOAD, payload),
            ],
        ));
    }
    Node::structure(REQUEST_MESSAGE, fields)
}
fn num(n: &Node, tag: u32) -> u32 {
    n.required(tag).unwrap().number().unwrap()
}
fn text(n: &Node, tag: u32) -> String {
    n.required(tag)
        .unwrap()
        .identifier_text()
        .unwrap()
        .to_owned()
}
fn uid(id: &str) -> Node {
    Node::text(UNIQUE_IDENTIFIER, id)
}
fn private_uid(id: &str) -> Node {
    Node::text(PRIVATE_KEY_UNIQUE_IDENTIFIER, id)
}
/// Result of the first failed batch item: `Some(reason)`, or `None` when
/// every item succeeded.
fn outcome(r: &Node) -> Option<u32> {
    let failed = r.all(BATCH_ITEM).find(|i| num(i, RESULT_STATUS) != 0)?;
    LAST.with(|m| {
        *m.borrow_mut() = failed
            .get(RESULT_MESSAGE)
            .and_then(|n| n.string().ok())
            .unwrap_or_default()
            .to_owned()
    });
    Some(num(failed, RESULT_REASON))
}
thread_local! {
    /// Result Message of the last failure, for diagnostics.
    static LAST: std::cell::RefCell<String> = const { std::cell::RefCell::new(String::new()) };
}

/// A 1.x Attribute structure.
fn a(name: &str, value: Value) -> Node {
    Node::structure(
        ATTRIBUTE,
        vec![
            Node::text(ATTRIBUTE_NAME, name),
            Node {
                tag: ATTRIBUTE_VALUE,
                value,
            },
        ],
    )
}
fn a_at(name: &str, index: i32, value: Value) -> Node {
    let mut n = a(name, value);
    if let Value::Structure(fields) = &mut n.value {
        fields.insert(1, Node::int(ATTRIBUTE_INDEX, index));
    }
    n
}
fn name_value(value: &str) -> Value {
    Value::Structure(vec![
        Node::text(NAME_VALUE, value),
        Node::enumeration(NAME_TYPE, 1),
    ])
}
fn name(value: &str) -> Node {
    a("Name", name_value(value))
}
/// A template reference inside a Template-Attribute (1.x Table 29).
fn template_ref(value: &str) -> Node {
    Node {
        tag: NAME,
        value: name_value(value),
    }
}
fn ta(attrs: Vec<Node>) -> Node {
    Node::structure(TEMPLATE_ATTRIBUTE, attrs)
}
fn aes_attrs(usage: i32) -> Vec<Node> {
    vec![
        a("Cryptographic Algorithm", Value::Enumeration(3)),
        a("Cryptographic Length", Value::Integer(256)),
        a("Cryptographic Usage Mask", Value::Integer(usage)),
    ]
}
fn create_payload(extra: Vec<Node>) -> Vec<Node> {
    let mut attrs = aes_attrs(0x0C);
    attrs.extend(extra);
    vec![Node::enumeration(OBJECT_TYPE, 2), ta(attrs)]
}
fn pair_payload(extra: Vec<Node>) -> Vec<Node> {
    let mut attrs = vec![
        a("Cryptographic Algorithm", Value::Enumeration(4)),
        a("Cryptographic Length", Value::Integer(2048)),
    ];
    attrs.extend(extra);
    vec![
        Node::structure(COMMON_TEMPLATE_ATTRIBUTE, attrs),
        Node::structure(
            PRIVATE_KEY_TEMPLATE_ATTRIBUTE,
            vec![a("Cryptographic Usage Mask", Value::Integer(1))],
        ),
        Node::structure(
            PUBLIC_KEY_TEMPLATE_ATTRIBUTE,
            vec![a("Cryptographic Usage Mask", Value::Integer(2))],
        ),
    ]
}
fn symmetric_key(bytes: &[u8]) -> Node {
    Node::structure(
        SYMMETRIC_KEY,
        vec![Node::structure(
            KEY_BLOCK,
            vec![
                Node::enumeration(KEY_FORMAT_TYPE, 1),
                Node::structure(KEY_VALUE, vec![Node::bytes(KEY_MATERIAL, bytes.to_vec())]),
                Node::enumeration(CRYPTOGRAPHIC_ALGORITHM, 3),
                Node::int(CRYPTOGRAPHIC_LENGTH, (bytes.len() * 8) as i32),
            ],
        )],
    )
}
fn secret_data(bytes: &[u8]) -> Node {
    Node::structure(
        SECRET_DATA,
        vec![
            Node::enumeration(SECRET_DATA_TYPE, 2),
            Node::structure(
                KEY_BLOCK,
                vec![
                    Node::enumeration(KEY_FORMAT_TYPE, 1),
                    Node::structure(KEY_VALUE, vec![Node::bytes(KEY_MATERIAL, bytes.to_vec())]),
                ],
            ),
        ],
    )
}
fn register_payload(kind: u32, attrs: Vec<Node>, object: Node) -> Vec<Node> {
    vec![Node::enumeration(OBJECT_TYPE, kind), ta(attrs), object]
}
fn template_payload(template_name: &str, content: Vec<Node>) -> Vec<Node> {
    vec![
        Node::enumeration(OBJECT_TYPE, 6),
        ta(vec![name(template_name)]),
        Node::structure(TEMPLATE, content),
    ]
}
fn asi(namespace: &str) -> Node {
    a(
        "Application Specific Information",
        Value::Structure(vec![Node::text(APPLICATION_NAMESPACE, namespace)]),
    )
}
fn revocation(code: u32) -> Node {
    Node::structure(
        REVOCATION_REASON,
        vec![Node::enumeration(REVOCATION_REASON_CODE, code)],
    )
}
fn wrapping(method: u32, info: u32, key: &str, extra: Vec<Node>) -> Node {
    let mut fields = vec![
        Node::enumeration(WRAPPING_METHOD, method),
        Node::structure(info, vec![uid(key)]),
    ];
    fields.extend(extra);
    Node::structure(KEY_WRAPPING_SPECIFICATION, fields)
}
fn wrapping_with(method: u32, info: u32, key: &str, cp: Node, extra: Vec<Node>) -> Node {
    let mut fields = vec![
        Node::enumeration(WRAPPING_METHOD, method),
        Node::structure(info, vec![uid(key), cp]),
    ];
    fields.extend(extra);
    Node::structure(KEY_WRAPPING_SPECIFICATION, fields)
}
fn key_wrap_parameters() -> Node {
    Node::structure(
        CRYPTOGRAPHIC_PARAMETERS,
        vec![Node::enumeration(BLOCK_CIPHER_MODE, 12)],
    )
}
fn stream(op: u32, id: &str) -> Vec<Node> {
    let mut p = vec![uid(id)];
    match op {
        34 => p.push(Node::bytes(SIGNATURE_DATA, vec![1; 16])),
        36 => p.push(Node::bytes(MAC_DATA, vec![1; 16])),
        _ => {}
    }
    p.push(Node::bytes(DATA, vec![1; 16]));
    p.push(Node::bytes(CORRELATION_VALUE, vec![0xAB; 16]));
    p
}

/// Objects of one edition used by the probes.
struct Ctx {
    f: Fixture,
    v: Version,
    /// Active AES-256 key (Encrypt, Decrypt, Wrap, Unwrap, MAC, MAC Verify).
    key: String,
    pre_active: String,
    archived: String,
    destroyed: String,
    /// Active Secret Data (no cryptographic usage).
    secret: String,
    /// A Template named "tpl" (1.x).
    template: String,
    /// Active RSA key pair (Sign, Verify).
    private: String,
    public: String,
}
impl Ctx {
    fn new(v: Version) -> Self {
        let mut f = Fixture::new();
        let all = 0x0C | 0x10 | 0x20 | 0x80 | 0x100 | 0x200;
        let mut attrs = aes_attrs(all);
        attrs.push(a(
            "Cryptographic Parameters",
            Value::Structure(vec![Node::enumeration(BLOCK_CIPHER_MODE, 12)]),
        ));
        let key = f.id(v, 1, vec![Node::enumeration(OBJECT_TYPE, 2), ta(attrs)]);
        f.ok(v, 18, vec![uid(&key)]);
        let pre_active = f.id(v, 1, create_payload(vec![]));
        let archived = f.id(v, 1, create_payload(vec![]));
        f.ok(v, 21, vec![uid(&archived)]);
        let destroyed = f.id(v, 1, create_payload(vec![]));
        f.ok(v, 20, vec![uid(&destroyed)]);
        let secret = f.id(
            v,
            3,
            register_payload(
                7,
                vec![a("Cryptographic Usage Mask", Value::Integer(0))],
                secret_data(&[3; 16]),
            ),
        );
        f.ok(v, 18, vec![uid(&secret)]);
        let group = || a("Object Group", Value::TextString("g".into()));
        let template = f.id(v, 3, template_payload("tpl", vec![group()]));
        let archived_template = f.id(v, 3, template_payload("archived-tpl", vec![group()]));
        f.ok(v, 21, vec![uid(&archived_template)]);
        let pair = f.ok(v, 2, pair_payload(vec![]));
        let private = text(&pair, PRIVATE_KEY_UNIQUE_IDENTIFIER);
        let public = text(&pair, PUBLIC_KEY_UNIQUE_IDENTIFIER);
        f.ok(v, 18, vec![uid(&private)]);
        f.ok(v, 18, vec![uid(&public)]);
        Self {
            f,
            v,
            key,
            pre_active,
            archived,
            destroyed,
            secret,
            template,
            private,
            public,
        }
    }
    fn call(&mut self, op: u32, payload: Vec<Node>) -> Option<u32> {
        let r = self.f.call(self.v, op, payload);
        outcome(&r)
    }
    fn send(&mut self, request: Node) -> Option<u32> {
        let r = self.f.send(&request);
        outcome(&r)
    }
    fn fresh(&mut self, extra: Vec<Node>) -> String {
        self.f.id(self.v, 1, create_payload(extra))
    }
}

enum Expect {
    /// The listed Result Reason.
    Reason(u32),
    /// The row's action is to process the request normally.
    Success,
}
type Probe = fn(&mut Ctx) -> Option<u32>;
enum How {
    Probe(Expect, Probe),
    /// The condition cannot arise on this server; the text says why.
    Cannot(&'static str),
}
struct Row {
    table: &'static str,
    /// Editions (minor versions of 1.x) whose table has the row.
    minors: &'static [u32],
    label: &'static str,
    how: How,
}
const ALL: &[u32] = &[0, 1, 2, 3, 4];
const FROM_1_1: &[u32] = &[1, 2, 3, 4];
const FROM_1_2: &[u32] = &[2, 3, 4];
const FROM_1_3: &[u32] = &[3, 4];
const ONLY_1_4: &[u32] = &[4];
const ONLY_1_0: &[u32] = &[0];
const UP_TO_1_1: &[u32] = &[0, 1];

use Expect::*;
use How::*;

const CRYPTO_INTERNAL: &str = "provider errors map to Cryptographic Failure (protocol.rs From<ErrorStack>), but every client input is validated first, so no request reaches a provider failure";
const NO_INSTANCE_LIMIT: &str = "the server sets no per-attribute instance limit below the message size limit, so no request exceeds one";
const NO_ATTESTATION: &str = "no operation requires attestation data (Query Capability reports Attestation Capability false)";

macro_rules! row {
    ($table:expr, $minors:expr, $label:expr, $reason:expr, $probe:expr) => {
        Row {
            table: $table,
            minors: $minors,
            label: $label,
            how: Probe(Reason($reason), $probe),
        }
    };
}
macro_rules! cannot {
    ($table:expr, $minors:expr, $label:expr, $why:expr) => {
        Row {
            table: $table,
            minors: $minors,
            label: $label,
            how: Cannot($why),
        }
    };
}

/// Probes for the rows several operations share.
fn missing(op: u32) -> Vec<Node> {
    let mut p = vec![uid("no-such-object")];
    extra(op, &mut p);
    p
}
fn extra(op: u32, p: &mut Vec<Node>) {
    match op {
        17 => p.push(Node::long(USAGE_LIMITS_COUNT, 1)),
        19 => p.push(revocation(1)),
        31 | 32 | 33 | 35 => p.push(Node::bytes(DATA, vec![0; 16])),
        34 => {
            p.push(Node::bytes(DATA, vec![0; 16]));
            p.push(Node::bytes(SIGNATURE_DATA, vec![0; 16]));
        }
        36 => {
            p.push(Node::bytes(DATA, vec![0; 16]));
            p.push(Node::bytes(MAC_DATA, vec![0; 16]));
        }
        13 => p.push(a("Contact Information", Value::TextString("x".into()))),
        14 => p.push(a("Contact Information", Value::TextString("x".into()))),
        15 => p.push(Node::text(ATTRIBUTE_NAME, "Contact Information")),
        _ => {}
    }
}
fn on(c: &mut Ctx, op: u32, id: &str) -> Option<u32> {
    let mut p = vec![uid(id)];
    extra(op, &mut p);
    c.call(op, p)
}

macro_rules! not_found {
    ($table:expr, $minors:expr, $op:expr) => {
        row!(
            $table,
            $minors,
            "no object with the identifier",
            ITEM_NOT_FOUND,
            |c| c.call($op, missing($op))
        )
    };
}
macro_rules! archived {
    ($table:expr, $minors:expr, $op:expr) => {
        row!(
            $table,
            $minors,
            "object is archived",
            OBJECT_ARCHIVED,
            |c| {
                let id = c.archived.clone();
                on(c, $op, &id)
            }
        )
    };
}

fn rows() -> Vec<Row> {
    vec![
        // 11.1 General.
        row!(
            "General",
            ALL,
            "protocol major version mismatch",
            INVALID_MESSAGE,
            |c| {
                // Major 0 stands for a 1.x-family mismatch; an unsupported major above
                // 2 is answered under the 2.x rule (Unsupported Protocol Version).
                c.send(req(Version(0, 9), vec![], vec![(10, vec![uid("x")])]))
            }
        ),
        row!(
            "General",
            ALL,
            "batch item payload cannot be parsed",
            INVALID_MESSAGE,
            |c| {
                let mut r = req(c.v, vec![], vec![(10, vec![])]);
                if let Value::Structure(fields) = &mut r.value
                    && let Value::Structure(item) = &mut fields[1].value
                {
                    item[2] = Node::int(REQUEST_PAYLOAD, 1);
                }
                c.send(r)
            }
        ),
        row!(
            "General",
            ALL,
            "a field given twice",
            INVALID_MESSAGE,
            |c| {
                let id = c.key.clone();
                c.call(10, vec![uid(&id), uid(&id)])
            }
        ),
        Row {
            table: "General",
            minors: ALL,
            label: "later minor version, unknown field: ignored, processed as 1.4",
            how: Probe(Success, |c| {
                // A tag no 1.x edition defines, in the header and the payload.
                let unknown = || Node::text(0x4203F0, "from a later minor version");
                let mut r = req(
                    Version(1, 9),
                    vec![unknown()],
                    vec![(24, vec![Node::enumeration(QUERY_FUNCTION, 1), unknown()])],
                );
                if let Value::Structure(fields) = &mut r.value
                    && let Value::Structure(header) = &mut fields[0].value
                {
                    let count = header.pop().unwrap();
                    header.insert(1, count);
                }
                let response = c.f.send(&r);
                let version = response
                    .required(RESPONSE_HEADER)
                    .unwrap()
                    .required(PROTOCOL_VERSION)
                    .unwrap();
                if num(version, PROTOCOL_VERSION_MAJOR) != 1
                    || num(version, PROTOCOL_VERSION_MINOR) != 4
                {
                    return Some(0xFFFD);
                }
                outcome(&response)
            }),
        },
        row!(
            "General",
            ALL,
            "same version, unknown field",
            INVALID_FIELD,
            |c| {
                let id = c.key.clone();
                c.call(10, vec![uid(&id), Node::int(BATCH_COUNT, 1)])
            }
        ),
        row!(
            "General",
            ALL,
            "client not allowed to perform the operation",
            PERMISSION_DENIED,
            |c| {
                let id = c.key.clone();
                let r =
                    c.f.engine
                        .process_authorized(
                            "alice",
                            &req(c.v, vec![], vec![(10, vec![uid(&id)])]),
                            Some(&[1]),
                        )
                        .unwrap();
                outcome(&r)
            }
        ),
        cannot!(
            "General",
            UP_TO_1_1,
            "operation cannot complete synchronously for a synchronous client",
            "every operation completes synchronously unless the client asks for asynchronous processing"
        ),
        row!(
            "General",
            ALL,
            "Maximum Response Size exceeded",
            RESPONSE_TOO_LARGE,
            |c| {
                let v = c.v;
                c.send(req(
                    v,
                    vec![Node::int(MAXIMUM_RESPONSE_SIZE, 250)],
                    vec![(24, vec![Node::enumeration(QUERY_FUNCTION, 1)])],
                ))
            }
        ),
        row!(
            "General",
            ALL,
            "operation not supported",
            OPERATION_NOT_SUPPORTED,
            |c| c.call(0x1B, vec![])
        ),
        row!(
            "General",
            ALL,
            "critical message extension not understood",
            FEATURE_NOT_SUPPORTED,
            |c| {
                let mut r = req(
                    c.v,
                    vec![],
                    vec![(24, vec![Node::enumeration(QUERY_FUNCTION, 1)])],
                );
                if let Value::Structure(fields) = &mut r.value
                    && let Value::Structure(item) = &mut fields[1].value
                {
                    item.push(Node::structure(
                        MESSAGE_EXTENSION,
                        vec![
                            Node::text(VENDOR_IDENTIFICATION, "unknown"),
                            Node::boolean(CRITICALITY_INDICATOR, true),
                            Node::structure(VENDOR_EXTENSION, vec![]),
                        ],
                    ));
                }
                c.send(r)
            }
        ),
        row!(
            "General",
            ALL,
            "message cannot be parsed",
            INVALID_MESSAGE,
            |c| {
                c.send(Node::structure(
                    REQUEST_MESSAGE,
                    vec![Node::int(BATCH_COUNT, 1)],
                ))
            }
        ),
        cannot!(
            "General",
            FROM_1_2,
            "attestation required, client attestation capable",
            NO_ATTESTATION
        ),
        cannot!(
            "General",
            FROM_1_2,
            "attestation required, client not attestation capable",
            NO_ATTESTATION
        ),
        cannot!(
            "General",
            FROM_1_2,
            "attestation data does not validate",
            NO_ATTESTATION
        ),
        // 11.2 Create.
        row!(
            "Create",
            ALL,
            "object type not recognized",
            INVALID_FIELD,
            |c| {
                c.call(
                    1,
                    vec![Node::enumeration(OBJECT_TYPE, 0x7F), ta(aes_attrs(0x0C))],
                )
            }
        ),
        row!(
            "Create",
            ALL,
            "template does not exist",
            ITEM_NOT_FOUND,
            |c| { c.call(1, create_payload(vec![template_ref("no-such-template")])) }
        ),
        row!(
            "Create",
            ALL,
            "incorrect attribute value",
            INVALID_FIELD,
            |c| {
                let mut p = create_payload(vec![]);
                p[1] = ta(vec![
                    a("Cryptographic Algorithm", Value::Enumeration(3)),
                    a("Cryptographic Length", Value::Integer(100)),
                    a("Cryptographic Usage Mask", Value::Integer(0x0C)),
                ]);
                c.call(1, p)
            }
        ),
        cannot!(
            "Create",
            ALL,
            "error creating the cryptographic object",
            CRYPTO_INTERNAL
        ),
        cannot!(
            "Create",
            ALL,
            "more instances than supported",
            NO_INSTANCE_LIMIT
        ),
        row!(
            "Create",
            ALL,
            "Name already used by another object",
            INVALID_FIELD,
            |c| {
                c.fresh(vec![name("taken-create")]);
                c.call(1, create_payload(vec![name("taken-create")]))
            }
        ),
        row!(
            "Create",
            ALL,
            "unsupported Application Namespace without data",
            APPLICATION_NAMESPACE_NOT_SUPPORTED,
            |c| { c.call(1, create_payload(vec![asi("unknown-namespace")])) }
        ),
        row!(
            "Create",
            ALL,
            "template is archived",
            OBJECT_ARCHIVED,
            |c| { c.call(1, create_payload(vec![template_ref("archived-tpl")])) }
        ),
        // 11.3 Create Key Pair.
        row!(
            "Create Key Pair",
            ALL,
            "template does not exist",
            ITEM_NOT_FOUND,
            |c| { c.call(2, pair_payload(vec![template_ref("no-such-template")])) }
        ),
        row!(
            "Create Key Pair",
            ALL,
            "incorrect attribute value",
            INVALID_FIELD,
            |c| {
                let mut p = pair_payload(vec![]);
                p[0] = Node::structure(
                    COMMON_TEMPLATE_ATTRIBUTE,
                    vec![
                        a("Cryptographic Algorithm", Value::Enumeration(4)),
                        a("Cryptographic Length", Value::Integer(100)),
                    ],
                );
                c.call(2, p)
            }
        ),
        cannot!(
            "Create Key Pair",
            ALL,
            "error creating the cryptographic object",
            CRYPTO_INTERNAL
        ),
        row!(
            "Create Key Pair",
            ALL,
            "Name already used by another object",
            INVALID_FIELD,
            |c| {
                c.fresh(vec![name("taken-pair")]);
                let mut p = pair_payload(vec![]);
                p[1] = Node::structure(
                    PRIVATE_KEY_TEMPLATE_ATTRIBUTE,
                    vec![
                        a("Cryptographic Usage Mask", Value::Integer(1)),
                        name("taken-pair"),
                    ],
                );
                c.call(2, p)
            }
        ),
        cannot!(
            "Create Key Pair",
            ALL,
            "more instances than supported",
            NO_INSTANCE_LIMIT
        ),
        row!(
            "Create Key Pair",
            ALL,
            "required field missing",
            INVALID_MESSAGE,
            |c| c.call(2, vec![])
        ),
        row!(
            "Create Key Pair",
            ALL,
            "unsupported Application Namespace without data",
            APPLICATION_NAMESPACE_NOT_SUPPORTED,
            |c| { c.call(2, pair_payload(vec![asi("unknown-namespace")])) }
        ),
        row!(
            "Create Key Pair",
            ALL,
            "template is archived",
            OBJECT_ARCHIVED,
            |c| { c.call(2, pair_payload(vec![template_ref("archived-tpl")])) }
        ),
        // 11.4 Register.
        row!(
            "Register",
            ALL,
            "object type not recognized",
            INVALID_FIELD,
            |c| { c.call(3, register_payload(0x7F, vec![], symmetric_key(&[1; 16]))) }
        ),
        row!(
            "Register",
            ALL,
            "object type does not match the object",
            INVALID_FIELD,
            |c| { c.call(3, register_payload(7, vec![], symmetric_key(&[1; 16]))) }
        ),
        row!(
            "Register",
            ALL,
            "template does not exist",
            ITEM_NOT_FOUND,
            |c| {
                c.call(
                    3,
                    register_payload(
                        2,
                        vec![
                            template_ref("no-such-template"),
                            a("Cryptographic Usage Mask", Value::Integer(4)),
                        ],
                        symmetric_key(&[1; 16]),
                    ),
                )
            }
        ),
        row!(
            "Register",
            ALL,
            "incorrect attribute value",
            INVALID_FIELD,
            |c| {
                c.call(
                    3,
                    register_payload(
                        2,
                        vec![a("Cryptographic Usage Mask", Value::TextString("x".into()))],
                        symmetric_key(&[1; 16]),
                    ),
                )
            }
        ),
        row!(
            "Register",
            FROM_1_2,
            "Template with a Name inside the Template structure",
            INVALID_FIELD,
            |c| { c.call(3, template_payload("outer", vec![name("inner")])) }
        ),
        row!(
            "Register",
            ALL,
            "Name already used by another object",
            INVALID_FIELD,
            |c| {
                c.fresh(vec![name("taken-register")]);
                c.call(
                    3,
                    register_payload(
                        2,
                        vec![
                            a("Cryptographic Usage Mask", Value::Integer(4)),
                            name("taken-register"),
                        ],
                        symmetric_key(&[1; 16]),
                    ),
                )
            }
        ),
        cannot!(
            "Register",
            ALL,
            "more instances than supported",
            NO_INSTANCE_LIMIT
        ),
        row!(
            "Register",
            ALL,
            "unsupported Application Namespace without data",
            APPLICATION_NAMESPACE_NOT_SUPPORTED,
            |c| {
                c.call(
                    3,
                    register_payload(
                        2,
                        vec![
                            a("Cryptographic Usage Mask", Value::Integer(4)),
                            asi("unknown-namespace"),
                        ],
                        symmetric_key(&[1; 16]),
                    ),
                )
            }
        ),
        row!(
            "Register",
            ALL,
            "template is archived",
            OBJECT_ARCHIVED,
            |c| {
                c.call(
                    3,
                    register_payload(
                        2,
                        vec![
                            template_ref("archived-tpl"),
                            a("Cryptographic Usage Mask", Value::Integer(4)),
                        ],
                        symmetric_key(&[1; 16]),
                    ),
                )
            }
        ),
        cannot!(
            "Register",
            FROM_1_1,
            "Encoding Option with wrapped attribute names",
            "a Register request has no Key Wrapping Specification, so it cannot name attributes to wrap"
        ),
        cannot!(
            "Register",
            ONLY_1_4,
            "PKCS#12 without exactly one PKCS#12 Password Link",
            "the server does not accept Key Format Type PKCS#12 for Register (Feature Not Supported), so no PKCS#12 Password Link is examined"
        ),
        cannot!(
            "Register",
            ONLY_1_4,
            "PKCS#12 Password Link not to a password Secret Data",
            "the server does not accept Key Format Type PKCS#12 for Register (Feature Not Supported), so no PKCS#12 Password Link is examined"
        ),
        // 11.5 Re-key.
        not_found!("Re-key", ALL, 4),
        row!(
            "Re-key",
            ALL,
            "object cannot be re-keyed",
            PERMISSION_DENIED,
            |c| {
                let id = c.private.clone();
                c.call(4, vec![uid(&id)])
            }
        ),
        row!(
            "Re-key",
            ALL,
            "Offset given with a date attribute",
            INVALID_MESSAGE,
            |c| {
                let id = c.key.clone();
                c.call(
                    4,
                    vec![
                        uid(&id),
                        Node::interval(OFFSET, 60),
                        ta(vec![a("Activation Date", Value::DateTime(2_000_000_000))]),
                    ],
                )
            }
        ),
        cannot!(
            "Re-key",
            ALL,
            "cryptographic error during re-key",
            CRYPTO_INTERNAL
        ),
        row!(
            "Re-key",
            ALL,
            "unsupported Application Namespace without data",
            APPLICATION_NAMESPACE_NOT_SUPPORTED,
            |c| {
                let id = c.key.clone();
                c.call(4, vec![uid(&id), ta(vec![asi("unknown-namespace")])])
            }
        ),
        archived!("Re-key", ALL, 4),
        row!(
            "Re-key",
            ALL,
            "Offset without an Activation Date",
            ILLEGAL_OPERATION,
            |c| {
                // A Deactivation Date to shift, but no Activation Date.
                let id = c.fresh(vec![a("Deactivation Date", Value::DateTime(4_000_000_000))]);
                c.call(4, vec![uid(&id), Node::interval(OFFSET, 60)])
            }
        ),
        row!(
            "Re-key",
            FROM_1_2,
            "key value not present",
            KEY_VALUE_NOT_PRESENT,
            |c| {
                let id = c.destroyed.clone();
                c.call(4, vec![uid(&id)])
            }
        ),
        // 11.6 Re-key Key Pair.
        row!(
            "Re-key Key Pair",
            FROM_1_1,
            "no object with the identifier",
            ITEM_NOT_FOUND,
            |c| c.call(29, vec![private_uid("no-such-object")])
        ),
        row!(
            "Re-key Key Pair",
            FROM_1_1,
            "object cannot be re-keyed",
            PERMISSION_DENIED,
            |c| {
                let id = c.key.clone();
                c.call(29, vec![private_uid(&id)])
            }
        ),
        row!(
            "Re-key Key Pair",
            FROM_1_1,
            "Offset given with a date attribute",
            INVALID_MESSAGE,
            |c| {
                let id = c.private.clone();
                c.call(
                    29,
                    vec![
                        private_uid(&id),
                        Node::interval(OFFSET, 60),
                        Node::structure(
                            COMMON_TEMPLATE_ATTRIBUTE,
                            vec![a("Activation Date", Value::DateTime(2_000_000_000))],
                        ),
                    ],
                )
            }
        ),
        cannot!(
            "Re-key Key Pair",
            FROM_1_1,
            "cryptographic error during re-key",
            CRYPTO_INTERNAL
        ),
        row!(
            "Re-key Key Pair",
            FROM_1_1,
            "unsupported Application Namespace without data",
            APPLICATION_NAMESPACE_NOT_SUPPORTED,
            |c| {
                let id = c.private.clone();
                c.call(
                    29,
                    vec![
                        private_uid(&id),
                        Node::structure(COMMON_TEMPLATE_ATTRIBUTE, vec![asi("unknown-namespace")]),
                    ],
                )
            }
        ),
        row!(
            "Re-key Key Pair",
            FROM_1_1,
            "object is archived",
            OBJECT_ARCHIVED,
            |c| {
                let v = c.v;
                let pair = c.f.ok(v, 2, pair_payload(vec![]));
                let id = text(&pair, PRIVATE_KEY_UNIQUE_IDENTIFIER);
                c.f.ok(v, 21, vec![uid(&id)]);
                c.call(29, vec![private_uid(&id)])
            }
        ),
        row!(
            "Re-key Key Pair",
            FROM_1_1,
            "Offset without an Activation Date",
            ILLEGAL_OPERATION,
            |c| {
                let v = c.v;
                let pair = c.f.ok(
                    v,
                    2,
                    pair_payload(vec![a("Deactivation Date", Value::DateTime(4_000_000_000))]),
                );
                let id = text(&pair, PRIVATE_KEY_UNIQUE_IDENTIFIER);
                c.call(29, vec![private_uid(&id), Node::interval(OFFSET, 60)])
            }
        ),
        row!(
            "Re-key Key Pair",
            FROM_1_2,
            "key value not present",
            KEY_VALUE_NOT_PRESENT,
            |c| {
                let v = c.v;
                let pair = c.f.ok(v, 2, pair_payload(vec![]));
                let id = text(&pair, PRIVATE_KEY_UNIQUE_IDENTIFIER);
                c.f.ok(v, 20, vec![uid(&id)]);
                c.call(29, vec![private_uid(&id)])
            }
        ),
    ]
}

fn derive(
    c: &mut Ctx,
    sources: Vec<String>,
    method: u32,
    params: Vec<Node>,
    attrs: Vec<Node>,
) -> Option<u32> {
    let mut p = vec![Node::enumeration(OBJECT_TYPE, 2)];
    p.extend(sources.iter().map(|id| uid(id)));
    p.push(Node::enumeration(DERIVATION_METHOD, method));
    p.push(Node::structure(DERIVATION_PARAMETERS, params));
    let mut a_list = vec![
        a("Cryptographic Algorithm", Value::Enumeration(3)),
        a("Cryptographic Length", Value::Integer(128)),
        a("Cryptographic Usage Mask", Value::Integer(0x0C)),
    ];
    a_list.extend(attrs);
    p.push(ta(a_list));
    c.call(5, p)
}
fn hmac_params() -> Vec<Node> {
    vec![
        Node::structure(
            CRYPTOGRAPHIC_PARAMETERS,
            vec![Node::enumeration(HASHING_ALGORITHM, 6)],
        ),
        Node::bytes(DERIVATION_DATA, vec![5; 16]),
    ]
}
/// An active AES key that may derive keys.
fn derivable(c: &mut Ctx) -> String {
    let v = c.v;
    let id = c.f.id(
        v,
        1,
        vec![
            Node::enumeration(OBJECT_TYPE, 2),
            ta(vec![
                a("Cryptographic Algorithm", Value::Enumeration(9)),
                a("Cryptographic Length", Value::Integer(256)),
                a("Cryptographic Usage Mask", Value::Integer(0x200)),
            ]),
        ],
    );
    c.f.ok(v, 18, vec![uid(&id)]);
    id
}
/// A Certify request with a garbled PKCS#10 request.
fn certify_request(id: &str) -> Vec<Node> {
    vec![
        uid(id),
        Node::enumeration(CERTIFICATE_REQUEST_TYPE, 2),
        Node::bytes(CERTIFICATE_REQUEST, vec![0x30, 0x03, 0x02, 0x01, 0x00]),
    ]
}
fn local_key() -> openssl::pkey::PKey<openssl::pkey::Private> {
    openssl::pkey::PKey::from_rsa(openssl::rsa::Rsa::generate(2048).unwrap()).unwrap()
}
/// A Certify request with a well-formed, signed PKCS#10 request.
fn signed_request(id: &str) -> Vec<Node> {
    signed_request_for(id, &local_key())
}
/// A registered public key and a certificate of it, for `key`.
fn local_objects(
    c: &mut Ctx,
    key: &openssl::pkey::PKey<openssl::pkey::Private>,
) -> (String, String) {
    use openssl::{
        asn1::Asn1Time,
        hash::MessageDigest,
        x509::{X509, X509NameBuilder},
    };
    let v = c.v;
    let attrs = vec![
        a("Cryptographic Algorithm", Value::Enumeration(4)),
        a("Cryptographic Length", Value::Integer(2048)),
        a("Cryptographic Usage Mask", Value::Integer(2)),
    ];
    let public = Node::structure(
        PUBLIC_KEY,
        vec![Node::structure(
            KEY_BLOCK,
            vec![
                Node::enumeration(KEY_FORMAT_TYPE, 5),
                Node::structure(
                    KEY_VALUE,
                    vec![Node::bytes(KEY_MATERIAL, key.public_key_to_der().unwrap())],
                ),
                Node::enumeration(CRYPTOGRAPHIC_ALGORITHM, 4),
                Node::int(CRYPTOGRAPHIC_LENGTH, 2048),
            ],
        )],
    );
    let public = c.f.id(v, 3, register_payload(3, attrs.clone(), public));
    let mut n = X509NameBuilder::new().unwrap();
    n.append_entry_by_text("CN", "client").unwrap();
    let n = n.build();
    let mut b = X509::builder().unwrap();
    b.set_version(2).unwrap();
    b.set_subject_name(&n).unwrap();
    b.set_issuer_name(&n).unwrap();
    b.set_pubkey(key).unwrap();
    b.set_not_before(&Asn1Time::days_from_now(0).unwrap())
        .unwrap();
    b.set_not_after(&Asn1Time::days_from_now(30).unwrap())
        .unwrap();
    b.sign(key, MessageDigest::sha256()).unwrap();
    let der = b.build().to_der().unwrap();
    let certificate = Node::structure(
        CERTIFICATE,
        vec![
            Node::enumeration(CERTIFICATE_TYPE, 1),
            Node::bytes(CERTIFICATE_VALUE, der),
        ],
    );
    let certificate = c.f.id(
        v,
        3,
        register_payload(
            1,
            vec![a("Cryptographic Usage Mask", Value::Integer(2))],
            certificate,
        ),
    );
    (public, certificate)
}
fn signed_request_for(id: &str, key: &openssl::pkey::PKey<openssl::pkey::Private>) -> Vec<Node> {
    use openssl::{
        hash::MessageDigest,
        x509::{X509NameBuilder, X509ReqBuilder},
    };
    let mut b = X509ReqBuilder::new().unwrap();
    let mut n = X509NameBuilder::new().unwrap();
    n.append_entry_by_text("CN", "client").unwrap();
    b.set_subject_name(&n.build()).unwrap();
    b.set_pubkey(key).unwrap();
    b.sign(key, MessageDigest::sha256()).unwrap();
    vec![
        uid(id),
        Node::enumeration(CERTIFICATE_REQUEST_TYPE, 2),
        Node::bytes(CERTIFICATE_REQUEST, b.build().to_der().unwrap()),
    ]
}
fn split_payload(extra: Vec<Node>, method: u32) -> Vec<Node> {
    let mut p = vec![
        Node::enumeration(OBJECT_TYPE, 5),
        Node::int(SPLIT_KEY_PARTS, 3),
        Node::int(SPLIT_KEY_THRESHOLD, 3),
        Node::enumeration(SPLIT_KEY_METHOD, method),
    ];
    p.extend(extra);
    p
}
fn split_parts(c: &mut Ctx) -> Vec<String> {
    let v = c.v;
    let key = c.fresh(vec![]);
    let r = c.f.ok(v, 40, split_payload(vec![uid(&key), ta(vec![])], 1));
    r.all(UNIQUE_IDENTIFIER)
        .map(|n| n.identifier_text().unwrap().to_owned())
        .collect()
}
fn join(c: &mut Ctx, parts: &[String], extra: Vec<Node>) -> Option<u32> {
    let mut p = vec![Node::enumeration(OBJECT_TYPE, 2)];
    p.extend(parts.iter().map(|id| uid(id)));
    p.extend(extra);
    c.call(41, p)
}
fn import_payload(id: &str, extra: Vec<Node>) -> Vec<Node> {
    let mut p = vec![
        uid(id),
        Node::enumeration(OBJECT_TYPE, 2),
        a("Unique Identifier", Value::TextString(id.into())),
        a("Object Type", Value::Enumeration(2)),
        a("State", Value::Enumeration(1)),
        a("Sensitive", Value::Boolean(false)),
        a("Extractable", Value::Boolean(true)),
        a("Always Sensitive", Value::Boolean(false)),
        a("Never Extractable", Value::Boolean(false)),
        a("Initial Date", Value::DateTime(1_700_000_000)),
        a("Last Change Date", Value::DateTime(1_700_000_000)),
        a("Cryptographic Algorithm", Value::Enumeration(3)),
        a("Cryptographic Length", Value::Integer(256)),
        a("Cryptographic Usage Mask", Value::Integer(0x0C)),
        a(
            "Digest",
            Value::Structure(vec![
                Node::enumeration(HASHING_ALGORITHM, 6),
                Node::bytes(DIGEST_VALUE, openssl::sha::sha256(&[9; 32]).to_vec()),
                Node::enumeration(KEY_FORMAT_TYPE, 1),
            ]),
        ),
    ];
    p.extend(extra);
    p.push(symmetric_key(&[9; 32]));
    p
}
/// A Get or Export request asking for the key wrapped as the row needs.
fn wrapped(c: &mut Ctx, op: u32, spec: Node) -> Option<u32> {
    let id = c.key.clone();
    c.call(op, vec![uid(&id), spec])
}
fn active_pair(c: &mut Ctx) -> (String, String) {
    let v = c.v;
    let pair = c.f.ok(v, 2, pair_payload(vec![]));
    let private = text(&pair, PRIVATE_KEY_UNIQUE_IDENTIFIER);
    let public = text(&pair, PUBLIC_KEY_UNIQUE_IDENTIFIER);
    (private, public)
}

/// Rows shared by Get (1.0-1.4) and Export (1.4).
fn transfer_rows(table: &'static str, minors: &'static [u32], op: u32) -> Vec<Row> {
    let _ = op;
    macro_rules! transfer {
        ($label:expr, $reason:expr, $probe:expr) => {
            Row {
                table,
                minors,
                label: $label,
                how: Probe(Reason($reason), $probe),
            }
        };
    }
    let g = |op: u32| op;
    let _ = g;
    match op {
        10 => vec![
            transfer!("object does not exist", ITEM_NOT_FOUND, |c| c
                .call(10, missing(10))),
            transfer!("wrapping key does not exist", ITEM_NOT_FOUND, |c| wrapped(
                c,
                10,
                wrapping(1, ENCRYPTION_KEY_INFORMATION, "no-such-key", vec![])
            )),
            transfer!(
                "Encryption Key Information names an object that is not a key",
                ILLEGAL_OPERATION,
                |c| {
                    let s = c.secret.clone();
                    wrapped(
                        c,
                        10,
                        wrapping_with(
                            1,
                            ENCRYPTION_KEY_INFORMATION,
                            &s,
                            key_wrap_parameters(),
                            vec![],
                        ),
                    )
                }
            ),
            transfer!(
                "Encryption Key Information key cannot wrap",
                PERMISSION_DENIED,
                |c| {
                    let k = c.fresh(vec![a(
                        "Cryptographic Parameters",
                        Value::Structure(vec![Node::enumeration(BLOCK_CIPHER_MODE, 12)]),
                    )]);
                    let v = c.v;
                    c.f.ok(v, 18, vec![uid(&k)]);
                    wrapped(c, 10, wrapping(1, ENCRYPTION_KEY_INFORMATION, &k, vec![]))
                }
            ),
            transfer!(
                "MAC/Signature Key Information names an object that is not a key",
                ILLEGAL_OPERATION,
                |c| {
                    let s = c.secret.clone();
                    wrapped(
                        c,
                        10,
                        wrapping(2, MAC_SIGNATURE_KEY_INFORMATION, &s, vec![]),
                    )
                }
            ),
            transfer!(
                "MAC/Signature Key Information key cannot MAC or sign",
                PERMISSION_DENIED,
                |c| {
                    let k = c.pre_active.clone();
                    wrapped(
                        c,
                        10,
                        wrapping(2, MAC_SIGNATURE_KEY_INFORMATION, &k, vec![]),
                    )
                }
            ),
            transfer!(
                "Key Format Type or Key Compression Type not available",
                KEY_FORMAT_TYPE_NOT_SUPPORTED,
                |c| {
                    let id = c.key.clone();
                    c.call(10, vec![uid(&id), Node::enumeration(KEY_FORMAT_TYPE, 3)])
                }
            ),
            cannot!(
                table,
                minors,
                "only attributes are held for a non-Template object",
                "every stored object other than a Template holds its value; Register without a Key Value is refused (Key Value Present is not settable by clients)"
            ),
            transfer!(
                "Cryptographic Parameters do not match the wrapping key",
                ITEM_NOT_FOUND,
                |c| {
                    let k = c.key.clone();
                    wrapped(
                        c,
                        10,
                        wrapping_with(
                            1,
                            ENCRYPTION_KEY_INFORMATION,
                            &k,
                            Node::structure(
                                CRYPTOGRAPHIC_PARAMETERS,
                                vec![Node::enumeration(BLOCK_CIPHER_MODE, 1)],
                            ),
                            vec![],
                        ),
                    )
                }
            ),
            transfer!("object is archived", OBJECT_ARCHIVED, |c| {
                let id = c.archived.clone();
                c.call(10, vec![uid(&id)])
            }),
        ],
        _ => vec![
            transfer!("object does not exist", ITEM_NOT_FOUND, |c| c
                .call(43, missing(43))),
            transfer!("wrapping key does not exist", ITEM_NOT_FOUND, |c| wrapped(
                c,
                43,
                wrapping(1, ENCRYPTION_KEY_INFORMATION, "no-such-key", vec![])
            )),
            transfer!(
                "Encryption Key Information names an object that is not a key",
                ILLEGAL_OPERATION,
                |c| {
                    let s = c.secret.clone();
                    wrapped(
                        c,
                        43,
                        wrapping_with(
                            1,
                            ENCRYPTION_KEY_INFORMATION,
                            &s,
                            key_wrap_parameters(),
                            vec![],
                        ),
                    )
                }
            ),
            transfer!(
                "Encryption Key Information key cannot wrap",
                PERMISSION_DENIED,
                |c| {
                    let k = c.fresh(vec![a(
                        "Cryptographic Parameters",
                        Value::Structure(vec![Node::enumeration(BLOCK_CIPHER_MODE, 12)]),
                    )]);
                    let v = c.v;
                    c.f.ok(v, 18, vec![uid(&k)]);
                    wrapped(c, 43, wrapping(1, ENCRYPTION_KEY_INFORMATION, &k, vec![]))
                }
            ),
            transfer!(
                "MAC/Signature Key Information names an object that is not a key",
                ILLEGAL_OPERATION,
                |c| {
                    let s = c.secret.clone();
                    wrapped(
                        c,
                        43,
                        wrapping(2, MAC_SIGNATURE_KEY_INFORMATION, &s, vec![]),
                    )
                }
            ),
            transfer!(
                "MAC/Signature Key Information key cannot MAC or sign",
                PERMISSION_DENIED,
                |c| {
                    let k = c.pre_active.clone();
                    wrapped(
                        c,
                        43,
                        wrapping(2, MAC_SIGNATURE_KEY_INFORMATION, &k, vec![]),
                    )
                }
            ),
            transfer!(
                "Key Format Type or Key Compression Type not available",
                KEY_FORMAT_TYPE_NOT_SUPPORTED,
                |c| {
                    let id = c.key.clone();
                    c.call(43, vec![uid(&id), Node::enumeration(KEY_FORMAT_TYPE, 3)])
                }
            ),
            transfer!(
                "Cryptographic Parameters do not match the wrapping key",
                ITEM_NOT_FOUND,
                |c| {
                    let k = c.key.clone();
                    wrapped(
                        c,
                        43,
                        wrapping_with(
                            1,
                            ENCRYPTION_KEY_INFORMATION,
                            &k,
                            Node::structure(
                                CRYPTOGRAPHIC_PARAMETERS,
                                vec![Node::enumeration(BLOCK_CIPHER_MODE, 1)],
                            ),
                            vec![],
                        ),
                    )
                }
            ),
        ],
    }
}

fn rows2() -> Vec<Row> {
    let mut rows = vec![
        // 11.7 Derive Key.
        row!(
            "Derive Key",
            ALL,
            "a source object does not exist",
            ITEM_NOT_FOUND,
            |c| derive(c, vec!["no-such-object".into()], 3, hmac_params(), vec![])
        ),
        row!(
            "Derive Key",
            ALL,
            "a source object has the wrong type",
            INVALID_FIELD,
            |c| {
                let (p, _) = active_pair(c);
                derive(c, vec![p], 3, hmac_params(), vec![])
            }
        ),
        row!(
            "Derive Key",
            ALL,
            "template does not exist",
            ITEM_NOT_FOUND,
            |c| {
                let k = derivable(c);
                derive(
                    c,
                    vec![k],
                    3,
                    hmac_params(),
                    vec![template_ref("no-such-template")],
                )
            }
        ),
        row!(
            "Derive Key",
            ALL,
            "invalid Derivation Method",
            INVALID_FIELD,
            |c| {
                let k = derivable(c);
                derive(c, vec![k], 0x7F, hmac_params(), vec![])
            }
        ),
        row!(
            "Derive Key",
            ALL,
            "invalid Derivation Parameters",
            INVALID_FIELD,
            |c| {
                let k = derivable(c);
                let mut params = hmac_params();
                params.push(Node::bytes(SALT, vec![1; 8]));
                derive(c, vec![k], 3, params, vec![])
            }
        ),
        row!(
            "Derive Key",
            ALL,
            "Derivation Data and a Secret Data source together",
            INVALID_MESSAGE,
            |c| {
                let k = derivable(c);
                let v = c.v;
                let s = c.f.id(
                    v,
                    3,
                    register_payload(
                        7,
                        vec![a("Cryptographic Usage Mask", Value::Integer(0x200))],
                        secret_data(&[4; 32]),
                    ),
                );
                c.f.ok(v, 18, vec![uid(&s)]);
                derive(c, vec![k, s], 3, hmac_params(), vec![])
            }
        ),
        row!(
            "Derive Key",
            ALL,
            "incorrect attribute value",
            INVALID_FIELD,
            |c| {
                let k = derivable(c);
                derive(
                    c,
                    vec![k],
                    3,
                    hmac_params(),
                    vec![a("Object Group", Value::Integer(1))],
                )
            }
        ),
        row!(
            "Derive Key",
            ALL,
            "a source cannot derive keys",
            INVALID_FIELD,
            |c| {
                let k = c.fresh(vec![]);
                let v = c.v;
                c.f.ok(v, 18, vec![uid(&k)]);
                derive(c, vec![k], 3, hmac_params(), vec![])
            }
        ),
        row!(
            "Derive Key",
            ALL,
            "Name already used by another object",
            INVALID_FIELD,
            |c| {
                c.fresh(vec![name("taken-derive")]);
                let k = derivable(c);
                derive(c, vec![k], 3, hmac_params(), vec![name("taken-derive")])
            }
        ),
        row!(
            "Derive Key",
            ALL,
            "unsupported Application Namespace without data",
            APPLICATION_NAMESPACE_NOT_SUPPORTED,
            |c| {
                let k = derivable(c);
                derive(c, vec![k], 3, hmac_params(), vec![asi("unknown-namespace")])
            }
        ),
        row!(
            "Derive Key",
            ALL,
            "a source object is archived",
            OBJECT_ARCHIVED,
            |c| {
                let k = derivable(c);
                let v = c.v;
                c.f.ok(v, 21, vec![uid(&k)]);
                derive(c, vec![k], 3, hmac_params(), vec![])
            }
        ),
        row!(
            "Derive Key",
            ALL,
            "length exceeds the derivation output",
            CRYPTOGRAPHIC_FAILURE,
            |c| {
                let k = derivable(c);
                let v = c.v;
                let mut p = vec![
                    Node::enumeration(OBJECT_TYPE, 7),
                    uid(&k),
                    Node::enumeration(DERIVATION_METHOD, 3),
                ];
                p.push(Node::structure(DERIVATION_PARAMETERS, hmac_params()));
                p.push(ta(vec![
                    a("Cryptographic Length", Value::Integer(8 * 4096)),
                    a("Cryptographic Usage Mask", Value::Integer(0)),
                ]));
                let r = c.f.call(v, 5, p);
                outcome(&r)
            }
        ),
        row!(
            "Derive Key",
            FROM_1_2,
            "key value not present",
            KEY_VALUE_NOT_PRESENT,
            |c| {
                let k = derivable(c);
                let v = c.v;
                c.f.ok(v, 19, vec![uid(&k), revocation(1)]);
                c.f.ok(v, 20, vec![uid(&k)]);
                derive(c, vec![k], 3, hmac_params(), vec![])
            }
        ),
        // 11.8 Certify.
        row!(
            "Certify",
            ALL,
            "no object with the identifier",
            ITEM_NOT_FOUND,
            |c| c.call(6, signed_request("no-such-object"))
        ),
        row!(
            "Certify",
            ALL,
            "object cannot be certified",
            PERMISSION_DENIED,
            |c| {
                let k = c.key.clone();
                c.call(6, signed_request(&k))
            }
        ),
        row!(
            "Certify",
            ALL,
            "Certificate Request is not a signed request of its type",
            INVALID_FIELD,
            |c| {
                let k = c.public.clone();
                c.call(6, certify_request(&k))
            }
        ),
        row!(
            "Certify",
            ALL,
            "unsupported Application Namespace without data",
            APPLICATION_NAMESPACE_NOT_SUPPORTED,
            |c| {
                let key = local_key();
                let (k, _) = local_objects(c, &key);
                let mut p = signed_request_for(&k, &key);
                p.push(ta(vec![asi("unknown-namespace")]));
                c.call(6, p)
            }
        ),
        row!("Certify", ALL, "object is archived", OBJECT_ARCHIVED, |c| {
            let id = c.archived.clone();
            c.call(6, signed_request(&id))
        }),
        // 11.9 Re-certify.
        row!(
            "Re-certify",
            ALL,
            "no object with the identifier",
            ITEM_NOT_FOUND,
            |c| c.call(7, signed_request("no-such-object"))
        ),
        row!(
            "Re-certify",
            ALL,
            "object cannot be certified",
            PERMISSION_DENIED,
            |c| {
                let k = c.public.clone();
                c.call(7, signed_request(&k))
            }
        ),
        row!(
            "Re-certify",
            ALL,
            "Certificate Request is not a signed request of its type",
            INVALID_FIELD,
            |c| {
                let key = local_key();
                let (_, k) = local_objects(c, &key);
                c.call(7, certify_request(&k))
            }
        ),
        row!(
            "Re-certify",
            ALL,
            "Offset given with a date attribute",
            INVALID_MESSAGE,
            |c| {
                let key = local_key();
                let (_, k) = local_objects(c, &key);
                let mut p = signed_request_for(&k, &key);
                p.push(Node::interval(OFFSET, 60));
                p.push(ta(vec![a(
                    "Activation Date",
                    Value::DateTime(2_000_000_000),
                )]));
                c.call(7, p)
            }
        ),
        row!(
            "Re-certify",
            ALL,
            "unsupported Application Namespace without data",
            APPLICATION_NAMESPACE_NOT_SUPPORTED,
            |c| {
                let key = local_key();
                let (_, k) = local_objects(c, &key);
                let mut p = signed_request_for(&k, &key);
                p.push(ta(vec![asi("unknown-namespace")]));
                c.call(7, p)
            }
        ),
        row!(
            "Re-certify",
            ALL,
            "object is archived",
            OBJECT_ARCHIVED,
            |c| {
                let id = c.archived.clone();
                c.call(7, signed_request(&id))
            }
        ),
        // 11.10 Locate.
        row!(
            "Locate",
            ALL,
            "attribute the server does not understand",
            INVALID_FIELD,
            |c| c.call(8, vec![a("Bogus Attribute", Value::TextString("x".into()))])
        ),
        // 11.11 Check.
        row!("Check", ALL, "object does not exist", ITEM_NOT_FOUND, |c| c
            .call(9, missing(9))),
        row!("Check", ALL, "object is archived", OBJECT_ARCHIVED, |c| {
            let id = c.archived.clone();
            c.call(9, vec![uid(&id)])
        }),
        row!(
            "Check",
            ALL,
            "Check does not apply to the object",
            ILLEGAL_OPERATION,
            |c| {
                let id = c.template.clone();
                c.call(9, vec![uid(&id)])
            }
        ),
        row!(
            "Check",
            ALL,
            "the requested use is not allowed",
            PERMISSION_DENIED,
            |c| {
                let id = c.secret.clone();
                c.call(9, vec![uid(&id), Node::int(CRYPTOGRAPHIC_USAGE_MASK, 4)])
            }
        ),
    ];
    rows.extend(transfer_rows("Get", ALL, 10));
    rows.extend(vec![
        row!("Get", FROM_1_1, "value cannot be given in the Encoding Option", ENCODING_OPTION_ERROR, |c| {
            let k = c.key.clone();
            let id = c.private.clone();
            c.call(10, vec![uid(&id), Node::enumeration(KEY_FORMAT_TYPE, 10), wrapping_with(1, ENCRYPTION_KEY_INFORMATION, &k, key_wrap_parameters(), vec![Node::enumeration(ENCODING_OPTION, 1)])])
        }),
        row!("Get", FROM_1_1, "Encoding Option with wrapped attribute names", ENCODING_OPTION_ERROR, |c| { let k = c.key.clone(); wrapped(c, 10, wrapping_with(1, ENCRYPTION_KEY_INFORMATION, &k, key_wrap_parameters(), vec![Node::text(ATTRIBUTE_NAME, "Cryptographic Algorithm"), Node::enumeration(ENCODING_OPTION, 1)])) }),
        cannot!("Get", ONLY_1_4, "Key Wrap Type not supported", "both 1.4 Key Wrap Type values (Not Wrapped, As Registered) are supported"),
        row!("Get", ONLY_1_4, "object is Sensitive", SENSITIVE_REASON, |c| { let id = c.fresh(vec![a("Sensitive", Value::Boolean(true))]); c.call(10, vec![uid(&id)]) }),
        row!("Get", ONLY_1_4, "object is not Extractable", NOT_EXTRACTABLE, |c| { let id = c.fresh(vec![a("Extractable", Value::Boolean(false))]); c.call(10, vec![uid(&id)]) }),
        // 11.13 Get Attributes.
        not_found!("Get Attributes", ALL, 11),
        row!("Get Attributes", FROM_1_1, "an Attribute Name given twice", INVALID_MESSAGE, |c| { let id = c.key.clone(); c.call(11, vec![uid(&id), Node::text(ATTRIBUTE_NAME, "Name"), Node::text(ATTRIBUTE_NAME, "Name")]) }),
        archived!("Get Attributes", ALL, 11),
        cannot!("Get Attributes", ONLY_1_0, "Attribute Index without a matching instance", "the 1.0 Get Attributes request (Table 136) has no Attribute Index field, so a request cannot name an instance; an added Attribute Index is an unknown field (Invalid Field)"),
        // 11.14 Get Attribute List.
        not_found!("Get Attribute List", ALL, 12),
        archived!("Get Attribute List", ALL, 12),
        // 11.15 Add Attribute.
        not_found!("Add Attribute", ALL, 13),
        row!("Add Attribute", ALL, "attribute is read-only", PERMISSION_DENIED, |c| { let id = c.key.clone(); c.call(13, vec![uid(&id), a("Initial Date", Value::DateTime(1))]) }),
        row!("Add Attribute", ALL, "attribute does not apply to the object", PERMISSION_DENIED, |c| { let id = c.secret.clone(); c.call(13, vec![uid(&id), a("Cryptographic Length", Value::Integer(128))]) }),
        row!("Add Attribute", ALL, "attribute already exists", ILLEGAL_OPERATION, |c| { let id = c.fresh(vec![a("Contact Information", Value::TextString("x".into()))]); c.call(13, vec![uid(&id), a("Contact Information", Value::TextString("y".into()))]) }),
        row!("Add Attribute", ALL, "new attribute carries an Attribute Index", INVALID_FIELD, |c| { let id = c.key.clone(); c.call(13, vec![uid(&id), a_at("Object Group", 0, Value::TextString("g".into()))]) }),
        row!("Add Attribute", ALL, "Name already used by another object", ILLEGAL_OPERATION, |c| { c.fresh(vec![name("taken-add")]); let id = c.fresh(vec![]); c.call(13, vec![uid(&id), name("taken-add")]) }),
        cannot!("Add Attribute", ALL, "instance limit reached", NO_INSTANCE_LIMIT),
        row!("Add Attribute", ALL, "unsupported Application Namespace without data", APPLICATION_NAMESPACE_NOT_SUPPORTED, |c| { let id = c.key.clone(); c.call(13, vec![uid(&id), asi("unknown-namespace")]) }),
        archived!("Add Attribute", ALL, 13),
        // 11.16 Modify Attribute.
        not_found!("Modify Attribute", ALL, 14),
        row!("Modify Attribute", ALL, "attribute does not exist yet", INVALID_FIELD, |c| { let id = c.fresh(vec![]); c.call(14, vec![uid(&id), a("Contact Information", Value::TextString("x".into()))]) }),
        row!("Modify Attribute", FROM_1_1, "no matching attribute instance", ITEM_NOT_FOUND, |c| { let id = c.fresh(vec![a("Object Group", Value::TextString("g".into()))]); c.call(14, vec![uid(&id), a_at("Object Group", 4, Value::TextString("h".into()))]) }),
        row!("Modify Attribute", ALL, "attribute is read-only", PERMISSION_DENIED, |c| { let id = c.key.clone(); c.call(14, vec![uid(&id), a("Initial Date", Value::DateTime(1))]) }),
        row!("Modify Attribute", ALL, "Name already used by another object", ILLEGAL_OPERATION, |c| { c.fresh(vec![name("taken-modify")]); let id = c.fresh(vec![name("mine")]); c.call(14, vec![uid(&id), name("taken-modify")]) }),
        row!("Modify Attribute", ALL, "unsupported Application Namespace without data", APPLICATION_NAMESPACE_NOT_SUPPORTED, |c| {
            let id = c.fresh(vec![a("Application Specific Information", Value::Structure(vec![Node::text(APPLICATION_NAMESPACE, "x"), Node::text(APPLICATION_DATA, "y")]))]);
            c.call(14, vec![uid(&id), asi("unknown-namespace")])
        }),
        archived!("Modify Attribute", ALL, 14),
        row!("Modify Attribute", ONLY_1_0, "Attribute Index without a matching instance", ITEM_NOT_FOUND, |c| { let id = c.fresh(vec![a("Object Group", Value::TextString("g".into()))]); c.call(14, vec![uid(&id), a_at("Object Group", 4, Value::TextString("h".into()))]) }),
        // 11.17 Delete Attribute.
        not_found!("Delete Attribute", ALL, 15),
        row!("Delete Attribute", ALL, "attribute is read-only or required", PERMISSION_DENIED, |c| { let id = c.key.clone(); c.call(15, vec![uid(&id), Node::text(ATTRIBUTE_NAME, "Cryptographic Algorithm")]) }),
        row!("Delete Attribute", FROM_1_1, "no matching attribute instance", ITEM_NOT_FOUND, |c| { let id = c.fresh(vec![a("Object Group", Value::TextString("g".into()))]); c.call(15, vec![uid(&id), Node::text(ATTRIBUTE_NAME, "Object Group"), Node::int(ATTRIBUTE_INDEX, 4)]) }),
        row!("Delete Attribute", ALL, "no attribute of that name", ITEM_NOT_FOUND, |c| { let id = c.fresh(vec![]); c.call(15, vec![uid(&id), Node::text(ATTRIBUTE_NAME, "Contact Information")]) }),
        archived!("Delete Attribute", ALL, 15),
        row!("Delete Attribute", ONLY_1_0, "Attribute Index for a single-instance attribute", ITEM_NOT_FOUND, |c| { let id = c.fresh(vec![a("Contact Information", Value::TextString("x".into()))]); c.call(15, vec![uid(&id), Node::text(ATTRIBUTE_NAME, "Contact Information"), Node::int(ATTRIBUTE_INDEX, 1)]) }),
        cannot!("Delete Attribute", ONLY_1_0, "no Attribute Index for a multi-instance attribute",
            "1.0 also says index 0 is assumed when none is given, and clients (OVH kmip-go) rely on it; the server deletes instance 0"),
        // 11.18 Obtain Lease.
        not_found!("Obtain Lease", ALL, 16),
        row!("Obtain Lease", ALL, "no new lease may be issued", PERMISSION_DENIED, |c| { let id = c.destroyed.clone(); c.call(16, vec![uid(&id)]) }),
        archived!("Obtain Lease", ALL, 16),
        // 11.19 Get Usage Allocation.
        not_found!("Get Usage Allocation", ALL, 17),
        row!("Get Usage Allocation", ALL, "no Usage Limits or no protecting use", ILLEGAL_OPERATION, |c| { let id = c.key.clone(); c.call(17, vec![uid(&id), Node::long(USAGE_LIMITS_COUNT, 1)]) }),
        row!("Get Usage Allocation", ALL, "no Usage Limits Count", INVALID_MESSAGE, |c| { let id = c.key.clone(); c.call(17, vec![uid(&id)]) }),
        archived!("Get Usage Allocation", ALL, 17),
        row!("Get Usage Allocation", ALL, "requested amount cannot be granted", PERMISSION_DENIED, |c| {
            let limits = a("Usage Limits", Value::Structure(vec![Node::long(USAGE_LIMITS_TOTAL, 10), Node::long(USAGE_LIMITS_COUNT, 10), Node::enumeration(USAGE_LIMITS_UNIT, 2)]));
            let id = c.fresh(vec![limits]);
            let v = c.v;
            c.f.ok(v, 18, vec![uid(&id)]);
            c.call(17, vec![uid(&id), Node::long(USAGE_LIMITS_COUNT, 11)])
        }),
        // 11.20 Activate.
        not_found!("Activate", ALL, 18),
        row!("Activate", ALL, "object cannot be activated", ILLEGAL_OPERATION, |c| { let id = c.template.clone(); c.call(18, vec![uid(&id)]) }),
        row!("Activate", ALL, "object is not Pre-Active", PERMISSION_DENIED, |c| { let id = c.key.clone(); c.call(18, vec![uid(&id)]) }),
        archived!("Activate", ALL, 18),
        // 11.21 Revoke.
        not_found!("Revoke", ALL, 19),
        row!("Revoke", ALL, "Revocation Reason not recognized", INVALID_FIELD, |c| { let id = c.fresh(vec![]); c.call(19, vec![uid(&id), revocation(0x7F)]) }),
        row!("Revoke", ALL, "object cannot be revoked", ILLEGAL_OPERATION, |c| { let id = c.template.clone(); c.call(19, vec![uid(&id), revocation(1)]) }),
        archived!("Revoke", ALL, 19),
        // 11.22 Destroy.
        not_found!("Destroy", ALL, 20),
        row!("Destroy", ALL, "object already destroyed", PERMISSION_DENIED, |c| { let id = c.destroyed.clone(); c.call(20, vec![uid(&id)]) }),
        row!("Destroy", ALL, "object is Active", PERMISSION_DENIED, |c| { let id = c.key.clone(); c.call(20, vec![uid(&id)]) }),
        archived!("Destroy", ALL, 20),
        // 11.23 Archive and 11.24 Recover.
        not_found!("Archive", ALL, 21),
        row!("Archive", ALL, "object already archived", OBJECT_ARCHIVED, |c| { let id = c.archived.clone(); c.call(21, vec![uid(&id)]) }),
        not_found!("Recover", ALL, 22),
        // 11.25 Validate.
        row!("Validate", ALL, "no certificate list given", INVALID_MESSAGE, |c| c.call(23, vec![])),
        row!("Validate", ALL, "a listed object is archived", OBJECT_ARCHIVED, |c| { let id = c.archived.clone(); c.call(23, vec![uid(&id)]) }),
        // 11.29 Poll.
        row!("Poll", ALL, "no pending operation with the correlation value", ITEM_NOT_FOUND, |c| c.call(26, vec![Node::bytes(ASYNCHRONOUS_CORRELATION_VALUE, vec![9; 16])])),
    ]);
    // 11.30-11.35 cryptographic operations (1.3, 1.4).
    for (table, op) in [
        ("Encrypt", 31u32),
        ("Decrypt", 32),
        ("Sign", 33),
        ("Signature Verify", 34),
        ("MAC", 35),
        ("MAC Verify", 36),
    ] {
        let usable = |c: &mut Ctx, op: u32| -> String {
            if op == 33 {
                c.private.clone()
            } else if op == 34 {
                c.public.clone()
            } else {
                c.key.clone()
            }
        };
        let _ = usable;
        rows.push(match op {
            31 => not_found!("Encrypt", FROM_1_3, 31),
            32 => not_found!("Decrypt", FROM_1_3, 32),
            33 => not_found!("Sign", FROM_1_3, 33),
            34 => not_found!("Signature Verify", FROM_1_3, 34),
            35 => not_found!("MAC", FROM_1_3, 35),
            _ => not_found!("MAC Verify", FROM_1_3, 36),
        });
        rows.push(Row {
            table,
            minors: FROM_1_3,
            label: "object cannot be used for the operation",
            how: Probe(
                Reason(PERMISSION_DENIED),
                match op {
                    31 => |c: &mut Ctx| {
                        let id = c.secret.clone();
                        on(c, 31, &id)
                    },
                    32 => |c: &mut Ctx| {
                        let id = c.secret.clone();
                        on(c, 32, &id)
                    },
                    33 => |c: &mut Ctx| {
                        let id = c.public.clone();
                        on(c, 33, &id)
                    },
                    34 => |c: &mut Ctx| {
                        let id = c.private.clone();
                        on(c, 34, &id)
                    },
                    35 => |c: &mut Ctx| {
                        let id = c.secret.clone();
                        on(c, 35, &id)
                    },
                    _ => |c: &mut Ctx| {
                        let id = c.secret.clone();
                        on(c, 36, &id)
                    },
                },
            ),
        });
        rows.push(Row {
            table,
            minors: FROM_1_3,
            label: "cryptographic error",
            how: Cannot(CRYPTO_INTERNAL),
        });
        rows.push(Row {
            table,
            minors: FROM_1_3,
            label: "object is archived",
            how: Probe(
                Reason(OBJECT_ARCHIVED),
                match op {
                    31 => |c: &mut Ctx| {
                        let id = c.archived.clone();
                        on(c, 31, &id)
                    },
                    32 => |c: &mut Ctx| {
                        let id = c.archived.clone();
                        on(c, 32, &id)
                    },
                    33 => |c: &mut Ctx| {
                        let id = c.archived.clone();
                        on(c, 33, &id)
                    },
                    34 => |c: &mut Ctx| {
                        let id = c.archived.clone();
                        on(c, 34, &id)
                    },
                    35 => |c: &mut Ctx| {
                        let id = c.archived.clone();
                        on(c, 35, &id)
                    },
                    _ => |c: &mut Ctx| {
                        let id = c.archived.clone();
                        on(c, 36, &id)
                    },
                },
            ),
        });
        rows.push(Row {
            table,
            minors: FROM_1_3,
            label: "key value not present",
            how: Probe(
                Reason(KEY_VALUE_NOT_PRESENT),
                match op {
                    31 => |c: &mut Ctx| {
                        let id = c.destroyed.clone();
                        on(c, 31, &id)
                    },
                    32 => |c: &mut Ctx| {
                        let id = c.destroyed.clone();
                        on(c, 32, &id)
                    },
                    33 => |c: &mut Ctx| {
                        let (p, _) = active_pair(c);
                        let v = c.v;
                        c.f.ok(v, 20, vec![uid(&p)]);
                        on(c, 33, &p)
                    },
                    34 => |c: &mut Ctx| {
                        let (_, p) = active_pair(c);
                        let v = c.v;
                        c.f.ok(v, 20, vec![uid(&p)]);
                        on(c, 34, &p)
                    },
                    35 => |c: &mut Ctx| {
                        let id = c.destroyed.clone();
                        on(c, 35, &id)
                    },
                    _ => |c: &mut Ctx| {
                        let id = c.destroyed.clone();
                        on(c, 36, &id)
                    },
                },
            ),
        });
        rows.push(Row {
            table,
            minors: FROM_1_3,
            label: "no stream with the correlation value",
            how: Probe(
                Reason(ITEM_NOT_FOUND),
                match op {
                    31 => |c: &mut Ctx| {
                        let id = c.key.clone();
                        c.call(31, stream(31, &id))
                    },
                    32 => |c: &mut Ctx| {
                        let id = c.key.clone();
                        c.call(32, stream(32, &id))
                    },
                    33 => |c: &mut Ctx| {
                        let id = c.private.clone();
                        c.call(33, stream(33, &id))
                    },
                    34 => |c: &mut Ctx| {
                        let id = c.public.clone();
                        c.call(34, stream(34, &id))
                    },
                    35 => |c: &mut Ctx| {
                        let id = c.key.clone();
                        c.call(35, stream(35, &id))
                    },
                    _ => |c: &mut Ctx| {
                        let id = c.key.clone();
                        c.call(36, stream(36, &id))
                    },
                },
            ),
        });
    }
    rows.extend(vec![
        cannot!("RNG Retrieve", FROM_1_3, "cryptographic error", CRYPTO_INTERNAL),
        cannot!("RNG Seed", FROM_1_3, "cryptographic error", CRYPTO_INTERNAL),
        cannot!("Hash", FROM_1_3, "cryptographic error", CRYPTO_INTERNAL),
        row!("Hash", FROM_1_3, "no stream with the correlation value", ITEM_NOT_FOUND, |c| c.call(39, vec![Node::structure(CRYPTOGRAPHIC_PARAMETERS, vec![Node::enumeration(HASHING_ALGORITHM, 4)]), Node::bytes(DATA, vec![1; 4]), Node::bytes(CORRELATION_VALUE, vec![0xAB; 16])])),
        // 11.39 Create Split Key (1.2-1.4).
        row!("Create Split Key", FROM_1_2, "object type not recognized", INVALID_FIELD, |c| { let k = c.fresh(vec![]); let mut p = split_payload(vec![uid(&k), ta(vec![])], 1); p[0] = Node::enumeration(OBJECT_TYPE, 0x7F); c.call(40, p) }),
        row!("Create Split Key", FROM_1_2, "template does not exist", ITEM_NOT_FOUND, |c| { let k = c.fresh(vec![]); c.call(40, split_payload(vec![uid(&k), ta(vec![template_ref("no-such-template")])], 1)) }),
        row!("Create Split Key", FROM_1_2, "incorrect attribute value", INVALID_FIELD, |c| { let k = c.fresh(vec![]); c.call(40, split_payload(vec![uid(&k), ta(vec![a("Cryptographic Usage Mask", Value::TextString("x".into()))])], 1)) }),
        cannot!("Create Split Key", FROM_1_2, "error creating the cryptographic object", CRYPTO_INTERNAL),
        cannot!("Create Split Key", FROM_1_2, "more instances than supported", NO_INSTANCE_LIMIT),
        row!("Create Split Key", FROM_1_2, "Name already used by another object", INVALID_FIELD, |c| { c.fresh(vec![name("taken-split")]); let k = c.fresh(vec![]); c.call(40, split_payload(vec![uid(&k), ta(vec![name("taken-split")])], 1)) }),
        row!("Create Split Key", FROM_1_2, "unsupported Application Namespace without data", APPLICATION_NAMESPACE_NOT_SUPPORTED, |c| { let k = c.fresh(vec![]); c.call(40, split_payload(vec![uid(&k), ta(vec![asi("unknown-namespace")])], 1)) }),
        row!("Create Split Key", FROM_1_2, "template is archived", OBJECT_ARCHIVED, |c| { let k = c.fresh(vec![]); c.call(40, split_payload(vec![uid(&k), ta(vec![template_ref("archived-tpl")])], 1)) }),
        row!("Create Split Key", FROM_1_2, "Split Key Method not supported", INVALID_FIELD, |c| { let k = c.fresh(vec![]); c.call(40, split_payload(vec![uid(&k), ta(vec![])], 0x7F)) }),
        row!("Create Split Key", FROM_1_2, "no object with the identifier", ITEM_NOT_FOUND, |c| c.call(40, split_payload(vec![uid("no-such-object"), ta(vec![])], 1))),
        // 11.40 Join Split Key (1.2-1.4).
        row!("Join Split Key", FROM_1_2, "object type not recognized", INVALID_FIELD, |c| { let parts = split_parts(c); let mut p = vec![Node::enumeration(OBJECT_TYPE, 0x7F)]; p.extend(parts.iter().map(|id| uid(id))); c.call(41, p) }),
        row!("Join Split Key", FROM_1_2, "template does not exist", ITEM_NOT_FOUND, |c| { let parts = split_parts(c); join(c, &parts, vec![ta(vec![template_ref("no-such-template")])]) }),
        row!("Join Split Key", FROM_1_2, "incorrect attribute value", INVALID_FIELD, |c| { let parts = split_parts(c); join(c, &parts, vec![ta(vec![a("Cryptographic Usage Mask", Value::TextString("x".into()))])]) }),
        cannot!("Join Split Key", FROM_1_2, "error creating the cryptographic object", CRYPTO_INTERNAL),
        cannot!("Join Split Key", FROM_1_2, "more instances than supported", NO_INSTANCE_LIMIT),
        row!("Join Split Key", FROM_1_2, "Name already used by another object", INVALID_FIELD, |c| { c.fresh(vec![name("taken-join")]); let parts = split_parts(c); join(c, &parts, vec![ta(vec![name("taken-join")])]) }),
        row!("Join Split Key", FROM_1_2, "unsupported Application Namespace without data", APPLICATION_NAMESPACE_NOT_SUPPORTED, |c| { let parts = split_parts(c); join(c, &parts, vec![ta(vec![asi("unknown-namespace")])]) }),
        row!("Join Split Key", FROM_1_2, "template is archived", OBJECT_ARCHIVED, |c| { let parts = split_parts(c); join(c, &parts, vec![ta(vec![template_ref("archived-tpl")])]) }),
        row!("Join Split Key", FROM_1_2, "fewer parts than the threshold", CRYPTOGRAPHIC_FAILURE, |c| { let parts = split_parts(c); join(c, &parts[..1], vec![]) }),
        cannot!("Join Split Key", FROM_1_2, "Split Key Method not supported", "the method comes from the stored Split Key parts, which Create Split Key or Register only accept with a supported method"),
        row!("Join Split Key", FROM_1_2, "no object with the identifier", ITEM_NOT_FOUND, |c| { let mut parts = split_parts(c); parts[1] = "no-such-object".into(); join(c, &parts, vec![]) }),
        row!("Join Split Key", FROM_1_2, "a part is archived", OBJECT_ARCHIVED, |c| { let parts = split_parts(c); let v = c.v; c.f.ok(v, 21, vec![uid(&parts[0])]); join(c, &parts, vec![]) }),
    ]);
    rows.extend(transfer_rows("Export", ONLY_1_4, 43));
    rows.extend(vec![
        row!("Export", ONLY_1_4, "value cannot be given in the Encoding Option", ENCODING_OPTION_ERROR, |c| {
            let k = c.key.clone();
            let id = c.private.clone();
            c.call(43, vec![uid(&id), Node::enumeration(KEY_FORMAT_TYPE, 10), wrapping_with(1, ENCRYPTION_KEY_INFORMATION, &k, key_wrap_parameters(), vec![Node::enumeration(ENCODING_OPTION, 1)])])
        }),
        row!("Export", ONLY_1_4, "Encoding Option with wrapped attribute names", ENCODING_OPTION_ERROR, |c| { let k = c.key.clone(); wrapped(c, 43, wrapping_with(1, ENCRYPTION_KEY_INFORMATION, &k, key_wrap_parameters(), vec![Node::text(ATTRIBUTE_NAME, "Cryptographic Algorithm"), Node::enumeration(ENCODING_OPTION, 1)])) }),
        cannot!("Export", ONLY_1_4, "Key Wrap Type not supported", "both 1.4 Key Wrap Type values (Not Wrapped, As Registered) are supported"),
        // 11.42 Import (1.4).
        row!("Import", ONLY_1_4, "identifier exists and Replace Existing is not set", OBJECT_ALREADY_EXISTS, |c| { let id = c.fresh(vec![]); c.call(42, import_payload(&id, vec![])) }),
        row!("Import", ONLY_1_4, "object type not recognized", INVALID_FIELD, |c| { let mut p = import_payload("import-1", vec![]); p[1] = Node::enumeration(OBJECT_TYPE, 0x7F); c.call(42, p) }),
        row!("Import", ONLY_1_4, "object type does not match the object", INVALID_FIELD, |c| { let mut p = import_payload("import-2", vec![]); p[1] = Node::enumeration(OBJECT_TYPE, 7); c.call(42, p) }),
        row!("Import", ONLY_1_4, "incorrect attribute value", INVALID_FIELD, |c| c.call(42, import_payload("import-3", vec![a("Contact Information", Value::Integer(1))]))),
        row!("Import", ONLY_1_4, "Name already used by another object", INVALID_FIELD, |c| { c.fresh(vec![name("taken-import")]); c.call(42, import_payload("import-4", vec![name("taken-import")])) }),
        cannot!("Import", ONLY_1_4, "more instances than supported", NO_INSTANCE_LIMIT),
        row!("Import", ONLY_1_4, "unsupported Application Namespace without data", APPLICATION_NAMESPACE_NOT_SUPPORTED, |c| c.call(42, import_payload("import-5", vec![asi("unknown-namespace")]))),
        cannot!("Import", ONLY_1_4, "Encoding Option with wrapped attribute names", "an Import request has no Key Wrapping Specification, so it cannot name attributes to wrap"),
        row!("Import", ONLY_1_4, "field not supported", INVALID_FIELD, |c| c.call(42, import_payload("import-6", vec![Node::int(BATCH_COUNT, 1)]))),
        // 11.43 Batch Items: a failed item answers with its operation's reason.
        row!("Batch Items", ALL, "failure under Stop", ITEM_NOT_FOUND, |c| batch(c, 2)),
        row!("Batch Items", ALL, "failure under Continue", ITEM_NOT_FOUND, |c| batch(c, 1)),
        row!("Batch Items", ALL, "failure under Undo", ITEM_NOT_FOUND, |c| batch(c, 3)),
    ]);
    rows
}
/// A two-item batch whose second item fails: the first item keeps its normal
/// response (Stop, Continue) or is undone (Undo), the failed item carries the
/// Get table's reason, and Stop leaves no item unprocessed beyond the failure.
fn batch(c: &mut Ctx, option: u32) -> Option<u32> {
    let v = c.v;
    let r = c.f.send(&req(
        v,
        vec![Node::enumeration(BATCH_ERROR_CONTINUATION_OPTION, option)],
        vec![
            (1, create_payload(vec![])),
            (10, vec![uid("no-such-object")]),
            (24, vec![Node::enumeration(QUERY_FUNCTION, 1)]),
        ],
    ));
    let items: Vec<_> = r.all(BATCH_ITEM).collect();
    let statuses: Vec<_> = items.iter().map(|i| num(i, RESULT_STATUS)).collect();
    let expected: &[u32] = match option {
        1 => &[0, 1, 0],
        2 => &[0, 1],
        // The processed item is reported as Operation Undone.
        _ => &[3, 1],
    };
    if statuses != expected {
        return Some(0xFFFF);
    }
    if option == 3 {
        // The first item was undone: its object no longer exists.
        let id = text(
            items[0].required(RESPONSE_PAYLOAD).unwrap(),
            UNIQUE_IDENTIFIER,
        );
        if outcome(&c.f.call(v, 10, vec![uid(&id)])) != Some(ITEM_NOT_FOUND) {
            return Some(0xFFFE);
        }
    }
    Some(num(items[1], RESULT_REASON))
}

fn run(rows: &[Row]) -> Vec<String> {
    let mut problems = vec![];
    for v in V {
        let mut c = Ctx::new(v);
        for row in rows.iter().filter(|r| r.minors.contains(&v.1)) {
            let How::Probe(expect, probe) = &row.how else {
                continue;
            };
            LAST.with(|m| m.borrow_mut().clear());
            let got = probe(&mut c);
            let want = match expect {
                Reason(r) => Some(*r),
                Success => None,
            };
            if got != want {
                problems.push(format!(
                    "{}.{} {}: {}: expected {:?}, got {:?} ({})",
                    v.0,
                    v.1,
                    row.table,
                    row.label,
                    want,
                    got,
                    LAST.with(|m| m.borrow().clone())
                ));
            }
        }
    }
    problems
}

/// Rows of each edition's error tables (1.0 Tables 226-251 ... 1.4 Tables
/// 327-366), counted from the pinned specifications.
const TABLE_ROWS: [(u32, usize); 5] = [(0, 136), (1, 145), (2, 173), (3, 213), (4, 238)];

#[test]
fn rows_match_the_tables() {
    let mut all = rows();
    all.extend(rows2());
    for (minor, count) in TABLE_ROWS {
        let rows = all.iter().filter(|r| r.minors.contains(&minor)).count();
        assert_eq!(rows, count, "1.{minor}");
    }
    let cannot: Vec<_> = all
        .iter()
        .filter_map(|r| match r.how {
            Cannot(why) => Some(why),
            Probe(..) => None,
        })
        .collect();
    assert!(cannot.iter().all(|why| !why.is_empty()));
    assert!(
        cannot.len() < all.len() / 5,
        "{} rows cannot be produced",
        cannot.len()
    );
}

// REQ:b3fd13bc4403d75a 1.0-1.4 section 11: each listed error condition gets the Result Reason its table row names (every row of every table, per edition)
// REQ:e43922bb140e910d 1.0-1.4: a failed item's Result Reason is the one section 11 gives for its condition
#[test]
fn every_error_table_row_gets_its_result_reason() {
    let mut all = rows();
    all.extend(rows2());
    let problems = run(&all);
    assert!(problems.is_empty(), "{}", problems.join("\n"));
}
