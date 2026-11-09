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

//! Focused tests for per-operation server clauses of the requirement matrix
//! (operations of KMIP 1.0-2.1). Each asserting test names the
//! clause digests it checks as `REQ:<digest>` (see
//! docs/specs/requirement-matrix.json); the paraphrases are our own words.
use keytend_kmip_server::{
    protocol::{Engine, Version},
    store::Store,
    tags::*,
    ttlv::{Node, Value},
};
use tempfile::TempDir;

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
    _dir: TempDir,
    engine: Engine,
}
impl Fixture {
    fn new() -> Self {
        let d = tempfile::tempdir().unwrap();
        let k = d.path().join("master");
        std::fs::write(&k, [42; 32]).unwrap();
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
    /// One operation in its own request.
    fn call(&mut self, v: Version, op: u32, payload: Vec<Node>) -> Node {
        self.send(&req(v, vec![], vec![(op, payload)]))
    }
    /// A batch whose items all run (Batch Error Continuation Option Continue).
    fn batch(&mut self, v: Version, items: Vec<(u32, Vec<Node>)>) -> Node {
        self.send(&req(
            v,
            vec![Node::enumeration(BATCH_ERROR_CONTINUATION_OPTION, 1)],
            items,
        ))
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
fn items(r: &Node) -> Vec<&Node> {
    r.all(BATCH_ITEM).collect()
}
fn num(n: &Node, tag: u32) -> u32 {
    n.required(tag).unwrap().number().unwrap()
}
fn status_of(item: &Node) -> u32 {
    num(item, RESULT_STATUS)
}
fn item_payload(item: &Node) -> &Node {
    assert_eq!(
        status_of(item),
        0,
        "reason {:?} {:?}",
        item.get(RESULT_REASON).map(|n| n.number()),
        item.get(RESULT_MESSAGE).map(|n| n.string())
    );
    item.required(RESPONSE_PAYLOAD).unwrap()
}
fn payload(r: &Node) -> &Node {
    item_payload(items(r)[0])
}
/// Result Reason of a failed item.
fn item_reason(item: &Node) -> u32 {
    assert_eq!(status_of(item), 1, "expected Operation Failed");
    num(item, RESULT_REASON)
}
fn reason(r: &Node) -> u32 {
    item_reason(items(r)[0])
}
fn text(n: &Node, tag: u32) -> String {
    n.required(tag)
        .unwrap()
        .identifier_text()
        .unwrap()
        .to_owned()
}
fn id_of(r: &Node) -> String {
    text(payload(r), UNIQUE_IDENTIFIER)
}
fn uid(id: &str) -> Node {
    Node::text(UNIQUE_IDENTIFIER, id)
}
/// An attribute given with its 2.x tag, written in the edition's form.
fn attribute(v: Version, a: Node) -> Node {
    attribute_at(v, a, None)
}
fn attribute_at(v: Version, a: Node, index: Option<i32>) -> Node {
    if v.0 >= 2 {
        return a;
    }
    let mut fields = vec![Node::text(ATTRIBUTE_NAME, tag_name(a.tag).unwrap())];
    if let Some(i) = index {
        fields.push(Node::int(ATTRIBUTE_INDEX, i));
    }
    fields.push(Node {
        tag: ATTRIBUTE_VALUE,
        value: a.value.clone(),
    });
    Node::structure(ATTRIBUTE, fields)
}
/// Template-Attribute (1.x) or Attributes (2.x) holding `attrs`.
fn container(v: Version, attrs: Vec<Node>) -> Node {
    container_as(v, TEMPLATE_ATTRIBUTE, ATTRIBUTES, attrs)
}
fn container_as(v: Version, one: u32, two: u32, attrs: Vec<Node>) -> Node {
    if v.0 >= 2 {
        Node::structure(two, attrs)
    } else {
        Node::structure(one, attrs.into_iter().map(|a| attribute(v, a)).collect())
    }
}
fn aes(usage: i32) -> Vec<Node> {
    vec![
        Node::enumeration(CRYPTOGRAPHIC_ALGORITHM, 3),
        Node::int(CRYPTOGRAPHIC_LENGTH, 256),
        Node::int(CRYPTOGRAPHIC_USAGE_MASK, usage),
    ]
}
fn create_with(f: &mut Fixture, v: Version, extra: Vec<Node>) -> String {
    let mut a = aes(12);
    a.extend(extra);
    id_of(&f.call(
        v,
        1,
        vec![Node::enumeration(OBJECT_TYPE, 2), container(v, a)],
    ))
}
fn create(f: &mut Fixture, v: Version) -> String {
    create_with(f, v, vec![])
}
fn create_item(v: Version, extra: Vec<Node>) -> (u32, Vec<Node>) {
    let mut a = aes(12);
    a.extend(extra);
    (1, vec![Node::enumeration(OBJECT_TYPE, 2), container(v, a)])
}
fn activate(f: &mut Fixture, v: Version, id: &str) {
    payload(&f.call(v, 18, vec![uid(id)]));
}
/// The values returned by Get Attributes for one attribute (by 2.x tag).
fn attr_values(f: &mut Fixture, v: Version, id: &str, tag: u32) -> Vec<Node> {
    let name = tag_name(tag).unwrap();
    let selector = if v.0 >= 2 {
        Node::enumeration(ATTRIBUTE_REFERENCE, tag)
    } else {
        Node::text(ATTRIBUTE_NAME, name)
    };
    let r = f.call(v, 11, vec![uid(id), selector]);
    let p = payload(&r);
    if v.0 >= 2 {
        p.get(ATTRIBUTES)
            .map(|a| a.all(tag).cloned().collect())
            .unwrap_or_default()
    } else {
        p.all(ATTRIBUTE)
            .filter(|a| a.get(ATTRIBUTE_NAME).unwrap().string().unwrap() == name)
            .map(|a| Node {
                tag,
                value: a.required(ATTRIBUTE_VALUE).unwrap().value.clone(),
            })
            .collect()
    }
}
/// Register a raw symmetric key (or Secret Data, kind 7) with `attrs`.
fn register_raw(f: &mut Fixture, v: Version, kind: u32, bytes: &[u8], attrs: Vec<Node>) -> Node {
    let mut block = vec![
        Node::enumeration(KEY_FORMAT_TYPE, 1),
        Node::structure(KEY_VALUE, vec![Node::bytes(KEY_MATERIAL, bytes.to_vec())]),
    ];
    if kind == 2 {
        block.push(Node::enumeration(CRYPTOGRAPHIC_ALGORITHM, 3));
        block.push(Node::int(CRYPTOGRAPHIC_LENGTH, (bytes.len() * 8) as i32));
    }
    let mut object = vec![];
    if kind == 7 {
        object.push(Node::enumeration(SECRET_DATA_TYPE, 2));
    }
    object.push(Node::structure(KEY_BLOCK, block));
    f.call(
        v,
        3,
        vec![
            Node::enumeration(OBJECT_TYPE, kind),
            container(v, attrs),
            Node::structure(
                if kind == 7 {
                    SECRET_DATA
                } else {
                    SYMMETRIC_KEY
                },
                object,
            ),
        ],
    )
}
/// Derive Key request fields from `sources` with `method` and `params`.
fn derive_fields(
    v: Version,
    sources: &[&str],
    bits: Option<i32>,
    alg: bool,
    method: u32,
    params: Vec<Node>,
) -> Vec<Node> {
    let mut attrs = vec![Node::int(CRYPTOGRAPHIC_USAGE_MASK, 12)];
    if let Some(b) = bits {
        attrs.push(Node::int(CRYPTOGRAPHIC_LENGTH, b));
    }
    if alg {
        attrs.push(Node::enumeration(CRYPTOGRAPHIC_ALGORITHM, 3));
    }
    let mut fields = vec![Node::enumeration(OBJECT_TYPE, 2)];
    fields.extend(sources.iter().map(|id| uid(id)));
    fields.push(Node::enumeration(DERIVATION_METHOD, method));
    fields.push(Node::structure(DERIVATION_PARAMETERS, params));
    fields.push(container(v, attrs));
    fields
}

fn uids(p: &Node) -> Vec<String> {
    p.all(UNIQUE_IDENTIFIER)
        .map(|n| n.identifier_text().unwrap().to_owned())
        .collect()
}
/// Locate request fields for the given attributes.
fn locate_fields(v: Version, attrs: Vec<Node>) -> Vec<Node> {
    if v.0 >= 2 {
        vec![Node::structure(ATTRIBUTES, attrs)]
    } else {
        attrs.into_iter().map(|a| attribute(v, a)).collect()
    }
}
fn group(name: &str) -> Node {
    Node::text(OBJECT_GROUP, name)
}

// REQ:f2dbc8c2794e8909 the server keeps an ID Placeholder within a batch
// REQ:b45b5de70d82ac35 an identifier-returning operation fills the placeholder until a later one replaces it
// REQ:d1d2eba7d00186b0 the placeholder does not survive into the next request
#[test]
fn id_placeholder_lives_for_one_batch_and_follows_the_latest_identifier() {
    for v in FINAL {
        let mut f = Fixture::new();
        let r = f.batch(
            v,
            vec![
                create_item(v, vec![]),
                (11, vec![]),
                create_item(v, vec![]),
                (11, vec![]),
            ],
        );
        let it = items(&r);
        let first = text(item_payload(it[0]), UNIQUE_IDENTIFIER);
        let second = text(item_payload(it[2]), UNIQUE_IDENTIFIER);
        assert_ne!(first, second);
        assert_eq!(text(item_payload(it[1]), UNIQUE_IDENTIFIER), first);
        assert_eq!(text(item_payload(it[3]), UNIQUE_IDENTIFIER), second);
        // A new request starts without a placeholder.
        assert_eq!(status_of(items(&f.call(v, 11, vec![]))[0]), 1);
    }
}

// REQ:9d4f71c48efbb903 Create, Register, Derive Key and Join Split Key put their new identifier in the placeholder
// REQ:5124c34f2133d9db Register (1.x) and Import/Export (1.4+) put the returned identifier in the placeholder
#[test]
fn creating_operations_set_the_placeholder_to_their_new_object() {
    for v in FINAL {
        let mut f = Fixture::new();
        let source = id_of(&register_raw(
            &mut f,
            v,
            2,
            &[9; 32],
            vec![
                Node::int(CRYPTOGRAPHIC_USAGE_MASK, 512 | 12),
                ecb_parameters(),
            ],
        ));
        activate(&mut f, v, &source);
        let registration = vec![
            Node::enumeration(OBJECT_TYPE, 2),
            container(v, vec![Node::int(CRYPTOGRAPHIC_USAGE_MASK, 12)]),
            Node::structure(
                SYMMETRIC_KEY,
                vec![Node::structure(
                    KEY_BLOCK,
                    vec![
                        Node::enumeration(KEY_FORMAT_TYPE, 1),
                        Node::structure(KEY_VALUE, vec![Node::bytes(KEY_MATERIAL, vec![5; 16])]),
                        Node::enumeration(CRYPTOGRAPHIC_ALGORITHM, 3),
                        Node::int(CRYPTOGRAPHIC_LENGTH, 128),
                    ],
                )],
            ),
        ];
        let derivation = derive_fields(
            v,
            &[&source],
            Some(128),
            true,
            4,
            vec![
                Node::structure(
                    CRYPTOGRAPHIC_PARAMETERS,
                    vec![Node::enumeration(BLOCK_CIPHER_MODE, 2)],
                ),
                Node::bytes(DERIVATION_DATA, vec![1; 16]),
            ],
        );
        let mut ops = vec![create_item(v, vec![]), (3, registration), (5, derivation)];
        if v >= Version(1, 4) {
            ops.push((43, vec![uid(&source)]));
        }
        for op in ops {
            let code = op.0;
            let r = f.batch(v, vec![op, (11, vec![])]);
            let it = items(&r);
            let created = text(item_payload(it[0]), UNIQUE_IDENTIFIER);
            assert_eq!(
                text(item_payload(it[1]), UNIQUE_IDENTIFIER),
                created,
                "operation {code}"
            );
        }
        if v >= Version(1, 4) {
            // Import the exported object into another server.
            let exported = payload(&f.call(v, 43, vec![uid(&source)])).clone();
            let mut g = Fixture::new();
            let r = g.batch(
                v,
                vec![(42, exported.children().unwrap().to_vec()), (11, vec![])],
            );
            let it = items(&r);
            assert_eq!(text(item_payload(it[0]), UNIQUE_IDENTIFIER), source);
            assert_eq!(text(item_payload(it[1]), UNIQUE_IDENTIFIER), source);
        }
    }
}

// REQ:0473e4bd66f92d2c Derive Key never takes its source from the placeholder
#[test]
fn derive_key_ignores_the_placeholder() {
    for v in FINAL {
        let mut f = Fixture::new();
        let r = f.batch(
            v,
            vec![
                create_item(v, vec![]),
                (
                    5,
                    derive_fields(
                        v,
                        &[],
                        Some(128),
                        true,
                        4,
                        vec![Node::bytes(DERIVATION_DATA, vec![1; 16])],
                    ),
                ),
            ],
        );
        assert_eq!(statuses(&r), [0, 1]);
    }
}
fn ecb_parameters() -> Node {
    Node::structure(
        CRYPTOGRAPHIC_PARAMETERS,
        vec![Node::enumeration(BLOCK_CIPHER_MODE, 2)],
    )
}
fn statuses(r: &Node) -> Vec<u32> {
    items(r).into_iter().map(status_of).collect()
}

// REQ:9f0d8b3945817f11 a Locate with one result puts it in the placeholder
// REQ:80ff2f64f058a0e1 a Locate with several results empties the placeholder
// REQ:829da97320286280 later implicit-identifier items then fail
#[test]
fn locate_sets_or_empties_the_placeholder() {
    for v in FINAL {
        let mut f = Fixture::new();
        let one = create_with(&mut f, v, vec![group("single")]);
        create_with(&mut f, v, vec![group("pair")]);
        create_with(&mut f, v, vec![group("pair")]);
        let r = f.batch(
            v,
            vec![(8, locate_fields(v, vec![group("single")])), (11, vec![])],
        );
        assert_eq!(text(item_payload(items(&r)[1]), UNIQUE_IDENTIFIER), one);
        // A preceding Create's identifier is cleared by an ambiguous Locate.
        for max in [None, Some(2)] {
            let mut locate = locate_fields(v, vec![group("pair")]);
            if let Some(m) = max {
                locate.push(Node::int(MAXIMUM_ITEMS, m));
            }
            let r = f.batch(v, vec![create_item(v, vec![]), (8, locate), (11, vec![])]);
            let it = items(&r);
            assert_eq!(uids(item_payload(it[1])).len(), 2);
            assert_eq!(status_of(it[2]), 1);
        }
        // Maximum Items 1 returns a single identifier, which is kept.
        let r = f.batch(
            v,
            vec![
                (
                    8,
                    [
                        locate_fields(v, vec![group("pair")]),
                        vec![Node::int(MAXIMUM_ITEMS, 1)],
                    ]
                    .concat(),
                ),
                (11, vec![]),
            ],
        );
        let it = items(&r);
        assert_eq!(
            uids(item_payload(it[0])),
            [text(item_payload(it[1]), UNIQUE_IDENTIFIER)]
        );
    }
}

// REQ:e7e098436a589d11 Create Key Pair leaves the private key in the placeholder
// REQ:50a25b3d0e886df5 the new private key links to its public key
// REQ:421cc54609736830 the new public key links to its private key
#[test]
fn create_key_pair_links_both_keys_and_names_the_private_key() {
    for v in FINAL {
        let mut f = Fixture::new();
        let r = f.batch(v, vec![(2, rsa_pair(v, vec![])), (10, vec![])]);
        let it = items(&r);
        let p = item_payload(it[0]);
        let private = text(p, PRIVATE_KEY_UNIQUE_IDENTIFIER);
        let public = text(p, PUBLIC_KEY_UNIQUE_IDENTIFIER);
        let got = item_payload(it[1]);
        assert_eq!(text(got, UNIQUE_IDENTIFIER), private);
        assert_eq!(num(got, OBJECT_TYPE), 4);
        if v >= Version(1, 2) {
            assert_eq!(
                links(&mut f, v, &private, 0x102),
                std::slice::from_ref(&public)
            );
            assert_eq!(
                links(&mut f, v, &public, 0x103),
                std::slice::from_ref(&private)
            );
        }
    }
}
fn rsa_pair(v: Version, common: Vec<Node>) -> Vec<Node> {
    let mut c = vec![
        Node::enumeration(CRYPTOGRAPHIC_ALGORITHM, 4),
        Node::int(CRYPTOGRAPHIC_LENGTH, 2048),
    ];
    c.extend(common);
    vec![
        container_as(v, COMMON_TEMPLATE_ATTRIBUTE, COMMON_ATTRIBUTES, c),
        container_as(
            v,
            PRIVATE_KEY_TEMPLATE_ATTRIBUTE,
            PRIVATE_KEY_ATTRIBUTES,
            vec![Node::int(CRYPTOGRAPHIC_USAGE_MASK, 1)],
        ),
        container_as(
            v,
            PUBLIC_KEY_TEMPLATE_ATTRIBUTE,
            PUBLIC_KEY_ATTRIBUTES,
            vec![Node::int(CRYPTOGRAPHIC_USAGE_MASK, 2)],
        ),
    ]
}
/// Link targets of one Link Type, read through Get Attributes.
fn links(f: &mut Fixture, v: Version, id: &str, kind: u32) -> Vec<String> {
    attr_values(f, v, id, LINK)
        .iter()
        .filter(|l| num(l, LINK_TYPE) == kind)
        .map(|l| text(l, LINKED_OBJECT_IDENTIFIER))
        .collect()
}

fn query(f: &mut Fixture, v: Version, functions: &[u32]) -> Node {
    let r = f.call(
        v,
        24,
        functions
            .iter()
            .map(|q| Node::enumeration(QUERY_FUNCTION, *q))
            .collect(),
    );
    payload(&r).clone()
}
fn enums(p: &Node, tag: u32) -> Vec<u32> {
    p.all(tag).map(|n| n.number().unwrap()).collect()
}

// REQ:b6f55a168afc5262 1.x Query Operations lists every operation the server performs
// REQ:e5afa35f9c59096d 2.x Query Operations lists every operation the server performs
// REQ:8ebb919051e44406 Query Operations returns the Operation fields
// REQ:e7f2940784cc063c the test-only Interop operation is not available
#[test]
fn query_operations_lists_exactly_the_operations_that_are_not_refused() {
    for v in FINAL {
        let mut f = Fixture::new();
        let listed = enums(&query(&mut f, v, &[1]), OPERATION);
        assert!(!listed.is_empty());
        for op in 1..=70 {
            let r = f.call(v, op, vec![]);
            let refused = status_of(items(&r)[0]) == 1 && reason(&r) == 5;
            assert_eq!(
                refused,
                !listed.contains(&op),
                "{}.{} operation {op}",
                v.0,
                v.1
            );
        }
        // Interop (2.x section 6.1.26) is a test-only operation.
        assert!(!listed.contains(&52));
    }
}

// REQ:64f5d15b3170aa0a 1.x Query Objects lists the object types the server handles
// REQ:bf4362cc2a68e7d4 2.x Query Objects lists the object types the server handles
// REQ:b238395ce8fca9c5 Query Objects returns the Object Type fields
#[test]
fn query_objects_lists_the_object_types_that_can_be_registered() {
    for v in FINAL {
        let mut f = Fixture::new();
        let listed = enums(&query(&mut f, v, &[2]), OBJECT_TYPE);
        let mut expected = vec![1, 2, 3, 4, 5];
        if v < Version(2, 0) {
            expected.push(6);
        }
        expected.extend([7, 8]);
        if v >= Version(1, 2) {
            expected.push(9);
        }
        // Certificate Request objects exist from 2.0 (docs/certificates.md#certificate-requests).
        if v >= Version(2, 0) {
            expected.push(10);
        }
        assert_eq!(listed, expected, "{}.{}", v.0, v.1);
        // Types outside the list are refused by Register.
        for kind in (1..=16).filter(|k| !listed.contains(k)) {
            let r = f.call(
                v,
                3,
                vec![Node::enumeration(OBJECT_TYPE, kind), container(v, vec![])],
            );
            assert_eq!(status_of(items(&r)[0]), 1, "type {kind}");
        }
    }
}

// REQ:0020690c72168500 Query Server Information returns the vendor field
// REQ:93d84c2e1b5eda1b Vendor Identification is returned for Query Server Information
// REQ:3d5ddf9252cdc504 the Vendor Identification names this implementation
// REQ:289ce61b5929bb64 Application Namespace fields only answer Query Application Namespaces
// REQ:047d567c6e4b284c 1.0: the server generates data for no namespace and lists none
// REQ:43bef70b07960ebd 1.1-1.4: the server generates data for no namespace and lists none
// REQ:c7b834e1c8c8cbcf 2.x: the server generates data for no namespace and lists none
// REQ:a03d9b8e1e3735f2 2.x: each requested Query Function gets its items
#[test]
fn query_server_information_and_namespaces() {
    for v in FINAL {
        let mut f = Fixture::new();
        let p = query(&mut f, v, &[1, 2, 3, 4]);
        assert_eq!(
            p.required(VENDOR_IDENTIFICATION).unwrap().string().unwrap(),
            "keytend-kmip-server"
        );
        assert!(p.get(SERVER_INFORMATION).is_some());
        assert!(p.get(OPERATION).is_some() && p.get(OBJECT_TYPE).is_some());
        assert!(p.get(APPLICATION_NAMESPACE).is_none());
        let p = query(&mut f, v, &[1]);
        assert!(p.get(VENDOR_IDENTIFICATION).is_none());
        assert!(p.get(APPLICATION_NAMESPACE).is_none());
        // Application data is never generated: a namespace without data is refused.
        let id = create(&mut f, v);
        let asi = Node::structure(
            APPLICATION_SPECIFIC_INFORMATION,
            vec![Node::text(APPLICATION_NAMESPACE, "ssl")],
        );
        let add = if v.0 >= 2 {
            Node::structure(NEW_ATTRIBUTE, vec![asi])
        } else {
            attribute(v, asi)
        };
        assert_eq!(status_of(items(&f.call(v, 13, vec![uid(&id), add]))[0]), 1);
    }
}

// REQ:446d7454217f413e Query Extension List/Map answers with the (empty) extension list
// REQ:63ca8a56fcb67322 no extension is supported, so no Extension Information is returned
// REQ:c26586d7743020c4 1.2-1.4 Query Attestation Types lists the supported types: none
// REQ:188f451b84abe50e 2.x Query Attestation Types lists the supported types: none
// REQ:2a2ee073fa03bff0 Query Attestation Types succeeds and returns no type
// REQ:e0833d9a2ef8e5d2 1.3/1.4 Query RNGs lists the server's generator
// REQ:b97a4fe25c98a05f 2.x Query RNGs lists the server's generator
// REQ:87e0efbb14aded0f Query RNGs returns RNG Parameters
// REQ:10cbf83d599d2511 an undescribed generator is reported with RNG Algorithm Unspecified
// REQ:b30d6d0f1da25a81 2.x: an undescribed generator is reported as Unspecified
// REQ:d8e9aabfad0cec24 Query Validations returns zero Validation Information fields
// REQ:5633fba820bbb66a Query Profiles succeeds; no profile is claimed, so none is returned
// REQ:08a2142dd2eb3868 1.3/1.4: no client registration method is offered and none is listed
// REQ:7b106c6b5595b394 2.x: no client registration method is offered and none is listed
// REQ:a31dfe46ee58d3bb Query Client Registration Methods returns nothing when none is supported
// REQ:ab5c30280beae532 2.x Query Client Registration Methods returns nothing when none is supported
#[test]
fn query_capability_functions_answer_by_edition() {
    for v in FINAL {
        let mut f = Fixture::new();
        for q in [5, 6] {
            let p = query(&mut f, v, &[q]);
            assert!(p.children().unwrap().is_empty());
        }
        let refused = |f: &mut Fixture, q: u32| {
            let r = f.call(v, 24, vec![Node::enumeration(QUERY_FUNCTION, q)]);
            status_of(items(&r)[0]) == 1
        };
        if v >= Version(1, 2) {
            assert!(query(&mut f, v, &[7]).children().unwrap().is_empty());
        } else {
            assert!(refused(&mut f, 7));
        }
        if v >= Version(1, 3) {
            let p = query(&mut f, v, &[8]);
            let rngs: Vec<&Node> = p.all(RNG_PARAMETERS).collect();
            assert_eq!(rngs.len(), 1);
            assert_eq!(num(rngs[0], RNG_ALGORITHM), 1);
            for q in [9, 10, 12] {
                assert!(query(&mut f, v, &[q]).children().unwrap().is_empty(), "{q}");
            }
            let caps = query(&mut f, v, &[11]);
            let caps = caps.required(CAPABILITY_INFORMATION).unwrap();
            assert!(
                !caps
                    .required(ATTESTATION_CAPABILITY)
                    .unwrap()
                    .flag()
                    .unwrap()
            );
        } else {
            for q in [8, 9, 10, 12] {
                assert!(refused(&mut f, q), "{q}");
            }
        }
    }
}

// REQ:7ff3a572895845c2 1.0/1.1 Locate ignores Attribute Index values
// REQ:ba60de6a6924051c 1.2-1.4 Locate ignores Attribute Index values
// REQ:fd6f427dab69705f Locate returns only objects that match every given attribute
// REQ:b70e1d1f42d61a18 Locate without attributes matches every object
#[test]
fn locate_matches_all_given_attributes_and_ignores_indices() {
    for v in FINAL {
        let mut f = Fixture::new();
        let a = create_with(&mut f, v, vec![group("blue")]);
        let b = create_with(
            &mut f,
            v,
            vec![group("blue"), Node::text(OBJECT_GROUP, "x")],
        );
        let c = create_with(&mut f, v, vec![group("red")]);
        let found = |f: &mut Fixture, fields: Vec<Node>| {
            let mut ids = uids(payload(&f.call(v, 8, fields)));
            ids.sort();
            ids
        };
        let mut all = vec![a.clone(), b.clone(), c.clone()];
        all.sort();
        assert_eq!(found(&mut f, vec![]), all);
        let mut blue = vec![a.clone(), b.clone()];
        blue.sort();
        assert_eq!(found(&mut f, locate_fields(v, vec![group("blue")])), blue);
        assert_eq!(
            found(&mut f, locate_fields(v, vec![group("blue"), group("x")])),
            std::slice::from_ref(&b)
        );
        assert!(found(&mut f, locate_fields(v, vec![group("blue"), group("red")])).is_empty());
        if v.0 == 1 {
            let indexed = vec![attribute_at(v, group("red"), Some(5))];
            assert_eq!(found(&mut f, indexed), std::slice::from_ref(&c));
        }
    }
}

// REQ:271ce95bcfe32dad 1.0 Locate by Usage Limits keeps objects with at least the requested amounts
// REQ:1d780f38f858c085 1.1 Locate by Usage Limits keeps objects with at least the requested amounts
// REQ:0be7ae9fca33d94f 1.2-2.1 Locate by Usage Limits keeps objects with at least the requested amounts
#[test]
fn locate_by_usage_limits_requires_enough_remaining_usage() {
    let limits = |total: i64, count: i64| {
        Node::structure(
            USAGE_LIMITS,
            vec![
                Node::long(USAGE_LIMITS_TOTAL, total),
                Node::long(USAGE_LIMITS_COUNT, count),
                Node::enumeration(USAGE_LIMITS_UNIT, 2),
            ],
        )
    };
    for v in FINAL {
        let mut f = Fixture::new();
        let big = create_with(&mut f, v, vec![limits(100, 100)]);
        let small = create_with(&mut f, v, vec![limits(10, 10)]);
        create(&mut f, v);
        let found = |f: &mut Fixture, total, count| {
            let mut ids = uids(payload(&f.call(
                v,
                8,
                locate_fields(v, vec![limits(total, count)]),
            )));
            ids.sort();
            ids
        };
        let mut both = vec![big.clone(), small.clone()];
        both.sort();
        assert_eq!(found(&mut f, 10, 10), both);
        assert_eq!(found(&mut f, 50, 50), std::slice::from_ref(&big));
        assert!(found(&mut f, 500, 500).is_empty());
    }
}

// REQ:14b989a949a9c7d1 a structured Locate filter may give only some of its fields
#[test]
fn locate_matches_partial_structures() {
    for v in FINAL {
        let mut f = Fixture::new();
        let cbc = Node::structure(
            CRYPTOGRAPHIC_PARAMETERS,
            vec![
                Node::enumeration(BLOCK_CIPHER_MODE, 1),
                Node::enumeration(PADDING_METHOD, 3),
            ],
        );
        let id = create_with(&mut f, v, vec![cbc]);
        create_with(&mut f, v, vec![ecb_parameters()]);
        let only_mode = Node::structure(
            CRYPTOGRAPHIC_PARAMETERS,
            vec![Node::enumeration(BLOCK_CIPHER_MODE, 1)],
        );
        assert_eq!(
            uids(payload(&f.call(v, 8, locate_fields(v, vec![only_mode])))),
            std::slice::from_ref(&id)
        );
    }
}

// REQ:0e7fcf1132745cfe 2.x Locate lists the newest object first
#[test]
fn locate_orders_newest_first() {
    for v in [Version(2, 0), Version(2, 1)] {
        let mut f = Fixture::new();
        let ids: Vec<String> = (0..4).map(|_| create(&mut f, v)).collect();
        let mut newest_first = ids.clone();
        newest_first.reverse();
        assert_eq!(uids(payload(&f.call(v, 8, vec![]))), newest_first);
    }
}

// REQ:bf3ab27c25057d59 destroyed objects are only located with the Destroyed Storage bit
// REQ:3d1f07012495aa42 archived objects are only located with the Archived Storage bit
// REQ:c2338930bb57ce61 without a Storage Status Mask only on-line objects are located
// REQ:6d951d51debfd3e9 a located archived object must be recovered before Get succeeds
#[test]
fn locate_storage_status_mask_selects_online_archived_and_destroyed_objects() {
    for v in [Version(2, 0), Version(2, 1)] {
        let mut f = Fixture::new();
        let online = create(&mut f, v);
        let archived = create(&mut f, v);
        payload(&f.call(v, 21, vec![uid(&archived)]));
        let destroyed = create(&mut f, v);
        payload(&f.call(v, 20, vec![uid(&destroyed)]));
        let found = |f: &mut Fixture, mask: Option<i32>| {
            let mut fields = vec![];
            if let Some(m) = mask {
                fields.push(Node::int(STORAGE_STATUS_MASK, m));
            }
            let mut ids = uids(payload(&f.call(v, 8, fields)));
            ids.sort();
            ids
        };
        let sorted = |mut ids: Vec<String>| {
            ids.sort();
            ids
        };
        assert_eq!(found(&mut f, None), std::slice::from_ref(&online));
        assert_eq!(found(&mut f, Some(1)), std::slice::from_ref(&online));
        assert_eq!(found(&mut f, Some(2)), std::slice::from_ref(&archived));
        assert_eq!(found(&mut f, Some(4)), std::slice::from_ref(&destroyed));
        assert_eq!(
            found(&mut f, Some(7)),
            sorted(vec![online.clone(), archived.clone(), destroyed.clone()])
        );
        // The archived result is only usable after Recover.
        assert_eq!(reason(&f.call(v, 10, vec![uid(&archived)])), 13);
        payload(&f.call(v, 22, vec![uid(&archived)]));
        payload(&f.call(v, 10, vec![uid(&archived)]));
    }
}

// REQ:d11113610d2f49e0 1.0: an archived object is used only after Recover
// REQ:b7cce8bfc2bb5e7c 1.1-1.4: an archived object is used only after Recover
// REQ:1fe35805f155815a 2.x: an archived object is used only after Recover
#[test]
fn archived_objects_must_be_recovered_before_use() {
    for v in FINAL {
        let mut f = Fixture::new();
        let id = create(&mut f, v);
        payload(&f.call(v, 21, vec![uid(&id)]));
        for op in [10, 11, 18, 20] {
            assert_eq!(reason(&f.call(v, op, vec![uid(&id)])), 13, "op {op}");
        }
        payload(&f.call(v, 22, vec![uid(&id)]));
        payload(&f.call(v, 10, vec![uid(&id)]));
        activate(&mut f, v, &id);
    }
}

// REQ:382b098d25b4f0d9 1.1/1.2 Discover Versions ranks versions by preference, best first
// REQ:84d6ba52cfd06ec5 1.3-2.1 Discover Versions ranks versions in decreasing preference
// REQ:ae9b75b27e566b6a only versions both sides support are returned
// REQ:873fe3b6117d871d no common version yields an empty list
#[test]
fn discover_versions_returns_the_ranked_common_versions() {
    let key = |n: &Node| {
        (
            num(n, PROTOCOL_VERSION_MAJOR),
            num(n, PROTOCOL_VERSION_MINOR),
        )
    };
    for v in FINAL.into_iter().filter(|v| *v >= Version(1, 1)) {
        let mut f = Fixture::new();
        let all: Vec<(u32, u32)> = payload(&f.call(v, 30, vec![]))
            .all(PROTOCOL_VERSION)
            .map(key)
            .collect();
        assert_eq!(all.first(), Some(&(2, 1)));
        assert!(all.windows(2).all(|w| w[0] > w[1]), "{all:?}");
        let offered = vec![
            Version(1, 0).node(),
            Version(9, 9).node(),
            Version(2, 0).node(),
            Version(1, 3).node(),
        ];
        let common: Vec<(u32, u32)> = payload(&f.call(v, 30, offered))
            .all(PROTOCOL_VERSION)
            .map(key)
            .collect();
        assert_eq!(common, [(2, 0), (1, 3), (1, 0)]);
        let none = payload(&f.call(v, 30, vec![Version(9, 9).node()])).clone();
        assert!(none.children().unwrap().is_empty());
    }
}

fn date_of(n: &Node) -> i64 {
    match n.value {
        Value::DateTime(t) => t,
        _ => panic!("not a date"),
    }
}
fn date_attr(f: &mut Fixture, v: Version, id: &str, tag: u32) -> Option<i64> {
    attr_values(f, v, id, tag).first().map(date_of)
}
fn now() -> i64 {
    keytend_kmip_server::store::now()
}
fn aes_ecb(key: &[u8], data: &[u8]) -> Vec<u8> {
    let cipher = match key.len() {
        16 => openssl::symm::Cipher::aes_128_ecb(),
        _ => openssl::symm::Cipher::aes_256_ecb(),
    };
    let mut c =
        openssl::symm::Crypter::new(cipher, openssl::symm::Mode::Encrypt, key, None).unwrap();
    c.pad(false);
    let mut out = vec![0; data.len() + 32];
    let n = c.update(data, &mut out).unwrap();
    let m = c.finalize(&mut out[n..]).unwrap();
    out.truncate(n + m);
    out
}
fn key_bytes(f: &mut Fixture, v: Version, id: &str) -> Vec<u8> {
    payload(&f.call(v, 10, vec![uid(id)]))
        .required(SYMMETRIC_KEY)
        .unwrap()
        .required(KEY_BLOCK)
        .unwrap()
        .required(KEY_VALUE)
        .unwrap()
        .required(KEY_MATERIAL)
        .unwrap()
        .byte_string()
        .unwrap()
        .to_vec()
}
fn derivation_source(f: &mut Fixture, v: Version, usage: i32, extra: Vec<Node>) -> String {
    let mut attrs = vec![Node::int(CRYPTOGRAPHIC_USAGE_MASK, usage)];
    attrs.extend(extra);
    let id = id_of(&register_raw(f, v, 2, &[9; 32], attrs));
    activate(f, v, &id);
    id
}

// REQ:91e6895273351853 1.x Derive Key only uses keys with the Derive Key usage bit
// REQ:3e3b08a64f72b3bc 2.x Derive Key only uses objects with the Derive Key usage bit
// REQ:aea4074d8d0c6c16 a source without the Derive Key bit is an error
// REQ:a40e5c6fc5adfc53 the derived key is computed, registered and its new identifier returned
// REQ:6142abca815b5ee0 1.0/1.1 source and derived key are linked both ways
// REQ:1192800360bd3cfc the source gets a Derived Key link to the new object
// REQ:4e48dcd39852c986 the new object gets a Derivation Base Object link to its source
#[test]
fn derive_key_needs_the_usage_bit_and_links_a_new_object() {
    for v in FINAL {
        let mut f = Fixture::new();
        let params = vec![ecb_parameters(), Node::bytes(DERIVATION_DATA, vec![1; 16])];
        let refused = derivation_source(&mut f, v, 12, vec![ecb_parameters()]);
        assert_eq!(
            status_of(
                items(&f.call(
                    v,
                    5,
                    derive_fields(v, &[&refused], Some(128), true, 4, params.clone())
                ))[0]
            ),
            1
        );
        let source = derivation_source(&mut f, v, 512, vec![ecb_parameters()]);
        let before = uids(payload(&f.call(v, 8, vec![]))).len();
        let r = f.call(
            v,
            5,
            derive_fields(v, &[&source], Some(128), true, 4, params),
        );
        let derived = id_of(&r);
        assert_ne!(derived, source);
        assert_eq!(uids(payload(&f.call(v, 8, vec![]))).len(), before + 1);
        // ENCRYPT derivation: the first 128 bits of AES-ECB(source, data).
        assert_eq!(key_bytes(&mut f, v, &derived), aes_ecb(&[9; 32], &[1; 16]));
        assert_eq!(
            links(&mut f, v, &source, 0x105),
            std::slice::from_ref(&derived)
        );
        assert_eq!(
            links(&mut f, v, &derived, 0x104),
            std::slice::from_ref(&source)
        );
    }
}

// REQ:90e20ad1458c1525 a requested length beyond the method's output is an error
// REQ:f1466f2140171a6b 1.0/1.1 the derived length is limited to the method's output
// REQ:a427e5527babca50 1.0/1.1 a derived symmetric key needs length and algorithm
// REQ:0808b41c43cf6f55 1.2-1.4 a derived symmetric key needs length and algorithm
// REQ:23a75dd1d787cbde 2.x a derived symmetric key needs length and algorithm
#[test]
fn derive_key_checks_length_and_algorithm() {
    for v in FINAL {
        let mut f = Fixture::new();
        let source = derivation_source(&mut f, v, 512, vec![ecb_parameters()]);
        let params = vec![ecb_parameters(), Node::bytes(DERIVATION_DATA, vec![1; 16])];
        let attempt = |f: &mut Fixture, bits, alg| {
            status_of(
                items(&f.call(
                    v,
                    5,
                    derive_fields(v, &[&source], bits, alg, 4, params.clone()),
                ))[0],
            )
        };
        // 16 bytes of data encrypt to 128 bits; 256 bits cannot be produced.
        assert_eq!(attempt(&mut f, Some(256), true), 1);
        assert_eq!(attempt(&mut f, None, true), 1);
        assert_eq!(attempt(&mut f, Some(128), false), 1);
        assert_eq!(attempt(&mut f, Some(128), true), 0);
    }
}

// REQ:92cf7248f66d5d95 1.x a derivation mode must match one of the key's Cryptographic Parameters
// REQ:16af88b616b48910 1.x omitted parameters select the key's lowest-index Cryptographic Parameters
#[test]
fn legacy_derivation_parameters_come_from_the_key() {
    for v in FINAL.into_iter().filter(|v| v.0 == 1) {
        let mut f = Fixture::new();
        let cbc = Node::structure(
            CRYPTOGRAPHIC_PARAMETERS,
            vec![
                Node::enumeration(BLOCK_CIPHER_MODE, 1),
                Node::enumeration(PADDING_METHOD, 1),
            ],
        );
        let source = derivation_source(&mut f, v, 512, vec![ecb_parameters(), cbc]);
        let data = Node::bytes(DERIVATION_DATA, vec![1; 16]);
        // Omitted: index 0 (ECB) is used.
        let derived = id_of(&f.call(
            v,
            5,
            derive_fields(v, &[&source], Some(128), true, 4, vec![data.clone()]),
        ));
        assert_eq!(key_bytes(&mut f, v, &derived), aes_ecb(&[9; 32], &[1; 16]));
        // CBC is the key's second instance; CFB is not set for the key.
        let with_mode = |mode| {
            vec![
                Node::structure(
                    CRYPTOGRAPHIC_PARAMETERS,
                    vec![Node::enumeration(BLOCK_CIPHER_MODE, mode)],
                ),
                Node::bytes(INITIALIZATION_VECTOR, vec![0; 16]),
                data.clone(),
            ]
        };
        payload(&f.call(
            v,
            5,
            derive_fields(v, &[&source], Some(128), true, 4, with_mode(1)),
        ));
        let r = f.call(
            v,
            5,
            derive_fields(v, &[&source], Some(128), true, 4, with_mode(4)),
        );
        assert_eq!(status_of(items(&r)[0]), 1);
    }
}

// REQ:f0e1551ceeafea46 algorithm and length are the same for both keys of a pair
// REQ:710cf28acee31f2d 2.0 Table 176: pair attributes that must agree do agree
// REQ:868a7f03a7a879aa 2.1 Table 191: pair attributes that must agree do agree
// REQ:dfa1ab9ba67613af 1.2-1.4 multi-instance attributes are the union of common and key-specific values
// REQ:c683da1f3c70aad1 2.x multi-instance attributes are the union of common and key-specific values
#[test]
fn create_key_pair_shares_required_values_and_unions_multi_instance_attributes() {
    for v in FINAL {
        let mut f = Fixture::new();
        let rsa = |len: i32, usage: i32| {
            vec![
                Node::enumeration(CRYPTOGRAPHIC_ALGORITHM, 4),
                Node::int(CRYPTOGRAPHIC_LENGTH, len),
                Node::int(CRYPTOGRAPHIC_USAGE_MASK, usage),
            ]
        };
        let conflicting = f.call(
            v,
            2,
            vec![
                container_as(
                    v,
                    PRIVATE_KEY_TEMPLATE_ATTRIBUTE,
                    PRIVATE_KEY_ATTRIBUTES,
                    rsa(2048, 1),
                ),
                container_as(
                    v,
                    PUBLIC_KEY_TEMPLATE_ATTRIBUTE,
                    PUBLIC_KEY_ATTRIBUTES,
                    rsa(3072, 2),
                ),
            ],
        );
        assert_eq!(status_of(items(&conflicting)[0]), 1);
        let r = f.call(
            v,
            2,
            vec![
                container_as(
                    v,
                    COMMON_TEMPLATE_ATTRIBUTE,
                    COMMON_ATTRIBUTES,
                    vec![
                        Node::enumeration(CRYPTOGRAPHIC_ALGORITHM, 4),
                        Node::int(CRYPTOGRAPHIC_LENGTH, 2048),
                        group("common"),
                    ],
                ),
                container_as(
                    v,
                    PRIVATE_KEY_TEMPLATE_ATTRIBUTE,
                    PRIVATE_KEY_ATTRIBUTES,
                    vec![Node::int(CRYPTOGRAPHIC_USAGE_MASK, 1), group("private")],
                ),
                container_as(
                    v,
                    PUBLIC_KEY_TEMPLATE_ATTRIBUTE,
                    PUBLIC_KEY_ATTRIBUTES,
                    vec![Node::int(CRYPTOGRAPHIC_USAGE_MASK, 2), group("public")],
                ),
            ],
        );
        let p = payload(&r);
        let private = text(p, PRIVATE_KEY_UNIQUE_IDENTIFIER);
        let public = text(p, PUBLIC_KEY_UNIQUE_IDENTIFIER);
        for tag in [CRYPTOGRAPHIC_ALGORITHM, CRYPTOGRAPHIC_LENGTH] {
            assert!(attr_values(&mut f, v, &private, tag) == attr_values(&mut f, v, &public, tag));
        }
        let groups = |f: &mut Fixture, id: &str| {
            let mut g: Vec<String> = attr_values(f, v, id, OBJECT_GROUP)
                .iter()
                .map(|n| n.string().unwrap().to_owned())
                .collect();
            g.sort();
            g
        };
        assert_eq!(groups(&mut f, &private), ["common", "private"]);
        assert_eq!(groups(&mut f, &public), ["common", "public"]);
    }
}

/// A key with Activation, Process Start, Protect Stop and Deactivation dates.
fn dated_key(f: &mut Fixture, v: Version, base: i64) -> String {
    create_with(
        f,
        v,
        vec![
            Node::date(ACTIVATION_DATE, base + 1000),
            Node::date(PROCESS_START_DATE, base + 2000),
            Node::date(PROTECT_STOP_DATE, base + 3000),
            Node::date(DEACTIVATION_DATE, base + 5000),
        ],
    )
}
fn assert_shifted(f: &mut Fixture, v: Version, old: &str, new: &str, offset: i64, tags: &[u32]) {
    let it1 = date_attr(f, v, old, INITIAL_DATE).unwrap();
    let it2 = date_attr(f, v, new, INITIAL_DATE).unwrap();
    assert!(it2 >= it1);
    let at1 = date_attr(f, v, old, ACTIVATION_DATE).unwrap();
    let at2 = date_attr(f, v, new, ACTIVATION_DATE).unwrap();
    assert_eq!(at2, it2 + offset);
    for tag in tags {
        let t1 = date_attr(f, v, old, *tag).unwrap();
        assert_eq!(
            date_attr(f, v, new, *tag),
            Some(t1 + (at2 - at1)),
            "tag {tag:#x}"
        );
    }
}

// REQ:5c7088d918a85b89 Re-key puts the replacement key in the placeholder
// REQ:244aae96c822b58b Re-key with Offset shifts the replacement key's dates from the existing key's
// REQ:fe9d28e96e597acd the existing key gets a Replacement link to the new key
// REQ:c5891b2dc3015e6d the replacement key gets a Replaced link to the existing key
#[test]
fn rekey_sets_placeholder_offset_dates_and_replacement_links() {
    for v in FINAL {
        let mut f = Fixture::new();
        let old = dated_key(&mut f, v, now());
        let r = f.batch(
            v,
            vec![
                (4, vec![uid(&old), Node::interval(OFFSET, 100)]),
                (11, vec![]),
            ],
        );
        let it = items(&r);
        let new = text(item_payload(it[0]), UNIQUE_IDENTIFIER);
        assert_ne!(new, old);
        assert_eq!(text(item_payload(it[1]), UNIQUE_IDENTIFIER), new);
        assert_shifted(
            &mut f,
            v,
            &old,
            &new,
            100,
            &[PROCESS_START_DATE, PROTECT_STOP_DATE, DEACTIVATION_DATE],
        );
        if v >= Version(1, 2) {
            assert_eq!(links(&mut f, v, &old, 0x106), std::slice::from_ref(&new));
            assert_eq!(links(&mut f, v, &new, 0x107), std::slice::from_ref(&old));
        }
    }
}

// REQ:ef2e898ee9a8f9cf Re-key Key Pair puts the replacement private key in the placeholder
// REQ:c3c716a8b7cb11c8 1.1 Re-key Key Pair with Offset shifts the replacement pair's dates
// REQ:e869845d786c985a 1.2-2.1 Re-key Key Pair with Offset shifts the replacement pair's dates
// REQ:5e9270ac1fd2ec37 the existing public and private keys get Replacement links
// REQ:d8fef085ea79a146 the replacement public and private keys get Replaced links
#[test]
fn rekey_key_pair_sets_placeholder_offset_dates_and_replacement_links() {
    for v in FINAL.into_iter().filter(|v| *v >= Version(1, 1)) {
        let mut f = Fixture::new();
        let base = now();
        let p = payload(&f.call(
            v,
            2,
            rsa_pair(
                v,
                vec![
                    Node::date(ACTIVATION_DATE, base + 1000),
                    Node::date(DEACTIVATION_DATE, base + 5000),
                ],
            ),
        ))
        .clone();
        let private = text(&p, PRIVATE_KEY_UNIQUE_IDENTIFIER);
        let public = text(&p, PUBLIC_KEY_UNIQUE_IDENTIFIER);
        let r = f.batch(
            v,
            vec![
                (
                    29,
                    vec![
                        Node::text(PRIVATE_KEY_UNIQUE_IDENTIFIER, &private),
                        Node::interval(OFFSET, 100),
                    ],
                ),
                (11, vec![]),
            ],
        );
        let it = items(&r);
        let np = item_payload(it[0]);
        let new_private = text(np, PRIVATE_KEY_UNIQUE_IDENTIFIER);
        let new_public = text(np, PUBLIC_KEY_UNIQUE_IDENTIFIER);
        assert_eq!(text(item_payload(it[1]), UNIQUE_IDENTIFIER), new_private);
        assert_shifted(&mut f, v, &private, &new_private, 100, &[DEACTIVATION_DATE]);
        assert_shifted(&mut f, v, &public, &new_public, 100, &[DEACTIVATION_DATE]);
        if v >= Version(1, 2) {
            assert_eq!(
                links(&mut f, v, &private, 0x106),
                std::slice::from_ref(&new_private)
            );
            assert_eq!(
                links(&mut f, v, &public, 0x106),
                std::slice::from_ref(&new_public)
            );
            assert_eq!(
                links(&mut f, v, &new_private, 0x107),
                std::slice::from_ref(&private)
            );
            assert_eq!(
                links(&mut f, v, &new_public, 0x107),
                std::slice::from_ref(&public)
            );
        }
    }
}

// REQ:f3700fde3a68332d Register sets the Initial Date to the current time
#[test]
fn register_sets_initial_date_to_now() {
    for v in FINAL {
        let mut f = Fixture::new();
        let before = now();
        let id = id_of(&register_raw(
            &mut f,
            v,
            2,
            &[3; 16],
            vec![Node::int(CRYPTOGRAPHIC_USAGE_MASK, 12)],
        ));
        let after = now();
        let initial = date_attr(&mut f, v, &id, INITIAL_DATE).unwrap();
        assert!(before <= initial && initial <= after);
        // A client value is not accepted for the server-set date.
        let r = register_raw(
            &mut f,
            v,
            2,
            &[3; 16],
            vec![
                Node::int(CRYPTOGRAPHIC_USAGE_MASK, 12),
                Node::date(INITIAL_DATE, 1000),
            ],
        );
        assert_eq!(status_of(items(&r)[0]), 1);
    }
}

fn groups(f: &mut Fixture, v: Version, id: &str) -> Vec<String> {
    attr_values(f, v, id, OBJECT_GROUP)
        .iter()
        .map(|n| n.string().unwrap().to_owned())
        .collect()
}
fn contact(f: &mut Fixture, v: Version, id: &str) -> Vec<String> {
    attr_values(f, v, id, CONTACT_INFORMATION)
        .iter()
        .map(|n| n.string().unwrap().to_owned())
        .collect()
}
/// Add Attribute payload for one attribute.
fn add(v: Version, id: &str, a: Node) -> Vec<Node> {
    if v.0 >= 2 {
        vec![uid(id), Node::structure(NEW_ATTRIBUTE, vec![a])]
    } else {
        vec![uid(id), attribute(v, a)]
    }
}
/// Modify Attribute payload: 1.x by index, 2.x by current value.
fn modify(v: Version, id: &str, current: Option<(i32, Node)>, new: Node) -> Vec<Node> {
    if v.0 >= 2 {
        let mut p = vec![uid(id)];
        if let Some((_, c)) = current {
            p.push(Node::structure(CURRENT_ATTRIBUTE, vec![c]));
        }
        p.push(Node::structure(NEW_ATTRIBUTE, vec![new]));
        p
    } else {
        vec![uid(id), attribute_at(v, new, current.map(|(i, _)| i))]
    }
}

// REQ:5966179f842a65d5 1.x Add Attribute never changes an existing value
// REQ:0c66187677f2f739 2.x Add Attribute never changes an existing value
// REQ:d3b94bdfa4dd4cde read-only attributes cannot be added
// REQ:1865bbaf4da21598 1.0 Add Attribute refuses an Attribute Index
// REQ:db706850103ab263 1.1-1.4 Add Attribute refuses an Attribute Index
#[test]
fn add_attribute_only_adds_new_values() {
    for v in FINAL {
        let mut f = Fixture::new();
        let id = create_with(
            &mut f,
            v,
            vec![Node::text(CONTACT_INFORMATION, "first"), group("a")],
        );
        let r = f.call(
            v,
            13,
            add(v, &id, Node::text(CONTACT_INFORMATION, "second")),
        );
        assert_eq!(status_of(items(&r)[0]), 1);
        assert_eq!(contact(&mut f, v, &id), ["first"]);
        payload(&f.call(v, 13, add(v, &id, group("b"))));
        let mut g = groups(&mut f, v, &id);
        g.sort();
        assert_eq!(g, ["a", "b"]);
        for read_only in [Node::date(INITIAL_DATE, 5), Node::enumeration(STATE, 2)] {
            let r = f.call(v, 13, add(v, &id, read_only));
            assert_eq!(status_of(items(&r)[0]), 1);
        }
        if v.0 == 1 {
            let r = f.call(v, 13, vec![uid(&id), attribute_at(v, group("c"), Some(2))]);
            assert_eq!(status_of(items(&r)[0]), 1);
            assert_eq!(groups(&mut f, v, &id).len(), 2);
        }
    }
}

// REQ:4277677c45eabb43 1.0/1.2-1.4 Modify Attribute cannot create a missing attribute
// REQ:f8a383f55378f53c 1.1 Modify cannot create attributes and changes only the given instance
// REQ:02fc75e272dd4b9d only the selected instance is modified
// REQ:c2cf1cff837836be 1.0/1.1 an index without a value is an error
// REQ:203f8e85ef842668 1.2-1.4 an index without a value is an error
// REQ:3854f53b62008d84 2.x without Current Attribute a single instance is chosen and several are an error
// REQ:d157a3d734a8a7c0 2.x a Current Attribute the object lacks is an error
#[test]
fn modify_attribute_changes_only_an_existing_selected_instance() {
    for v in FINAL {
        let mut f = Fixture::new();
        let id = create_with(
            &mut f,
            v,
            vec![group("a"), group("b"), Node::text(CONTACT_INFORMATION, "c")],
        );
        // Absent attribute: Modify does not add it.
        let r = f.call(v, 14, modify(v, &id, None, Node::text(DESCRIPTION, "d")));
        assert_eq!(status_of(items(&r)[0]), 1);
        assert!(attr_values(&mut f, v, &id, DESCRIPTION).is_empty());
        // Missing instance.
        let r = f.call(v, 14, modify(v, &id, Some((7, group("zzz"))), group("x")));
        assert_eq!(status_of(items(&r)[0]), 1);
        // Only the selected instance changes.
        let original = groups(&mut f, v, &id);
        let target = original[1].clone();
        payload(&f.call(v, 14, modify(v, &id, Some((1, group(&target))), group("x"))));
        let changed = groups(&mut f, v, &id);
        assert_eq!(changed[0], original[0]);
        assert!(changed.contains(&"x".to_owned()) && !changed.contains(&target));
        if v.0 >= 2 {
            // Several instances and no Current Attribute: ambiguous.
            let r = f.call(v, 14, modify(v, &id, None, group("y")));
            assert_eq!(status_of(items(&r)[0]), 1);
            // A single instance is selected implicitly.
            payload(&f.call(
                v,
                14,
                modify(v, &id, None, Node::text(CONTACT_INFORMATION, "d")),
            ));
            assert_eq!(contact(&mut f, v, &id), ["d"]);
        }
    }
}

// REQ:abda73cd40544a89 1.0/1.1 always-required attributes are never deleted
// REQ:9e0ce4278786c4ea 1.2-2.1 always-required attributes are never deleted
// REQ:7ac5e90decfe294d 1.0 Delete Attribute removes one instance at a time
// REQ:a8f491f9cb081d5a 1.x deleting a missing attribute or index is an error
// REQ:764867f7a88ca69e 1.1-1.4 an omitted Attribute Index means index 0
// REQ:25be0ff064ba269a 2.x deleting a missing attribute or Current Attribute is an error
// REQ:f44eccdab4c3a5fb 2.x Attribute Reference without Current Attribute deletes every instance
#[test]
fn delete_attribute_rules() {
    for v in FINAL {
        let mut f = Fixture::new();
        let id = create_with(&mut f, v, vec![group("a"), group("b"), group("c")]);
        let by_name = |tag: u32, index: Option<i32>| {
            let mut p = vec![uid(&id)];
            if v.0 >= 2 {
                p.push(Node::enumeration(ATTRIBUTE_REFERENCE, tag));
            } else {
                p.push(Node::text(ATTRIBUTE_NAME, tag_name(tag).unwrap()));
                if let Some(i) = index {
                    p.push(Node::int(ATTRIBUTE_INDEX, i));
                }
            }
            p
        };
        for required in [CRYPTOGRAPHIC_ALGORITHM, OBJECT_TYPE, STATE, INITIAL_DATE] {
            assert_eq!(
                status_of(items(&f.call(v, 15, by_name(required, None)))[0]),
                1
            );
        }
        assert_eq!(
            status_of(items(&f.call(v, 15, by_name(DESCRIPTION, None)))[0]),
            1
        );
        if v.0 == 1 {
            assert_eq!(
                status_of(items(&f.call(v, 15, by_name(OBJECT_GROUP, Some(9))))[0]),
                1
            );
            let before = groups(&mut f, v, &id);
            payload(&f.call(v, 15, by_name(OBJECT_GROUP, Some(1))));
            let after = groups(&mut f, v, &id);
            assert_eq!(after.len(), 2);
            assert_eq!(after[0], before[0]);
            // No index: instance 0 is the one removed, in 1.0 too (its text
            // assumes index 0; see src/protocol/attributes.rs).
            payload(&f.call(v, 15, by_name(OBJECT_GROUP, None)));
            assert_eq!(groups(&mut f, v, &id), [after[1].clone()]);
        } else {
            let current =
                |g: &str| vec![uid(&id), Node::structure(CURRENT_ATTRIBUTE, vec![group(g)])];
            assert_eq!(status_of(items(&f.call(v, 15, current("zzz")))[0]), 1);
            payload(&f.call(v, 15, current("b")));
            let mut g = groups(&mut f, v, &id);
            g.sort();
            assert_eq!(g, ["a", "c"]);
            payload(&f.call(v, 15, by_name(OBJECT_GROUP, None)));
            assert!(groups(&mut f, v, &id).is_empty());
        }
    }
}

// REQ:760330b7f0931986 attributes without a value are left out of Get Attributes
// REQ:b38edfe075302a08 1.x if none of the requested attributes exist only the identifier is returned
// 7ebd66853ffb6476 (2.x: only the identifier) is met only under
// `--get-attributes-none identifier-only` (tests/get_attributes_none.rs); the
// default returns an empty Attributes structure as well (docs/interpretations.md).
// REQ:bc4fa0e791fb1e76 1.x Get Attributes without names returns every attribute
// REQ:36777d8dc7e96d89 2.x Get Attributes and Get Attribute List without references return every attribute
// REQ:24f5ef901006b053 1.1-1.4 a name repeated in Get Attributes is refused
// REQ:4240d602282d499e 2.x an Attribute Reference repeated in Get Attributes is refused
#[test]
fn get_attributes_selection_rules() {
    for v in FINAL {
        let mut f = Fixture::new();
        let id = create_with(&mut f, v, vec![group("a")]);
        let select = |tag: u32| {
            if v.0 >= 2 {
                Node::enumeration(ATTRIBUTE_REFERENCE, tag)
            } else {
                Node::text(ATTRIBUTE_NAME, tag_name(tag).unwrap())
            }
        };
        // One present, one absent.
        let p = payload(&f.call(
            v,
            11,
            vec![uid(&id), select(OBJECT_GROUP), select(DESCRIPTION)],
        ))
        .clone();
        let returned: Vec<u32> = if v.0 >= 2 {
            p.required(ATTRIBUTES)
                .unwrap()
                .children()
                .unwrap()
                .iter()
                .map(|n| n.tag)
                .collect()
        } else {
            p.all(ATTRIBUTE)
                .map(|a| {
                    a.required(ATTRIBUTE_NAME)
                        .unwrap()
                        .string()
                        .unwrap()
                        .to_owned()
                })
                .map(|n| if n == "Object Group" { OBJECT_GROUP } else { 0 })
                .collect()
        };
        assert_eq!(returned, [OBJECT_GROUP]);
        // Only absent attributes: the identifier, and in 2.x an empty
        // Attributes structure.
        let p = payload(&f.call(v, 11, vec![uid(&id), select(DESCRIPTION)])).clone();
        let fields: Vec<u32> = p.children().unwrap().iter().map(|n| n.tag).collect();
        if v.0 >= 2 {
            assert_eq!(fields, [UNIQUE_IDENTIFIER, ATTRIBUTES]);
            assert!(
                p.required(ATTRIBUTES)
                    .unwrap()
                    .children()
                    .unwrap()
                    .is_empty()
            );
        } else {
            assert_eq!(fields, [UNIQUE_IDENTIFIER]);
        }
        // No selector: everything.
        let all = payload(&f.call(v, 11, vec![uid(&id)])).clone();
        let count = if v.0 >= 2 {
            all.required(ATTRIBUTES).unwrap().children().unwrap().len()
        } else {
            all.all(ATTRIBUTE).count()
        };
        let list = payload(&f.call(v, 12, vec![uid(&id)])).clone();
        let listed = if v.0 >= 2 {
            list.all(ATTRIBUTE_REFERENCE).count()
        } else {
            list.all(ATTRIBUTE_NAME).count()
        };
        assert!(count >= 8 && listed >= 8, "{count} {listed}");
        for tag in [
            OBJECT_GROUP,
            CRYPTOGRAPHIC_ALGORITHM,
            CRYPTOGRAPHIC_LENGTH,
            STATE,
            INITIAL_DATE,
        ] {
            assert_eq!(attr_values(&mut f, v, &id, tag).len(), 1);
        }
        if v >= Version(1, 1) {
            let r = f.call(
                v,
                11,
                vec![uid(&id), select(OBJECT_GROUP), select(OBJECT_GROUP)],
            );
            assert_eq!(status_of(items(&r)[0]), 1);
        }
    }
}

// REQ:a860bc77299e9170 2.x Set Attribute neither adds nor changes read-only attributes
#[test]
fn set_attribute_refuses_read_only_attributes() {
    for v in [Version(2, 0), Version(2, 1)] {
        let mut f = Fixture::new();
        let id = create(&mut f, v);
        for a in [
            Node::date(INITIAL_DATE, 5),
            Node::enumeration(STATE, 2),
            Node::enumeration(CRYPTOGRAPHIC_ALGORITHM, 4),
        ] {
            let tag = a.tag;
            let before = attr_values(&mut f, v, &id, tag);
            let r = f.call(
                v,
                49,
                vec![uid(&id), Node::structure(NEW_ATTRIBUTE, vec![a])],
            );
            assert_eq!(status_of(items(&r)[0]), 1);
            assert!(attr_values(&mut f, v, &id, tag) == before);
        }
        payload(&f.call(
            v,
            49,
            vec![
                uid(&id),
                Node::structure(NEW_ATTRIBUTE, vec![Node::text(CONTACT_INFORMATION, "ok")]),
            ],
        ));
    }
}

fn state(f: &mut Fixture, v: Version, id: &str) -> u32 {
    attr_values(f, v, id, STATE)[0].number().unwrap()
}

// REQ:feefce38842c5b83 Activate moves a Pre-Active object to Active and stamps the Activation Date
#[test]
fn activate_only_from_pre_active() {
    for v in FINAL {
        let mut f = Fixture::new();
        let id = create(&mut f, v);
        assert_eq!(state(&mut f, v, &id), 1);
        assert!(date_attr(&mut f, v, &id, ACTIVATION_DATE).is_none());
        let before = now();
        activate(&mut f, v, &id);
        let after = now();
        assert_eq!(state(&mut f, v, &id), 2);
        let at = date_attr(&mut f, v, &id, ACTIVATION_DATE).unwrap();
        assert!(before <= at && at <= after);
        // Not Pre-Active any more.
        assert_eq!(status_of(items(&f.call(v, 18, vec![uid(&id)]))[0]), 1);
        assert_eq!(date_attr(&mut f, v, &id, ACTIVATION_DATE), Some(at));
    }
}

fn revoke(reason_code: u32, occurrence: Option<i64>) -> Vec<Node> {
    let mut p = vec![Node::structure(
        REVOCATION_REASON,
        vec![Node::enumeration(REVOCATION_REASON_CODE, reason_code)],
    )];
    if let Some(t) = occurrence {
        p.push(Node::date(COMPROMISE_OCCURRENCE_DATE, t));
    }
    p
}
fn active(f: &mut Fixture, v: Version) -> String {
    let id = create(f, v);
    activate(f, v, &id);
    id
}

// REQ:97b71b5573557e88 1.0/1.1 Destroy destroys the key material
// REQ:b80bbbd998b102a2 1.2-1.4 Destroy destroys the key material
// REQ:e787339879ffc6d5 2.x Destroy destroys or makes the key material inaccessible
// REQ:ef44421657695950 2.x the destroyed object's metadata is kept
// REQ:f67c2f51fe9ba984 2.x only Pre-Active or Deactivated objects are destroyed
#[test]
fn destroy_removes_material_keeps_metadata_and_needs_an_inactive_state() {
    for v in FINAL {
        let mut f = Fixture::new();
        let live = active(&mut f, v);
        assert_eq!(status_of(items(&f.call(v, 20, vec![uid(&live)]))[0]), 1);
        payload(&f.call(v, 10, vec![uid(&live)]));
        // Deactivated by revocation, then destroyed.
        let mut p = vec![uid(&live)];
        p.extend(revoke(5, None));
        payload(&f.call(v, 19, p));
        let pre_active = create_with(&mut f, v, vec![group("kept")]);
        for id in [&live, &pre_active] {
            payload(&f.call(v, 20, vec![uid(id)]));
            assert_eq!(status_of(items(&f.call(v, 10, vec![uid(id)]))[0]), 1);
            let stored = f.engine.store.get("alice", id).unwrap().unwrap();
            assert!(stored.material.is_empty());
        }
        assert_eq!(state(&mut f, v, &pre_active), 5);
        assert_eq!(groups(&mut f, v, &pre_active), ["kept"]);
        assert!(date_attr(&mut f, v, &pre_active, DESTROY_DATE).is_some());
    }
}

// REQ:a98d50634a62f51f 1.x destroying a Template removes it with all its metadata
// REQ:cac538a0976ab552 1.x Revoke refuses a Template
// REQ:1e44fdbfd6a7afbb 1.0-1.4 Get of a Template with a Key Format Type is refused
#[test]
fn templates_cannot_be_revoked_or_formatted_and_vanish_when_destroyed() {
    for v in FINAL.into_iter().filter(|v| v.0 == 1) {
        let mut f = Fixture::new();
        let name = Node::structure(
            NAME,
            vec![
                Node::text(NAME_VALUE, "template"),
                Node::enumeration(NAME_TYPE, 1),
            ],
        );
        let id = id_of(&f.call(
            v,
            3,
            vec![
                Node::enumeration(OBJECT_TYPE, 6),
                container(v, vec![name]),
                Node::structure(TEMPLATE, vec![attribute(v, group("g"))]),
            ],
        ));
        let mut p = vec![uid(&id)];
        p.extend(revoke(1, None));
        assert_eq!(status_of(items(&f.call(v, 19, p))[0]), 1);
        let r = f.call(v, 10, vec![uid(&id), Node::enumeration(KEY_FORMAT_TYPE, 1)]);
        assert_eq!(status_of(items(&r)[0]), 1);
        payload(&f.call(v, 10, vec![uid(&id)]));
        payload(&f.call(v, 20, vec![uid(&id)]));
        for op in [10, 11, 12] {
            assert_eq!(status_of(items(&f.call(v, op, vec![uid(&id)]))[0]), 1);
        }
        assert!(
            uids(payload(&f.call(
                v,
                8,
                locate_fields(v, vec![Node::enumeration(OBJECT_TYPE, 6)])
            )))
            .is_empty()
        );
    }
}

// REQ:e4ed1813d98381d3 1.0/1.1 a compromise revocation needs a Compromise Occurrence Date
// REQ:333ace0f71f069ce 1.2 a key-compromise revocation needs a Compromise Occurrence Date
// REQ:7135c57b83d9c7ab 1.4/2.x a Compromise Occurrence Date only goes with a compromise reason
#[test]
fn revoke_compromise_occurrence_date_rules() {
    for v in FINAL {
        let mut f = Fixture::new();
        let attempt = |f: &mut Fixture, code, date| {
            let id = active(f, v);
            let mut p = vec![uid(&id)];
            p.extend(revoke(code, date));
            status_of(items(&f.call(v, 19, p))[0])
        };
        let past = now() - 100;
        assert_eq!(attempt(&mut f, 2, Some(past)), 0);
        if v <= Version(1, 2) {
            assert_eq!(attempt(&mut f, 2, None), 1);
        }
        if v >= Version(1, 4) {
            for code in [1, 4, 5] {
                assert_eq!(attempt(&mut f, code, Some(past)), 1, "reason {code}");
                assert_eq!(attempt(&mut f, code, None), 0, "reason {code}");
            }
        }
    }
}

// REQ:e27257d0739eddda a lease the server will not issue is refused with an error
#[test]
fn obtain_lease_is_refused_for_objects_that_cannot_be_used() {
    for v in FINAL {
        let mut f = Fixture::new();
        let pre_active = create(&mut f, v);
        assert_eq!(
            status_of(items(&f.call(v, 16, vec![uid(&pre_active)]))[0]),
            1
        );
        let live = active(&mut f, v);
        payload(&f.call(v, 16, vec![uid(&live)]));
    }
}

// REQ:5aff5d233b6fe138 usage is allocated only while protection is enabled
// REQ:ed5b80bc340efea3 an object without Usage Limits has no allocation to give
// REQ:bac14331c0827cd9 an allocation larger than what remains is refused
// REQ:58064f9bc531eabe the whole allocated amount counts as consumed
#[test]
fn get_usage_allocation_rules() {
    let limits = Node::structure(
        USAGE_LIMITS,
        vec![
            Node::long(USAGE_LIMITS_TOTAL, 100),
            Node::long(USAGE_LIMITS_COUNT, 100),
            Node::enumeration(USAGE_LIMITS_UNIT, 2),
        ],
    );
    let count = |n: &Node| match n.required(USAGE_LIMITS_COUNT).unwrap().value {
        Value::LongInteger(c) => c,
        _ => panic!(),
    };
    for v in FINAL {
        let mut f = Fixture::new();
        let allocate = |f: &mut Fixture, id: &str, amount: i64| {
            status_of(
                items(&f.call(v, 17, vec![uid(id), Node::long(USAGE_LIMITS_COUNT, amount)]))[0],
            )
        };
        let pre_active = create_with(&mut f, v, vec![limits.clone()]);
        assert_eq!(allocate(&mut f, &pre_active, 1), 1);
        let unlimited = active(&mut f, v);
        assert_eq!(allocate(&mut f, &unlimited, 1), 1);
        let stopped = create_with(
            &mut f,
            v,
            vec![limits.clone(), Node::date(PROTECT_STOP_DATE, now() - 10)],
        );
        activate(&mut f, v, &stopped);
        assert_eq!(allocate(&mut f, &stopped, 1), 1);
        let id = create_with(&mut f, v, vec![limits.clone()]);
        activate(&mut f, v, &id);
        assert_eq!(allocate(&mut f, &id, 101), 1);
        assert_eq!(allocate(&mut f, &id, 30), 0);
        assert_eq!(count(&attr_values(&mut f, v, &id, USAGE_LIMITS)[0]), 70);
        assert_eq!(allocate(&mut f, &id, 71), 1);
        assert_eq!(allocate(&mut f, &id, 70), 0);
        assert_eq!(count(&attr_values(&mut f, v, &id, USAGE_LIMITS)[0]), 0);
    }
}

// REQ:8bebcac598c05c9c 1.0: a failed Check ends the batch even under Continue
#[test]
fn failed_check_ends_a_one_zero_batch() {
    for v in FINAL {
        let mut f = Fixture::new();
        let id = create(&mut f, v);
        let r = f.batch(
            v,
            vec![
                (9, vec![uid(&id), Node::int(CRYPTOGRAPHIC_USAGE_MASK, 1)]),
                (10, vec![uid(&id)]),
            ],
        );
        let expected: &[u32] = if v == Version(1, 0) { &[1] } else { &[1, 0] };
        assert_eq!(statuses(&r), expected);
    }
}

fn bytes_of(p: &Node, tag: u32) -> Vec<u8> {
    p.required(tag).unwrap().byte_string().unwrap().to_vec()
}
fn mac_key(f: &mut Fixture, v: Version) -> String {
    let id = id_of(&f.call(
        v,
        1,
        vec![
            Node::enumeration(OBJECT_TYPE, 2),
            container(
                v,
                vec![
                    Node::enumeration(CRYPTOGRAPHIC_ALGORITHM, 9),
                    Node::int(CRYPTOGRAPHIC_LENGTH, 256),
                    Node::int(CRYPTOGRAPHIC_USAGE_MASK, 0x180),
                ],
            ),
        ],
    ));
    activate(f, v, &id);
    id
}
fn signing_pair(f: &mut Fixture, v: Version) -> (String, String) {
    let params = Node::structure(
        CRYPTOGRAPHIC_PARAMETERS,
        vec![
            Node::enumeration(PADDING_METHOD, 8),
            Node::enumeration(HASHING_ALGORITHM, 6),
        ],
    );
    let p = payload(&f.call(v, 2, rsa_pair(v, vec![params, group("signing")]))).clone();
    let private = text(&p, PRIVATE_KEY_UNIQUE_IDENTIFIER);
    let public = text(&p, PUBLIC_KEY_UNIQUE_IDENTIFIER);
    activate(f, v, &private);
    activate(f, v, &public);
    (private, public)
}

// REQ:c07f1c61dfec374c cryptographic operations without an identifier use the placeholder
#[test]
fn cryptographic_operations_use_the_placeholder() {
    for v in FINAL.into_iter().filter(|v| *v >= Version(1, 2)) {
        let mut f = Fixture::new();
        let r = f.batch(
            v,
            vec![
                create_item(v, vec![ecb_parameters()]),
                (18, vec![]),
                (31, vec![Node::bytes(DATA, vec![4; 16])]),
            ],
        );
        let it = items(&r);
        let key = text(item_payload(it[0]), UNIQUE_IDENTIFIER);
        let encrypted = item_payload(it[2]);
        assert_eq!(text(encrypted, UNIQUE_IDENTIFIER), key);
        let ciphertext = bytes_of(encrypted, DATA);
        let r = f.batch(
            v,
            vec![
                (
                    8,
                    locate_fields(v, vec![Node::enumeration(CRYPTOGRAPHIC_ALGORITHM, 3)]),
                ),
                (32, vec![Node::bytes(DATA, ciphertext)]),
            ],
        );
        assert_eq!(bytes_of(item_payload(items(&r)[1]), DATA), vec![4; 16]);
        let mac = mac_key(&mut f, v);
        let r = f.batch(
            v,
            vec![
                (
                    8,
                    locate_fields(v, vec![Node::enumeration(CRYPTOGRAPHIC_ALGORITHM, 9)]),
                ),
                (35, vec![Node::bytes(DATA, b"abc".to_vec())]),
            ],
        );
        let tag = bytes_of(item_payload(items(&r)[1]), MAC_DATA);
        assert_eq!(text(item_payload(items(&r)[1]), UNIQUE_IDENTIFIER), mac);
        let r = f.batch(
            v,
            vec![
                (
                    8,
                    locate_fields(v, vec![Node::enumeration(CRYPTOGRAPHIC_ALGORITHM, 9)]),
                ),
                (
                    36,
                    vec![
                        Node::bytes(DATA, b"abc".to_vec()),
                        Node::bytes(MAC_DATA, tag),
                    ],
                ),
            ],
        );
        assert_eq!(num(item_payload(items(&r)[1]), VALIDITY_INDICATOR), 1);
        let (private, public) = signing_pair(&mut f, v);
        let r = f.batch(
            v,
            vec![
                (8, locate_fields(v, vec![Node::enumeration(OBJECT_TYPE, 4)])),
                (33, vec![Node::bytes(DATA, b"msg".to_vec())]),
            ],
        );
        let signed = item_payload(items(&r)[1]);
        assert_eq!(text(signed, UNIQUE_IDENTIFIER), private);
        let signature = bytes_of(signed, SIGNATURE_DATA);
        let r = f.batch(
            v,
            vec![
                (8, locate_fields(v, vec![Node::enumeration(OBJECT_TYPE, 3)])),
                (
                    34,
                    vec![
                        Node::bytes(DATA, b"msg".to_vec()),
                        Node::bytes(SIGNATURE_DATA, signature),
                    ],
                ),
            ],
        );
        let verified = item_payload(items(&r)[1]);
        assert_eq!(text(verified, UNIQUE_IDENTIFIER), public);
        assert_eq!(num(verified, VALIDITY_INDICATOR), 1);
    }
}

// REQ:81d158389957e887 without stored or requested parameters an algorithm that needs them fails
#[test]
fn operations_needing_parameters_fail_without_them() {
    for v in FINAL.into_iter().filter(|v| *v >= Version(1, 2)) {
        let mut f = Fixture::new();
        let key = active(&mut f, v);
        let r = f.call(v, 31, vec![uid(&key), Node::bytes(DATA, vec![0; 16])]);
        assert_eq!(status_of(items(&r)[0]), 1);
        let p = payload(&f.call(v, 2, rsa_pair(v, vec![]))).clone();
        let private = text(&p, PRIVATE_KEY_UNIQUE_IDENTIFIER);
        activate(&mut f, v, &private);
        let r = f.call(v, 33, vec![uid(&private), Node::bytes(DATA, vec![1; 8])]);
        assert_eq!(status_of(items(&r)[0]), 1);
    }
}

// REQ:42a11e9421b0aeb4 Encrypt draws its allocation from the key's Usage Limits first
// REQ:6c5f93e2f7941143 Sign draws its allocation from the key's Usage Limits first
// REQ:254c8c6855295301 an unavailable allocation fails with Permission Denied
#[test]
fn protection_operations_consume_usage_limits() {
    let count = |n: &Node| match n.required(USAGE_LIMITS_COUNT).unwrap().value {
        Value::LongInteger(c) => c,
        _ => panic!(),
    };
    for v in FINAL.into_iter().filter(|v| *v >= Version(1, 2)) {
        let mut f = Fixture::new();
        let bytes = Node::structure(
            USAGE_LIMITS,
            vec![
                Node::long(USAGE_LIMITS_TOTAL, 32),
                Node::long(USAGE_LIMITS_COUNT, 32),
                Node::enumeration(USAGE_LIMITS_UNIT, 1),
            ],
        );
        let key = create_with(&mut f, v, vec![bytes, ecb_parameters()]);
        activate(&mut f, v, &key);
        payload(&f.call(v, 31, vec![uid(&key), Node::bytes(DATA, vec![0; 16])]));
        assert_eq!(count(&attr_values(&mut f, v, &key, USAGE_LIMITS)[0]), 16);
        payload(&f.call(v, 31, vec![uid(&key), Node::bytes(DATA, vec![0; 16])]));
        let r = f.call(v, 31, vec![uid(&key), Node::bytes(DATA, vec![0; 16])]);
        assert_eq!(reason(&r), 12);
        // Signatures counted as objects.
        let params = Node::structure(
            CRYPTOGRAPHIC_PARAMETERS,
            vec![
                Node::enumeration(PADDING_METHOD, 8),
                Node::enumeration(HASHING_ALGORITHM, 6),
            ],
        );
        let p = payload(&f.call(
            v,
            2,
            vec![
                container_as(
                    v,
                    COMMON_TEMPLATE_ATTRIBUTE,
                    COMMON_ATTRIBUTES,
                    vec![
                        Node::enumeration(CRYPTOGRAPHIC_ALGORITHM, 4),
                        Node::int(CRYPTOGRAPHIC_LENGTH, 2048),
                        params,
                    ],
                ),
                container_as(
                    v,
                    PRIVATE_KEY_TEMPLATE_ATTRIBUTE,
                    PRIVATE_KEY_ATTRIBUTES,
                    vec![
                        Node::int(CRYPTOGRAPHIC_USAGE_MASK, 1),
                        Node::structure(
                            USAGE_LIMITS,
                            vec![
                                Node::long(USAGE_LIMITS_TOTAL, 1),
                                Node::long(USAGE_LIMITS_COUNT, 1),
                                Node::enumeration(USAGE_LIMITS_UNIT, 2),
                            ],
                        ),
                    ],
                ),
                container_as(
                    v,
                    PUBLIC_KEY_TEMPLATE_ATTRIBUTE,
                    PUBLIC_KEY_ATTRIBUTES,
                    vec![Node::int(CRYPTOGRAPHIC_USAGE_MASK, 2)],
                ),
            ],
        ))
        .clone();
        let private = text(&p, PRIVATE_KEY_UNIQUE_IDENTIFIER);
        activate(&mut f, v, &private);
        payload(&f.call(
            v,
            33,
            vec![uid(&private), Node::bytes(DATA, b"one".to_vec())],
        ));
        assert_eq!(count(&attr_values(&mut f, v, &private, USAGE_LIMITS)[0]), 0);
        let r = f.call(
            v,
            33,
            vec![uid(&private), Node::bytes(DATA, b"two".to_vec())],
        );
        assert_eq!(reason(&r), 12);
    }
}

fn part(id: &str, first: bool, last: bool, token: Option<&[u8]>, extra: Vec<Node>) -> Vec<Node> {
    let mut p = vec![
        uid(id),
        Node::boolean(INIT_INDICATOR, first),
        Node::boolean(FINAL_INDICATOR, last),
    ];
    if let Some(t) = token {
        p.push(Node::bytes(CORRELATION_VALUE, t.to_vec()));
    }
    p.extend(extra);
    p
}

// REQ:639e72f97f9f70f8 multi-part Encrypt takes its IV from the initial request only
// REQ:cdc49f8b318f6aff multi-part Decrypt takes its IV from the initial request only
#[test]
fn multipart_iv_belongs_to_the_initial_request() {
    for v in [Version(1, 4), Version(2, 0), Version(2, 1)] {
        let mut f = Fixture::new();
        let key = active(&mut f, v);
        let cbc = Node::structure(
            CRYPTOGRAPHIC_PARAMETERS,
            vec![
                Node::enumeration(BLOCK_CIPHER_MODE, 1),
                Node::enumeration(PADDING_METHOD, 1),
            ],
        );
        let one_shot = bytes_of(
            payload(&f.call(
                v,
                31,
                vec![
                    uid(&key),
                    cbc.clone(),
                    Node::bytes(DATA, vec![3; 32]),
                    Node::bytes(IV_COUNTER_NONCE, vec![1; 16]),
                ],
            )),
            DATA,
        );
        for op in [31, 32] {
            let input = if op == 31 {
                vec![3; 32]
            } else {
                one_shot.clone()
            };
            let expected = if op == 31 {
                one_shot.clone()
            } else {
                vec![3; 32]
            };
            // CBC needs the IV up front: it cannot follow later.
            let r = f.call(
                v,
                op,
                part(
                    &key,
                    true,
                    false,
                    None,
                    vec![cbc.clone(), Node::bytes(DATA, input[..16].to_vec())],
                ),
            );
            assert_eq!(status_of(items(&r)[0]), 1);
            let first = payload(&f.call(
                v,
                op,
                part(
                    &key,
                    true,
                    false,
                    None,
                    vec![
                        cbc.clone(),
                        Node::bytes(DATA, input[..16].to_vec()),
                        Node::bytes(IV_COUNTER_NONCE, vec![1; 16]),
                    ],
                ),
            ))
            .clone();
            let token = bytes_of(&first, CORRELATION_VALUE);
            let changed = f.call(
                v,
                op,
                part(
                    &key,
                    false,
                    true,
                    Some(&token),
                    vec![
                        Node::bytes(DATA, input[16..].to_vec()),
                        Node::bytes(IV_COUNTER_NONCE, vec![2; 16]),
                    ],
                ),
            );
            assert_eq!(status_of(items(&changed)[0]), 1);
            let last = payload(&f.call(
                v,
                op,
                part(
                    &key,
                    false,
                    true,
                    Some(&token),
                    vec![Node::bytes(DATA, input[16..].to_vec())],
                ),
            ))
            .clone();
            assert_eq!(
                [bytes_of(&first, DATA), bytes_of(&last, DATA)].concat(),
                expected,
                "op {op}"
            );
        }
    }
}

// REQ:da29aa6179c82835 2.x single-part and final Signature Verify carry the Validity Indicator
// REQ:9eea44401dd8e45f 2.x non-final Signature Verify parts carry no Validity Indicator
// REQ:1ec30c319eaef0c4 2.x single-part and final MAC Verify carry the Validity Indicator
// REQ:02064318769fd37d 2.x non-final MAC Verify parts carry no Validity Indicator
#[test]
fn validity_indicator_only_on_single_and_final_parts() {
    for v in [Version(2, 0), Version(2, 1)] {
        let mut f = Fixture::new();
        let mac = mac_key(&mut f, v);
        let tag = bytes_of(
            payload(&f.call(
                v,
                35,
                vec![uid(&mac), Node::bytes(DATA, b"abcdef".to_vec())],
            )),
            MAC_DATA,
        );
        let (private, public) = signing_pair(&mut f, v);
        let signature = bytes_of(
            payload(&f.call(
                v,
                33,
                vec![uid(&private), Node::bytes(DATA, b"abcdef".to_vec())],
            )),
            SIGNATURE_DATA,
        );
        for (op, id, proof) in [
            (36, mac.clone(), Node::bytes(MAC_DATA, tag)),
            (34, public.clone(), Node::bytes(SIGNATURE_DATA, signature)),
        ] {
            let single = payload(&f.call(
                v,
                op,
                vec![
                    uid(&id),
                    Node::bytes(DATA, b"abcdef".to_vec()),
                    proof.clone(),
                ],
            ))
            .clone();
            assert_eq!(num(&single, VALIDITY_INDICATOR), 1);
            let first = payload(&f.call(
                v,
                op,
                part(
                    &id,
                    true,
                    false,
                    None,
                    vec![Node::bytes(DATA, b"abc".to_vec())],
                ),
            ))
            .clone();
            assert!(first.get(VALIDITY_INDICATOR).is_none());
            let token = bytes_of(&first, CORRELATION_VALUE);
            let middle = payload(&f.call(
                v,
                op,
                part(
                    &id,
                    false,
                    false,
                    Some(&token),
                    vec![Node::bytes(DATA, b"d".to_vec())],
                ),
            ))
            .clone();
            assert!(middle.get(VALIDITY_INDICATOR).is_none());
            let token = bytes_of(&middle, CORRELATION_VALUE);
            let last = payload(&f.call(
                v,
                op,
                part(
                    &id,
                    false,
                    true,
                    Some(&token),
                    vec![Node::bytes(DATA, b"ef".to_vec()), proof.clone()],
                ),
            ))
            .clone();
            assert_eq!(num(&last, VALIDITY_INDICATOR), 1, "op {op}");
        }
    }
}

// REQ:51f3ac2e27e3efa5 1.2-1.4 MAC Verify without parameters uses the key's lowest-index Cryptographic Parameters
#[test]
fn mac_verify_defaults_to_the_lowest_index_parameters() {
    let cmac = || {
        Node::structure(
            CRYPTOGRAPHIC_PARAMETERS,
            vec![Node::enumeration(BLOCK_CIPHER_MODE, 7)],
        )
    };
    for v in [Version(1, 2), Version(1, 3), Version(1, 4)] {
        let mut f = Fixture::new();
        let usage = Node::int(CRYPTOGRAPHIC_USAGE_MASK, 0x180);
        let first = id_of(&register_raw(
            &mut f,
            v,
            2,
            &[6; 16],
            vec![usage.clone(), cmac(), ecb_parameters()],
        ));
        let second = id_of(&register_raw(
            &mut f,
            v,
            2,
            &[6; 16],
            vec![usage, ecb_parameters(), cmac()],
        ));
        activate(&mut f, v, &first);
        activate(&mut f, v, &second);
        let tag = bytes_of(
            payload(&f.call(
                v,
                35,
                vec![uid(&first), cmac(), Node::bytes(DATA, b"data".to_vec())],
            )),
            MAC_DATA,
        );
        let verify = |f: &mut Fixture, id: &str| {
            f.call(
                v,
                36,
                vec![
                    uid(id),
                    Node::bytes(DATA, b"data".to_vec()),
                    Node::bytes(MAC_DATA, tag.clone()),
                ],
            )
        };
        assert_eq!(num(payload(&verify(&mut f, &first)), VALIDITY_INDICATOR), 1);
        // Index 0 of the second key is ECB, which is not a MAC mode.
        assert_eq!(status_of(items(&verify(&mut f, &second))[0]), 1);
    }
}

fn kek(f: &mut Fixture, v: Version) -> String {
    let id = id_of(&register_raw(
        f,
        v,
        2,
        &[3; 32],
        vec![
            Node::int(CRYPTOGRAPHIC_USAGE_MASK, 48),
            Node::structure(
                CRYPTOGRAPHIC_PARAMETERS,
                vec![Node::enumeration(BLOCK_CIPHER_MODE, 12)],
            ),
        ],
    ));
    activate(f, v, &id);
    id
}
fn wrapping(kek: &str) -> Node {
    Node::structure(
        KEY_WRAPPING_SPECIFICATION,
        vec![
            Node::enumeration(WRAPPING_METHOD, 1),
            Node::structure(ENCRYPTION_KEY_INFORMATION, vec![uid(kek)]),
            Node::enumeration(ENCODING_OPTION, 1),
        ],
    )
}
fn has_tag(n: &Node, tag: u32) -> bool {
    n.tag == tag
        || n.children()
            .map(|c| c.iter().any(|c| has_tag(c, tag)))
            .unwrap_or(false)
}
/// Import fields that restore an exported object under its own identifier.
fn import_fields(v: Version, exported: &Node, extra: Vec<Node>) -> Vec<Node> {
    let mut fields = exported.children().unwrap().to_vec();
    if v.0 == 1 {
        fields.retain(|n| n.tag != OBJECT_TYPE);
    }
    fields.extend(extra);
    fields
}

fn key_block_object(kind: u32, format: u32, material: Vec<u8>, alg: u32, bits: i32) -> Node {
    let tag = match kind {
        2 => SYMMETRIC_KEY,
        3 => PUBLIC_KEY,
        _ => PRIVATE_KEY,
    };
    let value = if format == 7 {
        Node::structure(
            KEY_VALUE,
            vec![Node::structure(
                KEY_MATERIAL,
                vec![Node::bytes(KEY, material)],
            )],
        )
    } else {
        Node::structure(KEY_VALUE, vec![Node::bytes(KEY_MATERIAL, material)])
    };
    Node::structure(
        tag,
        vec![Node::structure(
            KEY_BLOCK,
            vec![
                Node::enumeration(KEY_FORMAT_TYPE, format),
                value,
                Node::enumeration(CRYPTOGRAPHIC_ALGORITHM, alg),
                Node::int(CRYPTOGRAPHIC_LENGTH, bits),
            ],
        )],
    )
}

// REQ:181fcc80b1178ef0 a key comes back from Get in the format it was registered in
#[test]
fn get_returns_keys_in_their_registered_format() {
    let rsa = openssl::pkey::PKey::from_rsa(openssl::rsa::Rsa::generate(2048).unwrap()).unwrap();
    let r = rsa.rsa().unwrap();
    let cases = [
        (2, 1, vec![8u8; 32], 3, 256, 4),
        (2, 7, vec![8u8; 32], 3, 256, 4),
        (4, 3, r.private_key_to_der().unwrap(), 4, 2048, 1),
        (4, 4, rsa.private_key_to_pkcs8().unwrap(), 4, 2048, 1),
        (3, 3, r.public_key_to_der_pkcs1().unwrap(), 4, 2048, 2),
        (3, 5, rsa.public_key_to_der().unwrap(), 4, 2048, 2),
    ];
    for v in FINAL {
        let mut f = Fixture::new();
        for (kind, format, material, alg, bits, usage) in cases.clone() {
            let object = key_block_object(kind, format, material, alg, bits);
            let id = id_of(&f.call(
                v,
                3,
                vec![
                    Node::enumeration(OBJECT_TYPE, kind),
                    container(v, vec![Node::int(CRYPTOGRAPHIC_USAGE_MASK, usage)]),
                    object.clone(),
                ],
            ));
            let got = payload(&f.call(
                v,
                10,
                vec![uid(&id), Node::enumeration(KEY_FORMAT_TYPE, format)],
            ))
            .clone();
            let returned = got.required(object.tag).unwrap();
            let block = |n: &Node| n.required(KEY_BLOCK).unwrap().clone();
            assert_eq!(num(&block(returned), KEY_FORMAT_TYPE), format);
            assert!(
                block(returned).required(KEY_VALUE).unwrap()
                    == block(&object).required(KEY_VALUE).unwrap(),
                "{}.{} format {format}",
                v.0,
                v.1
            );
        }
        // PKCS#12 (1.4+) is not offered: Key Format Type Not Supported.
        if v >= Version(1, 4) {
            let id = create(&mut f, v);
            let r = f.call(
                v,
                10,
                vec![uid(&id), Node::enumeration(KEY_FORMAT_TYPE, 22)],
            );
            assert_eq!(reason(&r), 16);
        }
    }
}

// REQ:e698be020a023fcd Export applies Key Format Type and Key Wrapping Specification as Get does
// REQ:fc8c2fc2272ff14b Export of a destroyed object returns no key material
#[test]
fn export_formats_like_get_and_withholds_destroyed_material() {
    for v in [Version(1, 4), Version(2, 0), Version(2, 1)] {
        let mut f = Fixture::new();
        let wrapper = kek(&mut f, v);
        let id = create(&mut f, v);
        for request in [
            vec![Node::enumeration(KEY_FORMAT_TYPE, 7)],
            vec![Node::enumeration(KEY_FORMAT_TYPE, 1), wrapping(&wrapper)],
        ] {
            let mut fields = vec![uid(&id)];
            fields.extend(request);
            let got = payload(&f.call(v, 10, fields.clone()))
                .required(SYMMETRIC_KEY)
                .unwrap()
                .clone();
            let exported = payload(&f.call(v, 43, fields))
                .required(SYMMETRIC_KEY)
                .unwrap()
                .clone();
            let block = |n: &Node| n.required(KEY_BLOCK).unwrap().clone();
            assert_eq!(
                num(&block(&got), KEY_FORMAT_TYPE),
                num(&block(&exported), KEY_FORMAT_TYPE)
            );
            let wrapped = |n: &Node| block(n).get(KEY_WRAPPING_DATA).is_some();
            assert_eq!(wrapped(&got), wrapped(&exported));
            if !wrapped(&got) {
                assert!(
                    block(&got).required(KEY_VALUE).unwrap()
                        == block(&exported).required(KEY_VALUE).unwrap()
                );
            }
        }
        payload(&f.call(v, 20, vec![uid(&id)]));
        let exported = payload(&f.call(v, 43, vec![uid(&id)])).clone();
        assert!(!has_tag(&exported, KEY_MATERIAL));
    }
}

// REQ:8607f218f9d8f4bb Import keeps the supplied attribute values instead of server-set ones
// REQ:e024bf937961e374 Replace Existing true replaces an object with the same identifier
// REQ:f1a21758a6a6f25f 1.4 without Replace Existing an identifier collision fails
// REQ:d938d14953bba414 2.x without Replace Existing an identifier collision fails
#[test]
fn import_keeps_supplied_attributes_and_only_replaces_on_request() {
    for v in [Version(1, 4), Version(2, 0), Version(2, 1)] {
        let mut f = Fixture::new();
        let id = create_with(&mut f, v, vec![group("original")]);
        activate(&mut f, v, &id);
        let exported = payload(&f.call(v, 43, vec![uid(&id)])).clone();
        let initial = date_attr(&mut f, v, &id, INITIAL_DATE).unwrap();
        let activation = date_attr(&mut f, v, &id, ACTIVATION_DATE).unwrap();
        for extra in [vec![], vec![Node::boolean(REPLACE_EXISTING, false)]] {
            let r = f.call(v, 42, import_fields(v, &exported, extra));
            assert_eq!(status_of(items(&r)[0]), 1);
        }
        payload(&f.call(v, 13, add(v, &id, group("added later"))));
        payload(&f.call(
            v,
            42,
            import_fields(v, &exported, vec![Node::boolean(REPLACE_EXISTING, true)]),
        ));
        assert_eq!(groups(&mut f, v, &id), ["original"]);
        // Imported into a fresh server: the dates and state are the supplied ones.
        let mut g = Fixture::new();
        payload(&g.call(v, 42, import_fields(v, &exported, vec![])));
        assert_eq!(date_attr(&mut g, v, &id, INITIAL_DATE), Some(initial));
        assert_eq!(date_attr(&mut g, v, &id, ACTIVATION_DATE), Some(activation));
        assert_eq!(state(&mut g, v, &id), 2);
    }
}

// REQ:92f08439bfa7e72a 1.4 Import Not Wrapped unwraps first and fails without the wrapping key
// REQ:2e7ff9e6032c100e 2.x Import Not Wrapped unwraps first and fails without the wrapping key
// REQ:16675e5059b47c19 1.4 otherwise Import stores the object as given
// REQ:a68405869cba84c7 2.x otherwise Import stores the object as given
#[test]
fn import_wrap_type_controls_unwrapping() {
    for v in [Version(1, 4), Version(2, 0), Version(2, 1)] {
        let mut f = Fixture::new();
        let wrapper = kek(&mut f, v);
        let id = create(&mut f, v);
        let clear = key_bytes(&mut f, v, &id);
        let exported = payload(&f.call(v, 43, vec![uid(&id), wrapping(&wrapper)])).clone();
        let wrapped_object = exported.required(SYMMETRIC_KEY).unwrap().clone();
        payload(&f.call(
            v,
            42,
            import_fields(
                v,
                &exported,
                vec![
                    Node::boolean(REPLACE_EXISTING, true),
                    Node::enumeration(KEY_WRAP_TYPE, 1),
                ],
            ),
        ));
        let stored = f.engine.store.get("alice", &id).unwrap().unwrap();
        assert_eq!(stored.material, clear);
        assert!(stored.wrapped.is_none());
        payload(&f.call(
            v,
            42,
            import_fields(
                v,
                &exported,
                vec![
                    Node::boolean(REPLACE_EXISTING, true),
                    Node::enumeration(KEY_WRAP_TYPE, 2),
                ],
            ),
        ));
        let as_registered =
            payload(&f.call(v, 10, vec![uid(&id), Node::enumeration(KEY_WRAP_TYPE, 2)])).clone();
        assert!(as_registered.required(SYMMETRIC_KEY).unwrap() == &wrapped_object);
        // Without the wrapping key, Not Wrapped cannot be honoured.
        let mut g = Fixture::new();
        let r = g.call(
            v,
            42,
            import_fields(v, &exported, vec![Node::enumeration(KEY_WRAP_TYPE, 1)]),
        );
        assert_eq!(status_of(items(&r)[0]), 1);
        assert!(g.engine.store.get("alice", &id).unwrap().is_none());
    }
}

// REQ:d46ee3dcc668c465 2.x registering a wrapped object links it to its wrapping key
#[test]
fn registering_a_wrapped_key_links_the_wrapping_key() {
    for v in [Version(2, 0), Version(2, 1)] {
        let mut f = Fixture::new();
        let wrapper = kek(&mut f, v);
        let id = create(&mut f, v);
        let object = payload(&f.call(v, 10, vec![uid(&id), wrapping(&wrapper)]))
            .required(SYMMETRIC_KEY)
            .unwrap()
            .clone();
        let registered = id_of(&f.call(
            v,
            3,
            vec![
                Node::enumeration(OBJECT_TYPE, 2),
                container(v, vec![Node::int(CRYPTOGRAPHIC_USAGE_MASK, 12)]),
                object,
            ],
        ));
        assert_eq!(
            links(&mut f, v, &registered, 0x10e),
            std::slice::from_ref(&wrapper)
        );
        assert!(links(&mut f, v, &id, 0x10e).is_empty());
    }
}

// REQ:6d99521554c647e2 Create Split Key leaves the part with Key Part Identifier 1 in the placeholder
// REQ:e5f7b1aa8d2c415f Join Split Key needs at least the threshold number of parts
// REQ:9d4f71c48efbb903 Join Split Key puts the joined object in the placeholder
#[test]
fn split_and_join_placeholders_and_threshold() {
    for v in FINAL.into_iter().filter(|v| *v >= Version(1, 2)) {
        let mut f = Fixture::new();
        let source = id_of(&register_raw(
            &mut f,
            v,
            2,
            &[5; 16],
            vec![Node::int(CRYPTOGRAPHIC_USAGE_MASK, 12)],
        ));
        let split = vec![
            Node::enumeration(OBJECT_TYPE, 5),
            Node::int(SPLIT_KEY_PARTS, 3),
            Node::int(SPLIT_KEY_THRESHOLD, 2),
            Node::enumeration(SPLIT_KEY_METHOD, 2),
            container(v, vec![]),
            uid(&source),
        ];
        let r = f.batch(v, vec![(40, split), (10, vec![])]);
        let it = items(&r);
        let parts = uids(item_payload(it[0]));
        assert_eq!(parts.len(), 3);
        let got = item_payload(it[1]);
        let part_one = text(got, UNIQUE_IDENTIFIER);
        assert!(parts.contains(&part_one));
        assert_eq!(
            got.required(SPLIT_KEY)
                .unwrap()
                .required(KEY_PART_IDENTIFIER)
                .unwrap()
                .number()
                .unwrap(),
            1
        );
        let join = |ids: &[&String]| {
            let mut fields = vec![Node::enumeration(OBJECT_TYPE, 2)];
            fields.extend(ids.iter().map(|id| uid(id)));
            fields
        };
        let r = f.call(v, 41, join(&[&parts[2]]));
        assert_eq!(status_of(items(&r)[0]), 1);
        let r = f.batch(v, vec![(41, join(&[&parts[2], &parts[0]])), (11, vec![])]);
        let it = items(&r);
        let joined = text(item_payload(it[0]), UNIQUE_IDENTIFIER);
        assert_eq!(text(item_payload(it[1]), UNIQUE_IDENTIFIER), joined);
        assert_eq!(key_bytes(&mut f, v, &joined), vec![5; 16]);
    }
}

fn asynchronous(v: Version) -> Node {
    if v.0 == 1 {
        Node::boolean(ASYNCHRONOUS_INDICATOR, true)
    } else {
        Node::enumeration(ASYNCHRONOUS_INDICATOR, 2)
    }
}
fn correlation(item: &Node) -> Node {
    item.required(ASYNCHRONOUS_CORRELATION_VALUE)
        .unwrap()
        .clone()
}
fn tags_of(n: &Node) -> Vec<u32> {
    n.children().unwrap().iter().map(|c| c.tag).collect()
}

// REQ:ee6b315c954c3b46 1.x Poll must name the original operation's correlation value
// REQ:2db3ce4cb76371f7 2.x Poll and Cancel must name the original correlation value
// REQ:4dd4359dc48be99e a Poll is always answered at once
// REQ:e56ce8a557786ca0 Poll answers either Pending or the completed result
// REQ:50e0e097d2d7aaf4 an unfinished operation polls as Pending without payload
// REQ:bb13b6343c6f5fb8 a finished operation polls with its payload
// REQ:893468adfeef4819 the polled result has the synchronous response's form
// REQ:cba5f9cd52c1dd8d 1.x Cancel answers with a Cancellation Result
// REQ:f599f4d1f72e36b4 2.x Cancel answers with a Cancellation Result
#[test]
fn poll_and_cancel_report_deferred_results() {
    for v in FINAL {
        let mut f = Fixture::new();
        let sync = payload(&f.call(v, 2, rsa_pair(v, vec![]))).clone();
        let r = f.send(&req(
            v,
            vec![asynchronous(v)],
            vec![(2, rsa_pair(v, vec![]))],
        ));
        let deferred = items(&r)[0];
        assert_eq!(status_of(deferred), 2);
        assert!(deferred.get(RESPONSE_PAYLOAD).is_none());
        let value = correlation(deferred);
        for p in [
            vec![],
            vec![Node::bytes(ASYNCHRONOUS_CORRELATION_VALUE, vec![0; 16])],
        ] {
            assert_eq!(status_of(items(&f.call(v, 26, p))[0]), 1);
        }
        assert_eq!(status_of(items(&f.call(v, 25, vec![]))[0]), 1);
        let pending = f.call(v, 26, vec![value.clone()]);
        assert_eq!(status_of(items(&pending)[0]), 2);
        assert!(items(&pending)[0].get(RESPONSE_PAYLOAD).is_none());
        assert!(f.engine.run_asynchronous());
        // Asked to defer, the Poll is still answered immediately.
        let done = f.send(&req(
            v,
            vec![asynchronous(v)],
            vec![(26, vec![value.clone()])],
        ));
        let done = items(&done)[0];
        assert_eq!(status_of(done), 0);
        assert!(done.get(ASYNCHRONOUS_CORRELATION_VALUE).is_none());
        assert_eq!(tags_of(item_payload(done)), tags_of(&sync));
        let canceled = payload(&f.call(v, 25, vec![value])).clone();
        assert_eq!(num(&canceled, CANCELLATION_RESULT), 3);
    }
}

/// Result Reasons of each 2.x per-operation error table (2.0/2.1 sections 6.1.x.1),
/// as (minor version, operation, reasons).
const ERROR_TABLES: &[(u32, u32, &[u32])] = &[
    (
        0,
        1,
        &[
            2, 4, 5, 7, 8, 10, 12, 20, 21, 29, 31, 34, 35, 44, 45, 48, 53, 58, 68,
        ],
    ),
    (
        0,
        2,
        &[
            2, 4, 5, 7, 8, 10, 12, 20, 21, 34, 35, 44, 45, 53, 58, 72, 73,
        ],
    ),
    (
        0,
        3,
        &[
            2, 4, 5, 7, 8, 12, 18, 20, 21, 34, 35, 37, 44, 45, 48, 53, 58, 68,
        ],
    ),
    (0, 4, &[2, 4, 5, 7, 8, 10, 12, 19, 20, 21, 48, 55, 68]),
    (
        0,
        5,
        &[
            2, 4, 5, 7, 8, 10, 12, 19, 20, 21, 36, 41, 44, 48, 53, 55, 62, 67,
        ],
    ),
    (0, 6, &[1, 2, 4, 5, 7, 8, 12, 20, 21, 47, 48, 68]),
    (0, 7, &[2, 4, 5, 7, 8, 12, 20, 21, 47, 48, 55, 68]),
    (0, 8, &[2, 4, 5, 7, 8, 12, 20, 21, 44]),
    (0, 9, &[2, 4, 5, 7, 8, 12, 20, 21, 26, 40, 41, 55]),
    (
        0,
        10,
        &[
            2, 4, 5, 7, 8, 12, 16, 17, 18, 19, 20, 21, 22, 23, 36, 41, 48, 50, 55, 64, 65, 66,
        ],
    ),
    (0, 11, &[2, 4, 5, 7, 8, 12, 20, 21, 44, 55]),
    (0, 12, &[2, 4, 5, 7, 8, 12, 20, 21, 55]),
    (0, 13, &[2, 4, 5, 7, 8, 12, 20, 21, 29, 35, 44, 53, 55, 58]),
    (0, 14, &[2, 4, 5, 7, 8, 12, 20, 21, 32, 33, 34, 53, 55]),
    (0, 15, &[2, 4, 5, 7, 8, 12, 20, 21, 32, 33, 34, 44, 55]),
    (0, 16, &[2, 4, 5, 7, 8, 12, 20, 21, 26, 55]),
    (0, 17, &[2, 4, 5, 7, 8, 12, 20, 21, 26, 33, 48, 55]),
    (0, 18, &[2, 4, 5, 7, 8, 12, 20, 21, 48, 55, 67]),
    (0, 19, &[2, 4, 5, 7, 8, 12, 20, 21, 48, 55, 67]),
    (0, 20, &[2, 4, 5, 7, 8, 12, 20, 21, 54, 55, 67]),
    (0, 21, &[2, 4, 5, 7, 8, 12, 13, 20, 21, 55]),
    (0, 22, &[2, 4, 5, 7, 8, 12, 20, 21, 55]),
    (0, 23, &[2, 4, 5, 7, 8, 12, 20, 21, 48, 55]),
    (0, 24, &[2, 4, 5, 7, 8, 12, 20, 21]),
    (0, 26, &[2, 4, 5, 7, 8, 12, 20, 21, 43]),
    (0, 29, &[2, 4, 5, 7, 8, 10, 12, 19, 20, 21, 48, 55, 72, 73]),
    (0, 30, &[2, 4, 5, 7, 8, 12, 20, 21]),
    (
        0,
        31,
        &[
            2, 4, 5, 7, 8, 10, 12, 19, 20, 21, 26, 36, 41, 46, 48, 52, 55, 62, 67,
        ],
    ),
    (
        0,
        32,
        &[
            2, 4, 5, 7, 8, 10, 12, 19, 20, 21, 36, 41, 46, 48, 52, 55, 62, 67,
        ],
    ),
    (
        0,
        33,
        &[
            2, 4, 5, 7, 8, 10, 12, 19, 20, 21, 26, 36, 41, 46, 48, 55, 62, 67,
        ],
    ),
    (
        0,
        34,
        &[
            2, 4, 5, 7, 8, 10, 12, 19, 20, 21, 36, 41, 46, 48, 55, 62, 67,
        ],
    ),
    (
        0,
        35,
        &[
            2, 4, 5, 7, 8, 10, 12, 19, 20, 21, 26, 36, 41, 46, 48, 55, 67,
        ],
    ),
    (
        0,
        36,
        &[2, 4, 5, 7, 8, 10, 12, 19, 20, 21, 36, 41, 46, 48, 55, 67],
    ),
    (0, 37, &[2, 4, 5, 7, 8, 10, 12, 20, 21]),
    (0, 38, &[2, 4, 5, 7, 8, 10, 12, 20, 21]),
    (0, 39, &[2, 4, 5, 7, 8, 10, 12, 20, 21, 46]),
    (
        0,
        40,
        &[
            1, 2, 4, 5, 7, 8, 10, 12, 20, 21, 36, 44, 45, 48, 53, 58, 62, 68,
        ],
    ),
    (
        0,
        41,
        &[
            2, 4, 5, 7, 8, 10, 12, 20, 21, 34, 35, 36, 44, 45, 48, 53, 55, 58, 62, 68,
        ],
    ),
    (
        0,
        42,
        &[
            2, 4, 5, 7, 8, 12, 18, 20, 21, 24, 34, 35, 44, 45, 53, 58, 68,
        ],
    ),
    (
        0,
        43,
        &[
            2, 4, 5, 7, 8, 12, 16, 17, 18, 19, 20, 21, 36, 41, 48, 50, 55, 64, 65, 66,
        ],
    ),
    (0, 44, &[2, 4, 5, 7, 8, 12, 20, 21]),
    (0, 45, &[2, 4, 5, 7, 8, 12, 20, 21]),
    (0, 46, &[2, 4, 5, 7, 8, 12, 20, 21, 25]),
    (0, 47, &[2, 4, 5, 7, 8, 12, 20, 21]),
    (
        0,
        48,
        &[1, 2, 4, 5, 7, 8, 12, 13, 20, 21, 27, 28, 29, 30, 31],
    ),
    (0, 49, &[2, 4, 5, 7, 8, 12, 20, 21, 29, 30, 45, 53, 55]),
    (0, 50, &[2, 4, 5, 7, 8, 12, 20, 21]),
    (0, 51, &[2, 4, 5, 7, 8, 12, 20, 21, 43, 69, 70, 71]),
    (0, 52, &[2, 4, 5, 7, 8, 12, 20, 21]),
    (0, 53, &[2, 4, 5, 7, 8, 10, 12, 20, 21]),
    (
        1,
        1,
        &[
            2, 4, 5, 7, 8, 10, 12, 20, 21, 29, 31, 34, 35, 44, 45, 48, 53, 58, 68,
        ],
    ),
    (
        1,
        2,
        &[
            2, 4, 5, 7, 8, 10, 12, 20, 21, 34, 35, 44, 45, 53, 58, 72, 73,
        ],
    ),
    (
        1,
        3,
        &[
            2, 4, 5, 7, 8, 12, 18, 20, 21, 34, 35, 37, 44, 45, 48, 53, 58, 68,
        ],
    ),
    (1, 4, &[2, 4, 5, 7, 8, 10, 12, 19, 20, 21, 48, 55, 68]),
    (
        1,
        5,
        &[
            2, 4, 5, 7, 8, 10, 12, 19, 20, 21, 36, 41, 44, 48, 53, 55, 62, 67,
        ],
    ),
    (1, 6, &[1, 2, 4, 5, 7, 8, 12, 20, 21, 47, 48, 68]),
    (1, 7, &[2, 4, 5, 7, 8, 12, 20, 21, 47, 48, 55, 68]),
    (1, 8, &[2, 4, 5, 7, 8, 12, 20, 21, 44]),
    (1, 9, &[2, 4, 5, 7, 8, 12, 20, 21, 26, 40, 41, 55]),
    (
        1,
        10,
        &[
            2, 4, 5, 7, 8, 12, 16, 17, 18, 19, 20, 21, 22, 23, 36, 41, 48, 50, 55, 64, 65, 66,
        ],
    ),
    (1, 11, &[2, 4, 5, 7, 8, 12, 20, 21, 44, 55]),
    (1, 12, &[2, 4, 5, 7, 8, 12, 20, 21, 55]),
    (
        1,
        13,
        &[2, 4, 5, 7, 8, 12, 20, 21, 29, 35, 44, 53, 55, 58, 67],
    ),
    (1, 14, &[2, 4, 5, 7, 8, 12, 20, 21, 32, 33, 34, 53, 55, 67]),
    (1, 15, &[2, 4, 5, 7, 8, 12, 20, 21, 32, 33, 34, 44, 55, 67]),
    (1, 16, &[2, 4, 5, 7, 8, 12, 20, 21, 26, 55]),
    (1, 17, &[2, 4, 5, 7, 8, 12, 20, 21, 26, 33, 48, 55]),
    (1, 18, &[2, 4, 5, 7, 8, 12, 20, 21, 48, 55, 67]),
    (1, 19, &[2, 4, 5, 7, 8, 12, 20, 21, 48, 55, 67]),
    (1, 20, &[2, 4, 5, 7, 8, 12, 20, 21, 54, 55, 67]),
    (1, 21, &[2, 4, 5, 7, 8, 12, 13, 20, 21, 55]),
    (1, 22, &[2, 4, 5, 7, 8, 12, 20, 21, 55]),
    (1, 23, &[2, 4, 5, 7, 8, 12, 20, 21, 48, 55]),
    (1, 24, &[2, 4, 5, 7, 8, 12, 20, 21, 74]),
    (1, 26, &[2, 4, 5, 7, 8, 12, 20, 21, 43]),
    (1, 29, &[2, 4, 5, 7, 8, 10, 12, 19, 20, 21, 48, 55, 72, 73]),
    (1, 30, &[2, 4, 5, 7, 8, 12, 20, 21]),
    (
        1,
        31,
        &[
            2, 4, 5, 7, 8, 10, 12, 19, 20, 21, 26, 36, 41, 46, 48, 52, 55, 62, 67,
        ],
    ),
    (
        1,
        32,
        &[
            2, 4, 5, 7, 8, 10, 12, 19, 20, 21, 36, 41, 46, 48, 52, 55, 62, 67,
        ],
    ),
    (
        1,
        33,
        &[
            2, 4, 5, 7, 8, 10, 12, 19, 20, 21, 26, 36, 41, 46, 48, 55, 62, 67,
        ],
    ),
    (
        1,
        34,
        &[
            2, 4, 5, 7, 8, 10, 12, 19, 20, 21, 36, 41, 46, 48, 55, 62, 67,
        ],
    ),
    (
        1,
        35,
        &[
            2, 4, 5, 7, 8, 10, 12, 19, 20, 21, 26, 36, 41, 46, 48, 55, 67,
        ],
    ),
    (
        1,
        36,
        &[2, 4, 5, 7, 8, 10, 12, 19, 20, 21, 36, 41, 46, 48, 55, 67],
    ),
    (1, 37, &[2, 4, 5, 7, 8, 10, 12, 20, 21]),
    (1, 38, &[2, 4, 5, 7, 8, 10, 12, 20, 21]),
    (1, 39, &[2, 4, 5, 7, 8, 10, 12, 20, 21, 46]),
    (
        1,
        40,
        &[
            1, 2, 4, 5, 7, 8, 10, 12, 20, 21, 36, 44, 45, 48, 53, 58, 62, 68,
        ],
    ),
    (
        1,
        41,
        &[
            2, 4, 5, 7, 8, 10, 12, 20, 21, 34, 35, 36, 44, 45, 48, 53, 55, 58, 62, 68,
        ],
    ),
    (
        1,
        42,
        &[
            2, 4, 5, 7, 8, 12, 18, 20, 21, 24, 34, 35, 44, 45, 53, 58, 68,
        ],
    ),
    (
        1,
        43,
        &[
            2, 4, 5, 7, 8, 12, 16, 17, 18, 19, 20, 21, 36, 41, 48, 50, 55, 64, 65, 66,
        ],
    ),
    (1, 44, &[2, 4, 5, 7, 8, 12, 20, 21]),
    (1, 45, &[2, 4, 5, 7, 8, 12, 20, 21]),
    (1, 46, &[2, 4, 5, 7, 8, 12, 20, 21, 25]),
    (1, 47, &[2, 4, 5, 7, 8, 12, 20, 21]),
    (
        1,
        48,
        &[1, 2, 4, 5, 7, 8, 12, 13, 20, 21, 27, 28, 29, 30, 31, 67],
    ),
    (1, 49, &[2, 4, 5, 7, 8, 12, 20, 21, 29, 30, 45, 53, 55, 67]),
    (1, 50, &[2, 4, 5, 7, 8, 12, 20, 21]),
    (1, 51, &[2, 4, 5, 7, 8, 12, 20, 21, 43, 69, 70, 71]),
    (1, 52, &[2, 4, 5, 7, 8, 12, 20, 21]),
    (1, 53, &[2, 4, 5, 7, 8, 10, 12, 20, 21]),
    (1, 54, &[2, 4, 5, 7, 8, 12, 20, 21, 48]),
    (1, 55, &[2, 4, 5, 7, 8, 12, 20, 21, 48]),
    (1, 56, &[2, 4, 5, 7, 8, 12, 20, 21, 48]),
    (1, 57, &[2, 4, 5, 8, 12, 20, 21]),
    (1, 58, &[2, 4, 5, 7, 8, 12, 20, 21, 43]),
    (0, 25, &[2, 4, 5, 7, 8, 12, 20, 21, 43]),
    (1, 25, &[2, 4, 5, 7, 8, 12, 20, 21, 43]),
];
fn table(v: Version, op: u32) -> &'static [u32] {
    ERROR_TABLES
        .iter()
        .find(|(minor, o, _)| *minor == v.1 && *o == op)
        .map(|(_, _, reasons)| *reasons)
        .unwrap_or_else(|| panic!("no error table for operation {op}"))
}
/// Erroneous requests for one operation: malformed payloads and identifiers
/// of missing, destroyed, archived, Pre-Active and wrong-type objects.
fn error_battery(f: &mut Fixture, v: Version, op: u32) -> Vec<(String, Vec<Node>)> {
    let destroyed = create(f, v);
    payload(&f.call(v, 20, vec![uid(&destroyed)]));
    let archived = create(f, v);
    payload(&f.call(v, 21, vec![uid(&archived)]));
    let pre_active = create(f, v);
    let secret = id_of(&register_raw(
        f,
        v,
        7,
        &[1; 16],
        vec![Node::int(CRYPTOGRAPHIC_USAGE_MASK, 12)],
    ));
    activate(f, v, &secret);
    let extra = |op: u32| -> Vec<Node> {
        match op {
            31..=36 => vec![Node::bytes(DATA, vec![0; 16])],
            17 => vec![Node::long(USAGE_LIMITS_COUNT, 1)],
            19 => revoke(1, None),
            13 | 49 => vec![Node::structure(
                NEW_ATTRIBUTE,
                vec![Node::text(CONTACT_INFORMATION, "x")],
            )],
            14 => vec![Node::structure(
                NEW_ATTRIBUTE,
                vec![Node::text(CONTACT_INFORMATION, "x")],
            )],
            15 => vec![Node::enumeration(ATTRIBUTE_REFERENCE, CONTACT_INFORMATION)],
            9 => vec![Node::int(CRYPTOGRAPHIC_USAGE_MASK, 4)],
            _ => vec![],
        }
    };
    let mut cases = vec![
        ("empty".to_owned(), vec![]),
        ("unknown field".to_owned(), vec![Node::int(BATCH_COUNT, 1)]),
    ];
    let aes_with = |length: i32| {
        container(
            v,
            vec![
                Node::enumeration(CRYPTOGRAPHIC_ALGORITHM, 3),
                Node::int(CRYPTOGRAPHIC_LENGTH, length),
                Node::int(CRYPTOGRAPHIC_USAGE_MASK, 12),
            ],
        )
    };
    let acv = |n: usize| Node::bytes(ASYNCHRONOUS_CORRELATION_VALUE, vec![9; n]);
    let specific: Vec<(&str, Vec<Node>)> = match op {
        1 => vec![
            (
                "bad type",
                vec![Node::enumeration(OBJECT_TYPE, 99), aes_with(256)],
            ),
            (
                "private key type",
                vec![Node::enumeration(OBJECT_TYPE, 4), aes_with(256)],
            ),
            (
                "bad length",
                vec![Node::enumeration(OBJECT_TYPE, 2), aes_with(100)],
            ),
            (
                "read-only attribute",
                vec![
                    Node::enumeration(OBJECT_TYPE, 2),
                    container(
                        v,
                        vec![
                            Node::enumeration(CRYPTOGRAPHIC_ALGORITHM, 3),
                            Node::int(CRYPTOGRAPHIC_LENGTH, 256),
                            Node::date(INITIAL_DATE, 5),
                        ],
                    ),
                ],
            ),
        ],
        2 => vec![(
            "bad length",
            vec![container_as(
                v,
                COMMON_TEMPLATE_ATTRIBUTE,
                COMMON_ATTRIBUTES,
                vec![
                    Node::enumeration(CRYPTOGRAPHIC_ALGORITHM, 4),
                    Node::int(CRYPTOGRAPHIC_LENGTH, 100),
                ],
            )],
        )],
        3 => vec![
            (
                "type mismatch",
                vec![
                    Node::enumeration(OBJECT_TYPE, 2),
                    container(v, vec![]),
                    Node::structure(SECRET_DATA, vec![]),
                ],
            ),
            (
                "empty key block",
                vec![
                    Node::enumeration(OBJECT_TYPE, 2),
                    container(v, vec![]),
                    Node::structure(SYMMETRIC_KEY, vec![Node::structure(KEY_BLOCK, vec![])]),
                ],
            ),
        ],
        8 => vec![
            (
                "unsupported filter",
                locate_fields(v, vec![Node::text(CONTACT_INFORMATION, "x")]),
            ),
            ("bad mask", vec![Node::int(STORAGE_STATUS_MASK, 0x100)]),
        ],
        24 => vec![("bad function", vec![Node::enumeration(QUERY_FUNCTION, 99)])],
        25 | 26 | 58 => vec![
            ("short value", vec![acv(3)]),
            ("unknown value", vec![acv(16)]),
        ],
        37 => vec![
            ("too long", vec![Node::int(DATA_LENGTH, 1 << 24)]),
            ("negative", vec![Node::int(DATA_LENGTH, -1)]),
        ],
        38 => vec![("wrong type", vec![Node::int(DATA, 1)])],
        39 => vec![
            (
                "bad hash",
                vec![
                    Node::structure(
                        CRYPTOGRAPHIC_PARAMETERS,
                        vec![Node::enumeration(HASHING_ALGORITHM, 99)],
                    ),
                    Node::bytes(DATA, vec![1]),
                ],
            ),
            (
                "no data",
                vec![Node::structure(
                    CRYPTOGRAPHIC_PARAMETERS,
                    vec![Node::enumeration(HASHING_ALGORITHM, 6)],
                )],
            ),
        ],
        40 => vec![(
            "threshold above parts",
            vec![
                Node::enumeration(OBJECT_TYPE, 5),
                Node::int(SPLIT_KEY_PARTS, 2),
                Node::int(SPLIT_KEY_THRESHOLD, 3),
                Node::enumeration(SPLIT_KEY_METHOD, 2),
                container(v, vec![]),
                uid("no-such-object"),
            ],
        )],
        44 => vec![("wrong type", vec![Node::int(LOG_MESSAGE, 1)])],
        51 => vec![("bad function", vec![Node::bytes(PKCS_11_FUNCTION, vec![1])])],
        _ => vec![],
    };
    for (label, p) in specific {
        cases.push((label.to_owned(), p));
    }
    let takes_id = ![1, 2, 3, 8, 24, 25, 26, 30, 37, 38, 39, 44, 51, 57, 58].contains(&op);
    if takes_id {
        for (label, id) in [
            ("missing", "no-such-object".to_owned()),
            ("destroyed", destroyed),
            ("archived", archived),
            ("pre-active", pre_active),
            ("secret data", secret),
        ] {
            let mut p = vec![uid(&id)];
            p.extend(extra(op));
            cases.push((label.to_owned(), p));
        }
    }
    cases
}

// REQ:866674131ca51bfc 2.x Create errors use Create's table of Result Reasons
// REQ:03c9fc3588188cd1 2.x Create Key Pair errors use its table of Result Reasons
// REQ:7a74ffa64a92145b 2.x Register errors use Register's table of Result Reasons
// REQ:0528911be98a1644 2.x Locate errors use Locate's table of Result Reasons
// REQ:25a8b3ea0e75020a 2.x Query errors use Query's table of Result Reasons
// REQ:f5818579ed098653 2.x Cancel errors use Cancel's table of Result Reasons
// REQ:11e0e5d72522a9f1 2.x Poll errors use Poll's table of Result Reasons
// REQ:f499a9019eb093f1 2.x Discover Versions errors use its table of Result Reasons
// REQ:020e395ab2409fe1 2.x RNG Retrieve errors use its table of Result Reasons
// REQ:8e77562cd8f53d58 2.x RNG Seed errors use its table of Result Reasons
// REQ:5016384194d76958 2.x Hash errors use Hash's table of Result Reasons
// REQ:b1868e3012b3cc8c 2.x Create Split Key errors use its table of Result Reasons
// REQ:07dd9b88ff140c3a 2.x Import errors use Import's table of Result Reasons
// REQ:ac16bbd5d6875ff8 2.x Adjust Attribute errors use its table of Result Reasons
// REQ:584060d1ce48c31c 2.x PKCS#11 errors use its table of Result Reasons
// REQ:8f4e627dc7aebd4c 2.1 Process errors use Process's table of Result Reasons
// REQ:e8e3951c11f7acb1 2.1 Query Asynchronous Requests errors use its table of Result Reasons
// REQ:4b6ccbf0e3837797 2.x Derive Key errors use its table of Result Reasons
// REQ:9ac8d3c8813511f2 2.x Archive errors use Archive's table of Result Reasons
// REQ:bd538293e32102dc 2.x Recover errors use Recover's table of Result Reasons
// REQ:6112d35b6229d4d4 2.x Re-key Key Pair errors use its table of Result Reasons
// REQ:036b3bbb98934f3a 2.x Join Split Key errors use its table of Result Reasons
// REQ:61ada52a7bbe37b0 2.x Re-key errors use Re-key's table of Result Reasons
// REQ:c993187a292a2d25 2.x Certify errors use Certify's table of Result Reasons
// REQ:41f3c4d1227a43fb 2.x Re-certify errors use its table of Result Reasons
// REQ:fd5dafb2d25e9364 2.x Check errors use Check's table of Result Reasons
// REQ:97ceb6b0d6644ea3 2.x Get errors use Get's table (Object Destroyed for a destroyed target)
// REQ:4953d329b5f770de 2.x Get Attributes errors use its table of Result Reasons
// REQ:306863620219f260 2.x Get Attribute List errors use its table of Result Reasons
// REQ:7e2ea777f3122034 2.x Add Attribute and Set Attribute errors use their tables of Result Reasons
// REQ:b7642aa3b76f8d4f 2.x Modify Attribute errors use its table of Result Reasons
// REQ:e86d4529d7e2cb88 2.x Delete Attribute errors use its table of Result Reasons
// REQ:288086bd968d41f0 2.x Obtain Lease errors use its table of Result Reasons
// REQ:008d8988063485f8 2.x Get Usage Allocation errors use its table of Result Reasons
// REQ:487bd4a8cb416c5f 2.x Activate errors use Activate's table of Result Reasons
// REQ:123ba3bacce17e3a 2.x Revoke errors use Revoke's table of Result Reasons
// REQ:b671d7d0bc83514f 2.x Destroy errors use Destroy's table of Result Reasons
// REQ:53ce3cfa0d947302 2.x Validate errors use Validate's table of Result Reasons
// REQ:7a47dd1e74c03a07 2.x Encrypt errors use Encrypt's table of Result Reasons
// REQ:1534726c1697f90c 2.x Decrypt errors use Decrypt's table of Result Reasons
// REQ:9515d862329af3e3 2.x Sign errors use Sign's table of Result Reasons
// REQ:919a28adf842875f 2.x Signature Verify errors use its table of Result Reasons
// REQ:c1096579c9890676 2.x MAC errors use MAC's table of Result Reasons
// REQ:9b6f817bc53fd69a 2.x MAC Verify errors use its table of Result Reasons
// REQ:d15e9a7f9c4ca14e 2.x Export errors use Export's table of Result Reasons
// REQ:68b376250ee3a4ef 2.x Login errors use Login's table of Result Reasons
// REQ:3ed3edb83cb49d88 2.x Logout errors use Logout's table of Result Reasons
// REQ:67bc87f715dee966 2.x Delegated Login errors use its table of Result Reasons
// REQ:808e8f3ce169c8c5 2.x a failed item's Result Reason is the one its operation's error handling names
// REQ:ca6dfee3e4dcf948 2.1 a condition the table omits gets the most appropriate reason: Object Archived for an archived target
const OBJECT_ARCHIVED: u32 = 0x0D;
const OBJECT_DESTROYED: u32 = 0x36;
#[test]
fn error_reasons_come_from_each_operations_table() {
    for v in [Version(2, 0), Version(2, 1)] {
        let mut ops = vec![
            1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24,
            25, 26, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48,
            49, 51,
        ];
        if v == Version(2, 1) {
            ops.extend([54, 55, 56, 57, 58]);
        }
        for op in ops {
            let mut f = Fixture::new();
            let mut failures = 0;
            for (label, p) in error_battery(&mut f, v, op) {
                let r = f.call(v, op, p);
                let it = items(&r)[0];
                if status_of(it) == 1 {
                    failures += 1;
                    let reason = num(it, RESULT_REASON);
                    if table(v, op).contains(&reason) {
                        continue;
                    }
                    // A condition the table does not list gets the most
                    // appropriate reason (2.1 section 6.1): Object Archived
                    // for an archived target and, for Get, Object Destroyed
                    // for a destroyed one (docs/interpretations.md).
                    let expected = match label.as_str() {
                        "archived" => Some(OBJECT_ARCHIVED),
                        "destroyed" if op == 10 => Some(OBJECT_DESTROYED),
                        _ => None,
                    };
                    assert_eq!(
                        Some(reason),
                        expected,
                        "{}.{} operation {op} {label}: reason {reason}",
                        v.0,
                        v.1
                    );
                }
            }
            assert!(failures >= 1, "operation {op}");
        }
    }
}

/// An omitted Unique Identifier with an empty ID Placeholder: 1.x answers
/// Item Not Found, the only row its error tables give for an unidentified
/// object (1.1 table 260, 1.2 table 301 Get; the 1.2 note's TC-152-11/12);
/// no 2.x error table lists Missing Data, so 2.x answers Invalid Field, which
/// every table lists (2.1 Tables 222 Get, 307 Re-key, 166
/// Activate). An attribute change on a destroyed object is Permission Denied up
/// to 2.0 (2.0 Table 154 has no state reason) and Wrong Key Lifecycle State
/// from 2.1 (Table 169).
#[test]
fn missing_data_and_destroyed_attribute_changes_follow_the_editions_tables() {
    for v in FINAL {
        let mut f = Fixture::new();
        for op in [4, 10, 18] {
            let r = f.call(v, op, vec![]);
            assert_eq!(reason(&r), if v.0 >= 2 { 7 } else { 1 }, "op {op}");
            if v.0 >= 2 {
                assert!(table(v, op).contains(&reason(&r)));
            }
        }
        let id = create(&mut f, v);
        payload(&f.call(v, 20, vec![uid(&id)]));
        let contact = attribute(v, Node::text(CONTACT_INFORMATION, "x"));
        let add = if v.0 >= 2 {
            vec![uid(&id), Node::structure(NEW_ATTRIBUTE, vec![contact])]
        } else {
            vec![uid(&id), contact]
        };
        let r = f.call(v, 13, add);
        assert_eq!(reason(&r), if v >= Version(2, 1) { 0x43 } else { 12 });
        if v.0 >= 2 {
            assert!(table(v, 13).contains(&reason(&r)));
        }
    }
}

// REQ:07d55ae145c03121 Interop is not offered: its only error is Operation Not Supported
// REQ:3d6d03f56615333f Re-Provision is not offered: its only error is Operation Not Supported
// REQ:46edabd26b04bd60 Set Endpoint Role is not offered: its only error is Operation Not Supported
#[test]
fn operations_not_offered_fail_with_a_reason_from_their_table() {
    for v in [Version(2, 0), Version(2, 1)] {
        // Set Endpoint Role (50) is implemented from 2.0 (tests/endpoint_role.rs).
        // Login, Logout and Delegated Login (45-47) are offered from 2.0
        // (tests/tickets.rs, tests/delegation.rs); Set Defaults, Set
        // Constraints and Get Constraints (54-56) from 2.1
        // (tests/server_defaults.rs, tests/server_constraints.rs). Interop
        // and Re-Provision are opt-in and not configured here.
        let ops = [52, 53];
        let mut f = Fixture::new();
        for op in ops {
            for p in [vec![], vec![uid("x")], vec![Node::int(BATCH_COUNT, 1)]] {
                let r = f.call(v, op, p);
                assert_eq!(reason(&r), 5);
                assert!(table(v, op).contains(&5));
            }
        }
    }
}

// REQ:571209ab8236d5d9 1.2-1.4 Register attributes are given in the Template-Attribute
// REQ:884cd7703499d40d 2.x Register attributes are given in the Attributes structure
#[test]
fn register_takes_attributes_only_from_its_container() {
    for v in FINAL.into_iter().filter(|v| *v >= Version(1, 2)) {
        let mut f = Fixture::new();
        let object = key_block_object(2, 1, vec![1; 16], 3, 128);
        let r = f.call(
            v,
            3,
            vec![
                Node::enumeration(OBJECT_TYPE, 2),
                container(v, vec![]),
                object.clone(),
                Node::int(CRYPTOGRAPHIC_USAGE_MASK, 12),
            ],
        );
        assert_eq!(status_of(items(&r)[0]), 1);
        let id = id_of(&f.call(
            v,
            3,
            vec![
                Node::enumeration(OBJECT_TYPE, 2),
                container(
                    v,
                    vec![Node::int(CRYPTOGRAPHIC_USAGE_MASK, 12), group("inside")],
                ),
                object,
            ],
        ));
        assert_eq!(groups(&mut f, v, &id), ["inside"]);
        assert_eq!(
            attr_values(&mut f, v, &id, CRYPTOGRAPHIC_USAGE_MASK)[0]
                .number()
                .unwrap(),
            12
        );
    }
}
