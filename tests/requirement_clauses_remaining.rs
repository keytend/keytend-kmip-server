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

//! Focused tests for requirement-matrix clauses that the other clause test
//! files leave open. Each asserting test
//! names the clause digests it checks as `REQ:<digest>` (see
//! docs/specs/requirement-matrix.json); the paraphrases are our own words.
use keytend_kmip_server::{
    protocol::{Engine, Version},
    store::Store,
    tags::*,
    ttlv::Node,
};
use openssl::{pkey::PKey, rsa::Rsa};
use tempfile::TempDir;

/// Editions that define the Random Number Generator attribute (1.3 section 3.44,
/// 2.0/2.1 section 4.46).
const RNG_EDITIONS: [Version; 4] = [Version(1, 3), Version(1, 4), Version(2, 0), Version(2, 1)];
const LEGACY: [Version; 5] = [
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
    /// One operation in its own request; returns its response Batch Item.
    fn call(&mut self, v: Version, op: u32, fields: Vec<Node>) -> Node {
        let request = Node::structure(
            REQUEST_MESSAGE,
            vec![
                Node::structure(REQUEST_HEADER, vec![v.node(), Node::int(BATCH_COUNT, 1)]),
                Node::structure(
                    BATCH_ITEM,
                    vec![
                        Node::enumeration(OPERATION, op),
                        Node::structure(REQUEST_PAYLOAD, fields),
                    ],
                ),
            ],
        );
        let response = self.engine.process("alice", &request).unwrap();
        response.required(BATCH_ITEM).unwrap().clone()
    }
}

fn label(v: Version) -> String {
    format!("{}.{}", v.0, v.1)
}
fn status(item: &Node) -> u32 {
    item.required(RESULT_STATUS).unwrap().number().unwrap()
}
fn ok(item: &Node) -> &Node {
    assert_eq!(
        status(item),
        0,
        "reason {:?} {:?}",
        item.get(RESULT_REASON).map(|n| n.number()),
        item.get(RESULT_MESSAGE).map(|n| n.string())
    );
    item.required(RESPONSE_PAYLOAD).unwrap()
}
fn reason(item: &Node) -> u32 {
    assert_eq!(status(item), 1, "expected Operation Failed");
    item.required(RESULT_REASON).unwrap().number().unwrap()
}
fn text(n: &Node, tag: u32) -> String {
    n.required(tag)
        .unwrap()
        .identifier_text()
        .unwrap()
        .to_owned()
}
fn id_of(item: &Node) -> String {
    text(ok(item), UNIQUE_IDENTIFIER)
}
fn uid(id: &str) -> Node {
    Node::text(UNIQUE_IDENTIFIER, id)
}
fn name_of(tag: u32) -> &'static str {
    match tag {
        CRYPTOGRAPHIC_ALGORITHM => "Cryptographic Algorithm",
        CRYPTOGRAPHIC_LENGTH => "Cryptographic Length",
        CRYPTOGRAPHIC_USAGE_MASK => "Cryptographic Usage Mask",
        CRYPTOGRAPHIC_PARAMETERS => "Cryptographic Parameters",
        CRYPTOGRAPHIC_DOMAIN_PARAMETERS => "Cryptographic Domain Parameters",
        t => tag_name(t).unwrap(),
    }
}
/// A 2.x attribute in the edition's form (1.x Attribute structure).
fn attribute(v: Version, a: Node) -> Node {
    if v.0 >= 2 {
        return a;
    }
    let mut value = a.clone();
    value.tag = ATTRIBUTE_VALUE;
    Node::structure(
        ATTRIBUTE,
        vec![Node::text(ATTRIBUTE_NAME, name_of(a.tag)), value],
    )
}
fn container_as(v: Version, one: u32, two: u32, attrs: Vec<Node>) -> Node {
    if v.0 >= 2 {
        Node::structure(two, attrs)
    } else {
        Node::structure(one, attrs.into_iter().map(|a| attribute(v, a)).collect())
    }
}
/// Template-Attribute (1.x) or Attributes (2.x).
fn container(v: Version, attrs: Vec<Node>) -> Node {
    container_as(v, TEMPLATE_ATTRIBUTE, ATTRIBUTES, attrs)
}
fn selector(v: Version, tag: u32) -> Node {
    if v.0 == 1 {
        Node::text(ATTRIBUTE_NAME, name_of(tag))
    } else {
        Node::enumeration(ATTRIBUTE_REFERENCE, tag)
    }
}
fn change(v: Version, a: Node) -> Node {
    if v.0 == 1 {
        attribute(v, a)
    } else {
        Node::structure(NEW_ATTRIBUTE, vec![a])
    }
}
/// Every value of one attribute, retagged with the attribute's own tag.
fn values(f: &mut Fixture, v: Version, id: &str, tag: u32) -> Vec<Node> {
    let item = f.call(v, 11, vec![uid(id), selector(v, tag)]);
    let p = ok(&item);
    if v.0 == 1 {
        p.all(ATTRIBUTE)
            .map(|a| {
                let mut n = a.required(ATTRIBUTE_VALUE).unwrap().clone();
                n.tag = tag;
                n
            })
            .collect()
    } else {
        p.get(ATTRIBUTES)
            .map(|a| a.all(tag).cloned().collect())
            .unwrap_or_default()
    }
}
fn activate(f: &mut Fixture, v: Version, id: &str) {
    ok(&f.call(v, 18, vec![uid(id)]));
}
fn count(f: &mut Fixture, v: Version) -> usize {
    ok(&f.call(v, 8, vec![])).all(UNIQUE_IDENTIFIER).count()
}

fn rng(algorithm: u32) -> Node {
    Node::structure(
        RANDOM_NUMBER_GENERATOR,
        vec![Node::enumeration(RNG_ALGORITHM, algorithm)],
    )
}
/// The server's own generator: details undisclosed, so RNG Algorithm Unspecified.
fn unspecified() -> Node {
    rng(1)
}
/// A generator the server does not offer: RNG Algorithm DRBG with Hash DRBG.
fn drbg() -> Node {
    Node::structure(
        RANDOM_NUMBER_GENERATOR,
        vec![
            Node::enumeration(RNG_ALGORITHM, 3),
            Node::enumeration(DRBG_ALGORITHM, 2),
        ],
    )
}
fn aes(extra: Vec<Node>) -> Vec<Node> {
    let mut a = vec![
        Node::enumeration(CRYPTOGRAPHIC_ALGORITHM, 3),
        Node::int(CRYPTOGRAPHIC_LENGTH, 256),
        Node::int(CRYPTOGRAPHIC_USAGE_MASK, 12),
    ];
    a.extend(extra);
    a
}
fn create(v: Version, extra: Vec<Node>) -> Vec<Node> {
    vec![Node::enumeration(OBJECT_TYPE, 2), container(v, aes(extra))]
}
fn create_pair(v: Version, common_extra: Vec<Node>) -> Vec<Node> {
    let mut common = vec![
        Node::enumeration(CRYPTOGRAPHIC_ALGORITHM, 4),
        Node::int(CRYPTOGRAPHIC_LENGTH, 2048),
    ];
    common.extend(common_extra);
    vec![
        container_as(v, COMMON_TEMPLATE_ATTRIBUTE, COMMON_ATTRIBUTES, common),
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
fn pair_ids(item: &Node) -> (String, String) {
    let p = ok(item);
    (
        text(p, PRIVATE_KEY_UNIQUE_IDENTIFIER),
        text(p, PUBLIC_KEY_UNIQUE_IDENTIFIER),
    )
}
fn rekey(v: Version, id: &str, extra: Vec<Node>) -> Vec<Node> {
    let mut fields = vec![uid(id)];
    if !extra.is_empty() {
        fields.push(container(v, extra));
    }
    fields
}
fn rekey_pair(v: Version, private: &str, extra: Vec<Node>) -> Vec<Node> {
    let mut fields = vec![Node::text(PRIVATE_KEY_UNIQUE_IDENTIFIER, private)];
    if !extra.is_empty() {
        fields.push(container_as(
            v,
            COMMON_TEMPLATE_ATTRIBUTE,
            COMMON_ATTRIBUTES,
            extra,
        ));
    }
    fields
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
/// An active AES key with the Derive Key usage bit (ENCRYPT derivation source).
fn derivation_source(f: &mut Fixture, v: Version) -> String {
    let attrs = vec![
        Node::int(CRYPTOGRAPHIC_USAGE_MASK, 512),
        Node::structure(
            CRYPTOGRAPHIC_PARAMETERS,
            vec![Node::enumeration(BLOCK_CIPHER_MODE, 2)],
        ),
    ];
    let item = f.call(
        v,
        3,
        vec![
            Node::enumeration(OBJECT_TYPE, 2),
            container(v, attrs),
            symmetric_key(&[9; 32]),
        ],
    );
    let id = id_of(&item);
    activate(f, v, &id);
    id
}
fn derive(v: Version, source: &str, extra: Vec<Node>) -> Vec<Node> {
    let mut attrs = vec![
        Node::int(CRYPTOGRAPHIC_USAGE_MASK, 12),
        Node::int(CRYPTOGRAPHIC_LENGTH, 128),
        Node::enumeration(CRYPTOGRAPHIC_ALGORITHM, 3),
    ];
    attrs.extend(extra);
    vec![
        Node::enumeration(OBJECT_TYPE, 2),
        uid(source),
        Node::enumeration(DERIVATION_METHOD, 4),
        Node::structure(
            DERIVATION_PARAMETERS,
            vec![
                Node::structure(
                    CRYPTOGRAPHIC_PARAMETERS,
                    vec![Node::enumeration(BLOCK_CIPHER_MODE, 2)],
                ),
                Node::bytes(DERIVATION_DATA, vec![1; 16]),
            ],
        ),
        container(v, attrs),
    ]
}

/// Run one generating operation with the given extra RNG attributes and return
/// the identifiers of the objects it created (or the failed item).
fn generate(f: &mut Fixture, v: Version, op: u32, rngs: Vec<Node>) -> Result<Vec<String>, Node> {
    let fields = match op {
        1 => create(v, rngs),
        2 => create_pair(v, rngs),
        4 => {
            let id = id_of(&f.call(v, 1, create(v, vec![])));
            rekey(v, &id, rngs)
        }
        29 => {
            let (private, _) = pair_ids(&f.call(v, 2, create_pair(v, vec![])));
            rekey_pair(v, &private, rngs)
        }
        5 => {
            let source = derivation_source(f, v);
            derive(v, &source, rngs)
        }
        _ => unreachable!(),
    };
    let item = f.call(v, op, fields);
    if status(&item) != 0 {
        return Err(item);
    }
    let p = ok(&item);
    Ok(if [2, 29].contains(&op) {
        vec![
            text(p, PRIVATE_KEY_UNIQUE_IDENTIFIER),
            text(p, PUBLIC_KEY_UNIQUE_IDENTIFIER),
        ]
    } else {
        vec![text(p, UNIQUE_IDENTIFIER)]
    })
}

fn created(r: Result<Vec<String>, Node>) -> Vec<String> {
    r.unwrap_or_else(|item| {
        ok(&item);
        unreachable!()
    })
}

// REQ:aa4ee13f391392c4 objects the server generates get a Random Number Generator naming the generator used
// REQ:242ced210c982337 the server does not disclose its generator's details, so RNG Algorithm is Unspecified
// REQ:2480771706384eb3 1.3/1.4 a requested RNG in Create, Create Key Pair, Derive Key, Re-key or Re-key Key Pair must match the generator used
// REQ:ff42cc1eb1165358 2.x a requested RNG in Create, Create Key Pair, Derive Key, Re-key or Re-key Key Pair must match the generator used
// REQ:24c05403124e54a9 a requested RNG the server cannot use fails the request and creates nothing
#[test]
fn generated_objects_name_the_rng_used_and_requests_must_match_it() {
    for v in RNG_EDITIONS {
        for op in [1, 2, 4, 5, 29] {
            let mut f = Fixture::new();
            // No request: the server records its own (undisclosed) generator.
            for id in created(generate(&mut f, v, op, vec![])) {
                assert!(
                    values(&mut f, v, &id, RANDOM_NUMBER_GENERATOR) == [unspecified()],
                    "{} op {op}",
                    label(v)
                );
            }
            // A generator the server cannot use fails the request.
            let before = count(&mut f, v);
            let failed = generate(&mut f, v, op, vec![drbg()]).unwrap_err();
            assert_eq!(reason(&failed), 8, "{} op {op}", label(v));
            // Re-key and Re-key Key Pair created their source objects first.
            let sources = if [4, 29].contains(&op) {
                1 + usize::from(op == 29)
            } else {
                usize::from(op == 5)
            };
            assert_eq!(count(&mut f, v), before + sources, "{} op {op}", label(v));
            // One matching value among several is enough; that one is recorded.
            for id in created(generate(&mut f, v, op, vec![drbg(), unspecified()])) {
                assert!(
                    values(&mut f, v, &id, RANDOM_NUMBER_GENERATOR) == [unspecified()],
                    "{} op {op}",
                    label(v)
                );
            }
        }
    }
}

fn rsa_object(tag: u32, format: u32, der: Vec<u8>) -> Node {
    Node::structure(
        tag,
        vec![Node::structure(
            KEY_BLOCK,
            vec![
                Node::enumeration(KEY_FORMAT_TYPE, format),
                Node::structure(KEY_VALUE, vec![Node::bytes(KEY_MATERIAL, der)]),
                Node::enumeration(CRYPTOGRAPHIC_ALGORITHM, 4),
                Node::int(CRYPTOGRAPHIC_LENGTH, 2048),
            ],
        )],
    )
}
fn link(kind: u32, id: &str) -> Node {
    Node::structure(
        LINK,
        vec![
            Node::enumeration(LINK_TYPE, kind),
            Node::text(LINKED_OBJECT_IDENTIFIER, id),
        ],
    )
}
/// A registered RSA pair whose keys carry a client-supplied RNG and reciprocal links.
fn registered_pair(f: &mut Fixture, v: Version, rng: Node) -> (String, String) {
    let key = Rsa::generate(2048).unwrap();
    let public = id_of(&f.call(
        v,
        3,
        vec![
            Node::enumeration(OBJECT_TYPE, 3),
            container(v, vec![Node::int(CRYPTOGRAPHIC_USAGE_MASK, 2), rng.clone()]),
            rsa_object(PUBLIC_KEY, 3, key.public_key_to_der_pkcs1().unwrap()),
        ],
    ));
    let pkcs8 = PKey::from_rsa(key).unwrap().private_key_to_pkcs8().unwrap();
    let private = id_of(&f.call(
        v,
        3,
        vec![
            Node::enumeration(OBJECT_TYPE, 4),
            container(
                v,
                vec![
                    Node::int(CRYPTOGRAPHIC_USAGE_MASK, 1),
                    rng,
                    link(0x102, &public),
                ],
            ),
            rsa_object(PRIVATE_KEY, 4, pkcs8),
        ],
    ));
    ok(&f.call(v, 13, vec![uid(&public), change(v, link(0x103, &private))]));
    activate(f, v, &private);
    activate(f, v, &public);
    (private, public)
}

// REQ:28044d382d289728 Re-key and Re-key Key Pair do not copy the original's Random Number Generator
// REQ:ac172c94eb75ef25 once set, Random Number Generator is neither changed nor deleted
#[test]
fn rng_is_not_copied_on_rekey_and_never_changes_once_set() {
    for v in RNG_EDITIONS {
        let mut f = Fixture::new();
        // A registered key keeps the generator its client reported.
        let key = id_of(&f.call(
            v,
            3,
            vec![
                Node::enumeration(OBJECT_TYPE, 2),
                container(v, vec![Node::int(CRYPTOGRAPHIC_USAGE_MASK, 12), drbg()]),
                symmetric_key(&[5; 32]),
            ],
        ));
        assert!(values(&mut f, v, &key, RANDOM_NUMBER_GENERATOR) == [drbg()]);
        activate(&mut f, v, &key);
        let replacement = id_of(&f.call(v, 4, vec![uid(&key)]));
        assert!(values(&mut f, v, &replacement, RANDOM_NUMBER_GENERATOR) == [unspecified()]);

        let (private, public) = registered_pair(&mut f, v, drbg());
        let (new_private, new_public) = pair_ids(&f.call(v, 29, rekey_pair(v, &private, vec![])));
        for (old, new) in [(&private, &new_private), (&public, &new_public)] {
            assert!(values(&mut f, v, old, RANDOM_NUMBER_GENERATOR) == [drbg()]);
            assert!(values(&mut f, v, new, RANDOM_NUMBER_GENERATOR) == [unspecified()]);
        }

        // Neither a registered nor a generated value can be replaced, joined
        // by a second value, or removed.
        for (id, set) in [(&key, drbg()), (&replacement, unspecified())] {
            let other = if set == drbg() { unspecified() } else { drbg() };
            for op in [13, 14] {
                let item = f.call(v, op, vec![uid(id), change(v, other.clone())]);
                assert_eq!(status(&item), 1, "{} op {op}", label(v));
            }
            let item = f.call(v, 15, vec![uid(id), selector(v, RANDOM_NUMBER_GENERATOR)]);
            assert_eq!(status(&item), 1, "{}", label(v));
            assert!(values(&mut f, v, id, RANDOM_NUMBER_GENERATOR) == [set]);
        }
    }
}

fn key_pair_fields(
    common: Vec<Node>,
    private: Vec<Node>,
    public: Vec<Node>,
    v: Version,
) -> Vec<Node> {
    vec![
        container_as(v, COMMON_TEMPLATE_ATTRIBUTE, COMMON_ATTRIBUTES, common),
        container_as(
            v,
            PRIVATE_KEY_TEMPLATE_ATTRIBUTE,
            PRIVATE_KEY_ATTRIBUTES,
            private,
        ),
        container_as(
            v,
            PUBLIC_KEY_TEMPLATE_ATTRIBUTE,
            PUBLIC_KEY_ATTRIBUTES,
            public,
        ),
    ]
}
fn rsa_parameters(padding: u32) -> Node {
    Node::structure(
        CRYPTOGRAPHIC_PARAMETERS,
        vec![Node::enumeration(PADDING_METHOD, padding)],
    )
}
fn curve(curve: u32) -> Node {
    Node::structure(
        CRYPTOGRAPHIC_DOMAIN_PARAMETERS,
        vec![Node::enumeration(RECOMMENDED_CURVE, curve)],
    )
}

// REQ:0a656c8e802f08a4 1.0 Table 112: Create Key Pair needs Algorithm and Usage Mask; Algorithm, Length, Domain and Cryptographic Parameters agree
// REQ:0f411417414d17a9 1.1 Table 126: the same required and same-value attributes
// REQ:e753de8822341826 1.2 Table 141: the same required and same-value attributes
// REQ:685595773f1cd153 1.3 Table 152: the same required and same-value attributes
// REQ:472625d89ff70469 1.4 Table 168: the same required and same-value attributes
// REQ:710cf28acee31f2d 2.0 Table 176: Algorithm, Length, Domain and Cryptographic Parameters agree
// REQ:868a7f03a7a879aa 2.1 Table 191: Algorithm, Length, Domain and Cryptographic Parameters agree
#[test]
fn create_key_pair_tables_require_and_share_their_attributes() {
    let algorithm = |a| Node::enumeration(CRYPTOGRAPHIC_ALGORITHM, a);
    let length = |l| Node::int(CRYPTOGRAPHIC_LENGTH, l);
    let mask = |m| Node::int(CRYPTOGRAPHIC_USAGE_MASK, m);
    for v in LEGACY.into_iter().chain([Version(2, 0), Version(2, 1)]) {
        let mut f = Fixture::new();
        if v.0 == 1 {
            // REQUIRED: Cryptographic Algorithm and Cryptographic Usage Mask,
            // each somewhere in the request (as in requirement_clauses.rs).
            for (common, private, public) in [
                (vec![length(2048)], vec![mask(1)], vec![mask(2)]),
                (vec![algorithm(4), length(2048)], vec![], vec![]),
            ] {
                let item = f.call(v, 2, key_pair_fields(common, private, public, v));
                assert_eq!(reason(&item), 4, "{}", label(v));
            }
        }
        // Same value for both keys: a conflicting value fails the request.
        let rsa_common = || vec![algorithm(4), length(2048)];
        for (private, public) in [
            (vec![algorithm(4)], vec![algorithm(6)]),
            (vec![length(2048)], vec![length(3072)]),
            (vec![rsa_parameters(1)], vec![rsa_parameters(8)]),
        ] {
            let mut p = vec![mask(1)];
            p.extend(private);
            let mut q = vec![mask(2)];
            q.extend(public);
            let item = f.call(v, 2, key_pair_fields(rsa_common(), p.clone(), q, v));
            assert_eq!(status(&item), 1, "{} {:#x}", label(v), p[1].tag);
        }
        let ec_common = || vec![algorithm(6), length(256)];
        let item = f.call(
            v,
            2,
            key_pair_fields(
                ec_common(),
                vec![mask(1), curve(7)],
                vec![mask(2), curve(10)],
                v,
            ),
        );
        assert_eq!(status(&item), 1, "{}", label(v));
        // Given once (in common or for one key only), both keys carry it.
        for (common, private) in [
            (vec![rsa_parameters(1)], vec![]),
            (vec![], vec![rsa_parameters(1)]),
        ] {
            let mut c = rsa_common();
            c.extend(common);
            let mut p = vec![mask(1)];
            p.extend(private);
            let (private, public) =
                pair_ids(&f.call(v, 2, key_pair_fields(c, p, vec![mask(2)], v)));
            for tag in [
                CRYPTOGRAPHIC_ALGORITHM,
                CRYPTOGRAPHIC_LENGTH,
                CRYPTOGRAPHIC_PARAMETERS,
            ] {
                let a = values(&mut f, v, &private, tag);
                assert!(!a.is_empty(), "{} {tag:#x}", label(v));
                assert!(
                    a == values(&mut f, v, &public, tag),
                    "{} {tag:#x}",
                    label(v)
                );
            }
        }
        let mut common = ec_common();
        common.push(curve(7));
        let (private, public) = pair_ids(&f.call(
            v,
            2,
            key_pair_fields(common, vec![mask(1)], vec![mask(2)], v),
        ));
        for tag in [
            CRYPTOGRAPHIC_ALGORITHM,
            CRYPTOGRAPHIC_LENGTH,
            CRYPTOGRAPHIC_DOMAIN_PARAMETERS,
        ] {
            let a = values(&mut f, v, &private, tag);
            assert!(!a.is_empty(), "{} {tag:#x}", label(v));
            assert!(
                a == values(&mut f, v, &public, tag),
                "{} {tag:#x}",
                label(v)
            );
        }
    }
}
