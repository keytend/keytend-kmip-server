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

//! Focused tests for the attribute, object, lifecycle and key-block clauses
//! of the requirement matrix. Each asserting test names the clause digests it
//! checks as `REQ:<digest>` (see docs/specs/requirement-matrix.json);
//! the paraphrases are our own words.
use keytend_kmip_server::{
    protocol::{Engine, Version},
    store::{Store, now},
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
    /// One operation as `owner`; returns its response Batch Item.
    fn call_as(&mut self, owner: &str, v: Version, op: u32, fields: Vec<Node>) -> Node {
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
        let response = self.engine.process(owner, &request).unwrap();
        response.required(BATCH_ITEM).unwrap().clone()
    }
    fn call(&mut self, v: Version, op: u32, fields: Vec<Node>) -> Node {
        self.call_as("alice", v, op, fields)
    }
}

fn label(v: Version) -> String {
    format!("{}.{}", v.0, v.1)
}
fn ok(item: &Node) -> &Node {
    assert_eq!(
        item.required(RESULT_STATUS).unwrap().number().unwrap(),
        0,
        "reason {:?} {:?}",
        item.get(RESULT_REASON).map(|n| n.number()),
        item.get(RESULT_MESSAGE).map(|n| n.string())
    );
    item.required(RESPONSE_PAYLOAD).unwrap()
}
fn failed(item: &Node) -> bool {
    item.required(RESULT_STATUS).unwrap().number().unwrap() == 1
}
fn reason(item: &Node) -> u32 {
    assert!(failed(item), "expected a failure");
    item.required(RESULT_REASON).unwrap().number().unwrap()
}
fn id_of(item: &Node) -> String {
    ok(item)
        .required(UNIQUE_IDENTIFIER)
        .unwrap()
        .identifier_text()
        .unwrap()
        .to_owned()
}
fn uid(id: &str) -> Node {
    Node::text(UNIQUE_IDENTIFIER, id)
}
/// The KMIP 1.x attribute name of a standard attribute tag.
fn name_of(tag: u32) -> &'static str {
    match tag {
        CRYPTOGRAPHIC_ALGORITHM => "Cryptographic Algorithm",
        CRYPTOGRAPHIC_LENGTH => "Cryptographic Length",
        CRYPTOGRAPHIC_USAGE_MASK => "Cryptographic Usage Mask",
        APPLICATION_SPECIFIC_INFORMATION => "Application Specific Information",
        t => tag_name(t).unwrap(),
    }
}
fn legacy(name: &str, mut value: Node, index: Option<i32>) -> Node {
    value.tag = ATTRIBUTE_VALUE;
    let mut fields = vec![Node::text(ATTRIBUTE_NAME, name)];
    if let Some(i) = index {
        fields.push(Node::int(ATTRIBUTE_INDEX, i));
    }
    fields.push(value);
    Node::structure(ATTRIBUTE, fields)
}
/// Template-Attribute (1.x) or Attributes (2.x) for an operation that creates an object.
fn container(v: Version, attrs: Vec<Node>) -> Node {
    if v.0 >= 2 {
        Node::structure(ATTRIBUTES, attrs)
    } else {
        Node::structure(
            TEMPLATE_ATTRIBUTE,
            attrs
                .into_iter()
                .map(|a| legacy(name_of(a.tag), a, None))
                .collect(),
        )
    }
}
fn selector(v: Version, tag: u32) -> Node {
    if v.0 == 1 {
        Node::text(ATTRIBUTE_NAME, name_of(tag))
    } else {
        Node::enumeration(ATTRIBUTE_REFERENCE, tag)
    }
}
/// The attribute argument of Add or Modify Attribute.
fn change(v: Version, a: Node) -> Node {
    if v.0 == 1 {
        legacy(name_of(a.tag), a, None)
    } else {
        Node::structure(NEW_ATTRIBUTE, vec![a])
    }
}
fn add(f: &mut Fixture, v: Version, id: &str, a: Node) -> Node {
    f.call(v, 13, vec![uid(id), change(v, a)])
}
fn modify(f: &mut Fixture, v: Version, id: &str, a: Node) -> Node {
    f.call(v, 14, vec![uid(id), change(v, a)])
}
fn delete(f: &mut Fixture, v: Version, id: &str, tag: u32) -> Node {
    f.call(v, 15, vec![uid(id), selector(v, tag)])
}
/// Every value of one attribute, retagged with the attribute's own tag.
fn values_as(f: &mut Fixture, owner: &str, v: Version, id: &str, tag: u32) -> Vec<Node> {
    let item = f.call_as(owner, v, 11, vec![uid(id), selector(v, tag)]);
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
fn values(f: &mut Fixture, v: Version, id: &str, tag: u32) -> Vec<Node> {
    values_as(f, "alice", v, id, tag)
}
fn value(f: &mut Fixture, v: Version, id: &str, tag: u32) -> Option<Node> {
    let mut all = values(f, v, id, tag);
    assert!(all.len() <= 1, "{} has several values", name_of(tag));
    all.pop()
}
/// Every attribute of an object as (tag, value) pairs, in response order.
fn all_attributes(f: &mut Fixture, owner: &str, v: Version, id: &str) -> Vec<Node> {
    let item = f.call_as(owner, v, 11, vec![uid(id)]);
    let p = ok(&item);
    if v.0 == 1 {
        p.all(ATTRIBUTE)
            .map(|a| {
                let name = a.required(ATTRIBUTE_NAME).unwrap().string().unwrap();
                let mut n = a.required(ATTRIBUTE_VALUE).unwrap().clone();
                n.tag = (0x420000..0x420200)
                    .find(|t| tag_name(*t).is_some() && name_of(*t) == name)
                    .unwrap_or(CUSTOM_ATTRIBUTE);
                n
            })
            .collect()
    } else {
        p.required(ATTRIBUTES).unwrap().children().unwrap().to_vec()
    }
}
fn date(n: &Node) -> i64 {
    match n.value {
        Value::DateTime(t) => t,
        _ => panic!("not a Date-Time"),
    }
}
fn state(f: &mut Fixture, v: Version, id: &str) -> u32 {
    value(f, v, id, STATE).unwrap().number().unwrap()
}
fn aes(v: Version, mask: i32, extra: Vec<Node>) -> Vec<Node> {
    let mut a = vec![
        Node::enumeration(CRYPTOGRAPHIC_ALGORITHM, 3),
        Node::int(CRYPTOGRAPHIC_LENGTH, 128),
        Node::int(CRYPTOGRAPHIC_USAGE_MASK, mask),
    ];
    a.extend(extra);
    vec![Node::enumeration(OBJECT_TYPE, 2), container(v, a)]
}
/// A 128-bit AES key usable for Encrypt and Decrypt (mask 12).
fn create_aes(f: &mut Fixture, v: Version, extra: Vec<Node>) -> String {
    id_of(&f.call(v, 1, aes(v, 12, extra)))
}
fn symmetric_key(format: u32, material: Node) -> Node {
    Node::structure(
        SYMMETRIC_KEY,
        vec![Node::structure(
            KEY_BLOCK,
            vec![
                Node::enumeration(KEY_FORMAT_TYPE, format),
                Node::structure(KEY_VALUE, vec![material]),
                Node::enumeration(CRYPTOGRAPHIC_ALGORITHM, 3),
                Node::int(CRYPTOGRAPHIC_LENGTH, 128),
            ],
        )],
    )
}
fn register_aes(f: &mut Fixture, v: Version, key: [u8; 16], mask: i32, extra: Vec<Node>) -> String {
    let mut fields = aes(v, mask, extra);
    fields.push(symmetric_key(1, Node::bytes(KEY_MATERIAL, key.to_vec())));
    id_of(&f.call(v, 3, fields))
}
fn activate(f: &mut Fixture, v: Version, id: &str) {
    ok(&f.call(v, 18, vec![uid(id)]));
}
fn revoke(f: &mut Fixture, v: Version, id: &str, code: u32) -> Node {
    let mut fields = vec![
        uid(id),
        Node::structure(
            REVOCATION_REASON,
            vec![Node::enumeration(REVOCATION_REASON_CODE, code)],
        ),
    ];
    if code == 2 {
        fields.push(Node::date(COMPROMISE_OCCURRENCE_DATE, now() - 10));
    }
    f.call(v, 19, fields)
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
const IV: [u8; 16] = [9; 16];
fn encrypt(f: &mut Fixture, v: Version, id: &str) -> Node {
    f.call(
        v,
        31,
        vec![
            uid(id),
            cbc(),
            Node::bytes(DATA, b"sixteen byte msg".to_vec()),
            Node::bytes(IV_COUNTER_NONCE, IV.to_vec()),
        ],
    )
}
fn decrypt(f: &mut Fixture, v: Version, id: &str, data: &[u8]) -> Node {
    f.call(
        v,
        32,
        vec![
            uid(id),
            cbc(),
            Node::bytes(DATA, data.to_vec()),
            Node::bytes(IV_COUNTER_NONCE, IV.to_vec()),
        ],
    )
}
/// A registered AES key-encryption key (Wrap and Unwrap) with an RFC 5649
/// Cryptographic Parameters instance.
fn kek(f: &mut Fixture, v: Version, extra: Vec<Node>) -> String {
    let mut a = vec![Node::structure(
        CRYPTOGRAPHIC_PARAMETERS,
        vec![Node::enumeration(BLOCK_CIPHER_MODE, 12)],
    )];
    a.extend(extra);
    register_aes(f, v, [3; 16], 48, a)
}
fn wrapping(kek: &str, option: Option<u32>) -> Node {
    let mut fields = vec![
        Node::enumeration(WRAPPING_METHOD, 1),
        Node::structure(ENCRYPTION_KEY_INFORMATION, vec![uid(kek)]),
    ];
    if let Some(o) = option {
        fields.push(Node::enumeration(ENCODING_OPTION, o));
    }
    Node::structure(KEY_WRAPPING_SPECIFICATION, fields)
}
fn get_wrapped(f: &mut Fixture, v: Version, id: &str, kek: &str) -> Node {
    f.call(v, 10, vec![uid(id), wrapping(kek, None)])
}
fn key_block(item: &Node) -> Node {
    let p = ok(item);
    p.children()
        .unwrap()
        .iter()
        .find_map(|n| n.get(KEY_BLOCK))
        .unwrap()
        .clone()
}
fn int(n: &Node) -> i32 {
    match n.value {
        Value::Integer(i) => i,
        _ => panic!("not an Integer"),
    }
}
/// 1.x instances of one attribute as (Attribute Index, value) pairs.
fn indexed(f: &mut Fixture, v: Version, id: &str, name: &str) -> Vec<(i32, String)> {
    let item = f.call(v, 11, vec![uid(id), Node::text(ATTRIBUTE_NAME, name)]);
    ok(&item)
        .all(ATTRIBUTE)
        .map(|a| {
            (
                a.get(ATTRIBUTE_INDEX).map_or(0, int),
                a.required(ATTRIBUTE_VALUE)
                    .unwrap()
                    .string()
                    .unwrap()
                    .to_owned(),
            )
        })
        .collect()
}

// REQ:26b91a47c739003f 1.x the first instance of an attribute gets Attribute Index 0
// REQ:fbb8ba82c37e034c 1.x deleting one instance leaves the other instances' indices unchanged
// REQ:7777ca6079a3ca18 1.x a single-instance attribute lives at index 0 and no other index reaches it
// REQ:4c68816d2e67b1ad 1.x an Attribute without Attribute Index addresses instance 0
#[test]
fn legacy_attribute_indices_start_at_zero_and_stay_stable() {
    for v in LEGACY {
        let mut f = Fixture::new();
        let id = create_aes(&mut f, v, vec![]);
        let mut assigned = vec![];
        for g in ["g0", "g1", "g2"] {
            let r = add(&mut f, v, &id, Node::text(OBJECT_GROUP, g));
            assigned.push(int(ok(&r)
                .required(ATTRIBUTE)
                .unwrap()
                .required(ATTRIBUTE_INDEX)
                .unwrap()));
        }
        assert_eq!(assigned, [0, 1, 2], "{}", label(v));
        let group = |i: i32, s: &str| (i, s.to_owned());
        ok(&f.call(
            v,
            15,
            vec![
                uid(&id),
                Node::text(ATTRIBUTE_NAME, "Object Group"),
                Node::int(ATTRIBUTE_INDEX, 1),
            ],
        ));
        assert_eq!(
            indexed(&mut f, v, &id, "Object Group"),
            [group(0, "g0"), group(2, "g2")]
        );
        // No index: Modify and Delete act on instance 0.
        ok(&f.call(
            v,
            14,
            vec![
                uid(&id),
                legacy("Object Group", Node::text(OBJECT_GROUP, "g0b"), None),
            ],
        ));
        assert_eq!(
            indexed(&mut f, v, &id, "Object Group"),
            [group(0, "g0b"), group(2, "g2")]
        );
        // No index means index 0 in every edition (1.0 included; see
        // src/protocol/attributes.rs).
        let delete = vec![uid(&id), Node::text(ATTRIBUTE_NAME, "Object Group")];
        ok(&f.call(v, 15, delete));
        assert_eq!(indexed(&mut f, v, &id, "Object Group"), [group(2, "g2")]);
        // Single-instance attributes: index 0 (or no index, meaning 0) only.
        let r = f.call(
            v,
            11,
            vec![uid(&id), Node::text(ATTRIBUTE_NAME, "Cryptographic Length")],
        );
        let a = ok(&r).required(ATTRIBUTE).unwrap();
        assert_eq!(a.get(ATTRIBUTE_INDEX).map_or(0, int), 0);
        ok(&add(&mut f, v, &id, Node::text(CONTACT_INFORMATION, "ops")));
        let at = |i: i32, s: &str| {
            vec![
                uid(&id),
                legacy("Contact Information", Node::text(0, s), Some(i)),
            ]
        };
        assert!(failed(&f.call(v, 14, at(1, "elsewhere"))));
        ok(&f.call(v, 14, at(0, "on-call")));
        assert_eq!(
            indexed(&mut f, v, &id, "Contact Information"),
            [group(0, "on-call")]
        );
    }
}

// REQ:d9cb12a5013c53ae a wrapped key's Key Block carries a Key Wrapping Data structure
// REQ:978231a58a5172af 1.0/1.1 Key Wrapping Data appears only when the key is wrapped
// REQ:d50b7405a1e4b0e5 1.2+ Key Wrapping Data appears only when the key is wrapped
// REQ:c234be13eb0315c1 1.0/1.1 returned Key Wrapping Data names the encryption key; data naming no key is refused
// REQ:41feeb51688ebdec 1.2+ returned Key Wrapping Data names the encryption key; data naming no key is refused
// REQ:d94b0beb98ccfe47 1.x an IV appears in Key Wrapping Data only when the method needs one (AES key wrap does not)
// REQ:e73e2d82a4a1bb70 2.x an IV appears in Key Wrapping Data only when the method needs one (AES key wrap does not)
#[test]
fn wrapped_key_blocks_carry_key_wrapping_data_only_when_wrapped() {
    for v in FINAL {
        let mut f = Fixture::new();
        let target = create_aes(&mut f, v, vec![]);
        let k = kek(&mut f, v, vec![]);
        activate(&mut f, v, &k);
        let plain = key_block(&f.call(v, 10, vec![uid(&target)]));
        assert!(plain.get(KEY_WRAPPING_DATA).is_none(), "{}", label(v));
        let wrapped = key_block(&get_wrapped(&mut f, v, &target, &k));
        let data = wrapped.required(KEY_WRAPPING_DATA).unwrap();
        assert_eq!(data.required(WRAPPING_METHOD).unwrap().number().unwrap(), 1);
        assert_eq!(
            data.required(ENCRYPTION_KEY_INFORMATION)
                .unwrap()
                .required(UNIQUE_IDENTIFIER)
                .unwrap()
                .identifier_text()
                .unwrap(),
            k
        );
        assert!(data.get(MAC_SIGNATURE_KEY_INFORMATION).is_none());
        assert!(data.get(IV_COUNTER_NONCE).is_none());
        // Registering the wrapped key works; without any key information it is refused.
        let register = |kb: Node| {
            let mut fields = aes(v, 12, vec![]);
            fields.push(Node::structure(SYMMETRIC_KEY, vec![kb]));
            fields
        };
        ok(&f.call(v, 3, register(wrapped.clone())));
        let mut keyless = wrapped.clone();
        if let Value::Structure(fields) = &mut keyless.value {
            for n in fields.iter_mut() {
                if n.tag == KEY_WRAPPING_DATA
                    && let Value::Structure(inner) = &mut n.value
                {
                    inner.retain(|n| n.tag != ENCRYPTION_KEY_INFORMATION);
                }
            }
        }
        let before = f.engine.store.list("alice").unwrap().len();
        assert!(failed(&f.call(v, 3, register(keyless))), "{}", label(v));
        assert_eq!(f.engine.store.list("alice").unwrap().len(), before);
    }
}

fn rsa_pair(f: &mut Fixture, v: Version) -> (String, String) {
    let common = vec![
        Node::enumeration(CRYPTOGRAPHIC_ALGORITHM, 4),
        Node::int(CRYPTOGRAPHIC_LENGTH, 2048),
    ];
    let mask = |m: i32| vec![Node::int(CRYPTOGRAPHIC_USAGE_MASK, m)];
    let fields = if v.0 >= 2 {
        vec![
            Node::structure(COMMON_ATTRIBUTES, common),
            Node::structure(PRIVATE_KEY_ATTRIBUTES, mask(1)),
            Node::structure(PUBLIC_KEY_ATTRIBUTES, mask(2)),
        ]
    } else {
        let t = |tag: u32, a: Vec<Node>| {
            Node::structure(
                tag,
                a.into_iter()
                    .map(|a| legacy(name_of(a.tag), a, None))
                    .collect(),
            )
        };
        vec![
            t(COMMON_TEMPLATE_ATTRIBUTE, common),
            t(PRIVATE_KEY_TEMPLATE_ATTRIBUTE, mask(1)),
            t(PUBLIC_KEY_TEMPLATE_ATTRIBUTE, mask(2)),
        ]
    };
    let r = f.call(v, 2, fields);
    let p = ok(&r);
    let text = |tag| {
        p.required(tag)
            .unwrap()
            .identifier_text()
            .unwrap()
            .to_owned()
    };
    (
        text(PRIVATE_KEY_UNIQUE_IDENTIFIER),
        text(PUBLIC_KEY_UNIQUE_IDENTIFIER),
    )
}
fn secret_data(material: &[u8]) -> Node {
    Node::structure(
        SECRET_DATA,
        vec![
            Node::enumeration(SECRET_DATA_TYPE, 1),
            Node::structure(
                KEY_BLOCK,
                vec![
                    Node::enumeration(KEY_FORMAT_TYPE, 1),
                    Node::structure(
                        KEY_VALUE,
                        vec![Node::bytes(KEY_MATERIAL, material.to_vec())],
                    ),
                ],
            ),
        ],
    )
}
fn register_secret(f: &mut Fixture, v: Version, extra: Vec<Node>) -> String {
    let mut a = vec![Node::int(CRYPTOGRAPHIC_USAGE_MASK, 0x80)];
    a.extend(extra);
    id_of(&f.call(
        v,
        3,
        vec![
            Node::enumeration(OBJECT_TYPE, 7),
            container(v, a),
            secret_data(b"sixteen secret b"),
        ],
    ))
}

// REQ:5d0372596de2c7d2 1.x a Key Block that names its Cryptographic Algorithm also gives its Cryptographic Length
// REQ:d2f12948c10fd2b4 2.x keys pair Cryptographic Algorithm with Cryptographic Length in the Key Block
// REQ:f0516c67a31ce585 a Key Block with a Cryptographic Length also names its Cryptographic Algorithm (keys and Secret Data)
// REQ:697b1808433e0dd0 a Transparent RSA Private Key carries the modulus with the private exponent or the full CRT set
#[test]
fn key_blocks_give_a_length_with_any_algorithm_and_rsa_transparent_keys_are_complete() {
    for v in FINAL {
        let mut f = Fixture::new();
        let sym = create_aes(&mut f, v, vec![]);
        let (private, public) = rsa_pair(&mut f, v);
        let secret = register_secret(&mut f, v, vec![]);
        for (id, keyed) in [
            (&sym, true),
            (&private, true),
            (&public, true),
            (&secret, false),
        ] {
            let kb = key_block(&f.call(v, 10, vec![uid(id)]));
            let algorithm = kb.get(CRYPTOGRAPHIC_ALGORITHM).is_some();
            let length = kb.get(CRYPTOGRAPHIC_LENGTH).is_some();
            assert!(!algorithm || length, "{}", label(v));
            // Secret Data has no algorithm, so its Key Block has no length either.
            assert!(!length || algorithm, "{}", label(v));
            assert_eq!(algorithm && length, keyed, "{}", label(v));
        }
        let kb = key_block(&f.call(
            v,
            10,
            vec![uid(&private), Node::enumeration(KEY_FORMAT_TYPE, 10)],
        ));
        let km = kb
            .required(KEY_VALUE)
            .unwrap()
            .required(KEY_MATERIAL)
            .unwrap();
        assert!(km.get(MODULUS).is_some());
        let crt = [P, Q, PRIME_EXPONENT_P, PRIME_EXPONENT_Q, CRT_COEFFICIENT];
        assert!(
            km.get(PRIVATE_EXPONENT).is_some() || crt.iter().all(|t| km.get(*t).is_some()),
            "{}",
            label(v)
        );
    }
}

fn split_share(method: u32, part: i32, prime: bool) -> Node {
    let mut fields = vec![
        Node::int(SPLIT_KEY_PARTS, 3),
        Node::int(KEY_PART_IDENTIFIER, part),
        Node::int(SPLIT_KEY_THRESHOLD, if method == 1 { 3 } else { 2 }),
        Node::enumeration(SPLIT_KEY_METHOD, method),
    ];
    if prime {
        fields.push(Node {
            tag: PRIME_FIELD_SIZE,
            value: Value::BigInteger(vec![0, 0, 0, 0, 0, 0, 1, 1]),
        });
    }
    let material = if method == 3 {
        vec![0, 254]
    } else {
        vec![0x66; 16]
    };
    fields.push(Node::structure(
        KEY_BLOCK,
        vec![
            Node::enumeration(KEY_FORMAT_TYPE, 1),
            Node::structure(KEY_VALUE, vec![Node::bytes(KEY_MATERIAL, material)]),
        ],
    ));
    Node::structure(SPLIT_KEY, fields)
}

// REQ:347bf8dcaf67198f a Key Part Identifier outside 1..=Split Key Parts is refused
// REQ:157ca4b2200d6304 Prime Field Size is required for prime-field polynomial sharing and refused otherwise
#[test]
fn split_key_part_identifiers_and_prime_field_sizes_are_validated() {
    for v in FINAL {
        let mut f = Fixture::new();
        let mut register = |share: Node| {
            f.call(
                v,
                3,
                vec![
                    Node::enumeration(OBJECT_TYPE, 5),
                    container(v, vec![]),
                    share,
                ],
            )
        };
        for part in 1..=3 {
            ok(&register(split_share(2, part, false)));
        }
        for part in [0, 4, -1] {
            assert!(
                failed(&register(split_share(2, part, false))),
                "{}",
                label(v)
            );
        }
        ok(&register(split_share(3, 2, true)));
        assert!(failed(&register(split_share(3, 2, false))));
        assert!(failed(&register(split_share(2, 2, true))));
        assert!(failed(&register(split_share(1, 2, true))));
    }
}

fn register_opaque(f: &mut Fixture, v: Version) -> String {
    id_of(&f.call(
        v,
        3,
        vec![
            Node::enumeration(OBJECT_TYPE, 8),
            container(v, vec![]),
            Node::structure(
                OPAQUE_OBJECT,
                vec![
                    Node::enumeration(OPAQUE_DATA_TYPE, 0x8000_0001),
                    Node::bytes(OPAQUE_DATA_VALUE, b"opaque bytes".to_vec()),
                ],
            ),
        ],
    ))
}
/// A client attempt to add, modify and delete `a` must fail and leave it unchanged.
fn refuse_changes(f: &mut Fixture, v: Version, id: &str, a: Node) {
    let before = values(f, v, id, a.tag);
    for item in [
        add(f, v, id, a.clone()),
        modify(f, v, id, a.clone()),
        delete(f, v, id, a.tag),
    ] {
        assert!(failed(&item), "{} {}", label(v), name_of(a.tag));
    }
    if v.0 >= 2 {
        assert!(failed(&f.call(v, 49, vec![uid(id), change(v, a.clone())])));
    }
    assert!(
        values(f, v, id, a.tag) == before,
        "{} {}",
        label(v),
        name_of(a.tag)
    );
}

// REQ:29dad0a5618df012 read-only attributes can be neither modified nor deleted by a client
// REQ:ecd61046a1102e0f the Unique Identifier is assigned at creation and cannot be changed or deleted
// REQ:db1c45de7969885b 1.0/1.1 the Object Type is set by the server and cannot be changed or deleted
// REQ:5a9bebd3f8701ec9 1.2+ the Object Type is set by the server and cannot be changed or deleted
// REQ:18e6834cb69b8b9a Cryptographic Algorithm is fixed at creation (Digital Signature Algorithm: see the certificate test)
// REQ:4e67752ca0360a30 Cryptographic Length and Initial Date are fixed at creation
// REQ:626a7aabd1d883cd Modify Attribute cannot change State
// REQ:878da69decb9155b 1.0/1.1 State is changed only by the server, as part of operations
// REQ:3783a19884d0fac3 1.2+ State is changed only by the server, as part of operations
// REQ:94922d85f3e9f3b5 clients can neither set nor change Lease Time
// REQ:5647b7a311dec572 clients can neither set nor change Key Value Present
// REQ:d4023c30e64c013e once set, Original Creation Date is neither deleted nor changed
// REQ:5a346107cd413792 2.x the Opaque Data Type is set at registration and cannot be changed or deleted
// REQ:21493e0c82acb931 the server keeps every attribute through other operations until a client deletes it
#[test]
fn server_set_attributes_are_read_only_to_clients_and_kept_by_the_server() {
    let t = now() - 1000;
    for v in FINAL {
        let mut f = Fixture::new();
        let id = create_aes(
            &mut f,
            v,
            vec![
                Node::text(CONTACT_INFORMATION, "ops"),
                Node::text(OBJECT_GROUP, "group"),
            ],
        );
        let before = all_attributes(&mut f, "alice", v, &id);
        let mut read_only = vec![
            Node::text(UNIQUE_IDENTIFIER, "other"),
            Node::enumeration(OBJECT_TYPE, 7),
            Node::enumeration(CRYPTOGRAPHIC_ALGORITHM, 2),
            Node::int(CRYPTOGRAPHIC_LENGTH, 256),
            Node::date(INITIAL_DATE, t),
            Node::enumeration(STATE, 2),
            Node::interval(LEASE_TIME, 10),
            Node::boolean(KEY_VALUE_PRESENT, true),
        ];
        if v >= Version(1, 2) {
            read_only.push(Node::date(ORIGINAL_CREATION_DATE, t));
        }
        for a in read_only {
            refuse_changes(&mut f, v, &id, a);
        }
        assert_eq!(state(&mut f, v, &id), 1);
        assert!(all_attributes(&mut f, "alice", v, &id) == before);
        // Server operations change State and dates, but drop nothing.
        activate(&mut f, v, &id);
        assert_eq!(state(&mut f, v, &id), 2);
        ok(&f.call(v, 10, vec![uid(&id)]));
        ok(&modify(
            &mut f,
            v,
            &id,
            Node::text(CONTACT_INFORMATION, "on-call"),
        ));
        let after = all_attributes(&mut f, "alice", v, &id);
        for a in &before {
            if [STATE, LAST_CHANGE_DATE, FRESH, CONTACT_INFORMATION].contains(&a.tag) {
                assert!(
                    after.iter().any(|b| b.tag == a.tag),
                    "{} {:x}",
                    label(v),
                    a.tag
                );
            } else {
                assert!(after.contains(a), "{} {:x}", label(v), a.tag);
            }
        }
        if v.0 >= 2 {
            let opaque = register_opaque(&mut f, v);
            assert_eq!(
                value(&mut f, v, &opaque, OPAQUE_DATA_TYPE)
                    .unwrap()
                    .number()
                    .unwrap(),
                0x8000_0001
            );
            refuse_changes(
                &mut f,
                v,
                &opaque,
                Node::enumeration(OPAQUE_DATA_TYPE, 0x8000_0002),
            );
        }
    }
}

struct Pki {
    der: Vec<u8>,
    subject: Vec<u8>,
    issuer: Vec<u8>,
}
/// An RSA leaf certificate (serial 7, SHA-256 with RSA) issued by a separate CA.
fn pki() -> Pki {
    use openssl::{
        asn1::Asn1Time,
        bn::BigNum,
        hash::MessageDigest,
        pkey::PKey,
        rsa::Rsa,
        x509::{X509, X509NameBuilder, extension::KeyUsage},
    };
    let name = |cn: &str| {
        let mut n = X509NameBuilder::new().unwrap();
        n.append_entry_by_text("CN", cn).unwrap();
        n.append_entry_by_text("O", "Example").unwrap();
        n.build()
    };
    let ca_key = PKey::from_rsa(Rsa::generate(2048).unwrap()).unwrap();
    let key = PKey::from_rsa(Rsa::generate(2048).unwrap()).unwrap();
    let mut b = X509::builder().unwrap();
    b.set_version(2).unwrap();
    b.set_serial_number(&BigNum::from_u32(7).unwrap().to_asn1_integer().unwrap())
        .unwrap();
    b.set_subject_name(&name("leaf")).unwrap();
    b.set_issuer_name(&name("issuing-ca")).unwrap();
    b.set_pubkey(&key).unwrap();
    b.set_not_before(&Asn1Time::days_from_now(0).unwrap())
        .unwrap();
    b.set_not_after(&Asn1Time::days_from_now(30).unwrap())
        .unwrap();
    b.append_extension(
        KeyUsage::new()
            .digital_signature()
            .key_encipherment()
            .build()
            .unwrap(),
    )
    .unwrap();
    b.sign(&ca_key, MessageDigest::sha256()).unwrap();
    let cert = b.build();
    Pki {
        der: cert.to_der().unwrap(),
        subject: cert.subject_name().to_der().unwrap(),
        issuer: cert.issuer_name().to_der().unwrap(),
    }
}
fn register_certificate(f: &mut Fixture, v: Version, p: &Pki) -> String {
    let attrs = if v >= Version(1, 1) {
        vec![
            Node::enumeration(CRYPTOGRAPHIC_ALGORITHM, 4),
            Node::int(CRYPTOGRAPHIC_LENGTH, 2048),
            Node::int(CERTIFICATE_LENGTH, p.der.len() as i32),
            Node::int(CRYPTOGRAPHIC_USAGE_MASK, 1 | 2 | 16 | 32),
        ]
    } else {
        vec![]
    };
    id_of(&f.call(
        v,
        3,
        vec![
            Node::enumeration(OBJECT_TYPE, 1),
            container(v, attrs),
            Node::structure(
                CERTIFICATE,
                vec![
                    Node::enumeration(CERTIFICATE_TYPE, 1),
                    Node::bytes(CERTIFICATE_VALUE, p.der.clone()),
                ],
            ),
        ],
    ))
}
fn text_field(n: &Node, tag: u32) -> String {
    n.required(tag).unwrap().string().unwrap().to_owned()
}
fn bytes_field(n: &Node, tag: u32) -> Vec<u8> {
    n.required(tag).unwrap().byte_string().unwrap().to_vec()
}

// REQ:5e9983cf3a7c6138 Certificate Type is taken from the registered certificate and cannot be changed or deleted
// REQ:dc689e5e2fd5287b 1.x Certificate Identifier (issuer and serial) is set from the certificate and fixed
// REQ:97d5bebfc942a1c6 1.x Certificate Subject is extracted from the registered certificate
// REQ:a4c17ea01ed4ab5c 1.x Certificate Issuer is extracted from the registered certificate
// REQ:8b4b51899af88ee3 certificate issuer attributes cannot be changed or deleted
// REQ:bd026cf1a8898d67 Certificate Length is the DER length, set by the server and fixed
// REQ:fa5dd3e085631eea X.509 Certificate Identifier (issuer DN and serial) is set from the certificate and fixed
// REQ:cfc0bf94ad747ae5 X.509 Certificate Subject is the subject DN extracted from the certificate
// REQ:2b56a3af385803f7 X.509 Certificate Issuer is the issuer DN extracted from the certificate
// REQ:18e6834cb69b8b9a Digital Signature Algorithm is extracted from the certificate and fixed
#[test]
fn certificate_attributes_are_extracted_from_the_certificate_and_read_only() {
    let p = pki();
    for v in FINAL {
        let mut f = Fixture::new();
        let id = register_certificate(&mut f, v, &p);
        let ty = value(&mut f, v, &id, CERTIFICATE_TYPE).unwrap();
        assert_eq!(ty.number().unwrap(), 1);
        refuse_changes(&mut f, v, &id, Node::enumeration(CERTIFICATE_TYPE, 2));
        if v.0 == 1 {
            let ident = value(&mut f, v, &id, CERTIFICATE_IDENTIFIER).unwrap();
            assert!(text_field(&ident, ISSUER).contains("CN=issuing-ca"));
            assert_eq!(text_field(&ident, SERIAL_NUMBER), "7");
            let subject = value(&mut f, v, &id, CERTIFICATE_SUBJECT).unwrap();
            let dn = text_field(&subject, CERTIFICATE_SUBJECT_DISTINGUISHED_NAME);
            assert!(dn.contains("CN=leaf") && !dn.contains("issuing-ca"), "{dn}");
            let issuer = value(&mut f, v, &id, CERTIFICATE_ISSUER).unwrap();
            let dn = text_field(&issuer, CERTIFICATE_ISSUER_DISTINGUISHED_NAME);
            assert!(dn.contains("CN=issuing-ca"), "{dn}");
            for a in [ident, subject, issuer] {
                refuse_changes(&mut f, v, &id, a);
            }
        }
        if v >= Version(1, 1) {
            let length = value(&mut f, v, &id, CERTIFICATE_LENGTH).unwrap();
            assert_eq!(int(&length), p.der.len() as i32);
            refuse_changes(&mut f, v, &id, Node::int(CERTIFICATE_LENGTH, 1));
            let ident = value(&mut f, v, &id, X_509_CERTIFICATE_IDENTIFIER).unwrap();
            assert_eq!(bytes_field(&ident, ISSUER_DISTINGUISHED_NAME), p.issuer);
            assert!(bytes_field(&ident, CERTIFICATE_SERIAL_NUMBER).ends_with(&[7]));
            let subject = value(&mut f, v, &id, X_509_CERTIFICATE_SUBJECT).unwrap();
            assert_eq!(bytes_field(&subject, SUBJECT_DISTINGUISHED_NAME), p.subject);
            let issuer = value(&mut f, v, &id, X_509_CERTIFICATE_ISSUER).unwrap();
            assert_eq!(bytes_field(&issuer, ISSUER_DISTINGUISHED_NAME), p.issuer);
            for a in [ident, subject, issuer] {
                refuse_changes(&mut f, v, &id, a);
            }
            let signature = value(&mut f, v, &id, DIGITAL_SIGNATURE_ALGORITHM).unwrap();
            assert_eq!(signature.number().unwrap(), 5, "SHA-256 with RSA");
            refuse_changes(
                &mut f,
                v,
                &id,
                Node::enumeration(DIGITAL_SIGNATURE_ALGORITHM, 3),
            );
        }
    }
}

// REQ:eb53e59dd9bfe6c4 objects carry every always-present attribute of their type from creation on
// REQ:97d14cf72c1f6256 attributes the tables mark as always having a value are present on every applicable object
// REQ:253b20713b5945de 2.x a Create that omits Cryptographic Algorithm, Length and Usage Mask gets server values
#[test]
fn always_present_attributes_exist_on_every_object_type() {
    let p = pki();
    for v in FINAL {
        let mut f = Fixture::new();
        let mut objects = vec![
            ("symmetric", create_aes(&mut f, v, vec![])),
            ("secret", register_secret(&mut f, v, vec![])),
            ("certificate", register_certificate(&mut f, v, &p)),
        ];
        if v.0 >= 2 {
            let r = f.call(
                v,
                1,
                vec![Node::enumeration(OBJECT_TYPE, 2), container(v, vec![])],
            );
            objects.push(("defaulted", id_of(&r)));
        }
        let (private, public) = rsa_pair(&mut f, v);
        objects.push(("private", private));
        objects.push(("public", public));
        if v.0 >= 2 {
            let opaque = register_opaque(&mut f, v);
            for (tag, expected) in [(OPAQUE_DATA_TYPE, 0x8000_0001), (KEY_FORMAT_TYPE, 2)] {
                let found = value(&mut f, v, &opaque, tag).unwrap();
                assert_eq!(found.number().unwrap(), expected);
            }
            let certificate = &objects[2].1.clone();
            let found = value(&mut f, v, certificate, KEY_FORMAT_TYPE).unwrap();
            assert_eq!(found.number().unwrap(), 5, "X.509");
        }
        for (kind, id) in objects {
            let present: Vec<u32> = all_attributes(&mut f, "alice", v, &id)
                .iter()
                .map(|a| a.tag)
                .collect();
            let mut expected = vec![
                UNIQUE_IDENTIFIER,
                OBJECT_TYPE,
                STATE,
                INITIAL_DATE,
                LAST_CHANGE_DATE,
                DIGEST,
                CRYPTOGRAPHIC_USAGE_MASK,
                CRYPTOGRAPHIC_LENGTH,
            ];
            if kind != "secret" {
                expected.push(CRYPTOGRAPHIC_ALGORITHM);
            }
            if v >= Version(1, 4) {
                expected.extend([SENSITIVE, ALWAYS_SENSITIVE, EXTRACTABLE, NEVER_EXTRACTABLE]);
            }
            if v.0 >= 2 {
                expected.extend([FRESH, PROTECTION_STORAGE_MASK]);
                expected.push(KEY_FORMAT_TYPE);
            }
            if kind == "certificate" {
                expected.push(CERTIFICATE_TYPE);
                if v.0 == 1 {
                    expected.extend([
                        CERTIFICATE_IDENTIFIER,
                        CERTIFICATE_SUBJECT,
                        CERTIFICATE_ISSUER,
                    ]);
                }
                if v >= Version(1, 1) {
                    expected.extend([
                        CERTIFICATE_LENGTH,
                        DIGITAL_SIGNATURE_ALGORITHM,
                        X_509_CERTIFICATE_IDENTIFIER,
                        X_509_CERTIFICATE_SUBJECT,
                        X_509_CERTIFICATE_ISSUER,
                    ]);
                }
            }
            for tag in expected {
                assert!(
                    present.contains(&tag),
                    "{} {kind} lacks {}",
                    label(v),
                    name_of(tag)
                );
            }
        }
    }
}

// REQ:79cdc308cb248790 1.0/1.1 Unique Identifiers never repeat on the server (they are random UUIDs)
// REQ:b6c7970e3b048844 1.2-1.4 Unique Identifiers never repeat on the server (they are random UUIDs)
// REQ:8cd12c62c2c2b2f8 2.x Unique Identifiers never repeat on the server (they are random UUIDs)
#[test]
fn unique_identifiers_are_unique_across_owners_versions_and_operations() {
    let mut f = Fixture::new();
    let mut seen = std::collections::HashSet::new();
    for v in FINAL {
        for owner in ["alice", "bob"] {
            for _ in 0..10 {
                let r = f.call_as(owner, v, 1, aes(v, 12, vec![]));
                assert!(seen.insert(id_of(&r)));
            }
        }
        assert!(seen.insert(register_secret(&mut f, v, vec![])));
        let (private, public) = rsa_pair(&mut f, v);
        assert!(seen.insert(private) && seen.insert(public));
    }
    for id in &seen {
        let b = id.as_bytes();
        assert_eq!(b.len(), 36, "{id}");
        assert!([8, 13, 18, 23].iter().all(|&i| b[i] == b'-'), "{id}");
    }
}

fn digests(f: &mut Fixture, v: Version, id: &str) -> Vec<(u32, Vec<u8>, Option<u32>)> {
    values(f, v, id, DIGEST)
        .iter()
        .map(|d| {
            (
                d.required(HASHING_ALGORITHM).unwrap().number().unwrap(),
                bytes_field(d, DIGEST_VALUE),
                d.get(KEY_FORMAT_TYPE).map(|n| n.number().unwrap()),
            )
        })
        .collect()
}
fn sha256(data: &[u8]) -> Vec<u8> {
    openssl::sha::sha256(data).to_vec()
}

// REQ:c329c63439c3ea22 1.0 the Digest is computed with SHA-256
// REQ:64af056b54371d7d 1.1+ the mandatory Digest instance is computed with SHA-256
// REQ:482d38b45b2e0c19 the Digest is set when the object is created or registered
// REQ:c27641a2f1a52409 a Byte String Key Material is digested as those bytes
// REQ:76a6652f12542360 1.1-1.4 a structured Key Material is digested as its TTLV encoding
// REQ:e0915b5026949270 2.x a structured Key Material is digested as its TTLV encoding
// REQ:36b03a123c6bcde7 1.1-1.4 a registered object is digested in its registered Key Format Type
// REQ:b06920f7141a8106 2.x one SHA-256 Digest is in the default Key Format Type
// REQ:8f82e65f26ee2a30 2.x an object held in a non-default format is digested in that format and in the default
// REQ:b3f4430d41f1da93 2.x Create naming a non-default Key Format Type is failed (the 4.26 alternative), so no extra digest is owed
// REQ:25261b070111799d 2.x a requested Key Format Type is produced or the request fails
// REQ:ab317beafc62ec97 2.x keys are returned in their default Key Format Type when none is requested
#[test]
fn digests_use_sha256_over_the_registered_and_default_formats() {
    let structured = Node::structure(KEY_MATERIAL, vec![Node::bytes(KEY, vec![5; 16])]);
    for v in FINAL {
        let mut f = Fixture::new();
        let raw = register_aes(&mut f, v, [5; 16], 12, vec![]);
        let kft = |k: u32| if v >= Version(1, 1) { Some(k) } else { None };
        assert_eq!(digests(&mut f, v, &raw), [(6, sha256(&[5; 16]), kft(1))]);
        let created = create_aes(&mut f, v, vec![]);
        let material = f
            .engine
            .store
            .get("alice", &created)
            .unwrap()
            .unwrap()
            .material
            .clone();
        assert_eq!(
            digests(&mut f, v, &created),
            [(6, sha256(&material), kft(1))]
        );
        let mut fields = aes(v, 12, vec![]);
        fields.push(symmetric_key(7, structured.clone()));
        let transparent = id_of(&f.call(v, 3, fields));
        let found = digests(&mut f, v, &transparent);
        assert!(
            found.contains(&(6, sha256(&structured.encode()), kft(7))),
            "{}",
            label(v)
        );
        if v.0 >= 2 {
            assert!(found.contains(&(6, sha256(&[5; 16]), Some(1))));
            let mut fields = aes(v, 12, vec![Node::enumeration(KEY_FORMAT_TYPE, 7)]);
            fields.truncate(2);
            assert!(failed(&f.call(v, 1, fields)));
            // Defaults: Raw for symmetric keys and Secret Data.
            let secret = register_secret(&mut f, v, vec![]);
            for id in [&raw, &secret] {
                let kb = key_block(&f.call(v, 10, vec![uid(id)]));
                assert_eq!(kb.required(KEY_FORMAT_TYPE).unwrap().number().unwrap(), 1);
            }
            // A format the key cannot take fails with Key Format Type Not Supported.
            let r = f.call(
                v,
                10,
                vec![uid(&raw), Node::enumeration(KEY_FORMAT_TYPE, 3)],
            );
            assert_eq!(reason(&r), 0x10);
            let r = f.call(
                v,
                10,
                vec![uid(&raw), Node::enumeration(KEY_FORMAT_TYPE, 1)],
            );
            let kb = key_block(&r);
            assert_eq!(kb.required(KEY_FORMAT_TYPE).unwrap().number().unwrap(), 1);
            assert_eq!(
                bytes_field(kb.required(KEY_VALUE).unwrap(), KEY_MATERIAL),
                [5; 16]
            );
        }
    }
}

// REQ:35ff9461bfe562bd clients can neither add nor change a 'y-' attribute
// REQ:dcbf278a73694cff custom attribute names must start with 'x-' or 'y-'
// REQ:f88a35321b82d8b0 a structured custom attribute value may not contain structures
// REQ:e568ad7ba7774b00 1.x custom attributes are returned inside an Attribute structure that carries their name
// REQ:05c4f2a8d68bf801 the server creates no custom attributes outside the 'y-' namespace
#[test]
fn custom_attribute_names_and_values_follow_the_x_and_y_rules() {
    for v in LEGACY {
        let mut f = Fixture::new();
        let id = create_aes(&mut f, v, vec![]);
        let custom = |name: &str, value: Node| legacy(name, value, None);
        let mut attempt = |a: Node| f.call(v, 13, vec![uid(&id), a]);
        assert!(failed(&attempt(custom("y-server", Node::text(0, "a")))));
        assert!(failed(&attempt(custom("unprefixed", Node::text(0, "a")))));
        let nested = Node::structure(
            0,
            vec![Node::structure(
                CUSTOM_ATTRIBUTE,
                vec![Node::text(CUSTOM_ATTRIBUTE, "a")],
            )],
        );
        assert!(failed(&attempt(custom("x-nested", nested))));
        ok(&attempt(custom("x-label", Node::text(0, "a"))));
        let flat = Node::structure(0, vec![Node::text(CUSTOM_ATTRIBUTE, "b")]);
        ok(&attempt(custom("x-flat", flat)));
        let r = f.call(v, 11, vec![uid(&id)]);
        let mut names = vec![];
        for a in ok(&r).all(ATTRIBUTE) {
            let name = text_field(a, ATTRIBUTE_NAME);
            if name.starts_with("x-") || name.starts_with("y-") {
                names.push(name);
            }
        }
        names.sort();
        assert_eq!(names, ["x-flat", "x-label"], "{}", label(v));
        assert!(ok(&r).get(CUSTOM_ATTRIBUTE).is_none());
        assert!(failed(&f.call(
            v,
            14,
            vec![uid(&id), custom("y-server", Node::text(0, "b"))]
        )));
    }
}

// REQ:cab0c709b4b035ec an Application Specific Information request for an unsupported namespace fails
#[test]
fn application_namespaces_the_server_does_not_support_are_refused() {
    for v in FINAL {
        let mut f = Fixture::new();
        // Query Application Namespaces lists none.
        let r = f.call(v, 24, vec![Node::enumeration(QUERY_FUNCTION, 4)]);
        assert!(ok(&r).get(APPLICATION_NAMESPACE).is_none());
        let id = create_aes(&mut f, v, vec![]);
        let asi = |data: Option<&str>| {
            let mut fields = vec![Node::text(APPLICATION_NAMESPACE, "ssl")];
            if let Some(d) = data {
                fields.push(Node::text(APPLICATION_DATA, d));
            }
            Node::structure(APPLICATION_SPECIFIC_INFORMATION, fields)
        };
        assert!(failed(&add(&mut f, v, &id, asi(None))));
        assert!(values(&mut f, v, &id, APPLICATION_SPECIFIC_INFORMATION).is_empty());
        // Client-supplied data is stored as given.
        ok(&add(&mut f, v, &id, asi(Some("www.example.com"))));
        assert_eq!(
            values(&mut f, v, &id, APPLICATION_SPECIFIC_INFORMATION).len(),
            1
        );
    }
}

// REQ:7d76aa21265777b8 a single-instance attribute cannot gain a second instance
#[test]
fn single_instance_attributes_reject_a_second_instance() {
    for v in FINAL {
        let mut f = Fixture::new();
        let id = create_aes(&mut f, v, vec![Node::text(CONTACT_INFORMATION, "ops")]);
        assert!(failed(&add(
            &mut f,
            v,
            &id,
            Node::text(CONTACT_INFORMATION, "dup")
        )));
        assert!(failed(&add(
            &mut f,
            v,
            &id,
            Node::int(CRYPTOGRAPHIC_USAGE_MASK, 4)
        )));
        assert_eq!(values(&mut f, v, &id, CONTACT_INFORMATION).len(), 1);
        // Multi-instance attributes accept further instances.
        ok(&add(&mut f, v, &id, Node::text(OBJECT_GROUP, "a")));
        ok(&add(&mut f, v, &id, Node::text(OBJECT_GROUP, "b")));
        assert_eq!(values(&mut f, v, &id, OBJECT_GROUP).len(), 2);
    }
}

/// PKCS#12 is not an implemented Key Format Type and is refused.
#[test]
fn pkcs12_key_format_is_refused() {
    for v in [Version(1, 4), Version(2, 0), Version(2, 1)] {
        let mut f = Fixture::new();
        let (private, _) = rsa_pair(&mut f, v);
        let r = f.call(
            v,
            10,
            vec![uid(&private), Node::enumeration(KEY_FORMAT_TYPE, 22)],
        );
        assert_eq!(reason(&r), 0x10);
        let object = Node::structure(
            PRIVATE_KEY,
            vec![Node::structure(
                KEY_BLOCK,
                vec![
                    Node::enumeration(KEY_FORMAT_TYPE, 22),
                    Node::structure(KEY_VALUE, vec![Node::bytes(KEY_MATERIAL, vec![0x30, 0])]),
                ],
            )],
        );
        let attrs = container(
            v,
            vec![
                Node::enumeration(CRYPTOGRAPHIC_ALGORITHM, 4),
                Node::int(CRYPTOGRAPHIC_LENGTH, 2048),
                Node::int(CRYPTOGRAPHIC_USAGE_MASK, 1),
            ],
        );
        let r = f.call(v, 3, vec![Node::enumeration(OBJECT_TYPE, 4), attrs, object]);
        assert!(failed(&r));
    }
}

fn destroy(f: &mut Fixture, v: Version, id: &str) {
    ok(&f.call(v, 20, vec![uid(id)]));
}
fn ciphertext(item: &Node) -> Vec<u8> {
    bytes_field(ok(item), DATA)
}
/// Stored lifecycle state (Get Attributes is not available for every destroyed object).
fn stored_state(f: &Fixture, id: &str) -> u32 {
    f.engine.store.get("alice", id).unwrap().unwrap().state
}

// REQ:5d0d99ac9ae9966b an object is always in exactly one of the six defined states
// REQ:115b9b037f13a7e4 a Pre-Active key is not used for any cryptographic purpose
// REQ:17a884624b715399 a key is used only after it has become Active
// REQ:d23107965a479100 a key whose Activation Date has not been reached is not used
// REQ:bf2b6b94e4408021 1.0/1.1 a Deactivated key does not apply protection (wrapping)
// REQ:7537cf91c63283ab 1.2+ a Deactivated key does not apply protection (encryption, wrapping)
// REQ:0cf800f98e64406d 1.0/1.1 once the Deactivation Date has passed the key no longer protects
// REQ:0995c70e84781e02 1.2-1.4 once the Deactivation Date has passed the key no longer protects
// REQ:e0ebec7257431d42 2.x once the Deactivation Date has passed the key no longer protects
// REQ:e405cb177c43f4ac a Compromised key does not apply protection
// REQ:8443da8b17242f74 a Destroyed key is not used for any purpose
// REQ:86d279ce6de36c88 a Destroyed Compromised key is not used for any purpose and stays marked compromised
#[test]
fn lifecycle_states_gate_cryptographic_use() {
    for v in FINAL {
        let mut f = Fixture::new();
        let crypto = v >= Version(1, 2);
        let target = create_aes(&mut f, v, vec![]);
        // Pre-Active, and Pre-Active with a future Activation Date.
        let pending = kek(&mut f, v, vec![]);
        let future = kek(&mut f, v, vec![Node::date(ACTIVATION_DATE, now() + 3600)]);
        for k in [&pending, &future] {
            assert_eq!(state(&mut f, v, k), 1);
            assert!(failed(&get_wrapped(&mut f, v, &target, k)), "{}", label(v));
        }
        let data = create_aes(&mut f, v, vec![]);
        if crypto {
            assert!(failed(&encrypt(&mut f, v, &data)));
        }
        // Active: usable.
        activate(&mut f, v, &pending);
        ok(&get_wrapped(&mut f, v, &target, &pending));
        activate(&mut f, v, &data);
        let sealed = if crypto {
            let c = ciphertext(&encrypt(&mut f, v, &data));
            ok(&decrypt(&mut f, v, &data, &c));
            c
        } else {
            vec![]
        };
        // Deactivated by Revoke, or by a passed Deactivation Date.
        ok(&revoke(&mut f, v, &pending, 6));
        let mut deactivated = vec![pending.clone()];
        let dates = vec![
            Node::date(ACTIVATION_DATE, now() - 100),
            Node::date(DEACTIVATION_DATE, now() - 10),
        ];
        if v == Version(1, 0) {
            // 1.0 section 3.17 sets the past Activation Date to the receipt
            // time, which the passed Deactivation Date would precede.
            assert_eq!(reason(&f.call(v, 1, aes(v, 12, dates))), 7, "{}", label(v));
        } else {
            deactivated.push(kek(&mut f, v, dates));
        }
        for k in &deactivated {
            assert_eq!(state(&mut f, v, k), 3);
            assert!(failed(&get_wrapped(&mut f, v, &target, k)), "{}", label(v));
        }
        if crypto {
            let revoked = register_aes(&mut f, v, [8; 16], 12, vec![]);
            activate(&mut f, v, &revoked);
            ok(&revoke(&mut f, v, &revoked, 6));
            assert!(failed(&encrypt(&mut f, v, &revoked)));
        }
        // Compromised.
        let leaked = kek(&mut f, v, vec![]);
        activate(&mut f, v, &leaked);
        ok(&revoke(&mut f, v, &leaked, 2));
        assert_eq!(state(&mut f, v, &leaked), 4);
        assert!(failed(&get_wrapped(&mut f, v, &target, &leaked)));
        if crypto {
            ok(&revoke(&mut f, v, &data, 2));
            assert!(failed(&encrypt(&mut f, v, &data)));
        }
        // Destroyed and Destroyed Compromised.
        let retired = kek(&mut f, v, vec![]);
        destroy(&mut f, v, &retired);
        assert_eq!(stored_state(&f, &retired), 5);
        destroy(&mut f, v, &leaked);
        assert_eq!(stored_state(&f, &leaked), 6);
        for k in [&retired, &leaked] {
            assert!(failed(&get_wrapped(&mut f, v, &target, k)));
        }
        if crypto {
            destroy(&mut f, v, &data);
            assert_eq!(stored_state(&f, &data), 6);
            assert!(failed(&decrypt(&mut f, v, &data, &sealed)));
            assert!(failed(&encrypt(&mut f, v, &data)));
        }
        for id in f.engine.store.list("alice").unwrap() {
            assert!((1..=6).contains(&id.state), "{}", label(v));
        }
    }
}

// REQ:a73898b1cc8d17fe an Active key is used only for what its Cryptographic Usage Mask allows
// REQ:b722add3c6942412 a key is used only for purposes permitted by its Cryptographic Usage Mask
#[test]
fn usage_masks_gate_cryptographic_use() {
    for v in FINAL {
        let mut f = Fixture::new();
        let target = create_aes(&mut f, v, vec![]);
        // A key that may encrypt and decrypt data, but not wrap keys.
        let not_wrapping = register_aes(
            &mut f,
            v,
            [3; 16],
            12,
            vec![Node::structure(
                CRYPTOGRAPHIC_PARAMETERS,
                vec![Node::enumeration(BLOCK_CIPHER_MODE, 12)],
            )],
        );
        activate(&mut f, v, &not_wrapping);
        assert!(failed(&get_wrapped(&mut f, v, &target, &not_wrapping)));
        if v >= Version(1, 2) {
            let sealer = register_aes(&mut f, v, [1; 16], 4, vec![]);
            let opener = register_aes(&mut f, v, [1; 16], 8, vec![]);
            activate(&mut f, v, &sealer);
            activate(&mut f, v, &opener);
            let c = ciphertext(&encrypt(&mut f, v, &sealer));
            assert!(failed(&decrypt(&mut f, v, &sealer, &c)));
            ok(&decrypt(&mut f, v, &opener, &c));
            assert!(failed(&encrypt(&mut f, v, &opener)));
        }
    }
}

// REQ:1cbbafa7fa5a1238 a key is not used to process protected data before its Process Start Date
// REQ:3b5d8903450c3fd7 1.2-1.4 a key is not used to process protected data before its Process Start Date
// REQ:507c71079d48a95b 2.x a key is not used to process protected data before its Process Start Date
// REQ:890316c7221f7a81 1.0/1.1 a key does not apply protection after its Protect Stop Date
// REQ:8d0fee35a5fbdb07 1.2-1.4 a key does not apply protection after its Protect Stop Date
// REQ:9569110410d5db78 2.x a key does not apply protection after its Protect Stop Date
// REQ:0f97112c6bc106fd 1.2-1.4 an Active key past its Protect Stop Date no longer protects
// REQ:22bb6227467493c8 2.x an Active key past its Protect Stop Date no longer protects
// The State section says "cryptographic purposes" for both dates; the date
// attributes themselves (1.x 3.25/3.26, 2.x 4.40/4.41) limit processing before
// the Process Start Date and protection after the Protect Stop Date, so the
// other direction stays allowed here.
#[test]
fn process_start_and_protect_stop_dates_gate_use() {
    for v in FINAL {
        let mut f = Fixture::new();
        let active = Node::date(ACTIVATION_DATE, now() - 100);
        let target = create_aes(&mut f, v, vec![]);
        // Wrapping applies protection with the key-encryption key.
        let stopped = kek(
            &mut f,
            v,
            vec![active.clone(), Node::date(PROTECT_STOP_DATE, now() - 10)],
        );
        assert_eq!(state(&mut f, v, &stopped), 2);
        assert!(
            failed(&get_wrapped(&mut f, v, &target, &stopped)),
            "{}",
            label(v)
        );
        // Registering a wrapped key processes it with the key-encryption key.
        let good = kek(&mut f, v, vec![active.clone()]);
        let waiting = kek(
            &mut f,
            v,
            vec![active.clone(), Node::date(PROCESS_START_DATE, now() + 3600)],
        );
        let wrapped = key_block(&get_wrapped(&mut f, v, &target, &good));
        let mut fields = aes(v, 12, vec![]);
        fields.push(Node::structure(SYMMETRIC_KEY, vec![wrapped.clone()]));
        ok(&f.call(v, 3, fields.clone()));
        let retarget = |n: &mut Node, from: &str, to: &str| {
            fn walk(n: &mut Node, from: &str, to: &str) {
                if n.tag == UNIQUE_IDENTIFIER
                    && matches!(&n.value, Value::TextString(s) if s == from)
                {
                    n.value = Value::TextString(to.to_owned());
                }
                if let Value::Structure(c) = &mut n.value {
                    c.iter_mut().for_each(|c| walk(c, from, to));
                }
            }
            walk(n, from, to)
        };
        let mut late = fields.clone();
        late.iter_mut().for_each(|n| retarget(n, &good, &waiting));
        assert!(failed(&f.call(v, 3, late)), "{}", label(v));
        if v >= Version(1, 2) {
            let sealer = register_aes(&mut f, v, [2; 16], 12, vec![active.clone()]);
            let c = ciphertext(&encrypt(&mut f, v, &sealer));
            let opener = register_aes(
                &mut f,
                v,
                [2; 16],
                12,
                vec![active.clone(), Node::date(PROCESS_START_DATE, now() + 3600)],
            );
            ok(&encrypt(&mut f, v, &opener));
            assert!(failed(&decrypt(&mut f, v, &opener, &c)));
            let closed = register_aes(
                &mut f,
                v,
                [2; 16],
                12,
                vec![active.clone(), Node::date(PROTECT_STOP_DATE, now() - 10)],
            );
            assert!(failed(&encrypt(&mut f, v, &closed)));
            ok(&decrypt(&mut f, v, &closed, &c));
        }
    }
}

// REQ:b3f08310ddc3142d a Process Start Date before the Activation Date is refused
// REQ:f4ef672ba445b90f a Protect Stop Date after the Deactivation Date is refused
// REQ:014486b18e8bf9a1 a Process Start Date that has passed cannot be changed or deleted
// REQ:51748f6140ea428c a Protect Stop Date that has passed cannot be changed or deleted
// REQ:c45078a1d5d116eb the Deactivation Date can be changed only while the key is Pre-Active or Active
#[test]
fn date_ordering_and_immutability_are_enforced() {
    for v in FINAL {
        let mut f = Fixture::new();
        let t = now();
        let order = |a: Vec<Node>| aes(v, 12, a);
        let r = f.call(
            v,
            1,
            order(vec![
                Node::date(ACTIVATION_DATE, t + 1000),
                Node::date(PROCESS_START_DATE, t + 500),
            ]),
        );
        assert!(failed(&r), "{}", label(v));
        let r = f.call(
            v,
            1,
            order(vec![
                Node::date(DEACTIVATION_DATE, t + 1000),
                Node::date(PROTECT_STOP_DATE, t + 2000),
            ]),
        );
        assert!(failed(&r));
        let id = create_aes(&mut f, v, vec![Node::date(ACTIVATION_DATE, t + 1000)]);
        assert!(failed(&add(
            &mut f,
            v,
            &id,
            Node::date(PROCESS_START_DATE, t + 500)
        )));
        ok(&add(
            &mut f,
            v,
            &id,
            Node::date(PROCESS_START_DATE, t + 1500),
        ));
        // Passed dates are frozen. (In 1.0 a past Activation Date becomes
        // the receipt time, which the passed dates would precede.)
        let mut passed = vec![
            Node::date(PROCESS_START_DATE, t - 50),
            Node::date(PROTECT_STOP_DATE, t - 10),
        ];
        if v != Version(1, 0) {
            passed.insert(0, Node::date(ACTIVATION_DATE, t - 100));
        }
        let id = create_aes(&mut f, v, passed);
        for tag in [PROCESS_START_DATE, PROTECT_STOP_DATE] {
            assert!(
                failed(&modify(&mut f, v, &id, Node::date(tag, t + 100))),
                "{}",
                label(v)
            );
            assert!(failed(&delete(&mut f, v, &id, tag)));
            assert!(value(&mut f, v, &id, tag).is_some());
        }
        // Deactivation Date: changeable while Pre-Active or Active only.
        let id = create_aes(&mut f, v, vec![Node::date(DEACTIVATION_DATE, t + 1000)]);
        ok(&modify(
            &mut f,
            v,
            &id,
            Node::date(DEACTIVATION_DATE, t + 2000),
        ));
        activate(&mut f, v, &id);
        ok(&modify(
            &mut f,
            v,
            &id,
            Node::date(DEACTIVATION_DATE, t + 3000),
        ));
        ok(&revoke(&mut f, v, &id, 6));
        assert_eq!(state(&mut f, v, &id), 3);
        let frozen = value(&mut f, v, &id, DEACTIVATION_DATE);
        assert!(failed(&modify(
            &mut f,
            v,
            &id,
            Node::date(DEACTIVATION_DATE, t + 4000)
        )));
        assert!(failed(&delete(&mut f, v, &id, DEACTIVATION_DATE)));
        assert!(value(&mut f, v, &id, DEACTIVATION_DATE) == frozen);
    }
}

// REQ:00712f6fe92c3872 Pre-Active becomes Active when the Activation Date arrives, when it is modified to the past, or on Activate
// REQ:654a8baa85bf2622 Activate sets the Activation Date to the time the request is received
// REQ:478e1cc957b483de Active becomes Deactivated when the Deactivation Date arrives, on a non-compromise Revoke, or when it is modified to the past
// REQ:ad8fa55a05f4853d 1.1+ an Activation Date already past at creation is kept as given and the key starts Active
#[test]
fn state_transitions_follow_the_listed_paths() {
    let mut f = Fixture::new();
    let soon = now() + 2;
    let mut scheduled = vec![];
    for v in FINAL {
        let a = create_aes(&mut f, v, vec![Node::date(ACTIVATION_DATE, soon)]);
        let d = create_aes(
            &mut f,
            v,
            vec![
                Node::date(ACTIVATION_DATE, now() - 10),
                Node::date(DEACTIVATION_DATE, soon),
            ],
        );
        assert_eq!((state(&mut f, v, &a), state(&mut f, v, &d)), (1, 2));
        scheduled.push((v, a, d));
        // Activate.
        let id = create_aes(&mut f, v, vec![]);
        let before = now();
        activate(&mut f, v, &id);
        assert_eq!(state(&mut f, v, &id), 2);
        let at = date(&value(&mut f, v, &id, ACTIVATION_DATE).unwrap());
        assert!(at >= before && at <= now(), "{}", label(v));
        // Revoke for a reason other than compromise.
        ok(&revoke(&mut f, v, &id, 5));
        assert_eq!(state(&mut f, v, &id), 3);
        // Modify Deactivation Date to now.
        let id = create_aes(&mut f, v, vec![Node::date(DEACTIVATION_DATE, now() + 3600)]);
        activate(&mut f, v, &id);
        ok(&modify(
            &mut f,
            v,
            &id,
            Node::date(DEACTIVATION_DATE, now()),
        ));
        assert_eq!(state(&mut f, v, &id), 3);
        // Modify Activation Date to now.
        let id = create_aes(&mut f, v, vec![Node::date(ACTIVATION_DATE, now() + 3600)]);
        ok(&modify(&mut f, v, &id, Node::date(ACTIVATION_DATE, now())));
        assert_eq!(state(&mut f, v, &id), 2);
        if v >= Version(1, 1) {
            let past = now() - 100;
            let id = create_aes(&mut f, v, vec![Node::date(ACTIVATION_DATE, past)]);
            assert_eq!(state(&mut f, v, &id), 2);
            assert_eq!(date(&value(&mut f, v, &id, ACTIVATION_DATE).unwrap()), past);
        }
    }
    while now() <= soon {
        std::thread::sleep(std::time::Duration::from_millis(200));
    }
    for (v, a, d) in scheduled {
        assert_eq!(state(&mut f, v, &a), 2, "{}", label(v));
        assert_eq!(state(&mut f, v, &d), 3, "{}", label(v));
    }
}

fn flag(f: &mut Fixture, v: Version, id: &str, tag: u32) -> bool {
    value(f, v, id, tag).unwrap().flag().unwrap()
}

// REQ:189466498b464900 1.2-1.4 Fresh is True when the server creates an object
// REQ:bf24a0844d9d3e0f 2.x Fresh is True on creation unless the registering client gives False
// REQ:d75fec2794cc94eb 1.1-1.4 Fresh becomes False once the object has been served to a client
// REQ:bb549819b5863028 2.x Fresh becomes False once the object has been served by Get
// REQ:74468c3cd07f8d03 1.2+ the server sets Original Creation Date equal to Initial Date
#[test]
fn fresh_and_original_creation_date_track_the_object_history() {
    for v in &FINAL[1..] {
        let v = *v;
        let mut f = Fixture::new();
        let created = create_aes(&mut f, v, vec![]);
        let registered = register_aes(&mut f, v, [4; 16], 12, vec![]);
        for id in [&created, &registered] {
            assert!(flag(&mut f, v, id, FRESH), "{}", label(v));
            // Reading metadata does not serve the object.
            ok(&f.call(v, 11, vec![uid(id)]));
            assert!(flag(&mut f, v, id, FRESH));
            ok(&f.call(v, 10, vec![uid(id)]));
            assert!(!flag(&mut f, v, id, FRESH));
            // Registered objects may carry a client-supplied date instead.
            if v >= Version(1, 2) && id == &created {
                let initial = value(&mut f, v, id, INITIAL_DATE).unwrap();
                let original = value(&mut f, v, id, ORIGINAL_CREATION_DATE).unwrap();
                assert_eq!(date(&original), date(&initial));
            }
        }
        if v.0 >= 2 {
            let stale = register_aes(&mut f, v, [4; 16], 12, vec![Node::boolean(FRESH, false)]);
            assert!(!flag(&mut f, v, &stale, FRESH));
        }
    }
}

// REQ:054a7e07875da12a Sensitive defaults to False
// REQ:8314d8841acd4e32 1.4 Extractable defaults to True
// REQ:7f8753a3dcca30e9 2.x Extractable defaults to True
// REQ:7349ba971bcc1b5d a Sensitive object's value is returned only wrapped
// REQ:9e150f6d98753bb7 1.4 a non-Extractable object's value is never returned
// REQ:a45f9f723ad2cf7a 2.x a non-Extractable object's value is never returned
// REQ:1f69c28112792516 1.4 Always Sensitive is True until Sensitive is first False, then stays False
// REQ:d7601fa70aa1b2a6 2.x the server creates Always Sensitive, True while Sensitive has always been True
// REQ:6dd15467d3a1400a 2.x Always Sensitive becomes False once Sensitive has been False
// REQ:cc533e65bf79a6fc 1.4 Never Extractable is True until Extractable is first True, then stays False
// REQ:35969b991ae67228 2.x the server creates Never Extractable, True while Extractable has always been False
// REQ:13ec07a71080b7b6 2.x Never Extractable becomes False once Extractable has been True
#[test]
fn sensitive_and_extractable_defaults_enforcement_and_histories() {
    for v in [Version(1, 4), Version(2, 0), Version(2, 1)] {
        let mut f = Fixture::new();
        let k = kek(&mut f, v, vec![]);
        activate(&mut f, v, &k);
        let plain = create_aes(&mut f, v, vec![]);
        assert!(!flag(&mut f, v, &plain, SENSITIVE));
        assert!(flag(&mut f, v, &plain, EXTRACTABLE));
        assert!(!flag(&mut f, v, &plain, ALWAYS_SENSITIVE));
        assert!(!flag(&mut f, v, &plain, NEVER_EXTRACTABLE));
        let guarded = create_aes(
            &mut f,
            v,
            vec![
                Node::boolean(SENSITIVE, true),
                Node::boolean(EXTRACTABLE, false),
            ],
        );
        assert!(flag(&mut f, v, &guarded, ALWAYS_SENSITIVE));
        assert!(flag(&mut f, v, &guarded, NEVER_EXTRACTABLE));
        assert!(failed(&f.call(v, 10, vec![uid(&guarded)])));
        assert!(failed(&get_wrapped(&mut f, v, &guarded, &k)));
        // Sensitive alone: wrapped only.
        let sensitive = create_aes(&mut f, v, vec![Node::boolean(SENSITIVE, true)]);
        assert!(failed(&f.call(v, 10, vec![uid(&sensitive)])));
        ok(&get_wrapped(&mut f, v, &sensitive, &k));
        // Histories never return to True.
        ok(&modify(
            &mut f,
            v,
            &guarded,
            Node::boolean(SENSITIVE, false),
        ));
        ok(&modify(
            &mut f,
            v,
            &guarded,
            Node::boolean(EXTRACTABLE, true),
        ));
        assert!(!flag(&mut f, v, &guarded, ALWAYS_SENSITIVE));
        assert!(!flag(&mut f, v, &guarded, NEVER_EXTRACTABLE));
        ok(&f.call(v, 10, vec![uid(&guarded)]));
        ok(&modify(&mut f, v, &guarded, Node::boolean(SENSITIVE, true)));
        ok(&modify(
            &mut f,
            v,
            &guarded,
            Node::boolean(EXTRACTABLE, false),
        ));
        assert!(!flag(&mut f, v, &guarded, ALWAYS_SENSITIVE));
        assert!(!flag(&mut f, v, &guarded, NEVER_EXTRACTABLE));
        assert!(failed(&f.call(v, 10, vec![uid(&guarded)])));
    }
}

// REQ:672c0f1853595fab 2.x different clients allowed to read an object see the same attribute values
#[test]
fn attribute_values_do_not_depend_on_the_requesting_client() {
    for v in FINAL {
        let mut f = Fixture::new();
        let id = create_aes(&mut f, v, vec![Node::text(CONTACT_INFORMATION, "ops")]);
        let mine = all_attributes(&mut f, "alice", v, &id);
        let grants = [keytend_kmip_server::authorization::ObjectGrant {
            owner: "alice".into(),
            user: None,
            device: None,
            identifier: id.clone(),
            operations: vec![11],
        }];
        let request = Node::structure(
            REQUEST_MESSAGE,
            vec![
                Node::structure(REQUEST_HEADER, vec![v.node(), Node::int(BATCH_COUNT, 1)]),
                Node::structure(
                    BATCH_ITEM,
                    vec![
                        Node::enumeration(OPERATION, 11),
                        Node::structure(REQUEST_PAYLOAD, vec![uid(&id)]),
                    ],
                ),
            ],
        );
        let r = f
            .engine
            .process_with_grants("bob", &request, Some(&[11]), &grants)
            .unwrap();
        let item = r.required(BATCH_ITEM).unwrap();
        assert!(
            ok(item) == ok(&f.call(v, 11, vec![uid(&id)])),
            "{}",
            label(v)
        );
        assert!(!mine.is_empty());
    }
}

fn usage_count(f: &mut Fixture, v: Version, id: &str) -> i64 {
    let limits = value(f, v, id, USAGE_LIMITS).unwrap();
    match limits.required(USAGE_LIMITS_COUNT).unwrap().value {
        Value::LongInteger(n) => n,
        _ => panic!("Usage Limits Count is a Long Integer"),
    }
}
fn limits(total: i64) -> Node {
    Node::structure(
        USAGE_LIMITS,
        vec![
            Node::long(USAGE_LIMITS_TOTAL, total),
            Node::enumeration(USAGE_LIMITS_UNIT, 2),
        ],
    )
}

// REQ:5469168200e0a1ff 1.x Usage Limits count only uses that apply protection (encrypting, wrapping)
// REQ:bd81d5839d705665 2.x Usage Limits count only uses that apply protection (encrypting, wrapping)
// REQ:b991dd9370a43c7e the Usage Limits Total cannot change once the key has applied protection
#[test]
fn usage_limits_count_protection_only_and_freeze_after_use() {
    for v in FINAL {
        let mut f = Fixture::new();
        let target = create_aes(&mut f, v, vec![]);
        let k = kek(&mut f, v, vec![limits(5)]);
        activate(&mut f, v, &k);
        ok(&get_wrapped(&mut f, v, &target, &k));
        assert_eq!(usage_count(&mut f, v, &k), 4, "{}", label(v));
        assert!(failed(&modify(&mut f, v, &k, limits(9))));
        if v >= Version(1, 2) {
            let id = create_aes(&mut f, v, vec![limits(5)]);
            ok(&modify(&mut f, v, &id, limits(6)));
            activate(&mut f, v, &id);
            let c = ciphertext(&encrypt(&mut f, v, &id));
            assert_eq!(usage_count(&mut f, v, &id), 5);
            ok(&decrypt(&mut f, v, &id, &c));
            ok(&decrypt(&mut f, v, &id, &c));
            assert_eq!(usage_count(&mut f, v, &id), 5);
            assert!(failed(&modify(&mut f, v, &id, limits(9))));
            assert!(failed(&delete(&mut f, v, &id, USAGE_LIMITS)));
        }
    }
}
