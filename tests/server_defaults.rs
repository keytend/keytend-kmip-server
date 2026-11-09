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

//! Set Defaults (2.1 section 6.1.53, draft 3.0) and the server defaults it
//! configures: validation, server-wide scope, application to Create, Create
//! Key Pair, Register and Derive Key in 2.0, 2.1 and 3.0 requests, pair-wide
//! key-pair resolution, stale entries, persistence and Undo. The reading is
//! in docs/defaults-and-constraints.md.
use keytend_kmip_server::{
    protocol::{Engine, TripleDesPolicy, Version},
    store::Store,
    tags::*,
    ttlv::{Node, Value},
};
use std::path::Path;

const V14: Version = Version(1, 4);
const V20: Version = Version(2, 0);
const V21: Version = Version(2, 1);
const V3: Version = Version(3, 0);
const CREATE: u32 = 1;
const CREATE_KEY_PAIR: u32 = 2;
const REGISTER: u32 = 3;
const DERIVE_KEY: u32 = 5;
const GET: u32 = 10;
const GET_ATTRIBUTES: u32 = 11;
const ACTIVATE: u32 = 18;
const QUERY: u32 = 24;
const SET_DEFAULTS: u32 = 0x36;
const AES: u32 = 3;
const TRIPLE_DES: u32 = 2;
const RSA: u32 = 4;
const ECDSA: u32 = 6;
const CHACHA20: u32 = 28;
const ML_DSA_65: u32 = 0x3d;

#[derive(Clone, Copy, Default)]
struct Settings {
    fips: bool,
    triple_des: bool,
}

struct Fixture {
    engine: Engine,
    directory: tempfile::TempDir,
}
fn open(directory: &Path, settings: Settings) -> Engine {
    let master = directory.join("master");
    if !master.exists() {
        std::fs::write(&master, [6; 32]).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&master, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
    }
    Engine::new(
        Store::open(&directory.join("store.sqlite"), &master).unwrap(),
        true,
    )
    .with_fips(settings.fips)
    .with_triple_des(if settings.triple_des {
        TripleDesPolicy::Enabled
    } else {
        TripleDesPolicy::Disabled
    })
}
impl Fixture {
    fn new() -> Self {
        Self::with(Settings::default())
    }
    fn with(settings: Settings) -> Self {
        let directory = tempfile::tempdir().unwrap();
        Self {
            engine: open(directory.path(), settings),
            directory,
        }
    }
    /// Restart the server on the same database with other settings.
    fn reopen(&mut self, settings: Settings) {
        let directory = self.directory.path().to_owned();
        self.engine = open(&directory, settings);
    }
    fn send(
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
        let many = items.len() > 1;
        for (index, (op, payload)) in items.into_iter().enumerate() {
            let mut item = vec![Node::enumeration(OPERATION, op)];
            if many && v.0 < 3 {
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
    fn call(&mut self, owner: &str, v: Version, op: u32, payload: Vec<Node>) -> Node {
        self.send(owner, v, vec![], vec![(op, payload)]).remove(0)
    }
    /// Set Defaults with these Object Defaults (None: no Defaults
    /// Information, which removes every configured default).
    fn set(&mut self, owner: &str, v: Version, entries: Option<Vec<Node>>) -> Node {
        self.call(
            owner,
            v,
            SET_DEFAULTS,
            entries
                .map(|e| vec![Node::structure(DEFAULTS_INFORMATION, e)])
                .unwrap_or_default(),
        )
    }
    fn set_ok(&mut self, entries: Vec<Node>) {
        let r = self.set("alice", V21, Some(entries));
        assert_eq!(status(&r), 0, "Set Defaults: {}", describe(&r));
        assert!(payload(&r).children().unwrap().is_empty());
    }
    /// The attributes of an object, from Get Attributes.
    fn attributes(&mut self, owner: &str, v: Version, id: &str) -> Vec<Node> {
        let r = self.call(owner, v, GET_ATTRIBUTES, vec![uid_node(v, id)]);
        if v.0 >= 2 {
            return payload(&r)
                .required(ATTRIBUTES)
                .unwrap()
                .children()
                .unwrap()
                .to_vec();
        }
        // 1.x: Attribute structures by name.
        payload(&r)
            .all(ATTRIBUTE)
            .filter_map(|a| {
                let tag = match a.required(ATTRIBUTE_NAME).unwrap().string().unwrap() {
                    "Cryptographic Algorithm" => CRYPTOGRAPHIC_ALGORITHM,
                    "Cryptographic Length" => CRYPTOGRAPHIC_LENGTH,
                    "Cryptographic Usage Mask" => CRYPTOGRAPHIC_USAGE_MASK,
                    _ => return None,
                };
                let mut value = a.required(ATTRIBUTE_VALUE).unwrap().clone();
                value.tag = tag;
                Some(value)
            })
            .collect()
    }
    /// Create a symmetric key with these request attributes; its attributes.
    fn create(&mut self, owner: &str, v: Version, attrs: Vec<Node>) -> Vec<Node> {
        let r = self.call(owner, v, CREATE, create_fields(v, attrs));
        let id = id_of(&r, UNIQUE_IDENTIFIER);
        self.attributes(owner, v, &id)
    }
    /// Create Key Pair with these Common, Private and Public attributes; the
    /// attributes of the private and the public key.
    fn pair(
        &mut self,
        v: Version,
        common: Vec<Node>,
        private: Vec<Node>,
        public: Vec<Node>,
    ) -> (Vec<Node>, Vec<Node>) {
        let r = self.call(
            "bob",
            v,
            CREATE_KEY_PAIR,
            pair_fields(v, common, private, public),
        );
        let private = id_of(&r, PRIVATE_KEY_UNIQUE_IDENTIFIER);
        let public = id_of(&r, PUBLIC_KEY_UNIQUE_IDENTIFIER);
        (
            self.attributes("bob", v, &private),
            self.attributes("bob", v, &public),
        )
    }
    /// The Defaults Information of a Query.
    fn query(&mut self, v: Version) -> Vec<Node> {
        let r = self.call("bob", v, QUERY, vec![Node::enumeration(QUERY_FUNCTION, 13)]);
        payload(&r)
            .required(DEFAULTS_INFORMATION)
            .unwrap()
            .all(OBJECT_DEFAULTS)
            .cloned()
            .collect()
    }
    /// The Query default of `tag` for `kind`, if one is reported.
    fn reported(&mut self, v: Version, kind: u32, tag: u32) -> Option<Node> {
        self.query(v)
            .into_iter()
            .find(|e| e.required(OBJECT_TYPE).unwrap().number().unwrap() == kind)
            .and_then(|e| e.required(ATTRIBUTES).unwrap().get(tag).cloned())
    }
}

fn status(item: &Node) -> u32 {
    item.required(RESULT_STATUS).unwrap().number().unwrap()
}
fn reason(item: &Node) -> u32 {
    item.get(RESULT_REASON).map_or(0, |n| n.number().unwrap())
}
fn describe(item: &Node) -> String {
    format!(
        "status {} reason {:#x} {:?}",
        status(item),
        reason(item),
        item.get(RESULT_MESSAGE)
            .map(|n| n.string().unwrap().to_owned())
    )
}
fn payload(item: &Node) -> &Node {
    assert_eq!(status(item), 0, "{}", describe(item));
    item.required(RESPONSE_PAYLOAD).unwrap()
}
fn id_of(item: &Node, tag: u32) -> String {
    payload(item)
        .required(tag)
        .unwrap()
        .identifier_text()
        .unwrap()
        .to_owned()
}
fn uid_node(v: Version, id: &str) -> Node {
    if v.0 >= 3 {
        Node::identifier(UNIQUE_IDENTIFIER, id)
    } else {
        Node::text(UNIQUE_IDENTIFIER, id)
    }
}
/// The request container of `attrs`: Template-Attribute in 1.x.
fn container(v: Version, tag: u32, attrs: Vec<Node>) -> Node {
    if v.0 >= 2 {
        return Node::structure(tag, attrs);
    }
    let old = match tag {
        ATTRIBUTES => TEMPLATE_ATTRIBUTE,
        COMMON_ATTRIBUTES => COMMON_TEMPLATE_ATTRIBUTE,
        PRIVATE_KEY_ATTRIBUTES => PRIVATE_KEY_TEMPLATE_ATTRIBUTE,
        _ => PUBLIC_KEY_TEMPLATE_ATTRIBUTE,
    };
    Node::structure(
        old,
        attrs
            .into_iter()
            .map(|a| {
                let name = match a.tag {
                    CRYPTOGRAPHIC_ALGORITHM => "Cryptographic Algorithm",
                    CRYPTOGRAPHIC_LENGTH => "Cryptographic Length",
                    _ => "Cryptographic Usage Mask",
                };
                let mut value = a;
                value.tag = ATTRIBUTE_VALUE;
                Node::structure(ATTRIBUTE, vec![Node::text(ATTRIBUTE_NAME, name), value])
            })
            .collect(),
    )
}
fn create_fields(v: Version, attrs: Vec<Node>) -> Vec<Node> {
    vec![
        Node::enumeration(OBJECT_TYPE, 2),
        container(v, ATTRIBUTES, attrs),
    ]
}
fn pair_fields(v: Version, common: Vec<Node>, private: Vec<Node>, public: Vec<Node>) -> Vec<Node> {
    let mut fields = vec![];
    for (tag, attrs) in [
        (COMMON_ATTRIBUTES, common),
        (PRIVATE_KEY_ATTRIBUTES, private),
        (PUBLIC_KEY_ATTRIBUTES, public),
    ] {
        if !attrs.is_empty() {
            fields.push(container(v, tag, attrs));
        }
    }
    fields
}
/// One Object Defaults for a single Object Type.
fn entry(kind: u32, attrs: Vec<Node>) -> Node {
    Node::structure(
        OBJECT_DEFAULTS,
        vec![
            Node::enumeration(OBJECT_TYPE, kind),
            Node::structure(ATTRIBUTES, attrs),
        ],
    )
}
fn algorithm(alg: u32) -> Node {
    Node::enumeration(CRYPTOGRAPHIC_ALGORITHM, alg)
}
fn length(bits: i32) -> Node {
    Node::int(CRYPTOGRAPHIC_LENGTH, bits)
}
fn mask(mask: i32) -> Node {
    Node::int(CRYPTOGRAPHIC_USAGE_MASK, mask)
}
fn curve(curve: u32) -> Node {
    Node::structure(
        CRYPTOGRAPHIC_DOMAIN_PARAMETERS,
        vec![Node::enumeration(RECOMMENDED_CURVE, curve)],
    )
}
fn value(attrs: &[Node], tag: u32) -> Option<i64> {
    attrs.iter().find(|a| a.tag == tag).map(|a| match &a.value {
        Value::Enumeration(n) => *n as i64,
        Value::Integer(n) => *n as i64,
        Value::Boolean(b) => *b as i64,
        _ => panic!("unexpected value type for {tag:#x}"),
    })
}
fn alg_bits(attrs: &[Node]) -> (i64, i64) {
    (
        value(attrs, CRYPTOGRAPHIC_ALGORITHM).unwrap(),
        value(attrs, CRYPTOGRAPHIC_LENGTH).unwrap(),
    )
}
fn ops(f: &mut Fixture, v: Version) -> Vec<u32> {
    let r = f.call("bob", v, QUERY, vec![Node::enumeration(QUERY_FUNCTION, 1)]);
    payload(&r)
        .all(OPERATION)
        .map(|n| n.number().unwrap())
        .collect()
}

#[test]
fn set_defaults_is_offered_from_2_1() {
    let mut f = Fixture::new();
    for v in [V21, V3] {
        let offered = ops(&mut f, v);
        for op in [0x36, 0x37, 0x38] {
            assert!(offered.contains(&op), "{v:?} op {op:#x}");
        }
    }
    assert!(!ops(&mut f, V20).contains(&0x36));
    // 2.0 does not define Set Defaults, but its requests get the defaults.
    for v in [V14, V20] {
        assert_eq!(reason(&f.set("alice", v, None)), 5, "{v:?}");
    }
}

#[test]
fn symmetric_defaults_apply_to_2_x_and_3_0_requests_only() {
    let mut f = Fixture::with(Settings {
        triple_des: true,
        ..Default::default()
    });
    f.set_ok(vec![entry(
        2,
        vec![
            algorithm(AES),
            length(128),
            mask(12),
            Node::boolean(SENSITIVE, true),
            Node::boolean(EXTRACTABLE, false),
        ],
    )]);
    for v in [V20, V21, V3] {
        // Another principal gets the server-wide defaults.
        let attrs = f.create("bob", v, vec![]);
        assert_eq!(alg_bits(&attrs), (AES as i64, 128), "{v:?}");
        assert_eq!(value(&attrs, CRYPTOGRAPHIC_USAGE_MASK), Some(12), "{v:?}");
        assert_eq!(value(&attrs, SENSITIVE), Some(1), "{v:?}");
        assert_eq!(value(&attrs, EXTRACTABLE), Some(0), "{v:?}");
        // Client values always win, attribute by attribute.
        let attrs = f.create("bob", v, vec![length(192), mask(4)]);
        assert_eq!(alg_bits(&attrs), (AES as i64, 192), "{v:?}");
        assert_eq!(value(&attrs, CRYPTOGRAPHIC_USAGE_MASK), Some(4), "{v:?}");
        // The length belongs to the AES default: 3DES without a length
        // still gets its own 168.
        let attrs = f.create("bob", v, vec![algorithm(TRIPLE_DES)]);
        assert_eq!(alg_bits(&attrs), (TRIPLE_DES as i64, 168), "{v:?}");
    }
    // 1.x requests are never affected.
    let attrs = f.create("bob", V14, vec![mask(12)]);
    assert_eq!(alg_bits(&attrs), (AES as i64, 256));
}

#[test]
fn a_symmetric_default_fills_in_derive_key() {
    let mut f = Fixture::new();
    f.set_ok(vec![entry(2, vec![algorithm(AES), length(128)])]);
    for v in [V20, V21, V3] {
        let ecb = Node::structure(
            CRYPTOGRAPHIC_PARAMETERS,
            vec![Node::enumeration(BLOCK_CIPHER_MODE, 2)],
        );
        let source = id_of(
            &f.call(
                "bob",
                v,
                CREATE,
                create_fields(v, vec![length(256), mask(512), ecb.clone()]),
            ),
            UNIQUE_IDENTIFIER,
        );
        payload(&f.call("bob", v, ACTIVATE, vec![uid_node(v, &source)]));
        // No algorithm or length in the request: both come from the default.
        let r = f.call(
            "bob",
            v,
            DERIVE_KEY,
            vec![
                Node::enumeration(OBJECT_TYPE, 2),
                uid_node(v, &source),
                Node::enumeration(DERIVATION_METHOD, 4),
                Node::structure(
                    DERIVATION_PARAMETERS,
                    vec![ecb, Node::bytes(DERIVATION_DATA, vec![1; 16])],
                ),
                Node::structure(ATTRIBUTES, vec![mask(12)]),
            ],
        );
        let derived = id_of(&r, UNIQUE_IDENTIFIER);
        let attrs = f.attributes("bob", v, &derived);
        assert_eq!(alg_bits(&attrs), (AES as i64, 128), "{v:?}");
    }
}

#[test]
fn register_gets_only_mask_sensitive_and_extractable() {
    let mut f = Fixture::new();
    f.set_ok(vec![
        entry(
            2,
            vec![algorithm(AES), length(128), Node::boolean(SENSITIVE, true)],
        ),
        entry(7, vec![mask(0x200), Node::boolean(EXTRACTABLE, false)]),
    ]);
    let key = |kind_tag: u32, kind: u32, bytes: usize| {
        vec![
            Node::enumeration(OBJECT_TYPE, kind),
            Node::structure(ATTRIBUTES, vec![]),
            Node::structure(
                kind_tag,
                vec![Node::structure(
                    KEY_BLOCK,
                    vec![
                        Node::enumeration(KEY_FORMAT_TYPE, if kind == 2 { 1 } else { 2 }),
                        Node::structure(KEY_VALUE, vec![Node::bytes(KEY_MATERIAL, vec![7; bytes])]),
                    ],
                )],
            ),
        ]
    };
    for v in [V20, V21, V3] {
        // A registered 32-byte key keeps its own length and the built-in
        // algorithm; only Sensitive comes from the default.
        let id = id_of(
            &f.call("bob", v, REGISTER, key(SYMMETRIC_KEY, 2, 32)),
            UNIQUE_IDENTIFIER,
        );
        let attrs = f.attributes("bob", v, &id);
        assert_eq!(alg_bits(&attrs), (AES as i64, 256), "{v:?}");
        assert_eq!(value(&attrs, SENSITIVE), Some(1), "{v:?}");
        let mut secret = key(SECRET_DATA, 7, 16);
        if let Value::Structure(fields) = &mut secret[2].value {
            fields.insert(0, Node::enumeration(SECRET_DATA_TYPE, 2));
        }
        let id = id_of(&f.call("bob", v, REGISTER, secret), UNIQUE_IDENTIFIER);
        let attrs = f.attributes("bob", v, &id);
        assert_eq!(
            value(&attrs, CRYPTOGRAPHIC_USAGE_MASK),
            Some(0x200),
            "{v:?}"
        );
        assert_eq!(value(&attrs, EXTRACTABLE), Some(0), "{v:?}");
    }
}

/// Pair-wide resolution with an RSA-3072 pair default: the default applies
/// only when the client chose no algorithm, and its length only when the
/// client also chose no length and no curve.
#[test]
fn key_pair_defaults_are_resolved_pair_wide() {
    let mut f = Fixture::new();
    f.set_ok(vec![
        entry(4, vec![algorithm(RSA), length(3072), mask(1)]),
        entry(3, vec![mask(2)]),
    ]);
    for v in [V20, V21, V3] {
        // No choice: the pair default, with per-side usage masks.
        let (private, public) = f.pair(v, vec![], vec![], vec![]);
        assert_eq!(alg_bits(&private), (RSA as i64, 3072), "{v:?}");
        assert_eq!(alg_bits(&public), (RSA as i64, 3072), "{v:?}");
        assert_eq!(value(&private, CRYPTOGRAPHIC_USAGE_MASK), Some(1), "{v:?}");
        assert_eq!(value(&public, CRYPTOGRAPHIC_USAGE_MASK), Some(2), "{v:?}");
        // A mask in Common is the client's choice for both sides.
        let (private, public) = f.pair(v, vec![mask(3)], vec![], vec![]);
        assert_eq!(value(&private, CRYPTOGRAPHIC_USAGE_MASK), Some(3), "{v:?}");
        assert_eq!(value(&public, CRYPTOGRAPHIC_USAGE_MASK), Some(3), "{v:?}");
        // A private-only EC choice: an EC pair, no RSA length.
        let (private, public) = f.pair(v, vec![], vec![algorithm(ECDSA)], vec![]);
        assert_eq!(alg_bits(&private), (ECDSA as i64, 256), "{v:?}");
        assert_eq!(alg_bits(&public), (ECDSA as i64, 256), "{v:?}");
        // A public-only length: the default algorithm with that length.
        let (private, public) = f.pair(v, vec![], vec![], vec![length(4096)]);
        assert_eq!(alg_bits(&private), (RSA as i64, 4096), "{v:?}");
        assert_eq!(alg_bits(&public), (RSA as i64, 4096), "{v:?}");
        // A Common EC curve with its algorithm: no RSA length is injected.
        let (private, _) = f.pair(v, vec![algorithm(ECDSA), curve(10)], vec![], vec![]);
        assert_eq!(alg_bits(&private), (ECDSA as i64, 384), "{v:?}");
        // A curve without an algorithm: RSA takes no curve, so the default
        // is not used, and the built-in RSA refuses the curve as it does
        // without server defaults.
        let r = f.call(
            "bob",
            v,
            CREATE_KEY_PAIR,
            pair_fields(v, vec![curve(10)], vec![], vec![]),
        );
        assert_eq!((status(&r), reason(&r)), (1, 7), "{v:?}");
    }
    // An EC pair default: a Common curve is the client's size choice.
    f.set_ok(vec![entry(4, vec![algorithm(ECDSA), length(521)])]);
    for v in [V20, V21, V3] {
        let (private, _) = f.pair(v, vec![], vec![], vec![]);
        assert_eq!(alg_bits(&private), (ECDSA as i64, 521), "{v:?}");
        let (private, _) = f.pair(v, vec![curve(10)], vec![], vec![]);
        assert_eq!(alg_bits(&private), (ECDSA as i64, 384), "{v:?}");
    }
    // 1.x requests are never affected.
    let (private, _) = f.pair(V14, vec![algorithm(RSA), mask(1)], vec![], vec![]);
    assert_eq!(alg_bits(&private), (RSA as i64, 2048));
}

/// The default algorithm fills an omitted algorithm when it accepts the
/// size the client chose; a size it does not accept keeps the built-in
/// algorithm, as without server defaults. A request that works without
/// defaults therefore works with them.
#[test]
fn a_default_algorithm_applies_only_to_a_size_it_accepts() {
    let mut f = Fixture::new();
    f.set_ok(vec![
        entry(4, vec![algorithm(ECDSA), length(256)]),
        entry(2, vec![algorithm(CHACHA20), length(256)]),
    ]);
    for v in [V20, V21, V3] {
        // ECDSA has no 2048-bit curve: RSA-2048, as without defaults.
        let (private, public) = f.pair(v, vec![length(2048)], vec![], vec![]);
        assert_eq!(alg_bits(&private), (RSA as i64, 2048), "{v:?}");
        assert_eq!(alg_bits(&public), (RSA as i64, 2048), "{v:?}");
        // A curve suits the EC default.
        let (private, _) = f.pair(v, vec![curve(10)], vec![], vec![]);
        assert_eq!(alg_bits(&private), (ECDSA as i64, 384), "{v:?}");
        // ChaCha20 has no 128-bit key: AES-128.
        let attrs = f.create("bob", v, vec![length(128), mask(12)]);
        assert_eq!(alg_bits(&attrs), (AES as i64, 128), "{v:?}");
        // No size: the defaults apply.
        let (private, _) = f.pair(v, vec![], vec![], vec![]);
        assert_eq!(alg_bits(&private), (ECDSA as i64, 256), "{v:?}");
        let attrs = f.create("bob", v, vec![mask(4)]);
        assert_eq!(alg_bits(&attrs), (CHACHA20 as i64, 256), "{v:?}");
    }
}

/// Derive Key has no built-in algorithm and normally gives the length: the
/// default algorithm fills it whenever the client named none.
#[test]
fn derive_key_gets_the_default_algorithm_with_its_own_length() {
    let mut f = Fixture::new();
    f.set_ok(vec![entry(2, vec![algorithm(AES), length(128)])]);
    for v in [V20, V21, V3] {
        let ecb = Node::structure(
            CRYPTOGRAPHIC_PARAMETERS,
            vec![Node::enumeration(BLOCK_CIPHER_MODE, 2)],
        );
        let source = id_of(
            &f.call(
                "bob",
                v,
                CREATE,
                create_fields(v, vec![length(256), mask(512), ecb.clone()]),
            ),
            UNIQUE_IDENTIFIER,
        );
        payload(&f.call("bob", v, ACTIVATE, vec![uid_node(v, &source)]));
        let r = f.call(
            "bob",
            v,
            DERIVE_KEY,
            vec![
                Node::enumeration(OBJECT_TYPE, 2),
                uid_node(v, &source),
                Node::enumeration(DERIVATION_METHOD, 4),
                Node::structure(
                    DERIVATION_PARAMETERS,
                    vec![ecb, Node::bytes(DERIVATION_DATA, vec![1; 32])],
                ),
                Node::structure(ATTRIBUTES, vec![mask(12), length(256)]),
            ],
        );
        let derived = id_of(&r, UNIQUE_IDENTIFIER);
        let attrs = f.attributes("bob", v, &derived);
        assert_eq!(alg_bits(&attrs), (AES as i64, 256), "{v:?}");
    }
}

/// A 3.0-only algorithm is stale in a 2.x request: the whole entry is
/// skipped, and the built-in defaults apply.
#[test]
fn a_stale_pair_entry_injects_nothing() {
    let mut f = Fixture::new();
    let r = f.set(
        "alice",
        V3,
        Some(vec![entry(4, vec![algorithm(ML_DSA_65), mask(1)])]),
    );
    assert_eq!(status(&r), 0, "{}", describe(&r));
    // Set in 3.0, the entry is not valid in 2.1: Set Defaults says so.
    let r = f.set(
        "alice",
        V21,
        Some(vec![entry(4, vec![algorithm(ML_DSA_65), mask(1)])]),
    );
    assert_eq!(reason(&r), 8);
    for v in [V20, V21] {
        let (private, _) = f.pair(v, vec![], vec![], vec![]);
        assert_eq!(alg_bits(&private), (RSA as i64, 2048), "{v:?}");
        assert_eq!(value(&private, CRYPTOGRAPHIC_USAGE_MASK), Some(0), "{v:?}");
        // Query reports the built-in default in this edition.
        let reported = f.reported(v, 4, CRYPTOGRAPHIC_ALGORITHM).unwrap();
        assert!(reported == algorithm(RSA), "{v:?}");
    }
    let (private, _) = f.pair(V3, vec![], vec![], vec![]);
    assert_eq!(
        value(&private, CRYPTOGRAPHIC_ALGORITHM),
        Some(ML_DSA_65 as i64)
    );
    assert_eq!(value(&private, CRYPTOGRAPHIC_USAGE_MASK), Some(1));
    assert!(f.reported(V3, 4, CRYPTOGRAPHIC_ALGORITHM).unwrap() == algorithm(ML_DSA_65));
}

/// Entries that a later `--fips` or `--triple-des` setting forbids are
/// skipped with a warning; Create still succeeds and Query omits them.
#[test]
fn entries_made_invalid_by_a_restart_are_skipped() {
    let mut f = Fixture::with(Settings {
        triple_des: true,
        ..Default::default()
    });
    f.set_ok(vec![entry(2, vec![algorithm(TRIPLE_DES), length(168)])]);
    assert_eq!(
        alg_bits(&f.create("bob", V21, vec![])),
        (TRIPLE_DES as i64, 168)
    );
    f.reopen(Settings::default());
    for v in [V20, V21, V3] {
        assert_eq!(alg_bits(&f.create("bob", v, vec![])), (AES as i64, 256));
        assert!(f.reported(v, 2, CRYPTOGRAPHIC_ALGORITHM).unwrap() == algorithm(AES));
        assert!(f.reported(v, 2, CRYPTOGRAPHIC_LENGTH).is_none());
    }
    // Without the setting a 3DES default cannot be set at all.
    let r = f.set(
        "alice",
        V21,
        Some(vec![entry(2, vec![algorithm(TRIPLE_DES)])]),
    );
    assert_eq!(reason(&r), 8);

    // ChaCha20 and ML-DSA are not available in FIPS mode: it skips both
    // entries.
    let r = f.set(
        "alice",
        V3,
        Some(vec![
            entry(2, vec![algorithm(CHACHA20), mask(12)]),
            entry(4, vec![algorithm(ML_DSA_65)]),
        ]),
    );
    assert_eq!(status(&r), 0, "{}", describe(&r));
    assert_eq!(
        alg_bits(&f.create("bob", V21, vec![])),
        (CHACHA20 as i64, 256)
    );
    f.reopen(Settings {
        fips: true,
        ..Default::default()
    });
    for v in [V20, V21, V3] {
        let attrs = f.create("bob", v, vec![]);
        assert_eq!(alg_bits(&attrs), (AES as i64, 256), "{v:?}");
        // The whole entry is skipped, its usage mask too.
        assert_eq!(value(&attrs, CRYPTOGRAPHIC_USAGE_MASK), Some(0), "{v:?}");
        let (private, _) = f.pair(v, vec![], vec![], vec![]);
        assert_eq!(alg_bits(&private), (RSA as i64, 2048), "{v:?}");
        assert!(f.reported(v, 2, CRYPTOGRAPHIC_ALGORITHM).unwrap() == algorithm(AES));
        assert!(f.reported(v, 4, CRYPTOGRAPHIC_ALGORITHM).unwrap() == algorithm(RSA));
    }
    // FIPS mode refuses to set them.
    let r = f.set(
        "alice",
        V21,
        Some(vec![entry(2, vec![algorithm(CHACHA20)])]),
    );
    assert_eq!(status(&r), 1);
}

#[test]
fn query_reports_the_effective_defaults() {
    let mut f = Fixture::new();
    f.set_ok(vec![
        entry(2, vec![algorithm(AES), length(128), mask(12)]),
        entry(4, vec![algorithm(RSA), length(3072)]),
        entry(1, vec![Node::boolean(SENSITIVE, true)]),
    ]);
    for v in [V20, V21, V3] {
        assert!(f.reported(v, 2, CRYPTOGRAPHIC_LENGTH).unwrap() == length(128));
        assert!(f.reported(v, 2, CRYPTOGRAPHIC_USAGE_MASK).unwrap() == mask(12));
        // Built-in defaults that were not configured stay.
        assert!(f.reported(v, 2, KEY_FORMAT_TYPE).is_some());
        assert!(f.reported(v, 2, EXTRACTABLE).unwrap() == Node::boolean(EXTRACTABLE, true));
        // The pair default is reported for both keys.
        for kind in [3, 4] {
            assert!(f.reported(v, kind, CRYPTOGRAPHIC_LENGTH).unwrap() == length(3072));
        }
        assert!(f.reported(v, 1, SENSITIVE).unwrap() == Node::boolean(SENSITIVE, true));
        let kinds: Vec<u32> = f
            .query(v)
            .iter()
            .map(|e| e.required(OBJECT_TYPE).unwrap().number().unwrap())
            .collect();
        assert_eq!(kinds, vec![1, 2, 3, 4, 7, 8]);
    }
    // Set Defaults without Defaults Information returns to the built-ins.
    let r = f.set("bob", V21, None);
    assert_eq!(status(&r), 0, "{}", describe(&r));
    for v in [V20, V21, V3] {
        assert!(f.reported(v, 2, CRYPTOGRAPHIC_LENGTH).is_none());
        assert!(f.reported(v, 2, CRYPTOGRAPHIC_USAGE_MASK).unwrap() == mask(0));
        assert_eq!(alg_bits(&f.create("bob", v, vec![])), (AES as i64, 256));
    }
}

#[test]
fn defaults_persist_follow_undo_and_replace_the_whole_set() {
    let mut f = Fixture::new();
    let aes128 = entry(2, vec![algorithm(AES), length(128)]);
    // Undo rolls Set Defaults back with the batch.
    let r = f.send(
        "alice",
        V21,
        vec![Node::enumeration(BATCH_ERROR_CONTINUATION_OPTION, 3)],
        vec![
            (
                SET_DEFAULTS,
                vec![Node::structure(DEFAULTS_INFORMATION, vec![aes128.clone()])],
            ),
            (GET, vec![Node::text(UNIQUE_IDENTIFIER, "missing")]),
        ],
    );
    assert_eq!(r.iter().map(status).collect::<Vec<_>>(), [3, 1]);
    assert_eq!(alg_bits(&f.create("bob", V21, vec![])), (AES as i64, 256));
    // A default set earlier in a batch applies to later items.
    let r = f.send(
        "alice",
        V21,
        vec![],
        vec![
            (
                SET_DEFAULTS,
                vec![Node::structure(DEFAULTS_INFORMATION, vec![aes128])],
            ),
            (CREATE, create_fields(V21, vec![])),
        ],
    );
    assert_eq!(r.iter().map(status).collect::<Vec<_>>(), [0, 0]);
    let id = id_of(&r[1], UNIQUE_IDENTIFIER);
    assert_eq!(
        alg_bits(&f.attributes("alice", V21, &id)),
        (AES as i64, 128)
    );
    // The defaults reload after a restart.
    f.reopen(Settings::default());
    assert_eq!(alg_bits(&f.create("bob", V3, vec![])), (AES as i64, 128));
    // Set replaces the whole set.
    f.set_ok(vec![entry(7, vec![mask(4)])]);
    assert_eq!(alg_bits(&f.create("bob", V21, vec![])), (AES as i64, 256));
    // The record is not a managed object of any principal.
    for owner in ["alice", "bob"] {
        assert!(
            f.engine
                .store
                .list(owner)
                .unwrap()
                .iter()
                .all(|o| o.object_type < 0x8000_0000)
        );
    }
    f.engine.store.verify_integrity().unwrap();
    f.engine.store.verify_audit().unwrap();
}

// REQ:3ad54238b5ed3c4d Set Defaults reasons come from its error table
#[test]
fn malformed_defaults_are_refused() {
    let mut f = Fixture::new();
    f.set_ok(vec![entry(2, vec![mask(12)])]);
    let types = |kinds: Vec<u32>, attrs: Vec<Node>| {
        Node::structure(
            OBJECT_DEFAULTS,
            vec![
                Node::structure(
                    OBJECT_TYPES,
                    kinds
                        .into_iter()
                        .map(|k| Node::enumeration(OBJECT_TYPE, k))
                        .collect(),
                ),
                Node::structure(ATTRIBUTES, attrs),
            ],
        )
    };
    let cases: Vec<(Vec<Node>, u32)> = vec![
        // Object Groups are not supported in Object Defaults.
        (
            vec![Node::structure(
                OBJECT_DEFAULTS,
                vec![
                    Node::enumeration(OBJECT_TYPE, 2),
                    Node::structure(ATTRIBUTES, vec![mask(4)]),
                    Node::structure(OBJECT_GROUPS, vec![Node::text(OBJECT_GROUP, "g")]),
                ],
            )],
            8,
        ),
        // Length only together with Algorithm.
        (vec![entry(2, vec![length(128)])], 7),
        // The pair default lives in the Private Key entry.
        (vec![entry(3, vec![algorithm(RSA)])], 8),
        (vec![entry(3, vec![length(2048)])], 8),
        // Object types without defaults: Invalid Object Type.
        (vec![entry(5, vec![mask(4)])], 0x30),
        (vec![entry(6, vec![mask(4)])], 0x30),
        (vec![entry(9, vec![mask(4)])], 0x30),
        (vec![entry(10, vec![Node::boolean(SENSITIVE, true)])], 0x30),
        // Attributes that cannot be set: Feature Not Supported.
        (vec![entry(2, vec![Node::text(OBJECT_GROUP, "g")])], 8),
        (vec![entry(2, vec![Node::interval(LEASE_TIME, 60)])], 8),
        (
            vec![entry(2, vec![Node::int(PROTECTION_STORAGE_MASK, 1)])],
            8,
        ),
        (vec![entry(3, vec![Node::boolean(SENSITIVE, true)])], 8),
        (vec![entry(1, vec![mask(4)])], 8),
        (vec![entry(8, vec![algorithm(AES)])], 8),
        (vec![entry(7, vec![algorithm(AES)])], 8),
        // Malformed values and entries: Invalid Field.
        (vec![entry(2, vec![algorithm(AES), length(100)])], 7),
        (vec![entry(4, vec![algorithm(RSA), length(1024)])], 7),
        (vec![entry(2, vec![Node::int(SENSITIVE, 1)])], 7),
        (vec![entry(2, vec![mask(4), mask(8)])], 7),
        (vec![entry(2, vec![])], 7),
        (vec![entry(2, vec![mask(4)]), entry(2, vec![mask(8)])], 7),
        (vec![types(vec![2, 7, 2], vec![mask(4)])], 7),
        (vec![types(vec![], vec![mask(4)])], 7),
        (
            vec![Node::structure(
                OBJECT_DEFAULTS,
                vec![Node::enumeration(OBJECT_TYPE, 2)],
            )],
            7,
        ),
        (
            vec![Node::structure(
                OBJECT_DEFAULTS,
                vec![
                    Node::enumeration(OBJECT_TYPE, 2),
                    Node::structure(OBJECT_TYPES, vec![Node::enumeration(OBJECT_TYPE, 7)]),
                    Node::structure(ATTRIBUTES, vec![mask(4)]),
                ],
            )],
            7,
        ),
        (vec![Node::enumeration(OBJECT_TYPE, 2)], 7),
    ];
    for (index, (entries, expected)) in cases.into_iter().enumerate() {
        let r = f.set("alice", V21, Some(entries));
        assert_eq!(
            (status(&r), reason(&r)),
            (1, expected),
            "case {index}: {}",
            describe(&r)
        );
    }
    // A field outside Defaults Information.
    let r = f.call("alice", V21, SET_DEFAULTS, vec![mask(4)]);
    assert_eq!(reason(&r), 8);
    // A failed Set leaves the previous set in place.
    let attrs = f.create("bob", V21, vec![]);
    assert_eq!(value(&attrs, CRYPTOGRAPHIC_USAGE_MASK), Some(12));
    // Object Types expands to one entry per type.
    f.set_ok(vec![types(vec![2, 7], vec![mask(8)])]);
    assert!(f.reported(V21, 2, CRYPTOGRAPHIC_USAGE_MASK).unwrap() == mask(8));
    assert!(f.reported(V21, 7, CRYPTOGRAPHIC_USAGE_MASK).unwrap() == mask(8));
}

/// A defaults record that cannot be read fails factory requests closed
/// rather than creating objects without the configured defaults.
#[test]
fn a_corrupt_defaults_record_fails_closed() {
    let mut f = Fixture::new();
    f.set_ok(vec![entry(2, vec![Node::boolean(SENSITIVE, true)])]);
    assert!(f.engine.check_server_records().is_ok());
    let (owner, id) = ("\0server\0defaults", "defaults\0server");
    let mut record = f.engine.store.get(owner, id).unwrap().unwrap();
    record.material = b"not TTLV".to_vec();
    f.engine.store.put(&record).unwrap();
    assert!(f.engine.check_server_records().is_err());
    for v in [V20, V21, V3] {
        let r = f.call("bob", v, CREATE, create_fields(v, vec![]));
        assert_eq!((status(&r), reason(&r)), (1, 0x100), "{v:?}");
        let r = f.call("bob", v, QUERY, vec![Node::enumeration(QUERY_FUNCTION, 13)]);
        assert_eq!(status(&r), 1, "{v:?}");
    }
    assert!(f.engine.store.list("bob").unwrap().is_empty());
    // 1.x requests do not read the record.
    f.create("bob", V14, vec![mask(12)]);
    // Set Defaults replaces it.
    assert_eq!(status(&f.set("alice", V21, None)), 0);
    assert!(f.engine.check_server_records().is_ok());
    assert_eq!(alg_bits(&f.create("bob", V21, vec![])), (AES as i64, 256));
}
